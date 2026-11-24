// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
/*
 * Full-text index maintenance for private stores; see fts.hpp.
 */
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iterator>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <set>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/ctype_helper.h>
#include <libHX/scope.hpp>
#include <gromox/clock.hpp>
#include <gromox/database.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "db_engine.hpp"
#include "fts.hpp"

using namespace gromox;
using LLU = unsigned long long;

namespace {

/* State attached to one exchange.sqlite3 connection */
struct fts_hstate {
	std::string dir;
	std::vector<uint64_t> staged;
};

struct fts_work {
	bool reconcile = false;
	std::set<uint64_t> ids;
	time_point last_touch{};
};

struct fts_db_close {
	void operator()(sqlite3 *d) const { sqlite3_close_v2(d); }
};
using fts_handle = std::unique_ptr<sqlite3, fts_db_close>;

struct fts_doc {
	bool present = false, partial = false;
	uint64_t folder_id = 0, cn = 0;
	std::string subject, sender, rcpts, body, attach;
};

}

std::atomic<bool> g_exmdb_fts;
unsigned int g_exmdb_fts_max_body = 1U << 20, g_exmdb_fts_nice = 10;

/* Commits are given time to become visible before the indexer reads them */
static constexpr auto fts_settle_time = std::chrono::seconds(1);
static constexpr size_t fts_batch_size = 64;
static constexpr auto fts_idle_close = std::chrono::seconds(60);
static constexpr int fts_schema_version = 1;

static std::mutex g_fts_lock; /* protects g_fts_queue */
static std::condition_variable g_fts_cond;
static std::map<std::string, fts_work> g_fts_queue;
static std::atomic<bool> g_fts_stop{true};
static pthread_t g_fts_tid;

static constexpr char fts_triggers[] =
	"CREATE TEMP TRIGGER IF NOT EXISTS gx_fts_ins AFTER INSERT ON main.messages "
	"WHEN new.parent_fid IS NOT NULL "
	"BEGIN SELECT gx_fts_touch(new.message_id); END;"
	"CREATE TEMP TRIGGER IF NOT EXISTS gx_fts_upd AFTER UPDATE OF change_number, parent_fid ON main.messages "
	"WHEN new.parent_fid IS NOT NULL OR old.parent_fid IS NOT NULL "
	"BEGIN SELECT gx_fts_touch(new.message_id); END;"
	"CREATE TEMP TRIGGER IF NOT EXISTS gx_fts_del AFTER DELETE ON main.messages "
	"WHEN old.parent_fid IS NOT NULL "
	"BEGIN SELECT gx_fts_touch(old.message_id); END;";

/*
 * The trigram table answers substring queries (RES_CONTENT/FL_SUBSTRING).
 * It is contentless: the text itself stays in exchange.sqlite3/cid.
 */
static constexpr char fts_schema[] =
	"CREATE TABLE IF NOT EXISTS docs (message_id INTEGER PRIMARY KEY, "
	"folder_id INTEGER NOT NULL, cn INTEGER NOT NULL, "
	"partial INTEGER NOT NULL DEFAULT 0);"
	"CREATE INDEX IF NOT EXISTS docs_fid ON docs(folder_id);"
	"CREATE VIRTUAL TABLE IF NOT EXISTS ftri USING fts5(subject, sender, "
	"recipients, body, attachments, tokenize='trigram remove_diacritics 1', "
	"content='', contentless_delete=1);";

static void fts_touch_fn(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
	auto st = static_cast<fts_hstate *>(sqlite3_user_data(ctx));
	try {
		st->staged.push_back(sqlite3_value_int64(argv[0]));
	} catch (const std::bad_alloc &) {
		/* lost; the reconciliation at the next store open repairs it */
	}
	sqlite3_result_null(ctx);
}

static int fts_commit_fn(void *arg)
{
	auto st = static_cast<fts_hstate *>(arg);
	if (st->staged.empty())
		return 0;
	try {
		std::unique_lock lk(g_fts_lock);
		auto &w = g_fts_queue[st->dir];
		w.ids.insert(st->staged.cbegin(), st->staged.cend());
		w.last_touch = tp_now();
	} catch (const std::bad_alloc &) {
	}
	st->staged.clear();
	g_fts_cond.notify_one();
	return 0;
}

static void fts_rollback_fn(void *arg)
{
	static_cast<fts_hstate *>(arg)->staged.clear();
}

static void fts_hstate_free(void *arg)
{
	delete static_cast<fts_hstate *>(arg);
}

/**
 * Install the change tracking on a fresh exchange.sqlite3 connection.
 */
bool fts_handle_setup(sqlite3 *db, const char *dir) try
{
	auto st = new fts_hstate;
	st->dir = dir;
	/* On failure, sqlite3_create_function_v2 calls xDestroy itself. */
	auto ret = sqlite3_create_function_v2(db, "gx_fts_touch", 1, SQLITE_UTF8,
	           st, fts_touch_fn, nullptr, nullptr, fts_hstate_free);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1782: %s: create_function: %s", dir, sqlite3_errstr(ret));
		return false;
	}
	sqlite3_commit_hook(db, fts_commit_fn, st);
	sqlite3_rollback_hook(db, fts_rollback_fn, st);
	if (gx_sql_exec(db, fts_triggers) != SQLITE_OK) {
		sqlite3_commit_hook(db, nullptr, nullptr);
		sqlite3_rollback_hook(db, nullptr, nullptr);
		mlog(LV_ERR, "E-1783: %s: cannot install FTS triggers", dir);
		return false;
	}
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1784: ENOMEM");
	return false;
}

/**
 * Request a comparison of the index against the store, done by the indexer
 * thread. Called once per store open.
 */
void fts_store_opened(const char *dir) try
{
	{
		std::unique_lock lk(g_fts_lock);
		g_fts_queue[dir].reconcile = true;
	}
	g_fts_cond.notify_one();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1785: ENOMEM");
}

static std::string fts_uri_escape(const std::string &s)
{
	std::string out;
	for (auto c : s) {
		if (c == '%' || c == '?' || c == '#')
			out += fmt::format("%{:02X}", static_cast<unsigned char>(c));
		else
			out += c;
	}
	return out;
}

static fts_handle fts_open(const std::string &dir)
{
	auto path = dir + "/exmdb/fts.sqlite3";
	sqlite3 *raw = nullptr;
	auto ret = sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE |
	           SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI, nullptr);
	fts_handle db(raw);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1786: sqlite3_open %s: %s", path.c_str(), sqlite3_errstr(ret));
		return nullptr;
	}
	sqlite3_busy_timeout(db.get(), int(g_sqlite_busy_timeout_ns / 1000000));
	if (gx_sql_exec(db.get(), "PRAGMA journal_mode=WAL") != SQLITE_OK)
		/* keep going with existing mode */;
	/* The index can always be rebuilt; durability of the last batch is moot. */
	if (gx_sql_exec(db.get(), "PRAGMA synchronous=NORMAL") != SQLITE_OK)
		/* keep going with existing mode */;
	auto stm = gx_sql_prep(db.get(), "PRAGMA user_version");
	if (stm == nullptr || stm.step() != SQLITE_ROW)
		return nullptr;
	auto ver = stm.col_int64(0);
	stm.finalize();
	if (ver == fts_schema_version)
		return db;
	if (ver != 0) {
		mlog(LV_ERR, "E-1787: %s has unknown schema version %lld", path.c_str(),
			static_cast<long long>(ver));
		return nullptr;
	}
	if (gx_sql_exec(db.get(), fts_schema) != SQLITE_OK ||
	    gx_sql_exec(db.get(), fmt::format("PRAGMA user_version={}", fts_schema_version)) != SQLITE_OK) {
		mlog(LV_ERR, "E-1788: %s: cannot create FTS schema (SQLite >= 3.45 with FTS5 needed)",
			path.c_str());
		return nullptr;
	}
	return db;
}

/**
 * Collect the messages whose index entry is missing, outdated or orphaned.
 */
static bool fts_reconcile(sqlite3 *fdb, const std::string &dir, std::set<uint64_t> &ids)
{
	auto uri = "file:" + fts_uri_escape(dir + "/exmdb/exchange.sqlite3") + "?mode=ro";
	auto stm = gx_sql_prep(fdb, "ATTACH DATABASE ? AS ex");
	if (stm == nullptr)
		return false;
	stm.bind_text(1, uri);
	if (stm.step() != SQLITE_DONE) {
		mlog(LV_ERR, "E-1789: %s: attach: %s", dir.c_str(), sqlite3_errmsg(fdb));
		return false;
	}
	stm.finalize();
	auto cl_0 = HX::make_scope_exit([&]() {
		if (gx_sql_exec(fdb, "DETACH DATABASE ex") != SQLITE_OK)
			/* ignore */;
	});
	auto txn = gx_sql_begin(fdb, txn_mode::read);
	if (!txn)
		return false;
	stm = gx_sql_prep(fdb, "SELECT m.message_id FROM ex.messages AS m "
	      "LEFT JOIN docs AS d ON d.message_id=m.message_id "
	      "WHERE m.parent_fid IS NOT NULL AND (d.cn IS NULL OR "
	      "d.cn!=m.change_number OR d.folder_id!=m.parent_fid) "
	      "UNION ALL SELECT d.message_id FROM docs AS d WHERE NOT EXISTS "
	      "(SELECT 1 FROM ex.messages AS m WHERE m.message_id=d.message_id "
	      "AND m.parent_fid IS NOT NULL)");
	if (stm == nullptr)
		return false;
	while (stm.step() == SQLITE_ROW)
		ids.insert(stm.col_uint64(0));
	return true;
}

static void fts_append(std::string &s, const char *v)
{
	if (v == nullptr || *v == '\0')
		return;
	if (!s.empty())
		s += '\n';
	s += v;
}

/* Plaintext of the message body, from whichever body representation exists */
static void fts_get_body(const db_conn &db, uint64_t mid, std::string &out)
{
	void *v = nullptr;
	if (cu_get_property(MAPI_MESSAGE, mid, CP_UTF8, db, PR_BODY, &v) && v != nullptr) {
		out = static_cast<const char *>(v);
		return;
	}
	std::string html;
	cpid_t cpid = CP_OEMCP;
	if (cu_get_property(MAPI_MESSAGE, mid, CP_UTF8, db, PR_HTML, &v) && v != nullptr) {
		auto bin = static_cast<const BINARY *>(v);
		html.assign(bin->pc, bin->cb);
		if (cu_get_property(MAPI_MESSAGE, mid, CP_UTF8, db, PR_INTERNET_CPID, &v) &&
		    v != nullptr)
			cpid = static_cast<cpid_t>(*static_cast<const uint32_t *>(v));
	} else if (cu_get_property(MAPI_MESSAGE, mid, CP_UTF8, db, PR_RTF_COMPRESSED, &v) &&
	    v != nullptr) {
		std::string rtf;
		if (rtfcp_uncompress(*static_cast<const BINARY *>(v), rtf) != ecSuccess)
			return;
		/* In-process conversion, as with HTML below */
		auto at = attachment_list_init();
		auto at_clean = HX::make_scope_exit([&]() { attachment_list_free(at); });
		if (rtf_to_html_boring(rtf, "utf-8", html, at) != ecSuccess)
			return;
		cpid = CP_UTF8;
	} else {
		return;
	}
	/*
	 * The in-process converters are used rather than html_to_plain and
	 * rtf_to_html, which run an external renderer per document: layout
	 * does not matter for an index, throughput does.
	 */
	std::string plain;
	if (html_to_plain_boring(html, plain) < 0)
		return;
	if (cpid == CP_OEMCP || cpid == CP_UTF8) {
		out = std::move(plain);
		return;
	}
	auto s = cu_mb_to_utf8_dup(cpid, plain);
	if (s != nullptr)
		out = s;
}

/* Truncate at a UTF-8 character boundary */
static bool fts_truncate(std::string &s, size_t max)
{
	if (s.size() <= max)
		return false;
	while (max > 0 && (static_cast<unsigned char>(s[max]) & 0xC0) == 0x80)
		--max;
	s.resize(max);
	return true;
}

static bool fts_extract(const db_conn &db, uint64_t mid, fts_doc &doc)
{
	auto txn = gx_sql_begin(db.psqlite, txn_mode::read);
	if (!txn)
		return false;
	auto stm = db.prep("SELECT parent_fid, change_number FROM messages "
	           "WHERE message_id=? AND parent_fid IS NOT NULL");
	if (stm == nullptr)
		return false;
	stm.bind_int64(1, mid);
	if (stm.step() != SQLITE_ROW)
		return true; /* gone */
	doc.present = true;
	doc.folder_id = stm.col_uint64(0);
	doc.cn = stm.col_uint64(1);
	stm.finalize();

	static constexpr proptag_t mtags[] = {
		PR_SUBJECT, PR_SENDER_NAME, PR_SENDER_SMTP_ADDRESS,
		PR_SENDER_EMAIL_ADDRESS, PR_SENT_REPRESENTING_NAME,
		PR_SENT_REPRESENTING_SMTP_ADDRESS,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS,
	};
	TPROPVAL_ARRAY vals{};
	if (cu_get_properties(MAPI_MESSAGE, mid, CP_UTF8, db, mtags, &vals)) {
		fts_append(doc.subject, vals.get<const char>(PR_SUBJECT));
		for (auto t : {PR_SENDER_NAME, PR_SENDER_SMTP_ADDRESS,
		    PR_SENDER_EMAIL_ADDRESS, PR_SENT_REPRESENTING_NAME,
		    PR_SENT_REPRESENTING_SMTP_ADDRESS,
		    PR_SENT_REPRESENTING_EMAIL_ADDRESS})
			fts_append(doc.sender, vals.get<const char>(t));
	}

	static constexpr proptag_t rtags[] = {PR_DISPLAY_NAME, PR_SMTP_ADDRESS, PR_EMAIL_ADDRESS};
	std::vector<uint64_t> sub_ids;
	stm = db.prep("SELECT recipient_id FROM recipients WHERE message_id=?");
	if (stm == nullptr)
		return false;
	stm.bind_int64(1, mid);
	while (stm.step() == SQLITE_ROW)
		sub_ids.push_back(stm.col_uint64(0));
	stm.finalize();
	for (auto rid : sub_ids) {
		vals = {};
		if (!cu_get_properties(MAPI_MAILUSER, rid, CP_UTF8, db, rtags, &vals))
			continue;
		for (auto t : rtags)
			fts_append(doc.rcpts, vals.get<const char>(t));
	}

	static constexpr proptag_t atags[] = {PR_ATTACH_LONG_FILENAME, PR_ATTACH_FILENAME, PR_DISPLAY_NAME};
	sub_ids.clear();
	stm = db.prep("SELECT attachment_id FROM attachments WHERE message_id=?");
	if (stm == nullptr)
		return false;
	stm.bind_int64(1, mid);
	while (stm.step() == SQLITE_ROW)
		sub_ids.push_back(stm.col_uint64(0));
	stm.finalize();
	for (auto aid : sub_ids) {
		vals = {};
		if (!cu_get_properties(MAPI_ATTACH, aid, CP_UTF8, db, atags, &vals))
			continue;
		for (auto t : atags) {
			auto s = vals.get<const char>(t);
			if (s != nullptr) {
				fts_append(doc.attach, s);
				break;
			}
		}
	}

	fts_get_body(db, mid, doc.body);
	doc.partial = fts_truncate(doc.body, g_exmdb_fts_max_body);
	return true;
}

static bool fts_write(sqlite3 *fdb, const std::vector<std::pair<uint64_t, fts_doc>> &docs)
{
	auto txn = gx_sql_begin(fdb, txn_mode::write);
	if (!txn)
		return false;
	auto del_tri  = gx_sql_prep(fdb, "DELETE FROM ftri WHERE rowid=?");
	auto del_doc  = gx_sql_prep(fdb, "DELETE FROM docs WHERE message_id=?");
	auto ins_tri  = gx_sql_prep(fdb, "INSERT INTO ftri (rowid, subject, sender, "
	                "recipients, body, attachments) VALUES (?,?,?,?,?,?)");
	auto ins_doc  = gx_sql_prep(fdb, "INSERT INTO docs (message_id, folder_id, cn, partial) VALUES (?,?,?,?)");
	if (del_tri == nullptr || del_doc == nullptr || ins_tri == nullptr ||
	    ins_doc == nullptr)
		return false;
	for (const auto &[mid, doc] : docs) {
		for (auto stm : {&del_tri, &del_doc}) {
			stm->bind_int64(1, mid);
			if (stm->step() != SQLITE_DONE)
				return false;
			stm->reset();
		}
		if (!doc.present)
			continue;
		ins_tri.bind_int64(1, mid);
		ins_tri.bind_text(2, doc.subject);
		ins_tri.bind_text(3, doc.sender);
		ins_tri.bind_text(4, doc.rcpts);
		ins_tri.bind_text(5, doc.body);
		ins_tri.bind_text(6, doc.attach);
		if (ins_tri.step() != SQLITE_DONE)
			return false;
		ins_tri.reset();
		ins_doc.bind_int64(1, mid);
		ins_doc.bind_int64(2, doc.folder_id);
		ins_doc.bind_int64(3, doc.cn);
		ins_doc.bind_int64(4, doc.partial);
		if (ins_doc.step() != SQLITE_DONE)
			return false;
		ins_doc.reset();
	}
	return txn.commit() == SQLITE_OK;
}

/**
 * Index (or unindex) up to fts_batch_size messages of one store. Leftover
 * ids are handed back to the queue so that other stores get their turn.
 */
static void fts_process(const std::string &dir, sqlite3 *fdb, fts_work &&work) try
{
	if (work.reconcile) {
		auto before = work.ids.size();
		if (!fts_reconcile(fdb, dir, work.ids))
			return;
		if (work.ids.size() > before)
			mlog(LV_NOTICE, "I-1790: %s: %zu messages to (re)index",
				dir.c_str(), work.ids.size() - before);
	}
	std::vector<std::pair<uint64_t, fts_doc>> docs;
	{
		exmdb_server::build_env(EM_PRIVATE, dir.c_str());
		auto cl_0 = HX::make_scope_exit(exmdb_server::free_env);
		auto pdb = db_engine_get_db(dir.c_str());
		if (!pdb)
			return;
		/* Newest first: fresh mail is not held up by a backfill */
		while (!work.ids.empty() && docs.size() < fts_batch_size) {
			auto it = std::prev(work.ids.end());
			auto mid = *it;
			work.ids.erase(it);
			fts_doc doc;
			if (!fts_extract(*pdb, mid, doc)) {
				mlog(LV_WARN, "W-1791: %s: cannot read message %llu for indexing",
					dir.c_str(), LLU{mid});
				continue;
			}
			docs.emplace_back(mid, std::move(doc));
		}
	}
	if (!fts_write(fdb, docs))
		mlog(LV_ERR, "E-1792: %s: writing the FTS index failed: %s",
			dir.c_str(), sqlite3_errmsg(fdb));
	if (work.ids.empty())
		return;
	std::unique_lock lk(g_fts_lock);
	g_fts_queue[dir].ids.merge(work.ids);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1793: ENOMEM");
}

static void *fts_thread(void *)
{
	if (nice(g_exmdb_fts_nice) < 0)
		/* ignore */;
	std::string last;
	/*
	 * Connections are kept open while a store is being worked on. Closing
	 * the last connection checkpoints and resets the WAL, which would
	 * happen after every batch and stall concurrent readers.
	 */
	std::map<std::string, std::pair<fts_handle, time_point>> conns;
	std::unique_lock lk(g_fts_lock);
	while (!g_fts_stop) {
		auto now = tp_now();
		std::erase_if(conns, [&](const auto &e) { return now - e.second.second > fts_idle_close; });
		/* Round-robin over stores, skipping those with very recent commits */
		auto earliest = time_point::max();
		auto it = g_fts_queue.upper_bound(last);
		auto pick = g_fts_queue.end();
		for (size_t i = 0; i < g_fts_queue.size(); ++i, ++it) {
			if (it == g_fts_queue.end())
				it = g_fts_queue.begin();
			auto ready = it->second.last_touch + fts_settle_time;
			if (it->second.reconcile || ready <= now) {
				pick = it;
				break;
			}
			earliest = std::min(earliest, ready);
		}
		if (pick == g_fts_queue.end()) {
			if (!conns.empty())
				earliest = std::min(earliest, now + fts_idle_close);
			if (earliest == time_point::max())
				g_fts_cond.wait(lk);
			else
				g_fts_cond.wait_until(lk, earliest);
			continue;
		}
		last = pick->first;
		auto work = std::move(pick->second);
		g_fts_queue.erase(pick);
		lk.unlock();
		if (g_exmdb_fts) {
			auto &c = conns[last];
			if (c.first == nullptr)
				c.first = fts_open(last);
			c.second = tp_now();
			if (c.first != nullptr)
				fts_process(last, c.first.get(), std::move(work));
			else
				conns.erase(last);
		}
		lk.lock();
	}
	return nullptr;
}

int fts_run()
{
	g_fts_stop = false;
	auto ret = pthread_create4(&g_fts_tid, nullptr, fts_thread, nullptr);
	if (ret != 0) {
		g_fts_stop = true;
		mlog(LV_ERR, "E-1794: pthread_create: %s", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_fts_tid, "fts");
	return 0;
}

void fts_stop()
{
	if (g_fts_stop)
		return;
	{
		std::unique_lock lk(g_fts_lock);
		g_fts_stop = true;
	}
	g_fts_cond.notify_all();
	pthread_join(g_fts_tid, nullptr);
	g_fts_queue.clear();
}

/*
 * Index column holding the text of a property, for properties whose
 * values are indexed verbatim (so that the index text contains every
 * substring the property value contains).
 */
static const char *fts_column(proptag_t tag, bool in_attach)
{
	if (in_attach)
		/*
		 * The indexer stores the first of PR_ATTACH_LONG_FILENAME,
		 * PR_ATTACH_FILENAME, PR_DISPLAY_NAME; only the first one is
		 * thus guaranteed to be there when it is set.
		 */
		return tag == PR_ATTACH_LONG_FILENAME ? "attachments" : nullptr;
	switch (tag) {
	case PR_SUBJECT:
	case PR_NORMALIZED_SUBJECT:
		return "subject";
	case PR_BODY:
		return "body";
	case PR_SENDER_NAME:
	case PR_SENDER_SMTP_ADDRESS:
	case PR_SENDER_EMAIL_ADDRESS:
	case PR_SENT_REPRESENTING_NAME:
	case PR_SENT_REPRESENTING_SMTP_ADDRESS:
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		return "sender";
	case PR_DISPLAY_TO:
	case PR_DISPLAY_CC:
	case PR_DISPLAY_BCC:
		/* "; "-joined names; see fts_needle */
		return "recipients";
	}
	return nullptr;
}

/*
 * Pick the part of @needle that the index can be asked for. Any substring
 * of the needle will do, as it is implied by the needle. PR_DISPLAY_TO and
 * friends are synthesized as "name1; name2", while the index holds the
 * names separately, so for those, only a piece that cannot straddle a
 * separator is usable.
 */
static std::string_view fts_needle(std::string_view col, std::string_view needle)
{
	if (col != "recipients")
		return needle;
	std::string_view best;
	while (!needle.empty()) {
		auto pos = needle.find(';');
		auto seg = needle.substr(0, pos);
		while (!seg.empty() && HX_isspace(seg.front()))
			seg.remove_prefix(1);
		while (!seg.empty() && HX_isspace(seg.back()))
			seg.remove_suffix(1);
		if (seg.size() > best.size())
			best = seg;
		if (pos == needle.npos)
			break;
		needle.remove_prefix(pos + 1);
	}
	return best;
}

/**
 * Derive an FTS5 query that every message matching @r also matches.
 * Returns false if no such constraint can be derived.
 */
static bool fts_res_query(const RESTRICTION &r, std::string &q,
    bool in_attach = false)
{
	switch (r.rt) {
	case RES_AND:
	case RES_OR: {
		std::string out;
		size_t parts = 0;
		for (const auto &sub : *r.andor) {
			std::string sq;
			if (!fts_res_query(sub, sq, in_attach)) {
				if (r.rt == RES_OR)
					return false;
				continue;
			}
			if (parts++ > 0)
				out += r.rt == RES_AND ? " AND " : " OR ";
			out += "(" + sq + ")";
		}
		if (parts == 0)
			return false;
		q = std::move(out);
		return true;
	}
	case RES_CONTENT: {
		auto &c = *r.cont;
		auto col = fts_column(c.proptag, in_attach);
		auto lvl = c.fuzzy_level & 0xFFFF;
		if (col == nullptr || PROP_TYPE(c.propval.proptag) != PT_UNICODE ||
		    c.propval.pvalue == nullptr ||
		    (lvl != FL_FULLSTRING && lvl != FL_SUBSTRING && lvl != FL_PREFIX))
			return false;
		auto needle = fts_needle(col, static_cast<const char *>(c.propval.pvalue));
		size_t chars = 0;
		for (auto ch : needle)
			if ((static_cast<unsigned char>(ch) & 0xC0) != 0x80)
				++chars;
		if (chars < 3)
			return false; /* the trigram index cannot answer this */
		q = fmt::format("{} : \"", col);
		for (auto ch : needle) {
			if (ch == '"')
				q += '"';
			q += ch;
		}
		q += '"';
		return true;
	}
	case RES_SUBRESTRICTION:
		/*
		 * The attachments column holds the names of all attachments of
		 * the message, so whatever one attachment has to contain, the
		 * column contains as well.
		 */
		if (in_attach || r.sub->subobject != PR_MESSAGE_ATTACHMENTS)
			return false;
		return fts_res_query(r.sub->res, q, true);
	default:
		return false;
	}
}

fts_prefilter::~fts_prefilter() = default;

/**
 * Prepare a candidate filter for @res. Returns nullptr when the index cannot
 * narrow the search; the caller then evaluates every message as usual.
 */
std::unique_ptr<fts_prefilter> fts_prefilter::create(const char *dir,
    const db_conn &db, const RESTRICTION *res) try
{
	if (!g_exmdb_fts || dir == nullptr || res == nullptr)
		return nullptr;
	std::string query;
	if (!fts_res_query(*res, query))
		return nullptr;
	auto path = fmt::format("{}/exmdb/fts.sqlite3", dir);
	sqlite3 *raw = nullptr;
	auto ret = sqlite3_open_v2(path.c_str(), &raw,
	           SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
	fts_handle fdb(raw);
	if (ret != SQLITE_OK)
		return nullptr;
	sqlite3_busy_timeout(fdb.get(), int(g_sqlite_busy_timeout_ns / 1000000));
	auto stm = gx_sql_prep(fdb.get(), "PRAGMA user_version");
	if (stm == nullptr || stm.step() != SQLITE_ROW ||
	    stm.col_int64(0) != fts_schema_version)
		return nullptr;
	stm.finalize();
	std::unique_ptr<fts_prefilter> f(new fts_prefilter);
	/* Hits and docs rows must come from the same snapshot */
	f->m_txn = gx_sql_begin(fdb.get(), txn_mode::read);
	if (!f->m_txn)
		return nullptr;
	stm = gx_sql_prep(fdb.get(), "SELECT rowid FROM ftri WHERE ftri MATCH ?");
	if (stm == nullptr)
		return nullptr;
	stm.bind_text(1, query);
	while ((ret = stm.step()) == SQLITE_ROW)
		f->m_hits.insert(stm.col_uint64(0));
	if (ret != SQLITE_DONE) {
		mlog(LV_WARN, "W-1795: %s: FTS query <%s> failed: %s", dir,
			query.c_str(), sqlite3_errmsg(fdb.get()));
		return nullptr;
	}
	stm.finalize();
	f->m_doc = gx_sql_prep(fdb.get(), "SELECT cn, partial FROM docs WHERE message_id=?");
	f->m_msg = db.prep("SELECT change_number FROM messages WHERE message_id=?");
	if (f->m_doc == nullptr || f->m_msg == nullptr)
		return nullptr;
	f->m_fdb.reset(fdb.release());
	mlog(LV_DEBUG, "fts: %s: <%s> -> %zu hits", dir, query.c_str(), f->m_hits.size());
	return f;
} catch (const std::bad_alloc &) {
	return nullptr;
}

/**
 * Whether message @mid can possibly satisfy the restriction. Messages whose
 * index entry is missing, outdated or truncated are always candidates.
 */
bool fts_prefilter::may_match(uint64_t mid)
{
	if (m_hits.contains(mid))
		return true;
	m_doc.reset();
	m_doc.bind_int64(1, mid);
	if (m_doc.step() != SQLITE_ROW || m_doc.col_int64(1) != 0)
		return true;
	m_msg.reset();
	m_msg.bind_int64(1, mid);
	if (m_msg.step() != SQLITE_ROW)
		return true;
	return m_msg.col_uint64(0) != m_doc.col_uint64(0);
}

void fts_prefilter::close::operator()(sqlite3 *d) const
{
	sqlite3_close_v2(d);
}
