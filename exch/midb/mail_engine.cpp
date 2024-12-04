// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iconv.h>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <fmt/core.h>
#include <libHX/ctype_helper.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/database.h>
#include <gromox/dbop.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/midb.hpp>
#include <gromox/mjson.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/process.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/safeint.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "cmd_parser.hpp"
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "mail_engine.hpp"
#include "system_services.hpp"
#define MAX_DIGLEN						256*1024
#define RELOAD_INTERVAL					3600
#define MAX_DB_WAITING_THREADS			5

using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

enum {
	CONFIG_ID_USERNAME = 1, /* obsolete */
};

enum class midb_cond {
	x_none,	all, answered, deleted, draft, flagged,
	is_new, old, recent, seen,
	unanswered, undeleted, undraft, unflagged, unseen,

	/* ct_headers */
	header,

	/* ct_keyword */
	bcc, body, cc, from, keyword, subject, text, to, unkeyword,

	/* ct_time */
	before, on, sent_before, sent_on, sent_since, since,

	/* ct_size */
	larger, smaller,

	/* ct_seq */
	id, uid,
};

enum class midb_conj {
	c_and, c_or, c_not,
};

namespace {

struct syncfolder_entry {
	uint64_t parent_fid = 0, commit_max = 0;;
	std::string display_name;
};

struct syncmessage_entry {
	uint64_t mod_time = 0, recv_time = 0;
	uint32_t msg_flags = 0;
	bool has_midstr = false;
	std::string midstr;
};

using syncfolder_list = std::unordered_map<uint64_t /* folder_id */, syncfolder_entry>;
using syncmessage_list = std::unordered_map<uint64_t /* message_id */, syncmessage_entry>;

struct ct_node;
using CONDITION_TREE = std::vector<ct_node>;
struct ct_node {
	ct_node() = default;
	ct_node(ct_node &&);
	~ct_node();
	void operator=(ct_node &&) = delete;

	CONDITION_TREE *pbranch = nullptr;
	enum midb_conj conjunction = midb_conj::c_and;
	enum midb_cond condition = midb_cond::x_none;

	union {
		char *ct_headers[2]{};
		char *ct_keyword;
		time_t ct_time;
		size_t ct_size;
		imap_seq_list *ct_seq;
	};
};
using CONDITION_TREE_NODE = ct_node;

struct KEYWORD_ENUM {
	MJSON *pjson;
	BOOL b_result;
	const char *charset;
	const char *keyword;
};

struct IDB_ITEM {
	IDB_ITEM() = default;
	~IDB_ITEM();
	NOMOVE(IDB_ITEM);

	sqlite3 *psqlite = nullptr;
	/* client reference count, item can be flushed into file system only count is 0 */
	std::string username;
	time_t last_time = 0, load_time = 0;
	uint32_t sub_id = 0;
	std::atomic<int> reference{0};
	std::timed_mutex giant_lock;
};

struct idb_item_del {
	void operator()(IDB_ITEM *);
};

}

using IDB_REF = std::unique_ptr<IDB_ITEM, idb_item_del>;

enum {
	FIELD_NONE = 0,
	FIELD_UID,
};

unsigned int g_midb_schema_upgrades;
unsigned int g_midb_cache_interval, g_midb_reload_interval;

static constexpr time_duration DB_LOCK_TIMEOUT = std::chrono::seconds(60);
static size_t g_table_size;
static std::atomic<unsigned int> g_sequence_id;
static gromox::atomic_bool g_notify_stop; /* stop signal for scanning thread */
static pthread_t g_scan_tid;
static char g_org_name[256];
static char g_default_charset[32];
static std::mutex g_hash_lock;
static std::unordered_map<std::string, IDB_ITEM> g_hash_table;

static bool ct_hint_seq(const imap_seq_list &plist, unsigned int num, unsigned int max_uid);

template<typename T> static inline bool
array_find_str(const T &kwlist, const char *s)
{
	for (const auto kw : kwlist)
		if (strcmp(s, kw) == 0)
			return true;
	return false;
}

template<typename T> static inline bool
array_find_istr(const T &kwlist, const char *s)
{
	for (const auto kw : kwlist)
		if (strcasecmp(s, kw) == 0)
			return true;
	return false;
}

static std::unique_ptr<char[]> mail_engine_ct_to_utf8(const char *charset,
    const char *string) try
{
	int length;
	iconv_t conv_id;
	size_t in_len, out_len;

	if (strcasecmp(charset, "UTF-8") == 0||
	    strcasecmp(charset, "US-ASCII") == 0)
		return std::unique_ptr<char[]>(strdup(string));
	cset_cstr_compatible(charset);
	length = strlen(string) + 1;
	auto ret_string = std::make_unique<char[]>(2 * length);
	conv_id = iconv_open("UTF-8", charset);
	if (conv_id == (iconv_t)-1)
		return NULL;
	auto pin = deconst(string);
	auto pout = ret_string.get();
	in_len = length;
	out_len = 2*length;
	if (iconv(conv_id, &pin, &in_len, &pout, &out_len) == static_cast<size_t>(-1)) {
		iconv_close(conv_id);
		return NULL;
	}
	iconv_close(conv_id);
	return ret_string;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1963: ENOMEM");
	return nullptr;
}

static uint64_t mail_engine_get_digest(sqlite3 *psqlite, const char *mid_string,
    Json::Value &digest) try
{
	size_t size;
	char temp_path[256];
	
	snprintf(temp_path, 256, "%s/ext/%s",
		common_util_get_maildir(), mid_string);
	size_t slurp_size = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(temp_path, &slurp_size));
	if (slurp_data != nullptr) {
		if (!json_from_str(slurp_data.get(), digest))
			return 0;
	} else if (errno != ENOENT) {
		mlog(LV_ERR, "E-2139: read %s: %s", temp_path, strerror(errno));
		return 0;
	} else {
		snprintf(temp_path, 256, "%s/eml/%s",
			common_util_get_maildir(), mid_string);
		slurp_data.reset(HX_slurp_file(temp_path, &slurp_size));
		if (slurp_data == nullptr) {
			mlog(LV_ERR, "E-1252: %s: %s", temp_path, strerror(errno));
			return 0;
		}
		MAIL imail;
		if (!imail.load_from_str_move(slurp_data.get(), slurp_size))
			return 0;
		slurp_data.reset();
		if (imail.make_digest(&size, digest) <= 0)
			return 0;
		imail.clear();
		digest["file"] = "";
		auto djson = json_to_str(digest);
		snprintf(temp_path, 256, "%s/ext/%s",
			common_util_get_maildir(), mid_string);
		wrapfd fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
		if (fd.get() >= 0) {
			if (HXio_fullwrite(fd.get(), djson.c_str(), djson.size()) < 0 ||
			    fd.close_wr() != 0)
				mlog(LV_ERR, "E-2082: write %s: %s", temp_path, strerror(errno));
		} else {
			mlog(LV_ERR, "E-2138: open %s for write: %s", temp_path, strerror(errno));
		}
	}
	auto pstmt = gx_sql_prep(psqlite, "SELECT uid, recent, read,"
	             " unsent, flagged, replied, forwarded, deleted,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return 0;
	sqlite3_bind_text(pstmt, 1, mid_string, -1, SQLITE_STATIC);
	if (pstmt.step() != SQLITE_ROW)
		return 0;
	auto folder_id = pstmt.col_uint64(8);
	digest["file"]      = mid_string;
	digest["uid"]       = Json::Value::UInt64(pstmt.col_int64(0));
	digest["recent"]    = Json::Value::UInt64(pstmt.col_int64(1));
	digest["read"]      = Json::Value::UInt64(pstmt.col_int64(2));
	digest["unsent"]    = Json::Value::UInt64(pstmt.col_int64(3));
	digest["flag"]      = Json::Value::UInt64(pstmt.col_int64(4));
	digest["replied"]   = Json::Value::UInt64(pstmt.col_int64(5));
	digest["forwarded"] = Json::Value::UInt64(pstmt.col_int64(6));
	digest["deleted"]   = Json::Value::UInt64(pstmt.col_int64(7));
	return folder_id;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1139: ENOMEM");
	return 0;
}

static std::unique_ptr<char[]> mail_engine_ct_decode_mime(const char *charset,
    const char *mime_string) try
{
	int i, buff_len;
	int offset;
	int last_pos, begin_pos, end_pos;
	ENCODE_STRING encode_string;
	char temp_buff[1024];

	buff_len = strlen(mime_string);
	auto ret_string = std::make_unique<char[]>(2 * (buff_len + 1));
	auto in_buff = deconst(mime_string);
	auto out_buff = ret_string.get();
	offset = 0;
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	for (i=0; i<buff_len-1&&offset<2*buff_len+1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				memcpy(temp_buff, in_buff + last_pos, begin_pos - last_pos);
				temp_buff[begin_pos - last_pos] = '\0';
				HX_strltrim(temp_buff);
				auto tmp_string = mail_engine_ct_to_utf8(charset, temp_buff);
				if (tmp_string == nullptr)
					return NULL;
				auto tmp_len = strlen(tmp_string.get());
				memcpy(out_buff + offset, tmp_string.get(), tmp_len);
				offset += tmp_len;
				last_pos = i;
			}
		}
		if (end_pos == -1 && begin_pos != -1 && in_buff[i] == '?' &&
		    in_buff[i+1] == '=' && ((in_buff[i-1] != 'q' &&
		    in_buff[i-1] != 'Q') || in_buff[i-2] != '?'))
			end_pos = i + 1;
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			auto tmp_len = strlen(encode_string.title);
			std::unique_ptr<char[]> tmp_string;
			if (0 == strcmp(encode_string.encoding, "base64")) {
				size_t decode_len = 0;
				decode64(encode_string.title, tmp_len,
				         temp_buff, std::size(temp_buff), &decode_len);
				temp_buff[decode_len] = '\0';
				tmp_string = mail_engine_ct_to_utf8(encode_string.charset, temp_buff);
			} else if (0 == strcmp(encode_string.encoding, "quoted-printable")){
				auto decode_len = qp_decode_ex(temp_buff, std::size(temp_buff),
				                  encode_string.title, tmp_len);
				if (decode_len < 0)
					return NULL;
				temp_buff[decode_len] = '\0';
				tmp_string = mail_engine_ct_to_utf8(encode_string.charset, temp_buff);
			} else {
				tmp_string = mail_engine_ct_to_utf8(charset, encode_string.title);
			}
			if (tmp_string == nullptr)
				return NULL;
			tmp_len = strlen(tmp_string.get());
			memcpy(out_buff + offset, tmp_string.get(), tmp_len);
			offset += tmp_len;
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos) {
		auto tmp_string = mail_engine_ct_to_utf8(charset, in_buff + last_pos);
		if (tmp_string == nullptr)
			return NULL;
		auto tmp_len = strlen(tmp_string.get());
		memcpy(out_buff + offset, tmp_string.get(), tmp_len);
		offset += tmp_len;
	} 
	out_buff[offset] = '\0';
	return ret_string;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1968: ENOMEM");
	return nullptr;
}

static void mail_engine_ct_enum_mime(MJSON_MIME *pmime, void *param) try
{
	auto penum = static_cast<KEYWORD_ENUM *>(param);
	size_t temp_len;
	const char *charset;
	const char *filename;
	
	if (penum->b_result)
		return;
	if (pmime->get_mtype() != mime_type::single &&
	    pmime->get_mtype() != mime_type::single_obj)
		return;

	if (strncmp(pmime->get_ctype(), "text/", 5) != 0) {
		filename = pmime->get_filename();
		if ('\0' != filename[0]) {
			auto rs = mail_engine_ct_decode_mime(penum->charset, filename);
			if (rs != nullptr &&
			    search_string(rs.get(), penum->keyword,
			    strlen(rs.get())) != nullptr)
				penum->b_result = TRUE;
		}
	}
	auto length = pmime->get_content_length();
	auto pbuff = std::make_unique<char[]>(2 * length + 1);
	auto fd = penum->pjson->seek_fd(pmime->get_id(), MJSON_MIME_CONTENT);
	if (fd == -1)
		return;
	auto read_len = HXio_fullread(fd, pbuff.get(), length);
	if (read_len < 0 || static_cast<size_t>(read_len) != length)
		return;
	if (strcasecmp(pmime->get_encoding(), "base64") == 0) {
		if (decode64_ex(pbuff.get(), length, &pbuff[length],
		    length, &temp_len) != 0)
			return;
		pbuff[length + temp_len] = '\0';
	} else if (strcasecmp(pmime->get_encoding(), "quoted-printable") == 0) {
		auto xl = qp_decode_ex(&pbuff[length], length, pbuff.get(), length);
		if (xl < 0)
			return;
		temp_len = xl;
		pbuff[length + temp_len] = '\0';
	} else {
		memcpy(&pbuff[length], pbuff.get(), length);
		pbuff[2*length] = '\0';
	}

	charset = pmime->get_charset();
	auto rs = mail_engine_ct_to_utf8(*charset != '\0' ?
	          charset : penum->charset, &pbuff[length]);
	if (rs != nullptr && search_string(rs.get(), penum->keyword,
	    strlen(rs.get())) != nullptr)
		penum->b_result = TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1970: ENOMEM");
}

static bool mail_engine_ct_search_head(const char *charset,
	const char *file_path, const char *tag, const char *value)
{
	FILE * fp;
	bool stat_head = false;
	size_t head_offset = 0, offset = 0, len;
	MIME_FIELD mime_field;
	char head_buff[64*1024];
	
	fp = fopen(file_path, "r");
	if (fp == nullptr)
		return false;
	while (NULL != fgets(head_buff + head_offset,
		64*1024 - head_offset, fp)) {
		len = strlen(head_buff + head_offset);
		head_offset += len;
		
		if (head_offset >= 64*1024 - 1)
			break;
		if (2 == len && 0 == strcmp("\r\n", head_buff + head_offset - 2)) {
			stat_head = true;
			break;
		}
	}
	fclose(fp);
	if (!stat_head)
		return false;

	while ((len = parse_mime_field(head_buff + offset,
	       head_offset - offset, &mime_field)) != 0) {
		offset += len;
		if (strcasecmp(tag, mime_field.name.c_str()) != 0)
			continue;
		auto rs = mail_engine_ct_decode_mime(charset, mime_field.value.c_str());
		if (rs != nullptr &&
		    search_string(rs.get(), value, strlen(rs.get())))
			return true;
	}
	return false;
}

enum ctm_field {
	CTM_MSGID, CTM_MODTIME, CTM_UID, CTM_RECENT, CTM_READ, CTM_UNSENT,
	CTM_FLAGGED, CTM_REPLIED, CTM_FWD, CTM_DELETED, CTM_RCVDTIME,
	CTM_FOLDERID, CTM_SIZE,
};

static bool mail_engine_ct_match_mail(sqlite3 *psqlite, const char *charset,
    sqlite3_stmt *pstmt_message, const char *mid_string, int id, int total_mail,
    uint32_t uidnext, const CONDITION_TREE *ptree) try
{
	int sp = 0;
	bool b_loaded, b_result, b_result1, results[1024];
	midb_conj conjunction;
	time_t tmp_time;
	size_t temp_len;
	char temp_buff[1024];
	char temp_buff1[1024];
	midb_conj conjunctions[1024];
	KEYWORD_ENUM keyword_enum;
	const CONDITION_TREE *trees[1024];
	CONDITION_TREE::const_iterator pnode, nodes[1024];
	Json::Value digest;
	
#define PUSH_MATCH(TREE, NODE, CONJUNCTION, RESULT) \
		{trees[sp]=TREE;nodes[sp]=NODE;conjunctions[sp]=CONJUNCTION;results[sp]=RESULT;sp++;}
	
#define POP_MATCH(TREE, NODE, CONJUNCTION, RESULT) \
		{sp--;TREE=trees[sp];NODE=nodes[sp];CONJUNCTION=conjunctions[sp];RESULT=results[sp];}

/* begin of recursion procedure */
	while (true) {
 PROC_BEGIN:
	b_result = true;
	b_loaded = false;
	for (pnode = ptree->begin(); pnode != ptree->end(); ++pnode) {
		{
		auto ptree_node = &*pnode;
		conjunction = ptree_node->conjunction;
		if ((b_result && conjunction == midb_conj::c_or) ||
		    (!b_result && conjunction == midb_conj::c_and))
			continue;
		b_result1 = false;
		if (NULL != ptree_node->pbranch) {
			PUSH_MATCH(ptree, pnode, conjunction, b_result)
			ptree = ptree_node->pbranch;
			goto PROC_BEGIN;
		} else {
			switch (ptree_node->condition) {
			case midb_cond::all:
			case midb_cond::keyword:
			case midb_cond::unkeyword:
				b_result1 = true;
				break;
			case midb_cond::answered:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_REPLIED) != 0)
					b_result1 = true;
				break;
			case midb_cond::bcc:
				/* we do not support BCC field in mail digest,
					BCC should not recorded in mail head */
				break;
			case midb_cond::before:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, CTM_RCVDTIME));
				if (tmp_time < ptree_node->ct_time)
					b_result1 = true;
				break;
			case midb_cond::body: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string,
					    digest) == 0)
						break;
					b_loaded = true;
				}
				MJSON temp_mjson;
				snprintf(temp_buff, 256, "%s/eml",
						common_util_get_maildir());
				if (!temp_mjson.load_from_json(digest, temp_buff))
					break;
				keyword_enum.pjson = &temp_mjson;
				keyword_enum.b_result = FALSE;
				keyword_enum.charset = charset;
				keyword_enum.keyword = ptree_node->ct_keyword;
				temp_mjson.enum_mime(mail_engine_ct_enum_mime, &keyword_enum);
				if (keyword_enum.b_result)
					b_result1 = true;
				break;
			}
			case midb_cond::cc: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string,
					    digest) == 0)
						break;
					b_loaded = true;
				}
				if (!get_digest(digest, "cc", temp_buff, std::size(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = true;
				break;
			}
			case midb_cond::deleted:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_DELETED) != 0)
					b_result1 = true;
				break;
			case midb_cond::draft:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_UNSENT) != 0)
					b_result1 = true;
				break;
			case midb_cond::flagged:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_FLAGGED) != 0)
					b_result1 = true;
				break;
			case midb_cond::from: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string,
					    digest) == 0)
						break;
					b_loaded = true;
				}
				if (!get_digest(digest, "from", temp_buff, std::size(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = true;
				break;
			}
			case midb_cond::header:
				snprintf(temp_buff1, 256, "%s/eml/%s",
					common_util_get_maildir(), mid_string);
				b_result1 = mail_engine_ct_search_head(charset,
					temp_buff1, ptree_node->ct_headers[0],
					ptree_node->ct_headers[1]);
				break;
			case midb_cond::id:
				b_result1 = ct_hint_seq(*ptree_node->ct_seq, id, total_mail);
				break;
			case midb_cond::larger:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (gx_sql_col_uint64(pstmt_message, 12) >
				    ptree_node->ct_size)
					b_result1 = true;
				break;
			case midb_cond::is_new:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_RECENT) != 0 &&
				    sqlite3_column_int64(pstmt_message, CTM_READ) == 0)
					b_result1 = true;
				break;
			case midb_cond::old:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_RECENT) == 0)
					b_result1 = true;
				break;
			case midb_cond::on:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, CTM_RCVDTIME));
				if (tmp_time >= ptree_node->ct_time &&
				    tmp_time < ptree_node->ct_time + 86400)
					b_result1 = true;
				break;
			case midb_cond::recent:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_RECENT) != 0)
					b_result1 = true;
				break;
			case midb_cond::seen:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_READ) != 0)
					b_result1 = true;
				break;
			case midb_cond::sent_before:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, CTM_MODTIME));
				if (tmp_time < ptree_node->ct_time)
					b_result1 = true;
				break;
			case midb_cond::sent_on:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, CTM_MODTIME));
				if (tmp_time >= ptree_node->ct_time &&
				    tmp_time < ptree_node->ct_time + 86400)
					b_result1 = true;
				break;
			case midb_cond::sent_since:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, CTM_MODTIME));
				if (tmp_time >= ptree_node->ct_time)
					b_result1 = true;
				break;
			case midb_cond::since:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				tmp_time = rop_util_nttime_to_unix(
					sqlite3_column_int64(pstmt_message, CTM_RCVDTIME));
				if (tmp_time >= ptree_node->ct_time)
					b_result1 = true;
				break;
			case midb_cond::smaller:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (gx_sql_col_uint64(pstmt_message, 12) < ptree_node->ct_size)
					b_result1 = true;
				break;
			case midb_cond::subject: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string,
					    digest) == 0)
						break;
					b_loaded = true;
				}
				if (!get_digest(digest, "subject", temp_buff, std::size(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = true;
				break;
			}
			case midb_cond::text: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string,
					    digest) == 0)
						break;
					b_loaded = true;
				}
				if (get_digest(digest, "cc", temp_buff, std::size(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = true;
				}
				if (b_result1)
					break;
				if (get_digest(digest, "from", temp_buff, std::size(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = true;
				}
				if (b_result1)
					break;
				if (get_digest(digest, "subject", temp_buff, std::size(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = true;
				}
				if (b_result1)
					break;
				if (get_digest(digest, "to", temp_buff, std::size(temp_buff)) &&
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) == 0) {
					temp_buff1[temp_len] = '\0';
					auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
					if (rs != nullptr &&
					    search_string(rs.get(), ptree_node->ct_keyword,
					    strlen(rs.get())) != nullptr)
						b_result1 = true;
				}
				if (b_result1)
					break;
				MJSON temp_mjson;
				snprintf(temp_buff, 256, "%s/eml",
						common_util_get_maildir());
				if (!temp_mjson.load_from_json(digest, temp_buff))
					break;
				keyword_enum.pjson = &temp_mjson;
				keyword_enum.b_result = FALSE;
				keyword_enum.charset = charset;
				keyword_enum.keyword = ptree_node->ct_keyword;
				temp_mjson.enum_mime(mail_engine_ct_enum_mime, &keyword_enum);
				if (keyword_enum.b_result)
					b_result1 = true;
				break;
			}
			case midb_cond::to: {
				if (!b_loaded) {
					if (mail_engine_get_digest(psqlite, mid_string,
					    digest) == 0)
						break;
					b_loaded = true;
				}
				if (!get_digest(digest, "to", temp_buff, std::size(temp_buff)) ||
				    decode64(temp_buff, strlen(temp_buff),
				    temp_buff1, std::size(temp_buff1), &temp_len) != 0)
					break;
				temp_buff1[temp_len] = '\0';
				auto rs = mail_engine_ct_decode_mime(charset, temp_buff1);
				if (rs != nullptr &&
				    search_string(rs.get(), ptree_node->ct_keyword,
				    strlen(rs.get())) != nullptr)
					b_result1 = true;
				break;
			}
			case midb_cond::unanswered:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_REPLIED) == 0)
					b_result1 = true;
				break;
			case midb_cond::uid:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				b_result1 = ct_hint_seq(*ptree_node->ct_seq,
					sqlite3_column_int64(pstmt_message, CTM_UID),
					uidnext);
				break;
			case midb_cond::undeleted:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_DELETED) == 0)
					b_result1 = true;
				break;
			case midb_cond::undraft:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_UNSENT) == 0)
					b_result1 = true;
				break;
			case midb_cond::unflagged:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_FLAGGED) == 0)
					b_result1 = true;
				break;
			case midb_cond::unseen:
				sqlite3_reset(pstmt_message);
				sqlite3_bind_text(pstmt_message,
					1, mid_string, -1, SQLITE_STATIC);
				if (gx_sql_step(pstmt_message) != SQLITE_ROW)
					break;
				if (sqlite3_column_int64(pstmt_message, CTM_READ) == 0)
					b_result1 = true;
				break;
			default:
				mlog(LV_DEBUG, "mail_engine: condition stat %u unknown!",
					static_cast<unsigned int>(ptree_node->condition));
				break;
			}
		}
		}
		
 RECURSION_POINT:
		switch (conjunction) {
		case midb_conj::c_and:
			b_result &= b_result1;
			break;
		case midb_conj::c_or:
			b_result |= b_result1;
			break;
		case midb_conj::c_not:
			b_result &= !b_result1;
			break;
		}
	}
	if (sp > 0) {
		b_result1 = b_result;
		POP_MATCH(ptree, pnode, conjunction, b_result)
		goto RECURSION_POINT;
	}
	return b_result;
}
/* end of recursion procedure */

} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1133: ENOMEM");
	return false;
}

static int mail_engine_ct_compile_criteria(int argc,
	char **argv, int offset, char **argv_out)
{
	static constexpr const char *kwlist1[] =
		{"ALL", "ANSWERED", "DELETED", "DRAFT", "FLAGGED", "NEW",
		"OLD", "RECENT", "SEEN", "UNANSWERED", "UNDELETED", "UNDRAFT",
		"UNFLAGGED", "UNSEEN"};
	static constexpr const char *kwlist2[] =
		{"BCC", "BEFORE", "BODY", "CC", "FROM", "KEYWORD", "LARGER",
		"ON", "SENTBEFORE", "SENTON", "SENTSINCE", "SINCE", "SMALLER",
		"SUBJECT", "TEXT", "TO", "UID", "UNKEYWORD"};
	int i;
	int tmp_argc;
	int tmp_argc1;
	
	i = offset;
	if (argc < i + 1)
		return -1;
	argv_out[0] = argv[i];
	if (0 == strcasecmp(argv[i], "OR")) {
		i ++;
		if (argc < i + 1)
			return -1;
		tmp_argc = mail_engine_ct_compile_criteria(
						argc, argv, i, argv_out + 1);
		if (tmp_argc == -1)
			return -1;
		i += tmp_argc;
		if (argc < i + 1)
			return -1;
		tmp_argc1 = mail_engine_ct_compile_criteria(
			argc, argv, i, argv_out + 1 + tmp_argc);
		if (tmp_argc1 == -1)
			return -1;
		return tmp_argc + tmp_argc1 + 1;
	} else if (array_find_istr(kwlist1, argv[i])) {
		return 1;
	} else if (array_find_istr(kwlist2, argv[i])) {
		i ++;
		if (argc < i + 1)
			return -1;
		argv_out[1] = argv[i];
		return 2;
	} else if (0 == strcasecmp(argv[i], "HEADER")) {
		i ++;
		if (argc < i + 1)
			return -1;
		argv_out[1] = argv[i];
		i++;
		if (argc < i + 1)
			return -1;
		argv_out[2] = argv[i];
		return 3;
	} else if (0 == strcasecmp(argv[i], "NOT")) {
		i ++;
		if (argc < i + 1)
			return -1;
		tmp_argc = mail_engine_ct_compile_criteria(
						argc, argv, i, argv_out + 1);
		if (-1 == tmp_argc)
			return -1;
		return tmp_argc + 1;
	} else {
		/* <sequence set> or () as default */
		return 1;
	}
}

ct_node::ct_node(ct_node &&o) :
	pbranch(o.pbranch), conjunction(o.conjunction), condition(o.condition)
{
	o.pbranch = nullptr;
	switch (condition) {
	case midb_cond::id ... midb_cond::uid:
		ct_seq = o.ct_seq;
		o.ct_seq = nullptr;
		break;
	case midb_cond::bcc ... midb_cond::unkeyword:
		ct_keyword = o.ct_keyword;
		o.ct_keyword = nullptr;
		break;
	case midb_cond::header:
		ct_headers[0] = o.ct_headers[0];
		ct_headers[1] = o.ct_headers[1];
		o.ct_headers[0] = o.ct_headers[1] = nullptr;
		break;
	case midb_cond::before ... midb_cond::since:
		ct_time = o.ct_time;
		break;
	case midb_cond::larger ... midb_cond::smaller:
		ct_size = o.ct_size;
		break;
	default:
		break;
	}
	o.condition = midb_cond::x_none;
}

ct_node::~ct_node()
{
	if (pbranch != nullptr)
		return;
	switch (condition) {
	case midb_cond::bcc ... midb_cond::unkeyword:
		free(ct_keyword);
		break;
	case midb_cond::id ... midb_cond::uid:
		delete ct_seq;
		break;
	case midb_cond::header:
		free(ct_headers[0]);
		free(ct_headers[1]);
		break;
	default:
		break;
	}
}

static enum midb_cond cond_str_to_cond(const char *s)
{
#define E(kw) if (strcasecmp(s, #kw) == 0) return midb_cond::kw
#define E2(a, kw) if (strcasecmp(s, #a) == 0) return midb_cond::kw
	E(all);
	E(answered);
	E(bcc);
	E(before);
	E(body);
	E(cc);
	E(deleted);
	E(draft);
	E(flagged);
	E(from);
	E(header);
	E(id);
	E(keyword);
	E(larger);
	E2(new, is_new);
	E(old);
	E(on);
	E(recent);
	E(seen);
	E2(sentbefore, sent_before);
	E2(senton, sent_on);
	E2(sentsince, sent_since);
	E(since);
	E(smaller);
	E(subject);
	E(text);
	E(to);
	E(uid);
	E(unanswered);
	E(undeleted);
	E(undraft);
	E(unflagged);
	E(unkeyword);
	E(unseen);
#undef E2
#undef E
	return midb_cond::x_none;
}

static std::unique_ptr<CONDITION_TREE> mail_engine_ct_build_internal(
    const char *charset, int argc, char **argv) try
{
	static constexpr const char *kwlist1[] =
		{"BCC", "BODY", "CC", "FROM", "KEYWORD", "SUBJECT", "TEXT",
		"TO", "UNKEYWORD"};
	static constexpr const char *kwlist2[] =
		{"BEFORE", "ON", "SENTBEFORE", "SENTON", "SENTSINCE", "SINCE"};
	static constexpr const char *kwlist3[] =
		{"ALL", "ANSWERED", "DELETED", "DRAFT", "FLAGGED", "NEW",
		"OLD", "RECENT", "SEEN", "UNANSWERED", "UNDELETED", "UNDRAFT",
		"UNFLAGGED", "UNSEEN"};
	int i, len;
	int tmp_argc;
	int tmp_argc1;
	struct tm tmp_tm;
	char* tmp_argv[256];
	auto plist = std::make_unique<CONDITION_TREE>();

	for (i=0; i<argc; i++) {
		ct_node ctn, *ptree_node = &ctn;
		ptree_node->pbranch = NULL;
		if (0 == strcasecmp(argv[i], "NOT")) {
			ptree_node->conjunction = midb_conj::c_not;
			i ++;
			if (i >= argc)
				return {};
		} else {
			ptree_node->conjunction = midb_conj::c_and;
		}
		if (array_find_istr(kwlist1, argv[i])) {
			ptree_node->condition = cond_str_to_cond(argv[i]);
			i ++;
			if (i + 1 > argc)
				return {};
			ptree_node->ct_keyword = mail_engine_ct_to_utf8(charset, argv[i]).release();
			if (ptree_node->ct_keyword == nullptr)
				return {};
		} else if (array_find_istr(kwlist2, argv[i])) {
			if (i + 1 > argc)
				return {};
			ptree_node->condition = cond_str_to_cond(argv[i]);
			i ++;
			if (i + 1 > argc)
				return {};
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			if (strptime(argv[i], "%d-%b-%Y", &tmp_tm) == nullptr)
				return {};
			ptree_node->ct_time = mktime(&tmp_tm);
		} else if ('(' == argv[i][0]) {
			len = strlen(argv[i]);
			argv[i][len - 1] = '\0';
			tmp_argc = parse_imap_args(argv[i] + 1,
				len - 2, tmp_argv, sizeof(tmp_argv));
			if (tmp_argc == -1)
				return {};
			auto plist1 = mail_engine_ct_build_internal(
						charset, tmp_argc, tmp_argv);
			if (plist1 == nullptr)
				return {};
			ptree_node->pbranch = plist1.release();
		} else if (0 == strcasecmp(argv[i], "OR")) {
			i ++;
			if (i + 1 > argc)
				return {};
			tmp_argc = mail_engine_ct_compile_criteria(argc, argv, i, tmp_argv);
			if (tmp_argc == -1)
				return {};
			i += tmp_argc;
			if (i + 1 > argc)
				return {};
			tmp_argc1 = mail_engine_ct_compile_criteria(
					argc, argv, i, tmp_argv + tmp_argc);
			if (tmp_argc1 == -1)
				return {};
			auto plist1 = mail_engine_ct_build_internal(charset,
							tmp_argc + tmp_argc1, tmp_argv);
			if (plist1 == nullptr)
				return {};
			if (plist1->size() != 2)
				return {};
			auto &ln = plist1->back();
			ln.conjunction = midb_conj::c_or;
			ln.pbranch = plist1.release();
			i += tmp_argc1 - 1;
		} else if (array_find_istr(kwlist3, argv[i])) {
			ptree_node->condition = cond_str_to_cond(argv[i]);
		} else if (0 == strcasecmp(argv[i], "HEADER")) {
			ptree_node->condition = midb_cond::header;
			i ++;
			if (i + 1 > argc)
				return {};
			ptree_node->ct_headers[0] = strdup(argv[i]);
			i ++;
			if (i + 1 > argc)
				return {};
			ptree_node->ct_headers[1] = strdup(argv[i]);
		} else if (0 == strcasecmp(argv[i], "LARGER") ||
			0 == strcasecmp(argv[i], "SMALLER")) {
			ptree_node->condition = strcasecmp(argv[i], "LARGER") == 0 ?
			                        midb_cond::larger : midb_cond::smaller;
			i ++;
			if (i + 1 > argc)
				return {};
			ptree_node->ct_size = strtol(argv[i], nullptr, 0);
		} else if (0 == strcasecmp(argv[i], "UID")) {
			ptree_node->condition = midb_cond::uid;
			i ++;
			if (i + 1 > argc)
				return {};
			auto r = std::make_unique<imap_seq_list>();
			if (parse_imap_seq(*r, argv[i]) != 0)
				return {};
			ptree_node->ct_seq = r.release();
		} else {
			auto r = std::make_unique<imap_seq_list>();
			if (parse_imap_seq(*r, argv[i]) != 0)
				return {};
			ptree_node->condition = midb_cond::id;
			ptree_node->ct_seq = r.release();
		}
		plist->push_back(std::move(ctn));
	}
	return plist;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1971: ENOMEM");
	return {};
}

static std::unique_ptr<CONDITION_TREE> mail_engine_ct_build(int argc, char **argv)
{
	if (strcasecmp(argv[0], "CHARSET") != 0)
		return mail_engine_ct_build_internal("UTF-8", argc, argv);
	if (argc < 3)
		return {};
	return mail_engine_ct_build_internal(argv[1], argc - 2, argv + 2);
}

static bool ct_hint_seq(const imap_seq_list &list,
    unsigned int num, unsigned int max_uid)
{
	for (const auto &seq : list) {
		if (seq.hi == SEQ_STAR) {
			if (seq.lo == SEQ_STAR) {
				if (num == max_uid)
					return true;
			} else {
				if (num >= seq.lo)
					return true;
			}
		} else {
			if (seq.hi >= num && seq.lo <= num)
				return true;
		}
	}
	return false;
}

static std::optional<std::vector<int>> mail_engine_ct_match(const char *charset,
    sqlite3 *psqlite, uint64_t folder_id, const CONDITION_TREE *ptree,
    BOOL b_uid) try
{
	uint32_t uid;
	uint32_t uidnext;
	char sql_string[1024];

	snprintf(sql_string, std::size(sql_string), "SELECT count(message_id) "
	          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return {};
	auto total_mail = pstmt.col_uint64(0);
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT uidnext FROM"
	          " folders WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return {};
	uidnext = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	/* Match this column list to ctm_field */
	auto pstmt_message = gx_sql_prep(psqlite, "SELECT message_id, mod_time, "
	                     "uid, recent, read, unsent, flagged, replied, forwarded,"
	                     "deleted, received, folder_id, size FROM messages "
	                     "WHERE mid_string=?");
	if (pstmt_message == nullptr)
		return {};
	snprintf(sql_string, std::size(sql_string), "SELECT mid_string, uid FROM "
	          "messages WHERE folder_id=%llu ORDER BY uid", LLU{folder_id});
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return {};
	std::optional<std::vector<int>> presult;
	presult.emplace();
	for (size_t i = 1; pstmt.step() == SQLITE_ROW; ++i) {
		auto mid_string = pstmt.col_text(0);
		uid = sqlite3_column_int64(pstmt, 1);
		if (mail_engine_ct_match_mail(psqlite, charset, pstmt_message,
		    mid_string, i, total_mail, uidnext, ptree))
			presult->push_back(b_uid ? uid : i);
	}
	return presult;
} catch (const std::bad_alloc &) {
	return {};
}

static uint64_t me_get_folder_id_raw(IDB_ITEM *pidb, std::string_view name)
{
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT "
	             "folder_id FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return 0;
	pstmt.bind_text(1, name);
	return pstmt.step() != SQLITE_ROW ? 0 :
	       sqlite3_column_int64(pstmt, 0);
}

static uint64_t mail_engine_get_folder_id(IDB_ITEM *pidb, std::string_view name)
{
	return me_get_folder_id_raw(pidb, base64_decode(name));
}

static void mail_engine_extract_digest_fields(const Json::Value &digest, char *subject,
    size_t subjsize, char *from, size_t fromsize, char *rcpt, size_t rcptsize,
    size_t *psize)
{
	size_t out_len;
	char temp_buff[64*1024];
	char temp_buff1[64*1024];
	
	subject[0] = '\0';
	if (get_digest(digest, "subject", temp_buff, std::size(temp_buff)) &&
	    decode64(temp_buff, strlen(temp_buff), subject, subjsize, &out_len) != 0)
		/* Decode failed */
		subject[0] = '\0';
	from[0] = '\0';
	if (get_digest(digest, "from", temp_buff, std::size(temp_buff)) &&
	    decode64(temp_buff, strlen(temp_buff), temp_buff1,
	    std::size(temp_buff1), &out_len) == 0) {
		EMAIL_ADDR temp_address(temp_buff1);
		gx_strlcpy(from, temp_address.addr, fromsize);
	}
	rcpt[0] = '\0';
	if (get_digest(digest, "to", temp_buff, std::size(temp_buff)) &&
	    decode64(temp_buff, strlen(temp_buff), temp_buff1,
	    std::size(temp_buff1), &out_len) == 0) {
		for (size_t i = 0; i < out_len; ++i) {
			if (',' == temp_buff1[i] ||
			    ';' == temp_buff1[i]) {
				temp_buff1[i] = '\0';
				break;
			}
		}
		HX_strrtrim(temp_buff1);
		EMAIL_ADDR temp_address(temp_buff1);
		gx_strlcpy(rcpt, temp_address.addr, rcptsize);
	}
	*psize = 0;
	if (get_digest(digest, "size", temp_buff, std::size(temp_buff)))
		*psize = strtoull(temp_buff, nullptr, 0);
}

static void mail_engine_insert_message(sqlite3_stmt *pstmt, uint32_t *puidnext,
    uint64_t message_id, const char *mid_string, uint32_t message_flags,
    uint64_t received_time, uint64_t mod_time) try
{
	size_t size;
	char from[UADDR_SIZE], rcpt[UADDR_SIZE];
	const char *dir;
	char subject[1024];
	char temp_path[256];
	char temp_path1[256];
	char mid_string1[128];
	MESSAGE_CONTENT *pmsgctnt;
	
	temp_path[0] = '\0';
	temp_path1[0] = '\0';
	dir = common_util_get_maildir();
	std::string djson;
	if (NULL != mid_string) {
		sprintf(temp_path, "%s/ext/%s", dir, mid_string);
		size_t slurp_size = 0;
		std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_file(temp_path, &slurp_size));
		if (slurp_data == nullptr)
			mid_string = nullptr;
		else
			djson.assign(slurp_data.get(), slurp_size);
	}
	if (mid_string == nullptr) {
		if (!common_util_switch_allocator())
			return;
		if (!exmdb_client::read_message(dir, nullptr, CP_ACP,
			rop_util_make_eid_ex(1, message_id), &pmsgctnt)) {
			common_util_switch_allocator();
			mlog(LV_ERR, "E-2394: read_message(%s,%llu) EXRPC failed",
				dir, LLU{message_id});
			return;
		}
		if (NULL == pmsgctnt) {
			common_util_switch_allocator();
			mlog(LV_ERR, "E-2398: read_message(%s,%llu) EXRPC: no message by this id",
				dir, LLU{message_id});
			return;
		}
		auto log_id = dir + ":m"s + std::to_string(message_id);
		MAIL imail;
		if (!oxcmail_export(pmsgctnt, log_id.c_str(), false,
		    oxcmail_body::plain_and_html, &imail, common_util_alloc,
		    common_util_get_propids, common_util_get_propname)) {
			mlog(LV_ERR, "E-1222: oxcmail_export %s failed", log_id.c_str());
			common_util_switch_allocator();
			return;
		}
		common_util_switch_allocator();
		Json::Value digest;
		if (imail.make_digest(&size, digest) <= 0)
			return;
		digest["file"] = "";
		djson = json_to_str(digest);
		snprintf(mid_string1, std::size(mid_string1), "%lld.%u.midb",
		         static_cast<long long>(time(nullptr)), ++g_sequence_id);
		mid_string = mid_string1;
		sprintf(temp_path, "%s/ext/%s", dir, mid_string1);
		wrapfd fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
		if (fd.get() < 0) {
			mlog(LV_ERR, "E-1770: open %s for write: %s", temp_path, strerror(errno));
			return;
		}
		if (HXio_fullwrite(fd.get(), djson.c_str(), djson.size()) < 0 ||
		    fd.close_wr() != 0) {
			mlog(LV_ERR, "E-1134: write %s: %s", temp_path, strerror(errno));
			return;
		}
		sprintf(temp_path1, "%s/eml/%s", dir, mid_string1);
		fd = open(temp_path1, O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
		if (fd.get() < 0) {
			mlog(LV_ERR, "E-1771: open %s for write: %s", temp_path, strerror(errno));
			return;
		}
		auto err = imail.to_fd(fd.get());
		if (err == 0)
			err = fd.close_wr();
		if (err != 0) {
			mlog(LV_ERR, "E-1772: to_file %s failed: %s", temp_path, strerror(err));
			return;
		}
	}
	(*puidnext) ++;
	auto b_unsent = !!(message_flags & MSGFLAG_UNSENT);
	auto b_read   = !!(message_flags & MSGFLAG_READ);
	Json::Value digest;
	if (!json_from_str(djson.c_str(), digest))
		return;
	djson.clear();
	mail_engine_extract_digest_fields(digest, subject,
		std::size(subject), from, std::size(from), rcpt,
		std::size(rcpt), &size);
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, message_id);
	sqlite3_bind_text(pstmt, 2, mid_string, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 3, mod_time);
	sqlite3_bind_int64(pstmt, 4, *puidnext);
	sqlite3_bind_int64(pstmt, 5, b_unsent);
	sqlite3_bind_int64(pstmt, 6, b_read);
	sqlite3_bind_text(pstmt, 7, subject, -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 8, from, -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 9, rcpt, -1, SQLITE_STATIC);
	sqlite3_bind_int64(pstmt, 10, size);
	sqlite3_bind_int64(pstmt, 11, received_time);
	if (gx_sql_step(pstmt) != SQLITE_DONE)
		mlog(LV_ERR, "E-2075: sqlite_step not finished");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1137: ENOMEM");
}

static void mail_engine_sync_message(IDB_ITEM *pidb,
	sqlite3_stmt *pstmt, sqlite3_stmt *pstmt1, uint32_t *puidnext,
	uint64_t message_id, uint64_t received_time, const char *mid_string,
	const char *mid_string1, uint64_t mod_time, uint64_t mod_time1,
	uint32_t message_flags, uint8_t b_unsent, uint8_t b_read)
{
	char sql_string[256];
	
	if (NULL != mid_string || mod_time <= mod_time1) {
		auto b_unsent1 = !!(message_flags & MSGFLAG_UNSENT);
		auto b_read1   = !!(message_flags & MSGFLAG_READ);
		if (b_unsent != b_unsent1 || b_read != b_read1) {
			sqlite3_reset(pstmt1);
			sqlite3_bind_int64(pstmt1, 1, b_unsent1);
			sqlite3_bind_int64(pstmt1, 2, b_read1);
			sqlite3_bind_int64(pstmt1, 3, message_id);
			if (gx_sql_step(pstmt1) != SQLITE_DONE)
				return;
		}
		return;
	}
	snprintf(sql_string, std::size(sql_string), "DELETE FROM messages"
	        " WHERE message_id=%llu", LLU{message_id});
	if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
		return;	
	mail_engine_insert_message(pstmt, puidnext, message_id,
			NULL, message_flags, received_time, mod_time);
}

static BOOL mail_engine_sync_contents(IDB_ITEM *pidb, uint64_t folder_id) try
{
	const char *dir;
	TARRAY_SET rows;
	uint32_t uidnext;
	uint32_t uidnext1;
	char sql_string[1024];
	
	dir = common_util_get_maildir();
	mlog(LV_NOTICE, "Running sync_contents for %s, folder %llu",
	        dir, LLU{folder_id});

	{
		uint32_t table_id = 0, row_count = 0;
		if (!exmdb_client::load_content_table(dir, CP_ACP,
		    rop_util_make_eid_ex(1, folder_id), nullptr, TABLE_FLAG_NONOTIFICATIONS,
		    nullptr, nullptr, &table_id, &row_count))
			return false;
		auto cl_0 = make_scope_exit([&]() { exmdb_client::unload_table(dir, table_id); });
		static constexpr uint32_t proptags_0[] = {
			PidTagMid, PR_MESSAGE_FLAGS, PR_LAST_MODIFICATION_TIME,
			PR_MESSAGE_DELIVERY_TIME, PidTagMidString,
		};
		static constexpr PROPTAG_ARRAY proptags_1 = {std::size(proptags_0), deconst(proptags_0)};
		if (!exmdb_client::query_table(dir, nullptr, CP_ACP, table_id,
		    &proptags_1, 0, row_count, &rows))
			return false;
	}

	snprintf(sql_string, std::size(sql_string), "SELECT uidnext FROM"
	          " folders WHERE folder_id=%llu", LLU{folder_id});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (pstmt.step() != SQLITE_ROW)
		return TRUE;
	uidnext = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	uidnext1 = uidnext;

	syncmessage_list syncmessagelist;
	for (size_t i = 0; i < rows.count; ++i) {
		auto num = rows.pparray[i]->get<const uint64_t>(PidTagMid);
		if (num == nullptr)
			continue;
		auto message_id = rop_util_get_gc_value(*num);
		auto flags = rows.pparray[i]->get<uint32_t>(PR_MESSAGE_FLAGS);
		if (flags == nullptr)
			continue;
		*flags &= ~(MSGFLAG_HASATTACH | MSGFLAG_FROMME | MSGFLAG_ASSOCIATED |
		          MSGFLAG_RN_PENDING | MSGFLAG_NRN_PENDING);
		auto mod_time = rows.pparray[i]->get<uint64_t>(PR_LAST_MODIFICATION_TIME);
		auto recv_time = rows.pparray[i]->get<uint64_t>(PR_MESSAGE_DELIVERY_TIME);
		auto midstr = rows.pparray[i]->get<const char>(PidTagMidString);
		syncmessagelist.emplace(message_id, syncmessage_entry{
			mod_time != nullptr ? *mod_time : 0,
			recv_time != nullptr ? *recv_time : 0,
			*flags, midstr != nullptr, znul(midstr)
		});
	}

	size_t totalmsgs = syncmessagelist.size(), procmsgs = 0;
	auto pstmt1 = gx_sql_prep(pidb->psqlite, "SELECT message_id, mid_string,"
	              " mod_time, unsent, read FROM messages WHERE message_id=?");
	if (pstmt1 == nullptr)
		return FALSE;
	snprintf(sql_string, std::size(sql_string), "INSERT INTO messages (message_id, "
		"folder_id, mid_string, mod_time, uid, unsent, read, subject,"
		" sender, rcpt, size, received) VALUES (?, %llu, ?, ?, ?, ?, "
		"?, ?, ?, ?, ?, ?)", LLU{folder_id});
	auto pstmt2 = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt2 == nullptr)
		return FALSE;
	auto stm_upd_msg = gx_sql_prep(pidb->psqlite, "UPDATE messages"
	              " SET unsent=?, read=? WHERE message_id=?");
	if (stm_upd_msg == nullptr)
		return FALSE;
	for (const auto &[message_id, entry] : syncmessagelist) {
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, message_id);
		if (pstmt1.step() != SQLITE_ROW)
			mail_engine_insert_message(
				pstmt2, &uidnext, message_id,
				entry.has_midstr ? entry.midstr.c_str() : nullptr,
				entry.msg_flags, entry.recv_time, entry.mod_time);
		else
			mail_engine_sync_message(pidb,
				pstmt2, stm_upd_msg, &uidnext, message_id,
				entry.recv_time,
				entry.has_midstr ? entry.midstr.c_str() : nullptr,
				pstmt1.col_text(1),
				entry.mod_time,
				sqlite3_column_int64(pstmt1, 2),
				entry.msg_flags,
				sqlite3_column_int64(pstmt1, 3),
				sqlite3_column_int64(pstmt1, 4));
		if (++procmsgs % 512 == 0)
			mlog(LV_NOTICE, "sync_contents %s fld %llu progress: %zu/%zu",
			        dir, LLU{folder_id}, procmsgs, totalmsgs);
	}
	if (procmsgs > 512)
		/* display final value */
			mlog(LV_NOTICE, "sync_contents %s fld %llu progress: %zu/%zu",
			        dir, LLU{folder_id}, procmsgs, totalmsgs);
	pstmt1.finalize();
	pstmt2.finalize();
	stm_upd_msg.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT message_id FROM "
	          "messages WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;

	std::vector<uint64_t> temp_list;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t message_id = sqlite3_column_int64(pstmt, 0);
		if (syncmessagelist.find(message_id) == syncmessagelist.cend())
			temp_list.push_back(message_id);
	}
	pstmt.finalize();
	if (temp_list.size() > 0) {
		pstmt = gx_sql_prep(pidb->psqlite, "DELETE "
		        "FROM messages WHERE message_id=?");
		if (pstmt == nullptr)
			return FALSE;
		for (auto id : temp_list) {
			sqlite3_reset(pstmt);
			pstmt.bind_int64(1, id);
			if (pstmt.step() != SQLITE_DONE)
				return FALSE;
		}
		pstmt.finalize();
	}
	if (uidnext != uidnext1) {
		snprintf(sql_string, std::size(sql_string), "UPDATE folders SET uidnext=%u "
		        "WHERE folder_id=%llu", uidnext, LLU{folder_id});
		if (gx_sql_exec(pidb->psqlite, sql_string) != SQLITE_OK)
			return FALSE;
	}
	snprintf(sql_string, std::size(sql_string), "UPDATE folders SET sort_field=%d "
	        "WHERE folder_id=%llu", FIELD_NONE, LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1208: ENOMEM");
	return false;
}

/**
 * @pstmt:        prepared statement for lookup of folder names
 *                (re-uses in-memory copy of folder list)
 * @folder_id:    inspect this folder
 * @encoded_name: folder path; encoded for use within midb
 */
static BOOL mail_engine_get_encoded_name(const syncfolder_list &map,
    uint64_t folder_id, std::string &encoded_name) try
{
	std::vector<std::string> temp_list;
	do {
		auto it = map.find(folder_id);
		if (it == map.cend())
			return FALSE;
		folder_id = it->second.parent_fid;
		temp_list.emplace_back(it->second.display_name);
	} while (PRIVATE_FID_IPMSUBTREE != folder_id);
	std::reverse(temp_list.begin(), temp_list.end());
	encoded_name.clear();
	for (auto &&name : temp_list) {
		if (!encoded_name.empty())
			encoded_name += '/';
		encoded_name += std::move(name);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1207: ENOMEM");
	return false;
}

static uint64_t mail_engine_get_top_folder_id(const syncfolder_list &map,
    uint64_t folder_id)
{
	while (true) {
		auto it = map.find(folder_id);
		if (it == map.cend())
			return 0;
		if (it->second.parent_fid == PRIVATE_FID_IPMSUBTREE)
			return folder_id;
		folder_id = it->second.parent_fid;
	}
}

static inline bool ipf_note(const char *c)
{
	return c == nullptr || class_match_prefix(c, "IPF.Note") == 0;
}

static BOOL mail_engine_sync_mailbox(IDB_ITEM *pidb,
    bool force_resync = false) try
{
	auto dir = common_util_get_maildir();
	mlog(LV_NOTICE, "Running sync_mailbox for %s", dir);
	auto cl_err = make_scope_exit([&]() {
		mlog(LV_NOTICE, "sync_mailbox aborted for %s", dir);
	});
	unsigned int table_id = 0, row_count = 0;
	if (!exmdb_client::load_hierarchy_table(dir,
	    rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE),
	    NULL, TABLE_FLAG_DEPTH|TABLE_FLAG_NONOTIFICATIONS,
	    NULL, &table_id, &row_count))
		return FALSE;	

	static constexpr proptag_t proptag_buff[] =
		{PidTagFolderId, PidTagParentFolderId, PR_ATTR_HIDDEN,
		PR_CONTAINER_CLASS, PR_DISPLAY_NAME, PR_LOCAL_COMMIT_TIME_MAX};
	static constexpr PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	TARRAY_SET rows{};
	if (!exmdb_client::query_table(dir, NULL,
	    CP_ACP, table_id, &proptags, 0, row_count, &rows)) {
		exmdb_client::unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client::unload_table(dir, table_id);

	/*
	 * Step 1: Avoid making too many exmdb requests and just take a
	 * "snapshot" of the entire folder list for faster lookup. The folder
	 * list remains "flat" in the sense that we remember PR_DISPLAY_NAME
	 * and not PR_FOLDER_PATH.
	 */
	syncfolder_list syncfolderlist;
	for (size_t i = 0; i < rows.count; ++i) {
		auto num = rows.pparray[i]->get<const uint64_t>(PidTagFolderId);
		if (num == nullptr)
			continue;
		auto folder_id = rop_util_get_gc_value(*num);
		auto flag = rows.pparray[i]->get<const uint8_t>(PR_ATTR_HIDDEN);
		if (flag != nullptr && *flag != 0) {
			mlog(LV_NOTICE, "sync_mailbox %s fld %llu skipped: PR_ATTR_HIDDEN=1",
			        dir, LLU{folder_id});
			continue;
		}
		if (!ipf_note(rows.pparray[i]->get<const char>(PR_CONTAINER_CLASS))) {
			mlog(LV_NOTICE, "sync_mailbox %s fld %llu skipped: PR_CONTAINER_CLASS not IPF.Note",
			        dir, LLU{folder_id});
			continue;
		}
		num = rows.pparray[i]->get<uint64_t>(PidTagParentFolderId);
		if (num == nullptr)
			continue;
		auto parent_fid = rop_util_get_gc_value(*num);
		num = rows.pparray[i]->get<uint64_t>(PR_LOCAL_COMMIT_TIME_MAX);
		syncfolder_entry entry = {parent_fid, num != nullptr ? *num : 0};
		if (folder_id == PRIVATE_FID_INBOX) {
			entry.display_name = "INBOX";
		} else {
			auto str = rows.pparray[i]->get<char>(PR_DISPLAY_NAME);
			if (str == nullptr || strlen(str) >= 256)
				continue;
			entry.display_name = str;
			if (parent_fid == PRIVATE_FID_IPMSUBTREE &&
			    strncasecmp(str, "inbox", 5) == 0)
				entry.display_name += "."s + std::to_string(folder_id);
		}
		syncfolderlist.emplace(folder_id, std::move(entry));
	}

	/* syncfolderlist is now complete and can be used to construct pathnames */

	{
	auto pidb_transact = gx_sql_begin(pidb->psqlite, txn_mode::write);
	if (!pidb_transact)
		return false;

	/*
	 * rename all folders to temporary names so that there
	 * is no conflict when adding any new folders' names
	 * (name column is set to UNIQUE)
	 */
	auto ret = gx_sql_exec(pidb->psqlite, "UPDATE folders SET name=CONCAT('t',ROWID)");
	if (ret != SQLITE_OK)
		/* ignore */;

	/*
	 * Step 2: Now iterate over the in-memory folder list and synchronize
	 * contents from exmdb to midb.
	 */
	auto pstmt1 = gx_sql_prep(pidb->psqlite, "SELECT folder_id, parent_fid, "
	              "commit_max, name FROM folders WHERE folder_id=?");
	if (pstmt1 == nullptr)
		return false;
	auto pstmt2 = gx_sql_prep(pidb->psqlite, "INSERT INTO folders (folder_id, "
				"parent_fid, commit_max, name) VALUES (?, ?, ?, ?)");
	if (pstmt2 == nullptr)
		return false;
	for (const auto &[folder_id, entry] : syncfolderlist) {
		switch (mail_engine_get_top_folder_id(syncfolderlist, folder_id)) {
		case PRIVATE_FID_OUTBOX:
		case PRIVATE_FID_SYNC_ISSUES:
			continue;			
		}
		const auto &parent_fid = entry.parent_fid;
		const auto &commit_max = entry.commit_max;
		std::string encoded_name;
		if (!mail_engine_get_encoded_name(syncfolderlist, folder_id, encoded_name))
			continue;
		sqlite3_reset(pstmt1);
		sqlite3_bind_int64(pstmt1, 1, folder_id);

		bool b_new = false;
		if (pstmt1.step() != SQLITE_ROW) {
			sqlite3_reset(pstmt2);
			sqlite3_bind_int64(pstmt2, 1, folder_id);
			sqlite3_bind_int64(pstmt2, 2, parent_fid);
			sqlite3_bind_int64(pstmt2, 3, commit_max);
			pstmt2.bind_text(4, encoded_name);
			auto rx = pstmt2.step();
			if (rx == SQLITE_CONSTRAINT) {
				mlog(LV_ERR, "E-1224: XXX: Not implemented: midb is unable to cope with folder deletions that occurred while midb was not connected to exmdb");
				return false;
			} else if (rx != SQLITE_DONE) {
				/* step() will already log */
				return false;
			}
			b_new = true;
		} else {
			if (gx_sql_col_uint64(pstmt1, 1) != parent_fid) {
				auto qstr = fmt::format("UPDATE folders SET "
					"parent_fid={} WHERE folder_id={}",
					parent_fid, folder_id);
				gx_sql_exec(pidb->psqlite, qstr.c_str());
			}
			if (strcmp(encoded_name.c_str(), pstmt1.col_text(3)) != 0) {
				auto ust = gx_sql_prep(pidb->psqlite, "UPDATE folders SET name=? "
				           "WHERE folder_id=?");
				if (ust == nullptr ||
				    ust.bind_text(1, encoded_name) != SQLITE_OK ||
				    ust.bind_int64(2, folder_id) != SQLITE_OK ||
				    ust.step() != SQLITE_DONE)
					/* ignore */;
			}
			if (gx_sql_col_uint64(pstmt1, 2) == commit_max && !force_resync)
				continue;	
		}
		if (!mail_engine_sync_contents(pidb, folder_id))
			return false;
		if (!b_new) {
			auto qstr = fmt::format("UPDATE folders SET commit_max={}"
			        " WHERE folder_id={}", commit_max, folder_id);
			gx_sql_exec(pidb->psqlite, qstr.c_str());
		}
	}
	pstmt1.finalize();
	pstmt2.finalize();

	/*
	 * Step 3: Loop over all folders in midb.sqlite3 and see if some
	 * are gone (synchronize deletions).
	 */
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id FROM folders");
	if (pstmt == nullptr)
		return false;

	std::vector<uint64_t> temp_list;
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t folder_id = sqlite3_column_int64(pstmt, 0);
		if (syncfolderlist.find(folder_id) == syncfolderlist.cend())
			temp_list.push_back(folder_id);
	}
	pstmt.finalize();
	if (temp_list.size() > 0) {
		pstmt = gx_sql_prep(pidb->psqlite, "DELETE"
		        " FROM folders WHERE folder_id=?");
		if (pstmt == nullptr)
			return false;
		for (auto id : temp_list) {
			sqlite3_reset(pstmt);
			pstmt.bind_int64(1, id);
			if (pstmt.step() != SQLITE_DONE)
				return false;
		}
		pstmt.finalize();
	}
	if (pidb_transact.commit() != SQLITE_OK)
		return false;
	}
	cl_err.release();
	if (!exmdb_client::subscribe_notification(dir,
	    NF_OBJECT_CREATED | NF_OBJECT_DELETED | NF_OBJECT_MODIFIED |
	    NF_OBJECT_MOVED | NF_OBJECT_COPIED | NF_NEW_MAIL, TRUE,
	    0, 0, &pidb->sub_id))
		pidb->sub_id = 0;	
	pidb->load_time = time(nullptr);
	mlog(LV_NOTICE, "Ended sync_mailbox for %s", dir);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1206: ENOMEM");
	return false;
}

static IDB_REF mail_engine_peek_idb(const char *path)
{
	std::unique_lock hhold(g_hash_lock);
	auto it = g_hash_table.find(path);
	if (it == g_hash_table.end())
		return {};
	auto pidb = &it->second;
	pidb->reference ++;
	hhold.unlock();
	pidb->giant_lock.lock();
	if (pidb->psqlite != nullptr)
		return IDB_REF(pidb);
	pidb->last_time = 0;
	pidb->giant_lock.unlock();
	hhold.lock();
	pidb->reference --;
	hhold.unlock();
	return {};
}

static int mail_engine_autoupgrade(sqlite3 *db, const char *filedesc)
{
	if (g_midb_schema_upgrades == MIDB_UPGRADE_NO)
		return 0;
	auto recent = dbop_sqlite_recentversion(sqlite_kind::midb);
	auto current = dbop_sqlite_schemaversion(db, sqlite_kind::midb);
	if (current < 0) {
		mlog(LV_ERR, "dbop_sqlite: %s: impossible to determine schemaversion", filedesc);
		return -1;
	}
	if (current >= recent)
		return 0;
	mlog(LV_NOTICE, "dbop_sqlite: %s: current schema EM-%d; upgrading to EM-%d.",
		filedesc, current, recent);
	auto ret = dbop_sqlite_upgrade(db, filedesc, sqlite_kind::midb, DBOP_VERBOSE);
	if (ret != 0) {
		mlog(LV_NOTICE, "dbop_sqlite upgrade %s: %s",
		        filedesc, strerror(-ret));
		return -1;
	}
	mlog(LV_NOTICE, "dbop_sqlite: upgrade %s: complete", filedesc);
	return 0;
}

static IDB_REF mail_engine_get_idb(const char *path, bool force_resync = false)
{
	BOOL b_load;
	char temp_path[256];
	
	b_load = FALSE;
	std::unique_lock hhold(g_hash_lock);
	if (g_hash_table.size() >= g_table_size) {
		mlog(LV_WARN, "W-1295: too many sqlites referenced at once (midb.cfg:table_size=%zu)", g_table_size);
		return {};
	}
	decltype(g_hash_table.try_emplace(path)) xp;
	try {
		xp = g_hash_table.try_emplace(path);
	} catch (const std::bad_alloc &) {
		hhold.unlock();
		mlog(LV_ERR, "E-1294: mail_engine_get_idb ENOMEM");
		return {};
	}
	auto pidb = &xp.first->second;
	if (xp.second) {
		sprintf(temp_path, "%s/exmdb/midb.sqlite3", path);
		auto ret = sqlite3_open_v2(temp_path, &pidb->psqlite, SQLITE_OPEN_READWRITE, nullptr);
		if (ret != SQLITE_OK) {
			g_hash_table.erase(xp.first);
			mlog(LV_ERR, "E-1438: sqlite3_open %s: %s", temp_path, sqlite3_errstr(ret));
			return {};
		}
		ret = mail_engine_autoupgrade(pidb->psqlite, temp_path);
		if (ret != 0) {
			sqlite3_close(pidb->psqlite);
			pidb->psqlite = nullptr;
			return {};
		}
		gx_sql_exec(pidb->psqlite, "PRAGMA foreign_keys=ON");
		gx_sql_exec(pidb->psqlite, "PRAGMA journal_mode=WAL");
		gx_sql_exec(pidb->psqlite, "DELETE FROM mapping");
		/* Delete obsolete field (old midb versions cannot use the db then however) */
		// gx_sql_exec(pidb->psqlite, "DELETE FROM configurations WHERE config_id=1");

		try {
			unsigned int user_id = 0;
			pidb->username.resize(UADDR_SIZE);
			if (!system_services_get_id_from_maildir(path, &user_id) ||
			    !system_services_get_username_from_id(user_id, pidb->username.data(), pidb->username.size())) {
				g_hash_table.erase(xp.first);
				mlog(LV_ERR, "E-2400: user for path %s not found", path);
				return {};
			}
			pidb->username.resize(strlen(pidb->username.c_str()));
		} catch (const std::bad_alloc &) {
			g_hash_table.erase(xp.first);
			mlog(LV_ERR, "E-2401: ENOMEM");
			return {};
		}
		b_load = TRUE;
	} else if (pidb->reference > MAX_DB_WAITING_THREADS) {
		hhold.unlock();
		mlog(LV_ERR, "E-2402: mail_engine: there are already %u threads waiting on %s",
			MAX_DB_WAITING_THREADS, path);
		return {};
	}
	pidb->reference ++;
	hhold.unlock();
	if (!pidb->giant_lock.try_lock_for(DB_LOCK_TIMEOUT)) {
		hhold.lock();
		pidb->reference --;
		hhold.unlock();
		mlog(LV_ERR, "E-2403: mail_engine: timed out obtaining a reference on %s", path);
		return {};
	}
	if (b_load || force_resync) {
		mail_engine_sync_mailbox(pidb, force_resync);
	} else if (pidb->psqlite == nullptr) {
		pidb->last_time = 0;
		pidb->giant_lock.unlock();
		hhold.lock();
		pidb->reference--;
		hhold.unlock();
		mlog(LV_ERR, "E-2404: sqlite object went away on %s, retry", path);
		return {};
	}
	return IDB_REF(pidb);
}

void idb_item_del::operator()(IDB_ITEM *pidb)
{
	pidb->last_time = time(nullptr);
	pidb->giant_lock.unlock();
	std::lock_guard hhold(g_hash_lock);
	pidb->reference --;
}

IDB_ITEM::~IDB_ITEM()
{
	if (psqlite != nullptr)
		sqlite3_close(psqlite);
}

static void *midbme_scanwork(void *param)
{
	int count;

	count = 0;
	while (!g_notify_stop) {
		std::vector<std::pair<std::string, uint32_t>> unsub_list;
		sleep(1);
		if (count < 10) {
			count ++;
			continue;
		}
		count = 0;
		std::unique_lock hhold(g_hash_lock);
		for (auto it = g_hash_table.begin(); it != g_hash_table.end(); ) {
			auto pidb = &it->second;
			auto now_time = time(nullptr);
			auto last_diff = now_time - pidb->last_time;
			auto load_diff = now_time - pidb->load_time;
			bool do_clean = pidb->reference == 0 &&
			             (pidb->sub_id == 0 ||
			             gromox::cmp_greater(last_diff, g_midb_cache_interval) ||
			             gromox::cmp_greater(load_diff, g_midb_reload_interval));
			if (!do_clean) {
				++it;
				continue;
			}
			if (pidb->sub_id != 0) try {
				unsub_list.emplace_back(it->first.c_str(), pidb->sub_id);
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1622: ENOMEM");
			}
			mlog(LV_INFO, "I-2175: Closing user %s midb.sqlite3 (sub=%u, c=%lld, l=%lld)",
			        pidb->username.c_str(), pidb->sub_id,
			        static_cast<long long>(last_diff),
			        static_cast<long long>(load_diff));
			it = g_hash_table.erase(it);
		}
		hhold.unlock();
		for (auto &&e : unsub_list) {
			if (common_util_build_environment(e.first.c_str())) {
				exmdb_client::unsubscribe_notification(e.first.c_str(), e.second);
				common_util_free_environment();
			}
		}
	}
	std::unique_lock hhold(g_hash_lock);
	for (auto it = g_hash_table.begin(); it != g_hash_table.end(); ) {
		auto pidb = &it->second;
		if (pidb->sub_id != 0 &&
		    common_util_build_environment(it->first.c_str())) {
			exmdb_client::unsubscribe_notification(it->first.c_str(), pidb->sub_id);
			common_util_free_environment();
		}
		it = g_hash_table.erase(it);
	}
	hhold.unlock();
	return nullptr;
}

/**
 * Reset the inactivity timer on midb.sqlite.
 *
 * Request:
 * 	M-PING <store-dir>
 * Response:
 * 	TRUE
 */
static int mail_engine_mping(int argc, char **argv, int sockd)
{
	mail_engine_get_idb(argv[1]);
	exmdb_client::ping_store(argv[1]);
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Emit the list of folders in the store. Special-use folders are not part of
 * the list as imapd will unconditionally list them.
 *
 * Request:
 * 	M-ENUM <store-dir>
 * Response:
 * 	TRUE <#folders>
 * 	<folder-id> <folder-name>  // repeat x #folders
 */
static int mail_engine_menum(int argc, char **argv, int sockd) try
{
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id, name FROM folders");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	size_t count = 0;
	std::string rsp;
	rsp.reserve(65536);
	while (pstmt.step() == SQLITE_ROW) {
		rsp += std::to_string(pstmt.col_uint64(0)) + " " +
		       base64_encode(pstmt.col_text(1)) + "\r\n"s;
		count ++;
	}
	pstmt.finalize();
	pidb.reset();
	rsp.insert(0, "TRUE " + std::to_string(count) + "\r\n");
	return cmd_write(sockd, rsp.c_str(), rsp.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2531: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Insert mail into exmdb and midb.sqlite.
 *
 * (Placement of eml/ in the filesystem needs to be done by midb user like
 * imapd ahead of the call.)
 *
 * Request:
 * 	M-INST <store-dir> <folder-name> <mid> <flags> <delivery-time>
 * Response:
 * 	TRUE
 */
static int mail_engine_minst(int argc, char **argv, int sockd) try
{
	size_t mess_len;
	uint32_t tmp_flags;
	char temp_path[256];
	uint64_t change_num;
	uint64_t message_id;
	char sql_string[1024];
	
	uint8_t b_unsent = strchr(argv[4], 'U') != nullptr;
	uint8_t b_read = strchr(argv[4], 'S') != nullptr;
	sprintf(temp_path, "%s/eml/%s", argv[1], argv[3]);
	size_t slurp_size = 0;
	std::unique_ptr<char[], stdlib_delete> pbuff(HX_slurp_file(temp_path, &slurp_size));
	if (pbuff == nullptr) {
		mlog(LV_ERR, "E-2071: read %s: %s", temp_path, strerror(errno));
		return errno == ENOMEM ? MIDB_E_NO_MEMORY : MIDB_E_DISK_ERROR;
	}

	MAIL imail;
	if (!imail.load_from_str_move(pbuff.get(), slurp_size))
		return MIDB_E_IMAIL_RETRIEVE;
	Json::Value digest;
	if (imail.make_digest(&mess_len, digest) <= 0)
		return MIDB_E_IMAIL_DIGEST;
	digest["file"] = "";
	auto djson = json_to_str(digest);
	sprintf(temp_path, "%s/ext/%s", argv[1], argv[3]);
	wrapfd fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, FMODE_PRIVATE);
	if (fd.get() < 0) {
		mlog(LV_ERR, "E-2073: Opening %s for writing failed: %s", temp_path, strerror(errno));
		return MIDB_E_DISK_ERROR;
	}
	if (HXio_fullwrite(fd.get(), djson.data(), djson.size()) < 0 ||
	    fd.close_wr() != 0)
		mlog(LV_ERR, "E-2085: write %s: %s", temp_path, strerror(errno));
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	else if (folder_id == PRIVATE_FID_DRAFT)
		b_unsent = true;
	unsigned int user_id = 0;
	if (!system_services_get_user_ids(pidb->username.c_str(), &user_id, nullptr, nullptr))
		return MIDB_E_SSGETID;
	sql_meta_result mres;
	auto mret = system_services_meta(pidb->username.c_str(),
	            WANTPRIV_METAONLY, mres);
	auto charset = mret == 0 ? lang_to_charset(mres.lang.c_str()) : nullptr;
	if (*znul(charset) == '\0')
		charset = g_default_charset;
	auto tmzone = mret == 0 ? mres.timezone.c_str() : nullptr;
	if (*znul(tmzone) == '\0')
		tmzone = GROMOX_FALLBACK_TIMEZONE;
	auto pmsgctnt = oxcmail_import(charset, tmzone, &imail,
	                common_util_alloc, common_util_get_propids_create);
	imail.clear();
	pbuff.reset();
	if (pmsgctnt == nullptr)
		return MIDB_E_OXCMAIL_IMPORT;
	auto cl_msg = make_scope_exit([&]() { message_content_free(pmsgctnt); });
	auto nt_time = rop_util_unix_to_nttime(strtol(argv[5], nullptr, 0));
	if (pmsgctnt->proplist.set(PR_MESSAGE_DELIVERY_TIME, &nt_time) != 0)
		return MIDB_E_NO_MEMORY;
	static_assert(std::is_same_v<decltype(b_read), uint8_t>);
	if (b_read && pmsgctnt->proplist.set(PR_READ, &b_read) != 0)
		return MIDB_E_NO_MEMORY;
	if (0 != b_unsent) {
		tmp_flags = MSGFLAG_UNSENT;
		if (pmsgctnt->proplist.set(PR_MESSAGE_FLAGS, &tmp_flags) != 0)
			return MIDB_E_NO_MEMORY;
	}
	if (!exmdb_client::allocate_message_id(argv[1],
		rop_util_make_eid_ex(1, folder_id), &message_id) ||
	    !exmdb_client::allocate_cn(argv[1], &change_num))
		return MIDB_E_MDB_ALLOCID;
	snprintf(sql_string, std::size(sql_string), "INSERT INTO mapping"
		" (message_id, mid_string, flag_string) VALUES"
		" (%llu, ?, ?)", LLU{rop_util_get_gc_value(message_id)});
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	sqlite3_bind_text(pstmt, 2, argv[4], -1, SQLITE_STATIC);
	if (pstmt.step() != SQLITE_DONE)
		return MIDB_E_SQLUNEXP;
	pstmt.finalize();
	std::string username;
	try {
		username = pidb->username;
	} catch (const std::bad_alloc &) {
		return MIDB_E_NO_MEMORY;
	}
	pidb.reset();
	if (pmsgctnt->proplist.set(PidTagMid, &message_id) != 0 ||
	    pmsgctnt->proplist.set(PidTagChangeNumber, &change_num) != 0)
		return MIDB_E_NO_MEMORY;
	auto pbin = cu_xid_to_bin({rop_util_make_user_guid(user_id), change_num});
	if (pbin == nullptr ||
	    pmsgctnt->proplist.set(PR_CHANGE_KEY, pbin) != 0)
		return MIDB_E_NO_MEMORY;
	auto newval = common_util_pcl_append(NULL, pbin);
	if (newval == nullptr ||
	    pmsgctnt->proplist.set(PR_PREDECESSOR_CHANGE_LIST, newval) != 0)
		return MIDB_E_NO_MEMORY;
	auto cpid = cset_to_cpid(charset);
	if (cpid == CP_ACP)
		cpid = static_cast<cpid_t>(1252);
	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client::write_message(argv[1], cpid,
	    rop_util_make_eid_ex(1, folder_id), pmsgctnt, &e_result) ||
	    e_result != ecSuccess)
		return MIDB_E_MDB_WRITEMESSAGE;
	return cmd_write(sockd, "TRUE\r\n");
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1136: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Mail deletion from exmdb and midb.sqlite
 *
 * Request:
 * 	M-DELE <store-dir> <folder-name> <mid>...
 * Response:
 * 	TRUE
 */
static int mail_engine_mdele(int argc, char **argv, int sockd)
{
	int i;
	BOOL b_partial;
	EID_ARRAY message_ids;

	message_ids.count = 0;
	message_ids.pids = cu_alloc<uint64_t>(argc - 3);
	if (message_ids.pids == nullptr)
		return MIDB_E_NO_MEMORY;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	unsigned int user_id = 0;
	if (!system_services_get_user_ids(pidb->username.c_str(), &user_id, nullptr, nullptr))
		return MIDB_E_SSGETID;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	for (i=3; i<argc; i++) {
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, argv[i], -1, SQLITE_STATIC);
		if (SQLITE_ROW != pstmt.step() ||
		    gx_sql_col_uint64(pstmt, 1) != folder_id)
			continue;
		message_ids.pids[message_ids.count++] =
			rop_util_make_eid_ex(1, sqlite3_column_int64(pstmt, 0));
	}
	pstmt.finalize();
	pidb.reset();
	if (!exmdb_client::delete_messages(argv[1], CP_ACP, nullptr,
	    rop_util_make_eid_ex(1, folder_id), &message_ids, TRUE, &b_partial))
		return MIDB_E_MDB_DELETEMESSAGES;
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Duplicate a message.
 *
 * Request:
 * 	M-COPY <store-dir> <src-folder-name> <src-mid> <dst-folder-name>
 * Response:
 * 	TRUE <new-mid>
 */
static int mail_engine_mcopy(int argc, char **argv, int sockd) try
{
	if (strlen(argv[4]) >= 1024)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto src_fid = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (src_fid == 0)
		return MIDB_E_NO_FOLDER;
	auto dst_fid = mail_engine_get_folder_id(pidb.get(), argv[4]);
	if (dst_fid == 0)
		return MIDB_E_NO_FOLDER;
	/* Match this column list to ctm_field */
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id, mod_time, "
	             "uid, recent, read, unsent, flagged, replied, forwarded,"
	             "deleted, received, folder_id, size FROM messages "
	             "WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (pstmt.step() != SQLITE_ROW ||
	    pstmt.col_uint64(CTM_FOLDERID) != src_fid)
		return MIDB_E_NO_MESSAGE;
	uint64_t src_mid = pstmt.col_uint64(CTM_MSGID), message_id = 0;
	pstmt.finalize();
	if (!exmdb_client::allocate_message_id(argv[1],
	    rop_util_make_eid_ex(1, dst_fid), &message_id))
		return MIDB_E_MDB_ALLOCID;

	/*
	 * exmdb-level copy: this triggers an event and some other midb threads
	 * will instantiate the midb message (and decide mid_string)
	 */
	BOOL e_result = false;
	if (!exmdb_client::movecopy_message(argv[1], CP_UTF8, rop_util_make_eid_ex(1, src_mid),
	    rop_util_make_eid_ex(1, dst_fid), message_id,
	    false, &e_result) || !e_result)
		return MIDB_E_MDB_WRITEMESSAGE;

	pidb.reset(); /* release giant lock, let event get processed */
	std::string mid_string;
	for (unsigned int i = 0; i < 10; ++i) {
		pidb = mail_engine_get_idb(argv[1]);
		if (pidb == nullptr)
			return MIDB_E_HASHTABLE_FULL;
		pstmt = gx_sql_prep(pidb->psqlite, "SELECT mid_string FROM messages WHERE message_id=?");
		if (pstmt == nullptr)
			return MIDB_E_NO_MEMORY;
		pstmt.bind_int64(1, rop_util_get_gc_value(message_id));
		if (pstmt.step() == SQLITE_ROW) {
			mid_string = "TRUE "s + pstmt.col_text(0) + "\r\n";
			break;
		}
		pstmt.reset();
		pidb.reset();
		usleep(100000);
	}
	if (mid_string.empty())
		mid_string = "FALSE\r\n";
	return cmd_write(sockd, mid_string.c_str(), mid_string.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1486: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Rename a folder.
 *
 * Request:
 * 	M-RENF <store-dir> <old-folder-name> <new-folder-name>
 * Response:
 * 	TRUE
 */
static int mail_engine_mrenf(int argc, char **argv, int sockd)
{
	if (strlen(argv[3]) >= 1024 || strcmp(argv[2], argv[3]) == 0)
		return MIDB_E_PARAMETER_ERROR;
	auto decoded_name = base64_decode(argv[2]);
	if (decoded_name.empty())
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	unsigned int user_id = 0;
	if (!system_services_get_user_ids(pidb->username.c_str(), &user_id, nullptr, nullptr))
		return MIDB_E_SSGETID;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " parent_fid FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	pstmt.bind_text(1, decoded_name);
	if (pstmt.step() != SQLITE_ROW)
		return MIDB_E_SQLUNEXP;
	auto folder_id = pstmt.col_uint64(0);
	if (folder_id == PRIVATE_FID_INBOX)
		return MIDB_E_NOTPERMITTED;
	auto parent_id = pstmt.col_uint64(1);
	pstmt.finalize();
	if (mail_engine_get_folder_id(pidb.get(), argv[3]) != 0)
		return MIDB_E_FOLDER_EXISTS;

	const char *ptoken = decoded_name.c_str(), *ptoken1;
	uint64_t folder_id1 = PRIVATE_FID_IPMSUBTREE;
	while ((ptoken1 = strchr(ptoken, '/')) != NULL) {
		std::string temp_name(ptoken, ptoken1 - ptoken);
		auto parent_name = std::string_view(decoded_name.c_str(), ptoken1 - decoded_name.c_str());
		auto folder_id2 = me_get_folder_id_raw(pidb.get(), parent_name);
			if (0 == folder_id2) {
				if (!common_util_create_folder(argv[1],
				    user_id, rop_util_make_eid_ex(1, folder_id1),
				    temp_name.c_str(), &folder_id2))
					return MIDB_E_CREATEFOLDER;
				folder_id1 = rop_util_get_gc_value(folder_id2);
			} else {
				folder_id1 = folder_id2;
			}
		ptoken = ptoken1 + 1;
	}
	pidb.reset();
	if (parent_id != folder_id1) {
		ec_error_t errcode = ecSuccess;
		if (!exmdb_client::movecopy_folder(argv[1], CP_ACP, false,
		    nullptr, rop_util_make_eid_ex(1, parent_id),
		    rop_util_make_eid_ex(1, folder_id),
		    rop_util_make_eid_ex(1, folder_id1),
		    ptoken, false, &errcode))
			return MIDB_E_MDB_MOVECOPY;
		if (errcode == ecDuplicateName)
			return MIDB_E_FOLDER_EXISTS;
		if (errcode != ecSuccess)
			return MIDB_E_MDB_PARTIAL;
	}

	uint64_t change_num = 0;
	if (!exmdb_client::allocate_cn(argv[1], &change_num))
		return MIDB_E_MDB_ALLOCID;
	static constexpr proptag_t tmp_proptag[] = {PR_PREDECESSOR_CHANGE_LIST};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
	TPROPVAL_ARRAY propvals;
	if (!exmdb_client::get_folder_properties(argv[1], CP_ACP,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return MIDB_E_MDB_GETFOLDERPROPS;
	auto pbin1 = propvals.get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);

	auto nt_time = rop_util_current_nttime();
	TAGGED_PROPVAL propval_buff[5];
	TPROPVAL_ARRAY pset = {0, propval_buff};
	pset.emplace_back(PidTagChangeNumber, &change_num);
	auto pbin = cu_xid_to_bin({rop_util_make_user_guid(user_id), change_num});
	if (pbin == nullptr)
		return MIDB_E_NO_MEMORY;
	pset.emplace_back(PR_CHANGE_KEY, pbin);
	pset.emplace_back(PR_PREDECESSOR_CHANGE_LIST, common_util_pcl_append(pbin1, pbin));
	if (propval_buff[2].pvalue == nullptr)
		return MIDB_E_NO_MEMORY;
	pset.emplace_back(PR_LAST_MODIFICATION_TIME, &nt_time);
	if (parent_id == folder_id1)
		pset.emplace_back(PR_DISPLAY_NAME, ptoken);

	PROBLEM_ARRAY problems;
	if (!exmdb_client::set_folder_properties(argv[1], CP_ACP,
	    rop_util_make_eid_ex(1, folder_id), &pset, &problems))
		return MIDB_E_MDB_SETFOLDERPROPS;
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Create a folder.
 *
 * Request:
 * 	M-MAKF <store-dir> <folder-path>
 * folder-path: this specifies both the parent where to anchor at,
 * and the new folder's name.
 * Response:
 * 	TRUE
 */
static int mail_engine_mmakf(int argc, char **argv, int sockd)
{
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	unsigned int user_id = 0;
	if (!system_services_get_user_ids(pidb->username.c_str(), &user_id, nullptr, nullptr))
		return MIDB_E_SSGETID;
	auto decoded_name = base64_decode(argv[2]);
	if (decoded_name.empty())
		return MIDB_E_PARAMETER_ERROR;
	if (me_get_folder_id_raw(pidb.get(), decoded_name) != 0)
		return MIDB_E_FOLDER_EXISTS;

	const char *ptoken = decoded_name.c_str(), *ptoken1;
	uint64_t folder_id1 = PRIVATE_FID_IPMSUBTREE;
	while ((ptoken1 = strchr(ptoken, '/')) != NULL) {
		std::string temp_name(ptoken, ptoken1 - ptoken);
		auto parent_name = std::string_view(decoded_name.c_str(), ptoken1 - decoded_name.c_str());
		auto folder_id2 = mail_engine_get_folder_id(pidb.get(), parent_name);
			if (0 == folder_id2) {
				if (!common_util_create_folder(argv[1],
				    user_id, rop_util_make_eid_ex(1, folder_id1),
				    temp_name.c_str(), &folder_id2))
					return MIDB_E_CREATEFOLDER;
				folder_id1 = rop_util_get_gc_value(folder_id2);
			} else {
				folder_id1 = folder_id2;
			}
		ptoken = ptoken1 + 1;
	}
	pidb.reset();
	uint64_t new_fid = 0;
	if (!common_util_create_folder(argv[1],
	    user_id, rop_util_make_eid_ex(1, folder_id1),
	    ptoken, &new_fid) || new_fid == 0)
		return MIDB_E_CREATEFOLDER;
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Remove a folder.
 *
 * Request:
 * 	M-REMF <store-dir> <folder-name>
 * Response:
 * 	TRUE
 */
static int mail_engine_mremf(int argc, char **argv, int sockd)
{
	BOOL b_result;
	BOOL b_partial;
	
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (0 == folder_id) {
		pidb.reset();
		return cmd_write(sockd, "TRUE\r\n");
	}
	pidb.reset();
	if (folder_id < CUSTOM_EID_BEGIN)
		return MIDB_E_NOTPERMITTED;
	folder_id = rop_util_make_eid_ex(1, folder_id);
	if (!exmdb_client::empty_folder(argv[1], CP_ACP, nullptr, folder_id,
	    DELETE_HARD_DELETE | DEL_MESSAGES | DEL_ASSOCIATED, &b_partial) || b_partial ||
	    !exmdb_client::empty_folder(argv[1], CP_ACP, nullptr, folder_id,
	    DELETE_HARD_DELETE | DEL_FOLDERS, &b_partial) || b_partial ||
	    !exmdb_client::delete_folder(argv[1], CP_ACP, folder_id, TRUE,
	    &b_result) || !b_result)
		return MIDB_E_MDB_DELETEFOLDER;
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Lookup UID for a message.
 *
 * Request:
 * 	P-UNID <store-dir> <folder-name> <mid>
 * Response:
 * 	TRUE <uid>
 */
static int mail_engine_punid(int argc, char **argv, int sockd)
{
	int temp_len;
	uint32_t uid;
	char temp_buff[1024];

	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " uid FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (pstmt.step() != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return MIDB_E_NO_MESSAGE;
	uid = sqlite3_column_int64(pstmt, 1);
	pstmt.finalize();
	pidb.reset();
	temp_len = sprintf(temp_buff, "TRUE %u\r\n", uid);
	return cmd_write(sockd, temp_buff, temp_len);
}

/**
 * Folder summary
 *
 * Request:
 * 	P-FDDT <store-dir> <folder-name>
 * Response:
 * 	TRUE <#messages> <#recents> <#unreads> <uidvalidity> <uidnext>
 */
static int mail_engine_pfddt(int argc, char **argv, int sockd)
{
	char temp_buff[1024];
	char sql_string[1024];
	
	auto decoded_name = base64_decode(argv[2]);
	if (decoded_name.empty())
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id,"
	             " uidnext FROM folders WHERE name=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	pstmt.bind_text(1, decoded_name);
	if (pstmt.step() != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	auto folder_id = pstmt.col_uint64(0);
	auto uidnext = pstmt.col_uint64(1);
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT count(message_id) "
	          "FROM messages WHERE folder_id=%llu", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (pstmt.step() != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	size_t total = pstmt.col_uint64(0);
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT count(message_id) FROM "
	          "messages WHERE folder_id=%llu AND read=0", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	size_t unreads = pstmt.step() == SQLITE_ROW ? pstmt.col_uint64(0) : 0;
	pstmt.finalize();
	snprintf(sql_string, std::size(sql_string), "SELECT count(message_id) FROM"
	          " messages WHERE folder_id=%llu AND recent=0", LLU{folder_id});
	pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	size_t recents = pstmt.step() == SQLITE_ROW ? pstmt.col_uint64(0) : 0;
	pstmt.finalize();
	pidb.reset();
	auto temp_len = sprintf(temp_buff, "TRUE %zu %zu %zu %llu %llu\r\n",
	                total, recents, unreads, LLU{folder_id},
	                LLU{uidnext + 1});
	return cmd_write(sockd, temp_buff, temp_len);
}

/**
 * Subscribe to a folder.
 *
 * Request:
 * 	P-SUBF <store-dir> <folder-name>
 * Response:
 * 	TRUE
 */
static int mail_engine_psubf(int argc, char **argv, int sockd)
{
	char sql_string[1024];

	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	snprintf(sql_string, std::size(sql_string), "UPDATE folders SET unsub=0"
	        " WHERE folder_id=%llu", LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Unsubscribe from a folder.
 *
 * Request:
 * 	P-UNSF <store-dir> <folder-name>
 * Response:
 * 	TRUE
 */
static int mail_engine_punsf(int argc, char **argv, int sockd)
{
	char sql_string[1024];

	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	snprintf(sql_string, std::size(sql_string), "UPDATE folders SET unsub=1"
	        " WHERE folder_id=%llu", LLU{folder_id});
	gx_sql_exec(pidb->psqlite, sql_string);
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * List folders subscribed to.
 *
 * Request:
 * 	P-SUBL <store-dir>
 * Response:
 * 	TRUE <#folders>
 * 	<folder-id> <folder-name>  // repeat x #folders
 */
static int mail_engine_psubl(int argc, char **argv, int sockd) try
{
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id, name FROM folders WHERE unsub=0");
	if (pstmt == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	size_t count = 0;
	std::string rsp;
	rsp.reserve(65536);
	for (; pstmt.step() == SQLITE_ROW; ++count)
		rsp += std::to_string(pstmt.col_uint64(0)) + " " + pstmt.col_text(1) + "\r\n"s;
	pstmt.finalize();
	pidb.reset();
	rsp.insert(0, "TRUE " + std::to_string(count) + "\r\n");
	return cmd_write(sockd, rsp.c_str(), rsp.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2532: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

namespace {

struct simu_node {
	uint32_t uid;
	unsigned int size;
	std::string flags, mid_string;
};

}

static int simu_query(IDB_ITEM *pidb, const char *sql_string,
    size_t total_mail, std::vector<simu_node> &temp_list) try
{
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	while (pstmt.step() == SQLITE_ROW) {
		simu_node sn;
		sn.mid_string = pstmt.col_text(1);
		sn.uid = pstmt.col_int64(2);
		sn.flags = "(";
		if (pstmt.col_int64(3) != 0)
			sn.flags += 'A';
		if (pstmt.col_int64(4) != 0)
			sn.flags += 'U';
		if (pstmt.col_int64(5) != 0)
			sn.flags += 'F';
		if (pstmt.col_int64(6) != 0)
			sn.flags += 'D';
		if (pstmt.col_int64(7) != 0)
			sn.flags += 'S';
		if (pstmt.col_int64(8) != 0)
			sn.flags += 'R';
		if (pstmt.col_int64(9) != 0)
			sn.flags += 'W';
		sn.flags += ')';
		sn.size = pstmt.col_uint64(10);
		temp_list.push_back(std::move(sn));
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2417: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Give summary of messages present in folder (via IMAP UID)
 *
 * Request:
 * 	P-SIMU <store-dir> <folder-name> <uid(min)> <uid(max)>
 * Response:
 * 	TRUE <#msgcount>
 * 	- <midstr> <uid> <flags> <size>  // repeat x #msgcount
 *
 * midb_agent:list_mail [POP3 logic] uses midstr and size.
 * midb_agent:fetch_simple_uid [IMAP logic] uses midstr, uid, flags.
 */
static int mail_engine_psimu(int argc, char **argv, int sockd) try
{
	int total_mail = 0;
	
	seq_node::value_type first = strtol(argv[3], nullptr, 0), last = strtol(argv[4], nullptr, 0);
	if (first < 1 && first != SEQ_STAR)
		return MIDB_E_PARAMETER_ERROR;
	if (last < 1 && last != SEQ_STAR)
		return MIDB_E_PARAMETER_ERROR;
	if (first != SEQ_STAR && last != SEQ_STAR && last < first)
		std::swap(first, last);
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;

	std::string qstr;
	if (first == SEQ_STAR && last == SEQ_STAR)
		/* "MAX:MAX" */
		qstr = "SELECT 0, mid_string, uid, replied, unsent, flagged,"
		       " deleted, read, recent, forwarded, size"
		       " FROM messages WHERE folder_id=" + std::to_string(folder_id) +
		       " ORDER BY uid DESC LIMIT 1";
	else if (first == SEQ_STAR)
		/* "MAX:99" */
		qstr = fmt::format("SELECT 0, mid_string, uid, replied, unsent, "
		       "flagged, deleted, read, recent, forwarded, size "
		       "FROM messages WHERE folder_id={} AND uid<={} "
		       "ORDER BY uid DESC LIMIT 1", folder_id, last);
	else if (last == SEQ_STAR)
		/* "99:MAX" */
		qstr = fmt::format("SELECT 0, mid_string, uid, replied, unsent, "
		       "flagged, deleted, read, recent, forwarded, size "
		       "FROM messages WHERE folder_id={} AND uid>={} ORDER BY uid",
		       folder_id, first);
	else
		qstr = fmt::format("SELECT 0, mid_string, uid, replied, unsent, "
		       "flagged, deleted, read, recent, forwarded, size "
		       "FROM messages WHERE folder_id={} AND uid>={} AND uid<={} "
		       "ORDER BY uid", folder_id, first, last);

	std::vector<simu_node> temp_list;
	auto iret = simu_query(pidb.get(), qstr.c_str(), total_mail, temp_list);
	if (iret != 0)
		return iret;
	if (temp_list.size() == 0 && (first == SEQ_STAR || last == SEQ_STAR)) {
		/*
		 * RFC 3501: "a UID range of 559:* always includes the UID of
		 * the last message in the mailbox, even if 559 is higher than
		 * any assigned UID value".
		 */
		qstr = "SELECT 0, mid_string, uid, replied, unsent, flagged,"
		       " deleted, read, recent, forwarded, size"
		       " FROM messages WHERE folder_id=" + std::to_string(folder_id) +
		       " ORDER BY uid DESC LIMIT 1";
		iret = simu_query(pidb.get(), qstr.c_str(), total_mail, temp_list);
		if (iret != 0)
			return iret;
	}

	std::string rsp;
	rsp.reserve(65536);
	rsp += "TRUE " + std::to_string(temp_list.size()) + "\r\n";
	for (const auto &sn : temp_list) {
		rsp += fmt::format("- {} {} {} {}\r\n", sn.mid_string, sn.uid,
		       sn.flags, sn.size);
		if (rsp.size() < rsp.capacity() / 2)
			continue;
		auto ret = cmd_write(sockd, rsp.c_str(), rsp.size());
		if (ret != 0)
			return ret;
		rsp.clear();
	}
	pidb.reset();
	return cmd_write(sockd, rsp.c_str(), rsp.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1204: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * List \Deleted-flagged mails
 *
 * Request:
 * 	P-DELL <dir> <folder-name>
 * Response:
 * 	TRUE <#messages>
 * 	- <mid> <uid>  // repeat x #messages
 */
static int mail_engine_pdell(int argc, char **argv, int sockd) try
{
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto qstr = "SELECT count(message_id) FROM messages WHERE folder_id=" +
	            std::to_string(folder_id) + " AND deleted=1";
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	if (pstmt.step() != SQLITE_ROW)
		return MIDB_E_NO_FOLDER;
	size_t length = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	qstr = "SELECT mid_string, uid FROM messages WHERE folder_id=" +
	       std::to_string(folder_id) + " AND deleted=1 ORDER BY uid";
	pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;

	std::string rsp;
	rsp.reserve(65536);
	rsp += "TRUE " + std::to_string(length) + "\r\n";
	while (pstmt.step() == SQLITE_ROW) {
		auto mid_string = pstmt.col_text(0);
		uint32_t uid = pstmt.col_uint64(1);
		rsp += fmt::format("- {} {}\r\n", mid_string, uid);
		if (rsp.size() < rsp.capacity() / 2)
			continue;
		auto ret = cmd_write(sockd, rsp.c_str(), rsp.size());
		if (ret != 0)
			return ret;
		rsp.clear();
	}
	pstmt.finalize();
	pidb.reset();
	return cmd_write(sockd, rsp.c_str(), rsp.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2533: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

static int dtlu_query(IDB_ITEM *pidb, const char *sql_string,
    size_t total_mail, std::vector<std::string> &temp_list)
{
	auto pstmt = gx_sql_prep(pidb->psqlite, sql_string);
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	while (pstmt.step() == SQLITE_ROW)
		temp_list.emplace_back(pstmt.col_text(0));
	return 0;
}

/**
 * Fetch detail (via IMAP UID)
 *
 * Request:
 * 	P-DTLU <store-dir> <folder-name> <1-based imapuid(min)> <1-based imapuid(max)>
 * Response:
 * 	TRUE <#messages>
 * 	- <digest>  // repeat x #messages
 */
static int mail_engine_pdtlu(int argc, char **argv, int sockd) try
{
	int total_mail = 0;
	char sql_string[1024];
	
	seq_node::value_type first = strtol(argv[3], nullptr, 0), last = strtol(argv[4], nullptr, 0);
	if (first < 1 && first != SEQ_STAR)
		return MIDB_E_PARAMETER_ERROR;
	if (last < 1 && last != SEQ_STAR)
		return MIDB_E_PARAMETER_ERROR;
	if (first != SEQ_STAR && last != SEQ_STAR && last < first)
		std::swap(first, last);
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	/* UNSET always means MAX, never MIN */
	if (first == SEQ_STAR && last == SEQ_STAR)
		snprintf(sql_string, std::size(sql_string), "SELECT mid_string"
		         " FROM messages WHERE folder_id=%llu ORDER BY uid DESC LIMIT 1",
		         LLU{folder_id});
	else if (first == SEQ_STAR)
		snprintf(sql_string, std::size(sql_string), "SELECT mid_string "
		         "FROM messages WHERE folder_id=%llu AND uid<=%u "
		         " ORDER BY uid DESC LIMIT 1", LLU{folder_id}, last);
	else if (last == SEQ_STAR)
		snprintf(sql_string, std::size(sql_string), "SELECT mid_string "
		         "FROM messages WHERE folder_id=%llu AND uid>=%u"
		         " ORDER BY uid", LLU{folder_id}, first);
	else if (last == first)
		snprintf(sql_string, std::size(sql_string), "SELECT mid_string "
		         "FROM messages WHERE folder_id=%llu AND uid=%u",
		         LLU{folder_id}, first);
	else
		snprintf(sql_string, std::size(sql_string), "SELECT mid_string "
		         "FROM messages WHERE folder_id=%llu AND uid>=%u AND"
		         " uid<=%u ORDER BY uid", LLU{folder_id}, first, last);

	std::vector<std::string> temp_list;
	auto iret = dtlu_query(pidb.get(), sql_string, total_mail, temp_list);
	if (iret != 0)
		return iret;
	if (temp_list.empty() && (first == SEQ_STAR || last == SEQ_STAR)) {
		/* Rerun like in pshru */
		snprintf(sql_string, std::size(sql_string), "SELECT mid_string"
		         " FROM messages WHERE folder_id=%llu ORDER BY uid"
		         " DESC LIMIT 1", LLU{folder_id});
		iret = dtlu_query(pidb.get(), sql_string, total_mail, temp_list);
		if (iret != 0)
			return iret;
	}

	char temp_buff[32];
	auto temp_len = gx_snprintf(temp_buff, std::size(temp_buff),
	                "TRUE %zu\r\n", temp_list.size());
	auto ret = cmd_write(sockd, temp_buff, temp_len);
	if (ret != 0)
		return ret;
	for (const auto &dt : temp_list) {
		temp_len = gx_snprintf(temp_buff, std::size(temp_buff), "- ");
		Json::Value digest;
		if (mail_engine_get_digest(pidb->psqlite, dt.c_str(), digest) == 0)
			digest = Json::objectValue;
		auto djson = json_to_str(digest);
		djson.insert(0, temp_buff);
		djson.append("\r\n");
		ret = cmd_write(sockd, djson.c_str(), djson.size());
		if (ret != 0)
			return ret;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1210: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Set flags on message. For (S)een and (U)nsent, exmdb is contacted(!), which
 * is different from GFLG.
 *
 * Request:
 * 	P-SFLG <store-dir> <folder-name> <mid> <flags>
 * Response:
 * 	TRUE
 */
static int mail_engine_psflg(int argc, char **argv, int sockd)
{
	uint64_t read_cn;
	uint64_t message_id;
	char sql_string[1024];
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != pstmt.step() ||
	    gx_sql_col_uint64(pstmt, 1) != folder_id)
		return MIDB_E_NO_MESSAGE;
	message_id = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (NULL != strchr(argv[4], 'A')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET replied=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'U')) {
		static constexpr proptag_t tmp_proptag[] = {PR_MESSAGE_FLAGS};
		static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
		if (!exmdb_client::get_message_properties(argv[1], NULL,
		    CP_ACP, rop_util_make_eid_ex(1, message_id),
		    &proptags, &propvals) || propvals.count == 0)
			return MIDB_E_MDB_GETMSGPROPS;
		auto message_flags = *static_cast<uint32_t *>(propvals.ppropval[0].pvalue);
		if (!(message_flags & MSGFLAG_UNSENT)) {
			message_flags |= MSGFLAG_UNSENT;
			propvals.ppropval[0].pvalue = &message_flags;
			if (!exmdb_client::set_message_properties(argv[1],
			    nullptr, CP_ACP, rop_util_make_eid_ex(1, message_id),
			    &propvals, &problems))
				return MIDB_E_MDB_SETMSGPROPS;
		}
	}
	if (NULL != strchr(argv[4], 'F')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET flagged=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'W')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET forwarded=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'D')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET deleted=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (strchr(argv[4], 'S') != nullptr &&
	    !exmdb_client::set_message_read_state(argv[1], nullptr,
	    rop_util_make_eid_ex(1, message_id), 1, &read_cn))
		return MIDB_E_MDB_SETMSGRD;
	if (NULL != strchr(argv[4], 'R')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET recent=1"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Remove flags on message. Flags (S)een and (U)nsent trigger contact to exmdb.
 *
 * Request:
 * 	P-RFLG <store-dir> <folder-name> <mid> <flags>
 * Response:
 * 	TRUE
 */
static int mail_engine_prflg(int argc, char **argv, int sockd)
{
	uint64_t read_cn;
	uint64_t message_id;
	char sql_string[1024];
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;

	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT message_id,"
	             " folder_id FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != pstmt.step() ||
	    gx_sql_col_uint64(pstmt, 1) != folder_id)
		return MIDB_E_NO_MESSAGE;
	message_id = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	if (NULL != strchr(argv[4], 'A')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET replied=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'U')) {
		static constexpr proptag_t tmp_proptag[] = {PR_MESSAGE_FLAGS};
		static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
		if (!exmdb_client::get_message_properties(argv[1], nullptr,
		    CP_ACP, rop_util_make_eid_ex(1, message_id),
		    &proptags, &propvals) || propvals.count == 0)
			return MIDB_E_MDB_GETMSGPROPS;
		auto message_flags = *static_cast<uint32_t *>(propvals.ppropval[0].pvalue);
		if (message_flags & MSGFLAG_UNSENT) {
			message_flags &= ~MSGFLAG_UNSENT;
			propvals.ppropval[0].pvalue = &message_flags;
			if (!exmdb_client::set_message_properties(argv[1],
			    nullptr, CP_ACP, rop_util_make_eid_ex(1, message_id),
			    &propvals, &problems))
				return MIDB_E_MDB_SETMSGPROPS;
		}
	}
	if (NULL != strchr(argv[4], 'F')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET flagged=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'W')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET forwarded=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (NULL != strchr(argv[4], 'D')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET deleted=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	if (strchr(argv[4], 'S') != nullptr &&
	    !exmdb_client::set_message_read_state(argv[1], nullptr,
	    rop_util_make_eid_ex(1, message_id), 0, &read_cn))
		return MIDB_E_MDB_SETMSGRD;
	if (NULL != strchr(argv[4], 'R')) {
		snprintf(sql_string, std::size(sql_string), "UPDATE messages SET recent=0"
		        " WHERE message_id=%llu", LLU{message_id});
		gx_sql_exec(pidb->psqlite, sql_string);
	}
	pidb.reset();
	return cmd_write(sockd, "TRUE\r\n");
}

/**
 * Get flags on message from midb.sqlite without contacting exmdb.
 * You better hope that the change notification socket is working,
 * because otherwise changes from SFLG/RFLG won't be visible.
 *
 * Request:
 * 	P-GFLG <store-dir> <folder-name> <mid>
 * Response:
 * 	TRUE <flags>
 *
 * Flags: e.g. Answered(A), Unsent(U), Flagged(F), Deleted(D), Read/Seen(S),
 * Recent(R), Forwarded(W)
 */
static int mail_engine_pgflg(int argc, char **argv, int sockd) try
{
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	auto pstmt = gx_sql_prep(pidb->psqlite, "SELECT folder_id, recent, "
	             "read, unsent, flagged, replied, forwarded, deleted "
	             "FROM messages WHERE mid_string=?");
	if (pstmt == nullptr)
		return MIDB_E_SQLPREP;
	sqlite3_bind_text(pstmt, 1, argv[3], -1, SQLITE_STATIC);
	if (SQLITE_ROW != pstmt.step() ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return MIDB_E_NO_MESSAGE;
	std::string ans = "TRUE (";
	if (pstmt.col_int64(5) != 0) ans += 'A';
	if (pstmt.col_int64(3) != 0) ans += 'U';
	if (pstmt.col_int64(4) != 0) ans += 'F';
	if (pstmt.col_int64(6) != 0) ans += 'W';
	if (pstmt.col_int64(7) != 0) ans += 'D';
	if (pstmt.col_int64(2) != 0) ans += 'S';
	if (pstmt.col_int64(1) != 0) ans += 'R';
	pstmt.finalize();
	pidb.reset();
	ans += ")\r\n";
	return cmd_write(sockd, ans.c_str(), ans.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2419: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Search and list messages
 *
 * Request:
 * 	P-SRHL <store-dir> <folder-name> <charset> <condition-tree-spec>
 * ct-spec: \0 terminated list of \0-terminated strings
 * ct-spec e.g. "UNDELETED\x00\x00"
 * ct-spec max elems 1024
 * Response:
 * 	TRUE <uid>...
 */
static int mail_engine_psrhl(int argc, char **argv, int sockd) try
{
	char *parg;
	int tmp_argc;
	sqlite3 *psqlite;
	size_t decode_len;
	char temp_path[256];
	char* tmp_argv[1024];
	char tmp_buff[16*1024];
	
	auto tmp_len = strlen(argv[4]);
	if (tmp_len >= sizeof(tmp_buff) ||
	    decode64(argv[4], tmp_len, tmp_buff, std::size(tmp_buff), &decode_len) != 0)
		return MIDB_E_PARAMETER_ERROR;
	tmp_argc = 0;
	parg = tmp_buff;
	while (*parg != '\0' && parg - tmp_buff >= 0 &&
	       static_cast<size_t>(parg - tmp_buff) < decode_len &&
	       static_cast<size_t>(tmp_argc) < sizeof(tmp_argv)) {
		tmp_argv[tmp_argc] = parg;
		parg += strlen(parg) + 1;
		tmp_argc ++;
	}
	if (tmp_argc == 0)
		return MIDB_E_PARAMETER_ERROR;
	auto ptree = mail_engine_ct_build(tmp_argc, tmp_argv);
	if (ptree == nullptr)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	pidb.reset();
	sprintf(temp_path, "%s/exmdb/midb.sqlite3", argv[1]);
	auto ret = sqlite3_open_v2(temp_path, &psqlite, SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1439: sqlite3_open %s: %s", temp_path, sqlite3_errstr(ret));
		return MIDB_E_HASHTABLE_FULL;
	}
	auto presult = mail_engine_ct_match(argv[3], psqlite, folder_id, ptree.get(), false);
	if (!presult.has_value()) {
		sqlite3_close(psqlite);
		return MIDB_E_MNG_CTMATCH;
	}
	sqlite3_close(psqlite);

	std::string rsp = "TRUE";
	rsp.reserve(65536);
	for (auto result : *presult) {
		rsp += " " + std::to_string(result);
		if (rsp.size() < rsp.capacity() / 2)
			continue;
		ret = cmd_write(sockd, rsp.c_str(), rsp.size());
		if (ret != 0)
			return ret;
		rsp.clear();
	}
	rsp += "\r\n";
	return cmd_write(sockd, rsp.c_str(), rsp.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2534: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Search by UIDs
 *
 * Request:
 * 	P-SRHU <store-dir> <folder-name> <charset> <uid-list>
 * uid-list: \0 terminated list of \0-terminated UIDs
 * uid-list e.g. "1\x00""2\x00\x00"
 * uid-list max elem 1024
 * Response:
 * 	TRUE <uid-list>
 * uid-list: space-separated IDs
 */
static int mail_engine_psrhu(int argc, char **argv, int sockd) try
{
	char *parg;
	int tmp_argc;
	sqlite3 *psqlite;
	size_t decode_len;
	char temp_path[256];
	char* tmp_argv[1024];
	char tmp_buff[16*1024];
	
	auto tmp_len = strlen(argv[4]);
	if (tmp_len >= sizeof(tmp_buff) ||
	    decode64(argv[4], tmp_len, tmp_buff, std::size(tmp_buff), &decode_len) != 0)
		return MIDB_E_PARAMETER_ERROR;
	tmp_argc = 0;
	parg = tmp_buff;
	while (*parg != '\0' && parg - tmp_buff >= 0 &&
	       static_cast<size_t>(parg - tmp_buff) < decode_len &&
	       static_cast<size_t>(tmp_argc) < sizeof(tmp_argv)) {
		tmp_argv[tmp_argc] = parg;
		parg += strlen(parg) + 1;
		tmp_argc ++;
	}
	if (tmp_argc == 0)
		return MIDB_E_PARAMETER_ERROR;
	auto ptree = mail_engine_ct_build(tmp_argc, tmp_argv);
	if (ptree == nullptr)
		return MIDB_E_PARAMETER_ERROR;
	auto pidb = mail_engine_get_idb(argv[1]);
	if (pidb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	auto folder_id = mail_engine_get_folder_id(pidb.get(), argv[2]);
	if (folder_id == 0)
		return MIDB_E_NO_FOLDER;
	pidb.reset();
	sprintf(temp_path, "%s/exmdb/midb.sqlite3", argv[1]);
	auto ret = sqlite3_open_v2(temp_path, &psqlite, SQLITE_OPEN_READWRITE, nullptr);
	if (ret != SQLITE_OK) {
		mlog(LV_ERR, "E-1505: sqlite3_open %s: %s", temp_path, sqlite3_errstr(ret));
		return MIDB_E_HASHTABLE_FULL;
	}
	auto presult = mail_engine_ct_match(argv[3], psqlite, folder_id, ptree.get(), TRUE);
	if (!presult.has_value()) {
		sqlite3_close(psqlite);
		return MIDB_E_MNG_CTMATCH;
	}
	sqlite3_close(psqlite);

	std::string rsp = "TRUE";
	rsp.reserve(65536);
	for (auto result : *presult) {
		rsp += " " + std::to_string(result);
		if (rsp.size() < rsp.capacity() / 2)
			continue;
		ret = cmd_write(sockd, rsp.c_str(), rsp.size());
		if (ret != 0)
			return ret;
		rsp.clear();
    }
	rsp += "\r\n";
	return cmd_write(sockd, rsp.c_str(), rsp.size());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2535: ENOMEM");
	return MIDB_E_NO_MEMORY;
}

/**
 * Unload a midb database. (For diagnostic purposes.)
 *
 * Request:
 * 	X-UNLD <store-dir>
 * Response:
 * 	TRUE 1
 */
static int mail_engine_xunld(int argc, char **argv, int sockd)
{
	std::lock_guard hhold(g_hash_lock);
	auto it = g_hash_table.find(argv[1]);
	if (it == g_hash_table.end())
		return MIDB_E_STORE_NOT_LOADED;
	auto pidb = &it->second;
	if (pidb->reference != 0)
		return MIDB_E_STORE_BUSY;
	if (pidb->sub_id != 0)
		exmdb_client::unsubscribe_notification(argv[1], pidb->sub_id);
	g_hash_table.erase(it);
	return cmd_write(sockd, "TRUE 1\r\n");
}

/**
 * Force-resynchronize a mailbox.
 *
 * Request:
 * 	X-RSYM <store-dir>
 * Response:
 * 	TRUE <0|1|2>
 */
static int mail_engine_xrsym(int argc, char **argv, int sockd)
{
	auto idb = mail_engine_peek_idb(argv[1]);
	if (idb == nullptr) {
		mail_engine_get_idb(argv[1], true);
		return cmd_write(sockd, "TRUE 2\r\n");
	} else if (!mail_engine_sync_mailbox(idb.get(), true)) {
		return cmd_write(sockd, "TRUE 0\r\n");
	} else {
		return cmd_write(sockd, "TRUE 1\r\n");
	}
}

/**
 * Force-resynchronize a folder
 *
 * Request:
 * 	X-RSYF <store-dir> <exmdb-folder-id-gc-value>
 * Response:
 * 	TRUE 1
 * 	FALSE 1
 * 	(also the regular FALSE 0 by way of midb core)
 */
static int mail_engine_xrsyf(int argc, char **argv, int sockd)
{
	auto idb = mail_engine_get_idb(argv[1]);
	if (idb == nullptr)
		return MIDB_E_HASHTABLE_FULL;
	if (!mail_engine_sync_contents(idb.get(), strtoul(argv[2], nullptr, 0)))
		return cmd_write(sockd, "FALSE 1\r\n");
	else
		return cmd_write(sockd, "TRUE 1\r\n");
}

static void mail_engine_add_notification_message(IDB_ITEM *pidb,
    uint64_t folder_id, uint64_t message_id) try
{
	static constexpr proptag_t tmp_proptags[] =
		{PR_MESSAGE_DELIVERY_TIME, PR_LAST_MODIFICATION_TIME,
		PidTagMidString, PR_MESSAGE_FLAGS};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptags), deconst(tmp_proptags)};
	TPROPVAL_ARRAY propvals;
	if (!exmdb_client::get_message_properties(common_util_get_maildir(),
	    nullptr, CP_ACP, rop_util_make_eid_ex(1, message_id),
	    &proptags, &propvals))
		return;		

	auto lnum = propvals.get<const uint64_t>(PR_LAST_MODIFICATION_TIME);
	auto mod_time = lnum != nullptr ? *lnum : 0;
	lnum = propvals.get<uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	auto received_time = lnum != nullptr ? *lnum : 0;
	auto num = propvals.get<const uint32_t>(PR_MESSAGE_FLAGS);
	auto message_flags = num != nullptr ? *num : 0;

	std::string flags_buff;
	char mid_string[128];
	auto str = propvals.get<const char>(PidTagMidString);
	if (str == nullptr) {
		auto qstr = fmt::format("SELECT mid_string, flag_string"
		            " FROM mapping WHERE message_id={}", message_id);
		auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
		if (pstmt == nullptr)
			return;
		if (pstmt.step() == SQLITE_ROW) {
			flags_buff = znul(pstmt.col_text(1));
			gx_strlcpy(mid_string, pstmt.col_text(0), std::size(mid_string));
			str = mid_string;
		}
		pstmt.finalize();
		if (str != nullptr) {
			qstr = fmt::format("DELETE FROM mapping"
			        " WHERE message_id={}", message_id);
			gx_sql_exec(pidb->psqlite, qstr.c_str());
		}
	}
	auto qstr = fmt::format("SELECT uidnext FROM folders WHERE folder_id={}", folder_id);
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return;

	uint32_t uidnext = sqlite3_column_int64(pstmt, 0);
	pstmt.finalize();
	qstr = fmt::format("UPDATE folders SET"
		" uidnext=uidnext+1, sort_field={} "
		"WHERE folder_id={}", static_cast<int>(FIELD_NONE), folder_id);
	if (gx_sql_exec(pidb->psqlite, qstr.c_str()) != SQLITE_OK)
		return;
	qstr = fmt::format("INSERT INTO messages ("
		"message_id, folder_id, mid_string, mod_time, uid, "
		"unsent, read, subject, sender, rcpt, size, received)"
		" VALUES (?, {}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", folder_id);
	pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr)
		return;	
	mail_engine_insert_message(pstmt, &uidnext, message_id, str,
		message_flags, received_time, mod_time);
	pstmt.finalize();
	if (flags_buff.find('F') != flags_buff.npos) {
		qstr = fmt::format("UPDATE messages SET "
		       "flagged=1 WHERE message_id={}", message_id);
		gx_sql_exec(pidb->psqlite, qstr.c_str());
	}
	if (flags_buff.find('A') != flags_buff.npos) {
		qstr = fmt::format("UPDATE messages SET "
		       "replied=1 WHERE message_id={}", message_id);
		gx_sql_exec(pidb->psqlite, qstr.c_str());
	}
	if (flags_buff.find('W') != flags_buff.npos) {
		qstr = fmt::format("UPDATE messages SET "
		       "forwarded=1 WHERE message_id={}", message_id);
		gx_sql_exec(pidb->psqlite, qstr.c_str());
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2418: ENOMEM");
}

static void mail_engine_delete_notification_message(IDB_ITEM *pidb,
    uint64_t folder_id, uint64_t message_id, const std::string &username,
    const char *folder_name) try
{
	auto qstr = fmt::format("SELECT folder_id, uid FROM "
	            "messages WHERE message_id={}", message_id);
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW ||
	    gx_sql_col_uint64(pstmt, 0) != folder_id)
		return;
	system_services_broadcast_event(fmt::format("MESSAGE-EXPUNGE {} {} {}",
		username, folder_name, pstmt.col_uint64(1)).c_str());
	pstmt.finalize();
	qstr = fmt::format("DELETE FROM messages WHERE message_id={}", message_id);
	gx_sql_exec(pidb->psqlite, qstr.c_str());
	qstr = fmt::format("UPDATE folders SET sort_field={} "
	       "WHERE folder_id={}", static_cast<int>(FIELD_NONE), folder_id);
	gx_sql_exec(pidb->psqlite, qstr.c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2420: ENOMEM");
}

static BOOL mail_engine_add_notification_folder(IDB_ITEM *pidb,
    uint64_t parent_id, uint64_t folder_id) try
{
	std::string decoded_name;

	if (parent_id == PRIVATE_FID_IPMSUBTREE) {
	} else {
		auto qstr = fmt::format("SELECT name FROM"
		           " folders WHERE folder_id={}", parent_id);
		auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return FALSE;
		decoded_name = pstmt.col_text(0);
	}

	static constexpr proptag_t tmp_proptags[] =
		{PR_DISPLAY_NAME, PR_LOCAL_COMMIT_TIME_MAX, PR_CONTAINER_CLASS,
		PR_ATTR_HIDDEN};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptags), deconst(tmp_proptags)};
	bool b_waited = false;
 REQUERY_FOLDER:
	TPROPVAL_ARRAY propvals{};
	if (!exmdb_client::get_folder_properties(common_util_get_maildir(), CP_ACP,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return FALSE;		
	auto flag = propvals.get<const uint8_t>(PR_ATTR_HIDDEN);
	if (flag != nullptr && *flag != 0)
		return FALSE;
	auto cont_class = propvals.get<const char>(PR_CONTAINER_CLASS);
	if (cont_class == nullptr && !b_waited) {
		/* outlook will set the PR_CONTAINER_CLASS
			after RopCreateFolder, so try to wait! */
		sleep(1);
		b_waited = true;
		goto REQUERY_FOLDER;
	}
	if (!ipf_note(cont_class))
		return FALSE;
	auto lnum = propvals.get<const uint64_t>(PR_LOCAL_COMMIT_TIME_MAX);
	auto commit_max = lnum != nullptr ? *lnum : 0;
	auto str = propvals.get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr)
		return FALSE;
	auto tmp_len = strlen(str);
	if (tmp_len >= 256)
		return FALSE;
	std::string temp_name;
	if (parent_id == PRIVATE_FID_IPMSUBTREE) {
		temp_name.assign(str, tmp_len);
	} else {
		temp_name = std::move(decoded_name) + "/"s + str;
	}
	auto stm = gx_sql_prep(pidb->psqlite, "INSERT INTO folders (folder_id, parent_fid, "
	           "commit_max, name) VALUES (?, ?, ?, ?)");
	if (stm == nullptr ||
	    stm.bind_int64(1, folder_id) != SQLITE_OK ||
	    stm.bind_int64(2, parent_id) != SQLITE_OK ||
	    stm.bind_int64(3, commit_max) != SQLITE_OK ||
	    stm.bind_text(4, temp_name) != SQLITE_OK ||
	    stm.step() != SQLITE_DONE)
		return FALSE;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1477: ENOMEM");
	return false;
}

static void mail_engine_delete_notification_folder(IDB_ITEM *pidb,
    uint64_t folder_id) try
{
	auto qstr = fmt::format("DELETE FROM folders WHERE folder_id={}", folder_id);
	gx_sql_exec(pidb->psqlite, qstr.c_str());
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2421: ENOMEM");
}

static void mail_engine_update_subfolders_name(IDB_ITEM *pidb,
    uint64_t parent_id, const std::string &parent_name) try
{
	auto qstr = fmt::format("SELECT folder_id, name"
	            " FROM folders WHERE parent_fid={}", parent_id);
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr)
		return;	
	while (pstmt.step() == SQLITE_ROW) {
		uint64_t folder_id = pstmt.col_int64(0);
		auto ptoken = strrchr(pstmt.col_text(1), '/');
		if (ptoken == nullptr)
			continue;
		auto temp_name = parent_name + ptoken;
		auto ust = gx_sql_prep(pidb->psqlite, "UPDATE folders SET name=? WHERE folder_id=?");
		if (ust != nullptr) {
			if (ust.bind_text(1, temp_name) != SQLITE_OK ||
			    ust.bind_int64(2, folder_id) != SQLITE_OK ||
			    ust.step() != SQLITE_DONE)
				/* ignore */;
			ust.finalize();
		}
		mail_engine_update_subfolders_name(pidb, folder_id, temp_name);
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2422: ENOMEM");
}

static void mail_engine_move_notification_folder(IDB_ITEM *pidb,
    uint64_t parent_id, uint64_t folder_id) try
{
	auto qstr = fmt::format("SELECT folder_id "
	            "FROM folders WHERE folder_id={}", folder_id);
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr)
		return;	
	if (pstmt.step() != SQLITE_ROW) {
		pstmt.finalize();
		mail_engine_add_notification_folder(
				pidb, parent_id, folder_id);
		return;
	}
	pstmt.finalize();

	std::string decoded_name;
	if (parent_id == PRIVATE_FID_IPMSUBTREE) {
	} else {
		qstr = fmt::format("SELECT name FROM folders WHERE folder_id={}", parent_id);
		pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
		if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
			return;
		decoded_name = pstmt.col_text(0);
		pstmt.finalize();
	}
	static constexpr proptag_t tmp_proptag[] = {PR_DISPLAY_NAME};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
	TPROPVAL_ARRAY propvals;
	if (!exmdb_client::get_folder_properties(common_util_get_maildir(), CP_ACP,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return;		

	auto str = propvals.get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr)
		return;
	auto tmp_len = strlen(str);
	if (tmp_len >= 256)
		return;
	std::string temp_name;
	if (parent_id == PRIVATE_FID_IPMSUBTREE) {
		temp_name.assign(str, tmp_len);
	} else {
		temp_name = std::move(decoded_name) + "/"s + str;
	}
	auto ust = gx_sql_prep(pidb->psqlite,
	           "UPDATE folders SET parent_fid=?, name=? WHERE folder_id=?");
	if (ust != nullptr) {
		if (ust.bind_int64(1, parent_id) != SQLITE_OK ||
		    ust.bind_text(2, temp_name) != SQLITE_OK ||
		    ust.bind_int64(3, folder_id) != SQLITE_OK ||
		    ust.step() != SQLITE_DONE)
			/* ignore */;
		ust.finalize();
	}
	mail_engine_update_subfolders_name(pidb, folder_id, temp_name);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1478: ENOMEM");
}

static void mail_engine_modify_notification_folder(IDB_ITEM *pidb,
    uint64_t folder_id) try
{
	if (folder_id == PRIVATE_FID_IPMSUBTREE || folder_id == PRIVATE_FID_INBOX)
		return;
	auto qstr = fmt::format("SELECT name, parent_fid FROM folders WHERE folder_id={}", folder_id);
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return;
	std::string decoded_name = pstmt.col_text(0);
	uint64_t parent_fid = pstmt.col_uint64(1);
	pstmt.finalize();

	static constexpr proptag_t tmp_proptag[] = {PR_DISPLAY_NAME};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptag), deconst(tmp_proptag)};
	TPROPVAL_ARRAY propvals;
	if (!exmdb_client::get_folder_properties(common_util_get_maildir(), CP_ACP,
	    rop_util_make_eid_ex(1, folder_id), &proptags, &propvals))
		return;		
	auto str = propvals.get<const char>(PR_DISPLAY_NAME);
	if (str == nullptr)
		return;
	auto pdisplayname = strrchr(decoded_name.c_str(), '/');
	std::string new_path;
	if (pdisplayname == nullptr) {
		if (strcmp(decoded_name.c_str(), str) == 0)
			return;
		new_path = str;
	} else {
		if (strcmp(pdisplayname + 1, str) == 0)
			return;
		new_path = std::string(decoded_name, pdisplayname - decoded_name.c_str() + 1) + str;
	}
	if (parent_fid == PRIVATE_FID_IPMSUBTREE && strncasecmp(str, "inbox", 5) == 0)
		new_path += "." + std::to_string(folder_id);
	auto xact = gx_sql_begin(pidb->psqlite, txn_mode::write);
	if (!xact)
		return;
	auto ust = gx_sql_prep(pidb->psqlite, "UPDATE folders SET name=? "
	           "WHERE folder_id=?");
	if (ust == nullptr ||
	    ust.bind_text(1, new_path) != SQLITE_OK ||
	    ust.bind_int64(2, folder_id) != SQLITE_OK ||
	    ust.step() != SQLITE_DONE)
		/* ignore */;
	ust.finalize();
	mail_engine_update_subfolders_name(pidb, folder_id, new_path);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2423: ENOMEM");
}

static void mail_engine_modify_notification_message(IDB_ITEM *pidb,
    uint64_t folder_id, uint64_t message_id) try
{
	TPROPVAL_ARRAY propvals;
	static constexpr proptag_t tmp_proptags[] = {PR_MESSAGE_FLAGS, PR_LAST_MODIFICATION_TIME, PidTagMidString};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tmp_proptags), deconst(tmp_proptags)};
	if (!exmdb_client::get_message_properties(common_util_get_maildir(),
	    nullptr, CP_ACP, rop_util_make_eid_ex(1, message_id),
	    &proptags, &propvals))
		return;	
	auto num = propvals.get<const uint32_t>(PR_MESSAGE_FLAGS);
	auto message_flags = num != nullptr ? *num : 0;
	auto str = propvals.get<const char>(PidTagMidString);
	if (str != nullptr) {
 UPDATE_MESSAGE_FLAGS:
		auto b_unsent = !!(message_flags & MSGFLAG_UNSENT);
		auto b_read   = !!(message_flags & MSGFLAG_READ);
		auto qstr = fmt::format("UPDATE messages SET read={}, unsent={}"
		            " WHERE message_id={}", b_read, b_unsent, message_id);
		gx_sql_exec(pidb->psqlite, qstr.c_str());
		return;
	}
	auto ts = propvals.get<const uint64_t>(PR_LAST_MODIFICATION_TIME);
	auto mod_time = ts != nullptr ? *ts : 0;
	auto qstr = fmt::format("SELECT mod_time FROM"
	            " messages WHERE message_id={}", message_id);
	auto pstmt = gx_sql_prep(pidb->psqlite, qstr.c_str());
	if (pstmt == nullptr || pstmt.step() != SQLITE_ROW)
		return;
	if (gx_sql_col_uint64(pstmt, 0) == mod_time) {
		pstmt.finalize();
		goto UPDATE_MESSAGE_FLAGS;
	}
	pstmt.finalize();
	qstr = fmt::format("DELETE FROM messages WHERE message_id={}", message_id);
	if (gx_sql_exec(pidb->psqlite, qstr.c_str()) != SQLITE_OK)
		return;	
	return mail_engine_add_notification_message(
					pidb, folder_id, message_id);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2424: ENOMEM");
}

static void mail_engine_notification_proc(const char *dir,
    BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify) try
{
	if (b_table)
		return;
	auto pidb = mail_engine_peek_idb(dir);
	if (pidb == nullptr || pidb->sub_id != notify_id)
		return;
	uint64_t parent_id = 0, folder_id = 0, message_id = 0;
	switch (pdb_notify->type) {
	case db_notify_type::new_mail: {
		auto n = static_cast<const DB_NOTIFY_NEW_MAIL *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case db_notify_type::folder_created: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_CREATED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		parent_id = n->parent_id;
		mail_engine_add_notification_folder(pidb.get(), parent_id, folder_id);
		break;
	}
	case db_notify_type::message_created: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case db_notify_type::folder_deleted: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_DELETED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		mail_engine_delete_notification_folder(pidb.get(), folder_id);
		break;
	}
	case db_notify_type::message_deleted: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;

		auto qstr = fmt::format("SELECT name FROM folders WHERE folder_id={}", folder_id);
		auto stm = gx_sql_prep(pidb->psqlite, qstr.c_str());
		if (stm == nullptr || stm.step() != SQLITE_ROW)
			return;
		std::string name = znul(stm.col_text(0));
		/* end implicit transaction since we have not attempted to read
		 * past the last row yet */
		stm.finalize();
		mail_engine_delete_notification_message(pidb.get(), folder_id,
			message_id, pidb->username, name.c_str());
		folder_id = 0;
		break;
	}
	case db_notify_type::folder_modified: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		mail_engine_modify_notification_folder(pidb.get(), folder_id);
		break;
	}
	case db_notify_type::message_modified: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata);
		message_id = n->message_id;
		folder_id = n->folder_id;
		mail_engine_modify_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	case db_notify_type::folder_moved: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		parent_id = n->parent_id;
		mail_engine_move_notification_folder(pidb.get(), parent_id, folder_id);
		break;
	}
	case db_notify_type::message_moved: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		folder_id = n->old_folder_id;
		message_id = n->old_message_id;

		auto qstr = fmt::format("SELECT name FROM folders WHERE folder_id={}", folder_id);
		auto stm = gx_sql_prep(pidb->psqlite, qstr.c_str());
		if (stm == nullptr || stm.step() != SQLITE_ROW)
			return;
		std::string name = znul(stm.col_text(0));
		stm.finalize();
		mail_engine_delete_notification_message(pidb.get(), folder_id,
			message_id, pidb->username, name.c_str());
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id,
			message_id);
		break;
	}
	case db_notify_type::folder_copied: {
		auto n = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		parent_id = n->parent_id;
		if (mail_engine_add_notification_folder(pidb.get(), parent_id, folder_id))
			mail_engine_sync_contents(pidb.get(), folder_id);
		break;
	}
	case db_notify_type::message_copied: {
		auto n = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		folder_id = n->folder_id;
		message_id = n->message_id;
		mail_engine_add_notification_message(pidb.get(), folder_id, message_id);
		break;
	}
	default:
		break;
	}

	/* Broadcast a FOLDER-TOUCH event */
	if (folder_id != 0) {
		auto qstr = fmt::format("SELECT name FROM folders WHERE folder_id={}", folder_id);
		auto stm = gx_sql_prep(pidb->psqlite, qstr.c_str());
		if (stm == nullptr || stm.step() != SQLITE_ROW)
			return;
		std::string name = znul(stm.col_text(0));
		stm.finalize();
		qstr = fmt::format("FOLDER-TOUCH {} {}", pidb->username, name);
		system_services_broadcast_event(qstr.c_str());
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2346: ENOMEM");
}

void mail_engine_init(const char *default_charset, const char *org_name,
    size_t table_size)
{
	g_sequence_id = 0;
	gx_strlcpy(g_default_charset, default_charset, std::size(g_default_charset));
	gx_strlcpy(g_org_name, org_name, std::size(g_org_name));
	g_table_size = table_size;
}

static constexpr struct {
	const char key[8];
	midb_cmd value;
} mail_engine_commands[] = {
	{"M-INST", {mail_engine_minst, 6}},
	{"M-DELE", {mail_engine_mdele, 4, INT_MAX}},
	{"M-COPY", {mail_engine_mcopy, 5}},
	{"M-MAKF", {mail_engine_mmakf, 3}},
	{"M-REMF", {mail_engine_mremf, 3}},
	{"M-RENF", {mail_engine_mrenf, 4}},
	{"M-ENUM", {mail_engine_menum, 2}},
	{"M-PING", {mail_engine_mping, 2}},
	{"P-UNID", {mail_engine_punid, 4}},
	{"P-FDDT", {mail_engine_pfddt, 3}},
	{"P-SUBF", {mail_engine_psubf, 3}},
	{"P-UNSF", {mail_engine_punsf, 3}},
	{"P-SUBL", {mail_engine_psubl, 2}},
	{"P-SIMU", {mail_engine_psimu, 5}},
	{"P-DELL", {mail_engine_pdell, 3}},
	{"P-DTLU", {mail_engine_pdtlu, 5}},
	{"P-SFLG", {mail_engine_psflg, 5}},
	{"P-RFLG", {mail_engine_prflg, 5}},
	{"P-GFLG", {mail_engine_pgflg, 4}},
	{"P-SRHL", {mail_engine_psrhl, 5}},
	{"P-SRHU", {mail_engine_psrhu, 5}},
	{"X-UNLD", {mail_engine_xunld, 2}},
	{"X-RSYM", {mail_engine_xrsym, 2}},
	{"X-RSYF", {mail_engine_xrsyf, 3}},
};

int mail_engine_run()
{
	if (sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK)
		mlog(LV_WARN, "mail_engine: failed to change "
			"to multiple thread mode for sqlite engine");
	if (sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0) != SQLITE_OK)
		mlog(LV_WARN, "mail_engine: failed to close"
			" memory statistic for sqlite engine");
	if (!oxcmail_init_library(g_org_name, system_services_get_user_ids,
	    system_services_get_domain_ids, system_services_get_username_from_id)) {
		mlog(LV_ERR, "mail_engine: failed to init oxcmail library");
		return -1;
	}
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_tid, nullptr, midbme_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "mail_engine: failed to create scan thread: %s", strerror(ret));
		return -5;
	}
	pthread_setname_np(g_scan_tid, "mail_engine");
	for (const auto &e : mail_engine_commands)
		cmd_parser_register_command(e.key, e.value);
	exmdb_client_register_proc(reinterpret_cast<void *>(mail_engine_notification_proc));
	return 0;
}

void mail_engine_stop()
{
	g_notify_stop = true;
	if (!pthread_equal(g_scan_tid, {})) {
		pthread_kill(g_scan_tid, SIGALRM);
		pthread_join(g_scan_tid, NULL);
	}
	{ /* silence cov-scan, take locks even in single-thread scenarios */
		std::lock_guard lk(g_hash_lock);
		g_hash_table.clear();
	}
}
