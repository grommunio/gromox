#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <unordered_set>
#include <sqlite3.h>
#include <gromox/database.h>
#include <gromox/mapidefs.h>

/*
 * Full-text index of a private store, kept in <maildir>/exmdb/fts.sqlite3.
 *
 * exchange.sqlite3 is not modified. Every main database handle gets
 * temporary triggers on the messages table; changed message ids are
 * collected per handle and only handed to the indexer thread once the
 * transaction has committed. The index is maintained asynchronously and may
 * lag behind for a few seconds. When a store is opened, the index is
 * reconciled against messages.change_number, which also repairs whatever
 * was lost to a crash or to writes by other programs.
 */

extern std::atomic<bool> g_exmdb_fts;
extern unsigned int g_exmdb_fts_max_body, g_exmdb_fts_nice;

extern bool fts_handle_setup(sqlite3 *, const char *dir);
extern void fts_store_opened(const char *dir);
extern int fts_run();
extern void fts_stop();

struct db_conn;

/*
 * Narrows a restriction evaluation to the messages that can possibly
 * match, according to the index. It never decides a match by itself;
 * candidates still go through the regular restriction evaluation.
 */
class fts_prefilter {
	public:
	~fts_prefilter();
	static std::unique_ptr<fts_prefilter> create(const char *dir, const db_conn &, const RESTRICTION *);
	bool may_match(uint64_t mid);

	private:
	struct close { void operator()(sqlite3 *) const; };
	fts_prefilter() = default;

	/* m_fdb must outlive the statements and transaction below */
	std::unique_ptr<sqlite3, close> m_fdb;
	gromox::xtransaction m_txn;
	gromox::xstmt m_doc, m_msg;
	std::unordered_set<uint64_t> m_hits;
};
