#pragma once
#include <atomic>
#include <cstdint>
#include <sqlite3.h>

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
