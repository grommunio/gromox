#pragma once
#include <cstdint>
#include <sqlite3.h>
#include <string>
#include <utility>
#include <gromox/dbop.h>

enum cnguid_type { CN_USER, CN_DOMAIN };
extern void adjust_rights(int fd);
extern void adjust_rights(const char *);
extern bool make_mailbox_hierarchy(const std::string &basedir);
extern int mbop_truncate_chown(const char *, const char *, bool);
extern int mbop_insert_namedprops(sqlite3 *, const char *);
extern int mbop_insert_storeprops(sqlite3 *, const std::pair<uint32_t, uint64_t> *);
extern int mbop_slurp(const char *, const char *, std::string &);
extern int mbop_create_generic_folder(sqlite3 *, uint64_t fid, uint64_t parent, int secid, const char *dispname, const char *cont_cls = nullptr, bool hidden = false);
extern int mbop_create_search_folder(sqlite3 *, uint64_t fid, uint64_t parent, int secid, const char *dispname);
extern int mbop_upgrade(const char *, gromox::sqlite_kind);

extern uint64_t g_last_cn;
extern uint32_t g_last_art;
