#pragma once
#include <cstdint>
#include <sqlite3.h>
#include <string>
#include <utility>
enum cnguid_type { CN_USER, CN_DOMAIN };
extern void adjust_rights(int fd);
extern void adjust_rights(const char *);
extern bool make_mailbox_hierarchy(const std::string &basedir);
extern bool add_folderprop_iv(sqlite3_stmt *, uint32_t art_num, bool add_next);
extern bool add_folderprop_sv(sqlite3_stmt *, const char *dispname, const char *contcls);
extern bool add_folderprop_tv(sqlite3_stmt *);
extern bool add_changenum(sqlite3_stmt *, enum cnguid_type, uint64_t user_id, uint64_t change_num);
extern int mbop_truncate_chown(const char *, const char *, bool);
extern int mbop_insert_namedprops(sqlite3 *, const char *);
extern int mbop_insert_storeprops(sqlite3 *, const std::pair<uint32_t, uint64_t> *);
extern int mbop_slurp(const char *, const char *, std::string &);
