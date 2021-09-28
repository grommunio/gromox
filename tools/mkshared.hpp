#pragma once
#include <cstdint>
#include <sqlite3.h>
extern void adjust_rights(int fd);
extern void adjust_rights(const char *file);
extern bool add_folderprop_iv(sqlite3_stmt *, uint32_t art_num, bool add_next);
extern bool add_folderprop_sv(sqlite3_stmt *, const char *dispname, const char *contcls);
extern bool add_folderprop_tv(sqlite3_stmt *, uint64_t nt_time);
