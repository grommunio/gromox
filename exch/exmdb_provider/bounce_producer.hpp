#pragma once
#include <sqlite3.h>

struct MAIL;
extern int bounce_producer_run(const char *, const char *, const char *);
extern BOOL exmdb_bouncer_make_content(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, const char *bounce_type, char *mime_from, char *subject, char *content_type, char *content, size_t content_size);
extern BOOL exmdb_bouncer_make(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, const char *bounce_type, MAIL *);
