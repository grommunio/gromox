#pragma once
#include <sqlite3.h>

struct MAIL;
extern int bounce_producer_run(const char *, const char *, const char *);
extern BOOL bounce_producer_make_content(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, const char *bounce_type, char *mime_from, char *subject, char *content_type, char *content);
extern BOOL bounce_producer_make(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, const char *bounce_type, MAIL *);
