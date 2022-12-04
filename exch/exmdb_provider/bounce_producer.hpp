#pragma once
#include <sqlite3.h>
#include <gromox/mail.hpp>

enum{
    BOUNCE_AUTO_RESPONSE,
    BOUNCE_MAIL_TOO_LARGE,
	BOUNCE_CANNOT_DISPLAY,
    BOUNCE_GENERIC_ERROR,
	BOUNCE_TOTAL_NUM
};

extern int bounce_producer_run(const char *, const char *, const char *);
extern BOOL bounce_producer_make_content(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, unsigned int bounce_type, char *mime_from, char *subject, char *content_type, char *content);
extern BOOL bounce_producer_make(const char *from, const char *rcpt, sqlite3 *, uint64_t msg_id, unsigned int bounce_type, MAIL *);
