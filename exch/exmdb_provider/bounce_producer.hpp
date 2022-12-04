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

extern void bounce_producer_init(const char *separator);
extern int bounce_producer_run(const char *data_path);
BOOL bounce_producer_make_content(const char *from,
	const char *rcpt, sqlite3 *psqlite, uint64_t message_id,
	int bounce_type, char *mime_from, char *subject,
	char *content_type, char *pcontent);
BOOL bounce_producer_make(const char *from, const char *rcpt,
	sqlite3 *psqlite, uint64_t message_id, int bounce_type,
	MAIL *pmail);
