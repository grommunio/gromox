#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_
#include "mail.h"
#include <sqlite3.h>

enum{
    BOUNCE_AUTO_RESPONSE,
    BOUNCE_MAIL_TOO_LARGE,
	BOUNCE_CANNOT_DISPLAY,
    BOUNCE_GENERIC_ERROR,
	BOUNCE_TOTAL_NUM
};

void bounce_producer_init(const char *path, const char *separator);

int bounce_producer_run();

int bounce_producer_stop();

void bounce_producer_free();

BOOL bounce_producer_refresh();

BOOL bounce_producer_make_content(const char *from,
	const char *rcpt, sqlite3 *psqlite, uint64_t message_id,
	int bounce_type, char *mime_from, char *subject,
	char *content_type, char *pcontent);

BOOL bounce_producer_make(const char *from, const char *rcpt,
	sqlite3 *psqlite, uint64_t message_id, int bounce_type,
	MAIL *pmail);

#endif /* _H_BOUNCE_PRODUCER_ */
