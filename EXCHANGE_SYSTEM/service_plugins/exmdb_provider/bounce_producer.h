#pragma once
#include "mail.h"
#include <sqlite3.h>

enum{
    BOUNCE_AUTO_RESPONSE,
    BOUNCE_MAIL_TOO_LARGE,
	BOUNCE_CANNOT_DISPLAY,
    BOUNCE_GENERIC_ERROR,
	BOUNCE_TOTAL_NUM
};

#ifdef __cplusplus
extern "C" {
#endif

void bounce_producer_init(const char *path, const char *separator);
extern int bounce_producer_run(void);
extern void bounce_producer_stop(void);
extern void bounce_producer_free(void);
extern BOOL bounce_producer_refresh(void);
BOOL bounce_producer_make_content(const char *from,
	const char *rcpt, sqlite3 *psqlite, uint64_t message_id,
	int bounce_type, char *mime_from, char *subject,
	char *content_type, char *pcontent);

BOOL bounce_producer_make(const char *from, const char *rcpt,
	sqlite3 *psqlite, uint64_t message_id, int bounce_type,
	MAIL *pmail);

#ifdef __cplusplus
} /* extern "C" */
#endif
