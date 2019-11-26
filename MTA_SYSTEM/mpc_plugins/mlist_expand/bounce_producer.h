#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_
#include "hook_common.h"

enum{
	BOUNCE_MLIST_SPECIFIED,
    BOUNCE_MLIST_INTERNAL,
    BOUNCE_MLIST_DOMAIN,
	BOUNCE_TOTAL_NUM
};


void bounce_producer_init(const char *path, const char *separator);

int bounce_producer_run();
extern void bounce_producer_stop(void);
void bounce_producer_free();

BOOL bounce_producer_refresh();

void bounce_producer_make(const char *from, const char *rcpt,
	MAIL *pmail_original, int bounce_type, MAIL *pmail);

#endif
