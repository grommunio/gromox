#pragma once
#include <gromox/hook_common.h>

enum{
	BOUNCE_MLIST_SPECIFIED,
    BOUNCE_MLIST_INTERNAL,
    BOUNCE_MLIST_DOMAIN,
	BOUNCE_TOTAL_NUM
};

extern void bounce_producer_init(const char *separator);
extern int bounce_producer_run(const char *datadir);
void bounce_producer_make(const char *from, const char *rcpt,
	MAIL *pmail_original, int bounce_type, MAIL *pmail);
