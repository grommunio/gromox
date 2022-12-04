#pragma once
#include <gromox/hook_common.h>

enum{
	BOUNCE_MLIST_SPECIFIED,
    BOUNCE_MLIST_INTERNAL,
    BOUNCE_MLIST_DOMAIN,
	BOUNCE_TOTAL_NUM
};

extern int bounce_producer_run(const char *, const char *, const char *);
extern bool bounce_producer_make(const char *from, const char *rcpt, MAIL *orig, unsigned int bounce_type, MAIL *cur);
