#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_

#include <gromox/hook_common.h>

enum{
	BOUNCE_MLIST_SPECIFIED,
    BOUNCE_MLIST_INTERNAL,
    BOUNCE_MLIST_DOMAIN,
	BOUNCE_TOTAL_NUM
};


void bounce_producer_init(const char *path, const char *separator);
extern int bounce_producer_run(void);
extern void bounce_producer_stop(void);
extern void bounce_producer_free(void);
extern BOOL bounce_producer_refresh(void);
void bounce_producer_make(const char *from, const char *rcpt,
	MAIL *pmail_original, int bounce_type, MAIL *pmail);

#endif
