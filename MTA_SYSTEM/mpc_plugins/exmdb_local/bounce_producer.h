#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_
#include "hook_common.h"
#include <time.h>

enum{
    BOUNCE_NO_USER,
    BOUNCE_MAILBOX_FULL,
    BOUNCE_OPERATION_ERROR,
	BOUNCE_MAIL_DELIVERED,
	BOUNCE_TOTAL_NUM
};

void bounce_producer_init(const char *path, const char *separator);

int bounce_producer_run();
extern void bounce_producer_stop(void);
void bounce_producer_free();

BOOL bounce_producer_refresh();

void bounce_producer_make(const char *from, const char *rcpt,
	MAIL *pmail_original, time_t orignal_time, int bounce_type, MAIL *pmail);

#endif /* _H_BOUNCE_PRODUCER_ */
