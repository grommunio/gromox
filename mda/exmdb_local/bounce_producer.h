#pragma once
#include <ctime>
#include <gromox/hook_common.h>

enum{
    BOUNCE_NO_USER,
    BOUNCE_MAILBOX_FULL,
    BOUNCE_OPERATION_ERROR,
	BOUNCE_MAIL_DELIVERED,
	BOUNCE_TOTAL_NUM
};

extern void bounce_producer_init(const char *separator);
extern int bounce_producer_run();
extern void bounce_producer_stop();
extern void bounce_producer_free();
extern BOOL bounce_producer_refresh();
void bounce_producer_make(const char *from, const char *rcpt,
	MAIL *pmail_original, time_t orignal_time, int bounce_type, MAIL *pmail);
