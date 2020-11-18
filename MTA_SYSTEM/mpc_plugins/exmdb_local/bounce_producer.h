#pragma once
#include <time.h>
#include <gromox/hook_common.h>

enum{
    BOUNCE_NO_USER,
    BOUNCE_MAILBOX_FULL,
    BOUNCE_OPERATION_ERROR,
	BOUNCE_MAIL_DELIVERED,
	BOUNCE_TOTAL_NUM
};

#ifdef  __cplusplus
extern "C" {
#endif

void bounce_producer_init(const char *path, const char *separator);
extern int bounce_producer_run(void);
extern void bounce_producer_stop(void);
extern void bounce_producer_free(void);
extern BOOL bounce_producer_refresh(void);
void bounce_producer_make(const char *from, const char *rcpt,
	MAIL *pmail_original, time_t orignal_time, int bounce_type, MAIL *pmail);

#ifdef  __cplusplus
}
#endif
