#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_

#include <time.h>
#include <gromox/hook_common.h>

enum{
    BOUNCE_ADDRESS_ILLEGAL,
    BOUNCE_DNS_ERROR,
    BOUNCE_CANNOT_CONNECT,
    BOUNCE_TIME_OUT,
    BOUNCE_CONNECTION_REFUSED,
	BOUNCE_EXCEED_SIZE,
    BOUNCE_NO_USER,
    BOUNCE_RESPONSE_ERROR,
	BOUNCE_TOTAL_NUM
};


void bounce_producer_init(const char *path, const char* separator);
extern int bounce_producer_run(void);
extern void bounce_producer_stop(void);
extern void bounce_producer_free(void);
extern BOOL bounce_producer_refresh(void);
void bounce_producer_make(MESSAGE_CONTEXT *pcontext, time_t orignal_time,
	int bounce_type, const char *remote_ip, char *reason_buff, MAIL *pmail);

#endif
