#ifndef _H_SMTP_DELIVERER_
#define _H_SMTP_DELIVERER_
#include "hook_common.h"

enum{
	SMTP_DELIVERER_OK,
	SMTP_DELIVERER_GIVE_UP,
	SMTP_DELIVERER_DNS_ERROR,
	SMTP_DELIVERER_CANNOT_CONNECT,
	SMTP_DELIVERER_TIME_OUT,
	SMTP_DELIVERER_CONNECTION_REFUSED,
	SMTP_DELIVERER_EXCEED_SIZE,
	SMTP_DELIVERER_NO_USER,
	SMTP_DELIVERER_TEMP_ERROR,
	SMTP_DELIVERER_PERMANENT_ERROR,
	SMTP_DELIVERER_UNKOWN_RESPONSE
};

enum{
	SMTP_DELIVERER_TRYING_TIMES,
	SMTP_DELIVERER_SSL_SWITCH
};

#define		BOUND_REMOTE_BOUNCE			5

void smtp_deliverer_init(int trying_times, BOOL ssl_switch);

int smtp_deliverer_run();

int smtp_deliverer_stop();

void smtp_deliverer_free();

int smtp_deliverer_process(MESSAGE_CONTEXT *pcontext,
	char *ip_addr, char *response_line, int length);

int smtp_deliverer_get_param(int param);

void smtp_deliverer_set_param(int param, int val);

void smtp_deliverer_log_info(MESSAGE_CONTEXT *pcontext,
	int level, char *format, ...);


#endif /* _H_SMTP_DELIVERER_ */

