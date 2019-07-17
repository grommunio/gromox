#ifndef _H_SMTP_CLONE_
#define _H_SMTP_CLONE_
#include "hook_common.h"

enum{
	SMTP_CLONE_OK,
	SMTP_CLONE_TEMP_ERROR,
	SMTP_CLONE_PERMANENT_ERROR,
	SMTP_CLONE_TOTAL_NUM
};

void smtp_clone_init();

int smtp_clone_run();

int smtp_clone_stop();

void smtp_clone_free();

int smtp_clone_process(MESSAGE_CONTEXT *pcontext, const char *ip, int port);

void smtp_clone_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...);


#endif /* _H_SMTP_CLONE_ */

