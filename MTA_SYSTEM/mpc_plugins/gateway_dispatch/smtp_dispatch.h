#ifndef _H_SMTP_DISPATCH_
#define _H_SMTP_DISPATCH_
#include "hook_common.h"

enum{
	SMTP_DISPATCH_OK,
	SMTP_DISPATCH_NO_USER,
	SMTP_DISPATCH_TEMP_ERROR,
	SMTP_DISPATCH_PERMANENT_ERROR,
	SMTP_DISPATCH_TOTAL_NUM
};

void smtp_dispatch_init(const char *mask_string);

int smtp_dispatch_run();

int smtp_dispatch_stop();

void smtp_dispatch_free();

int smtp_dispatch_process(MESSAGE_CONTEXT *pcontext,
	char *dest_ip, char *response_line, int length);

void smtp_dispatch_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...);

BOOL smtp_dispatch_has_maskstring();

#endif /* _H_SMTP_DISPATCH_ */

