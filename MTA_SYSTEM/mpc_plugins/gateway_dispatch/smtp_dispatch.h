#pragma once
#include <gromox/hook_common.h>

enum{
	SMTP_DISPATCH_OK,
	SMTP_DISPATCH_NO_USER,
	SMTP_DISPATCH_TEMP_ERROR,
	SMTP_DISPATCH_PERMANENT_ERROR,
	SMTP_DISPATCH_TOTAL_NUM
};

void smtp_dispatch_init(const char *mask_string);
extern int smtp_dispatch_run(void);
extern void smtp_dispatch_stop(void);
extern void smtp_dispatch_free(void);
int smtp_dispatch_process(MESSAGE_CONTEXT *pcontext,
	char *dest_ip, char *response_line, int length);
extern void smtp_dispatch_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);
extern BOOL smtp_dispatch_has_maskstring(void);
