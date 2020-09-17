#pragma once
#include <gromox/hook_common.h>

enum{
	SMTP_CLONE_OK,
	SMTP_CLONE_TEMP_ERROR,
	SMTP_CLONE_PERMANENT_ERROR,
	SMTP_CLONE_TOTAL_NUM
};

int smtp_clone_process(MESSAGE_CONTEXT *pcontext, const char *ip, int port);
extern void smtp_clone_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);
