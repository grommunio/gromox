#pragma once
#include "common_types.h"
#include <time.h>

extern void auto_response_init(void);
extern int auto_response_run(void);
extern void auto_response_stop(void);
extern void auto_response_free(void);
void auto_response_reply(const char *user_home, const char *from,
	const char *rcpt);
