#pragma once
#include "common_types.h"

void invalid_user_init(const char *config_path, int size, int valid_intvl);
extern int invalid_user_run(void);
BOOL invalid_user_check(const char *rcpt_address);
extern int invalid_user_stop(void);
extern void invalid_user_free(void);
void invalid_user_console_talk(int argc, char **argv, char *result, int length);
