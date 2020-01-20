#pragma once
#include "common_types.h"

void precise_interception_init(const char *path);
extern int precise_interception_run(void);
extern int precise_interception_stop(void);
extern void precise_interception_free(void);
BOOL precise_interception_judge(const char* ptr, int length);

void precise_interception_console_talk(int argc, char **argv, char *result,
	int length);
