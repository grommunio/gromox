#ifndef _H_PRECISE_INTERCEPTION_
#define _H_PRECISE_INTERCEPTION_
#include "common_types.h"

void precise_interception_init(const char *path);

int precise_interception_run();

int precise_interception_stop();

void precise_interception_free();

BOOL precise_interception_judge(const char* ptr, int length);

void precise_interception_console_talk(int argc, char **argv, char *result,
	int length);


#endif /* _H_PRECISE_INTERCEPTION_ */
