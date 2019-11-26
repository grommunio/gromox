#ifndef _H_SYSTEM_LOG_
#define _H_SYSTEM_LOG_
#include <time.h>

void system_log_init(const char *path);

int system_log_run();

void system_log_info(char *format, ...);

int system_log_stop();

void system_log_free();

#endif
