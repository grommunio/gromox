#ifndef _H_LOG_ANALYZER_
#define _H_LOG_ANALYZER_
#include <time.h>

void log_analyzer_init(time_t now_time, const char *statistic_path,
	const char *orignal_path);

int log_analyzer_run();

int log_analyzer_stop();

void log_analyzer_free();


#endif
