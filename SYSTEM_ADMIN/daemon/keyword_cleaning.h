#ifndef _H_KEYWORD_CLEANING_
#define _H_KEYWORD_CLEANING_
#include <time.h>


void keyword_cleaning_init(time_t now_time, const char *group_path,
	const char *console_path, const char *statistic_path);

int keyword_cleaning_run();

int keyword_cleaning_stop();

void keyword_cleaning_free();

#endif
