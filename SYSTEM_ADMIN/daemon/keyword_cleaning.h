#pragma once
#include <time.h>


void keyword_cleaning_init(time_t now_time, const char *group_path,
	const char *console_path, const char *statistic_path);
extern int keyword_cleaning_run(void);
