#pragma once
#include <time.h>


void keyword_cleaning_init(time_t now_time, const char *group_path,
	const char *console_path, const char *statistic_path);
extern int keyword_cleaning_run(void);
extern int keyword_cleaning_stop(void);
extern void keyword_cleaning_free(void);
