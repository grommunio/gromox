#pragma once
#include <time.h>

void domain_cleaner_init(time_t now_time);
extern int domain_cleaner_run(void);
