#pragma once
#include <time.h>

void password_cleaner_init(time_t now_time);
extern int password_cleaner_run(void);
extern void password_cleaner_stop(void);
extern void password_cleaner_free(void);
