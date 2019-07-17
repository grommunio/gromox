#ifndef _H_DOMAIN_CLEANER_
#define _H_DOMAIN_CLEANER_
#include <time.h>

void domain_cleaner_init(time_t now_time);

int domain_cleaner_run();

int domain_cleaner_stop();

void domain_cleaner_free();

#endif
