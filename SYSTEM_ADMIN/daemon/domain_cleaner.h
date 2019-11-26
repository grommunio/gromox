#ifndef _H_DOMAIN_CLEANER_
#define _H_DOMAIN_CLEANER_
#include <time.h>

void domain_cleaner_init(time_t now_time);
extern int domain_cleaner_run(void);
extern int domain_cleaner_stop(void);
extern void domain_cleaner_free(void);

#endif
