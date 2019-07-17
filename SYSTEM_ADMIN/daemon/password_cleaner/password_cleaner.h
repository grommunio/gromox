#ifndef _H_PASSWORD_CLEANER_
#define _H_PASSWORD_CLEANER_
#include <time.h>

void password_cleaner_init(time_t now_time);

int password_cleaner_run();


int password_cleaner_stop();


void password_cleaner_free();


#endif
