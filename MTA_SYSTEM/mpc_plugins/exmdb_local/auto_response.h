#ifndef _H_AUTO_RESPONSE_
#define _H_AUTO_RESPONSE_
#include "common_types.h"
#include <time.h>


void auto_response_init();

int auto_response_run();
extern void auto_response_stop(void);
void auto_response_free();

void auto_response_reply(const char *user_home, const char *from,
	const char *rcpt);


#endif
