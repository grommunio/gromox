#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_
#include "hook_common.h"
#include <time.h>


void bounce_producer_init(const char *path, const char* separator);

int bounce_producer_run();

int bounce_producer_stop();

void bounce_producer_free();

BOOL bounce_producer_refresh();

void bounce_producer_make(MESSAGE_CONTEXT *pcontext, char *forward_to,
	char *language, char *url, MAIL *pmail);

#endif
