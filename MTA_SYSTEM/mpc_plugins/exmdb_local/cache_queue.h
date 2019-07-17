#ifndef _H_CACHE_QUEUE_
#define _H_CACHE_QUEUE_
#include "hook_common.h"
#include "bounce_producer.h"
#include <time.h>

enum{
	CACHE_QUEUE_SCAN_INTERVAL,
	CACHE_QUEUE_RETRYING_TIMES
};

void cache_queue_init(const char *path, int scan_interval, int retrying_times);

int cache_queue_run();

int cache_queue_stop();

void cache_queue_free();

BOOL cache_queue_put(MESSAGE_CONTEXT *pcontext, const char *rcpt_to,
	time_t original_time);

int cache_queue_get_param(int param);

void cache_queue_set_param(int param, int val);

#endif /* _H_CACHE_QUEUE_ */
