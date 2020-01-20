#pragma once
#include "bounce_producer.h"
#include <time.h>
#include <gromox/hook_common.h>

enum{
	CACHE_QUEUE_SCAN_INTERVAL,
	CACHE_QUEUE_RETRYING_TIMES
};

void cache_queue_init(const char *path, int scan_interval, int retrying_times);
extern int cache_queue_run(void);
extern void cache_queue_stop(void);
extern void cache_queue_free(void);
BOOL cache_queue_put(MESSAGE_CONTEXT *pcontext, time_t original_time);

int cache_queue_get_param(int param);

void cache_queue_set_param(int param, int val);
