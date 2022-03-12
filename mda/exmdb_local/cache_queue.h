#pragma once
#include <ctime>
#include <gromox/hook_common.h>
#include "bounce_producer.h"

void cache_queue_init(const char *path, int scan_interval, int retrying_times);
extern int cache_queue_run();
extern void cache_queue_stop();
extern void cache_queue_free();
extern int cache_queue_put(MESSAGE_CONTEXT *, const char *rcpt, time_t orig_time);
