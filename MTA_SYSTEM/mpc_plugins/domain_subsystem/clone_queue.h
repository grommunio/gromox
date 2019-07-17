#ifndef _H_CLONE_QUEUE_
#define _H_CLONE_QUEUE_
#include "hook_common.h"
#include <time.h>

enum{
	CLONE_QUEUE_SCAN_INTERVAL,
	CLONE_QUEUE_RETRYING_TIMES
};

void clone_queue_init(const char *path, int scan_interval, int retrying_times);

int clone_queue_run();

int clone_queue_stop();

void clone_queue_free();

BOOL clone_queue_put(MESSAGE_CONTEXT *pcontext, time_t original_time);

int clone_queue_get_param(int param);

void clone_queue_set_param(int param, int val);

#endif /* _H_CLONE_QUEUE_ */

