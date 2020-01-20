#pragma once
#include <time.h>
#include <gromox/hook_common.h>

enum{
	CLONE_QUEUE_SCAN_INTERVAL,
	CLONE_QUEUE_RETRYING_TIMES
};

void clone_queue_init(const char *path, int scan_interval, int retrying_times);
extern int clone_queue_run(void);
extern int clone_queue_stop(void);
extern void clone_queue_free(void);
BOOL clone_queue_put(MESSAGE_CONTEXT *pcontext, time_t original_time);

int clone_queue_get_param(int param);

void clone_queue_set_param(int param, int val);
