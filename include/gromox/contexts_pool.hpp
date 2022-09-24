#pragma once
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#define MAX_TURN_COUNTS     0x7FFFFFFF

enum{
	CONTEXT_BEGIN = 0,
	CONTEXT_FREE = 0,	/* context is free */
	CONTEXT_IDLING,		/* context is waiting on self-defined condition */
	CONTEXT_POLLING,	/* context is waiting on epoll*/
	CONTEXT_SLEEPING,	/* context is need to sleep */
	CONTEXT_TURNING,	/* context is waiting to be served by pool threads */
	CONTEXT_TYPES,
	CONTEXT_CONSTRUCTING,	/* context is got from pool
								and wait to be construct */
	CONTEXT_SWITCHING		/* context is switching between scheduling
								(polling, idling to turning) queues */
};

/* enumeration for distinguishing parameters of contexts pool */
enum{
	MAX_CONTEXTS_NUM,
	CONTEXTS_PER_THR,
	CUR_VALID_CONTEXTS,
	CUR_SLEEPING_CONTEXTS,
	CUR_SCHEDULING_CONTEXTS,
};

#define POLLING_READ						0x1
#define POLLING_WRITE						0x2

struct schedule_context {
	DOUBLE_LIST_NODE node{};
	int type = CONTEXT_FREE;
	BOOL b_waiting = false; /* is still in epoll queue */
	int polling_mask = 0;
	unsigned int context_id = 0;
};
using SCHEDULE_CONTEXT = schedule_context;

template<typename T> static inline auto
CALCULATE_INTERVAL(T a, T b) -> decltype(a-b) { return a - b; }

extern GX_EXPORT void contexts_pool_init(schedule_context **, unsigned int context_num, int (*get_socket)(const schedule_context *), gromox::time_point (*get_ts)(const schedule_context *), unsigned int contexts_per_thr, gromox::time_duration timeout);
extern int contexts_pool_run();
extern void contexts_pool_stop();
SCHEDULE_CONTEXT* contexts_pool_get_context(int type);
void contexts_pool_put_context(SCHEDULE_CONTEXT *pcontext, int type);
BOOL contexts_pool_wakeup_context(SCHEDULE_CONTEXT *pcontext, int type);
void context_pool_activate_context(SCHEDULE_CONTEXT *);
void contexts_pool_signal(SCHEDULE_CONTEXT *pcontext);
int contexts_pool_get_param(int type);
