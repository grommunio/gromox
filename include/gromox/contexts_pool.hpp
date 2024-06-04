#pragma once
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#define MAX_TURN_COUNTS     0x7FFFFFFF

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

enum class sctx_status {
	invalid = -1,
	begin = 0,
	free = 0, /* context is free */
	idling, /* context is waiting on self-defined condition */
	polling, /* context is waiting on epoll*/
	sleeping, /* context is need to sleep */
	turning, /* context is waiting to be served by pool threads */
	_alloc_max,
	/* special types follow */
	constructing, /* context is newly obtained from pool and waiting to be constructed */
	switching, /* context is switching between scheduling (polling, idling to turning) queues */
};

struct schedule_context {
	DOUBLE_LIST_NODE node{};
	sctx_status type = sctx_status::free;
	BOOL b_waiting = false; /* is still in epoll queue */
	int polling_mask = 0;
	unsigned int context_id = 0;
};
using SCHEDULE_CONTEXT = schedule_context;

extern GX_EXPORT void contexts_pool_init(schedule_context **, unsigned int context_num, int (*get_socket)(const schedule_context *), gromox::time_point (*get_ts)(const schedule_context *), unsigned int contexts_per_thr, gromox::time_duration timeout);
extern GX_EXPORT int contexts_pool_run();
extern GX_EXPORT void contexts_pool_stop();
extern GX_EXPORT schedule_context *contexts_pool_get_context(sctx_status);
extern GX_EXPORT void contexts_pool_put_context(schedule_context *, sctx_status);
extern GX_EXPORT BOOL contexts_pool_wakeup_context(schedule_context *, sctx_status);
extern GX_EXPORT void context_pool_activate_context(schedule_context *);
extern GX_EXPORT void contexts_pool_signal(schedule_context *);
extern GX_EXPORT int contexts_pool_get_param(int type);
