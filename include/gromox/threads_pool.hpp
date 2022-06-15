#pragma once

enum{
	THREADS_POOL_MIN_NUM,
	THREADS_POOL_MAX_NUM,
	THREADS_POOL_CUR_THR_NUM
};

/* enumeration for indicating the thread the result of context and what to do */
enum{
	PROCESS_IDLE = 0,		/* wait for checking user-defined condition */
	PROCESS_CONTINUE,
	PROCESS_POLLING_NONE,
	PROCESS_POLLING_RDONLY,
	PROCESS_POLLING_WRONLY,
	PROCESS_POLLING_RDWR,
	PROCESS_SLEEPING,		/* context need to be pended */
	PROCESS_CLOSE			/* put the context into free queue */
};

/* enumeration for indicating events of threads e.g. thread create or destroy */
enum{
	THREAD_CREATE,
	THREAD_DESTROY
};

using THREADS_EVENT_PROC = int (*)(int);
struct schedule_context;

extern GX_EXPORT void threads_pool_init(unsigned int init_pool_num, int (*process_func)(schedule_context *));
extern int threads_pool_run(const char *hint = nullptr);
extern void threads_pool_stop();
int threads_pool_get_param(int type);
THREADS_EVENT_PROC threads_pool_register_event_proc(THREADS_EVENT_PROC proc);
extern void threads_pool_wakeup_thread();
extern void threads_pool_wakeup_all_threads();
