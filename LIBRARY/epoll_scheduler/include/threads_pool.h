#ifndef _H_THREADS_POOL_
#define _H_THREADS_POOL_

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

typedef int (*THREADS_EVENT_PROC)(int);

#ifdef __cplusplus
extern "C" {
#endif

void threads_pool_init(int init_pool_num,
	int (*process_func)(SCHEDULE_CONTEXT*));

int threads_pool_run();

int threads_pool_stop();

void threads_pool_free();

int threads_pool_get_param(int type);

THREADS_EVENT_PROC threads_pool_register_event_proc(THREADS_EVENT_PROC proc);

void threads_pool_wakeup_thread();

void threads_pool_wakeup_all_threads();

#ifdef __cplusplus
}
#endif

#endif
