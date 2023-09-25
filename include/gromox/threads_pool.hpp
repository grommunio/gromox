#pragma once

enum{
	THREADS_POOL_MIN_NUM,
	THREADS_POOL_MAX_NUM,
	THREADS_POOL_CUR_THR_NUM
};

/* enumeration for indicating the thread the result of context and what to do */
enum class tproc_status {
	idle = 0, /* wait for checking user-defined condition */
	cont,
	polling_rdonly,
	polling_wronly,
	sleeping, /* context needs to be pended */
	close, /* put the context into free queue */

	/* special codes for http; not used by tpool itself */
	runoff,
	endproc,
	app_specific_codes = runoff,
	loop,

	/* special codes for imap; not used by tpool itself */
	context_processing,
	cmd_processing,
	literal_checking,
	literal_processing,
};

/* enumeration for indicating events of threads e.g. thread create or destroy */
enum{
	THREAD_CREATE,
	THREAD_DESTROY
};

using THREADS_EVENT_PROC = int (*)(int);
struct schedule_context;

extern GX_EXPORT void threads_pool_init(unsigned int init_pool_num, tproc_status (*process_func)(schedule_context *));
extern int threads_pool_run(const char *hint = nullptr);
extern void threads_pool_stop();
int threads_pool_get_param(int type);
THREADS_EVENT_PROC threads_pool_register_event_proc(THREADS_EVENT_PROC proc);
extern void threads_pool_wakeup_thread();
extern void threads_pool_wakeup_all_threads();
