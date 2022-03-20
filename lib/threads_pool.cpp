// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/lib_buffer.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>

#define MAX_TIMES_NOT_SERVED			100

#define MAX_NOT_EMPTY_TIMES				10

#define THREAD_STACK_SIZE           	16 * 1024 * 1024

namespace {
struct THR_DATA {
	DOUBLE_LIST_NODE node;
	BOOL notify_stop;
	pthread_t id;
};
}

static pthread_t g_scan_id;
static gromox::atomic_bool g_notify_stop{true};
static unsigned int g_threads_pool_min_num, g_threads_pool_max_num, g_threads_pool_cur_thr_num;
static std::unique_ptr<LIB_BUFFER> g_threads_data_buff;
static DOUBLE_LIST g_threads_data_list;
static THREADS_EVENT_PROC g_threads_event_proc;
static std::mutex g_threads_pool_data_lock, g_threads_pool_cond_mutex;
static std::condition_variable g_threads_pool_waken_cond;

static void *tpol_thrwork(void *);
static void *tpol_scanwork(void *);

static int (*threads_pool_process_func)(SCHEDULE_CONTEXT*);

void threads_pool_init(unsigned int init_pool_num, int (*process_func)(SCHEDULE_CONTEXT *))
{
	unsigned int contexts_max_num, contexts_per_thr;

	gromox::setup_sigalrm();
	g_threads_pool_min_num = init_pool_num;
	threads_pool_process_func = process_func;
	/* Caution: Threads pool should be initialized
	after that contexts pool has been initialized. */
	contexts_max_num = contexts_pool_get_param(MAX_CONTEXTS_NUM);
	contexts_per_thr = contexts_pool_get_param(CONTEXTS_PER_THR);
	g_threads_pool_max_num = (contexts_max_num +
		contexts_per_thr - 1)/ contexts_per_thr; 
	if (g_threads_pool_min_num > g_threads_pool_max_num) {
		g_threads_pool_min_num = g_threads_pool_max_num;
	}
	g_threads_pool_cur_thr_num = 0;
	g_threads_data_buff.reset();
	g_threads_event_proc = NULL;
	double_list_init(&g_threads_data_list);
}

int threads_pool_run()
{
	int created_thr_num;
	pthread_attr_t attr;
	
	/* g_threads_data_buff is protected by g_threads_pool_data_lock */
	g_threads_data_buff = LIB_BUFFER::create(sizeof(THR_DATA),
	                      g_threads_pool_max_num, false);
	if (NULL == g_threads_data_buff) {
		printf("[threads_pool]: Failed to allocate memory for threads pool\n");
		return -1;
	}
	/* list is also protected by g_threads_pool_data_lock */
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, tpol_scanwork, nullptr);
	if (ret != 0) {
		printf("[threads_pool]: failed to create scan thread: %s\n", strerror(ret));
		g_threads_data_buff.reset();
		return -2;
	}
	pthread_setname_np(g_scan_id, "ep_pool/scan");
	pthread_attr_init(&attr);
	created_thr_num = 0;
	for (size_t i = 0; i < g_threads_pool_min_num; ++i) {
		auto pdata = g_threads_data_buff->get<THR_DATA>();
		pdata->node.pdata = pdata;
		pdata->id = (pthread_t)-1;
		pdata->notify_stop = FALSE;
		pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
		ret = pthread_create(&pdata->id, &attr, tpol_thrwork, pdata);
		if (ret != 0) {
			printf("[threads_pool]: failed to create a pool thread: %s\n", strerror(ret));
		} else {
			char buf[32];
			snprintf(buf, sizeof(buf), "ep_pool/%zu", i);
			pthread_setname_np(pdata->id, buf);
			created_thr_num ++;
			double_list_append_as_tail(&g_threads_data_list, &pdata->node);
		}
	}
	pthread_attr_destroy(&attr);
	g_threads_pool_cur_thr_num = created_thr_num;
	return 0;
}

void threads_pool_stop()
{
	THR_DATA *pthr;
	pthread_t thr_id;
	DOUBLE_LIST_NODE *pnode;
	BOOL b_should_exit = FALSE;
	
	g_notify_stop = true;
	if (!pthread_equal(g_scan_id, {})) {
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, NULL);
	}
	while (true) {
		/* get a thread from list */
		std::unique_lock tpd_hold(g_threads_pool_data_lock);
		pnode = double_list_get_head(&g_threads_data_list);
		if (1 == double_list_get_nodes_num(&g_threads_data_list)) {
			b_should_exit = TRUE;
		}
		tpd_hold.unlock();
		pthr = (THR_DATA*)pnode->pdata;
		thr_id = pthr->id;
		/* notify this thread to exit */
		pthr->notify_stop = TRUE;
		/* wake up all thread waiting on the event */
		g_threads_pool_waken_cond.notify_all();
		pthread_kill(thr_id, SIGALRM); /* may be in nanosleep */
		pthread_join(thr_id, NULL);
		if (b_should_exit)
			break;
	}
	g_threads_data_buff.reset();
	g_threads_data_buff.reset();
	g_threads_pool_min_num = 0;
	g_threads_pool_max_num = 0;
	g_threads_pool_cur_thr_num = 0;
	g_threads_event_proc = NULL;
}

int threads_pool_get_param(int type)
{
	switch(type) {
	case THREADS_POOL_MIN_NUM:
		return g_threads_pool_min_num;
	case THREADS_POOL_MAX_NUM:
		return g_threads_pool_max_num;
	case THREADS_POOL_CUR_THR_NUM:
		return g_threads_pool_cur_thr_num;
	default:
		return -1;
	}
}

static void *tpol_thrwork(void *pparam)
{
	THR_DATA *pdata;
	int cannot_served_times;
	int max_contexts_per_thr;
	int contexts_per_threads;
	SCHEDULE_CONTEXT *pcontext;
	
	
	pdata = (THR_DATA*)pparam;
	max_contexts_per_thr = contexts_pool_get_param(CONTEXTS_PER_THR);
	contexts_per_threads = max_contexts_per_thr / 4;
	if (NULL!= g_threads_event_proc) {
		g_threads_event_proc(THREAD_CREATE);
	}   
	
	cannot_served_times = 0;
	while (!pdata->notify_stop) {
		pcontext = contexts_pool_get_context(CONTEXT_TURNING);
		if (NULL == pcontext) {
			if (MAX_TIMES_NOT_SERVED == cannot_served_times) {
				std::unique_lock tpd_hold(g_threads_pool_data_lock);
				int gpr;
				if (g_threads_pool_cur_thr_num > g_threads_pool_min_num &&
				    (gpr = contexts_pool_get_param(CUR_VALID_CONTEXTS)) >= 0 &&
				    g_threads_pool_cur_thr_num * contexts_per_threads > static_cast<size_t>(gpr)) {
					double_list_remove(&g_threads_data_list, &pdata->node);
					g_threads_data_buff->put(pdata);
					g_threads_pool_cur_thr_num --;
					tpd_hold.unlock();
					if (NULL != g_threads_event_proc) {
						g_threads_event_proc(THREAD_DESTROY);
					}
					pthread_detach(pthread_self());
					return nullptr;
				}
			} else {
				cannot_served_times ++;
			}
			/* wait context */
			std::unique_lock tpc_hold(g_threads_pool_cond_mutex);
			g_threads_pool_waken_cond.wait_for(tpc_hold, std::chrono::seconds(1));
			continue;
		}
		cannot_served_times = 0;
		switch (threads_pool_process_func(pcontext)) {
		case PROCESS_CONTINUE:
			contexts_pool_put_context(pcontext, CONTEXT_TURNING);
			break;
		case PROCESS_IDLE:
			contexts_pool_put_context(pcontext, CONTEXT_IDLING);
			break;
		case PROCESS_POLLING_NONE:
			pcontext->polling_mask = 0;
			contexts_pool_put_context(pcontext, CONTEXT_POLLING);
			break;
		case PROCESS_POLLING_RDONLY:
			pcontext->polling_mask = POLLING_READ;
			contexts_pool_put_context(pcontext, CONTEXT_POLLING);
			break;
		case PROCESS_POLLING_WRONLY:
			pcontext->polling_mask = POLLING_WRITE;
			contexts_pool_put_context(pcontext, CONTEXT_POLLING);
			break;
		case PROCESS_POLLING_RDWR:
			pcontext->polling_mask = POLLING_READ | POLLING_WRITE;
			contexts_pool_put_context(pcontext, CONTEXT_POLLING);
			break;
		case PROCESS_SLEEPING:
			contexts_pool_put_context(pcontext, CONTEXT_SLEEPING);
			break;
		case PROCESS_CLOSE:
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			break;
		}
	}
	
	std::unique_lock tpd_hold(g_threads_pool_data_lock);
	double_list_remove(&g_threads_data_list, &pdata->node);
	g_threads_data_buff->put(pdata);
	g_threads_pool_cur_thr_num --;
	tpd_hold.unlock();
	if (NULL != g_threads_event_proc) {
		g_threads_event_proc(THREAD_DESTROY);
	}
	return NULL;
}

void threads_pool_wakeup_thread()
{
	if (g_notify_stop)
		return;
	g_threads_pool_waken_cond.notify_one();
}

void threads_pool_wakeup_all_threads()
{
	if (g_notify_stop)
		return;
	g_threads_pool_waken_cond.notify_all();
}

static void *tpol_scanwork(void *pparam)
{
	THR_DATA *pdata;
	int not_empty_times;
	pthread_attr_t attr;
	
	not_empty_times = 0;
	while (!g_notify_stop) {
		sleep(1);
		if (contexts_pool_get_param(CUR_SCHEDUING_CONTEXTS) > 1) {
			not_empty_times ++;
			if (not_empty_times < MAX_NOT_EMPTY_TIMES) {
				continue;
			}
			std::lock_guard tpd_hold(g_threads_pool_data_lock);
			if (g_threads_pool_cur_thr_num >= g_threads_pool_max_num) {
				continue;
			}
			pdata = g_threads_data_buff->get<THR_DATA>();
			if (NULL != pdata) {
				pdata->node.pdata = pdata;
				pdata->id = (pthread_t)-1;
				pdata->notify_stop = FALSE;
				pthread_attr_init(&attr);
				pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
				auto ret = pthread_create(&pdata->id, &attr, tpol_thrwork, pdata);
				if (ret != 0) {
					debug_info("[threads_pool]: W-1445: failed to increase pool threads: %s\n", strerror(ret));
					g_threads_data_buff->put(pdata);
				} else {
					pthread_setname_np(pdata->id, "ep_pool/+");
					double_list_append_as_tail(
						&g_threads_data_list, &pdata->node);
					g_threads_pool_cur_thr_num ++;
				}
				pthread_attr_destroy(&attr);
			} else {
				debug_info("[threads_pool]: fatal error,"
					" threads pool memory conflicts!\n");
			}
		}
		not_empty_times = 0;
	}
	return nullptr;
}

THREADS_EVENT_PROC threads_pool_register_event_proc(THREADS_EVENT_PROC proc)
{
	THREADS_EVENT_PROC temp_proc;

	temp_proc = g_threads_event_proc;
	g_threads_event_proc = proc;
	return temp_proc;
}
