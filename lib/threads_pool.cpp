// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <atomic>
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
#include <gromox/process.hpp>
#include <gromox/scope.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>

#define MAX_TIMES_NOT_SERVED			100

#define MAX_NOT_EMPTY_TIMES				10

using namespace gromox;

namespace {
struct THR_DATA {
	DOUBLE_LIST_NODE node;
	BOOL notify_stop;
	pthread_t id;
};
}

static pthread_t g_scan_id;
static gromox::atomic_bool g_notify_stop{true};
static unsigned int g_threads_pool_min_num, g_threads_pool_max_num;
static std::atomic<unsigned int> g_threads_pool_cur_thr_num;
static DOUBLE_LIST g_threads_data_list;
static THREADS_EVENT_PROC g_threads_event_proc;
static std::mutex g_threads_pool_data_lock, g_threads_pool_cond_mutex;
static std::condition_variable g_threads_pool_waken_cond;

static void *tpol_thrwork(void *);
static void *tpol_scanwork(void *);

static tproc_status (*threads_pool_process_func)(schedule_context *);

void threads_pool_init(unsigned int init_pool_num,
    tproc_status (*process_func)(schedule_context *))
{
	unsigned int contexts_max_num, contexts_per_thr;

	gromox::setup_signal_defaults();
	g_threads_pool_min_num = init_pool_num;
	threads_pool_process_func = process_func;
	/* Caution: Threads pool should be initialized
	after that contexts pool has been initialized. */
	contexts_max_num = contexts_pool_get_param(MAX_CONTEXTS_NUM);
	contexts_per_thr = contexts_pool_get_param(CONTEXTS_PER_THR);
	g_threads_pool_max_num = (contexts_max_num +
		contexts_per_thr - 1)/ contexts_per_thr; 
	if (g_threads_pool_min_num > g_threads_pool_max_num)
		g_threads_pool_min_num = g_threads_pool_max_num;
	g_threads_pool_cur_thr_num = 0;
	g_threads_event_proc = NULL;
	double_list_init(&g_threads_data_list);
}

int threads_pool_run(const char *hint) try
{
	int created_thr_num;
	
	/* list is protected by g_threads_pool_data_lock */
	g_notify_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, tpol_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "threads_pool: failed to create scan thread: %s", strerror(ret));
		return -2;
	}
	pthread_setname_np(g_scan_id, "ep_pool/scan");

	created_thr_num = 0;
	for (size_t i = 0; i < g_threads_pool_min_num; ++i) {
		auto pdata = new THR_DATA;
		pdata->node.pdata = pdata;
		pdata->id = (pthread_t)-1;
		pdata->notify_stop = FALSE;
		ret = pthread_create4(&pdata->id, nullptr, tpol_thrwork, pdata);
		if (ret != 0) {
			mlog(LV_ERR, "threads_pool: failed to create a pool thread: %s", strerror(ret));
			return -1;
		} else {
			char buf[32];
			snprintf(buf, sizeof(buf), "ep_pool/%zu", i);
			pthread_setname_np(pdata->id, buf);
			created_thr_num ++;
			double_list_append_as_tail(&g_threads_data_list, &pdata->node);
		}
	}
	g_threads_pool_cur_thr_num = created_thr_num;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2369: ENOMEM");
	return -1;
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
		if (double_list_get_nodes_num(&g_threads_data_list) == 1)
			b_should_exit = TRUE;
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
	
	pdata = (THR_DATA*)pparam;
	max_contexts_per_thr = contexts_pool_get_param(CONTEXTS_PER_THR);
	contexts_per_threads = max_contexts_per_thr / 4;
	if (g_threads_event_proc != nullptr)
		g_threads_event_proc(THREAD_CREATE);
	
	cannot_served_times = 0;
	while (!pdata->notify_stop) {
		auto pcontext = contexts_pool_get_context(sctx_status::turning);
		if (NULL == pcontext) {
			if (MAX_TIMES_NOT_SERVED == cannot_served_times) {
				std::unique_lock tpd_hold(g_threads_pool_data_lock);
				int gpr;
				/*
				 * See if some worker threads can be dropped
				 * (logic similar to PHP-FPM
				 * min_spare_servers).
				 */
				if (g_threads_pool_cur_thr_num > g_threads_pool_min_num &&
				    (gpr = contexts_pool_get_param(CUR_VALID_CONTEXTS)) >= 0 &&
				    g_threads_pool_cur_thr_num * contexts_per_threads > static_cast<size_t>(gpr)) {
					double_list_remove(&g_threads_data_list, &pdata->node);
					delete pdata;
					g_threads_pool_cur_thr_num --;
					tpd_hold.unlock();
					if (g_threads_event_proc != nullptr)
						g_threads_event_proc(THREAD_DESTROY);
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
		case tproc_status::cont:
			contexts_pool_insert(pcontext, sctx_status::turning);
			break;
		case tproc_status::idle:
			contexts_pool_insert(pcontext, sctx_status::idling);
			break;
		case tproc_status::polling_rdonly:
			pcontext->polling_mask = POLLING_READ;
			contexts_pool_insert(pcontext, sctx_status::polling);
			break;
		case tproc_status::polling_wronly:
			pcontext->polling_mask = POLLING_WRITE;
			contexts_pool_insert(pcontext, sctx_status::polling);
			break;
		case tproc_status::sleeping:
			contexts_pool_insert(pcontext, sctx_status::sleeping);
			break;
		case tproc_status::close:
			contexts_pool_insert(pcontext, sctx_status::free);
			break;
		default:
			break;
		}
	}
	
	std::unique_lock tpd_hold(g_threads_pool_data_lock);
	double_list_remove(&g_threads_data_list, &pdata->node);
	delete pdata;
	g_threads_pool_cur_thr_num --;
	tpd_hold.unlock();
	if (g_threads_event_proc != nullptr)
		g_threads_event_proc(THREAD_DESTROY);
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

/**
 * Dedicated thread "ep_pool/scan", which watches context_pool for
 * contention, and if so, spawn more threads. This is similar to
 * PHP-FPM's max_spare_servers.
 */
static void *tpol_scanwork(void *pparam)
{
	int not_empty_times;

	not_empty_times = 0;
	while (!g_notify_stop) {
		sleep(1);
		if (contexts_pool_get_param(CUR_SCHEDULING_CONTEXTS) <= 1) {
			not_empty_times = 0;
			continue;
		}
		not_empty_times++;
		if (not_empty_times < MAX_NOT_EMPTY_TIMES)
			continue;
		std::lock_guard tpd_hold(g_threads_pool_data_lock);
		if (g_threads_pool_cur_thr_num >= g_threads_pool_max_num)
			continue;
		THR_DATA *pdata;
		try {
			pdata = new THR_DATA;
		} catch (const std::bad_alloc &) {
			mlog(LV_DEBUG, "E-2368: ENOMEM");
			not_empty_times = 0;
			continue;
		}
		pdata->node.pdata = pdata;
		pdata->id = (pthread_t)-1;
		pdata->notify_stop = FALSE;
		auto ret = pthread_create4(&pdata->id, nullptr, tpol_thrwork, pdata);
		if (ret != 0) {
			mlog(LV_WARN, "W-1445: failed to increase pool threads: %s", strerror(ret));
			delete pdata;
			not_empty_times = 0;
			continue;
		}
		pthread_setname_np(pdata->id, "ep_pool/+");
		double_list_append_as_tail(
			&g_threads_data_list, &pdata->node);
		g_threads_pool_cur_thr_num++;
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
