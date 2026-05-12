// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
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
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>

#define MAX_TIMES_NOT_SERVED			100

using namespace gromox;

namespace {

/**
 * @nid: Trivial numeric ID for debugging with ps/gdb/etc.
 *       -1 is used for a thread spawned dynamically in response to contention.
 *       "Normal" values >= 0 indicate static threads that are always present.
 */
struct THR_DATA {
	~THR_DATA();
	void signal_stop();

	gromox::atomic_bool notify_stop;
	pthread_t thr_id{};
	long nid = ~0ULL;
	std::mutex m_mtx; /* protects thr_id */
};

struct tpw_param {
	std::shared_ptr<THR_DATA> sp;
};

}

static pthread_t g_scan_id;
static gromox::atomic_bool g_thrpool_stop{true};
static unsigned int g_threads_pool_min_num, g_threads_pool_max_num;
static std::vector<std::shared_ptr<THR_DATA>> g_threads_data_list;
static THREADS_EVENT_PROC g_threads_event_proc;
static std::mutex g_threads_pool_data_lock; /* protects g_threads_data_list */
static std::mutex g_threads_pool_cond_mutex;
static std::condition_variable g_threads_pool_waken_cond;

static void *tpol_thrwork(void *);
static void *tpol_scanwork(void *);

static tproc_status (*threads_pool_process_func)(schedule_context *);

THR_DATA::~THR_DATA()
{
	if (pthread_equal(thr_id, {}))
		return;
	if (pthread_equal(thr_id, pthread_self()))
		pthread_detach(thr_id);
	else
		pthread_join(thr_id, nullptr);
}

void THR_DATA::signal_stop()
{
	notify_stop = true;
	std::lock_guard lk(m_mtx);
	if (!pthread_equal(thr_id, {}))
		pthread_kill(thr_id, SIGALRM);
}

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
	g_threads_event_proc = NULL;
}

int threads_pool_run(const char *hint) try
{
	g_thrpool_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, tpol_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "threads_pool: failed to create scan thread: %s", strerror(ret));
		threads_pool_stop();
		return -2;
	}

	for (size_t i = 0; i < g_threads_pool_min_num; ++i) {
		auto up = std::make_unique<tpw_param>();
		auto sp = up->sp = std::make_shared<THR_DATA>();
		sp->nid = i;
		{
			std::lock_guard tpd_hold(g_threads_pool_data_lock);
			g_threads_data_list.push_back(sp);
		}
		ret = pthread_create4(&sp->thr_id, nullptr, tpol_thrwork, up.get());
		if (ret != 0) {
			mlog(LV_ERR, "threads_pool: failed to create a pool thread: %s", strerror(ret));
			threads_pool_stop();
			return -1;
		}
		/* thread should be vivid now */
		up.release();
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	threads_pool_stop();
	return -1;
}

void threads_pool_stop()
{
	g_thrpool_stop = true;
	if (!pthread_equal(g_scan_id, {})) {
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, NULL);
		g_scan_id = {};
	}
	{
		std::unique_lock tpd_hold(g_threads_pool_data_lock);
		for (auto &t : g_threads_data_list)
			t->signal_stop();
		g_threads_data_list.clear();
	}
	g_threads_pool_min_num = 0;
	g_threads_pool_max_num = 0;
	g_threads_event_proc = NULL;
}

static size_t get_threads_pool_cur_thr_num()
{
	std::lock_guard lk(g_threads_pool_data_lock);
	return g_threads_data_list.size();
}

int threads_pool_get_param(int type)
{
	switch(type) {
	case THREADS_POOL_MIN_NUM:
		return g_threads_pool_min_num;
	case THREADS_POOL_MAX_NUM:
		return g_threads_pool_max_num;
	case THREADS_POOL_CUR_THR_NUM:
		return get_threads_pool_cur_thr_num();
	default:
		return -1;
	}
}

static bool should_ditch_worker(THR_DATA &self)
{
	std::unique_lock tpd_hold(g_threads_pool_data_lock);
	/*
	 * See if some worker threads can be dropped (logic similar to PHP-FPM
	 * min_spare_servers).
	 */
	if (self.nid >= 0)
		return false; /* we are a static thread */
	auto gpr = contexts_pool_get_param(CUR_VALID_CONTEXTS);
	if (gpr < 0)
		return false;
	auto max_contexts_per_thr = contexts_pool_get_param(CONTEXTS_PER_THR);
	auto contexts_per_threads = max_contexts_per_thr / 4;
	if (get_threads_pool_cur_thr_num() * contexts_per_threads <= static_cast<size_t>(gpr))
		return false;
	return true;
}

static void *tpol_thrwork(void *pparam)
{
	std::unique_ptr<tpw_param> xup(static_cast<tpw_param *>(pparam));
	auto &pdata = xup->sp;
	int cannot_served_times;

	if (pdata->nid >= 0) {
		char buf[16];
		snprintf(buf, std::size(buf), "ep_pool/%ld", pdata->nid);
		pthread_setname_np(pthread_self(), buf);
	} else {
		pthread_setname_np(pthread_self(), "ep_pool/+");
	}

	if (g_threads_event_proc != nullptr)
		g_threads_event_proc(THREAD_CREATE);
	
	cannot_served_times = 0;
	while (!pdata->notify_stop) {
		auto pcontext = contexts_pool_get_context(sctx_status::turning);
		if (NULL == pcontext) {
			if (MAX_TIMES_NOT_SERVED == cannot_served_times) {
				if (should_ditch_worker(*pdata))
					break;
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
	
	if (g_threads_event_proc != nullptr)
		g_threads_event_proc(THREAD_DESTROY);

	{
		std::lock_guard tpd_hold(g_threads_pool_data_lock);
		gromox::erase_first(g_threads_data_list, pdata);
	}
	return NULL;
}

void threads_pool_wakeup_thread()
{
	if (g_thrpool_stop)
		return;
	g_threads_pool_waken_cond.notify_one();
}

void threads_pool_wakeup_all_threads()
{
	if (g_thrpool_stop)
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
	pthread_setname_np(pthread_self(), "tpol_scan");
	while (!g_thrpool_stop) try {
		if (contexts_pool_get_param(CUR_SCHEDULING_CONTEXTS) <= 1) {
			sleep(1);
			continue;
		}
		if (get_threads_pool_cur_thr_num() >= g_threads_pool_max_num) {
			sleep(1);
			continue;
		}

		auto up = std::make_unique<tpw_param>();
		auto sp = up->sp = std::make_shared<THR_DATA>();
		{
			std::lock_guard tpd_hold(g_threads_pool_data_lock);
			g_threads_data_list.push_back(sp);
		}
		auto ret = pthread_create4(&sp->thr_id, nullptr, tpol_thrwork, up.get());
		if (ret != 0) {
			mlog(LV_WARN, "W-1445: failed to increase pool threads: %s", strerror(ret));
			sleep(1);
			continue;
		}
		/* Thread seems to be vivid */
		up.release();
		usleep(500);
	} catch (const std::bad_alloc &) {
		mlog(LV_DEBUG, "E-2368: ENOMEM");
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
