// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <gromox/atomic.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/poll_ctx.hpp>
#include <gromox/process.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static time_duration g_time_out;
static unsigned int g_context_num, g_contexts_per_thr;
static poll_ctx g_poll_ctx;
static pthread_t g_scan_id;
static SCHEDULE_CONTEXT **g_context_ptr;
static pthread_t g_thread_id;
static gromox::atomic_bool g_ctxpool_stop{true};
static DOUBLE_LIST g_context_lists[static_cast<int>(sctx_status::_alloc_max)];
static std::mutex g_context_locks[static_cast<int>(sctx_status::_alloc_max)]; /* protects g_context_lists */

static int (*contexts_pool_get_context_socket)(const schedule_context *);
static time_point (*contexts_pool_get_context_timestamp)(const schedule_context *);

static void context_init(SCHEDULE_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		mlog(LV_DEBUG, "pcontext is NULL in %s", __PRETTY_FUNCTION__);
		return;
	}
	pcontext->type = sctx_status::free;
	pcontext->node.pdata = pcontext;
}

static void context_free(SCHEDULE_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		mlog(LV_DEBUG, "pcontext is NULL in %s", __PRETTY_FUNCTION__);
		return;
	}
	pcontext->type = sctx_status::invalid;
	pcontext->node.pdata = NULL;
	return;
}

int contexts_pool_get_param(int type)
{
	switch(type) {
	case MAX_CONTEXTS_NUM:
		return g_context_num;
	case CONTEXTS_PER_THR:
		return g_contexts_per_thr;
	case CUR_VALID_CONTEXTS:
		return g_context_num - double_list_get_nodes_num(&g_context_lists[static_cast<int>(sctx_status::free)]);
	case CUR_SLEEPING_CONTEXTS:
		return double_list_get_nodes_num(&g_context_lists[static_cast<int>(sctx_status::sleeping)]);
	case CUR_SCHEDULING_CONTEXTS:
		return double_list_get_nodes_num(&g_context_lists[static_cast<int>(sctx_status::turning)]);
	default:
		return -1;
	}
}

static void *ctxp_thrwork(void *pparam)
{
	while (!g_ctxpool_stop) {
		auto num = g_poll_ctx.wait();
		if (num <= 0)
			continue;
		for (unsigned int i = 0; i < static_cast<unsigned int>(num); ++i) {
			auto pcontext = static_cast<schedule_context *>(g_poll_ctx.data(i));
			std::unique_lock poll_hold(g_context_locks[static_cast<int>(sctx_status::polling)]);
			if (pcontext->type != sctx_status::polling)
				/* context may be waked up and modified by
				scan_work_func or context_pool_activate_context */
				continue;
			if (!pcontext->b_waiting) {
				mlog(LV_DEBUG, "contexts_pool: error in context"
					" queue! b_waiting mismatch in thread_work_func"
					" context: %p", pcontext);
				continue;
			}
			double_list_remove(&g_context_lists[static_cast<int>(sctx_status::polling)], &pcontext->node);
			pcontext->type = sctx_status::switching;
			poll_hold.unlock();
			contexts_pool_insert(pcontext, sctx_status::turning);
		}
		if (num == 1)
			threads_pool_wakeup_thread();
		else
			threads_pool_wakeup_all_threads();
	}
	return nullptr;
}

static void *ctxp_scanwork(void *pparam)
{
	int num;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	SCHEDULE_CONTEXT *pcontext;
	
	double_list_init(&temp_list);
	while (!g_ctxpool_stop) {
		std::unique_lock poll_hold(g_context_locks[static_cast<int>(sctx_status::polling)]);
		auto current_time = tp_now();
		auto ptail = double_list_get_tail(&g_context_lists[static_cast<int>(sctx_status::polling)]);
		while ((pnode = double_list_pop_front(&g_context_lists[static_cast<int>(sctx_status::polling)])) != nullptr) {
			pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
			if (!pcontext->b_waiting) {
				pcontext->type = sctx_status::switching;
				double_list_append_as_tail(&temp_list, pnode);
				goto CHECK_TAIL;
			}
			if (current_time - contexts_pool_get_context_timestamp(pcontext) >= g_time_out) {
				if (g_poll_ctx.del(contexts_pool_get_context_socket(pcontext)) != 0) {
					mlog(LV_DEBUG, "contexts_pool: failed to remove event from epoll");
				} else {
					pcontext->b_waiting = FALSE;
					pcontext->type = sctx_status::switching;
					double_list_append_as_tail(&temp_list, pnode);
					goto CHECK_TAIL;
				}
			}
			double_list_append_as_tail(&g_context_lists[static_cast<int>(sctx_status::polling)], pnode);
 CHECK_TAIL:
			if (pnode == ptail)
				break;
		}
		poll_hold.unlock();
		std::unique_lock idle_hold(g_context_locks[static_cast<int>(sctx_status::idling)]);
		while ((pnode = double_list_pop_front(&g_context_lists[static_cast<int>(sctx_status::idling)])) != nullptr) {
			pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
			pcontext->type = sctx_status::switching;
			double_list_append_as_tail(&temp_list, pnode);
		}
		idle_hold.unlock();
		num = 0;
		std::unique_lock turn_hold(g_context_locks[static_cast<int>(sctx_status::turning)]);
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			static_cast<schedule_context *>(pnode->pdata)->type = sctx_status::turning;
			double_list_append_as_tail(&g_context_lists[static_cast<int>(sctx_status::turning)], pnode);
			num ++;
		}
		turn_hold.unlock();
		if (num == 1)
			threads_pool_wakeup_thread();
		else if (num > 1)
			threads_pool_wakeup_all_threads();
		sleep(1);
	}
	double_list_free(&temp_list);
	return nullptr;
}

void contexts_pool_init(SCHEDULE_CONTEXT **pcontexts, unsigned int context_num,
    int (*get_socket)(const schedule_context *),
    time_point (*get_timestamp)(const schedule_context *),
    unsigned int contexts_per_thr, time_duration timeout)
{
	setup_signal_defaults();
	g_context_ptr = pcontexts;
	g_context_num = context_num;
	contexts_pool_get_context_socket = get_socket;
	contexts_pool_get_context_timestamp = get_timestamp;
	g_contexts_per_thr = contexts_per_thr;
	g_time_out = timeout;
	for (auto i = static_cast<unsigned int>(sctx_status::begin); i < std::size(g_context_lists); ++i)
		double_list_init(&g_context_lists[i]);
	for (size_t i = 0; i < g_context_num; ++i) {
		auto pcontext = g_context_ptr[i];
		context_init(pcontext);
		double_list_append_as_tail(&g_context_lists[static_cast<int>(sctx_status::free)], &pcontext->node);
	}
}

int contexts_pool_run()
{    
	auto err = g_poll_ctx.init(g_context_num);
	if (err != 0)
		return -1;
	g_ctxpool_stop = false;
	int ret = pthread_create4(&g_thread_id, nullptr, ctxp_thrwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "contexts_pool: failed to create epoll thread: %s", strerror(ret));
		g_ctxpool_stop = true;
		return -3;
	}
	pthread_setname_np(g_thread_id, "epollctx/work");
	ret = pthread_create4(&g_scan_id, nullptr, ctxp_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "contexts_pool: failed to create scan thread: %s", strerror(ret));
		g_ctxpool_stop = true;
		if (!pthread_equal(g_thread_id, {})) {
			pthread_kill(g_thread_id, SIGALRM);
			pthread_join(g_thread_id, NULL);
		}
		return -4;
	}
	pthread_setname_np(g_scan_id, "epollctx/scan");
	return 0;    
}

void contexts_pool_stop()
{
	g_ctxpool_stop = true;
	if (!pthread_equal(g_thread_id, {}))
		pthread_kill(g_thread_id, SIGALRM);
	if (!pthread_equal(g_scan_id, {}))
		pthread_kill(g_scan_id, SIGALRM);
	if (!pthread_equal(g_thread_id, {}))
		pthread_join(g_thread_id, NULL);
	if (!pthread_equal(g_scan_id, {}))
		pthread_join(g_scan_id, NULL);
	g_poll_ctx.reset();
	for (size_t i = 0; i < g_context_num; ++i)
		context_free(g_context_ptr[i]);
	for (auto i = static_cast<unsigned int>(sctx_status::begin); i < std::size(g_context_lists); ++i)
		double_list_free(&g_context_lists[i]);
	g_context_ptr = nullptr;
	g_context_num = 0;
	g_contexts_per_thr = 0;
}

/*
 *	@param    
 *		type	type can only be one of sctx_status::free OR sctx_status::turning
 *	@return    
 * 		the pointer of SCHEDULE_CONTEXT, NULL if there's no context available
 */
schedule_context *contexts_pool_get_context(sctx_status tpraw)
{
	const auto type = static_cast<unsigned int>(tpraw);
	DOUBLE_LIST_NODE *pnode;
	if (tpraw != sctx_status::free && tpraw != sctx_status::turning)
		return NULL;
	std::lock_guard xhold(g_context_locks[type]);
	pnode = double_list_pop_front(&g_context_lists[type]);
	/* do not change context type under this circumstance */
	return pnode != nullptr ? static_cast<SCHEDULE_CONTEXT *>(pnode->pdata) : nullptr;
}

/**
 * Move back a context into the pool
 *	@param
 *		 pcontext	the context pointer to release
 *		 type		type can only be sctx_status::free, sctx_status::sleeping
 *					sctx_status::polling, sctx_status::idling, sctx_status::turning
 */
void contexts_pool_insert(schedule_context *pcontext, sctx_status tpraw)
{
	if (pcontext == nullptr)
		return;
	const auto type = static_cast<unsigned int>(tpraw);
	switch (tpraw) {
	case sctx_status::free:
	case sctx_status::idling:
	case sctx_status::polling:
	case sctx_status::turning:
	case sctx_status::sleeping:
		break;
	default:
		mlog(LV_DEBUG, "contexts_pool: cannot put context into queue of type %u", type);
		return;
	}
	
	/* append the context at the tail of the corresponding list */
	std::lock_guard xhold(g_context_locks[type]);
	auto original_type = pcontext->type;
	pcontext->type = tpraw;
	if (tpraw == sctx_status::polling) {
		int fd = contexts_pool_get_context_socket(pcontext);
		if (original_type == sctx_status::constructing) {
			if (g_poll_ctx.add(pcontext->polling_mask, fd, pcontext) != 0) {
				pcontext->b_waiting = FALSE;
				mlog(LV_DEBUG, "contexts_pool: failed to add event to epoll");
			} else {
				pcontext->b_waiting = TRUE;
			}
		} else if (g_poll_ctx.mod(pcontext->polling_mask, fd, pcontext) != 0) {
			int se = errno;
			if (errno == ENOENT && g_poll_ctx.add(pcontext->polling_mask, fd, pcontext) == 0) {
				/* sometimes, fd will be removed by scanning
				thread because of timeout, add it back
				into epoll queue again */
				pcontext->b_waiting = TRUE;
			} else {
				mlog(LV_DEBUG, "contexts_pool: failed to modify event in epoll: %s (T1), %s (T2)",
					strerror(se), strerror(errno));
				shutdown(fd, SHUT_RDWR);
			}
		}
	} else if (tpraw == sctx_status::free && original_type == sctx_status::turning) {
		if (pcontext->b_waiting)
			/* socket was removed by "close()" function automatically,
				no need to call epoll_ctl with EPOLL_CTL_DEL */
			pcontext->b_waiting = FALSE;
	}
	double_list_append_as_tail(&g_context_lists[type], &pcontext->node);
}

void contexts_pool_signal(SCHEDULE_CONTEXT *pcontext)
{
	std::unique_lock idle_hold(g_context_locks[static_cast<int>(sctx_status::idling)]);
	if (pcontext->type != sctx_status::idling)
		return;
	double_list_remove(&g_context_lists[static_cast<int>(sctx_status::idling)], &pcontext->node);
	pcontext->type = sctx_status::switching;
	idle_hold.unlock();
	contexts_pool_insert(pcontext, sctx_status::turning);
	threads_pool_wakeup_thread();
}

/*
 *	wake up a context in sleeping queue
 *	@param
 *		pcontext [in]	indicate the context object
 *		type			can only be sctx_status::polling,
 *						sctx_status::idling or sctx_status::turning
 *	@return
 *		TRUE     contextis waked up
 *		FALSE    context is not in sleeping queue
 */
BOOL contexts_pool_wakeup_context(schedule_context *pcontext, sctx_status type)
{
	if (pcontext == nullptr)
		return FALSE;
	if (type != sctx_status::polling && type != sctx_status::idling &&
	    type != sctx_status::turning)
		return FALSE;
	while (pcontext->type != sctx_status::sleeping) {
		usleep(100000);
		mlog(LV_DEBUG, "contexts_pool: waiting context %p to be sctx_status::sleeping", pcontext);
	}
	std::unique_lock sleep_hold(g_context_locks[static_cast<int>(sctx_status::sleeping)]);
	double_list_remove(&g_context_lists[static_cast<int>(sctx_status::sleeping)], &pcontext->node);
	sleep_hold.unlock();
	/* put the context into waiting queue */
	contexts_pool_insert(pcontext, type);
	if (type == sctx_status::turning)
		threads_pool_wakeup_thread();
	return TRUE;
}

/*
 *	try to activate a context from polling queue
 *	@param
 *		pcontext [in]	indicate the context object
 *		type			can only be sctx_status::polling,
 */
void context_pool_activate_context(SCHEDULE_CONTEXT *pcontext)
{
	{
		std::unique_lock poll_hold(g_context_locks[static_cast<int>(sctx_status::polling)]);
		if (pcontext->type != sctx_status::polling)
			return;
		double_list_remove(&g_context_lists[static_cast<int>(sctx_status::polling)], &pcontext->node);
		pcontext->type = sctx_status::switching;
	}
	{
		std::unique_lock turn_hold(g_context_locks[static_cast<int>(sctx_status::turning)]);
		pcontext->type = sctx_status::turning;
		double_list_append_as_tail(&g_context_lists[static_cast<int>(sctx_status::turning)], &pcontext->node);
	}
	threads_pool_wakeup_thread();
}
