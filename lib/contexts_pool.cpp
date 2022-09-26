// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <pthread.h>
#include <unistd.h>
#ifdef HAVE_SYS_EPOLL_H
#	include <sys/epoll.h>
#endif
#ifdef HAVE_SYS_EVENT_H
#	include <sys/event.h>
#endif
#include <sys/socket.h>
#include <gromox/atomic.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>

using namespace gromox;

namespace {
struct evqueue {
	~evqueue() { reset(); }

	unsigned int m_num = 0;
	int m_fd = -1;
#ifdef HAVE_SYS_EPOLL_H
	std::unique_ptr<epoll_event[]> m_events;
	inline SCHEDULE_CONTEXT *get_data(size_t i) const { return static_cast<schedule_context *>(m_events[i].data.ptr); }
#elif defined(HAVE_SYS_EVENT_H)
	std::unique_ptr<struct kevent[]> m_events;
	inline SCHEDULE_CONTEXT *get_data(size_t i) const { return static_cast<schedule_context *>(m_events[i].udata); }
#endif

	errno_t init(unsigned int numctx);
	int wait();
	errno_t mod(SCHEDULE_CONTEXT *, bool add);
	errno_t del(SCHEDULE_CONTEXT *);
	void reset();
};
}

static time_duration g_time_out;
static unsigned int g_context_num, g_contexts_per_thr;
static evqueue g_poll_ctx;
static pthread_t g_scan_id;
static SCHEDULE_CONTEXT **g_context_list;
static pthread_t g_thread_id;
static gromox::atomic_bool g_notify_stop{true};
static DOUBLE_LIST g_context_lists[CONTEXT_TYPES];
static std::mutex g_context_locks[CONTEXT_TYPES];

static int (*contexts_pool_get_context_socket)(const schedule_context *);
static time_point (*contexts_pool_get_context_timestamp)(const schedule_context *);

void evqueue::reset()
{
	if (m_fd >= 0) {
		close(m_fd);
		m_fd = -1;
	}
	m_events.reset();
}

errno_t evqueue::init(unsigned int numctx) try
{
	m_num = numctx;
#ifdef HAVE_SYS_EPOLL_H
	if (m_fd >= 0)
		close(m_fd);
	m_fd = epoll_create(numctx);
	if (m_fd < 0) {
		fprintf(stderr, "[contexts_pool]: epoll_create: %s\n", strerror(errno));
		return errno;
	}
	m_events = std::make_unique<epoll_event[]>(numctx);
#elif defined(HAVE_SYS_EVENT_H)
	m_fd = kqueue();
	if (m_fd < 0) {
		fprintf(stderr, "[contexts_pool]: kqueue: %s\n", strerror(errno));
		return errno;
	}
	m_events = std::make_unique<struct kevent[]>(numctx * 2);
#endif
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

int evqueue::wait()
{
#ifdef HAVE_SYS_EPOLL_H
	return epoll_wait(m_fd, m_events.get(), m_num, -1);
#elif defined(HAVE_SYS_EVENT_H)
	return kevent(m_fd, nullptr, 0, m_events.get(), m_num, nullptr);
#endif
}

errno_t evqueue::mod(SCHEDULE_CONTEXT *ctx, bool add)
{
	auto fd = contexts_pool_get_context_socket(ctx);
#ifdef HAVE_SYS_EPOLL_H
	struct epoll_event ev{};
	ev.data.ptr = ctx;
	ev.events = EPOLLET | EPOLLONESHOT;
	if (ctx->polling_mask & POLLING_READ)
		ev.events |= EPOLLIN;
	if (ctx->polling_mask & POLLING_WRITE)
		ev.events |= EPOLLOUT;
	return epoll_ctl(m_fd, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &ev);
#else
	struct kevent ev{};
	if (ctx->polling_mask & POLLING_READ) {
		EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_ONESHOT | EV_CLEAR, 0, 0, ctx);
		auto ret = kevent(m_fd, &ev, 1, nullptr, 0, nullptr);
		if (ret != 0)
			return ret;
		if (ev.flags & EV_ERROR)
			fprintf(stderr, "evqueue::add: %s\n", strerror(ev.data));
	}
	if (ctx->polling_mask & POLLING_WRITE) {
		EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_ONESHOT | EV_CLEAR, 0, 0, ctx);
		auto ret = kevent(m_fd, &ev, 1, nullptr, 0, nullptr);
		if (ret != 0)
			return ret;
		if (ev.flags & EV_ERROR)
			fprintf(stderr, "evqueue::add: %s\n", strerror(ev.data));
	}
	return 0;
#endif
}

errno_t evqueue::del(SCHEDULE_CONTEXT *ctx)
{
	auto fd = contexts_pool_get_context_socket(ctx);
#ifdef HAVE_SYS_EPOLL_H
	return epoll_ctl(m_fd, EPOLL_CTL_DEL, fd, nullptr);
#elif defined(HAVE_SYS_EVENT_H)
	struct kevent ev[2];
	EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
	EV_SET(&ev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
	return kevent(m_fd, ev, std::size(ev), nullptr, 0, nullptr);
#endif
}

static void context_init(SCHEDULE_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		debug_info("[contexts_pool]: pcontext is NULL in context_init!\n");
		return;
	}
	pcontext->type = CONTEXT_FREE;
	pcontext->node.pdata = pcontext;
}

static void context_free(SCHEDULE_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		debug_info("[contexts_pool]: pcontext is NULL in context_free!\n");
		return;
	}
	pcontext->type = -1;
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
		return g_context_num - double_list_get_nodes_num(
						&g_context_lists[CONTEXT_FREE]);
	case CUR_SLEEPING_CONTEXTS:
		return double_list_get_nodes_num(
			&g_context_lists[CONTEXT_SLEEPING]);
	case CUR_SCHEDULING_CONTEXTS:
		return double_list_get_nodes_num(
			&g_context_lists[CONTEXT_TURNING]);
	default:
		return -1;
	}
}

static void *ctxp_thrwork(void *pparam)
{
	while (!g_notify_stop) {
		auto num = g_poll_ctx.wait();
		if (num <= 0) {
			continue;
		}
		for (unsigned int i = 0; i < num; ++i) {
			auto pcontext = g_poll_ctx.get_data(i);
			std::unique_lock poll_hold(g_context_locks[CONTEXT_POLLING]);
			if (CONTEXT_POLLING != pcontext->type) {
				/* context may be waked up and modified by
				scan_work_func or context_pool_activate_context */
				continue;
			}
			if (!pcontext->b_waiting) {
				debug_info("[contexts_pool]: fatal error in context"
					" queue! b_waiting mismatch in thread_work_func"
					" context: %p\n", pcontext);
				continue;
			}
			double_list_remove(&g_context_lists[CONTEXT_POLLING],
				&pcontext->node);
			pcontext->type = CONTEXT_SWITCHING;
			poll_hold.unlock();
			contexts_pool_put_context(pcontext, CONTEXT_TURNING);
		}
		if (1 == num) {
			threads_pool_wakeup_thread();
		} else {
			threads_pool_wakeup_all_threads();
		}
	}
	return nullptr;
}

static void *ctxp_scanwork(void *pparam)
{
	int num;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	SCHEDULE_CONTEXT *pcontext;
	
	double_list_init(&temp_list);
	while (!g_notify_stop) {
		std::unique_lock poll_hold(g_context_locks[CONTEXT_POLLING]);
		auto current_time = tp_now();
		ptail = double_list_get_tail(
			&g_context_lists[CONTEXT_POLLING]);
		while ((pnode = double_list_pop_front(&g_context_lists[CONTEXT_POLLING])) != nullptr) {
			pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
			if (!pcontext->b_waiting) {
				pcontext->type = CONTEXT_SWITCHING;
				double_list_append_as_tail(&temp_list, pnode);
				goto CHECK_TAIL;
			}
			if (CALCULATE_INTERVAL(current_time,
				contexts_pool_get_context_timestamp(pcontext))
				>= g_time_out) {
				if (g_poll_ctx.del(pcontext) != 0) {
					debug_info("[contexts_pool]: fail "
						"to remove event from epoll\n");
				} else {
					pcontext->b_waiting = FALSE;
					pcontext->type = CONTEXT_SWITCHING;
					double_list_append_as_tail(&temp_list, pnode);
					goto CHECK_TAIL;
				}
			}
			double_list_append_as_tail(
				&g_context_lists[CONTEXT_POLLING], pnode);
 CHECK_TAIL:
			if (pnode == ptail) {
				break;
			}
		}
		poll_hold.unlock();
		std::unique_lock idle_hold(g_context_locks[CONTEXT_IDLING]);
		while ((pnode = double_list_pop_front(&g_context_lists[CONTEXT_IDLING])) != nullptr) {
			pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
			pcontext->type = CONTEXT_SWITCHING;
			double_list_append_as_tail(&temp_list, pnode);
		}
		idle_hold.unlock();
		num = 0;
		std::unique_lock turn_hold(g_context_locks[CONTEXT_TURNING]);
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			((SCHEDULE_CONTEXT*)pnode->pdata)->type = CONTEXT_TURNING;
			double_list_append_as_tail(
				&g_context_lists[CONTEXT_TURNING], pnode);
			num ++;
		}
		turn_hold.unlock();
		if (1 == num) {
			threads_pool_wakeup_thread();
		} else if (num > 1) {
			threads_pool_wakeup_all_threads();
		}
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
	setup_sigalrm();
	g_context_list = pcontexts;
	g_context_num = context_num;
	contexts_pool_get_context_socket = get_socket;
	contexts_pool_get_context_timestamp = get_timestamp;
	g_contexts_per_thr = contexts_per_thr;
	g_time_out = timeout;
	for (size_t i = CONTEXT_BEGIN; i < CONTEXT_TYPES; ++i)
		double_list_init(&g_context_lists[i]);
	for (size_t i = 0; i < g_context_num; ++i) {
		auto pcontext = g_context_list[i];
		context_init(pcontext);
		double_list_append_as_tail(
			&g_context_lists[CONTEXT_FREE], &pcontext->node);
	}
}

int contexts_pool_run()
{    
	auto ret = g_poll_ctx.init(g_context_num);
	if (ret != 0) {
		fprintf(stderr, "[contexts_pool]: evqueue: %s\n", strerror(ret));
		return -1;
	}
	g_notify_stop = false;
	ret = pthread_create(&g_thread_id, nullptr, ctxp_thrwork, nullptr);
	if (ret != 0) {
		fprintf(stderr, "[contexts_pool]: failed to create epoll thread: %s\n", strerror(ret));
		g_notify_stop = true;
		return -3;
	}
	pthread_setname_np(g_thread_id, "epollctx/work");
	ret = pthread_create(&g_scan_id, nullptr, ctxp_scanwork, nullptr);
	if (ret != 0) {
		fprintf(stderr, "[contexts_pool]: failed to create scan thread: %s\n", strerror(ret));
		g_notify_stop = true;
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
	g_notify_stop = true;
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
		context_free(g_context_list[i]);
	for (size_t i = CONTEXT_BEGIN; i < CONTEXT_TYPES; ++i)
		double_list_free(&g_context_lists[i]);
	g_context_list = NULL;
	
	g_context_num = 0;
	g_contexts_per_thr = 0;
}

/*
 *	@param    
 *		type	type can only be one of CONTEXT_FREE OR CONTEXT_TURNING
 *	@return    
 * 		the pointer of SCHEDULE_CONTEXT, NULL if there's no context available
 */
SCHEDULE_CONTEXT* contexts_pool_get_context(int type)
{
	DOUBLE_LIST_NODE *pnode;
	if (CONTEXT_FREE != type && CONTEXT_TURNING != type) {
		return NULL;
	}
	std::lock_guard xhold(g_context_locks[type]);
	pnode = double_list_pop_front(&g_context_lists[type]);
	/* do not change context type under this circumstance */
	return pnode != nullptr ? static_cast<SCHEDULE_CONTEXT *>(pnode->pdata) : nullptr;
}

/*
 *	release one context to the pool
 *	@param
 *		 pcontext	the context pointer to release
 *		 type		type can only be CONTEXT_FREE, CONTEXT_SLEEPING
 *					CONTEXT_POLLING, CONTEXT_IDLING, CONTEXT_TURNING
 */
void contexts_pool_put_context(SCHEDULE_CONTEXT *pcontext, int type)
{
	if (NULL == pcontext) {
		return;
	}
	
	switch(type) {
	case CONTEXT_FREE:
	case CONTEXT_IDLING:
	case CONTEXT_POLLING:
	case CONTEXT_TURNING:
	case CONTEXT_SLEEPING:
		break;
	default:
		debug_info("[contexts_pool]: cannot put "
			"context into queue of type %d\n", type); 
		return;
	}
	
	/* append the context at the tail of the corresponding list */
	std::lock_guard xhold(g_context_locks[type]);
	auto original_type = pcontext->type;
	pcontext->type = type;
	if (CONTEXT_POLLING == type) {
		if (original_type == CONTEXT_CONSTRUCTING) {
			if (g_poll_ctx.mod(pcontext, true) != 0) {
				pcontext->b_waiting = FALSE;
				debug_info("[contexts_pool]: fail to add event to epoll!\n");
			} else {
				pcontext->b_waiting = TRUE;
			}
		} else if (g_poll_ctx.mod(pcontext, false) != 0) {
			if (errno == ENOENT && g_poll_ctx.mod(pcontext, true) != 0) {
				/* sometimes, fd will be removed by scanning
				thread because of timeout, add it back
				into epoll queue again */
				pcontext->b_waiting = TRUE;
			} else {
				shutdown(contexts_pool_get_context_socket(
				         pcontext), SHUT_RDWR);
				debug_info("[contexts_pool]: fail"
					" to modify event in epoll\n");
			}
		}
	} else if (type == CONTEXT_FREE && original_type == CONTEXT_TURNING) {
		if (pcontext->b_waiting)
			/* socket was removed by "close()" function automatically,
				no need to call epoll_ctl with EPOLL_CTL_DEL */
			pcontext->b_waiting = FALSE;
	}
	double_list_append_as_tail(&g_context_lists[type], 
									&pcontext->node);
}

void contexts_pool_signal(SCHEDULE_CONTEXT *pcontext)
{
	std::unique_lock idle_hold(g_context_locks[CONTEXT_IDLING]);
	if (CONTEXT_IDLING != pcontext->type) {
		return;
	}
	double_list_remove(&g_context_lists[CONTEXT_IDLING], &pcontext->node);
	pcontext->type = CONTEXT_SWITCHING;
	idle_hold.unlock();
	contexts_pool_put_context(pcontext, CONTEXT_TURNING);
	threads_pool_wakeup_thread();
}

/*
 *	wake up a context in sleeping queue
 *	@param
 *		pcontext [in]	indicate the context object
 *		type			can only be CONTEXT_POLLING,
 *						CONTEXT_IDLING or CONTEXT_TURNING
 *	@return
 *		TRUE     contextis waked up
 *		FALSE    context is not in sleeping queue
 */
BOOL contexts_pool_wakeup_context(SCHEDULE_CONTEXT *pcontext, int type)
{
	if (NULL == pcontext) {
		return FALSE;
	}
	if (CONTEXT_POLLING != type &&
		CONTEXT_IDLING != type &&
		CONTEXT_TURNING != type) {
		return FALSE;
	}
	while (CONTEXT_SLEEPING != pcontext->type) {
		usleep(100000);
		debug_info("[contexts_pool]: waiting context"
			" %p to be CONTEXT_SLEEPING\n", pcontext);
	}
	std::unique_lock sleep_hold(g_context_locks[CONTEXT_SLEEPING]);
	double_list_remove(&g_context_lists[CONTEXT_SLEEPING], &pcontext->node);
	sleep_hold.unlock();
	/* put the context into waiting queue */
	contexts_pool_put_context(pcontext, type);
	if (CONTEXT_TURNING == type) {
		threads_pool_wakeup_thread();
	}
	return TRUE;
}

/*
 *	try to activate a context from polling queue
 *	@param
 *		pcontext [in]	indicate the context object
 *		type			can only be CONTEXT_POLLING,
 */
void context_pool_activate_context(SCHEDULE_CONTEXT *pcontext)
{
	std::unique_lock poll_hold(g_context_locks[CONTEXT_POLLING]);
	if (CONTEXT_POLLING != pcontext->type) {
		return;
	}
	double_list_remove(&g_context_lists[CONTEXT_POLLING], &pcontext->node);
	pcontext->type = CONTEXT_SWITCHING;
	poll_hold.unlock();
	std::unique_lock turn_hold(g_context_locks[CONTEXT_TURNING]);
	pcontext->type = CONTEXT_TURNING;
	double_list_append_as_tail(
		&g_context_lists[CONTEXT_TURNING],
		&pcontext->node);
	turn_hold.unlock();
	threads_pool_wakeup_thread();
}
