#include "contexts_pool.h"
#include "threads_pool.h"
#include "util.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>


static int g_time_out;
static int g_context_num;
static int g_epoll_fd = -1;
static pthread_t g_scan_id;
static void *g_context_list;
static int g_context_offset;
static pthread_t g_thread_id;
static int g_contexts_per_thr;
static BOOL g_notify_stop = TRUE;
static struct epoll_event *g_events;
static DOUBLE_LIST g_context_lists[CONTEXT_TYPES];
static pthread_mutex_t g_context_locks[CONTEXT_TYPES];

static int (*contexts_pool_get_context_socket)(void *pcontext);

static struct timeval (*contexts_pool_get_context_timestamp)(void *pcontext);

void context_init(SCHEDULE_CONTEXT *pcontext)
{
	if (NULL == pcontext) {
		debug_info("[contexts_pool]: pcontext is NULL in context_init!\n");
		return;
	}
	pcontext->type = CONTEXT_FREE;
	pcontext->node.pdata = pcontext;
}

void context_free(SCHEDULE_CONTEXT *pcontext)
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
	case CUR_SCHEDUING_CONTEXTS:
		return double_list_get_nodes_num(
			&g_context_lists[CONTEXT_TURNING]);
	default:
		return -1;
	}
}

static void* thread_work_func(void *pparam)
{
	int i, num;
	SCHEDULE_CONTEXT *pcontext;
	
	while (FALSE == g_notify_stop) {
		num = epoll_wait(g_epoll_fd, g_events, g_context_num, 1000);
		if (num <= 0) {
			continue;
		}
		for (i=0; i<num; i++) {
			pcontext = g_events[i].data.ptr;
			pthread_mutex_lock(&g_context_locks[CONTEXT_POLLING]);
			if (CONTEXT_POLLING != pcontext->type) {
				/* context may be waked up and modified by
				scan_work_func or context_pool_activate_context */
				pthread_mutex_unlock(&g_context_locks[CONTEXT_POLLING]);
				continue;
			}
			if (FALSE == pcontext->b_waiting) {
				debug_info("[contexts_pool]: fatal error in context"
					" queue! b_waiting mismatch in thread_work_func"
					" conext: %p\n", pcontext);
				pthread_mutex_unlock(&g_context_locks[CONTEXT_POLLING]);
				continue;
			}
			double_list_remove(&g_context_lists[CONTEXT_POLLING],
				&pcontext->node);
			pcontext->type = CONTEXT_SWITCHING;
			pthread_mutex_unlock(&g_context_locks[CONTEXT_POLLING]);
			contexts_pool_put_context(pcontext, CONTEXT_TURNING);
		}
		if (1 == num) {
			threads_pool_wakeup_thread();
		} else {
			threads_pool_wakeup_all_threads();
		}
	}
	pthread_exit(0);
}

static void *scan_work_func(void *pparam)
{
	int num;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	SCHEDULE_CONTEXT *pcontext;
	struct timeval current_time;
	
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_context_locks[CONTEXT_POLLING]);
		gettimeofday(&current_time, NULL);
		ptail = double_list_get_tail(
			&g_context_lists[CONTEXT_POLLING]);
		while (pnode=double_list_get_from_head(
			&g_context_lists[CONTEXT_POLLING])) {
			pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
			if (FALSE == pcontext->b_waiting) {
				pcontext->type = CONTEXT_SWITCHING;
				double_list_append_as_tail(&temp_list, pnode);
				goto CHECK_TAIL;
			}
			if (CALCULATE_INTERVAL(current_time,
				contexts_pool_get_context_timestamp(pcontext))
				>= g_time_out) {
				if (-1 == epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL,
					contexts_pool_get_context_socket(pcontext), NULL)) {
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
		pthread_mutex_unlock(&g_context_locks[CONTEXT_POLLING]);
		pthread_mutex_lock(&g_context_locks[CONTEXT_IDLING]);
		while (pnode=double_list_get_from_head(
			&g_context_lists[CONTEXT_IDLING])) {
			pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
			pcontext->type = CONTEXT_SWITCHING;
			double_list_append_as_tail(&temp_list, pnode);
		}
		pthread_mutex_unlock(&g_context_locks[CONTEXT_IDLING]);
		num = 0;
		pthread_mutex_lock(&g_context_locks[CONTEXT_TURNING]);
		while (pnode=double_list_get_from_head(&temp_list)) {
			((SCHEDULE_CONTEXT*)pnode->pdata)->type = CONTEXT_TURNING;
			double_list_append_as_tail(
				&g_context_lists[CONTEXT_TURNING], pnode);
			num ++;
		}
		pthread_mutex_unlock(&g_context_locks[CONTEXT_TURNING]);
		if (1 == num) {
			threads_pool_wakeup_thread();
		} else if (num > 1) {
			threads_pool_wakeup_all_threads();
		}
		sleep(1);
	}
	double_list_free(&temp_list);
	pthread_exit(0);
}

void contexts_pool_init(void *pcontexts, int context_num,
	int unit_offset, int (*get_socket)(void*),
	struct timeval (*get_timestamp)(void*),
	int contexts_per_thr, int timeout)
{
	int i;
	SCHEDULE_CONTEXT* pcontext;
	
	g_context_list = pcontexts;
	g_context_num = context_num;
	g_context_offset = unit_offset;
	contexts_pool_get_context_socket = get_socket;
	contexts_pool_get_context_timestamp = get_timestamp;
	g_contexts_per_thr = contexts_per_thr;
	g_time_out = timeout;
	for (i=CONTEXT_BEGIN; i<CONTEXT_TYPES; i++) {
		double_list_init(&g_context_lists[i]);
	}
	if (g_context_offset < sizeof(SCHEDULE_CONTEXT)) {
		debug_info("[contexts_pool]: contexts offset"
				" error passed into contexts pool\n");
	}
	for (i=0; i<g_context_num; i++) {
		pcontext = (SCHEDULE_CONTEXT*)((char*)
			g_context_list + i*g_context_offset);
		context_init(pcontext);
		double_list_append_as_tail(
			&g_context_lists[CONTEXT_FREE], &pcontext->node);
	}
	for (i=CONTEXT_BEGIN; i<CONTEXT_TYPES; i++) {
		pthread_mutex_init(&g_context_locks[i], NULL);
	}
}

int contexts_pool_run()
{    
	g_epoll_fd = epoll_create(g_context_num);
	if (-1 == g_epoll_fd) {
		printf("[contexts_pool]: fail to create epoll instance\n");
		return -1;
	}
	g_events = malloc(sizeof(struct epoll_event)*g_context_num);
	if (NULL == g_events) {
		close(g_epoll_fd);
		g_epoll_fd = -1;
		printf("[contexts_pool]: fail to allocate memory for events\n");
		return -2;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
		printf("[contexts_pool]: fail to create epoll thread\n");
		g_notify_stop = TRUE;
		free(g_events);
		g_events = NULL;
		close(g_epoll_fd);
		g_epoll_fd = -1;
	}
	if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
		printf("[contexts_pool]: fail to create scan thread\n");
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
		close(g_epoll_fd);
		g_epoll_fd = -1;
		free(g_events);
		g_events = NULL;
	}
	return 0;    
}

int contexts_pool_stop()
{
	g_notify_stop = TRUE;
	pthread_join(g_thread_id, NULL);
	pthread_join(g_scan_id, NULL);
	close(g_epoll_fd);
	g_epoll_fd = -1;
	free(g_events);
	g_events = NULL;
	return 0;
}

void contexts_pool_free()
{
	int i;
	
	for (i=0; i<g_context_num; i++) {
		context_free((SCHEDULE_CONTEXT*)((char*)
			g_context_list + i * g_context_offset));
	}
	for (i=CONTEXT_BEGIN; i<CONTEXT_TYPES; i++) {
		pthread_mutex_destroy(&g_context_locks[i]);
	}
	for (i=CONTEXT_BEGIN; i<CONTEXT_TYPES; i++) {
		double_list_free(&g_context_lists[i]);
	}
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
	SCHEDULE_CONTEXT *pcontext;
	if (CONTEXT_FREE != type && CONTEXT_TURNING != type) {
		return NULL;
	}
	pthread_mutex_lock(&g_context_locks[type]);
	pnode = double_list_get_from_head(&g_context_lists[type]);
	if (NULL != pnode) {
		pcontext = (SCHEDULE_CONTEXT*)pnode->pdata;
	} else {
		pcontext = NULL;
	}
	/* do not change context type under this circumstance */
	pthread_mutex_unlock(&g_context_locks[type]);
	return pcontext;
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
	int orignal_type;
	struct epoll_event tmp_ev;
	
	
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
	pthread_mutex_lock(&g_context_locks[type]);
	orignal_type = pcontext->type;
	pcontext->type = type;
	tmp_ev.events = 0;
	if (CONTEXT_POLLING == type) {
		if (POLLING_READ & pcontext->polling_mask) {
			tmp_ev.events |= EPOLLIN;
		}
		if (POLLING_WRITE & pcontext->polling_mask) {
			tmp_ev.events |= EPOLLOUT;
		}
		tmp_ev.events |= EPOLLET | EPOLLONESHOT;
		tmp_ev.data.ptr = pcontext;
		if (CONTEXT_CONSTRUCTING == orignal_type) {
			if (-1 == epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD,
				contexts_pool_get_context_socket(pcontext), &tmp_ev)) {
				pcontext->b_waiting = FALSE;
				debug_info("[contexts_pool]: fail to add event to epoll!\n");
			} else {
				pcontext->b_waiting = TRUE;
			}
		} else {
			if (-1 == epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD,
				contexts_pool_get_context_socket(pcontext), &tmp_ev)) {
				if (ENOENT == errno && 0 == epoll_ctl(g_epoll_fd,
					EPOLL_CTL_ADD, contexts_pool_get_context_socket(
					pcontext), &tmp_ev)) {
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
		}
	} else if (CONTEXT_FREE == type && CONTEXT_TURNING == orignal_type) {
		if (TRUE == pcontext->b_waiting) {
			/* socket was removed by "close()" function automatically,
				no need to call epoll_ctl with EPOLL_CTL_DEL */
			pcontext->b_waiting = FALSE;
		}
	}
	double_list_append_as_tail(&g_context_lists[type], 
									&pcontext->node);
	pthread_mutex_unlock(&g_context_locks[type]);
}

void contexts_pool_signal(SCHEDULE_CONTEXT *pcontext)
{
	pthread_mutex_lock(&g_context_locks[CONTEXT_IDLING]);
	if (CONTEXT_IDLING != pcontext->type) {
		pthread_mutex_unlock(&g_context_locks[CONTEXT_IDLING]);
		return;
	}
	double_list_remove(&g_context_lists[CONTEXT_IDLING], &pcontext->node);
	pcontext->type = CONTEXT_SWITCHING;
	pthread_mutex_unlock(&g_context_locks[CONTEXT_IDLING]);
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
	pthread_mutex_lock(&g_context_locks[CONTEXT_SLEEPING]);
	double_list_remove(&g_context_lists[CONTEXT_SLEEPING], &pcontext->node);
	pthread_mutex_unlock(&g_context_locks[CONTEXT_SLEEPING]);
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
	pthread_mutex_lock(&g_context_locks[CONTEXT_POLLING]);
	if (CONTEXT_POLLING != pcontext->type) {
		pthread_mutex_unlock(&g_context_locks[CONTEXT_POLLING]);
		return;
	}
	double_list_remove(&g_context_lists[CONTEXT_POLLING], &pcontext->node);
	pcontext->type = CONTEXT_SWITCHING;
	pthread_mutex_unlock(&g_context_locks[CONTEXT_POLLING]);
	pthread_mutex_lock(&g_context_locks[CONTEXT_TURNING]);
	pcontext->type = CONTEXT_TURNING;
	double_list_append_as_tail(
		&g_context_lists[CONTEXT_TURNING],
		&pcontext->node);
	pthread_mutex_unlock(&g_context_locks[CONTEXT_TURNING]);
	threads_pool_wakeup_thread();
}
