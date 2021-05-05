// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <mutex>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "asyncemsmdb_interface.h"
#include "emsmdb_interface.h"
#include <gromox/proc_common.h>
#include "common_util.h"
#include <gromox/double_list.hpp>
#include <gromox/lib_buffer.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/util.hpp>
#include <pthread.h>
#include <unistd.h>
#include <cstdio>
#define WAITING_INTERVAL						300

#define FLAG_NOTIFICATION_PENDING				0x00000001

namespace {

struct ASYNC_WAIT {
	DOUBLE_LIST_NODE node;
	time_t wait_time;
	char username[256];
	uint16_t cxr;
	uint32_t async_id;
	union {
		ECDOASYNCWAITEX_OUT *pout;
		int context_id; /* when async_id is 0 */
	} out_payload;
};

}

static int g_threads_num;
static pthread_t g_scan_id;
static pthread_t *g_thread_ids;
static std::atomic<bool> g_notify_stop{true};
static DOUBLE_LIST g_wakeup_list;
static STR_HASH_TABLE *g_tag_hash;
static std::mutex g_list_lock, g_async_lock;
static std::condition_variable g_waken_cond;
static INT_HASH_TABLE *g_async_hash;
static LIB_BUFFER *g_wait_allocator;

static void *aemsi_scanwork(void *);
static void *aemsi_thrwork(void *);

static void (*active_hpm_context)(int context_id, BOOL b_pending);

/* called by moh_emsmdb module */
void asyncemsmdb_interface_register_active(void *pproc)
{
	active_hpm_context = reinterpret_cast<decltype(active_hpm_context)>(pproc);
}

void asyncemsmdb_interface_init(int threads_num)
{
	g_thread_ids = NULL;
	g_threads_num = threads_num;
	double_list_init(&g_wakeup_list);
}

int asyncemsmdb_interface_run()
{
	int i;
	int context_num;
	
	context_num = get_context_num();
	g_thread_ids = me_alloc<pthread_t>(g_threads_num);
	if (NULL == g_thread_ids) {
		printf("[exchange_emsmdb]: Failed to allocate thread id buffer\n");
		return -1;
	}
	g_async_hash = int_hash_init(2 * context_num, sizeof(ASYNC_WAIT *));
	if (NULL == g_async_hash) {
		printf("[exchange_emsmdb]: Failed to init async ID hash table\n");
		return -2;
	}
	g_wait_allocator = lib_buffer_init(
		sizeof(ASYNC_WAIT), 2*context_num, TRUE);
	if (NULL == g_wait_allocator) {
		printf("[exchange_emsmdb]: Failed to init async wait allocator\n");
		return -3;
	}
	g_tag_hash = str_hash_init(context_num, sizeof(ASYNC_WAIT*), NULL);
	if (NULL == g_tag_hash) {
		printf("[exchange_emsmdb]: Failed to init async user hash table\n");
		return -4;
	}
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, aemsi_scanwork, nullptr);
	if (ret != 0) {
		printf("[exchange_emsmdb]: failed to create scanning thread "
		       "for asyncemsmdb: %s\n", strerror(ret));
		g_notify_stop = true;
		return -5;
	}
	pthread_setname_np(g_scan_id, "asyncems/scan");
	for (i=0; i<g_threads_num; i++) {
		ret = pthread_create(&g_thread_ids[i], nullptr, aemsi_thrwork, nullptr);
		if (ret != 0) {
			g_threads_num = i;
			printf("[exchange_emsmdb]: failed to create wake up "
			       "thread for asyncemsmdb: %s\n", strerror(ret));
			return -6;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "asyncems/%u", i);
		pthread_setname_np(g_thread_ids[i], buf);
	}
	return 0;
}

int asyncemsmdb_interface_stop()
{
	int i;
	
	if (!g_notify_stop) {
		g_notify_stop = true;
		g_waken_cond.notify_all();
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, NULL);
		for (i=0; i<g_threads_num; i++) {
			pthread_join(g_thread_ids[i], NULL);
		}
	}
	if (NULL != g_thread_ids) {
		free(g_thread_ids);
		g_thread_ids = NULL;
	}
	if (NULL != g_tag_hash) {
		str_hash_free(g_tag_hash);
		g_tag_hash = NULL;
	}
	if (NULL != g_wait_allocator) {
		lib_buffer_free(g_wait_allocator);
		g_wait_allocator = NULL;
	}
	if (NULL != g_async_hash) {
		int_hash_free(g_async_hash);
		g_async_hash = NULL;
	}
	return 0;
}

void asyncemsmdb_interface_free()
{
	double_list_free(&g_wakeup_list);
}

int asyncemsmdb_interface_async_wait(uint32_t async_id,
	ECDOASYNCWAITEX_IN *pin, ECDOASYNCWAITEX_OUT *pout)
{
	char tmp_tag[256];
	
	auto pwait = static_cast<ASYNC_WAIT *>(lib_buffer_get(g_wait_allocator));
	if (NULL == pwait) {
		pout->flags_out = 0;
		pout->result = ecRejected;
		return DISPATCH_SUCCESS;
	}
	auto rpc_info = get_rpc_info();
	if (FALSE == emsmdb_interface_check_acxh(
		&pin->acxh, pwait->username, &pwait->cxr, TRUE) ||
		0 != strcasecmp(rpc_info.username, pwait->username)) {
		lib_buffer_put(g_wait_allocator, pwait);
		pout->flags_out = 0;
		pout->result = ecRejected;
		return DISPATCH_SUCCESS;
	}
	if (TRUE == emsmdb_interface_check_notify(&pin->acxh)) {
		lib_buffer_put(g_wait_allocator, pwait);
		pout->flags_out = FLAG_NOTIFICATION_PENDING;
		pout->result = ecSuccess;
		return DISPATCH_SUCCESS;
	}
	pwait->node.pdata = pwait;
	pwait->async_id = async_id;
	HX_strlower(pwait->username);
	time(&pwait->wait_time);
	if (0 == async_id) {
		pwait->out_payload.context_id = pout->flags_out;
	} else {
		pwait->out_payload.pout = pout;
	}
	snprintf(tmp_tag, GX_ARRAY_SIZE(tmp_tag), "%s:%d", pwait->username,
	         static_cast<int>(pwait->cxr));
	HX_strlower(tmp_tag);
	std::unique_lock as_hold(g_async_lock);
	if (0 != async_id) {
		if (1 != int_hash_add(g_async_hash, async_id, &pwait)) {
			as_hold.unlock();
			lib_buffer_put(g_wait_allocator, pwait);
			pout->flags_out = 0;
			pout->result = ecRejected;
			return DISPATCH_SUCCESS;
		}
	}
	if (1 != str_hash_add(g_tag_hash, tmp_tag, &pwait)) {
		if (0 != async_id) {
			int_hash_remove(g_async_hash, async_id);
		}
		as_hold.unlock();
		lib_buffer_put(g_wait_allocator, pwait);
		pout->flags_out = 0;
		pout->result = ecRejected;
		return DISPATCH_SUCCESS;
	}
	return DISPATCH_PENDING;
}

void asyncemsmdb_interface_reclaim(uint32_t async_id)
{
	char tmp_tag[256];
	ASYNC_WAIT *pwait;
	
	std::unique_lock as_hold(g_async_lock);
	auto ppwait = static_cast<ASYNC_WAIT **>(int_hash_query(g_async_hash, async_id));
	if (NULL == ppwait) {
		return;
	}
	pwait = *ppwait;
	snprintf(tmp_tag, GX_ARRAY_SIZE(tmp_tag), "%s:%d", pwait->username,
	         static_cast<int>(pwait->cxr));
	HX_strlower(tmp_tag);
	str_hash_remove(g_tag_hash, tmp_tag);
	int_hash_remove(g_async_hash, async_id);
	as_hold.unlock();
	lib_buffer_put(g_wait_allocator, pwait);
}

/* called by moh_emsmdb module */
void asyncemsmdb_interface_remove(ACXH *pacxh)
{
	uint16_t cxr;
	ASYNC_WAIT *pwait;
	char tmp_tag[256];
	char username[256];

	if (FALSE == emsmdb_interface_check_acxh(
		pacxh, username, &cxr, FALSE)) {
		return;
	}
	sprintf(tmp_tag, "%s:%d", username, cxr);
	HX_strlower(tmp_tag);
	std::unique_lock as_hold(g_async_lock);
	auto ppwait = static_cast<ASYNC_WAIT **>(str_hash_query(g_tag_hash, tmp_tag));
	if (NULL == ppwait) {
		return;
	}
	pwait = *ppwait;
	if (0 != pwait->async_id) {
		int_hash_remove(g_async_hash, pwait->async_id);
	}
	str_hash_remove(g_tag_hash, tmp_tag);
	as_hold.unlock();
	lib_buffer_put(g_wait_allocator, pwait);
}

static void asyncemsmdb_interface_activate(
	ASYNC_WAIT *pwait, BOOL b_pending)
{
	if (0 == pwait->async_id) {
		active_hpm_context(pwait->out_payload.context_id, b_pending);
	} else {
		if (TRUE == rpc_build_environment(pwait->async_id)) {
			pwait->out_payload.pout->result = ecSuccess;
			if (TRUE == b_pending) {
				pwait->out_payload.pout->flags_out =
							FLAG_NOTIFICATION_PENDING;
			} else {
				pwait->out_payload.pout->flags_out = 0;
			}
			async_reply(pwait->async_id, pwait->out_payload.pout);
		}
	}
	lib_buffer_put(g_wait_allocator, pwait);
}

void asyncemsmdb_interface_wakeup(const char *username, uint16_t cxr)
{
	char tmp_tag[256];
	ASYNC_WAIT *pwait;
	
	sprintf(tmp_tag, "%s:%d", username, (int)cxr);
	HX_strlower(tmp_tag);
	std::unique_lock as_hold(g_async_lock);
	auto ppwait = static_cast<ASYNC_WAIT **>(str_hash_query(g_tag_hash, tmp_tag));
	if (NULL == ppwait) {
		return;
	}
	pwait = *ppwait;
	str_hash_remove(g_tag_hash, tmp_tag);
	if (0 != pwait->async_id) {
		int_hash_remove(g_async_hash, pwait->async_id);
	}
	as_hold.unlock();
	std::unique_lock ll_hold(g_list_lock);
	double_list_append_as_tail(&g_wakeup_list, &pwait->node);
	ll_hold.unlock();
	g_waken_cond.notify_one();
}

static void *aemsi_thrwork(void *param)
{
	DOUBLE_LIST_NODE *pnode;
	std::mutex g_cond_mutex;
	
	while (!g_notify_stop) {
		std::unique_lock cm_hold(g_cond_mutex);
		g_waken_cond.wait(cm_hold);
		cm_hold.unlock();
 NEXT_WAKEUP:
		if (g_notify_stop)
			break;
		std::unique_lock ll_hold(g_list_lock);
		pnode = double_list_pop_front(&g_wakeup_list);
		ll_hold.unlock();
		if (NULL == pnode) {
			continue;
		}
		asyncemsmdb_interface_activate(static_cast<ASYNC_WAIT *>(pnode->pdata), TRUE);
		goto NEXT_WAKEUP;
	}
	return nullptr;
}

static void *aemsi_scanwork(void *param)
{
	time_t cur_time;
	ASYNC_WAIT *pwait;
	STR_HASH_ITER *iter;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&temp_list);
	while (!g_notify_stop) {
		sleep(1);
		time(&cur_time);
		std::unique_lock as_hold(g_async_lock);
		iter = str_hash_iter_init(g_tag_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			auto ppwait = static_cast<ASYNC_WAIT **>(str_hash_iter_get_value(iter, nullptr));
			pwait = *ppwait;
			if (cur_time - pwait->wait_time > WAITING_INTERVAL - 3) {
				str_hash_iter_remove(iter);
				if (0 != pwait->async_id) {
					int_hash_remove(g_async_hash, pwait->async_id);
				}
				double_list_append_as_tail(&temp_list, &pwait->node);
			}
		}
		str_hash_iter_free(iter);
		as_hold.unlock();
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr)
			asyncemsmdb_interface_activate(static_cast<ASYNC_WAIT *>(pnode->pdata), FALSE);
	}
	double_list_free(&temp_list);
	return nullptr;
}
