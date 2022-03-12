// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/int_hash.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "asyncemsmdb_interface.h"
#include "asyncemsmdb_ndr.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#define WAITING_INTERVAL						300

#define FLAG_NOTIFICATION_PENDING				0x00000001

using namespace gromox;

namespace {

struct ASYNC_WAIT {
	DOUBLE_LIST_NODE node;
	time_t wait_time;
	char username[UADDR_SIZE];
	uint16_t cxr;
	uint32_t async_id;
	union {
		ECDOASYNCWAITEX_OUT *pout;
		int context_id; /* when async_id is 0 */
	} out_payload;
};

}

static constexpr size_t TAG_SIZE = UADDR_SIZE + 1 + HXSIZEOF_Z32;
static unsigned int g_threads_num;
static pthread_t g_scan_id;
static std::vector<pthread_t> g_thread_ids;
static gromox::atomic_bool g_notify_stop{true};
static DOUBLE_LIST g_wakeup_list;
static std::unordered_map<std::string, ASYNC_WAIT *> g_tag_hash;
static size_t g_tag_hash_max;
static std::mutex g_list_lock, g_async_lock;
static std::condition_variable g_waken_cond;
static std::unique_ptr<INT_HASH_TABLE> g_async_hash;
static LIB_BUFFER g_wait_allocator;

static void *aemsi_scanwork(void *);
static void *aemsi_thrwork(void *);

static void (*active_hpm_context)(int context_id, BOOL b_pending);

/* called by moh_emsmdb module */
void asyncemsmdb_interface_register_active(void *pproc)
{
	active_hpm_context = reinterpret_cast<decltype(active_hpm_context)>(pproc);
}

void asyncemsmdb_interface_init(unsigned int threads_num)
{
	g_threads_num = threads_num;
	g_thread_ids.reserve(threads_num);
	double_list_init(&g_wakeup_list);
}

int asyncemsmdb_interface_run()
{
	int context_num;
	
	context_num = get_context_num();
	g_async_hash = INT_HASH_TABLE::create(2 * context_num, sizeof(ASYNC_WAIT *));
	if (NULL == g_async_hash) {
		printf("[exchange_emsmdb]: Failed to init async ID hash table\n");
		return -2;
	}
	g_wait_allocator = LIB_BUFFER(sizeof(ASYNC_WAIT), 2 * context_num);
	g_tag_hash_max = context_num;
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, aemsi_scanwork, nullptr);
	if (ret != 0) {
		printf("[exchange_emsmdb]: failed to create scanning thread "
		       "for asyncemsmdb: %s\n", strerror(ret));
		g_notify_stop = true;
		return -5;
	}
	pthread_setname_np(g_scan_id, "asyncems/scan");
	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		ret = pthread_create(&tid, nullptr, aemsi_thrwork, nullptr);
		if (ret != 0) {
			printf("[exchange_emsmdb]: failed to create wake up "
			       "thread for asyncemsmdb: %s\n", strerror(ret));
			asyncemsmdb_interface_stop();
			return -6;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "asyncems/%u", i);
		pthread_setname_np(tid, buf);
		g_thread_ids.push_back(tid);
	}
	return 0;
}

void asyncemsmdb_interface_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		g_waken_cond.notify_all();
		if (!pthread_equal(g_scan_id, {})) {
			pthread_kill(g_scan_id, SIGALRM);
			pthread_join(g_scan_id, NULL);
		}
		for (auto tid : g_thread_ids) {
			pthread_kill(tid, SIGALRM);
			pthread_join(tid, nullptr);
		}
	}
	g_thread_ids.clear();
	g_tag_hash.clear();
	g_async_hash.reset();
}

void asyncemsmdb_interface_free()
{
	double_list_free(&g_wakeup_list);
}

int asyncemsmdb_interface_async_wait(uint32_t async_id,
	ECDOASYNCWAITEX_IN *pin, ECDOASYNCWAITEX_OUT *pout)
{
	char tmp_tag[TAG_SIZE];
	
	auto pwait = g_wait_allocator->get<ASYNC_WAIT>();
	if (NULL == pwait) {
		pout->flags_out = 0;
		pout->result = ecRejected;
		return DISPATCH_SUCCESS;
	}
	auto rpc_info = get_rpc_info();
	if (!emsmdb_interface_check_acxh(&pin->acxh, pwait->username, &pwait->cxr, TRUE) ||
		0 != strcasecmp(rpc_info.username, pwait->username)) {
		g_wait_allocator->put(pwait);
		pout->flags_out = 0;
		pout->result = ecRejected;
		return DISPATCH_SUCCESS;
	}
	if (emsmdb_interface_check_notify(&pin->acxh)) {
		g_wait_allocator->put(pwait);
		pout->flags_out = FLAG_NOTIFICATION_PENDING;
		pout->result = ecSuccess;
		return DISPATCH_SUCCESS;
	}
	pwait->node.pdata = pwait;
	pwait->async_id = async_id;
	HX_strlower(pwait->username);
	time(&pwait->wait_time);
	if (async_id == 0)
		pwait->out_payload.context_id = pout->flags_out;
	else
		pwait->out_payload.pout = pout;
	snprintf(tmp_tag, GX_ARRAY_SIZE(tmp_tag), "%s:%d", pwait->username,
	         static_cast<int>(pwait->cxr));
	HX_strlower(tmp_tag);
	std::unique_lock as_hold(g_async_lock);
	if (0 != async_id) {
		if (g_async_hash->add(async_id, &pwait) != 1) {
			as_hold.unlock();
			g_wait_allocator->put(pwait);
			pout->flags_out = 0;
			pout->result = ecRejected;
			return DISPATCH_SUCCESS;
		}
	}
	try {
		if (g_tag_hash.size() < g_tag_hash_max &&
		    g_tag_hash.emplace(tmp_tag, pwait).second)
			return DISPATCH_PENDING;
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "W-1540: ENOMEM\n");
	}
	if (async_id != 0)
		g_async_hash->remove(async_id);
	as_hold.unlock();
	g_wait_allocator->put(pwait);
	pout->flags_out = 0;
	pout->result = ecRejected;
	return DISPATCH_SUCCESS;
}

void asyncemsmdb_interface_reclaim(uint32_t async_id)
{
	char tmp_tag[TAG_SIZE];
	ASYNC_WAIT *pwait;
	
	std::unique_lock as_hold(g_async_lock);
	auto ppwait = g_async_hash->query<ASYNC_WAIT *>(async_id);
	if (NULL == ppwait) {
		return;
	}
	pwait = *ppwait;
	snprintf(tmp_tag, GX_ARRAY_SIZE(tmp_tag), "%s:%d", pwait->username,
	         static_cast<int>(pwait->cxr));
	HX_strlower(tmp_tag);
	g_tag_hash.erase(tmp_tag);
	g_async_hash->remove(async_id);
	as_hold.unlock();
	g_wait_allocator->put(pwait);
}

/* called by moh_emsmdb module */
void asyncemsmdb_interface_remove(ACXH *pacxh)
{
	uint16_t cxr;
	char tmp_tag[TAG_SIZE];
	char username[UADDR_SIZE];

	if (!emsmdb_interface_check_acxh(pacxh, username, &cxr, false))
		return;
	snprintf(tmp_tag, GX_ARRAY_SIZE(tmp_tag), "%s:%d", username, cxr);
	HX_strlower(tmp_tag);
	std::unique_lock as_hold(g_async_lock);
	auto iter = g_tag_hash.find(tmp_tag);
	if (iter == g_tag_hash.cend())
		return;
	auto pwait = iter->second;
	if (0 != pwait->async_id) {
		g_async_hash->remove(pwait->async_id);
	}
	g_tag_hash.erase(iter);
	as_hold.unlock();
	g_wait_allocator->put(pwait);
}

static void asyncemsmdb_interface_activate(
	ASYNC_WAIT *pwait, BOOL b_pending)
{
	if (0 == pwait->async_id) {
		active_hpm_context(pwait->out_payload.context_id, b_pending);
	} else if (rpc_build_environment(pwait->async_id)) {
		pwait->out_payload.pout->result = ecSuccess;
		pwait->out_payload.pout->flags_out = b_pending ? FLAG_NOTIFICATION_PENDING : 0;
		async_reply(pwait->async_id, pwait->out_payload.pout);
	}
	g_wait_allocator->put(pwait);
}

void asyncemsmdb_interface_wakeup(const char *username, uint16_t cxr)
{
	char tmp_tag[TAG_SIZE];
	
	snprintf(tmp_tag, GX_ARRAY_SIZE(tmp_tag), "%s:%d",
	         username, static_cast<int>(cxr));
	HX_strlower(tmp_tag);
	std::unique_lock as_hold(g_async_lock);
	auto iter = g_tag_hash.find(tmp_tag);
	if (iter == g_tag_hash.cend())
		return;
	auto pwait = iter->second;
	g_tag_hash.erase(iter);
	if (0 != pwait->async_id) {
		g_async_hash->remove(pwait->async_id);
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
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&temp_list);
	while (!g_notify_stop) {
		sleep(1);
		time(&cur_time);
		std::unique_lock as_hold(g_async_lock);
		for (auto iter = g_tag_hash.cbegin(); iter != g_tag_hash.end(); ){
			auto pwait = iter->second;
			if (cur_time - pwait->wait_time <= WAITING_INTERVAL - 3) {
				++iter;
				continue;
			}
			iter = g_tag_hash.erase(iter);
			if (pwait->async_id != 0)
				g_async_hash->remove(pwait->async_id);
			double_list_append_as_tail(&temp_list, &pwait->node);
		}
		as_hold.unlock();
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr)
			asyncemsmdb_interface_activate(static_cast<ASYNC_WAIT *>(pnode->pdata), FALSE);
	}
	double_list_free(&temp_list);
	return nullptr;
}
