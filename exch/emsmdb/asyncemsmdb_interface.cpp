// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
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
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/proc_common.h>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "asyncemsmdb_interface.hpp"
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "emsmdb_ndr.hpp"
#define WAITING_INTERVAL						300

#define FLAG_NOTIFICATION_PENDING				0x00000001

using namespace gromox;

namespace {

struct ASYNC_WAIT {
	time_t wait_time = 0;
	std::string username;
	uint16_t cxr = 0;
	uint32_t async_id = 0;
	ECDOASYNCWAITEX_OUT *pout = nullptr;
	int context_id = 0; /* when async_id is 0 */
};

}

static unsigned int g_threads_num;
static pthread_t g_scan_id;
static std::vector<pthread_t> g_thread_ids;
static gromox::atomic_bool g_aemsi_stop{true};
static std::vector<std::shared_ptr<ASYNC_WAIT>> g_wakeup_list;
static std::unordered_map<std::string, std::shared_ptr<ASYNC_WAIT>> g_tag_hash;
static size_t g_tag_hash_max;
static std::mutex g_list_lock; /* protects g_wakeup_list */
static std::mutex g_async_lock; /* protects g_tag_hash & g_async_hash */
static std::condition_variable g_waken_cond;
static std::unordered_map<int, std::shared_ptr<ASYNC_WAIT>> g_async_hash;

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
}

int asyncemsmdb_interface_run()
{
	int context_num;
	
	context_num = get_context_num();
	g_tag_hash_max = context_num;
	g_aemsi_stop = false;
	auto ret = pthread_create4(&g_scan_id, nullptr, aemsi_scanwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "emsmdb: failed to create scanning thread "
		       "for asyncemsmdb: %s", strerror(ret));
		g_aemsi_stop = true;
		return -5;
	}
	for (unsigned int i = 0; i < g_threads_num; ++i) {
		pthread_t tid;
		ret = pthread_create4(&tid, nullptr, aemsi_thrwork, nullptr);
		if (ret != 0) {
			mlog(LV_ERR, "emsmdb: failed to create wake up "
			       "thread for asyncemsmdb: %s", strerror(ret));
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
	if (!g_aemsi_stop) {
		g_aemsi_stop = true;
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
	{ /* silence cov-scan, take locks even in single-thread scenarios */
		std::lock_guard lk(g_async_lock);
		g_tag_hash.clear();
		g_async_hash.clear();
	}
}

void asyncemsmdb_interface_free()
{
	std::unique_lock hold(g_list_lock); /* silence cov-scan */
	g_wakeup_list.clear();
}

int asyncemsmdb_interface_async_wait(uint32_t async_id,
    const ECDOASYNCWAITEX_IN *pin, ECDOASYNCWAITEX_OUT *pout)
{
	auto cl_fail = HX::make_scope_exit([&]() {
		pout->flags_out = 0;
		pout->result = ecRejected;
	});

	auto pwait = std::make_shared<ASYNC_WAIT>();
	auto rpc_info = get_rpc_info();
	if (!emsmdb_interface_inspect_acxh(&pin->acxh, pwait->username,
	    &pwait->cxr, true) ||
	    strcasecmp(rpc_info.username, pwait->username.c_str()) != 0)
		return DISPATCH_SUCCESS;
	if (emsmdb_interface_notifications_pending(pin->acxh))
		return DISPATCH_SUCCESS;
	pwait->async_id = async_id;
	HX_strlower(pwait->username.data());
	pwait->wait_time = time(nullptr);
	if (async_id == 0) {
		pwait->context_id = pout->flags_out;
		pwait->pout = nullptr;
	} else {
		pwait->context_id = 0;
		pwait->pout = pout;
	}
	auto tag = pwait->username + ":" + std::to_string(pwait->cxr);
	HX_strlower(tag.data());
	std::unique_lock as_hold(g_async_lock);
	if (async_id == 0) {
		if (g_tag_hash.size() < g_tag_hash_max &&
		    g_tag_hash.emplace(tag, pwait).second) {
			/* actual "success" case */
			cl_fail.release();
			return DISPATCH_PENDING;
		}
		return DISPATCH_SUCCESS;
	}

	if (g_async_hash.size() >= 2 * get_context_num())
		return DISPATCH_SUCCESS;
	auto pair = g_async_hash.emplace(async_id, pwait);
	if (!pair.second)
		return DISPATCH_SUCCESS;
	auto cl_fail2 = HX::make_scope_exit([&]() { g_async_hash.erase(async_id); });
	if (g_tag_hash.size() < g_tag_hash_max &&
	    g_tag_hash.emplace(tag, pwait).second) {
		/* actual success case */
		cl_fail2.release();
		cl_fail.release();
		return DISPATCH_PENDING;
	}
	return DISPATCH_SUCCESS;
}

void asyncemsmdb_interface_reclaim(uint32_t async_id) try
{
	std::unique_lock as_hold(g_async_lock);
	auto iter = g_async_hash.find(async_id);
	if (iter == g_async_hash.end())
		return;
	auto pwait = iter->second;
	auto tag = pwait->username + ":" + std::to_string(pwait->cxr);
	HX_strlower(tag.data());
	g_tag_hash.erase(tag.data());
	g_async_hash.erase(async_id);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

/* called by moh_emsmdb module */
void asyncemsmdb_interface_remove(ACXH *pacxh) try
{
	uint16_t cxr;
	std::string tag;

	if (!emsmdb_interface_inspect_acxh(pacxh, tag, &cxr, false))
		return;
	tag += ":" + std::to_string(cxr);
	HX_strlower(tag.data());
	std::unique_lock as_hold(g_async_lock);
	auto iter = g_tag_hash.find(std::move(tag));
	if (iter == g_tag_hash.cend())
		return;
	auto pwait = iter->second;
	if (pwait->async_id != 0)
		g_async_hash.erase(pwait->async_id);
	g_tag_hash.erase(iter);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

static void asyncemsmdb_interface_activate(std::shared_ptr<ASYNC_WAIT> &&pwait, bool b_pending)
{
	if (0 == pwait->async_id) {
		active_hpm_context(pwait->context_id, b_pending);
	} else if (rpc_build_environment(pwait->async_id)) {
		pwait->pout->result = ecSuccess;
		pwait->pout->flags_out = b_pending ? FLAG_NOTIFICATION_PENDING : 0;
		async_reply(pwait->async_id, pwait->pout);
	}
}

void asyncemsmdb_interface_wakeup(std::string &&tag, uint16_t cxr) try
{
	tag += ":";
	tag += std::to_string(cxr);
	HX_strlower(tag.data());
	std::unique_lock as_hold(g_async_lock);
	auto iter = g_tag_hash.find(std::move(tag));
	if (iter == g_tag_hash.cend())
		return;
	auto pwait = iter->second;
	g_tag_hash.erase(iter);
	if (pwait->async_id != 0)
		g_async_hash.erase(pwait->async_id);
	as_hold.unlock();
	std::unique_lock ll_hold(g_list_lock);
	g_wakeup_list.emplace_back(std::move(pwait));
	ll_hold.unlock();
	g_waken_cond.notify_one();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

static void *aemsi_thrwork(void *param)
{
	while (true) {
		std::shared_ptr<ASYNC_WAIT> pnode;
		{
			std::unique_lock<std::mutex> holder(g_list_lock);
			g_waken_cond.wait(holder, [] {
				return g_aemsi_stop || g_wakeup_list.size() > 0;
			});
			if (g_aemsi_stop)
				break;
			if (g_wakeup_list.empty())
				continue;
			pnode = std::move(g_wakeup_list.front());
			g_wakeup_list.erase(g_wakeup_list.begin());
		}
		asyncemsmdb_interface_activate(std::move(pnode), TRUE);
	}
	return nullptr;
}

static void *aemsi_scanwork(void *param)
{
	pthread_setname_np(pthread_self(), "aemsi_scan");
	std::vector<std::shared_ptr<ASYNC_WAIT>> tl;
	
	while (!g_aemsi_stop) {
		sleep(1);
		auto cur_time = time(nullptr);
		std::unique_lock as_hold(g_async_lock);
		for (auto iter = g_tag_hash.cbegin(); iter != g_tag_hash.end(); ){
			auto pwait = iter->second;
			if (cur_time - pwait->wait_time <= WAITING_INTERVAL - 3) {
				++iter;
				continue;
			}
			tl.push_back(pwait);
			iter = g_tag_hash.erase(iter);
			if (pwait->async_id != 0)
				g_async_hash.erase(pwait->async_id);
		}
		as_hold.unlock();
		while (tl.size() > 0) {
			auto pwait = std::move(tl.front());
			tl.erase(tl.begin());
			asyncemsmdb_interface_activate(std::move(pwait), false);
		}
	}
	return nullptr;
}
