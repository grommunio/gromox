// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <vector>
#include <sys/socket.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include <gromox/zcore_rpc.hpp>
#include "common_util.hpp"
#include "rpc_ext.hpp"
#include "rpc_parser.hpp"
#include "zserver.hpp"

using namespace gromox;

enum {
	DISPATCH_TRUE,
	DISPATCH_FALSE,
	DISPATCH_CONTINUE
};

static unsigned int g_thread_num;
static gromox::atomic_bool g_zrpc_stop;
static std::vector<pthread_t> g_thread_ids;
static std::vector<wrapfd> g_conn_list;
static std::condition_variable g_waken_cond;
static std::mutex g_conn_lock;
unsigned int g_zrpc_debug;

template<typename T> static inline auto optional_ptr(std::optional<T> &p) { return p ? &*p : nullptr; }
template<typename T> static inline auto optional_ptr(const std::optional<T> &p) { return p ? &*p : nullptr; }
template<typename T> static inline auto optional_ptr(const std::vector<T> &p) { return p.size() != 0 ? &p : nullptr; }

void rpc_parser_init(unsigned int thread_num)
{
	g_zrpc_stop = true;
	g_thread_num = thread_num;
	g_thread_ids.reserve(thread_num);
}

void rpc_parser_activate_connection(wrapfd &&fd) try
{
	{
		std::unique_lock cl_hold(g_conn_lock);
		g_conn_list.emplace_back(std::move(fd));
	}
	g_waken_cond.notify_one();
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

static int rpc_parser_dispatch(const zcreq *q0, std::unique_ptr<zcresp> &r0) try
{
	auto tstart = tp_now();
	GUID dbg_hsession{};
	switch (q0->call_id) {
#include <zrpc_dispatch.cpp>
	default:
		mlog(LV_ERR, "E-2046: unknown zrpc request type %u",
		        static_cast<unsigned int>(r0->call_id));
		return DISPATCH_FALSE;
	}
	auto tend = tp_now();
	if (q0->call_id == zcore_callid::notifdequeue && r0->result == ecNotFound)
		return DISPATCH_CONTINUE;
	r0->call_id = q0->call_id;
	if (g_zrpc_debug == 0)
		return DISPATCH_TRUE;
	if (r0->result != ecSuccess || g_zrpc_debug == 2) {
		auto info = zs_query_session(dbg_hsession);
		mlog(LV_DEBUG, "ZRPC %s %5luµs %8xh %s",
		        info != nullptr ? info->username.c_str() : "<>",
		        static_cast<unsigned long>(std::chrono::duration_cast<std::chrono::microseconds>(tend - tstart).count()),
		        static_cast<unsigned int>(r0->result), zcore_rpc_idtoname(q0->call_id));
	}
	return DISPATCH_TRUE;
} catch (const std::bad_alloc &) {
	return DISPATCH_FALSE;
}

static void *zcrp_thrwork(void *param)
{
	uint32_t offset;
	struct pollfd fdpoll;

	while (true) {
	wrapfd clifd;

	/* Wait for work items */
	{
		std::unique_lock cm_hold(g_conn_lock);
		g_waken_cond.wait(cm_hold, []() { return g_zrpc_stop || g_conn_list.size() > 0; });
		if (g_zrpc_stop)
			return nullptr;
		if (g_conn_list.empty())
			continue;
		clifd = std::move(g_conn_list.front());
		g_conn_list.erase(g_conn_list.begin());
	}

	offset = 0;
	fdpoll.fd = clifd.get();
	fdpoll.events = POLLIN|POLLPRI;
	if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) != 1)
		continue;

	std::string pbuff;
	try {
		uint32_t buff_len = 0;
		auto read_len = read(clifd.get(), &buff_len, sizeof(uint32_t));
		if (read_len < 0 || static_cast<size_t>(read_len) != sizeof(uint32_t) ||
		    buff_len >= UINT_MAX)
			continue;
		buff_len = std::min(buff_len, UINT32_MAX);
		pbuff.resize(buff_len);
	} catch (const std::bad_alloc &) {
		auto tmp_byte = zcore_response::lack_memory;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd.get(), &tmp_byte, 1) < 1)
				/* ignore */;
		continue;
	}
	while (true) {
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) != 1) {
			clifd.close_rd();
			break;
		}
		auto read_len = read(clifd.get(), &pbuff[offset], pbuff.size() - offset);
		if (read_len <= 0) {
			clifd.close_rd();
			break;
		}
		offset += read_len;
		if (offset == pbuff.size())
			break;
	}
	/*
	 * Interrupt the read loop and, if the entire buffer has not
	 * been read, we go back to waiting.
	 */
	if (offset != pbuff.size())
		continue;

	common_util_build_environment();
	std::unique_ptr<zcreq> request;
	if (rpc_ext_pull_request(pbuff, request) != pack_result::ok) {
		common_util_free_environment();
		auto tmp_byte = zcore_response::pull_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd.get(), &tmp_byte, 1) < 1)
				/* ignore */;
		continue;
	}
	pbuff = {};

	/*
	 * Transfer ownership of the fd to rpc_parser. Afterwards, we try
	 * taking the fd back from rpc_parser. Either we get it, or it is clear
	 * that e.g. zs_notifdequeue took it for itself.
	 */
	cu_set_clifd(std::move(clifd));
	std::unique_ptr<zcresp> response;
	auto ds_result = rpc_parser_dispatch(request.get(), response);
	if (auto p = cu_get_clifd())
		clifd = std::move(*p);

	if (ds_result == DISPATCH_FALSE) {
		common_util_free_environment();
		if (clifd.get() < 0)
			continue;
		auto tmp_byte = zcore_response::dispatch_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd.get(), &tmp_byte, 1) < 1)
				/* ignore */;
		continue;
	} else if (ds_result == DISPATCH_CONTINUE) {
		common_util_free_environment();
		continue;
	}
	/* DISPATCH_TRUE: */
	if (clifd.get() < 0) {
		common_util_free_environment();
		continue;
	}

	BINARY tmp_bin{};
	if (rpc_ext_push_response(response.get(), &tmp_bin) != pack_result::ok) {
		common_util_free_environment();
		auto tmp_byte = zcore_response::push_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd.get(), &tmp_byte, 1) < 1)
				/* ignore */;
		continue;
	}
	common_util_free_environment();
	fdpoll.events = POLLOUT|POLLWRBAND;
	if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
		if (write(clifd.get(), tmp_bin.pb, tmp_bin.cb) < 0)
			/* ignore */;
	shutdown(clifd.get(), SHUT_WR);
	uint8_t tmp_byte;
	if (read(clifd.get(), &tmp_byte, 1))
		/* ignore */;
	clifd.close_rd();
	free(tmp_bin.pb);
	tmp_bin.pb = nullptr;
	}
	return nullptr;
}

int rpc_parser_run() try
{
	g_zrpc_stop = false;
	int ret = 0;
	for (unsigned int i = 0; i < g_thread_num; ++i) {
		pthread_t tid;
		ret = pthread_create4(&tid, nullptr, zcrp_thrwork, nullptr);
		if (ret != 0) {
			mlog(LV_ERR, "rpc_parser: failed to create pool thread: %s", strerror(ret));
			rpc_parser_stop();
			return -1;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "rpc/%u", i);
		pthread_setname_np(tid, buf);
		g_thread_ids.push_back(tid);
	}
	return 0;
} catch (const std::bad_alloc &) {
	rpc_parser_stop();
	return -1;
}

void rpc_parser_stop()
{
	g_zrpc_stop = true;
	g_waken_cond.notify_all();
	for (auto tid : g_thread_ids) {
		pthread_kill(tid, SIGALRM);
		pthread_join(tid, nullptr);
	}
	g_thread_ids.clear();
	std::unique_lock cl_hold(g_conn_lock);
	g_conn_list.clear();
}
