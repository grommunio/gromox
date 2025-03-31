// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
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

namespace {
struct CLIENT_NODE {
	DOUBLE_LIST_NODE node;
	int clifd;
};
}

static unsigned int g_thread_num;
static gromox::atomic_bool g_zrpc_stop;
static std::vector<pthread_t> g_thread_ids;
static DOUBLE_LIST g_conn_list;
static std::condition_variable g_waken_cond;
static std::mutex g_conn_lock;
unsigned int g_zrpc_debug;

void rpc_parser_init(unsigned int thread_num)
{
	g_zrpc_stop = true;
	g_thread_num = thread_num;
	g_thread_ids.reserve(thread_num);
}

BOOL rpc_parser_activate_connection(int clifd)
{
	auto pclient = gromox::me_alloc<CLIENT_NODE>();
	if (pclient == nullptr)
		return FALSE;
	pclient->node.pdata = pclient;
	pclient->clifd = clifd;
	std::unique_lock cl_hold(g_conn_lock);
	double_list_append_as_tail(&g_conn_list, &pclient->node);
	cl_hold.unlock();
	g_waken_cond.notify_one();
	return TRUE;
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
	int read_len;
	BINARY tmp_bin;
	uint32_t offset;
	uint32_t buff_len;
	struct pollfd fdpoll;
	DOUBLE_LIST_NODE *pnode;

	while (true) {
	/* Wait for work items */
	{
		std::unique_lock cm_hold(g_conn_lock);
		g_waken_cond.wait(cm_hold, []() { return g_zrpc_stop || double_list_get_nodes_num(&g_conn_list) > 0; });
		if (g_zrpc_stop)
			return nullptr;
		pnode = double_list_pop_front(&g_conn_list);
	}
	if (pnode == nullptr)
		continue;

	auto clifd = static_cast<CLIENT_NODE *>(pnode->pdata)->clifd;
	free(pnode->pdata);
	
	offset = 0;
	buff_len = 0;
	
	fdpoll.fd = clifd;
	fdpoll.events = POLLIN|POLLPRI;
	if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) != 1) {
		close(clifd);
		continue;
	}
	read_len = read(clifd, &buff_len, sizeof(uint32_t));
	if (read_len != sizeof(uint32_t) || buff_len >= UINT_MAX) {
		close(clifd);
		continue;
	}
	buff_len = std::min(buff_len, UINT32_MAX);
	auto pbuff = malloc(buff_len);
	if (NULL == pbuff) {
		auto tmp_byte = zcore_response::lack_memory;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd, &tmp_byte, 1) < 1)
				/* ignore */;
		close(clifd);
		continue;
	}
	while (true) {
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) != 1) {
			close(clifd);
			free(pbuff);
			break;
		}
		read_len = read(clifd, static_cast<char *>(pbuff) + offset, buff_len - offset);
		if (read_len <= 0) {
			close(clifd);
			free(pbuff);
			break;
		}
		offset += read_len;
		if (offset == buff_len)
			break;
	}
	/*
	 * Interrupt the read loop and, if the entire buffer has not
	 * been read, we go back to waiting.
	 */
	if (offset != buff_len)
		continue;

	common_util_build_environment();
	tmp_bin.pv = pbuff;
	tmp_bin.cb = buff_len;
	std::unique_ptr<zcreq> request;
	if (rpc_ext_pull_request(&tmp_bin, request) != pack_result::ok) {
		free(pbuff);
		common_util_free_environment();
		auto tmp_byte = zcore_response::pull_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd, &tmp_byte, 1) < 1)
				/* ignore */;
		close(clifd);
		continue;
	}
	free(pbuff);
	if (request->call_id == zcore_callid::notifdequeue)
		common_util_set_clifd(clifd);
	std::unique_ptr<zcresp> response;
	switch (rpc_parser_dispatch(request.get(), response)) {
	case DISPATCH_FALSE: {
		common_util_free_environment();
		auto tmp_byte = zcore_response::dispatch_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd, &tmp_byte, 1) < 1)
				/* ignore */;
		close(clifd);
		continue;
	}
	case DISPATCH_CONTINUE:
		common_util_free_environment();
		// Connection stays active, handled elsewhere
		continue;
	}
	if (rpc_ext_push_response(response.get(), &tmp_bin) != pack_result::ok) {
		common_util_free_environment();
		auto tmp_byte = zcore_response::push_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
			if (write(clifd, &tmp_byte, 1) < 1)
				/* ignore */;
		close(clifd);
		continue;
	}
	common_util_free_environment();
	fdpoll.events = POLLOUT|POLLWRBAND;
	if (poll(&fdpoll, 1, SOCKET_TIMEOUT_MS) == 1)
		if (write(clifd, tmp_bin.pb, tmp_bin.cb) < 0)
			/* ignore */;
	shutdown(clifd, SHUT_WR);
	uint8_t tmp_byte;
	if (read(clifd, &tmp_byte, 1))
		/* ignore */;
	close(clifd);
	free(tmp_bin.pb);
	tmp_bin.pb = nullptr;
	}
	return nullptr;
}

int rpc_parser_run()
{
	g_zrpc_stop = false;
	int ret = 0;
	for (unsigned int i = 0; i < g_thread_num; ++i) {
		pthread_t tid;
		ret = pthread_create4(&tid, nullptr, zcrp_thrwork, nullptr);
		if (ret != 0) {
			mlog(LV_ERR, "rpc_parser: failed to create pool thread: %s", strerror(ret));
			rpc_parser_stop();
			return -2;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "rpc/%u", i);
		pthread_setname_np(tid, buf);
		g_thread_ids.push_back(tid);
	}
	return 0;
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
}
