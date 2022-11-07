// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#include <gromox/zcore_rpc.hpp>
#include "common_util.h"
#include "rpc_ext.h"
#include "rpc_parser.hpp"
#include "zarafa_server.h"

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
static gromox::atomic_bool g_notify_stop;
static std::vector<pthread_t> g_thread_ids;
static DOUBLE_LIST g_conn_list;
static std::condition_variable g_waken_cond;
static std::mutex g_conn_lock, g_cond_mutex;
unsigned int g_zrpc_debug;

void rpc_parser_init(unsigned int thread_num)
{
	g_notify_stop = true;
	g_thread_num = thread_num;
	g_thread_ids.reserve(thread_num);
}

BOOL rpc_parser_activate_connection(int clifd)
{
	auto pclient = gromox::me_alloc<CLIENT_NODE>();
	if (NULL == pclient) {
		return FALSE;
	}
	pclient->node.pdata = pclient;
	pclient->clifd = clifd;
	std::unique_lock cl_hold(g_conn_lock);
	double_list_append_as_tail(&g_conn_list, &pclient->node);
	cl_hold.unlock();
	g_waken_cond.notify_one();
	return TRUE;
}

static int rpc_parser_dispatch(const zcreq *q0, zcresp *&r0)
{
	switch (q0->call_id) {
#include <zrpc_dispatch.cpp>
	default:
		mlog(LV_ERR, "E-2046: unknown zrpc request type %u",
		        static_cast<unsigned int>(r0->call_id));
		return DISPATCH_FALSE;
	}
	if (q0->call_id == zcore_callid::notifdequeue && r0->result == ecNotFound)
		return DISPATCH_CONTINUE;
	r0->call_id = q0->call_id;
	if (g_zrpc_debug == 0)
		return DISPATCH_TRUE;
	if (r0->result != 0 || g_zrpc_debug == 2)
		fprintf(stderr, "ZRPC %s %8xh %s\n",
		        r0->result == 0 ? "ok  " : "FAIL",
		        r0->result,
		        zcore_rpc_idtoname(q0->call_id));
	return DISPATCH_TRUE;
}

static void *zcrp_thrwork(void *param)
{
	void *pbuff;
	int tv_msec;
	int read_len;
	BINARY tmp_bin;
	uint32_t offset;
	uint32_t buff_len;
	struct pollfd fdpoll;
	DOUBLE_LIST_NODE *pnode;

 WAIT_CLIFD:
	std::unique_lock cm_hold(g_cond_mutex);
	g_waken_cond.wait(cm_hold);
	cm_hold.unlock();
 NEXT_CLIFD:
	std::unique_lock cl_hold(g_conn_lock);
	pnode = double_list_pop_front(&g_conn_list);
	cl_hold.unlock();
	if (NULL == pnode) {
		if (g_notify_stop)
			return nullptr;
		goto WAIT_CLIFD;
	}
	auto clifd = static_cast<CLIENT_NODE *>(pnode->pdata)->clifd;
	free(pnode->pdata);
	
	offset = 0;
	buff_len = 0;
	
	tv_msec = SOCKET_TIMEOUT * 1000;
	fdpoll.fd = clifd;
	fdpoll.events = POLLIN|POLLPRI;
	if (1 != poll(&fdpoll, 1, tv_msec)) {
		close(clifd);
		goto NEXT_CLIFD;
	}
	read_len = read(clifd, &buff_len, sizeof(uint32_t));
	if (read_len != sizeof(uint32_t)) {
		close(clifd);
		goto NEXT_CLIFD;
	}
	pbuff = malloc(buff_len);
	if (NULL == pbuff) {
		auto tmp_byte = zcore_response::lack_memory;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	while (true) {
		if (1 != poll(&fdpoll, 1, tv_msec)) {
			close(clifd);
			free(pbuff);
			goto NEXT_CLIFD;
		}
		read_len = read(clifd, static_cast<char *>(pbuff) + offset, buff_len - offset);
		if (read_len <= 0) {
			close(clifd);
			free(pbuff);
			goto NEXT_CLIFD;
		}
		offset += read_len;
		if (offset == buff_len) {
			break;
		}
	}
	common_util_build_environment();
	tmp_bin.pv = pbuff;
	tmp_bin.cb = buff_len;
	zcreq *request = nullptr;
	if (!rpc_ext_pull_request(&tmp_bin, request)) {
		free(pbuff);
		common_util_free_environment();
		auto tmp_byte = zcore_response::pull_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	free(pbuff);
	if (request->call_id == zcore_callid::notifdequeue)
		common_util_set_clifd(clifd);
	zcresp *response = nullptr;
	switch (rpc_parser_dispatch(request, response)) {
	case DISPATCH_FALSE: {
		common_util_free_environment();
		auto tmp_byte = zcore_response::dispatch_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	case DISPATCH_CONTINUE:
		common_util_free_environment();
		/* clifd will be maintained by zarafa_server */
		goto NEXT_CLIFD;
	}
	if (!rpc_ext_push_response(response, &tmp_bin)) {
		common_util_free_environment();
		auto tmp_byte = zcore_response::push_error;
		fdpoll.events = POLLOUT|POLLWRBAND;
		if (1 == poll(&fdpoll, 1, tv_msec)) {
			write(clifd, &tmp_byte, 1);
		}
		close(clifd);
		goto NEXT_CLIFD;
	}
	common_util_free_environment();
	fdpoll.events = POLLOUT|POLLWRBAND;
	if (1 == poll(&fdpoll, 1, tv_msec)) {
		write(clifd, tmp_bin.pb, tmp_bin.cb);
	}
	shutdown(clifd, SHUT_WR);
	uint8_t tmp_byte;
	if (read(clifd, &tmp_byte, 1))
		/* ignore */;
	close(clifd);
	free(tmp_bin.pb);
	tmp_bin.pb = nullptr;
	goto NEXT_CLIFD;
}

int rpc_parser_run()
{
	g_notify_stop = false;
	int ret = 0;
	for (unsigned int i = 0; i < g_thread_num; ++i) {
		pthread_t tid;
		ret = pthread_create(&tid, nullptr, zcrp_thrwork, nullptr);
		if (ret != 0) {
			printf("[rpc_parser]: failed to create pool thread: %s\n", strerror(ret));
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
	g_notify_stop = true;
	g_waken_cond.notify_all();
	for (auto tid : g_thread_ids) {
		pthread_kill(tid, SIGALRM);
		pthread_join(tid, nullptr);
	}
	g_thread_ids.clear();
}
