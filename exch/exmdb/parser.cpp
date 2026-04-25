// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <utility>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <libHX/io.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_ext.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/list_file.hpp>
#include <gromox/listener_ctx.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "notification_agent.hpp"
#include "parser.hpp"
#ifndef AI_V4MAPPED
#	define AI_V4MAPPED 0
#endif

using namespace gromox;

struct parser_params {
	std::shared_ptr<EXMDB_CONNECTION> conn;
	bool is_connected = false, b_private = false;
};

static size_t g_max_threads, g_max_routers;
static std::unordered_set<std::shared_ptr<ROUTER_CONNECTION>> g_router_list;
/* used for counting and for setting c->b_stop on exit from main thread */
static std::unordered_set<std::shared_ptr<EXMDB_CONNECTION>> g_connection_list;
static std::mutex g_router_lock, g_connection_lock;
static gromox::atomic_bool g_exmdblisten_stop;
static std::vector<std::string> g_acl_list;
static listener_ctx exmdb_listen_ctx;
std::atomic<unsigned int> g_enable_dam;
std::string g_host_id;

ROUTER_CONNECTION::~ROUTER_CONNECTION()
{
	if (sockd >= 0)
		close(sockd);
	for (auto &&bin : datagram_list)
		free(bin.pb);
}

void exmdb_parser_init(size_t max_threads, size_t max_routers)
{
	g_max_threads = max_threads;
	g_max_routers = max_routers;
}

static std::shared_ptr<EXMDB_CONNECTION> exmdb_parser_make_conn()
{
	if (g_max_threads != 0) {
		std::lock_guard lk(g_connection_lock);
		if (g_connection_list.size() >= g_max_threads)
			return nullptr;
	}
	try {
		return std::make_shared<EXMDB_CONNECTION>();
	} catch (const std::bad_alloc &) {
	}
	return nullptr;
}

/**
 * Indicate whether this machine is responsible for serving a mailbox
 *
 * @prefix:  a mailbox directory
 * @pvt:     returns whether the directory refers to a private or public store
 */
static bool exmdb_parser_is_local(const char *prefix, bool *pvt)
{
	if (*prefix == '\0')
		return true;
	std::string hostname;
	auto err = mysql_adaptor_get_homeserver_for_dir(prefix, pvt, hostname);
	if (err == ENOENT)
		return false;
	if (err != 0) {
		mlog(LV_ERR, "%s: %s: %s", __func__, prefix, strerror(err));
		return false;
	}
	if (hostname == g_host_id || hostname.empty())
		return true;
	mlog(LV_ERR, "exmdb: is_local: %s not served here (%s) (but by %s)",
		prefix, g_host_id.c_str(), hostname.c_str());
	return false;
}

static BOOL exmdb_parser_dispatch3(const exreq *q0, std::unique_ptr<exresp> &r0)
{
	switch (q0->call_id) {
#include <exmdb_dispatch.cpp>
	default:
		return FALSE;
	}
}

static BOOL exmdb_parser_dispatch2(const exreq *prequest, std::unique_ptr<exresp> &r0) try
{
	/*
	 * Special handling for a few RPCs in lieu of the default code provided
	 * for these callids in dispatch3.
	 */
	switch (prequest->call_id) {
	case exmdb_callid::get_content_sync: {
		auto &q = *static_cast<const exreq_get_content_sync *>(prequest);
		auto r1 = std::make_unique<exresp_get_content_sync>();
		auto &r = *r1;
		auto b_return = exmdb_server::get_content_sync(prequest->dir,
		           q.folder_id, q.username, q.pgiven, q.pseen,
		           q.pseen_fai, q.pread, q.cpid, q.prestriction,
		           q.b_ordered, &r.fai_count, &r.fai_total,
		           &r.normal_count, &r.normal_total, &r.updated_mids,
		           &r.chg_mids, &r.last_cn, &r.given_mids,
		           &r.deleted_mids, &r.nolonger_mids, &r.read_mids,
		           &r.unread_mids, &r.last_readcn);
		delete q.pgiven;
		delete q.pseen;
		delete q.pseen_fai;
		delete q.pread;
		r0 = std::move(r1);
		return b_return;
	}
	case exmdb_callid::get_hierarchy_sync: {
		auto &q = *static_cast<const exreq_get_hierarchy_sync *>(prequest);
		auto r1 = std::make_unique<exresp_get_hierarchy_sync>();
		auto &r = *r1;
		auto b_return = exmdb_server::get_hierarchy_sync(prequest->dir,
		           q.folder_id, q.username, q.pgiven, q.pseen,
		           &r.fldchgs, &r.last_cn, &r.given_fids,
		           &r.deleted_fids);
		delete q.pgiven;
		delete q.pseen;
		r0 = std::move(r1);
		return b_return;
	}
	default:
		return exmdb_parser_dispatch3(prequest, r0);
	}
} catch (const std::bad_alloc &) {
	return false;
}

static BOOL exmdb_parser_dispatch(const exreq *prequest, std::unique_ptr<exresp> &presponse)
{
	auto tstart = tp_now();
	exmdb_server::set_dir(prequest->dir);
	auto ret = exmdb_parser_dispatch2(prequest, presponse);
	if (ret)
		presponse->call_id = prequest->call_id;
	auto dbg = g_exrpc_debug.load();
	if (dbg == 0)
		return ret;
	auto tend = tp_now();
	if (!ret || dbg == 2)
		mlog(LV_DEBUG, "EXRPC %s %s %5luµs %s", znul(prequest->dir),
		        ret == 0 ? "ERR" : "ok ",
		        static_cast<unsigned long>(std::chrono::duration_cast<std::chrono::microseconds>(tend - tstart).count()),
		        exmdb_rpc_idtoname(prequest->call_id));
	return ret;
}

static inline void stripslash(char *s)
{
	for (auto z = strlen(s); z > 1 && s[z-1] == '/'; --z)
		s[z-1] = '\0';
}

static bool max_routers_reached()
{
	std::unique_lock r_hold(g_router_lock);
	return g_router_list.size() >= g_max_routers;
}

static int rqi_terminate(EXMDB_CONNECTION &conn, exmdb_response resp_code)
{
	if (HXio_fullwrite(conn.sockd, &resp_code, 1) != 1)
		/* ignore */;
	return -1;
}

static int rqi_connect(parser_params &param, const exreq_connect &q,
    BINARY &output_buf)
{
	auto &conn = *param.conn;

	if (!exmdb_parser_is_local(q.dir, &param.b_private))
		return rqi_terminate(conn, exmdb_response::misconfig_prefix);
	else if (!!param.b_private != !!q.b_private)
		return rqi_terminate(conn, exmdb_response::misconfig_mode);

	conn.remote_id = q.remote_id;
	exmdb_server::set_remote_id(conn.remote_id.c_str());
	param.is_connected = true;
	free(output_buf.pb);
	output_buf.pb = static_cast<uint8_t *>(calloc(1, 5));
	if (output_buf.pb == nullptr)
		return rqi_terminate(conn, exmdb_response::lack_memory);
	output_buf.pb[0] = static_cast<uint8_t>(exmdb_response::success);
	output_buf.cb = 5;
	return 0;
}

static int rqi_listen(parser_params &param, const exreq_listen_notification &q) try
{
	auto &conn = *param.conn;
	if (g_max_routers != 0 && max_routers_reached())
		return rqi_terminate(conn, exmdb_response::max_reached);

	auto router = std::make_shared<ROUTER_CONNECTION>();
	router->remote_id = q.remote_id;
	static constexpr char success[5]{};
	auto wrret = write(conn.sockd, success, std::size(success));
	if (wrret < 0 || static_cast<size_t>(wrret) != std::size(success))
		return -1; /* OS error */
	router->thr_id = std::move(conn.thr_id);
	router->sockd  = std::move(conn.sockd);
	conn.thr_id = {};
	conn.sockd = -1;
	router->last_time = time(nullptr);
	{
		std::unique_lock r_hold(g_router_lock);
		g_router_list.insert(router);
	}
	{
		std::unique_lock chold(g_connection_lock);
		g_connection_list.erase(param.conn);
	}
	/*
	 * This function runs practically forever;
	 * thus we close the connection when that is all done.
	 */
	return notification_agent_thread_work(std::move(router));
} catch (const std::bad_alloc &) {
	return rqi_terminate(*param.conn, exmdb_response::lack_memory);
}

static int rqi_unconnected(parser_params &param, const exreq &request,
    BINARY &output_buf)
{
	switch (request.call_id) {
	case exmdb_callid::connect:
		return rqi_connect(param, static_cast<const exreq_connect &>(request),
		       output_buf);
	case exmdb_callid::listen_notification:
		return rqi_listen(param, static_cast<const exreq_listen_notification &>(request));
	default:
		return rqi_terminate(*param.conn, exmdb_response::connect_incomplete);
	}
}

/**
 * On success, sets output_buf to something to send to the network and returns
 * 0. On error when the connection should be immediately closed, -1 is
 * returned. (In the error case, writing the error packet to the network is
 * done by rqp_io itself.)
 */
static int rqi_handle_buffer(parser_params &param, std::string_view input_buf,
    BINARY &output_buf)
{
	auto &conn = *param.conn;
	exmdb_server::build_env(param.b_private ? EM_PRIVATE : 0, nullptr);
	auto cl_env = HX::make_scope_exit(exmdb_server::free_env);

	std::unique_ptr<exreq> request;
	auto status = exmdb_ext_pull_request(input_buf, request);
	if (status != pack_result::ok)
		return rqi_terminate(conn, exmdb_response::pull_error);
	if (request == nullptr)
		return rqi_terminate(conn, exmdb_response::lack_memory);
	if (request->dir != nullptr)
		stripslash(request->dir);

	std::unique_ptr<exresp> response;
	if (!param.is_connected)
		return rqi_unconnected(param, *request, output_buf);
	if (!exmdb_parser_dispatch(request.get(), response))
		return rqi_terminate(conn, exmdb_response::dispatch_error);
	if (exmdb_ext_push_response(response.get(), &output_buf) != pack_result::success)
		return rqi_terminate(conn, exmdb_response::push_error);
	return 0;
}

static void *request_parser_thread(void *pparam)
{
	uint8_t resp_buff[5]{};
	struct pollfd pfd_read;
	
	std::unique_ptr<parser_params> param(static_cast<parser_params *>(pparam));
	auto &pconnection = param->conn;
	try {
		char txt[16];
		snprintf(txt, std::size(txt), "exrq/%hu", pconnection->client_port);
		pthread_setname_np(pthread_self(), txt);
		std::unique_lock chold(g_connection_lock);
		g_connection_list.insert(pconnection);
	} catch (...) {
		return nullptr;
	}
	size_t offset = 0;
	bool is_writing = false, is_connected = false;
	BINARY output_buf{};
	auto cl_0 = HX::make_scope_exit([&]() { free(output_buf.pb); });
	std::string input_buf;

	while (!pconnection->b_stop) {
		if (is_writing) {
			auto wlen = write(pconnection->sockd, &output_buf.pb[offset],
			            output_buf.cb - offset);
			if (wlen <= 0)
				break;
			offset += wlen;
			if (offset < output_buf.cb)
				continue; /* keep writing if necessary */
			free(output_buf.pb);
			output_buf.pb = nullptr;
			output_buf.cb = 0;
			offset = 0;
			is_writing = false;
			continue;
		}
		pfd_read.fd = pconnection->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1)
			break;
		if (input_buf.empty()) {
			uint32_t buff_len = 0;
			auto read_len = read(pconnection->sockd,
					&buff_len, sizeof(uint32_t));
			if (read_len != sizeof(uint32_t))
				break;
			/* ping packet */
			if (0 == buff_len) {
				if (HXio_fullwrite(pconnection->sockd, resp_buff, 1) != 1)
					break;
				continue;
			} else if (buff_len >= UINT_MAX) {
				/* make cov-scan happy that we tested for buff_len */
				break;
			}
			try {
				input_buf.resize(buff_len);
			} catch (const std::bad_alloc &) {
				auto tmp_byte = exmdb_response::lack_memory;
				if (HXio_fullwrite(pconnection->sockd, &tmp_byte, 1) != 1 ||
				    !is_connected)
					break;
			}
			offset = 0;
			continue;
		}
		auto read_len = read(pconnection->sockd, &input_buf[offset],
		                input_buf.size() - offset);
		if (read_len <= 0)
			break;
		offset += read_len;
		if (offset < input_buf.size())
			continue; /* keep reading as necessary */
		if (rqi_handle_buffer(*param, input_buf, output_buf) < 0)
			break;
		input_buf.clear();
		offset = 0;
		is_writing = true;
	}
	if (pconnection->sockd >= 0) {
		close(pconnection->sockd);
		pconnection->sockd = -1;
	}
	if (!pconnection->b_stop) {
		pconnection->thr_id = {};
		pthread_detach(pthread_self());
	}
	return nullptr;
}

bool exmdb_parser_insert_conn(generic_connection &&co) try
{
	auto par = std::make_unique<parser_params>();
	par->conn = exmdb_parser_make_conn();
	if (par->conn == nullptr)
		return false;
	static_cast<generic_connection &>(*par->conn) = std::move(co);

	auto ret = pthread_create4(&par->conn->thr_id, nullptr,
	           request_parser_thread, par.get());
	if (ret != 0) {
		mlog(LV_WARN, "W-1440: pthread_create: %s", strerror(ret));
		return false;
	} else {
		par.release(); /* thread should be vivid now */
		return true;
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

std::shared_ptr<ROUTER_CONNECTION> exmdb_parser_extract_router(const char *remote_id)
{
	std::lock_guard rhold(g_router_lock);
	auto it = std::find_if(g_router_list.begin(), g_router_list.end(),
	          [&](const auto &r) { return r->remote_id == remote_id; });
	if (it == g_router_list.end())
		return nullptr;
	auto rt = *it;
	g_router_list.erase(it);
	return rt;
}

void exmdb_parser_insert_router(std::shared_ptr<ROUTER_CONNECTION> &&pconnection)
{
	std::lock_guard rhold(g_router_lock);
	try {
		g_router_list.insert(std::move(pconnection));
	} catch (const std::bad_alloc &) {
	}
}

BOOL exmdb_parser_erase_router(const std::shared_ptr<ROUTER_CONNECTION> &pconnection)
{
	std::lock_guard rhold(g_router_lock);
	auto it = g_router_list.find(pconnection);
	if (it == g_router_list.cend())
		return false;
	g_router_list.erase(it);
	return TRUE;
}

void exmdb_parser_stop()
{
	std::vector<pthread_t> pthr_ids;
	
	std::unique_lock chold(g_connection_lock);
	size_t num = g_connection_list.size();
	pthr_ids.reserve(num);
	if (num > 0) {
	for (auto &pconnection : g_connection_list) {
		pconnection->b_stop = true;
		if (pconnection->sockd >= 0)
			shutdown(pconnection->sockd, SHUT_RDWR); /* closed in ~EXMDB_CONNECTION */
		if (!pthread_equal(pconnection->thr_id, {})) {
			pthr_ids.push_back(pconnection->thr_id);
			pthread_kill(pconnection->thr_id, SIGALRM);
		}
	}
	chold.unlock();
		for (auto tid : pthr_ids)
			pthread_join(tid, nullptr);
	}
	std::unique_lock rhold(g_router_lock);
	num = g_router_list.size();
	pthr_ids.clear();
	pthr_ids.reserve(num);
	if (num > 0) {
	for (auto &rt : g_router_list) {
		rt->b_stop = true;
		rt->waken_cond.notify_one();
		if (!pthread_equal(rt->thr_id, {})) {
			pthr_ids.emplace_back(rt->thr_id);
			pthread_kill(rt->thr_id, SIGALRM);
		}
	}
	rhold.unlock();
		for (auto tid : pthr_ids)
			pthread_join(tid, nullptr);
	}
}

static int sockaccept_thread(generic_connection &&conn)
{
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    conn.client_addr) == g_acl_list.cend()) {
			static std::atomic<time_t> g_lastwarn_time;
			auto prev = g_lastwarn_time.load();
			auto next = prev + 60;
			auto now = time(nullptr);
			if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
				mlog(LV_INFO, "I-1666: Rejecting %s: not allowed by exmdb_acl", conn.client_addr);
			auto tmp_byte = exmdb_response::access_deny;
			if (HXio_fullwrite(conn.sockd, &tmp_byte, 1) != 1)
				/* ignore */;
			return 0;
		}
		if (!exmdb_parser_insert_conn(std::move(conn))) {
			auto tmp_byte = exmdb_response::max_reached;
			if (HXio_fullwrite(conn.sockd, &tmp_byte, 1) != 1)
				/* ignore */;
			return 0;
		}

	return 0;
}

static int exmdb_acl_read(const char *config_path, const char *hosts_allow)
{
	auto &acl = g_acl_list;
	if (hosts_allow != nullptr)
		acl = gx_split(hosts_allow, ' ');
	auto ret = read_file_by_line("exmdb_acl.txt", config_path, acl);
	if (ret == ENOENT) {
	} else if (ret != 0) {
		mlog(LV_ERR, "exmdb_provider: Failed to read ACLs from exmdb_acl.txt: %s", strerror(errno));
		return -5;
	}
	std::sort(acl.begin(), acl.end());
	std::erase(acl, "");
	acl.erase(std::unique(acl.begin(), acl.end()), acl.end());
	if (acl.size() == 0) {
		mlog(LV_NOTICE, "exmdb_provider: defaulting to implicit access ACL containing ::1.");
		acl = {"::1"};
	}
	return 0;
}

int exmdb_listener_init(const config_file &gxcfg, const config_file &oldcfg)
{
	auto &ctx = exmdb_listen_ctx;
	ctx.m_thread_name = "exmdb_accept";
	auto line = gxcfg.get_value("exmdb_listen");
	if (line != nullptr)
		return ctx.add_bunch(line);
	auto host = oldcfg.get_value("listen_ip");
	if (host != nullptr)
		mlog(LV_NOTICE, "%s:listen_ip is deprecated in favor of %s:exmdb_listen",
			oldcfg.m_filename.c_str(), gxcfg.m_filename.c_str());
	else
		host = "::1";
	auto ps = oldcfg.get_value("exmdb_listen_port");
	uint16_t port = 5000;
	if (ps != nullptr) {
		mlog(LV_NOTICE, "%s:exmdb_listen_port is deprecated in favor of %s:exmdb_listen",
			oldcfg.m_filename.c_str(), gxcfg.m_filename.c_str());
		port = strtoul(znul(ps), nullptr, 0);
	}
	if (port != 0 && ctx.add_inet(host, port) != 0)
		return -1;
	return 0;
}

int exmdb_listener_run(const char *config_path, const config_file &oldcfg)
{
	auto ret = exmdb_acl_read(config_path, oldcfg.get_value("exmdb_hosts_allow"));
	if (ret != 0)
		return ret;
	if (exmdb_listen_ctx.empty())
		return 0;
	g_exmdblisten_stop = false;
	auto err = exmdb_listen_ctx.watch_start(g_exmdblisten_stop, sockaccept_thread);
	if (err != 0) {
		mlog(LV_ERR, "exmdb_provider: failed to create exmdb listener thread: %s", strerror(err));
		return -1;
	}
	return 0;
}

void exmdb_listener_stop()
{
	g_exmdblisten_stop = true;
	exmdb_listen_ctx.reset();
}
