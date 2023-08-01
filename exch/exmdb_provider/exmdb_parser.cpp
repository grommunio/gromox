// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cassert>
#include <cerrno>
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
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <libHX/socket.h>
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_ext.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#include "exmdb_parser.h"
#include "notification_agent.h"
#ifndef AI_V4MAPPED
#	define AI_V4MAPPED 0
#endif

using namespace gromox;

static size_t g_max_threads, g_max_routers;
static std::vector<EXMDB_ITEM> g_local_list;
static std::unordered_set<std::shared_ptr<ROUTER_CONNECTION>> g_router_list;
static std::unordered_set<std::shared_ptr<EXMDB_CONNECTION>> g_connection_list;
static std::mutex g_router_lock, g_connection_lock;
unsigned int g_exrpc_debug, g_enable_dam;

EXMDB_CONNECTION::~EXMDB_CONNECTION()
{
	if (sockd >= 0)
		close(sockd);
}

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

std::shared_ptr<EXMDB_CONNECTION> exmdb_parser_get_connection()
{
	if (g_max_threads != 0 && g_connection_list.size() >= g_max_threads)
		return nullptr;
	try {
		return std::make_shared<EXMDB_CONNECTION>();
	} catch (const std::bad_alloc &) {
	}
	return nullptr;
}

static BOOL exmdb_parser_check_local(const char *prefix, BOOL *pb_private)
{
	auto i = std::find_if(g_local_list.cbegin(), g_local_list.cend(),
	         [&](const EXMDB_ITEM &s) { return strncmp(s.prefix.c_str(), prefix, s.prefix.size()) == 0; });
	if (i == g_local_list.cend())
		return false;
	*pb_private = i->type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false;
	return TRUE;
}

static BOOL exmdb_parser_dispatch3(const exreq *q0, exresp *&r0)
{
	switch (q0->call_id) {
#include <exmdb_dispatch.cpp>
	default:
		return FALSE;
	}
}

static BOOL exmdb_parser_dispatch2(const exreq *prequest, exresp *&r0)
{
	/*
	 * Special handling for a few RPCs in lieu of the default code provided
	 * for these callids in dispatch3.
	 */
	switch (prequest->call_id) {
	case exmdb_callid::get_content_sync: {
		auto &q = *static_cast<const exreq_get_content_sync *>(prequest);
		auto r1 = cu_alloc<exresp_get_content_sync>();
		r0 = r1;
		if (r1 == nullptr)
			return false;
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
		return b_return;
	}
	case exmdb_callid::get_hierarchy_sync: {
		auto &q = *static_cast<const exreq_get_hierarchy_sync *>(prequest);
		auto r1 = cu_alloc<exresp_get_hierarchy_sync>();
		r0 = r1;
		if (r1 == nullptr)
			return false;
		auto &r = *r1;
		auto b_return = exmdb_server::get_hierarchy_sync(prequest->dir,
		           q.folder_id, q.username, q.pgiven, q.pseen,
		           &r.fldchgs, &r.last_cn, &r.given_fids,
		           &r.deleted_fids);
		delete q.pgiven;
		delete q.pseen;
		return b_return;
	}
	default:
		return exmdb_parser_dispatch3(prequest, r0);
	}
}

static BOOL exmdb_parser_dispatch(const exreq *prequest, exresp *&presponse)
{
	if (access(prequest->dir, R_OK | X_OK) < 0)
		mlog(LV_DEBUG, "exmdb rpc %s accessing %s: %s",
			exmdb_rpc_idtoname(prequest->call_id),
		       prequest->dir, strerror(errno));
	exmdb_server::set_dir(prequest->dir);
	auto ret = exmdb_parser_dispatch2(prequest, presponse);
	if (ret)
		presponse->call_id = prequest->call_id;
	if (g_exrpc_debug == 0)
		return ret;
	if (!ret || g_exrpc_debug == 2)
		mlog(LV_DEBUG, "EXRPC %s %s (%s)",
		        ret == 0 ? "FAIL" : "ok  ",
		        exmdb_rpc_idtoname(prequest->call_id),
		        znul(prequest->dir));
	return ret;
}

static void *mdpps_thrwork(void *pparam)
{
	int tv_msec;
	void *pbuff;
	int read_len;
	BOOL b_private;
	BINARY tmp_bin;
	uint32_t offset;
	int written_len;
	BOOL is_writing;
	BOOL is_connected;
	uint32_t buff_len;
	uint8_t resp_buff[5]{};
	struct pollfd pfd_read;
	
	b_private = FALSE; /* whatever for connect request */
	/* unordered_set currently owns it, now take another ref */
	auto pconnection = static_cast<EXMDB_CONNECTION *>(pparam)->shared_from_this();
	pthread_setname_np(pconnection->thr_id, "exmdb_parser");
	pbuff = NULL;
	offset = 0;
	buff_len = 0;
	is_writing = FALSE;
	is_connected = FALSE;
	while (!pconnection->b_stop) {
		if (is_writing) {
			written_len = write(pconnection->sockd,
			              static_cast<char *>(pbuff) + offset, buff_len - offset);
			if (written_len <= 0) {
				break;
			}
			offset += written_len;
			if (offset == buff_len) {
				free(pbuff);
				pbuff = NULL;
				buff_len = 0;
				offset = 0;
				is_writing = FALSE;
			}
			continue;
		}
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pconnection->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			break;
		}
		if (NULL == pbuff) {
			read_len = read(pconnection->sockd,
					&buff_len, sizeof(uint32_t));
			if (read_len != sizeof(uint32_t)) {
				break;
			}
			/* ping packet */
			if (0 == buff_len) {
				if (1 != write(pconnection->sockd, resp_buff, 1)) {
					break;
				}
				continue;
			}
			pbuff = malloc(buff_len);
			if (NULL == pbuff) {
				auto tmp_byte = exmdb_response::lack_memory;
				write(pconnection->sockd, &tmp_byte, 1);
				if (!is_connected)
					break;
				buff_len = 0;
			}
			offset = 0;
			continue;
		}
		read_len = read(pconnection->sockd,
		           static_cast<char *>(pbuff) + offset, buff_len - offset);
		if (read_len <= 0) {
			break;
		}
		offset += read_len;
		if (offset < buff_len) {
			continue;
		}
		exmdb_server::build_env(b_private ? EM_PRIVATE : 0, nullptr);
		tmp_bin.pv = pbuff;
		tmp_bin.cb = buff_len;
		exreq *request = nullptr;
		auto status = exmdb_ext_pull_request(&tmp_bin, request);
		free(pbuff);
		pbuff = NULL;
		exmdb_response tmp_byte;
		exresp *response = nullptr;
		if (EXT_ERR_SUCCESS != status) {
			tmp_byte = exmdb_response::pull_error;
		} else if (!is_connected) {
			if (request->call_id == exmdb_callid::connect) {
				auto &q = *static_cast<const exreq_connect *>(request);
				if (!exmdb_parser_check_local(q.prefix, &b_private)) {
					tmp_byte = exmdb_response::misconfig_prefix;
				} else if (b_private != q.b_private) {
					tmp_byte = exmdb_response::misconfig_mode;
				} else {
					pconnection->remote_id = q.remote_id;
					exmdb_server::free_env();
					exmdb_server::set_remote_id(pconnection->remote_id.c_str());
					is_connected = TRUE;
					if (5 != write(pconnection->sockd, resp_buff, 5)) {
						break;
					}
					offset = 0;
					buff_len = 0;
					continue;
				}
			} else if (request->call_id == exmdb_callid::listen_notification) {
				auto &q = *static_cast<const exreq_listen_notification *>(request);
				std::shared_ptr<ROUTER_CONNECTION> prouter;
				try {
					prouter = std::make_shared<ROUTER_CONNECTION>();
					prouter->remote_id.reserve(strlen(q.remote_id));
				} catch (const std::bad_alloc &) {
				}
				if (NULL == prouter) {
					tmp_byte = exmdb_response::lack_memory;
				} else if (g_max_routers != 0 && g_router_list.size() >= g_max_routers) {
					tmp_byte = exmdb_response::max_reached;
				} else {
					prouter->remote_id = q.remote_id;
					exmdb_server::free_env();
					if (5 != write(pconnection->sockd, resp_buff, 5)) {
						break;
					} else {
						prouter->thr_id = pconnection->thr_id;
						prouter->sockd = pconnection->sockd;
						pconnection->thr_id = {};
						pconnection->sockd = -1;
						prouter->last_time = time(nullptr);
						std::unique_lock r_hold(g_router_lock);
						g_router_list.insert(prouter);
						r_hold.unlock();
						std::unique_lock chold(g_connection_lock);
						g_connection_list.erase(pconnection);
						chold.unlock();
						notification_agent_thread_work(std::move(prouter));
					}
				}
			} else {
				tmp_byte = exmdb_response::connect_incomplete;
			}
		} else if (!exmdb_parser_dispatch(request, response)) {
			tmp_byte = exmdb_response::dispatch_error;
		} else if (EXT_ERR_SUCCESS != exmdb_ext_push_response(response, &tmp_bin)) {
			tmp_byte = exmdb_response::push_error;
		} else {
			exmdb_server::free_env();
			offset = 0;
			pbuff = tmp_bin.pb;
			buff_len = tmp_bin.cb;
			is_writing = TRUE;
			continue;
		}
		exmdb_server::free_env();
		write(pconnection->sockd, &tmp_byte, 1);
		break;
	}
	close(pconnection->sockd);
	pconnection->sockd = -1;
	if (NULL != pbuff) {
		free(pbuff);
	}
	if (!pconnection->b_stop) {
		pconnection->thr_id = {};
		pthread_detach(pthread_self());
	}
	return nullptr;
}

void exmdb_parser_put_connection(std::shared_ptr<EXMDB_CONNECTION> &&pconnection)
{
	std::unique_lock chold(g_connection_lock);
	auto stpair = g_connection_list.insert(pconnection);
	chold.unlock();
	auto ret = pthread_create4(&pconnection->thr_id, nullptr, mdpps_thrwork, pconnection.get());
	if (ret == 0)
		return;
	mlog(LV_WARN, "W-1440: pthread_create: %s", strerror(ret));
	chold.lock();
	g_connection_list.erase(stpair.first);
}

std::shared_ptr<ROUTER_CONNECTION> exmdb_parser_get_router(const char *remote_id)
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

void exmdb_parser_put_router(std::shared_ptr<ROUTER_CONNECTION> &&pconnection)
{
	std::lock_guard rhold(g_router_lock);
	try {
		g_router_list.insert(std::move(pconnection));
	} catch (const std::bad_alloc &) {
	}
}

BOOL exmdb_parser_remove_router(const std::shared_ptr<ROUTER_CONNECTION> &pconnection)
{
	std::lock_guard rhold(g_router_lock);
	auto it = g_router_list.find(pconnection);
	if (it == g_router_list.cend())
		return false;
	g_router_list.erase(it);
	return TRUE;
}

int exmdb_parser_run(const char *config_path)
{
	auto ret = list_file_read_exmdb("exmdb_list.txt", config_path, g_local_list);
	if (ret != 0) {
		mlog(LV_ERR, "exmdb_provider: list_file_read_exmdb: %s", strerror(ret));
		return 1;
	}
#if __cplusplus >= 202000L
	std::erase_if(g_local_list,
		[&](const EXMDB_ITEM &s) { return !HX_ipaddr_is_local(s.host.c_str(), AI_V4MAPPED); });
#else
	g_local_list.erase(std::remove_if(g_local_list.begin(), g_local_list.end(),
		[&](const EXMDB_ITEM &s) { return !HX_ipaddr_is_local(s.host.c_str(), AI_V4MAPPED); }),
		g_local_list.end());
#endif
	return 0;
}

void exmdb_parser_stop()
{
	size_t i = 0;
	pthread_t *pthr_ids;
	
	pthr_ids = NULL;
	std::unique_lock chold(g_connection_lock);
	size_t num = g_connection_list.size();
	if (num > 0) {
		pthr_ids = gromox::me_alloc<pthread_t>(num);
		if (NULL == pthr_ids) {
			return;
		}
	for (auto &pconnection : g_connection_list) {
		pconnection->b_stop = true;
		if (pconnection->sockd >= 0)
			shutdown(pconnection->sockd, SHUT_RDWR); /* closed in ~EXMDB_CONNECTION */
		if (!pthread_equal(pconnection->thr_id, {})) {
			pthr_ids[i++] = pconnection->thr_id;
			pthread_kill(pconnection->thr_id, SIGALRM);
		}
	}
	chold.unlock();
	num = i;
	for (i=0; i<num; i++) {
		pthread_join(pthr_ids[i], NULL);
	}
		free(pthr_ids);
	}
	std::unique_lock rhold(g_router_lock);
	num = g_router_list.size();
	if (num > 0) {
		pthr_ids = gromox::me_alloc<pthread_t>(num);
		if (NULL == pthr_ids) {
			return;
		}
	i = 0;
	for (auto &rt : g_router_list) {
		rt->b_stop = true;
		rt->waken_cond.notify_one();
		if (!pthread_equal(rt->thr_id, {})) {
			pthr_ids[i++] = rt->thr_id;
			pthread_kill(rt->thr_id, SIGALRM);
		}
	}
	rhold.unlock();
	num = i;
	for (i=0; i<num; i++) {
		pthread_join(pthr_ids[i], NULL);
	}
		free(pthr_ids);
	}
}
