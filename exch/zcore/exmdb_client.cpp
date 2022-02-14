// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <atomic>
#include <cstdint>
#include <list>
#include <mutex>
#include <utility>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include "exmdb_client.h"
#include "common_util.h"
#include "exmdb_ext.h"
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <ctime>
#include <poll.h>

using namespace gromox;

static auto &g_lost_list = mdcl_lost_list;
static auto &g_server_list = mdcl_server_list;
static auto &g_server_lock = mdcl_server_lock;
static auto &g_notify_stop = mdcl_notify_stop;

static void (*exmdb_client_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

static int cl_rd_sock(int fd, BINARY *b) { return exmdb_client_read_socket(fd, b, SOCKET_TIMEOUT * 1000); }

static int exmdb_client_connect_exmdb(REMOTE_SVR *pserver, BOOL b_listen)
{
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	EXMDB_REQUEST request;
	uint8_t response_code;

	int sockd = gx_inet_connect(pserver->host.c_str(), pserver->port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> g_lastwarn_time;
		auto prev = g_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
			fprintf(stderr, "gx_inet_connect exmdb_client@zcore@[%s]:%hu: %s\n",
			        pserver->host.c_str(), pserver->port, strerror(-sockd));
	        return -1;
	}
	process_id = getpid();
	sprintf(remote_id, "zcore:%d", process_id);
	if (!b_listen) {
		request.call_id = exmdb_callid::CONNECT;
		request.payload.connect.prefix = deconst(pserver->prefix.c_str());
		request.payload.connect.remote_id = remote_id;
		request.payload.connect.b_private = pserver->type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false;
	} else {
		request.call_id = exmdb_callid::LISTEN_NOTIFICATION;
		request.payload.listen_notification.remote_id = remote_id;
	}
	if (EXT_ERR_SUCCESS != exmdb_ext_push_request(&request, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	if (!exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return -1;
	}
	free(tmp_bin.pb);
	common_util_build_environment();
	if (!cl_rd_sock(sockd, &tmp_bin)) {
		common_util_free_environment();
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (tmp_bin.cb != 5) {
			common_util_free_environment();
			printf("[exmdb_client]: response format error "
			       "during connect to [%s]:%hu/%s\n",
			       pserver->host.c_str(), pserver->port, pserver->prefix.c_str());
			close(sockd);
			return -1;
		}
		common_util_free_environment();
		return sockd;
	}
	printf("[exmdb_provider]: Failed to connect to [%s]:%hu/%s: %s\n",
	       pserver->host.c_str(), pserver->port, pserver->prefix.c_str(),
	       exmdb_rpc_strerror(response_code));
	common_util_free_environment();
	close(sockd);
	return -1;
}

static void *zccl_scanwork(void *pparam)
{
	int tv_msec;
	time_t now_time;
	uint8_t resp_buff;
	uint32_t ping_buff;
	struct pollfd pfd_read;
	std::list<REMOTE_CONN> temp_list;
	
	ping_buff = 0;
	while (!g_notify_stop) {
		std::unique_lock sv_hold(g_server_lock);
		time(&now_time);
		for (auto &srv : g_server_list) {
			auto tail = srv.conn_list.size() > 0 ? &srv.conn_list.back() : nullptr;
			while (srv.conn_list.size() > 0) {
				auto pconn = &srv.conn_list.front();
				if (now_time - pconn->last_time >= SOCKET_TIMEOUT - 3)
					temp_list.splice(temp_list.end(), srv.conn_list, srv.conn_list.begin());
				else
					srv.conn_list.splice(srv.conn_list.end(), srv.conn_list, srv.conn_list.begin());
				if (pconn == tail)
					break;
			}
		}
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pconn = &temp_list.front();
			if (g_notify_stop) {
				close(pconn->sockd);
				temp_list.pop_front();
				continue;
			}
			if (sizeof(uint32_t) != write(pconn->sockd,
				&ping_buff, sizeof(uint32_t))) {
				close(pconn->sockd);
				pconn->sockd = -1;
				sv_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
				continue;
			}
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pconn->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
				1 != read(pconn->sockd, &resp_buff, 1) ||
			    resp_buff != exmdb_response::SUCCESS) {
				close(pconn->sockd);
				pconn->sockd = -1;
				sv_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			} else {
				time(&pconn->last_time);
				sv_hold.lock();
				pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			}
		}

		sv_hold.lock();
		temp_list = std::move(g_lost_list);
		g_lost_list.clear();
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pconn = &temp_list.front();
			if (g_notify_stop) {
				close(pconn->sockd);
				temp_list.pop_front();
				continue;
			}
			pconn->sockd = exmdb_client_connect_exmdb(pconn->psvr, FALSE);
			if (-1 != pconn->sockd) {
				time(&pconn->last_time);
				sv_hold.lock();
				pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			} else {
				sv_hold.lock();
				g_lost_list.splice(g_lost_list.end(), temp_list, temp_list.begin());
				sv_hold.unlock();
			}
		}
		sleep(1);
	}
	return NULL;
}

static void *zccl_thrwork(void *pparam)
{
	int tv_msec;
	BINARY tmp_bin;
	uint8_t resp_code;
	uint32_t offset = 0, buff_len;
	uint8_t buff[0x8000];
	AGENT_THREAD *pagent;
	struct pollfd pfd_read;
	DB_NOTIFY_DATAGRAM notify;
	
	pagent = (AGENT_THREAD*)pparam;
	while (!g_notify_stop) {
		pagent->sockd = exmdb_client_connect_exmdb(
							pagent->pserver, TRUE);
		if (-1 == pagent->sockd) {
			sleep(1);
			continue;
		}
		buff_len = 0;
		while (true) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pagent->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				close(pagent->sockd);
				pagent->sockd = -1;
				break;
			}
			if (0 == buff_len) {
				if (sizeof(uint32_t) != read(pagent->sockd,
					&buff_len, sizeof(uint32_t))) {
					close(pagent->sockd);
					pagent->sockd = -1;
					break;
				}
				/* ping packet */
				if (0 == buff_len) {
					resp_code = exmdb_response::SUCCESS;
					if (1 != write(pagent->sockd, &resp_code, 1)) {
						close(pagent->sockd);
						pagent->sockd = -1;
						break;
					}
				}
				offset = 0;
				continue;
			}
			auto read_len = read(pagent->sockd, buff + offset, buff_len - offset);
			if (read_len <= 0) {
				close(pagent->sockd);
				pagent->sockd = -1;
				break;
			}
			offset += read_len;
			if (offset == buff_len) {
				tmp_bin.cb = buff_len;
				tmp_bin.pb = buff;
				common_util_build_environment();
				resp_code = exmdb_ext_pull_db_notify(&tmp_bin, &notify) == EXT_ERR_SUCCESS ?
				            exmdb_response::SUCCESS : exmdb_response::PULL_ERROR;
				if (1 != write(pagent->sockd, &resp_code, 1)) {
					close(pagent->sockd);
					pagent->sockd = -1;
					common_util_free_environment();
					break;
				}
				if (resp_code == exmdb_response::SUCCESS) {
					for (size_t i = 0; i < notify.id_array.count; ++i)
						exmdb_client_event_proc(notify.dir,
							notify.b_table, notify.id_array.pl[i],
							&notify.db_notify);
				}
				common_util_free_environment();
				buff_len = 0;
			}
		}
	}
	return nullptr;
}

int exmdb_client_run_front(const char *dir)
{
	return exmdb_client_run(dir, EXMDB_CLIENT_NO_FLAGS,
	       zccl_scanwork, zccl_thrwork);
}

BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid)
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	tmp_propnames.count = 1;
	tmp_propnames.ppropname = (PROPERTY_NAME*)ppropname;
	if (!exmdb_client::get_named_propids(dir,
		b_create, &tmp_propnames, &tmp_propids)) {
		return FALSE;	
	}
	*ppropid = *tmp_propids.ppropid;
	return TRUE;
}

BOOL exmdb_client_get_folder_property(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_folder_properties(
		dir, cpid, folder_id, &tmp_proptags,
		&tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_get_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_message_properties(dir,
		username, cpid, message_id, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_delete_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t folder_id,
	uint64_t message_id, BOOL b_hard, BOOL *pb_done)
{
	BOOL b_partial;
	EID_ARRAY message_ids;
	
	message_ids.count = 1;
	message_ids.pids = &message_id;
	if (!exmdb_client::delete_messages(dir, account_id,
		cpid, NULL, folder_id, &message_ids, b_hard, &b_partial)) {
		return FALSE;	
	}
	*pb_done = !b_partial ? TRUE : false;
	return TRUE;
}

BOOL exmdb_client_get_instance_property(
	const char *dir, uint32_t instance_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_instance_properties(dir,
		0, instance_id, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_set_instance_property(
	const char *dir, uint32_t instance_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (!exmdb_client::set_instance_properties(dir,
		instance_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_instance_property(const char *dir,
	uint32_t instance_id, uint32_t proptag, uint32_t *presult)
{
	PROPTAG_ARRAY tmp_proptags;
	PROBLEM_ARRAY tmp_problems;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::remove_instance_properties(
		dir, instance_id, &tmp_proptags, &tmp_problems)) {
		return FALSE;	
	}
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_message_property(const char *dir,
	uint32_t cpid, uint64_t message_id, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::remove_message_properties(
		dir, cpid, message_id, &tmp_proptags)) {
		return FALSE;	
	}
	return TRUE;
}

BOOL exmdb_client_check_message_owner(const char *dir,
	uint64_t message_id, const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	char tmp_name[UADDR_SIZE];
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (!exmdb_client_get_message_property(dir, nullptr, 0, message_id,
	    PR_CREATOR_ENTRYID, reinterpret_cast<void **>(&pbin)))
		return FALSE;
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&ab_entryid) != EXT_ERR_SUCCESS) {
		*pb_owner = false;
		return TRUE;
	}
	if (!common_util_essdn_to_username(ab_entryid.px500dn,
	    tmp_name, arsizeof(tmp_name))) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(username, tmp_name) == 0 ? TRUE : false;
	return TRUE;
}

void exmdb_client_register_proc(void *pproc)
{
	exmdb_client_event_proc = reinterpret_cast<decltype(exmdb_client_event_proc)>(pproc);
}
