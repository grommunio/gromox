// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <list>
#include <mutex>
#include <utility>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include "exmdb_client.h"
#include "exmdb_server.h"
#include "common_util.h"
#include "exmdb_ext.h"
#include <unistd.h>
#include <ctime>
#include <poll.h>

using namespace gromox;

static auto &g_local_list = mdcl_local_list;
static auto &g_lost_list = mdcl_lost_list;
static auto &g_server_list = mdcl_server_list;
static auto &g_server_lock = mdcl_server_lock;
static auto &g_notify_stop = mdcl_notify_stop;

static void buildenv(const remote_svr &s)
{
	exmdb_server_build_environment(false,
		s.type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false, nullptr);
}

static void *mdpcl_scanwork(void *pparam)
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
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pconn = &temp_list.front();
			if (g_notify_stop) {
				close(pconn->sockd);
				temp_list.pop_front();
				continue;
			}
			pconn->sockd = exmdb_client_connect_exmdb(*pconn->psvr, false,
			               "exmdb_provider", buildenv,
			               exmdb_server_free_environment);
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

static void *mdpcl_thrwork(void *pparam)
{
	int tv_msec;
	BINARY tmp_bin;
	uint8_t resp_code;
	uint32_t buff_len, offset = 0;
	uint8_t buff[0x8000];
	AGENT_THREAD *pagent;
	struct pollfd pfd_read;
	DB_NOTIFY_DATAGRAM notify;
	
	pagent = (AGENT_THREAD*)pparam;
	while (!g_notify_stop) {
		pagent->sockd = exmdb_client_connect_exmdb(*pagent->pserver, true,
		                "mdclntfy", buildenv,
		                exmdb_server_free_environment);
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
				exmdb_server_build_environment(false, pagent->pserver->type == EXMDB_ITEM::EXMDB_PRIVATE, nullptr);
				resp_code = exmdb_ext_pull_db_notify(&tmp_bin, &notify) == EXT_ERR_SUCCESS ?
				            exmdb_response::SUCCESS : exmdb_response::PULL_ERROR;
				if (1 != write(pagent->sockd, &resp_code, 1)) {
					close(pagent->sockd);
					pagent->sockd = -1;
					exmdb_server_free_environment();
					break;
				}
				if (resp_code == exmdb_response::SUCCESS) {
					for (size_t i = 0; i < notify.id_array.count; ++i)
						exmdb_server_event_proc(notify.dir,
							notify.b_table, notify.id_array.pl[i],
							&notify.db_notify);
				}
				exmdb_server_free_environment();
				buff_len = 0;
			}
		}
	}
	return nullptr;
}

int exmdb_client_run_front(const char *dir)
{
	return exmdb_client_run(dir, EXMDB_CLIENT_ALLOW_DIRECT,
	       mdpcl_thrwork, mdpcl_scanwork);
}

/* Caution. This function is not a common exmdb service,
	it only can be called by message_rule_new_message to
	pass a message to the delegate's mailbox. */
BOOL exmdb_client_relay_delivery(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult)
{
	BOOL b_result;
	BOOL b_private;
	EXMDB_REQUEST request;
	EXMDB_RESPONSE response;
	const char *orignal_dir;
	
	if (exmdb_client_check_local(dir, &b_private)) {
		orignal_dir = exmdb_server_get_dir();
		exmdb_server_set_dir(dir);
		b_result = exmdb_server_delivery_message(
					dir, from_address, account,
					cpid, pmsg, pdigest, presult);
		exmdb_server_set_dir(orignal_dir);
		return b_result;
	}
	request.call_id = exmdb_callid::DELIVERY_MESSAGE;
	request.dir = deconst(dir);
	request.payload.delivery_message.from_address = deconst(from_address);
	request.payload.delivery_message.account = deconst(account);
	request.payload.delivery_message.cpid = cpid;
	request.payload.delivery_message.pmsg = deconst(pmsg);
	request.payload.delivery_message.pdigest = deconst(pdigest);
	if (!exmdb_client_do_rpc(dir, &request, &response))
		return FALSE;
	*presult = response.payload.delivery_message.result;
	return TRUE;
}
