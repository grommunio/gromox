// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <list>
#include <mutex>
#include <utility>
#include <gromox/endian.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/fileio.h>
#include "exmdb_client.h"
#include <gromox/exmdb_rpc.hpp>
#include <gromox/hook_common.h>
#include <gromox/socket.h>
#include <gromox/ext_buffer.hpp>
#include <cstdlib>
#include <unistd.h>
#include <cstdio>
#include <ctime>

#define SOCKET_TIMEOUT								60

using namespace gromox;

namespace {

struct CONNECT_REQUEST {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct DELIVERY_MESSAGE_REQUEST {
	const char *dir;
	const char *from_address;
	const char *account;
	uint32_t cpid;
	const MESSAGE_CONTENT *pmsg;
	const char *pdigest;
};

struct CHECK_CONTACT_ADDRESS_REQUEST {
	const char *dir;
	const char *paddress;
};

}

static auto &g_lost_list = mdcl_lost_list;
static auto &g_server_list = mdcl_server_list;
static auto &g_server_lock = mdcl_server_lock;
static auto &g_notify_stop = mdcl_notify_stop;
static auto &g_conn_num = mdcl_conn_num;

static int cl_rd_sock(int fd, BINARY *b) { return exmdb_client_read_socket(fd, b, SOCKET_TIMEOUT * 1000); }
static int cl_wr_sock(int fd, const BINARY *b) { return exmdb_client_write_socket(fd, b, SOCKET_TIMEOUT * 1000); }

static int exmdb_client_push_connect_request(
	EXT_PUSH *pext, const CONNECT_REQUEST *r)
{
	auto status = pext->p_str(r->prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = pext->p_str(r->remote_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return pext->p_bool(r->b_private);
}

static int exmdb_client_push_delivery_message_request(
	EXT_PUSH *pext, const DELIVERY_MESSAGE_REQUEST *r)
{
	auto status = pext->p_str(r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = pext->p_str(r->from_address);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = pext->p_str(r->account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = pext->p_uint32(r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = pext->p_msgctnt(*r->pmsg);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return pext->p_str(r->pdigest);
}

static int exmdb_client_push_check_contact_address_request(
	EXT_PUSH *pext, const CHECK_CONTACT_ADDRESS_REQUEST *r)
{
	auto status = pext->p_str(r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return pext->p_str(r->paddress);
}

static int exmdb_client_push_request(uint8_t call_id,
	void *prequest, BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT))
		return EXT_ERR_ALLOC;
	status = ext_push.advance(sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_push.p_uint8(call_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	switch (call_id) {
	case exmdb_callid::CONNECT:
		status = exmdb_client_push_connect_request(&ext_push, static_cast<CONNECT_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case exmdb_callid::DELIVERY_MESSAGE:
		status = exmdb_client_push_delivery_message_request(&ext_push, static_cast<DELIVERY_MESSAGE_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		break;
	case exmdb_callid::CHECK_CONTACT_ADDRESS:
		status = exmdb_client_push_check_contact_address_request(&ext_push, static_cast<CHECK_CONTACT_ADDRESS_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			return status;
		}
		break;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
	pbin_out->cb = ext_push.m_offset;
	ext_push.m_offset = 0;
	status = ext_push.p_uint32(pbin_out->cb - sizeof(uint32_t));
	if (status != EXT_ERR_SUCCESS)
		return status;
	/* memory referenced by ext_push.data will be freed outside */
	pbin_out->pb = ext_push.release();
	return EXT_ERR_SUCCESS;
}

static void *exmlc_scanwork(void *pparam)
{
	fd_set myset;
	time_t now_time;
	struct timeval tv;
	uint8_t resp_buff;
	uint32_t ping_buff;
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
				continue;
			}
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(pconn->sockd, &myset);
			if (select(pconn->sockd + 1, &myset, NULL, NULL, &tv) <= 0 ||
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
			pconn->sockd = exmdb_client_connect_exmdb(*pconn->psvr, false, "exmdb_local", nullptr, nullptr);
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

int exmdb_client_run_front()
{
	return exmdb_client_run(get_config_path(), EXMDB_CLIENT_NO_FLAGS,
	       exmlc_scanwork, nullptr);
}

int exmdb_client_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest)
{
	BINARY tmp_bin;
	uint32_t result;
	DELIVERY_MESSAGE_REQUEST request;
	
	request.dir = dir;
	request.from_address = from_address;
	request.account = account;
	request.cpid = cpid;
	request.pmsg = pmsg;
	request.pdigest = pdigest;
	if (exmdb_client_push_request(exmdb_callid::DELIVERY_MESSAGE,
	    &request, &tmp_bin) != EXT_ERR_SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	auto pconn = exmdb_client_get_connection(dir);
	if (pconn == nullptr) {
		free(tmp_bin.pb);
		return EXMDB_NO_SERVER;
	}
	if (!cl_wr_sock(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		return EXMDB_RDWR_ERROR;
	}
	free(tmp_bin.pb);
	if (!cl_rd_sock(pconn->sockd, &tmp_bin))
		return EXMDB_RDWR_ERROR;
	time(&pconn->last_time);
	pconn.reset();
	if (5 + sizeof(uint32_t) != tmp_bin.cb ||
	    tmp_bin.pb[0] != exmdb_response::SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	result = le32p_to_cpu(&tmp_bin.pb[5]);
	if (0 == result) {
		return EXMDB_RESULT_OK;
	} else if (1 == result) {
		return EXMDB_MAILBOX_FULL;
	} else {
		return EXMDB_RESULT_ERROR;
	}
}

int exmdb_client_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found)
{
	BINARY tmp_bin;
	CHECK_CONTACT_ADDRESS_REQUEST request;
	
	request.dir = dir;
	request.paddress = paddress;
	if (exmdb_client_push_request(exmdb_callid::CHECK_CONTACT_ADDRESS,
	    &request, &tmp_bin) != EXT_ERR_SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	auto pconn = exmdb_client_get_connection(dir);
	if (pconn == nullptr) {
		free(tmp_bin.pb);
		return EXMDB_NO_SERVER;
	}
	if (!cl_wr_sock(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		return EXMDB_RDWR_ERROR;
	}
	free(tmp_bin.pb);
	if (!cl_rd_sock(pconn->sockd, &tmp_bin))
		return EXMDB_RDWR_ERROR;
	time(&pconn->last_time);
	pconn.reset();
	if (5 + sizeof(uint8_t) != tmp_bin.cb ||
	    tmp_bin.pb[0] != exmdb_response::SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	if (0 == tmp_bin.pb[5]) {
		*pb_found = FALSE;
	} else {
		*pb_found = TRUE;
	}
	return EXMDB_RESULT_OK;
}
