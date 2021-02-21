// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <list>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/endian_macro.hpp>
#include <gromox/fileio.h>
#include "exmdb_client.h"
#include <gromox/double_list.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/hook_common.h>
#include <gromox/socket.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/list_file.hpp>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <cerrno>
#include <cstdio>
#include <ctime>

#define SOCKET_TIMEOUT								60

struct REMOTE_CONN;
struct REMOTE_SVR : public EXMDB_ITEM {
	REMOTE_SVR(EXMDB_ITEM &&o) : EXMDB_ITEM(std::move(o)) {}
	std::list<REMOTE_CONN> conn_list;
};

struct REMOTE_CONN {
	time_t last_time;
	REMOTE_SVR *psvr;
	int sockd;
};

struct REMOTE_CONN_floating {
	REMOTE_CONN_floating() = default;
	REMOTE_CONN_floating(REMOTE_CONN_floating &&);
	~REMOTE_CONN_floating() { reset(true); }
	REMOTE_CONN *operator->() { return tmplist.size() != 0 ? &tmplist.front() : nullptr; }
	bool operator==(std::nullptr_t) const { return tmplist.size() == 0; }
	bool operator!=(std::nullptr_t) const { return tmplist.size() != 0; }
	void reset(bool lost = false);

	std::list<REMOTE_CONN> tmplist;
};

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

static int g_conn_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static std::list<REMOTE_CONN> g_lost_list;
static std::list<REMOTE_SVR> g_server_list;
static std::mutex g_server_lock;

static int exmdb_client_push_connect_request(
	EXT_PUSH *pext, const CONNECT_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->prefix);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->remote_id);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_bool(pext, r->b_private);
}

static int exmdb_client_push_delivery_message_request(
	EXT_PUSH *pext, const DELIVERY_MESSAGE_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->from_address);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_string(pext, r->account);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_uint32(pext, r->cpid);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	status = ext_buffer_push_message_content(pext, r->pmsg);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->pdigest);
}

static int exmdb_client_push_check_contact_address_request(
	EXT_PUSH *pext, const CHECK_CONTACT_ADDRESS_REQUEST *r)
{
	int status;
	
	status = ext_buffer_push_string(pext, r->dir);
	if (EXT_ERR_SUCCESS != status) {
		return status;
	}
	return ext_buffer_push_string(pext, r->paddress);
}

static int exmdb_client_push_request(uint8_t call_id,
	void *prequest, BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_WCOUNT)) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_advance(&ext_push, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	status = ext_buffer_push_uint8(&ext_push, call_id);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	switch (call_id) {
	case exmdb_callid::CONNECT:
		status = exmdb_client_push_connect_request(&ext_push, static_cast<CONNECT_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case exmdb_callid::DELIVERY_MESSAGE:
		status = exmdb_client_push_delivery_message_request(&ext_push, static_cast<DELIVERY_MESSAGE_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	case exmdb_callid::CHECK_CONTACT_ADDRESS:
		status = exmdb_client_push_check_contact_address_request(&ext_push, static_cast<CHECK_CONTACT_ADDRESS_REQUEST *>(prequest));
		if (EXT_ERR_SUCCESS != status) {
			ext_buffer_push_free(&ext_push);
			return status;
		}
		break;
	default:
		ext_buffer_push_free(&ext_push);
		return EXT_ERR_BAD_SWITCH;
	}
	pbin_out->cb = ext_push.offset;
	ext_push.offset = 0;
	ext_buffer_push_uint32(&ext_push,
		pbin_out->cb - sizeof(uint32_t));
	/* memory referenced by ext_push.data will be freed outside */
	pbin_out->pb = ext_buffer_push_release(&ext_push);
	return EXT_ERR_SUCCESS;
}

static BOOL exmdb_client_read_socket(int sockd, BINARY *pbin)
{
	fd_set myset;
	int read_len;
	uint32_t offset;
	struct timeval tv;
	uint8_t resp_buff[5];
	
	pbin->cb = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		if (0 == pbin->cb) {
			read_len = read(sockd, resp_buff, 5);
			if (1 == read_len) {
				pbin->cb = 1;
				*(uint8_t*)pbin->pb = resp_buff[0];
				return TRUE;
			} else if (5 == read_len) {
				pbin->cb = *(uint32_t*)(resp_buff + 1) + 5;
				if (pbin->cb >= 1024) {
					return FALSE;
				}
				memcpy(pbin->pb, resp_buff, 5);
				offset = 5;
				if (offset == pbin->cb) {
					return TRUE;
				}
				continue;
			} else {
				return FALSE;
			}
		}
		read_len = read(sockd,
			pbin->pb + offset,
			pbin->cb - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset == pbin->cb) {
			return TRUE;
		}
	}
}

static BOOL exmdb_client_write_socket(
	int sockd, const BINARY *pbin)
{
	fd_set myset;
	int written_len;
	uint32_t offset;
	struct timeval tv;
	
	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, NULL, &myset, NULL, &tv) <= 0) {
			return FALSE;
		}
		written_len = write(sockd,
				pbin->pb + offset,
				pbin->cb - offset);
		if (written_len <= 0) {
			return FALSE;
		}
		offset += written_len;
		if (offset == pbin->cb) {
			return TRUE;
		}
	}
}

static int exmdb_client_connect_exmdb(REMOTE_SVR *pserver)
{
	int process_id;
	BINARY tmp_bin;
	char remote_id[128];
	const char *str_host;
	uint8_t response_code, tmp_buff[1024];
	CONNECT_REQUEST request;

	int sockd = gx_inet_connect(pserver->host.c_str(), pserver->port, 0);
	if (sockd < 0)
		return -1;
	str_host = get_host_ID();
	process_id = getpid();
	sprintf(remote_id, "%s:%d", str_host, process_id);
	request.prefix = deconst(pserver->prefix.c_str());
	request.remote_id = remote_id;
	request.b_private = pserver->type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false;
	if (exmdb_client_push_request(exmdb_callid::CONNECT, &request,
	    &tmp_bin) != EXT_ERR_SUCCESS) {
		close(sockd);
		return -1;
	}
	if (FALSE == exmdb_client_write_socket(sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		close(sockd);
		return -1;
	}
	free(tmp_bin.pb);
	tmp_bin.pb = tmp_buff;
	if (FALSE == exmdb_client_read_socket(sockd, &tmp_bin)) {
		close(sockd);
		return -1;
	}
	response_code = tmp_bin.pb[0];
	if (response_code == exmdb_response::SUCCESS) {
		if (5 != tmp_bin.cb || 0 != *(uint32_t*)(tmp_bin.pb + 1)) {
			printf("[exmdb_local]: response format error "
			       "during connect to [%s]:%hu/%s\n",
			       pserver->host.c_str(), pserver->port, pserver->prefix.c_str());
			close(sockd);
			return -1;
		}
		return sockd;
	}
	printf("[exmdb_provider]: Failed to connect to [%s]:%hu/%s",
	       pserver->host.c_str(), pserver->port, pserver->prefix.c_str());
	switch (response_code) {
	case exmdb_response::ACCESS_DENY:
		printf(": access denied\n");
		break;
	case exmdb_response::MAX_REACHED:
		printf(": maximum connections reached in server\n");
		break;
	case exmdb_response::LACK_MEMORY:
		printf(": server out of memory\n");
		break;
	case exmdb_response::MISCONFIG_PREFIX:
		printf(": prefix not served by server\n");
		break;
	case exmdb_response::MISCONFIG_MODE:
		printf(": misconfigured prefix mode\n");
		break;
	default:
		printf(": error code %d\n", response_code);
		break;
	}
	close(sockd);
	return -1;
}

static void *scan_work_func(void *pparam)
{
	fd_set myset;
	time_t now_time;
	struct timeval tv;
	uint8_t resp_buff;
	uint32_t ping_buff;
	std::list<REMOTE_CONN> temp_list;
	
	ping_buff = 0;
	while (FALSE == g_notify_stop) {
		std::unique_lock sv_hold(g_server_lock);
		time(&now_time);
		for (auto &srv : g_server_list) {
			auto tail = &*srv.conn_list.rbegin();
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
			if (TRUE == g_notify_stop) {
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
		sv_hold.unlock();

		while (temp_list.size() > 0) {
			auto pconn = &temp_list.front();
			if (TRUE == g_notify_stop) {
				close(pconn->sockd);
				temp_list.pop_front();
				continue;
			}
			pconn->sockd = exmdb_client_connect_exmdb(pconn->psvr);
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

static REMOTE_CONN_floating exmdb_client_get_connection(const char *dir)
{
	REMOTE_CONN_floating fc;
	auto i = std::find_if(g_server_list.begin(), g_server_list.end(),
	         [&](const REMOTE_SVR &s) { return strncmp(dir, s.prefix.c_str(), s.prefix.size()) == 0; });
	if (i == g_server_list.end()) {
		printf("[exmdb_local]: cannot find remote server for %s\n", dir);
		return fc;
	}
	std::unique_lock sv_hold(g_server_lock);
	if (i->conn_list.size() == 0) {
		sv_hold.unlock();
		printf("[exmdb_client]: no alive connection for [%s]:%hu/%s\n",
		       i->host.c_str(), i->port, i->prefix.c_str());
		return fc;
	}
	fc.tmplist.splice(fc.tmplist.end(), i->conn_list, i->conn_list.begin());
	return fc;
}

BOOL exmdb_client_get_exmdb_information(
	const char *dir, char *ip_addr, int *pport,
	int *pconn_num, int *palive_conn)
{
	auto i = std::find_if(g_server_list.begin(), g_server_list.end(),
	         [&](const REMOTE_SVR &s) { return strncmp(dir, s.prefix.c_str(), s.prefix.size()) == 0; });
	if (i == g_server_list.end())
		return FALSE;
	strcpy(ip_addr, i->host.c_str());
	*pport = i->port;
	*palive_conn = i->conn_list.size();
	*pconn_num = g_conn_num;
	return TRUE;
}

void REMOTE_CONN_floating::reset(bool lost)
{
	if (tmplist.size() == 0)
		return;
	auto pconn = &tmplist.front();
	if (!lost) {
		std::unique_lock sv_hold(g_server_lock);
		pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), tmplist, tmplist.begin());
	} else {
		close(pconn->sockd);
		pconn->sockd = -1;
		std::unique_lock sv_hold(g_server_lock);
		g_lost_list.splice(g_lost_list.end(), tmplist, tmplist.begin());
	}
	tmplist.clear();
}

REMOTE_CONN_floating::REMOTE_CONN_floating(REMOTE_CONN_floating &&o)
{
	reset(true);
	tmplist = std::move(o.tmplist);
}

void exmdb_client_init(int conn_num)
{
	g_notify_stop = TRUE;
	g_conn_num = conn_num;
}

int exmdb_client_run()
{
	std::vector<EXMDB_ITEM> xmlist;
	auto ret = list_file_read_exmdb("exmdb_list.txt", get_config_path(), xmlist);
	if (ret < 0) {
		printf("[exmdb_local]: list_file_read_exmdb: %s\n", strerror(-ret));
		return 1;
	}
	g_notify_stop = FALSE;
	for (auto &&item : xmlist) {
		try {
			g_server_list.emplace_back(std::move(item));
		} catch (const std::bad_alloc &) {
			printf("[exmdb_local]: Failed to allocate memory for exmdb\n");
			g_notify_stop = TRUE;
			return 3;
		}
		auto &srv = g_server_list.back();
		for (decltype(g_conn_num) j = 0; j < g_conn_num; ++j) {
			REMOTE_CONN conn;
			conn.sockd = -1;
			static_assert(std::is_same_v<decltype(g_server_list), std::list<decltype(g_server_list)::value_type>>,
				"addrof REMOTE_SVRs must not change; REMOTE_CONN/AGENT_THREAD has a pointer to it");
			conn.psvr = &srv;
			try {
				g_lost_list.push_back(std::move(conn));
			} catch (const std::bad_alloc &) {
				printf("[exmdb_local]: fail to "
					"allocate memory for exmdb\n");
				g_notify_stop = TRUE;
				return 4;
			}
		}
	}
	ret = pthread_create(&g_scan_id, nullptr, scan_work_func, nullptr);
	if (ret != 0) {
		printf("[exmdb_local]: failed to create proxy scan thread: %s\n", strerror(ret));
		g_notify_stop = TRUE;
		return 5;
	}
	pthread_setname_np(g_scan_id, "mdbloc/scan");
	return 0;
}

int exmdb_client_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
	}
	g_notify_stop = TRUE;
	for (auto &srv : g_server_list)
		for (auto &conn : srv.conn_list)
			close(conn.sockd);
	return 0;
}

int exmdb_client_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest)
{
	BINARY tmp_bin;
	uint32_t result;
	uint8_t tmp_buff[1024];
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
	if (FALSE == exmdb_client_write_socket(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		return EXMDB_RDWR_ERROR;
	}
	free(tmp_bin.pb);
	tmp_bin.pb = tmp_buff;
	if (FALSE == exmdb_client_read_socket(pconn->sockd, &tmp_bin)) {
		return EXMDB_RDWR_ERROR;
	}
	time(&pconn->last_time);
	pconn.reset();
	if (5 + sizeof(uint32_t) != tmp_bin.cb ||
	    tmp_buff[0] != exmdb_response::SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	result = IVAL(tmp_buff, 5);
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
	uint8_t tmp_buff[1024];
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
	if (FALSE == exmdb_client_write_socket(pconn->sockd, &tmp_bin)) {
		free(tmp_bin.pb);
		return EXMDB_RDWR_ERROR;
	}
	free(tmp_bin.pb);
	tmp_bin.pb = tmp_buff;
	if (FALSE == exmdb_client_read_socket(pconn->sockd, &tmp_bin)) {
		return EXMDB_RDWR_ERROR;
	}
	time(&pconn->last_time);
	pconn.reset();
	if (5 + sizeof(uint8_t) != tmp_bin.cb ||
	    tmp_buff[0] != exmdb_response::SUCCESS)
		return EXMDB_RUNTIME_ERROR;
	if (0 == tmp_bin.pb[5]) {
		*pb_found = FALSE;
	} else {
		*pb_found = TRUE;
	}
	return EXMDB_RESULT_OK;
}
