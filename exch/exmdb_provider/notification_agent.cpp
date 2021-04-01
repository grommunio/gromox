// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <gromox/exmdb_rpc.hpp>
#include "common_util.h"
#include "notification_agent.h"
#include "exmdb_parser.h"
#include "exmdb_server.h"
#include "exmdb_ext.h"
#include <unistd.h>
#include <ctime>
#include <poll.h>

struct DATAGRAM_NODE {
	DOUBLE_LIST_NODE node;
	BINARY data_bin;
};

void notification_agent_backward_notify(
	const char *remote_id, DB_NOTIFY_DATAGRAM *pnotify)
{
	DATAGRAM_NODE *pdnode;
	
	if (NULL == remote_id) {
		for (size_t i = 0; i < pnotify->id_array.count; ++i)
			exmdb_server_event_proc(pnotify->dir, pnotify->b_table,
				pnotify->id_array.pl[i], &pnotify->db_notify);
		return;
	}
	auto prouter = exmdb_parser_get_router(remote_id);
	if (NULL == prouter) {
		return;
	}
	pdnode = me_alloc<DATAGRAM_NODE>();
	if (NULL == pdnode) {
		exmdb_parser_put_router(std::move(prouter));
		return;
	}
	pdnode->node.pdata = pdnode;
	if (EXT_ERR_SUCCESS != exmdb_ext_push_db_notify(
		pnotify, &pdnode->data_bin)) {
		exmdb_parser_put_router(std::move(prouter));
		free(pdnode);
		return;	
	}
	std::unique_lock rt_hold(prouter->lock);
	double_list_append_as_tail(&prouter->datagram_list, &pdnode->node);
	rt_hold.unlock();
	prouter->waken_cond.notify_one();
	exmdb_parser_put_router(std::move(prouter));
}

static BOOL notification_agent_read_response(std::shared_ptr<ROUTER_CONNECTION> prouter)
{
	int tv_msec;
	uint8_t resp_code;
	struct pollfd pfd_read;
	
	tv_msec = SOCKET_TIMEOUT * 1000;
	pfd_read.fd = prouter->sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 != poll(&pfd_read, 1, tv_msec) ||
		1 != read(prouter->sockd, &resp_code, 1) ||
	    resp_code != exmdb_response::SUCCESS)
		return FALSE;
	return TRUE;
}

void notification_agent_thread_work(std::shared_ptr<ROUTER_CONNECTION> &&prouter)
{
	uint32_t ping_buff;
	DATAGRAM_NODE *pdnode;
	DOUBLE_LIST_NODE *pnode;
	
	while (FALSE == prouter->b_stop) {
		std::unique_lock cn_hold(prouter->cond_mutex);
		static_assert(SOCKET_TIMEOUT >= 3, "integer underflow");
		prouter->waken_cond.wait_for(cn_hold, std::chrono::seconds(SOCKET_TIMEOUT - 3));
		cn_hold.unlock();

		std::unique_lock rt_hold(prouter->lock);
		pnode = double_list_pop_front(&prouter->datagram_list);
		rt_hold.unlock();
		if (NULL == pnode) {
			ping_buff = 0;
			if (sizeof(uint32_t) != write(prouter->sockd,
				&ping_buff, sizeof(uint32_t)) || FALSE ==
				notification_agent_read_response(prouter)) {
				goto EXIT_THREAD;
			}
			continue;
		}
		while (TRUE) {
			pdnode = (DATAGRAM_NODE*)pnode->pdata;
			if (pdnode->data_bin.cb != write(prouter->sockd,
				pdnode->data_bin.pb, pdnode->data_bin.cb) ||
				FALSE == notification_agent_read_response(prouter)) {
				free(pdnode->data_bin.pb);
				free(pdnode);
				goto EXIT_THREAD;
			}
			free(pdnode->data_bin.pb);
			free(pdnode);
			cn_hold.unlock();
			std::lock_guard rt_lock(prouter->lock);
			pnode = double_list_pop_front(&prouter->datagram_list);
			if (NULL == pnode) {
				break;
			}
		}
	}
 EXIT_THREAD:
	while (FALSE == exmdb_parser_remove_router(prouter)) {
		sleep(1);
	}
	close(prouter->sockd);
	prouter->sockd = -1;
	while ((pnode = double_list_pop_front(&prouter->datagram_list)) != nullptr) {
		pdnode = (DATAGRAM_NODE*)pnode->pdata;
		free(pdnode->data_bin.pb);
		free(pdnode);
	}
	double_list_free(&prouter->datagram_list);
	if (FALSE == prouter->b_stop) {
		pthread_detach(pthread_self());
	}
	pthread_exit(nullptr);
}
