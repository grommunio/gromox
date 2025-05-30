// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <poll.h>
#include <unistd.h>
#include <utility>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_ext.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include "notification_agent.hpp"
#include "parser.hpp"

void notification_agent_backward_notify(const char *remote_id,
    const DB_NOTIFY_DATAGRAM *pnotify)
{
	if (NULL == remote_id) {
		for (size_t i = 0; i < pnotify->id_array.size(); ++i)
			exmdb_server::event_proc(pnotify->dir, pnotify->b_table,
				pnotify->id_array[i], &pnotify->db_notify);
		return;
	}
	auto prouter = exmdb_parser_extract_router(remote_id);
	if (NULL == prouter) {
		return;
	}
	BINARY bin{};
	if (exmdb_ext_push_db_notify(pnotify, &bin) != pack_result::ok) {
		exmdb_parser_insert_router(std::move(prouter));
		return;	
	}
	try {
		std::unique_lock rt_hold(prouter->lock);
		prouter->datagram_list.push_back(bin);
	} catch (...) {
		free(bin.pb);
		return;
	}
	prouter->waken_cond.notify_one();
	exmdb_parser_insert_router(std::move(prouter));
}

static BOOL notification_agent_read_response(std::shared_ptr<ROUTER_CONNECTION> prouter)
{
	exmdb_response resp_code;
	struct pollfd pfd_read;
	
	pfd_read.fd = prouter->sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1 ||
		1 != read(prouter->sockd, &resp_code, 1) ||
	    resp_code != exmdb_response::success)
		return FALSE;
	return TRUE;
}

void notification_agent_thread_work(std::shared_ptr<ROUTER_CONNECTION> &&prouter)
{
	uint32_t ping_buff;
	
	while (!prouter->b_stop) {
		BINARY dg;
		std::unique_lock cn_hold(prouter->cond_mutex);
		static_assert(SOCKET_TIMEOUT >= 3, "integer underflow");
		prouter->waken_cond.wait_for(cn_hold, std::chrono::seconds(SOCKET_TIMEOUT - 3));
		cn_hold.unlock();

		std::unique_lock rt_hold(prouter->lock);
		if (prouter->datagram_list.size() > 0) {
			dg = prouter->datagram_list.front();
			prouter->datagram_list.pop_front();
		} else {
			dg.cb = 0;
			dg.pb = nullptr;
		}
		rt_hold.unlock();
		if (dg.pb == nullptr) {
			ping_buff = 0;
			if (write(prouter->sockd, &ping_buff, sizeof(uint32_t)) != sizeof(uint32_t) ||
			    !notification_agent_read_response(prouter))
				goto EXIT_THREAD;
			continue;
		}
		while (dg.pb != nullptr) {
			auto bytes_written = write(prouter->sockd, dg.pb, dg.cb);
			free(dg.pb);
			if (bytes_written < 0 ||
			    static_cast<size_t>(bytes_written) != dg.cb ||
			    !notification_agent_read_response(prouter))
				goto EXIT_THREAD;
			std::unique_lock rt_lock(prouter->lock);
			if (prouter->datagram_list.size() > 0) {
				dg = prouter->datagram_list.front();
				prouter->datagram_list.pop_front();
			} else {
				rt_lock.unlock();
				dg.cb = 0;
				dg.pb = nullptr;
			}
		}
	}
 EXIT_THREAD:
	while (!exmdb_parser_erase_router(prouter))
		sleep(1);
	close(prouter->sockd);
	prouter->sockd = -1;
	{
		std::lock_guard lk(prouter->lock);
		for (auto &&bin : prouter->datagram_list)
			free(bin.pb);
		prouter->datagram_list.clear();
	}
	if (!prouter->b_stop) {
		prouter->thr_id = {};
		pthread_detach(pthread_self());
	}
	pthread_exit(nullptr);
}
