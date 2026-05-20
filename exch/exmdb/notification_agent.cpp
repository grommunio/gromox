// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <poll.h>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/scope.hpp>
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
	auto prouter = exmdb_parser_get_router(remote_id);
	if (NULL == prouter) {
		return;
	}
	BINARY bin{};
	if (exmdb_ext_push_db_notify(pnotify, &bin) != pack_result::ok)
		return;	
	prouter->push_and_wake(std::move(bin));
}

static BOOL notification_agent_read_response(std::shared_ptr<ROUTER_CONNECTION> prouter)
{
	exmdb_response resp_code;
	struct pollfd pfd_read;
	
	pfd_read.fd = prouter->sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (poll(&pfd_read, 1, SOCKET_TIMEOUT_MS) != 1 ||
	    read(prouter->sockd, &resp_code, 1) != 1 ||
	    resp_code != exmdb_response::success)
		return FALSE;
	return TRUE;
}

int notification_agent_thread_work(std::shared_ptr<ROUTER_CONNECTION> &&prouter)
{
	uint32_t ping_buff;
	auto cl_0 = HX::make_scope_exit([&]() {
		/* Stop others getting new references */
		exmdb_parser_erase_router(prouter);

		/* Force remaining holders into a wall */
		prouter->close_fd();
	});
	
	while (!prouter->b_stop) {
		bool got = false;
		{
			std::unique_lock dg_hold(prouter->dg_lock);
			static_assert(SOCKET_TIMEOUT >= 3, "integer underflow");
			got = prouter->waken_cond.wait_for(dg_hold, std::chrono::seconds(SOCKET_TIMEOUT - 3),
			      [&]() { return prouter->b_stop || prouter->datagram_list.size() > 0; });
		}
		if (prouter->b_stop)
			break;
		if (!got) {
			/* We had nothing to write out since quite a while... */
			std::unique_lock fd_hold(prouter->base_lock);
			ping_buff = 0;
			if (write(prouter->sockd, &ping_buff, sizeof(uint32_t)) != sizeof(uint32_t) ||
			    !notification_agent_read_response(prouter))
				return -1;
			continue;
		}
		while (got) {
			router_connection::xbinary dg;
			{
				std::unique_lock dg_hold(prouter->dg_lock);
				if (prouter->datagram_list.empty())
					goto EO1;
				dg = std::move(prouter->datagram_list.front());
				prouter->datagram_list.pop_front();
				got = prouter->datagram_list.size() > 0;
			}
			std::unique_lock fd_hold(prouter->base_lock);
			auto bytes_written = HXio_fullwrite(prouter->sockd, dg.pb.get(), dg.cb);
			if (bytes_written < 0 ||
			    static_cast<size_t>(bytes_written) != dg.cb ||
			    !notification_agent_read_response(prouter))
				return -1;
		}
 EO1:
		;
	}
	return -1;
}
