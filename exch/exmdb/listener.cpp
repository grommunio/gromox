// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <gromox/atomic.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/list_file.hpp>
#include <gromox/listener_ctx.hpp>
#include <gromox/util.hpp>
#include "listener.hpp"
#include "parser.hpp"

using namespace gromox;

static gromox::atomic_bool g_exmdblisten_stop;
static std::vector<std::string> g_acl_list;
static listener_ctx exmdb_listen_ctx;

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
		auto pconnection = exmdb_parser_make_conn();
		if (pconnection == nullptr) {
			auto tmp_byte = exmdb_response::max_reached;
			if (HXio_fullwrite(conn.sockd, &tmp_byte, 1) != 1)
				/* ignore */;
			return 0;
		}
		/* move(conn) deferred until here, else cov-scan complains about conn.sockd being moved out */
		static_cast<generic_connection &>(*pconnection) = std::move(conn);
		exmdb_parser_insert_conn(std::move(pconnection));

	return 0;
}

int exmdb_listener_init(const char *config_path, const char *hosts_allow,
    const char *laddr, uint16_t port)
{
	auto &acl = g_acl_list;
	if (hosts_allow != nullptr)
		acl = gx_split(hosts_allow, ' ');
	auto ret = list_file_read_fixedstrings("exmdb_acl.txt", config_path, acl);
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

	if (port == 0)
		return 0;
	exmdb_listen_ctx.m_thread_name = "exmdb_accept";
	if (exmdb_listen_ctx.add_inet(laddr, port) != 0)
		return -1;
	return 0;
}

int exmdb_listener_trigger_accept()
{
	if (exmdb_listen_ctx.empty())
		return 0;
	g_exmdblisten_stop = false;
	auto ret = exmdb_listen_ctx.watch_start(g_exmdblisten_stop, sockaccept_thread);
	if (ret != 0) {
		mlog(LV_ERR, "exmdb_provider: failed to create exmdb listener thread: %s", strerror(ret));
		return -1;
	}
	return 0;
}

void exmdb_listener_stop()
{
	g_exmdblisten_stop = true;
	exmdb_listen_ctx.reset();
}
