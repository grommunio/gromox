// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/io.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/list_file.hpp>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "listener.hpp"
#include "parser.hpp"

using namespace gromox;

static uint16_t g_listen_port;
static int g_listen_sockd;
static gromox::atomic_bool g_notify_stop;
static char g_listen_ip[40];
static std::vector<std::string> g_acl_list;
static pthread_t g_listener_id;

static void *sockaccept_thread(void *param)
{
	while (ems_send_mail == nullptr || ems_send_vmail == nullptr) {
		if (g_notify_stop)
			break;
		sleep(1);	
	}
	while (!g_notify_stop) {
		auto conn = generic_connection::accept(g_listen_sockd, false, &g_notify_stop);
		if (conn.sockd == -2)
			return nullptr;
		else if (conn.sockd < 0)
			continue;
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    conn.client_ip) == g_acl_list.cend()) {
			static std::atomic<time_t> g_lastwarn_time;
			auto prev = g_lastwarn_time.load();
			auto next = prev + 60;
			auto now = time(nullptr);
			if (next <= now && g_lastwarn_time.compare_exchange_strong(prev, now))
				mlog(LV_INFO, "I-1666: Rejecting %s: not allowed by exmdb_acl", conn.client_ip);
			auto tmp_byte = exmdb_response::access_deny;
			if (HXio_fullwrite(conn.sockd, &tmp_byte, 1) != 1)
				/* ignore */;
			continue;
		}
		auto pconnection = exmdb_parser_make_conn();
		if (pconnection == nullptr) {
			auto tmp_byte = exmdb_response::max_reached;
			if (HXio_fullwrite(conn.sockd, &tmp_byte, 1) != 1)
				/* ignore */;
			continue;
		}
		/* move(conn) deferred until here, else cov-scan complains about conn.sockd being moved out */
		static_cast<generic_connection &>(*pconnection) = std::move(conn);
		exmdb_parser_insert_conn(std::move(pconnection));
	}
	return nullptr;
}

void exmdb_listener_init(const char *ip, uint16_t port)
{
	if (ip[0] != '\0')
		gx_strlcpy(g_listen_ip, ip, std::size(g_listen_ip));
	g_listen_port = port;
	g_listen_sockd = -1;
	g_notify_stop = true;
}

int exmdb_listener_run(const char *config_path, const char *hosts_allow)
{
	if (0 == g_listen_port) {
		return 0;
	}
	g_listen_sockd = HX_inet_listen(g_listen_ip, g_listen_port);
	if (g_listen_sockd < 0) {
		mlog(LV_ERR, "exmdb_provider: failed to create listen socket: %s", strerror(-g_listen_sockd));
		return -1;
	}
	gx_reexec_record(g_listen_sockd);
	auto &acl = g_acl_list;
	if (hosts_allow != nullptr)
		acl = gx_split(hosts_allow, ' ');
	auto ret = list_file_read_fixedstrings("exmdb_acl.txt", config_path, acl);
	if (ret == ENOENT) {
	} else if (ret != 0) {
		mlog(LV_ERR, "exmdb_provider: Failed to read ACLs from exmdb_acl.txt: %s", strerror(errno));
		close(g_listen_sockd);
		return -5;
	}
	std::sort(acl.begin(), acl.end());
	acl.erase(std::remove(acl.begin(), acl.end(), ""), acl.end());
	acl.erase(std::unique(acl.begin(), acl.end()), acl.end());
	if (acl.size() == 0) {
		mlog(LV_NOTICE, "exmdb_provider: defaulting to implicit access ACL containing ::1.");
		acl = {"::1"};
	}
	return 0;
}

int exmdb_listener_trigger_accept()
{
	if (0 == g_listen_port) {
		return 0;
	}
	g_notify_stop = false;
	auto ret = pthread_create4(&g_listener_id, nullptr, sockaccept_thread, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "exmdb_provider: failed to create exmdb listener thread: %s", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_listener_id, "exmdb_accept");
	return 0;
}

void exmdb_listener_stop()
{
	if (0 == g_listen_port) {
		return;
	}
	if (!g_notify_stop) {
		g_notify_stop = true;
		if (g_listen_sockd >= 0)
			shutdown(g_listen_sockd, SHUT_RDWR);
		if (!pthread_equal(g_listener_id, {})) {
			pthread_kill(g_listener_id, SIGALRM);
			pthread_join(g_listener_id, NULL);
		}
	}
	if (-1 != g_listen_sockd) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
}
