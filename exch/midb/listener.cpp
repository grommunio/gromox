// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include "cmd_parser.h"
#include "common_util.h"
#include "listener.h"

using namespace gromox;

static uint16_t g_listen_port;
static char g_listen_ip[40];
static int g_listen_sockd = -1;
static gromox::atomic_bool g_notify_stop;
static std::vector<std::string> g_acl_list;

static void *midls_thrwork(void *);

void listener_init(const char *ip, uint16_t port)
{
	if ('\0' != ip[0]) {
		gx_strlcpy(g_listen_ip, ip, GX_ARRAY_SIZE(g_listen_ip));
	} else {
		g_listen_ip[0] = '\0';
	}
	g_listen_port = port;
	g_listen_sockd = -1;
	g_notify_stop = true;
}

int listener_run(const char *configdir)
{
	g_listen_sockd = gx_inet_listen(g_listen_ip, g_listen_port);
	if (g_listen_sockd < 0) {
		mlog(LV_ERR, "listener: failed to create listen socket: %s", strerror(-g_listen_sockd));
		return -1;
	}
	gx_reexec_record(g_listen_sockd);
	
	auto ret = list_file_read_fixedstrings("midb_acl.txt",
	           configdir, g_acl_list);
	if (ret == ENOENT) {
		mlog(LV_NOTICE, "system: defaulting to implicit access ACL containing ::1.");
		g_acl_list = {"::1"};
	} else if (ret != 0) {
		mlog(LV_ERR, "listener: list_file_initd \"midb_acl.txt\": %s", strerror(errno));
		close(g_listen_sockd);
		return -5;
	}
	return 0;
}

int listener_trigger_accept()
{
	pthread_t thr_id;

	g_notify_stop = false;
	auto ret = pthread_create(&thr_id, nullptr, midls_thrwork, nullptr);
	if (ret != 0) {
		mlog(LV_ERR, "listener: failed to create listener thread: %s", strerror(ret));
		return -1;
	}
	pthread_setname_np(thr_id, "listener");
	return 0;
}

void listener_stop() {
	g_notify_stop = true;
	if (g_listen_sockd >= 0) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
}

static void *midls_thrwork(void *param)
{
	socklen_t addrlen;
	char client_hostip[40];
	struct sockaddr_storage peer_name;

	while (!g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
		auto sockd = accept(g_listen_sockd, reinterpret_cast<struct sockaddr *>(&peer_name), &addrlen);
		if (-1 == sockd) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICSERV | NI_NUMERICHOST);
		if (ret != 0) {
			mlog(LV_ERR, "getnameinfo: %s", gai_strerror(ret));
			close(sockd);
			continue;
		}
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    client_hostip) == g_acl_list.cend()) {
			if (HXio_fullwrite(sockd, "FALSE Access Deny\r\n", 19) != 19)
				/* ignore */;
			close(sockd);
			continue;
		}

		auto holder = cmd_parser_get_connection();
		if (holder.size() == 0) {
			if (HXio_fullwrite(sockd, "FALSE Maximum Connection Reached!\r\n", 35) != 35)
				/* ignore */;
			close(sockd);
			continue;

		}
		auto pconnection = &holder.front();
		pconnection->sockd = sockd;
		pconnection->is_selecting = FALSE;
		if (HXio_fullwrite(sockd, "OK\r\n", 4) != 4)
			continue;
		cmd_parser_put_connection(std::move(holder));
	}
	return nullptr;
}


