// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cerrno>
#include <string>
#include <vector>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/socket.h>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include "cmd_parser.h"
#include <gromox/list_file.hpp>
#include "listener.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <cstdio>
#include "common_util.h"

using namespace gromox;

static int g_listen_port;
static char g_listen_ip[40];
static int g_listen_sockd;
static BOOL g_notify_stop;
static std::vector<std::string> g_acl_list;

static void *thread_work_func(void *param);

void listener_init(const char *ip, int port)
{
	if ('\0' != ip[0]) {
		HX_strlcpy(g_listen_ip, ip, GX_ARRAY_SIZE(g_listen_ip));
	} else {
		g_listen_ip[0] = '\0';
	}
	g_listen_port = port;
	g_listen_sockd = -1;
	g_notify_stop = TRUE;
}

int listener_run(const char *configdir)
{
	g_listen_sockd = gx_inet_listen(g_listen_ip, g_listen_port);
	if (g_listen_sockd < 0) {
		printf("[listener]: failed to create listen socket: %s\n", strerror(-g_listen_sockd));
		return -1;
	}
	
	auto ret = list_file_read_fixedstrings("midb_acl.txt",
	           configdir, g_acl_list);
	if (ret == -ENOENT) {
		printf("[system]: defaulting to implicit access ACL containing ::1.\n");
		g_acl_list = {"::1"};
	} else if (ret < 0) {
		printf("[listener]: list_file_initd \"midb_acl.txt\": %s\n", strerror(errno));
		close(g_listen_sockd);
		return -5;
	}
	return 0;
}

int listener_trigger_accept()
{
	pthread_t thr_id;

	g_notify_stop = FALSE;
	int ret = pthread_create(&thr_id, nullptr, thread_work_func, nullptr);
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(thr_id, "listener");
	return 0;
}

int listener_stop() {
	g_notify_stop = TRUE;
	if (g_listen_sockd > 0) {
		close(g_listen_sockd);
		g_listen_sockd = -1;
	}
	return 0;
}

void listener_free(){
	g_listen_port = 0;
}


static void *thread_work_func(void *param)
{
	int sockd;
	socklen_t addrlen;
	char client_hostip[40];
	CONNECTION *pconnection;
	struct sockaddr_storage peer_name;

	while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd = accept(g_listen_sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICSERV | NI_NUMERICHOST);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd);
			continue;
		}
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    client_hostip) == g_acl_list.cend()) {
			write(sockd, "Access Deny\r\n", 13);
			close(sockd);
			continue;
		}

		pconnection = cmd_parser_get_connection();
		if (NULL == pconnection) {
			write(sockd, "Maximum Connection Reached!\r\n", 29);
			close(sockd);
			continue;

		}
		pconnection->sockd = sockd;
		pconnection->is_selecting = FALSE;
		write(sockd, "OK\r\n", 4);
		cmd_parser_put_connection(pconnection);
	}
	return nullptr;
}


