// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include "listener.hpp"
#include "rpc_parser.hpp"

using namespace gromox;

static gromox::atomic_bool g_notify_stop;
static int g_listen_sockd;
static pthread_t g_listener_id;

static void *zcls_thrwork(void *param)
{
	struct sockaddr_storage unix_addr;
	
	while (!g_notify_stop) {
		socklen_t len = sizeof(unix_addr);
		memset(&unix_addr, 0, sizeof(unix_addr));
		int clifd = accept(g_listen_sockd, reinterpret_cast<struct sockaddr *>(&unix_addr), &len);
		if (-1 == clifd) {
			continue;
		}
		if (!rpc_parser_activate_connection(clifd))
			close(clifd);
    }
	return NULL;
}

void listener_init()
{
	g_listen_sockd = -1;
	g_notify_stop = true;
}

int listener_run(const char *CS_PATH)
{
	g_listen_sockd = gx_local_listen(CS_PATH, true /* autodelete */);
	if (g_listen_sockd < 0) {
		printf("[listener]: listen %s: %s\n", CS_PATH, strerror(errno));
		return -1;
	}
	gx_reexec_record(g_listen_sockd);
	if (chmod(CS_PATH, 0666) < 0) {
		close(g_listen_sockd);
		printf("[listener]: fail to change access mode of %s\n", CS_PATH);
		return -3;
	}
	g_notify_stop = false;
	auto ret = pthread_create(&g_listener_id, nullptr, zcls_thrwork, nullptr);
	if (ret != 0) {
		close(g_listen_sockd);
		printf("[listener]: failed to create accept thread: %s\n", strerror(ret));
		return -5;
	}
	pthread_setname_np(g_listener_id, "accept");
	return 0;
}

void listener_stop()
{
	g_notify_stop = true;
	if (g_listen_sockd >= 0)
		shutdown(g_listen_sockd, SHUT_RDWR);
	if (!pthread_equal(g_listener_id, {})) {
		pthread_kill(g_listener_id, SIGALRM);
		pthread_join(g_listener_id, NULL);
	}
	if (g_listen_sockd >= 0)
		close(g_listen_sockd);
	g_listen_sockd = -1;
}
