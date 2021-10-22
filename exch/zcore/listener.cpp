// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <csignal>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <libHX/string.h>
#include <gromox/atomic.hpp>
#include <gromox/defs.h>
#include "listener.h"
#include "rpc_parser.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>

static gromox::atomic_bool g_notify_stop{false};
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
		if (FALSE == rpc_parser_activate_connection(clifd)) {
			close(clifd);
		}
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
	int len;
	struct sockaddr_un unix_addr;

	 /* Create a Unix domain stream socket */
	g_listen_sockd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (-1 == g_listen_sockd) {
		printf("[listener]: failed to create listen socket: %s\n", strerror(errno));
		return -1;
	}
	unlink(CS_PATH);
	/* Fill in socket address structure */
	memset(&unix_addr, 0, sizeof (unix_addr));
	unix_addr.sun_family = AF_UNIX;
	gx_strlcpy(unix_addr.sun_path, CS_PATH, gromox::arsizeof(unix_addr.sun_path));
	len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path);
	/* Bind the name to the descriptor */
	if (bind(g_listen_sockd, (struct sockaddr*)&unix_addr, len) < 0) {
		close(g_listen_sockd);
		printf("[listener]: bind %s: %s\n", unix_addr.sun_path, strerror(errno));
		return -2;
	}
	if (chmod(CS_PATH, 0666) < 0) {
		close(g_listen_sockd);
		printf("[listener]: fail to change access mode of %s\n", CS_PATH);
		return -3;
	}
	if (listen(g_listen_sockd, 5) < 0) {
		close(g_listen_sockd);
		printf("[listener]: fail to listen!\n");
		return -4;
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
	shutdown(g_listen_sockd, SHUT_RDWR);
	pthread_kill(g_listener_id, SIGALRM);
	pthread_join(g_listener_id, NULL);
	close(g_listen_sockd);
	g_listen_sockd = -1;
}
