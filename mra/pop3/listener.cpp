// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *    listener is a module, which listen a certain port and if a connection is
 *    coming, pass the connection in connection filter module and if the
 *    connection is legal, construct a context to represent the connection and 
 *    throw it into contexts pool, or close the connection
 */
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
#include <libHX/io.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include "pop3.hpp"

using namespace gromox;

static void *p3ls_thrwork(void *);

static pthread_t g_thr_id;
static gromox::atomic_bool g_stop_accept;
static std::string g_listener_addr;
static int g_listener_sock = -1, g_listener_ssl_sock = -1;
uint16_t g_listener_port, g_listener_ssl_port;
static pthread_t g_ssl_thr_id;

void listener_init(const char *addr, uint16_t port, uint16_t ssl_port)
{
	g_listener_addr = addr;
	g_listener_port = port;
	g_listener_ssl_port = ssl_port;
	g_stop_accept = false;
}

/*
 *    @return     
 *         0    success 
 *        -1    fail to create socket for listening
 *        -2    fail to set address for reuse
 *        -3    fail to bind listening socket
 *        -4    fail to listen    
 */
int listener_run()
{
	g_listener_sock = gx_inet_listen(g_listener_addr.c_str(), g_listener_port);
	if (g_listener_sock < 0) {
		printf("[listener]: failed to create socket [*]:%hu: %s\n",
		       g_listener_port, strerror(-g_listener_sock));
		return -1;
	}
	gx_reexec_record(g_listener_sock);
	if (g_listener_ssl_port > 0) {
		g_listener_ssl_sock = gx_inet_listen(g_listener_addr.c_str(), g_listener_ssl_port);
		if (g_listener_ssl_sock < 0) {
			printf("[listener]: failed to create socket [*]:%hu: %s\n",
			       g_listener_ssl_port, strerror(-g_listener_ssl_sock));
			return -1;
		}
		gx_reexec_record(g_listener_ssl_sock);
	}

	return 0;
}

int listener_trigger_accept()
{
	auto ret = pthread_create4(&g_thr_id, nullptr, p3ls_thrwork,
	           reinterpret_cast<void *>(uintptr_t(false)));
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create4(&g_ssl_thr_id, nullptr, p3ls_thrwork,
		      reinterpret_cast<void *>(uintptr_t(true)));
		if (ret != 0) {
			printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
			return -2;
		}
		pthread_setname_np(g_ssl_thr_id, "tls_accept");
	}
	return 0;
}

void listener_stop_accept()
{
	g_stop_accept = true;
	if (g_listener_sock >= 0)
		shutdown(g_listener_sock, SHUT_RDWR); /* closed in listener_stop */
	if (!pthread_equal(g_thr_id, {})) {
		pthread_kill(g_thr_id, SIGALRM);
		pthread_join(g_thr_id, NULL);
	}
	if (g_listener_ssl_sock >= 0)
		shutdown(g_listener_ssl_sock, SHUT_RDWR);
	if (!pthread_equal(g_ssl_thr_id, {})) {
		pthread_kill(g_ssl_thr_id, SIGALRM);
		pthread_join(g_ssl_thr_id, NULL);
	}
}

static void *p3ls_thrwork(void *arg)
{
	bool use_tls = reinterpret_cast<uintptr_t>(arg);
	socklen_t addrlen;
	int sockd2, client_port, len, flag;
	size_t string_length = 0;
	struct sockaddr_storage fact_addr, client_peer;
	char client_hostip[40], client_txtport[8], server_hostip[40];
	const char *pop3_reply_str, *pop3_reply_str2, *host_ID;
	char buff[1024];
	
	for (;;) {
		addrlen = sizeof(client_peer);
		/* wait for an incoming connection */
		sockd2 = accept(use_tls ? g_listener_ssl_sock : g_listener_sock,
		         reinterpret_cast<struct sockaddr *>(&client_peer), &addrlen);
		if (g_stop_accept) {
			if (sockd2 >= 0)
				close(sockd2);
			return nullptr;
		}
		if (-1 == sockd2) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<sockaddr *>(&client_peer),
		          addrlen, client_hostip, sizeof(client_hostip),
		          client_txtport, sizeof(client_txtport),
		          NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		addrlen = sizeof(fact_addr); 
		ret = getsockname(sockd2, reinterpret_cast<sockaddr *>(&fact_addr), &addrlen);
		if (ret != 0) {
			printf("getsockname: %s\n", strerror(errno));
			close(sockd2);
			continue;
		}
		ret = getnameinfo(reinterpret_cast<sockaddr *>(&fact_addr),
		      addrlen, server_hostip, sizeof(server_hostip),
		      nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		client_port = strtoul(client_txtport, nullptr, 0);
		if (fcntl(sockd2, F_SETFL, O_NONBLOCK) < 0)
			mlog(LV_WARN, "W-1405: fctnl: %s", strerror(errno));
		flag = 1;
		if (setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			mlog(LV_WARN, "W-1339: setsockopt: %s", strerror(errno));
		auto pcontext = static_cast<POP3_CONTEXT *>(contexts_pool_get_context(CONTEXT_FREE));
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			/* 421 <domain> Service not available */
			pop3_reply_str = resource_get_pop3_code(1713, 1, &string_length);
			pop3_reply_str2 = resource_get_pop3_code(1713, 2, &string_length);
			host_ID = resource_get_string("HOST_ID");
			len = sprintf(buff, "%s%s%s", pop3_reply_str, host_ID,
				  pop3_reply_str2);
			write(sockd2, buff, len);
			close(sockd2);
			continue;        
		}
		pcontext->type = CONTEXT_CONSTRUCTING;
		/* pass the client ipaddr into the ipaddr filter */
		if (system_services_judge_ip != nullptr &&
		    !system_services_judge_ip(client_hostip)) {
			/* access denied */
			pop3_reply_str = resource_get_pop3_code(1712, 1, &string_length);
			pop3_reply_str2 = resource_get_pop3_code(1712, 2, &string_length);
			len = sprintf(buff, "%s%s%s", pop3_reply_str, client_hostip,
				  pop3_reply_str2);
			write(sockd2, buff, len);
			mlog(LV_DEBUG, "Connection %s is denied by ipaddr filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			continue;
		}
		/* pass the client ipaddr into the ipaddr container */
		if (system_services_container_add_ip != nullptr &&
		    !system_services_container_add_ip(client_hostip)) {
			/* 421 Access is denied from your IP <remote_ip> for audit ... */
			pop3_reply_str = resource_get_pop3_code(1712, 1, &string_length);
			pop3_reply_str2 = resource_get_pop3_code(1712, 2, &string_length);
			len = sprintf(buff, "%s%s%s", pop3_reply_str, client_hostip,
				  pop3_reply_str2);
			write(sockd2, buff, len);
			mlog(LV_DEBUG, "Connection %s is denied by "
				"ipaddr container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			continue;
		}

		if (!use_tls) {
			/* +OK <domain> Service ready */
			pop3_reply_str = resource_get_pop3_code(1711, 1, &string_length);
			pop3_reply_str2 = resource_get_pop3_code(1711, 2, &string_length);
			host_ID = resource_get_string("HOST_ID");
			len = sprintf(buff, "%s%s%s", pop3_reply_str, host_ID,
			      pop3_reply_str2);
			if (HXio_fullwrite(sockd2, buff, len) != len)
				/* ignore */;
		}
		/* construct the context object */
		pcontext->connection.last_timestamp = tp_now();
		pcontext->connection.sockd             = sockd2;
		pcontext->is_stls                   = use_tls;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = use_tls ? g_listener_ssl_port : g_listener_port;
		gx_strlcpy(pcontext->connection.client_ip, client_hostip, arsizeof(pcontext->connection.client_ip));
		gx_strlcpy(pcontext->connection.server_ip, server_hostip, arsizeof(pcontext->connection.server_ip));
		/* 
		valid the context and wake up one thread if there are some threads
		block on the condition variable 
		*/
		pcontext->polling_mask = POLLING_READ;
		contexts_pool_put_context(pcontext, CONTEXT_POLLING);
	}
	return nullptr;
}

void listener_stop()
{
	if (g_listener_sock >= 0) {
		close(g_listener_sock);
		g_listener_sock = -1;
	}
	if (g_listener_ssl_sock >= 0) {
		close(g_listener_ssl_sock);
		g_listener_ssl_sock = -1;
	}
}
