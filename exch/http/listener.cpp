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
#include <unistd.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/fileio.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include "http_parser.h"
#include "listener.h"
#include "resource.h"
#include "system_services.h"

using namespace gromox;

static void *htls_thrwork(void *);
static void *htls_thrworkssl(void *);

static int g_mss_size;
static gromox::atomic_bool g_stop_accept;
static pthread_t g_thr_id;
static int g_listener_sock = -1, g_listener_ssl_sock = -1;
static uint16_t g_listener_port, g_listener_ssl_port;
static pthread_t g_ssl_thr_id;

void listener_init(uint16_t port, uint16_t ssl_port, int mss_size)
{
	g_listener_port = port;
	g_listener_ssl_port = ssl_port;
	g_mss_size = mss_size;
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
	g_listener_sock = gx_inet_listen("::", g_listener_port);
	if (g_listener_sock < 0) {
		printf("[listener]: failed to create socket [*]:%hu: %s\n",
		       g_listener_port, strerror(-g_listener_sock));
		return -1;
	}
	gx_reexec_record(g_listener_sock);
	if (g_mss_size > 0 &&
	    setsockopt(g_listener_sock, IPPROTO_TCP, TCP_MAXSEG,
	    &g_mss_size, sizeof(g_mss_size)) < 0)
		return -2;
	
	if (g_listener_ssl_port > 0) {
		g_listener_ssl_sock = gx_inet_listen("::", g_listener_ssl_port);
		if (g_listener_ssl_sock < 0) {
			printf("[listener]: failed to create socket [*]:%hu: %s\n",
			       g_listener_ssl_port, strerror(-g_listener_ssl_sock));
			return -1;
		}
		gx_reexec_record(g_listener_ssl_sock);
		if (g_mss_size > 0 &&
		    setsockopt(g_listener_ssl_sock, IPPROTO_TCP, TCP_MAXSEG,
		    &g_mss_size, sizeof(g_mss_size)) < 0)
			return -2;
	}

	return 0;
}

int listener_trigger_accept()
{
	pthread_attr_t  attr;

	pthread_attr_init(&attr);
	auto ret = pthread_create(&g_thr_id, &attr, htls_thrwork, nullptr);
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		pthread_attr_destroy(&attr);
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create(&g_ssl_thr_id, &attr, htls_thrworkssl, nullptr);
		if (ret != 0) {
			printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
			pthread_attr_destroy(&attr);
			return -2;
		}
		pthread_setname_np(g_ssl_thr_id, "tls_accept");
	}
	pthread_attr_destroy(&attr);
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

static void *htls_thrwork(void *arg)
{
	socklen_t addrlen;
	int len, flag, sockd2;
	struct sockaddr_storage fact_addr, client_peer;
	char client_hostip[40], client_txtport[8], server_hostip[40];
	HTTP_CONTEXT *pcontext;
	char buff[1024];
	
	for (;;) {
		addrlen = sizeof(client_peer);
		/* wait for an incoming connection */
		sockd2 = accept(g_listener_sock, (struct sockaddr*)&client_peer, 
			&addrlen);
		if (g_stop_accept) {
			if (sockd2 >= 0)
				close(sockd2);
			return nullptr;
		}
		if (-1 == sockd2) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&client_peer),
		          addrlen, client_hostip, sizeof(client_hostip),
		          client_txtport, sizeof(client_txtport),
		          NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		addrlen = sizeof(fact_addr); 
		ret = getsockname(sockd2, reinterpret_cast<struct sockaddr *>(&fact_addr), &addrlen);
		if (ret != 0) {
			printf("getsockname: %s\n", strerror(errno));
			close(sockd2);
			continue;
		}
		ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&fact_addr),
		      addrlen, server_hostip, sizeof(server_hostip),
		      nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getsockname: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		uint16_t client_port = strtoul(client_txtport, nullptr, 0);
		system_services_log_info(LV_DEBUG, "New connection from [%s]:%hu",
			client_hostip, client_port);
		if (fcntl(sockd2, F_SETFL, O_NONBLOCK) < 0)
			fprintf(stderr, "W-1408: fcntl: %s\n", strerror(errno));
		flag = 1;
		if (setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			fprintf(stderr, "W-1409: setsockopt: %s\n", strerror(errno));
		pcontext = (HTTP_CONTEXT*)contexts_pool_get_context(CONTEXT_FREE);
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			system_services_log_info(LV_NOTICE, "no available HTTP_CONTEXT/processing slot");
			len = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "HTTP/1.1 503 L-202 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			write(sockd2, buff, len);
			close(sockd2);
			continue;
		}
		pcontext->type = CONTEXT_CONSTRUCTING;
		/* pass the client ipaddr into the ipaddr filter */
		if (system_services_judge_ip != nullptr &&
		    !system_services_judge_ip(client_hostip)) {
			len = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "HTTP/1.1 503 L-216 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			write(sockd2, buff, len);
			system_services_log_info(LV_DEBUG, "Connection %s is denied by ipaddr filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			continue;
		}
		/* pass the client ipaddr into the ipaddr container */
		if (system_services_container_add_ip != nullptr &&
		    !system_services_container_add_ip(client_hostip)) {
			len = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "HTTP/1.1 503 L-234 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			write(sockd2, buff, len);
			system_services_log_info(LV_DEBUG, "Connection %s is denied by "
				"ipaddr container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			continue;
		}

		/* construct the context object */
		pcontext->connection.last_timestamp = time_point::clock::now();
		pcontext->connection.sockd          = sockd2;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = g_listener_port;
		gx_strlcpy(pcontext->connection.client_ip, client_hostip, GX_ARRAY_SIZE(pcontext->connection.client_ip));
		gx_strlcpy(pcontext->connection.server_ip, server_hostip, GX_ARRAY_SIZE(pcontext->connection.server_ip));
		pcontext->sched_stat                = SCHED_STAT_RDHEAD;
		/* 
		valid the context and wake up one thread if there are some threads
		block on the condition variable 
		*/
		pcontext->polling_mask = POLLING_READ;
		contexts_pool_put_context(pcontext, CONTEXT_POLLING);
	}
	return nullptr;
}

static void *htls_thrworkssl(void *arg)
{
	socklen_t addrlen;
	int len, flag, sockd2;
	struct sockaddr_storage fact_addr, client_peer;
	char client_hostip[40], client_txtport[8], server_hostip[40];
	HTTP_CONTEXT *pcontext;
	char buff[1024];
	
	for (;;) {
		addrlen = sizeof(client_peer);
		/* wait for an incoming connection */
		sockd2 = accept(g_listener_ssl_sock, (struct sockaddr*)&client_peer, 
			&addrlen);
		if (g_stop_accept) {
			if (sockd2 >= 0)
				close(sockd2);
			return nullptr;
		}
		if (-1 == sockd2) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&client_peer),
		          addrlen, client_hostip, sizeof(client_hostip),
		          client_txtport, sizeof(client_txtport),
		          NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		addrlen = sizeof(fact_addr); 
		ret = getsockname(sockd2, reinterpret_cast<struct sockaddr *>(&fact_addr), &addrlen);
		if (ret != 0) {
			printf("getsockname: %s\n", strerror(errno));
			close(sockd2);
			continue;
		}
		ret = getnameinfo(reinterpret_cast<struct sockaddr *>(&fact_addr),
		      addrlen, server_hostip, sizeof(server_hostip),
		      nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		uint16_t client_port = strtoul(client_txtport, nullptr, 0);
		system_services_log_info(LV_DEBUG, "New TLS connection from [%s]:%hu",
					client_hostip, client_port);
		if (fcntl(sockd2, F_SETFL, O_NONBLOCK) < 0)
			fprintf(stderr, "W-1410: fcntl: %s\n", strerror(errno));
		flag = 1;
		if (setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
			fprintf(stderr, "W-1411: setsockopt: %s\n", strerror(errno));
		pcontext = (HTTP_CONTEXT*)contexts_pool_get_context(CONTEXT_FREE);
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			system_services_log_info(LV_NOTICE, "no available HTTP_CONTEXT/processing slot");
			len = sprintf(buff, "HTTP/1.1 503 L-332 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			write(sockd2, buff, len);
			close(sockd2);
			continue;
		}
		pcontext->type = CONTEXT_CONSTRUCTING;
		/* pass the client ipaddr into the ipaddr filter */
		if (system_services_judge_ip != nullptr &&
		    !system_services_judge_ip(client_hostip)) {
			len = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "HTTP/1.1 503 L-346 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			write(sockd2, buff, len);
			system_services_log_info(LV_DEBUG, "TLS connection %s is denied by ipaddr filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			continue;
		}
		/* pass the client ipaddr into the ipaddr container */
		if (system_services_container_add_ip != nullptr &&
		    !system_services_container_add_ip(client_hostip)) {
			len = gx_snprintf(buff, GX_ARRAY_SIZE(buff), "HTTP/1.1 503 L-364 Service Unavailable\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n");
			write(sockd2, buff, len);
			system_services_log_info(LV_DEBUG, "TLS connection %s is denied by "
				"ipaddr container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context(pcontext, CONTEXT_FREE);
			continue;
		}
		
		/* construct the context object */
		pcontext->connection.last_timestamp = time_point::clock::now();
		pcontext->connection.sockd          = sockd2;
		pcontext->sched_stat                = SCHED_STAT_INITSSL;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = g_listener_ssl_port;
		gx_strlcpy(pcontext->connection.client_ip, client_hostip, GX_ARRAY_SIZE(pcontext->connection.client_ip));
		gx_strlcpy(pcontext->connection.server_ip, server_hostip, GX_ARRAY_SIZE(pcontext->connection.server_ip));
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
