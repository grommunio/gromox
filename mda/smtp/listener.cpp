// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *    listener is a module, which listen a certain port and if a connection is
 *    coming, pass the connection in connection filter module and if the
 *    connection is legal, construct a context to represent the connection and 
 *    throw it into contexts pool, or close the connection
 */
#include <cerrno>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "listener.h"
#include "system_services.h"
#include "contexts_pool.h"
#include "smtp_parser.h"
#include "util.h"
#include "resource.h"
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <cstring>

static void* thread_work_func(void* arg);

static void* thread_work_ssl_func(void* arg);

static pthread_t g_thr_id;
static BOOL g_stop_accept;
static int g_listener_sock;
static int g_listener_port;
static pthread_t g_ssl_thr_id;
static int g_listener_ssl_sock;
static int g_listener_ssl_port;
/*
 *    istener's construction function
 *    @param    
 *        glistener_port    port to listen
 */
void listener_init(int port, int ssl_port)
{
	g_listener_port = port;
	g_listener_ssl_port = ssl_port;
	g_stop_accept = FALSE;
}

/*
 *    run the listener
 *    @return     
 *         0    success 
 *        -1    fail to create socket for listening
 *        -2    fail to set address for reuse
 *        -3    fail to bind listening socket
 *        -4    fail to listen    
 */
int listener_run()
{
	struct sockaddr_in server_peer;

	int status, optval = 1;

	/* create a socket */
	g_listener_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listener_sock == -1) {
		printf("[listener]: failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	/* Eliminates "Address already in use" error from bind */
	if (setsockopt(g_listener_sock, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval, sizeof(int)) < 0) {
		return -2;
	}

	/* socket binding */
	server_peer.sin_family        = AF_INET;
	server_peer.sin_addr.s_addr = INADDR_ANY;
	server_peer.sin_port         = htons(g_listener_port);

	status = bind(g_listener_sock, (struct sockaddr*)&server_peer, 
		sizeof(server_peer));
	if (status == -1) {
		printf("[listener]: bind *:%u: %s\n", g_listener_port, strerror(errno));
		close(g_listener_sock);
		return -3;
	}
	status = listen(g_listener_sock, 1024);
	if (status == -1) {
		printf("[listener]: fail to listen\n");
		return -4;
	}

	if (g_listener_ssl_port > 0) {
		/* create a socket */
		g_listener_ssl_sock = socket(AF_INET, SOCK_STREAM, 0);
		if (g_listener_ssl_sock == -1) {
			printf("[listener]: failed to create socket: %s\n", strerror(errno));
			return -1;
		}

	    /* Eliminates "Address already in use" error from bind */
		if (setsockopt(g_listener_ssl_sock, SOL_SOCKET, SO_REUSEADDR,
			(const void *)&optval, sizeof(int)) < 0) {
			return -2;
		}

		/* socket binding */
		server_peer.sin_family       = AF_INET;
		server_peer.sin_addr.s_addr  = INADDR_ANY;
		server_peer.sin_port         = htons(g_listener_ssl_port);

		status = bind(g_listener_ssl_sock, (struct sockaddr*)&server_peer, 
			sizeof(server_peer));
		if (status == -1) {
			printf("[listener]: bind *:%u: %s\n", g_listener_ssl_port, strerror(errno));
			close(g_listener_ssl_sock);
			return -3;
		}
		status = listen(g_listener_ssl_sock, 1024);
		if (status == -1) {
			printf("[listener]: fail to listen\n");
			return -4;
		}
	}

	return 0;
}

/*
 *  trigger the listener to accept the connection
 *
 */
int listerner_trigger_accept()
{
	pthread_attr_t  attr;

	pthread_attr_init(&attr);
	int ret = pthread_create(&g_thr_id, &attr, thread_work_func, nullptr);
	if (ret != 0) {
		printf("[listener]: failed to create listener thread: %s\n", strerror(ret));
		pthread_attr_destroy(&attr);
		return -1;
	}
	pthread_setname_np(g_thr_id, "accept");
	if (g_listener_ssl_port > 0) {
		ret = pthread_create(&g_ssl_thr_id, &attr, thread_work_ssl_func, nullptr);
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

/*
 *  stop accept the connection
 */
void listener_stop_accept()
{
	g_stop_accept = TRUE;
	
	shutdown(g_listener_sock, SHUT_RDWR);
	pthread_join(g_thr_id, NULL);
	if (g_listener_ssl_port > 0) {
		shutdown(g_listener_ssl_sock, SHUT_RDWR);
		pthread_join(g_ssl_thr_id, NULL);
	}
}

/*
 * listener's thread work function
 *
 */
static void* thread_work_func(void* arg)
{
	socklen_t addrlen;
	int sockd2, client_port;
	int string_length, len, flag;
	struct sockaddr_storage fact_addr, client_peer;
	char client_hostip[32], client_txtport[32], server_hostip[32];
	SMTP_CONTEXT *pcontext;
	const char *smtp_reply_str, *smtp_reply_str2, *host_ID;
	char buff[1024];
	
	for (;;) {
		addrlen = sizeof(client_peer);
		/* wait for an incoming connection */
		sockd2 = accept(g_listener_sock, (struct sockaddr*)&client_peer, 
			&addrlen);
		if (TRUE == g_stop_accept) {
			pthread_exit(0);
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
		system_services_log_info(0, "new connection %s:%d is now incoming", 
					client_hostip, client_port);
		fcntl(sockd2, F_SETFL, O_NONBLOCK);
		flag = 1;
		setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
		pcontext = (SMTP_CONTEXT*)contexts_pool_get_context(CONTEXT_FREE);
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			/* 421 <domain> Service not available */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174001, 1,
							 &string_length);
			smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2174001, 2,
							 &string_length);
			host_ID = resource_get_string("HOST_ID");
			len = sprintf(buff, "%s%s%s", smtp_reply_str, host_ID,
				  smtp_reply_str2);
			write(sockd2, buff, len);
			close(sockd2);
			continue;        
		}
		((SCHEDULE_CONTEXT*)pcontext)->type = CONTEXT_CONSTRUCTING;
		/* pass the client ipaddr into the ipaddr filter */
		if (system_services_judge_ip != nullptr &&
		    !system_services_judge_ip(client_hostip)) {
			/* access denied */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174007, 1,
							 &string_length);
			smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2174007, 2,
							 &string_length);
			len = sprintf(buff, "%s%s%s", smtp_reply_str, client_hostip,
				  smtp_reply_str2);
			write(sockd2, buff, len);
			system_services_log_info(8, "connection %s is denied by ipaddr filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		/* pass the client ipaddr into the ipaddr container */
		if (FALSE == system_services_container_add_ip(client_hostip)) {
			/* 421 Access is denied from your IP address <remote_ip> for audit ... */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174007, 1,
							 &string_length);
			smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2174007, 2,
							 &string_length);
			len = sprintf(buff, "%s%s%s", smtp_reply_str, client_hostip,
				  smtp_reply_str2);
			write(sockd2, buff, len);
			system_services_log_info(8, "connection %s is denied by "
				"ipaddr container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		/* 220 <domain> Service ready */
		smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2172002, 1,
						 &string_length);
		smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2172002, 2,
						 &string_length);
		host_ID = resource_get_string("HOST_ID");
		len = sprintf(buff, "%s%s%s", smtp_reply_str, host_ID,
			  smtp_reply_str2);
		write(sockd2, buff, len);
		/* construct the context object */
		gettimeofday(&pcontext->connection.last_timestamp, NULL);
		pcontext->connection.sockd             = sockd2;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = g_listener_port;
		HX_strlcpy(pcontext->connection.client_ip, client_hostip, GX_ARRAY_SIZE(pcontext->connection.client_ip));
		HX_strlcpy(pcontext->connection.server_ip, server_hostip, GX_ARRAY_SIZE(pcontext->connection.server_ip));
		/* 
		valid the context and wake up one thread if there're some threads 
		block on the condition variable 
		*/
		((SCHEDULE_CONTEXT*)pcontext)->polling_mask = POLLING_READ;
		contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext, CONTEXT_POLLING);  
	}
	return 0;
}

/*
 * ssl listener's thread work function
 *
 */
static void* thread_work_ssl_func(void* arg)
{
	socklen_t addrlen;
	int sockd2, client_port;
	int string_length, len, flag;
	struct sockaddr_storage fact_addr, client_peer;
	char client_hostip[32], client_txtport[32], server_hostip[32];
	SMTP_CONTEXT *pcontext;
	const char *smtp_reply_str, *smtp_reply_str2, *host_ID;
	char buff[1024];
	
	for (;;) {
		addrlen = sizeof(client_peer);
		/* wait for an incoming connection */
		sockd2 = accept(g_listener_ssl_sock, (struct sockaddr*)&client_peer, 
			&addrlen);
		if (TRUE == g_stop_accept) {
			pthread_exit(0);
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
		system_services_log_info(0, "ssl new connection %s:%d is now incoming", 
					client_hostip, client_port);
		fcntl(sockd2, F_SETFL, O_NONBLOCK);
		flag = 1;
		setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
		pcontext = (SMTP_CONTEXT*)contexts_pool_get_context(CONTEXT_FREE);
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			/* 421 <domain> Service not available */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174001, 1,
							 &string_length);
			smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2174001, 2,
							 &string_length);
			host_ID = resource_get_string("HOST_ID");
			len = sprintf(buff, "%s%s%s", smtp_reply_str, host_ID,
				  smtp_reply_str2);
			write(sockd2, buff, len);
			close(sockd2);
			continue;        
		}
		((SCHEDULE_CONTEXT*)pcontext)->type = CONTEXT_CONSTRUCTING;
		/* pass the client ipaddr into the ipaddr filter */
		if (system_services_judge_ip != nullptr &&
		    !system_services_judge_ip(client_hostip)) {
			/* access denied */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174007, 1,
							 &string_length);
			smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2174007, 2,
							 &string_length);
			len = sprintf(buff, "%s%s%s", smtp_reply_str, client_hostip,
				  smtp_reply_str2);
			write(sockd2, buff, len);
			system_services_log_info(8, "SSL connection %s is denied by ipaddr filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		/* pass the client ipaddr into the ipaddr container */
		if (FALSE == system_services_container_add_ip(client_hostip)) {
			/* 421 Access is denied from your IP address <remote_ip> for audit ... */
			smtp_reply_str = resource_get_smtp_code(SMTP_CODE_2174007, 1,
							 &string_length);
			smtp_reply_str2 = resource_get_smtp_code(SMTP_CODE_2174007, 2,
							 &string_length);
			len = sprintf(buff, "%s%s%s", smtp_reply_str, client_hostip,
				  smtp_reply_str2);
			write(sockd2, buff, len);
			system_services_log_info(8, "ssl connection %s is denied by "
				"ipaddr container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		/* construct the context object */
		gettimeofday(&pcontext->connection.last_timestamp, NULL);
		pcontext->connection.sockd             = sockd2;
		pcontext->last_cmd                     = T_STARTTLS_CMD;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = g_listener_ssl_port;
		HX_strlcpy(pcontext->connection.client_ip, client_hostip, GX_ARRAY_SIZE(pcontext->connection.client_ip));
		HX_strlcpy(pcontext->connection.server_ip, server_hostip, GX_ARRAY_SIZE(pcontext->connection.server_ip));
		/* 
		valid the context and wake up one thread if there're some threads 
		block on the condition variable 
		*/
		((SCHEDULE_CONTEXT*)pcontext)->polling_mask = POLLING_READ;
		contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext, CONTEXT_POLLING);  
	}
	return 0;
}

/*
 *    stop listener
 *    @return     
		0    success
*/
int listener_stop()
{
	if (g_listener_sock > 2) {
		close(g_listener_sock);
	}
	if (g_listener_ssl_port > 0 && g_listener_ssl_port > 2) {
		close(g_listener_ssl_sock);
	}
	return 0;
}


/*
 *    listener's destruction function
 */
void listener_free()
{
	g_listener_port = 0;
	g_listener_ssl_port = 0;
}

