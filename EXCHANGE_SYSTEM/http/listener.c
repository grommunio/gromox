/*
 *    listener is a modlue, which listen a certain port and if a connection is 
 *    coming, pass the connection in connection filter module and if the
 *    connection is legal, construct a context to represent the connection and 
 *    throw it into contexts pool, or close the connection
 */
#include "listener.h"
#include "system_services.h"
#include "contexts_pool.h"
#include "http_parser.h"
#include "util.h"
#include "resource.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>

static void* thread_work_func(void* arg);

static void* thread_work_ssl_func(void* arg);

static int g_mss_size;
static BOOL g_stop_accept;
static pthread_t g_thr_id;
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
void listener_init(int port, int ssl_port, int mss_size)
{
	g_listener_port = port;
	g_listener_ssl_port = ssl_port;
	g_mss_size = mss_size;
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
	int status, optval;
	struct sockaddr_in server_peer;

	/* create a socket */
	g_listener_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listener_sock == -1) {
		printf("[listener]: fail to create socket\n");
		return -1;
	}
	
	optval = 1;
	/* Eliminates "Address already in use" error from bind */
	if (setsockopt(g_listener_sock, SOL_SOCKET, SO_REUSEADDR,
		(const void*)&optval, sizeof(int)) < 0) {
		return -2;
	}
	
	if (g_mss_size > 0) {
		if (setsockopt(g_listener_sock, IPPROTO_TCP, TCP_MAXSEG,
			(const void*)&g_mss_size, sizeof(int)) < 0) {
			return -2;	
		}
	}
	
	/* socket binding */
	server_peer.sin_family			= AF_INET;
	server_peer.sin_addr.s_addr		= INADDR_ANY;
	server_peer.sin_port			= htons(g_listener_port);

	status = bind(g_listener_sock, (struct sockaddr*)&server_peer, 
		sizeof(server_peer));
	if (status == -1) {
		printf("[listener]: fail to bind\n");
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
			printf("[listener]: fail to create socket\n");
			return -1;
		}
		
		optval = 1;
		/* Eliminates "Address already in use" error from bind */
		if (setsockopt(g_listener_ssl_sock, SOL_SOCKET, SO_REUSEADDR,
			(const void*)&optval, sizeof(int)) < 0) {
			return -2;
		}
		
		if (g_mss_size > 0) {
			if (setsockopt(g_listener_ssl_sock, IPPROTO_TCP, TCP_MAXSEG,
				(const void*)&g_mss_size, sizeof(int)) < 0) {
				return -2;	
			}
		}
		
		/* socket binding */
		server_peer.sin_family       = AF_INET;
		server_peer.sin_addr.s_addr  = INADDR_ANY;
		server_peer.sin_port         = htons(g_listener_ssl_port);
		
		status = bind(g_listener_ssl_sock, (struct sockaddr*)&server_peer, 
			sizeof(server_peer));
		if (status == -1) {
			printf("[listener]: fail to bind\n");
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
 */
int listerner_trigger_accept()
{
	pthread_attr_t  attr;

	pthread_attr_init(&attr);
	if(0 != pthread_create(&g_thr_id, &attr, thread_work_func, NULL)){
		printf("[listener]: fail to create listener thread\n");
		pthread_attr_destroy(&attr);
		return -1;
	}
	if (g_listener_ssl_port > 0) {
		if(0 != pthread_create(&g_ssl_thr_id,
			&attr, thread_work_ssl_func, NULL)){
			printf("[listener]: fail to create listener thread\n");
			pthread_attr_destroy(&attr);
			return -2;
		}
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
	struct sockaddr_in fact_addr, client_peer;
	char client_hostip[16], server_hostip[16];
	HTTP_CONTEXT *pcontext;
	const char *http_reply_str, *http_reply_str2, *host_ID;
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
		addrlen = sizeof(fact_addr); 
		getsockname(sockd2, (struct sockaddr*)&fact_addr, &addrlen);
		strcpy(client_hostip, inet_ntoa(client_peer.sin_addr));
		strcpy(server_hostip, inet_ntoa(fact_addr.sin_addr));
		client_port=ntohs(client_peer.sin_port);
		system_services_log_info(0, "new connection %s:%d "
			"is now incoming", client_hostip, client_port);
		fcntl(sockd2, F_SETFL, O_NONBLOCK);
		flag = 1;
		setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY,
				(const void*)&flag, sizeof(flag));
		pcontext = (HTTP_CONTEXT*)contexts_pool_get_context(CONTEXT_FREE);
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			system_services_log_info(8, "out of http context");
			host_ID = resource_get_string(RES_HOST_ID);
			len = snprintf(buff, 1024, "HTTP/1.1 503 Service Unavailable\r\n"
								"Server: %s\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n""", host_ID);
			write(sockd2, buff, len);
			close(sockd2);
			continue;
		}
		((SCHEDULE_CONTEXT*)pcontext)->type = CONTEXT_CONSTRUCTING;
		/* pass the client IP into the IP filter */
		if (FALSE == system_services_judge_ip(client_hostip)) {
			host_ID = resource_get_string(RES_HOST_ID);
			len = snprintf(buff, 1024, "HTTP/1.1 503 Service Unavailable\r\n"
								"Server: %s\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n""", host_ID);
			write(sockd2, buff, len);
			system_services_log_info(8, "connection %s is denied by ip filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		/* pass the client IP into the IP container */
		if (FALSE == system_services_container_add_ip(client_hostip)) {
			host_ID = resource_get_string(RES_HOST_ID);
			len = snprintf(buff, 1024, "HTTP/1.1 503 Service Unavailable\r\n"
								"Server: %s\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n""", host_ID);
			write(sockd2, buff, len);
			system_services_log_info(8, "connection %s is denied by "
				"ip container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		
SERVICE_AVAILABLE:
		/* construct the context object */
		gettimeofday(&pcontext->connection.last_timestamp, NULL);
		pcontext->connection.sockd          = sockd2;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = g_listener_port;
		strcpy(pcontext->connection.client_ip, client_hostip);
		strcpy(pcontext->connection.server_ip, server_hostip);
		pcontext->sched_stat                = SCHED_STAT_RDHEAD;
		/* 
		valid the context and wake up one thread if there're some threads 
		block on the condition variable 
		*/
		((SCHEDULE_CONTEXT*)pcontext)->polling_mask = POLLING_READ;
		contexts_pool_put_context(
			(SCHEDULE_CONTEXT*)pcontext, CONTEXT_POLLING);  
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
	struct sockaddr_in fact_addr, client_peer;
	char client_hostip[16], server_hostip[16];
	HTTP_CONTEXT *pcontext;
	const char *http_reply_str, *http_reply_str2, *host_ID;
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
		addrlen = sizeof(fact_addr); 
		getsockname(sockd2, (struct sockaddr*)&fact_addr, &addrlen);
		strcpy(client_hostip, inet_ntoa(client_peer.sin_addr));
		strcpy(server_hostip, inet_ntoa(fact_addr.sin_addr));
		client_port=ntohs(client_peer.sin_port);
		system_services_log_info(0, "ssl new connection %s:%d is now incoming", 
					client_hostip, client_port);
		fcntl(sockd2, F_SETFL, O_NONBLOCK);
		flag = 1;
		setsockopt(sockd2, IPPROTO_TCP, TCP_NODELAY,
				(const void*)&flag, sizeof(flag));
		pcontext = (HTTP_CONTEXT*)contexts_pool_get_context(CONTEXT_FREE);
		/* there's no context available in contexts pool, close the connection*/
		if (NULL == pcontext) {
			system_services_log_info(8, "out of http context");
			host_ID = resource_get_string(RES_HOST_ID);
			len = sprintf(buff, "HTTP/1.1 503 Service Unavailable\r\n"
								"Server: %s\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n""", host_ID);
			write(sockd2, buff, len);
			close(sockd2);
			continue;
		}
		((SCHEDULE_CONTEXT*)pcontext)->type = CONTEXT_CONSTRUCTING;
		/* pass the client IP into the IP filter */
		if (FALSE == system_services_judge_ip(client_hostip)) {
		   host_ID = resource_get_string(RES_HOST_ID);
			len = snprintf(buff, 1024, "HTTP/1.1 503 Service Unavailable\r\n"
								"Server: %s\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n""", host_ID);
			write(sockd2, buff, len);
			system_services_log_info(8, "ssl connection %s is denied by ip filter",
				client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		/* pass the client IP into the IP container */
		if (FALSE == system_services_container_add_ip(client_hostip)) {
			host_ID = resource_get_string(RES_HOST_ID);
			len = snprintf(buff, 1024, "HTTP/1.1 503 Service Unavailable\r\n"
								"Server: %s\r\n"
								"Content-Length: 0\r\n"
								"Connection: close\r\n"
								"\r\n""", host_ID);
			write(sockd2, buff, len);
			system_services_log_info(8, "ssl connection %s is denied by "
				"ip container", client_hostip);
			close(sockd2);
			/* release the context */
			contexts_pool_put_context((SCHEDULE_CONTEXT*)pcontext,
									  CONTEXT_FREE);
			continue;
		}
		
SERVICE_AVAILABLE:
		/* construct the context object */
		gettimeofday(&pcontext->connection.last_timestamp, NULL);
		pcontext->connection.sockd          = sockd2;
		pcontext->sched_stat                = SCHED_STAT_INITSSL;
		pcontext->connection.client_port    = client_port;
		pcontext->connection.server_port    = g_listener_ssl_port;
		strcpy(pcontext->connection.client_ip, client_hostip);
		strcpy(pcontext->connection.server_ip, server_hostip);
		/* 
		valid the context and wake up one thread if there're some threads 
		block on the condition variable 
		*/
		((SCHEDULE_CONTEXT*)pcontext)->polling_mask = POLLING_READ;
		contexts_pool_put_context(
			(SCHEDULE_CONTEXT*)pcontext, CONTEXT_POLLING);  
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

