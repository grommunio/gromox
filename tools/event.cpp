// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#include <gromox/fifo.hpp>
#include <gromox/str_hash.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/list_file.hpp>
#include <gromox/config_file.hpp>
#include <gromox/double_list.hpp>
#include <ctime>
#include <cstdio>
#include <unistd.h>
#include <csignal>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define SOCKET_TIMEOUT			60

#define SELECT_INTERVAL			24*60*60

#define HOST_INTERVAL			20*60

#define SCAN_INTERVAL			10*60

#define FIFO_AVERAGE_LENGTH		128

#define MAX_CMD_LENGTH			64*1024

#define HASH_CAPABILITY			10000

using namespace gromox;

struct ENQUEUE_NODE {
	DOUBLE_LIST_NODE node;
	char res_id[128];
	int sockd;
	int offset;
	char buffer[MAX_CMD_LENGTH];
	char line[MAX_CMD_LENGTH];
};

struct DEQUEUE_NODE {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_host;
	char res_id[128];
	int sockd;
	FIFO fifo;
	pthread_mutex_t lock;
	pthread_mutex_t cond_mutex;
	pthread_cond_t waken_cond;
};

struct HOST_NODE {
	DOUBLE_LIST_NODE node;
	char res_id[128];
	time_t last_time;
	STR_HASH_TABLE *phash;
	DOUBLE_LIST list;
};

static BOOL g_notify_stop = FALSE;
static int g_threads_num;
static LIB_BUFFER *g_fifo_alloc;
static LIB_BUFFER *g_file_alloc;
static std::vector<std::string> g_acl_list;
static DOUBLE_LIST g_enqueue_list;
static DOUBLE_LIST g_enqueue_list1;
static DOUBLE_LIST g_dequeue_list;
static DOUBLE_LIST g_dequeue_list1;
static DOUBLE_LIST g_host_list;
static pthread_mutex_t g_enqueue_lock;
static pthread_mutex_t g_dequeue_lock;
static pthread_mutex_t g_host_lock;
static pthread_mutex_t g_enqueue_cond_mutex;
static pthread_cond_t g_enqueue_waken_cond;
static pthread_mutex_t g_dequeue_cond_mutex;
static pthread_cond_t g_dequeue_waken_cond;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void* accept_work_func(void *param);

static void* enqueue_work_func(void *param);

static void* dequeue_work_func(void *param);

static void* scan_work_func(void *param);

static BOOL read_response(int sockd);

static BOOL read_mark(ENQUEUE_NODE *penqueue);

static void term_handler(int signo);

int main(int argc, const char **argv)
{
	int i;
	int listen_port;
	pthread_t thr_id;
	pthread_t *en_ids;
	pthread_t *de_ids;
	char listen_ip[40];
	ENQUEUE_NODE *penqueue;
	DEQUEUE_NODE *pdequeue;
	DOUBLE_LIST_NODE *pnode;
	pthread_attr_t thr_attr;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	auto pconfig = config_file_prg(opt_config_file, "event.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	char config_dir[256];
	auto str_value = config_file_get_value(pconfig, "config_file_path");
	HX_strlcpy(config_dir, str_value != nullptr ? str_value :
	           PKGSYSCONFDIR "/event:" PKGSYSCONFDIR, GX_ARRAY_SIZE(config_dir));
	str_value = config_file_get_value(pconfig, "EVENT_LISTEN_IP");
	HX_strlcpy(listen_ip, str_value != nullptr ? str_value : "::1",
	           GX_ARRAY_SIZE(listen_ip));

	str_value = config_file_get_value(pconfig, "EVENT_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 33333;
		config_file_set_value(pconfig, "EVENT_LISTEN_PORT", "33333");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 33333;
			config_file_set_value(pconfig, "EVENT_LISTEN_PORT", "33333");
		}
	}
	printf("[system]: listen address is [%s]:%d\n",
	       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

	str_value = config_file_get_value(pconfig, "EVENT_THREADS_NUM");
	if (NULL == str_value) {
		g_threads_num = 50;
		config_file_set_value(pconfig, "EVENT_THREADS_NUM", "50");
	} else {
		g_threads_num = atoi(str_value);
		if (g_threads_num < 1) {
			g_threads_num = 1;
			config_file_set_value(pconfig, "EVENT_THREADS_NUM", "20");
		}
		if (g_threads_num > 1000) {
			g_threads_num = 1000;
			config_file_set_value(pconfig, "EVENT_THREADS_NUM", "1000");
		}
	}

	printf("[system]: threads number is 2*%d\n", g_threads_num);
	
	g_threads_num ++;
	g_fifo_alloc = fifo_allocator_init(sizeof(MEM_FILE),
					g_threads_num*FIFO_AVERAGE_LENGTH, TRUE);
	if (NULL == g_fifo_alloc) {
		printf("[system]: Failed to init queue allocator\n");
		return 3;
	}
	
	g_file_alloc = lib_buffer_init(FILE_ALLOC_SIZE,
					g_threads_num*FIFO_AVERAGE_LENGTH, TRUE);
	if (NULL == g_file_alloc) {
		fifo_allocator_free(g_fifo_alloc);
		printf("[system]: Failed to init file allocator\n");
		return 4;
	}
	
	auto sockd = gx_inet_listen(listen_ip, listen_port);
	if (sockd < 0) {
		lib_buffer_free(g_file_alloc);
		fifo_allocator_free(g_fifo_alloc);
		printf("[system]: failed to create listen socket: %s\n", strerror(-sockd));
		return 5;
	}
	pthread_mutex_init(&g_enqueue_lock, NULL);
	pthread_mutex_init(&g_dequeue_lock, NULL);
	pthread_mutex_init(&g_host_lock, NULL);
	pthread_mutex_init(&g_enqueue_cond_mutex, NULL);
	pthread_cond_init(&g_enqueue_waken_cond, NULL);
	pthread_mutex_init(&g_dequeue_cond_mutex, NULL);
	pthread_cond_init(&g_dequeue_waken_cond, NULL);
	double_list_init(&g_enqueue_list);
	double_list_init(&g_enqueue_list1);
	double_list_init(&g_dequeue_list);
	double_list_init(&g_dequeue_list1);
	double_list_init(&g_host_list);
	

	en_ids = (pthread_t*)malloc(g_threads_num*sizeof(pthread_t));
	
	pthread_attr_init(&thr_attr);

	pthread_attr_setstacksize(&thr_attr, 1024*1024);
	

	for (i=0; i<g_threads_num; i++) {
		int ret = pthread_create(&en_ids[i], &thr_attr, enqueue_work_func, nullptr);
		if (ret != 0) {
			printf("[system]: failed to create enqueue pool thread: %s\n", strerror(ret));
			break;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "enqueue/%u", i);
		pthread_setname_np(en_ids[i], buf);
	}

	if (i != g_threads_num) {
		for (i-=1; i>=0; i--) {
			pthread_cancel(en_ids[i]);
		}
		free(en_ids);
		
		close(sockd);
		lib_buffer_free(g_file_alloc);
		fifo_allocator_free(g_fifo_alloc);
		double_list_free(&g_enqueue_list);
		double_list_free(&g_enqueue_list1);
		double_list_free(&g_dequeue_list);
		double_list_free(&g_dequeue_list1);
		double_list_free(&g_host_list);

		pthread_mutex_destroy(&g_enqueue_lock);
		pthread_mutex_destroy(&g_dequeue_lock);
		pthread_mutex_destroy(&g_host_lock);
		pthread_mutex_destroy(&g_enqueue_cond_mutex);
		pthread_cond_destroy(&g_enqueue_waken_cond);
		pthread_mutex_destroy(&g_dequeue_cond_mutex);
		pthread_cond_destroy(&g_dequeue_waken_cond);
		return 8;
	}
	
	de_ids = (pthread_t*)malloc(g_threads_num*sizeof(pthread_t));
	
	for (i=0; i<g_threads_num; i++) {
		int ret = pthread_create(&de_ids[i], &thr_attr, dequeue_work_func, nullptr);
		if (ret != 0) {
			printf("[system]: failed to create dequeue pool thread: %s\n", strerror(ret));
			break;
		}
		char buf[32];
		snprintf(buf, sizeof(buf), "dequeue/%u", i);
		pthread_setname_np(de_ids[i], buf);
	}
	
	if (i != g_threads_num) {
		for (i-=1; i>=0; i--) {
			pthread_cancel(de_ids[i]);
		}
		free(de_ids);
		for (i=0; i<g_threads_num; i++) {
			pthread_cancel(en_ids[i]);
		}
		free(de_ids);
		
		close(sockd);
		lib_buffer_free(g_file_alloc);
		fifo_allocator_free(g_fifo_alloc);
		double_list_free(&g_enqueue_list);
		double_list_free(&g_enqueue_list1);
		double_list_free(&g_dequeue_list);
		double_list_free(&g_dequeue_list1);
		double_list_free(&g_host_list);

		pthread_mutex_destroy(&g_enqueue_lock);
		pthread_mutex_destroy(&g_dequeue_lock);
		pthread_mutex_destroy(&g_host_lock);
		pthread_mutex_destroy(&g_enqueue_cond_mutex);
		pthread_cond_destroy(&g_enqueue_waken_cond);
		pthread_mutex_destroy(&g_dequeue_cond_mutex);
		pthread_cond_destroy(&g_dequeue_waken_cond);
		return 9;
	}
	
	pthread_attr_destroy(&thr_attr);

	auto ret = list_file_read_fixedstrings("event_acl.txt", config_dir, g_acl_list);
	if (ret == -ENOENT) {
		printf("[system]: defaulting to implicit access ACL containing ::1.\n");
		g_acl_list = {"::1"};
	} else if (ret < 0) {
		printf("[system]: list_file_initd event_acl.txt: %s\n", strerror(-ret));
		for (i=0; i<g_threads_num; i++) {
			pthread_cancel(en_ids[i]);
		}
		free(en_ids);
		for (i=0; i<g_threads_num; i++) {
			pthread_cancel(de_ids[i]);
		}
		free(de_ids);
		close(sockd);
		lib_buffer_free(g_file_alloc);
		fifo_allocator_free(g_fifo_alloc);
		double_list_free(&g_enqueue_list);
		double_list_free(&g_enqueue_list1);
		double_list_free(&g_dequeue_list);
		double_list_free(&g_dequeue_list1);
		double_list_free(&g_host_list);
		pthread_mutex_destroy(&g_enqueue_lock);
		pthread_mutex_destroy(&g_dequeue_lock);
		pthread_mutex_destroy(&g_host_lock);
		pthread_mutex_destroy(&g_enqueue_cond_mutex);
		pthread_cond_destroy(&g_enqueue_waken_cond);
		pthread_mutex_destroy(&g_dequeue_cond_mutex);
		pthread_cond_destroy(&g_dequeue_waken_cond);
		return 10;
	}

	if ((ret = pthread_create(&thr_id, nullptr, accept_work_func,
	    reinterpret_cast<void *>(static_cast<intptr_t>(sockd))) != 0) ||
	    (ret = pthread_create(&thr_id, nullptr, scan_work_func, nullptr)) != 0) {
		printf("[system]: failed to create accept or scanning thread: %s\n", strerror(ret));
		for (i=0; i<g_threads_num; i++) {
			pthread_cancel(en_ids[i]);
		}
		free(en_ids);
		for (i=0; i<g_threads_num; i++) {
			pthread_cancel(de_ids[i]);
		}
		free(de_ids);

		close(sockd);
		
		lib_buffer_free(g_file_alloc);
		fifo_allocator_free(g_fifo_alloc);
		double_list_free(&g_enqueue_list);
		double_list_free(&g_enqueue_list1);
		double_list_free(&g_dequeue_list);
		double_list_free(&g_dequeue_list1);
		double_list_free(&g_host_list);

		pthread_mutex_destroy(&g_enqueue_lock);
		pthread_mutex_destroy(&g_dequeue_lock);
		pthread_mutex_destroy(&g_host_lock);
		pthread_mutex_destroy(&g_enqueue_cond_mutex);
		pthread_cond_destroy(&g_enqueue_waken_cond);
		pthread_mutex_destroy(&g_dequeue_cond_mutex);
		pthread_cond_destroy(&g_dequeue_waken_cond);
		return 11;
	}
	
	pthread_setname_np(thr_id, "accept");
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: EVENT is now running\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}

	close(sockd);

	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(en_ids[i]);
	}
	free(en_ids);
	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(de_ids[i]);
	}
	free(de_ids);
	
	lib_buffer_free(g_file_alloc);
	fifo_allocator_free(g_fifo_alloc);
	while ((pnode = double_list_pop_front(&g_enqueue_list)) != nullptr) {
		penqueue = (ENQUEUE_NODE*)pnode->pdata;
		close(penqueue->sockd);
		free(penqueue);
	}

	double_list_free(&g_enqueue_list);

	while ((pnode = double_list_pop_front(&g_enqueue_list1)) != nullptr) {
		penqueue= (ENQUEUE_NODE*)pnode->pdata;
		close(penqueue->sockd);
		free(penqueue);
	}

	double_list_free(&g_enqueue_list1);
	
	while ((pnode = double_list_pop_front(&g_dequeue_list)) != nullptr) {
		pdequeue = (DEQUEUE_NODE*)pnode->pdata;
		close(pdequeue->sockd);
		free(pdequeue);
	}

	double_list_free(&g_dequeue_list);

	while ((pnode = double_list_pop_front(&g_dequeue_list1)) != nullptr) {
		pdequeue= (DEQUEUE_NODE*)pnode->pdata;
		close(pdequeue->sockd);
		free(pdequeue);
	}

	double_list_free(&g_dequeue_list1);
	
	double_list_free(&g_host_list);

	pthread_mutex_destroy(&g_enqueue_lock);
	pthread_mutex_destroy(&g_dequeue_lock);
	pthread_mutex_destroy(&g_host_lock);
	pthread_mutex_destroy(&g_enqueue_cond_mutex);
	pthread_cond_destroy(&g_enqueue_waken_cond);
	pthread_mutex_destroy(&g_dequeue_cond_mutex);
	pthread_cond_destroy(&g_dequeue_waken_cond);

	return 0;
}

static void* scan_work_func(void *param)
{
	int i = 0;
	time_t *ptime;
	time_t cur_time;
	HOST_NODE *phost;
	STR_HASH_ITER *iter;
	char temp_string[256];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	
	while (FALSE == g_notify_stop) {
		if (i < SCAN_INTERVAL) {
			sleep(1);
			i ++;
			continue;
		}
		i = 0;
		double_list_init(&temp_list);
		pthread_mutex_lock(&g_host_lock);
		time(&cur_time);
		ptail = double_list_get_tail(&g_host_list);
		while ((pnode = double_list_pop_front(&g_host_list)) != nullptr) {
			phost = (HOST_NODE*)pnode->pdata;
			if (0 == double_list_get_nodes_num(&phost->list) &&
				cur_time - phost->last_time > HOST_INTERVAL) {
				double_list_append_as_tail(&temp_list, pnode);
			} else {
				iter = str_hash_iter_init(phost->phash);
				for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
					str_hash_iter_forward(iter)) {
					ptime = (time_t*)str_hash_iter_get_value(iter, temp_string);
					if (cur_time - *ptime > SELECT_INTERVAL) {
						str_hash_iter_remove(iter);
					}
				}
				str_hash_iter_free(iter);
				double_list_append_as_tail(&g_host_list, pnode);
			}
			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_unlock(&g_host_lock);
		
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			phost = (HOST_NODE*)pnode->pdata;
			double_list_free(&phost->list);
			str_hash_free(phost->phash);
			free(phost);
		}
		double_list_free(&temp_list);
	}
	return NULL;
}

static void* accept_work_func(void *param)
{
	socklen_t addrlen;
	int sockd, sockd2;
	char client_hostip[40];
	struct sockaddr_storage peer_name;
	ENQUEUE_NODE *penqueue;

	sockd = (int)(long)param;
    while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd2) {
			continue;
		}
		int ret = getnameinfo(reinterpret_cast<sockaddr *>(&peer_name),
		          addrlen, client_hostip, sizeof(client_hostip),
		          nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret != 0) {
			printf("getnameinfo: %s\n", gai_strerror(ret));
			close(sockd2);
			continue;
		}
		if (std::find(g_acl_list.cbegin(), g_acl_list.cend(),
		    client_hostip) == g_acl_list.cend()) {
			write(sockd2, "Access Deny\r\n", 13);
			close(sockd2);
			continue;
		}

		penqueue = (ENQUEUE_NODE*)malloc(sizeof(ENQUEUE_NODE));
		if (NULL == penqueue) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			continue;
		}
		
		penqueue->node.pdata = penqueue;
		penqueue->sockd = sockd2;
		penqueue->offset = 0;
		penqueue->res_id[0] = '\0';
		
		
		pthread_mutex_lock(&g_enqueue_lock);
		if (double_list_get_nodes_num(&g_enqueue_list) + 1 +
			double_list_get_nodes_num(&g_enqueue_list1) >= g_threads_num) {
			pthread_mutex_unlock(&g_enqueue_lock);
			free(penqueue);
			write(sockd2, "Maximum Connection Reached!\r\n", 29);
			close(sockd2);
			continue;
		}
		
		double_list_append_as_tail(&g_enqueue_list1, &penqueue->node);
		pthread_mutex_unlock(&g_enqueue_lock);
		write(sockd2, "OK\r\n", 4);
		pthread_cond_signal(&g_enqueue_waken_cond);
	}
	return nullptr;
}

static void* enqueue_work_func(void *param)
{
	int temp_len;
	char *pspace;
	char *pspace1;
	char *pspace2;
	BOOL b_result;
	time_t cur_time;
	HOST_NODE *phost;
	MEM_FILE temp_file;
	char temp_string[256];
	ENQUEUE_NODE *penqueue;
	DEQUEUE_NODE *pdequeue;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
 NEXT_LOOP:
	pthread_mutex_lock(&g_enqueue_cond_mutex);
	pthread_cond_wait(&g_enqueue_waken_cond, &g_enqueue_cond_mutex);
	pthread_mutex_unlock(&g_enqueue_cond_mutex);

	pthread_mutex_lock(&g_enqueue_lock);
	pnode = double_list_pop_front(&g_enqueue_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_enqueue_list, pnode);
	}
	pthread_mutex_unlock(&g_enqueue_lock);

	if (NULL == pnode) {
		goto NEXT_LOOP;
	}

	penqueue = (ENQUEUE_NODE*)pnode->pdata;
	
	while (TRUE) {
		if (FALSE == read_mark(penqueue)) {
			close(penqueue->sockd);
			pthread_mutex_lock(&g_enqueue_lock);
			double_list_remove(&g_enqueue_list, &penqueue->node);
			pthread_mutex_unlock(&g_enqueue_lock);
			free(penqueue);
			goto NEXT_LOOP;
		}
		
		if (0 == strncasecmp(penqueue->line, "ID ", 3)) {
			strncpy(penqueue->res_id, penqueue->line + 3, 128);
			write(penqueue->sockd, "TRUE\r\n", 6);
			continue;
		} else if (0 == strncasecmp(penqueue->line, "LISTEN ", 7)) {
			pdequeue = (DEQUEUE_NODE*)malloc(sizeof(DEQUEUE_NODE));
			if (NULL == pdequeue) {
				write(penqueue->sockd, "FALSE\r\n", 7);
				continue;
			}
			pdequeue->node.pdata = pdequeue;
			pdequeue->node_host.pdata = pdequeue;
			pdequeue->sockd = penqueue->sockd;
			strncpy(pdequeue->res_id, penqueue->line + 7, 128);
			fifo_init(&pdequeue->fifo, g_fifo_alloc, sizeof(MEM_FILE),
				FIFO_AVERAGE_LENGTH);
			pthread_mutex_init(&pdequeue->lock, NULL);
			pthread_mutex_init(&pdequeue->cond_mutex, NULL);
			pthread_cond_init(&pdequeue->waken_cond, NULL);
		
			pthread_mutex_lock(&g_host_lock);
			for (pnode=double_list_get_head(&g_host_list); NULL!=pnode;
				pnode=double_list_get_after(&g_host_list, pnode)) {
				phost = (HOST_NODE*)pnode->pdata;
				if (0 == strcmp(phost->res_id, penqueue->line + 7)) {
					break;
				}
			}
			
			if (NULL == pnode) {
				phost = (HOST_NODE*)malloc(sizeof(HOST_NODE));
				if (NULL == phost) {
					pthread_mutex_unlock(&g_host_lock);
					fifo_free(&pdequeue->fifo);
					pthread_mutex_destroy(&pdequeue->lock);
					pthread_mutex_destroy(&pdequeue->cond_mutex);
					pthread_cond_destroy(&pdequeue->waken_cond);
					free(pdequeue);
					write(penqueue->sockd, "FALSE\r\n", 7);
					continue;
				}
				phost->phash = str_hash_init(HASH_CAPABILITY, sizeof(time_t), NULL);
				if (NULL == phost->phash) {
					pthread_mutex_unlock(&g_host_lock);
					free(phost);
					fifo_free(&pdequeue->fifo);
					pthread_mutex_destroy(&pdequeue->lock);
					pthread_mutex_destroy(&pdequeue->cond_mutex);
					pthread_cond_destroy(&pdequeue->waken_cond);
					free(pdequeue);
					write(penqueue->sockd, "FALSE\r\n", 7);
					continue;
				}
				phost->node.pdata = phost;
				strncpy(phost->res_id, penqueue->line + 7, 128);
				double_list_init(&phost->list);
				double_list_append_as_tail(&g_host_list, &phost->node);
			}
			time(&phost->last_time);
			double_list_append_as_tail(&phost->list, &pdequeue->node_host);
			pthread_mutex_unlock(&g_host_lock);
			
			write(penqueue->sockd, "TRUE\r\n", 6);
			
			pthread_mutex_lock(&g_dequeue_lock);
			double_list_append_as_tail(&g_dequeue_list1, &pdequeue->node);
			pthread_mutex_unlock(&g_dequeue_lock);
			pthread_cond_signal(&g_dequeue_waken_cond);
			
			pthread_mutex_lock(&g_enqueue_lock);
			double_list_remove(&g_enqueue_list, &penqueue->node);
			pthread_mutex_unlock(&g_enqueue_lock);
			free(penqueue);
			goto NEXT_LOOP;
		} else if (0 == strncasecmp(penqueue->line, "SELECT ", 7)) {
			pspace = strchr(penqueue->line + 7, ' ');
			temp_len = pspace - (penqueue->line + 7);
			if (NULL == pspace ||  temp_len > 127 || strlen(pspace + 1) > 63) {
				write(penqueue->sockd, "FALSE\r\n", 7);
				continue;
			}
			memcpy(temp_string, penqueue->line + 7, temp_len);
			temp_string[temp_len] = ':';
			temp_len ++;
			temp_string[temp_len] = '\0';
			HX_strlower(temp_string);
			strcat(temp_string, pspace + 1);
			
			b_result = FALSE;
			pthread_mutex_lock(&g_host_lock);
			for (pnode=double_list_get_head(&g_host_list); NULL!=pnode;
				pnode=double_list_get_after(&g_host_list, pnode)) {
				phost = (HOST_NODE*)pnode->pdata;
				if (0 == strcmp(penqueue->res_id, phost->res_id)) {
					time(&cur_time);
					auto ptime = static_cast<time_t *>(str_hash_query(phost->phash, temp_string));
					if (NULL != ptime) {
						*ptime = cur_time;
					} else {
						str_hash_add(phost->phash, temp_string, &cur_time);
					}
					b_result = TRUE;
					break;
				}
			}
			pthread_mutex_unlock(&g_host_lock);
			if (TRUE == b_result) {
				write(penqueue->sockd, "TRUE\r\n", 6);
			} else {
				write(penqueue->sockd, "FALSE\r\n", 7);
			}
			continue;
		} else if (0 == strncasecmp(penqueue->line, "UNSELECT ", 9)) {
			pspace = strchr(penqueue->line + 9, ' ');
			temp_len = pspace - (penqueue->line + 9);
			if (NULL == pspace ||  temp_len > 127 || strlen(pspace + 1) > 63) {
				write(penqueue->sockd, "FALSE\r\n", 7);
				continue;
			}
			memcpy(temp_string, penqueue->line + 9, temp_len);
			temp_string[temp_len] = ':';
			temp_len ++;
			temp_string[temp_len] = '\0';
			HX_strlower(temp_string);
			strcat(temp_string, pspace + 1);
			
			pthread_mutex_lock(&g_host_lock);
			for (pnode=double_list_get_head(&g_host_list); NULL!=pnode;
				pnode=double_list_get_after(&g_host_list, pnode)) {
				phost = (HOST_NODE*)pnode->pdata;
				if (0 == strcmp(penqueue->res_id, phost->res_id)) {
					str_hash_remove(phost->phash, temp_string);
					break;
				}
				
			}
			pthread_mutex_unlock(&g_host_lock);
			write(penqueue->sockd, "TRUE\r\n", 6);
			continue;
		} else if (0 == strcasecmp(penqueue->line, "QUIT")) {
			write(penqueue->sockd, "BYE\r\n", 5);
			close(penqueue->sockd);
			pthread_mutex_lock(&g_enqueue_lock);
			double_list_remove(&g_enqueue_list, &penqueue->node);
			pthread_mutex_unlock(&g_enqueue_lock);
			free(penqueue);
			goto NEXT_LOOP;
		} else if (0 == strcasecmp(penqueue->line, "PING")) {
			write(penqueue->sockd, "TRUE\r\n", 6);	
			continue;
		} else {
			pspace = strchr(penqueue->line, ' ');
			if (NULL == pspace) {
				write(penqueue->sockd, "FALSE\r\n", 7);
				continue;
			}
			pspace1 = strchr(pspace + 1, ' ');
			if (NULL == pspace1) {
				write(penqueue->sockd, "FALSE\r\n", 7);
				continue;
			}
			pspace2 = strchr(pspace1 + 1, ' ');
			if (NULL == pspace2) {
				pspace2 = penqueue->line + strlen(penqueue->line);
			}
			if (pspace1 - pspace > 128 || pspace2 - pspace1 > 64) {
				write(penqueue->sockd, "FALSE\r\n", 7);
				continue;
			}
			temp_len = pspace1 - (pspace + 1);
			memcpy(temp_string, pspace + 1, temp_len);
			temp_string[temp_len] = ':';
			temp_len ++;
			temp_string[temp_len] = '\0';
			HX_strlower(temp_string);
			memcpy(temp_string + temp_len, pspace1 + 1, pspace2 - pspace1 - 1);
			temp_string[temp_len + (pspace2 - pspace1 - 1)] = '\0';
			pthread_mutex_lock(&g_host_lock);
			for (pnode=double_list_get_head(&g_host_list); NULL!=pnode;
				pnode=double_list_get_after(&g_host_list, pnode)) {
				phost = (HOST_NODE*)pnode->pdata;
				if (0 == strcmp(penqueue->res_id, phost->res_id) ||
					NULL == str_hash_query(phost->phash, temp_string)) {
					continue;
				}
				
				pnode1 = double_list_pop_front(&phost->list);
				if (NULL != pnode1) {
					pdequeue = (DEQUEUE_NODE*)pnode1->pdata;
					mem_file_init(&temp_file, g_file_alloc);
					mem_file_write(&temp_file, penqueue->line,
						strlen(penqueue->line));
					pthread_mutex_lock(&pdequeue->lock);
					b_result = fifo_enqueue(&pdequeue->fifo, &temp_file);
					pthread_mutex_unlock(&pdequeue->lock);
					if (FALSE == b_result) {
						mem_file_free(&temp_file);
					} else {
						pthread_cond_signal(&pdequeue->waken_cond);
					}
					double_list_append_as_tail(&phost->list, pnode1);
				}
			}
			pthread_mutex_unlock(&g_host_lock);
			write(penqueue->sockd, "TRUE\r\n", 6);
			continue;
		}
	}
	return NULL;
}

static void* dequeue_work_func(void *param)
{
	int len;
	MEM_FILE *pfile;
	time_t cur_time;
	time_t last_time;
	HOST_NODE *phost;
	MEM_FILE temp_file;
	struct timespec ts;
	DEQUEUE_NODE *pdequeue;
	DOUBLE_LIST_NODE *pnode;
	char buff[MAX_CMD_LENGTH];
	
 NEXT_LOOP:
	pthread_mutex_lock(&g_dequeue_cond_mutex);
	pthread_cond_wait(&g_dequeue_waken_cond, &g_dequeue_cond_mutex);
	pthread_mutex_unlock(&g_dequeue_cond_mutex);

	pthread_mutex_lock(&g_dequeue_lock);
	pnode = double_list_pop_front(&g_dequeue_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_dequeue_list, pnode);
	}
	pthread_mutex_unlock(&g_dequeue_lock);

	if (NULL == pnode) {
		goto NEXT_LOOP;
	}
	
	time(&last_time);
	pdequeue = (DEQUEUE_NODE*)pnode->pdata;
	phost = NULL;
	pthread_mutex_lock(&g_host_lock);
	for (pnode=double_list_get_head(&g_host_list); NULL!=pnode;
		pnode=double_list_get_after(&g_host_list, pnode)) {
		phost = (HOST_NODE*)pnode->pdata;
		if (0 == strcmp(phost->res_id, pdequeue->res_id)) {
			break;
		}
	}
	pthread_mutex_unlock(&g_host_lock);
	
	if (NULL == phost) {
		pthread_mutex_lock(&g_dequeue_lock);
		double_list_remove(&g_dequeue_list, &pdequeue->node);
		pthread_mutex_unlock(&g_dequeue_lock);
		
		close(pdequeue->sockd);
		fifo_free(&pdequeue->fifo);
		pthread_mutex_destroy(&pdequeue->lock);
		pthread_mutex_destroy(&pdequeue->cond_mutex);
		pthread_cond_destroy(&pdequeue->waken_cond);
		free(pdequeue);
		goto NEXT_LOOP;
	}
	
	while (TRUE) {
		pthread_mutex_lock(&pdequeue->cond_mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec ++;
		pthread_cond_timedwait(&pdequeue->waken_cond,
			&pdequeue->cond_mutex, &ts);
		pthread_mutex_unlock(&pdequeue->cond_mutex);
		
		pthread_mutex_lock(&pdequeue->lock);
		pfile = static_cast<MEM_FILE *>(fifo_get_front(&pdequeue->fifo));
		if (NULL != pfile) {
			temp_file = *pfile;
			fifo_dequeue(&pdequeue->fifo);
		}
		pthread_mutex_unlock(&pdequeue->lock);
		
		time(&cur_time);
		
		if (NULL == pfile) {	
			if (cur_time - last_time >= SOCKET_TIMEOUT - 3) {
				if (6 != write(pdequeue->sockd, "PING\r\n", 6) ||
					FALSE == read_response(pdequeue->sockd)) {
					pthread_mutex_lock(&g_host_lock);
					double_list_remove(&phost->list, &pdequeue->node_host);
					pthread_mutex_unlock(&g_host_lock);
					
					pthread_mutex_lock(&g_dequeue_lock);
					double_list_remove(&g_dequeue_list, &pdequeue->node);
					pthread_mutex_unlock(&g_dequeue_lock);
					
					close(pdequeue->sockd);
					while ((pfile = static_cast<MEM_FILE *>(fifo_get_front(&pdequeue->fifo))) != nullptr) {
						mem_file_free(pfile);
						fifo_dequeue(&pdequeue->fifo);
					}
					fifo_free(&pdequeue->fifo);
					pthread_mutex_destroy(&pdequeue->lock);
					pthread_mutex_destroy(&pdequeue->cond_mutex);
					pthread_cond_destroy(&pdequeue->waken_cond);
					free(pdequeue);
					goto NEXT_LOOP;
				}
				last_time = cur_time;
				pthread_mutex_lock(&g_host_lock);
				phost->last_time = cur_time;
				pthread_mutex_unlock(&g_host_lock);
			}
			continue;
		}
		
		len = mem_file_read(&temp_file, buff, MAX_CMD_LENGTH);
		buff[len] = '\r';
		len ++;
		buff[len] = '\n';
		len ++;
		mem_file_free(&temp_file);
		if (len != write(pdequeue->sockd, buff, len) ||
			FALSE == read_response(pdequeue->sockd)) {
			pthread_mutex_lock(&g_host_lock);
			double_list_remove(&phost->list, &pdequeue->node_host);
			pthread_mutex_unlock(&g_host_lock);
			
			pthread_mutex_lock(&g_dequeue_lock);
			double_list_remove(&g_dequeue_list, &pdequeue->node);
			pthread_mutex_unlock(&g_dequeue_lock);
			
			close(pdequeue->sockd);
			while ((pfile = static_cast<MEM_FILE *>(fifo_get_front(&pdequeue->fifo))) != nullptr) {
				mem_file_free(pfile);
				fifo_dequeue(&pdequeue->fifo);
			}
			fifo_free(&pdequeue->fifo);
			pthread_mutex_destroy(&pdequeue->lock);
			pthread_mutex_destroy(&pdequeue->cond_mutex);
			pthread_cond_destroy(&pdequeue->waken_cond);
			free(pdequeue);
			goto NEXT_LOOP;
		}
		
		last_time = cur_time;
		pthread_mutex_lock(&g_host_lock);
		phost->last_time = cur_time;
		pthread_mutex_unlock(&g_host_lock);
		
	}	
	return NULL;
}

static BOOL read_response(int sockd)
{
	fd_set myset;
	int offset;
	int read_len;
	char buff[1024];
	struct timeval tv;

	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(sockd, buff + offset, 1024 - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		
		if (6 == offset) {
			if (0 == strncasecmp(buff, "TRUE\r\n", 6)) {
				return TRUE;
			} else {
				return FALSE;
			}
		}
		
		if (offset > 6) {
			return FALSE;
		}
	}
}

static BOOL read_mark(ENQUEUE_NODE *penqueue)
{
	fd_set myset;
	int i, read_len;
	struct timeval tv;

	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(penqueue->sockd, &myset);
		if (select(penqueue->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(penqueue->sockd, penqueue->buffer +
		penqueue->offset, MAX_CMD_LENGTH - penqueue->offset);
		if (read_len <= 0) {
			return FALSE;
		}
		penqueue->offset += read_len;
		for (i=0; i<penqueue->offset-1; i++) {
			if ('\r' == penqueue->buffer[i] &&
				'\n' == penqueue->buffer[i + 1]) {
				memcpy(penqueue->line, penqueue->buffer, i);
				penqueue->line[i] = '\0';
				penqueue->offset -= i + 2;
				memmove(penqueue->buffer, penqueue->buffer + i + 2,
					penqueue->offset);
				return TRUE;
			}
		}
		if (MAX_CMD_LENGTH == penqueue->offset) {
			return FALSE;
		}
	}
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}
