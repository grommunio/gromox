#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include <libHX/option.h>
#include "util.h"
#include "str_hash.h"
#include "list_file.h"
#include "config_file.h"
#include "double_list.h"
#include "exmdb_client.h"
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#define SOCKET_TIMEOUT		60

#define EXMDB_CONN_NUM		4

#define EVENT_THREAD_NUM	4

#define PING_INTERVAL		600

typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;

typedef struct _SUB_NODE {
	DOUBLE_LIST_NODE node;
	char maildir[256];
	uint32_t sub_id;
} SUB_NODE;

typedef struct _CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	int sockd;
	int offset;
	char buffer[1024];
	char line[1024];
} CONNECTION_NODE;

typedef struct _SENSOR_ITEM {
	int num;
	uint32_t sub_id;
	time_t time_stamp;
	time_t ping_time;
} SENSOR_ITEM;

static int g_threads_num;
static BOOL g_notify_stop;
static int g_max_interval;
static char g_list_path[256];
static DOUBLE_LIST g_acl_list;
static pthread_cond_t g_waken_cond;
static pthread_mutex_t g_hash_lock;
static pthread_mutex_t g_cond_mutex;
static STR_HASH_TABLE *g_hash_table;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_connection_list1;
static pthread_mutex_t g_connection_lock;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void* scan_work_func(void *param);

static void *accept_work_func(void *param);

static void *thread_work_func(void *param);

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

static void event_proc(const char *dir, BOOL b_table,
	uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	SENSOR_ITEM *pitem;
	
	pthread_mutex_lock(&g_hash_lock);
	pitem = str_hash_query(g_hash_table, dir);
	if (NULL != pitem) {
		pitem->num ++;
	}
	pthread_mutex_unlock(&g_hash_lock);
}

int main(int argc, const char **argv)
{
	int optval;
	int i, num;
	BOOL b_listen;
	int table_size;
	ACL_ITEM *pacl;
	int listen_port;
	LIST_FILE *plist;
	int sockd, status;
	pthread_t scan_id;
	pthread_t *thr_ids;
	char temp_buff[32];
	char listen_ip[16];
	char list_path[256];
	pthread_t accept_id;
	CONFIG_FILE *pconfig;
	char *str_value, *pitem;
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in my_name;
	CONNECTION_NODE *pconnection;

	opt_config_file = config_default_path("sensor.cfg");
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	pconfig = config_file_init(opt_config_file);
	if (NULL == pconfig) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(g_list_path, "../data/sensor_acl.txt");
		strcpy(list_path, "../data/exmdb_list.txt");
	} else {
		snprintf(g_list_path, 255, "%s/sensor_acl.txt", str_value);
		snprintf(list_path, 255, "%s/exmdb_list.txt", str_value);
	}
	printf("[system]: acl file path is %s\n", g_list_path);

	str_value = config_file_get_value(pconfig, "SENSOR_LISTEN_ANY");
	if (NULL == str_value) {
		b_listen = FALSE;
	} else {
		if (0 == strcasecmp(str_value, "TRUE")) {
			b_listen = TRUE;
		} else {
			b_listen = FALSE;
		}
	}

	if (FALSE == b_listen) {
		str_value = config_file_get_value(pconfig, "SENSOR_LISTEN_IP");
		if (NULL == str_value) {
			strcpy(listen_ip, "127.0.0.1");
			config_file_set_value(pconfig, "SENSOR_LISTEN_IP", "127.0.0.1");
		} else {
			strncpy(listen_ip, str_value, 16);
		}
		g_list_path[0] ='\0';
		printf("[system]: listen ip is %s\n", listen_ip);
	} else {
		listen_ip[0] = '\0';
		printf("[system]: listen ip is ANY\n");
	}

	str_value = config_file_get_value(pconfig, "SENSOR_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 11111;
		config_file_set_value(pconfig, "SENSOR_LISTEN_PORT", "11111");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 11111;
			config_file_set_value(pconfig, "SENSOR_LISTEN_PORT", "11111");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);

	str_value = config_file_get_value(pconfig, "SENSOR_TABLE_SIZE");
	if (NULL == str_value) {
		table_size = 3000;
		config_file_set_value(pconfig, "SENSOR_TABLE_SIZE", "3000");
	} else {
		table_size = atoi(str_value);
		if (table_size <= 0) {
			table_size = 3000;
			config_file_set_value(pconfig, "SENSOR_TABLE_SIZE", "3000");
		}
	}
	printf("[system]: hash table size is %d\n", table_size);

	str_value = config_file_get_value(pconfig, "SENSOR_THREADS_NUM");
	if (NULL == str_value) {
		g_threads_num = 20;
		config_file_set_value(pconfig, "SENSOR_THREADS_NUM", "20");
	} else {
		g_threads_num = atoi(str_value);
		if (g_threads_num < 10) {
			g_threads_num = 10;
			config_file_set_value(pconfig, "SENSOR_THREADS_NUM", "10");
		}
		if (g_threads_num > 100) {
			g_threads_num = 100;
			config_file_set_value(pconfig, "SENSOR_THREADS_NUM", "100");
		}
	}
	printf("[system]: threads number is %d\n", g_threads_num);

	g_threads_num ++;

	str_value = config_file_get_value(pconfig, "SENSOR_LIFE_CIRCLE");
	if (NULL == str_value) {
		g_max_interval = 300;
		config_file_set_value(pconfig, "SENSOR_LIFE_CIRCLE", "5minutes");
	} else {
		g_max_interval = atoitvl(str_value);
		if (g_max_interval < 30) {
			g_max_interval = 30;
			config_file_set_value(pconfig, "SENSOR_LIFE_CIRCLE", "30seconds");
		}
	}
	itvltoa(g_max_interval, temp_buff);
	printf("[system]: sensor item life circle is %s\n", temp_buff);
	
	config_file_save(pconfig);
	config_file_free(pconfig);
	
	exmdb_client_init(EXMDB_CONN_NUM, EVENT_THREAD_NUM, list_path);
	if (0 != exmdb_client_run()) {
		printf("[system]: fail to run exmdb_client\n");
		return 3;
	}
	exmdb_client_register_proc(event_proc);
	
	g_hash_table = str_hash_init(table_size, sizeof(SENSOR_ITEM), NULL);
	if (NULL == g_hash_table) {
		printf("[system]: fail to init hash table\n");
		return 4;
	}
	
	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sockd) {
        printf("[system]: fail to create socket for listening\n");
		return 5;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&optval, sizeof(int));
	
	/* socket binding */
	memset(&my_name, 0, sizeof(my_name));
	my_name.sin_family = AF_INET;
	if ('\0' != listen_ip[0]) {
		my_name.sin_addr.s_addr = inet_addr(listen_ip);
	} else {
		my_name.sin_addr.s_addr = INADDR_ANY;
	}   
	my_name.sin_port = htons(listen_port);
	
	status = bind(sockd, (struct sockaddr*)&my_name, sizeof(my_name));
	if (-1 == status) {
		printf("[system]: bind %s:%u: %s\n", listen_ip, listen_port, strerror(errno));
		return 6;
    }
	
	status = listen(sockd, 5);
	if (-1 == status) {
		printf("[system]: fail to listen socket\n");
		return 7;
	}

	pthread_mutex_init(&g_hash_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_acl_list);
	double_list_init(&g_connection_list);
	double_list_init(&g_connection_list1);

	thr_ids = (pthread_t*)malloc(g_threads_num*sizeof(pthread_t));

	for (i=0; i<g_threads_num; i++) {
		if (0 != pthread_create(&thr_ids[i],
			NULL, thread_work_func, NULL)) {
			printf("[system]: fail to create pool thread\n");
			return 8;
		}
	}
	
	if ('\0' != g_list_path[0]) {
		plist = list_file_init(g_list_path, "%s:16");
		if (NULL == plist) {
			printf("[system]: fail to load acl from %s\n", g_list_path);
			return 9;
		}
		num = list_file_get_item_num(plist);
		pitem = list_file_get_list(plist);
		for (i=0; i<num; i++) {
			pacl = (ACL_ITEM*)malloc(sizeof(ACL_ITEM));
			if (NULL == pacl) {
				continue;
			}
			pacl->node.pdata = pacl;
			strcpy(pacl->ip_addr, pitem + 16*i);
			double_list_append_as_tail(&g_acl_list, &pacl->node);
		}
		list_file_free(plist);
	}

	
	if (0 != pthread_create(&accept_id, NULL,
		accept_work_func, (void*)(long)sockd)) {
		printf("[system]: fail to create accept thread\n");
		return 10;
	}
	
	if (0 != pthread_create(&scan_id, NULL, scan_work_func, NULL)) {
		printf("[system]: fail to create event stub pool thread\n");
		return 11;
	}
	
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: SENSOR is now rinning\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}
	close(sockd);
	
	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(thr_ids[i]);
	}
	free(thr_ids);
	str_hash_free(g_hash_table);

	while ((pnode = double_list_get_from_head(&g_acl_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&g_acl_list);
	
	while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		close(pconnection->sockd);
		free(pconnection);
	}
	double_list_free(&g_connection_list);

	while ((pnode = double_list_get_from_head(&g_connection_list1)) != NULL) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		close(pconnection->sockd);
		free(pconnection);
	}
	double_list_free(&g_connection_list1);
	
	pthread_join(scan_id, NULL);
	
	exmdb_client_stop();
	exmdb_client_free();

	pthread_mutex_destroy(&g_connection_lock);
	pthread_mutex_destroy(&g_hash_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);
	
	return 0;
}

static void *accept_work_func(void *param)
{
	int sockd, sockd2;
	ACL_ITEM *pacl;
	socklen_t addrlen;
	char client_hostip[16];
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in peer_name;
	CONNECTION_NODE *pconnection;	

	sockd = (int)(long)param;
    while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd2) {
			continue;
		}
		strcpy(client_hostip, inet_ntoa(peer_name.sin_addr));
		if ('\0' != g_list_path[0]) {
			for (pnode=double_list_get_head(&g_acl_list); NULL!=pnode;
				pnode=double_list_get_after(&g_acl_list, pnode)) {
				pacl = (ACL_ITEM*)pnode->pdata;
				if (0 == strcmp(client_hostip, pacl->ip_addr)) {
					break;
				}
			}

			if (NULL == pnode) {
				write(sockd2, "Access Deny\r\n", 13);
				close(sockd2);
				continue;
			}
		}

		pconnection = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
		if (NULL == pconnection) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			continue;
		}
		pthread_mutex_lock(&g_connection_lock);
		if (double_list_get_nodes_num(&g_connection_list) + 1 +
			double_list_get_nodes_num(&g_connection_list1) >= g_threads_num) {
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			write(sockd2, "Maximum Connection Reached!\r\n", 29);
			close(sockd2);
			continue;
		}

		pconnection->node.pdata = pconnection;
		pconnection->sockd = sockd2;
		pconnection->offset = 0;
		double_list_append_as_tail(&g_connection_list1, &pconnection->node);
		pthread_mutex_unlock(&g_connection_lock);
		write(sockd2, "OK\r\n", 4);
		pthread_cond_signal(&g_waken_cond);
	}
	
	pthread_exit(0);

}

static void *scan_work_func(void *param)
{
	int i = 0;
	SUB_NODE *psub;
	time_t now_time;
	SENSOR_ITEM *pitem;
	STR_HASH_ITER *iter;
	char temp_buff[256];
	DOUBLE_LIST temp_list;
	DOUBLE_LIST temp_list1;
	DOUBLE_LIST_NODE *pnode;

	double_list_init(&temp_list);
	double_list_init(&temp_list1);
	while (FALSE == g_notify_stop) {
		sleep(1);
		i ++;
		if (i < 30) {
			continue;
		}
		i = 0;
		
		pthread_mutex_lock(&g_hash_lock);
		time(&now_time);
		iter = str_hash_iter_init(g_hash_table);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pitem = str_hash_iter_get_value(iter, temp_buff);
			if (now_time - pitem->time_stamp > g_max_interval) {
				str_hash_iter_remove(iter);
				psub = malloc(sizeof(SUB_NODE));
				if (NULL != psub) {
					psub->node.pdata = psub;
					psub->sub_id = pitem->sub_id;
					strcpy(psub->maildir, temp_buff);
					double_list_append_as_tail(&temp_list, &psub->node);
				}
			} else if (now_time - pitem->ping_time >= PING_INTERVAL) {
				pnode = malloc(sizeof(DOUBLE_LIST_NODE));
				if (NULL != pnode) {
					pnode->pdata = strdup(temp_buff);
					if (NULL == pnode->pdata) {
						free(pnode);
					} else {
						double_list_append_as_tail(&temp_list1, pnode);
						pitem->ping_time = now_time;
					}
				}
			}
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_hash_lock);
		
		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			psub = (SUB_NODE*)pnode->pdata;
			exmdb_client_unsubscribe_notification(
				psub->maildir, psub->sub_id);
			free(pnode->pdata);
		}
		
		while ((pnode = double_list_get_from_head(&temp_list1)) != NULL) {
			exmdb_client_ping_store(pnode->pdata);
			free(pnode->pdata);
			free(pnode);
		}
	}
	return NULL;
}

static BOOL read_mark(CONNECTION_NODE *pconnection)
{
	fd_set myset;
	int i, read_len;
	struct timeval tv;

	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1,
			&myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = read(pconnection->sockd, pconnection->buffer +
					pconnection->offset, 1024 - pconnection->offset);
		if (read_len <= 0) {
			return FALSE;
		}
		pconnection->offset += read_len;
		for (i=0; i<pconnection->offset-1; i++) {
			if ('\r' == pconnection->buffer[i] &&
				'\n' == pconnection->buffer[i + 1]) {
				memcpy(pconnection->line, pconnection->buffer, i);
				pconnection->line[i] = '\0';
				pconnection->offset -= i + 2;
				memmove(pconnection->buffer,
					pconnection->buffer + i + 2,
					pconnection->offset);
				return TRUE;
			}
		}
		if (1024 == pconnection->offset) {
			return FALSE;
		}
	}
}

static void *thread_work_func(void *param)
{
	time_t cur_time;
	int len, temp_num;
	SENSOR_ITEM *pitem;
	BOOL should_subscribe;
	SENSOR_ITEM temp_item;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;	
	char *pspace, temp_line[1024];
	
	
NEXT_LOOP:
	pthread_mutex_lock(&g_cond_mutex);
	pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
	pthread_mutex_unlock(&g_cond_mutex);

	pthread_mutex_lock(&g_connection_lock);
	pnode = double_list_get_from_head(&g_connection_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_connection_list, pnode);
	}
	pthread_mutex_unlock(&g_connection_lock);

	if (NULL == pnode) {
		goto NEXT_LOOP;
	}

	pconnection = (CONNECTION_NODE*)pnode->pdata;

	while (TRUE) {
		if (FALSE == read_mark(pconnection)) {
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			goto NEXT_LOOP;
		}

		if (0 == strncasecmp(pconnection->line, "SET ", 4)) {
			lower_string(pconnection->line + 4);
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);	
				continue;
			}
			*pspace = '\0';
			pspace ++;
			temp_num = atoi(pspace);
			if (temp_num < 0) {
				write(pconnection->sockd, "FALSE 2\r\n", 9);	
				continue;
			}

			should_subscribe = FALSE;
			pthread_mutex_lock(&g_hash_lock);
			pitem = (SENSOR_ITEM*)str_hash_query(
				g_hash_table, pconnection->line + 4);
			if (NULL == pitem) {
				memset(&temp_item, 0, sizeof(SENSOR_ITEM));
				time(&temp_item.time_stamp);
				time(&temp_item.ping_time);
				if (1 != str_hash_add(g_hash_table,
					pconnection->line + 4, &temp_item)) {
					pthread_mutex_unlock(&g_hash_lock);
					write(pconnection->sockd, "FALSE 3\r\n", 9);	
					continue;
				}
				should_subscribe = TRUE;
				pitem = str_hash_query(g_hash_table,
							pconnection->line + 4);
			}

			pitem->num = temp_num;
			time(&pitem->time_stamp);
			pthread_mutex_unlock(&g_hash_lock);
			if (TRUE == should_subscribe) {
				exmdb_client_subscribe_notification(
					pconnection->line + 4, NOTIFICATION_TYPE_NEWMAIL,
					TRUE, 0, 0, &pitem->sub_id);
			}
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "ADD ", 4)) {
			lower_string(pconnection->line + 4);
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE 1\r\n", 9);
				continue;
			}
			*pspace = '\0';
			pspace ++;
			temp_num = atoi(pspace);
			if (temp_num < 0) {
				write(pconnection->sockd, "FALSE 2\r\n", 9);	
				continue;
			}
			should_subscribe = FALSE;
			pthread_mutex_lock(&g_hash_lock);
			pitem = (SENSOR_ITEM*)str_hash_query(g_hash_table,
						pconnection->line + 4);
			if (NULL == pitem) {
				memset(&temp_item, 0, sizeof(SENSOR_ITEM));
				time(&temp_item.time_stamp);
				time(&temp_item.ping_time);
				if (1 != str_hash_add(g_hash_table,
					pconnection->line + 4, &temp_item)) {
					pthread_mutex_unlock(&g_hash_lock);
					write(pconnection->sockd, "FALSE 3\r\n", 9);	
					continue;
				}
				should_subscribe = TRUE;
				pitem = str_hash_query(g_hash_table, pconnection->line + 4);
			}

			pitem->num += temp_num;
			time(&pitem->time_stamp);
			pthread_mutex_unlock(&g_hash_lock);
			if (TRUE == should_subscribe) {
				exmdb_client_subscribe_notification(
					pconnection->line + 4, NOTIFICATION_TYPE_NEWMAIL,
					TRUE, 0, 0, &pitem->sub_id);
			}
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "REM ", 4)) {
			lower_string(pconnection->line + 4);
			pthread_mutex_lock(&g_hash_lock);
			str_hash_remove(g_hash_table, pconnection->line + 4);
			pthread_mutex_unlock(&g_hash_lock);
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "GET ", 4)) {
			lower_string(pconnection->line + 4);
			pthread_mutex_lock(&g_hash_lock);
			pitem = (SENSOR_ITEM*)str_hash_query(
				g_hash_table, pconnection->line + 4);
			if (NULL == pitem) {
				memset(&temp_item, 0,sizeof(SENSOR_ITEM));
				time(&temp_item.time_stamp);
				time(&temp_item.ping_time);
				if (1 != str_hash_add(g_hash_table,
					pconnection->line + 4, &temp_item)) {
					pthread_mutex_unlock(&g_hash_lock);
					write(pconnection->sockd, "FALSE 1\r\n", 9);	
					continue;
				}
				pitem = (SENSOR_ITEM*)str_hash_query(
					g_hash_table, pconnection->line + 4);
				pthread_mutex_unlock(&g_hash_lock);
				exmdb_client_subscribe_notification(
					pconnection->line + 4, NOTIFICATION_TYPE_NEWMAIL,
					TRUE, 0, 0, &pitem->sub_id);
				write(pconnection->sockd, "TRUE 0\r\n", 8);	
				continue;
			}
			time(&cur_time);
			if (cur_time - pitem->time_stamp > g_max_interval) {
				pitem->num = 0;
			}
			time(&pitem->time_stamp);
			len = sprintf(temp_line, "TRUE %d\r\n", pitem->num);
			pthread_mutex_unlock(&g_hash_lock);
			write(pconnection->sockd, temp_line, len);
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			write(pconnection->sockd, "BYE\r\n", 5);
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			goto NEXT_LOOP;
		} else if (0 == strcasecmp(pconnection->line, "PING")) {
			write(pconnection->sockd, "TRUE\r\n", 6);	
		} else {
			write(pconnection->sockd, "FALSE\r\n", 7);
		}
	}
	return NULL;
}
