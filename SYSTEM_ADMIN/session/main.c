#include "util.h"
#include "double_list.h"
#include "str_hash.h"
#include "list_file.h"
#include "config_file.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#define SESSION_VERSION				"4.0"

#define SOCKET_TIMEOUT				60

#define SESSION_FIELD_LENGTH		512

#define USER_FIELD_LENGTH			1024

typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;

typedef struct _CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	int sockd;
	int offset;
	char buffer[1024];
	char line[1024];
} CONNECTION_NODE;

typedef struct _SESSION {
	DOUBLE_LIST_NODE node;
	char name[32];
	char field[SESSION_FIELD_LENGTH + 1];
	time_t time_stamp;
} SESSION;

typedef struct _USER_ITEM {
	time_t time_stamp;
	char field[USER_FIELD_LENGTH];
} USER_ITEM;

static int g_item_num;
static int g_threads_num;
static BOOL g_notify_stop;
static int g_max_interval;
static char g_list_path[256];
static DOUBLE_LIST g_acl_list;
static pthread_cond_t g_waken_cond;
static pthread_mutex_t g_user_lock;
static STR_HASH_TABLE *g_user_table;
static pthread_mutex_t g_cond_mutex;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_connection_list1;
static pthread_mutex_t g_session_lock;
static STR_HASH_TABLE *g_session_table;
static pthread_mutex_t g_connection_lock;


static void *accept_work_func(void *param);

static void *thread_work_func(void *param);

static void produce_session(const char *tag, char *session);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static void term_handler(int signo);


int main(int argc, char **argv)
{
	int i, num;
	int optval;
	int table_size;
	int listen_port;
	int sockd, status;
	pthread_t thr_id;
	pthread_t *thr_ids;
	char temp_buff[32];
	char listen_ip[16];
	char *str_value, *pitem;
	ACL_ITEM *pacl;
	struct in_addr addr;
	struct sockaddr_in my_name;
	LIST_FILE *plist;
	CONFIG_FILE *pconfig;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;

	
	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", SESSION_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return -2;
	}

	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(g_list_path, "../data/session_acl.txt");
	} else {
		snprintf(g_list_path, 255, "%s/session_acl.txt", str_value);
	}
	printf("[system]: acl file path is %s\n", g_list_path);

	str_value = config_file_get_value(pconfig, "SESSION_LISTEN_IP");
	if (NULL == str_value) {
		listen_ip[0] = '\0';
		printf("[system]: listen ip is ANY\n");
	} else {
		strncpy(listen_ip, str_value, 16);
		g_list_path[0] = '\0';
		printf("[system]: listen ip is %s\n", listen_ip);
	}

	str_value = config_file_get_value(pconfig, "SESSION_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 9999;
		config_file_set_value(pconfig, "SESSION_LISTEN_PORT", "9999");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 9999;
			config_file_set_value(pconfig, "SESSION_LISTEN_PORT", "9999");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);

	str_value = config_file_get_value(pconfig, "SESSION_TABLE_SIZE");
	if (NULL == str_value) {
		table_size = 10000;
		config_file_set_value(pconfig, "SESSION_TABLE_SIZE", "10000");
	} else {
		table_size = atoi(str_value);
		if (table_size <= 0) {
			table_size = 10000;
			config_file_set_value(pconfig, "SESSION_TABLE_SIZE", "10000");
		}
	}
	printf("[system]: hash table size is %d\n", table_size);

	str_value = config_file_get_value(pconfig, "MAX_SESSIONS_PER_ITEM");
	if (NULL == str_value) {
		g_item_num = 5;
		config_file_set_value(pconfig, "MAX_SESSIONS_PER_ITEM", "5");
	} else {
		g_item_num = atoi(str_value);
		if (g_item_num <= 0) {
			g_item_num = 5;
			config_file_set_value(pconfig, "MAX_SESSIONS_PER_ITEM", "5");
		}
	}
	printf("[system]: maximum session number per item is %d\n", g_item_num);

	str_value = config_file_get_value(pconfig, "SESSION_THREADS_NUM");
	if (NULL == str_value) {
		g_threads_num = 100;
		config_file_set_value(pconfig, "SESSION_THREADS_NUM", "100");
	} else {
		g_threads_num = atoi(str_value);
		if (g_threads_num < 20) {
			g_threads_num = 20;
			config_file_set_value(pconfig, "SESSION_THREADS_NUM", "20");
		}
		if (g_threads_num > 1000) {
			g_threads_num = 1000;
			config_file_set_value(pconfig, "SESSION_THREADS_NUM", "1000");
		}
	}

	printf("[system]: threads number is %d\n", g_threads_num);

	g_threads_num ++;

	str_value = config_file_get_value(pconfig, "SESSION_TIMEOUT");
	if (NULL == str_value) {
		g_max_interval = 1800;
		config_file_set_value(pconfig, "SESSION_TIMEOUT", "30minutes");
	} else {
		g_max_interval = atoitvl(str_value);
		if (g_max_interval <= 0) {
			g_max_interval = 1800;
			config_file_set_value(pconfig, "SESSION_TIMEOUT", "30minutes");
		}
	}
	itvltoa(g_max_interval, temp_buff);
	printf("[system]: session timeout interval is %s\n", temp_buff);

	config_file_save(pconfig);
	config_file_free(pconfig);

	g_session_table = str_hash_init(table_size, sizeof(DOUBLE_LIST), NULL);
	if (NULL == g_session_table) {
		printf("[system]: fail to init session hash table\n");
		return -3;
	}
	
	g_user_table = str_hash_init(table_size, sizeof(USER_ITEM), NULL);
	if (NULL == g_user_table) {
		printf("[system]: fail to init user hash table\n");
		str_hash_free(g_session_table);
		return -3;
	}
	
	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) {
        printf("[system]: fail to create socket for listening\n");
		str_hash_free(g_session_table);
		str_hash_free(g_user_table);
		return -4;
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
		printf("[system]: fail to bind socket\n");
        close(sockd);
		str_hash_free(g_session_table);
		str_hash_free(g_user_table);
		return -5;
    }
	
	status = listen(sockd, 5);

	if (-1 == status) {
		printf("[system]: fail to listen socket\n");
		close(sockd);
		str_hash_free(g_session_table);
		str_hash_free(g_user_table);
		return -6;
	}
	
	pthread_mutex_init(&g_user_lock, NULL);
	pthread_mutex_init(&g_session_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_acl_list);
	double_list_init(&g_connection_list);
	double_list_init(&g_connection_list1);

	thr_ids = (pthread_t*)malloc(g_threads_num*sizeof(pthread_t));

	for (i=0; i<g_threads_num; i++) {
		if (0 != pthread_create(&thr_ids[i], NULL, thread_work_func, NULL)) {
			printf("[system]: fail to create pool thread\n");
			break;
		}
	}

	if (i != g_threads_num) {
		for (i-=1; i>=0; i--) {
			pthread_cancel(thr_ids[i]);
		}

		close(sockd);
		str_hash_free(g_session_table);
		str_hash_free(g_user_table);

		double_list_free(&g_acl_list);
		double_list_free(&g_connection_list);
		double_list_free(&g_connection_list1);

		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_session_lock);
		pthread_mutex_destroy(&g_cond_mutex);
		pthread_mutex_destroy(&g_user_lock);
		pthread_cond_destroy(&g_waken_cond);
		return -7;
	}
	
	if ('\0' != g_list_path[0]) {
		plist = list_file_init(g_list_path, "%s:16");
		if (NULL == plist) {
			for (i=g_threads_num-1; i>=0; i--) {
				pthread_cancel(thr_ids[i]);
			}

			close(sockd);
			str_hash_free(g_session_table);
			str_hash_free(g_user_table);

			double_list_free(&g_acl_list);
			double_list_free(&g_connection_list);
			double_list_free(&g_connection_list1);

			pthread_mutex_destroy(&g_connection_lock);
			pthread_mutex_destroy(&g_session_lock);
			pthread_mutex_destroy(&g_cond_mutex);
			pthread_mutex_destroy(&g_user_lock);
			pthread_cond_destroy(&g_waken_cond);
			printf("[system]: fail to load acl from %s\n", g_list_path);
			return -8;
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
	
	if (0 != pthread_create(&thr_id, NULL, accept_work_func, (void*)(long)sockd)) {
		printf("[system]: fail to create accept thread\n");

		for (i=g_threads_num-1; i>=0; i--) {
			pthread_cancel(thr_ids[i]);
		}

		close(sockd);
		str_hash_free(g_session_table);
		str_hash_free(g_user_table);

		while (pnode=double_list_get_from_head(&g_acl_list)) {
			free(pnode->pdata);
		}
		double_list_free(&g_acl_list);

		double_list_free(&g_connection_list);
		double_list_free(&g_connection_list1);

		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_session_lock);
		pthread_mutex_destroy(&g_cond_mutex);
		pthread_mutex_destroy(&g_user_lock);
		pthread_cond_destroy(&g_waken_cond);
		return -9;
	}
	
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: SESSION is now rinning\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}

	close(sockd);

	for (i=0; i<g_threads_num; i++) {
		pthread_cancel(thr_ids[i]);
	}

	free(thr_ids);

	str_hash_free(g_session_table);
	str_hash_free(g_user_table);

	while (pnode=double_list_get_from_head(&g_acl_list)) {
		free(pnode->pdata);
	}

	double_list_free(&g_acl_list);

	while (pnode=double_list_get_from_head(&g_connection_list)) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		close(pconnection->sockd);
		free(pconnection);
	}

	double_list_free(&g_connection_list);

	while (pnode=double_list_get_from_head(&g_connection_list1)) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		close(pconnection->sockd);
		free(pconnection);
	}

	double_list_free(&g_connection_list1);

	pthread_mutex_destroy(&g_connection_lock);
	pthread_mutex_destroy(&g_session_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_mutex_destroy(&g_user_lock);
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

static void *thread_work_func(void *param)
{
	int temp_len;
	time_t cur_time;
	USER_ITEM *puser;
	SESSION *psession;
	DOUBLE_LIST *plist;
	STR_HASH_ITER *iter;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	static USER_ITEM tmp_item;
	CONNECTION_NODE *pconnection;
	DOUBLE_LIST_NODE *pnode_last1;	
	char *pspace, *pspace1, temp_line[1024];
	
	
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

		if (0 == strncasecmp(pconnection->line, "ALLOC ", 6)) {
			lower_string(pconnection->line + 6);
			pthread_mutex_lock(&g_session_lock);
			plist = (DOUBLE_LIST*)str_hash_query(g_session_table,
						pconnection->line + 6);
			if (NULL == plist) {
				if (1 != str_hash_add(g_session_table, pconnection->line + 6,
					&temp_list)) {
					time(&cur_time);
					iter = str_hash_iter_init(g_session_table);
					for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
						str_hash_iter_forward(iter)) {
						plist = str_hash_iter_get_value(iter, NULL);
						pnode_last1 = double_list_get_tail(plist);
						while (pnode1=double_list_get_from_head(plist)) {
							psession = (SESSION*)pnode1->pdata;
							if (cur_time - psession->time_stamp >
								g_max_interval) {
								free(psession);
							} else {
								double_list_append_as_tail(plist, pnode1);
							}
							if (pnode1 == pnode_last1) {
								break;
							}
						}
						if (0 == double_list_get_nodes_num(plist)) {
							double_list_free(plist);
							str_hash_iter_remove(iter);
						}
					}
					str_hash_iter_free(iter);
					if (1 != str_hash_add(g_session_table, pconnection->line + 6,
						&temp_list)) {
						pthread_mutex_unlock(&g_session_lock);
						write(pconnection->sockd, "FALSE 1\r\n", 9);	
						continue;
					}
				}
				plist = str_hash_query(g_session_table, pconnection->line + 6);
				double_list_init(plist);
			}

			if (double_list_get_nodes_num(plist) >= g_item_num) {
				time(&cur_time);
				pnode_last1 = double_list_get_tail(plist);
				while (pnode1=double_list_get_from_head(plist)) {
					psession = (SESSION*)pnode1->pdata;
					if (cur_time - psession->time_stamp > g_max_interval) {
						free(psession);
					} else {
						double_list_append_as_tail(plist, pnode1);
					}
					if (pnode1 == pnode_last1) {
						break;
					}
				}
				if (double_list_get_nodes_num(plist) >= g_item_num) {
					pthread_mutex_unlock(&g_session_lock);
					write(pconnection->sockd, "FALSE 2\r\n", 9);	
					continue;
				}
			}
				
			psession = (SESSION*)malloc(sizeof(SESSION));
			if (NULL == psession) {
				if (0 == double_list_get_nodes_num(plist)) {
					double_list_free(plist);
					str_hash_remove(g_session_table, pconnection->line + 6);
				}
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE 3\r\n", 9);
				continue;
			}
			psession->node.pdata = psession;
			produce_session(pconnection->line + 6, psession->name);
			psession->field[0] = '\0';
			double_list_append_as_tail(plist, &psession->node);
			time(&psession->time_stamp);
			memcpy(temp_line, "TRUE ", 5);
			memcpy(temp_line + 5, psession->name, 32);
			memcpy(temp_line + 37, "\r\n", 2);
			pthread_mutex_unlock(&g_session_lock);
			write(pconnection->sockd, temp_line, 39);
		} else if (0 == strncasecmp(pconnection->line, "FREE ", 5)) {
			lower_string(pconnection->line + 5);
			pspace = strchr(pconnection->line + 5, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			*pspace = '\0';
			pspace ++;
			pthread_mutex_lock(&g_session_lock);
			plist = (DOUBLE_LIST*)str_hash_query(g_session_table, 
					pconnection->line + 5);
			if (NULL == plist) {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "TRUE\r\n", 6);
				continue;
			}
			for (pnode1=double_list_get_head(plist); NULL!=pnode1;
				pnode1=double_list_get_after(plist, pnode1)) {
				psession = (SESSION*)pnode1->pdata;
				if (0 == strncmp(psession->name, pspace, 32)) {
					double_list_remove(plist, pnode1);
					free(pnode1->pdata);
					break;
				}
			}
			if (0 == double_list_get_nodes_num(plist)) {
				double_list_free(plist);
				str_hash_remove(g_session_table, pconnection->line + 5);
			}
			pthread_mutex_unlock(&g_session_lock);
			write(pconnection->sockd, "TRUE\r\n", 6);	
		} else if (0 == strncasecmp(pconnection->line, "SET ", 4)) {
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			*pspace = '\0';
			lower_string(pconnection->line + 4);
			pspace ++;
			pspace1 = strchr(pspace, ' ');
			if (NULL == pspace1) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;							
			}
			*pspace1 = '\0';
			pspace1 ++;
			pthread_mutex_lock(&g_session_lock);
			plist = str_hash_query(g_session_table, pconnection->line + 4);
			if (NULL == plist) {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			for (pnode1=double_list_get_head(plist); NULL!=pnode1;
				pnode1=double_list_get_after(plist, pnode1)) {
				psession = (SESSION*)pnode1->pdata;
				if (0 == strncmp(psession->name, pspace, 32)) {
					break;
				}
			}
			if (NULL != pnode1) {
				time(&cur_time);
				if (cur_time - psession->time_stamp <= g_max_interval) {
					time(&psession->time_stamp);
					strncpy(psession->field, pspace1, SESSION_FIELD_LENGTH);
					pthread_mutex_unlock(&g_session_lock);
					write(pconnection->sockd, "TRUE\r\n", 6);
				} else {
					double_list_remove(plist, pnode1);
					if (0 == double_list_get_nodes_num(plist)) {
						double_list_free(plist);
						str_hash_remove(g_session_table, pconnection->line + 4);
					}
					pthread_mutex_unlock(&g_session_lock);
					free(pnode1->pdata);
					write(pconnection->sockd, "FALSE\r\n", 7);
				}
			} else {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
			}
		} else if (0 == strncasecmp(pconnection->line, "CHECK ", 6)) {
			lower_string(pconnection->line + 6);
			pspace = strchr(pconnection->line + 6, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			*pspace = '\0';
			pspace ++;
			pthread_mutex_lock(&g_session_lock);
			plist = str_hash_query(g_session_table, pconnection->line + 6);
			if (NULL == plist) {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			for (pnode1=double_list_get_head(plist); NULL!=pnode1;
				pnode1=double_list_get_after(plist, pnode1)) {
				psession = (SESSION*)pnode1->pdata;
				if (0 == strncmp(psession->name, pspace, 32)) {
					break;
				}
			}
			if (NULL != pnode1) {
				time(&cur_time);
				if (cur_time - psession->time_stamp <= g_max_interval) {
					time(&psession->time_stamp);
					pthread_mutex_unlock(&g_session_lock);
					write(pconnection->sockd, "TRUE\r\n", 6);
				} else {
					double_list_remove(plist, pnode1);
					if (0 == double_list_get_nodes_num(plist)) {
						double_list_free(plist);
						str_hash_remove(g_session_table, pconnection->line + 6);
					}
					pthread_mutex_unlock(&g_session_lock);
					free(pnode1->pdata);
					write(pconnection->sockd, "FALSE\r\n", 7);
				}
			} else {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
			}
		} else if (0 == strncasecmp(pconnection->line, "QUERY ", 6)) {
			lower_string(pconnection->line + 6);
			pspace = strchr(pconnection->line + 6, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			*pspace = '\0';
			pspace ++;
			pthread_mutex_lock(&g_session_lock);
			plist = str_hash_query(g_session_table, pconnection->line + 6);
			if (NULL == plist) {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			for (pnode1=double_list_get_head(plist); NULL!=pnode1;
				pnode1=double_list_get_after(plist, pnode1)) {
				psession = (SESSION*)pnode1->pdata;
				if (0 == strncmp(psession->name, pspace, 32)) {
					break;
				}
			}
			if (NULL != pnode1) {
				time(&cur_time);
				if (cur_time - psession->time_stamp <= g_max_interval) {
					time(&psession->time_stamp);
					temp_len = snprintf(temp_line, sizeof(temp_line),
									"TRUE %s\r\n", psession->field);	
					pthread_mutex_unlock(&g_session_lock);
					write(pconnection->sockd, temp_line, temp_len);
				} else {
					double_list_remove(plist, pnode1);
					if (0 == double_list_get_nodes_num(plist)) {
						double_list_free(plist);
						str_hash_remove(g_session_table, pconnection->line + 6);
					}
					pthread_mutex_unlock(&g_session_lock);
					free(pnode1->pdata);
					write(pconnection->sockd, "FALSE\r\n", 7);
				}
			} else {
				pthread_mutex_unlock(&g_session_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
			}
		} else if (0 == strncasecmp(pconnection->line, "PUT ", 4)) {
			pspace = strchr(pconnection->line + 4, ' ');
			if (NULL == pspace) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			*pspace = '\0';
			lower_string(pconnection->line + 4);
			pspace ++;
			pthread_mutex_lock(&g_user_lock);
			puser = str_hash_query(g_user_table, pconnection->line + 4);
			if (NULL == puser) {
				if (1 != str_hash_add(g_user_table,
					pconnection->line + 4, &tmp_item)) {
					time(&cur_time);
					iter = str_hash_iter_init(g_user_table);
					for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
						str_hash_iter_forward(iter)) {
						puser = str_hash_iter_get_value(iter, NULL);
						if (cur_time - puser->time_stamp > g_max_interval) {
							str_hash_iter_remove(iter);
						}
					}
					str_hash_iter_free(iter);
					if (1 != str_hash_add(g_user_table,
						pconnection->line + 4, &tmp_item)) {
						pthread_mutex_unlock(&g_user_lock);
						write(pconnection->sockd, "FALSE\r\n", 7);
						continue;							
					}
				}
				puser = str_hash_query(g_user_table, pconnection->line + 4);
			}
			time(&puser->time_stamp);
			strncpy(puser->field, pspace, USER_FIELD_LENGTH);
			pthread_mutex_unlock(&g_user_lock);
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "GET ", 4)) {
			lower_string(pconnection->line + 4);
			pthread_mutex_lock(&g_user_lock);
			puser = str_hash_query(g_user_table, pconnection->line + 4);
			if (NULL == puser) {
				pthread_mutex_unlock(&g_user_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			time(&cur_time);
			if (cur_time - puser->time_stamp > g_max_interval) {
				str_hash_remove(g_user_table, pconnection->line + 4);
				pthread_mutex_unlock(&g_user_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
			} else {
				temp_len = snprintf(temp_line, sizeof(temp_line),
									"TRUE %s\r\n", puser->field);
				time(&puser->time_stamp);
				pthread_mutex_unlock(&g_user_lock);
				write(pconnection->sockd, temp_line, temp_len);
			}
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
		if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
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
				memmove(pconnection->buffer, pconnection->buffer + i + 2,
					pconnection->offset);
				return TRUE;
			}
		}
		if (1024 == pconnection->offset) {
			return FALSE;
		}
	}
}


static void produce_session(const char *tag, char *session)
{
	char *pitem;
	time_t cur_time;
	int i, pos, mod;
	char temp_time[16];
	char temp_name[16];
	
	time(&cur_time);
	/* fill 'g' if length is too short */
	sprintf(temp_time, "%x", cur_time);
	if (strlen(tag) >= 16) {
		memcpy(temp_name, tag, 16);
	} else {
		memset(temp_name, '0', 16);
		memcpy(temp_name, tag, strlen(tag));
	}
	for (i=0; i<16; i++) {
		if ('@' == temp_name[i]) {
			temp_name[i] = '0';
		} else {
			temp_name[i] = tolower(temp_name[i]);
		}
	}
	for (i=0; i<32; i++) {
		mod = i%4;
		pos = i/4;
		if (0 == mod || 1 == mod) {
			session[i] = temp_name[pos*2 + mod];
		} else if (2 == mod) {
			session[i] = 'a' + rand()%26;
		} else {
			session[i] = temp_time[pos];
		}
	}
	session[32] = '\0';
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}
