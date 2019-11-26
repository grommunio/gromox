#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include "double_list.h"
#include "config_file.h"
#include "list_file.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>  
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#define SOCKET_TIMEOUT          60

typedef struct _MIDB_ITEM {
	char prefix[256];
	char ip_addr[16];
	int port;
} MIDB_ITEM;

typedef struct _BACK_SVR {
	DOUBLE_LIST_NODE node;
	char prefix[256];
	int prefix_len;
	char ip_addr[16];
	int port;
	DOUBLE_LIST conn_list;
} BACK_SVR;

typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
	BACK_SVR *psvr;
} BACK_CONN;

typedef struct _FRONT_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
    int offset;
    char buff[257*1024];
    BACK_CONN *pback;
} FRONT_CONN;


static void* scan_work_func(void *param);

static void* accept_work_func(void *param);

static void* thread_work_func(void *param);

static int read_line(FRONT_CONN *pconnection);

static int transfer_response(int f_sockd, int b_sockd, int type);

static int connect_midb(const char *ip_addr, int port);

static void term_handler(int signo);

static int g_conn_num;
static int g_notify_stop;
static pthread_mutex_t g_front_lock;
static pthread_mutex_t g_server_lock;
static pthread_mutex_t g_cond_mutex;
static pthread_cond_t g_waken_cond;
static DOUBLE_LIST g_front_list;
static DOUBLE_LIST g_front_list1;
static DOUBLE_LIST g_server_list;
static DOUBLE_LIST g_lost_list;
static char *opt_config_file = NULL;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	int i, j;
	int list_num;
    int listenfd;
	char *str_value;
	char list_path[256];
	char data_path[256];
	int len;
	pthread_t *thr_ids;
	pthread_t scan_id;
	pthread_t accept_id;
    struct sockaddr_un unix_addr;
    BACK_CONN *pback;
	BACK_SVR *pserver;
    FRONT_CONN *pfront;
	CONFIG_FILE *pconfig;
	LIST_FILE *plist;
	MIDB_ITEM *pitem;
    DOUBLE_LIST_NODE *pnode;

	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	pconfig = config_file_init2(opt_config_file, config_default_path("amidb.cfg"));
	if (opt_config_file != NULL && pconfig == NULL) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 1;
	}

	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(data_path, PKGDATAAGENTDIR, sizeof(data_path));
		config_file_set_value(pconfig, "DATA_FILE_PATH", data_path);
	} else {
		strcpy(data_path, str_value);
	}

	sprintf(list_path, "%s/midb_list.txt", data_path);

	str_value = config_file_get_value(pconfig, "MIDB_CONNECTION_NUM");
	if (NULL == str_value) {
		g_conn_num = 5;
		config_file_set_value(pconfig, "MIDB_CONNECTION_NUM", "5");
	} else {
		g_conn_num = atoi(str_value);
		if (g_conn_num < 2 || g_conn_num > 100) {
			g_conn_num = 5;
			config_file_set_value(pconfig, "MIDB_CONNECTION_NUM", "5");
		}
	}

	printf("[system]: midb connection number is %d\n", g_conn_num);

	g_conn_num ++;

	char CS_PATH[256];
	str_value = config_file_get_value(pconfig, "amidb_listen");
	if (str_value == NULL) {
		HX_strlcpy(CS_PATH, "/run/gromox/amidb.sock", sizeof(CS_PATH));
		config_file_set_value(pconfig, "amidb_listen", CS_PATH);
	} else {
		HX_strlcpy(CS_PATH, str_value, sizeof(CS_PATH));
	}
	config_file_free(pconfig);

	plist = list_file_init(list_path, "%s:256%s:16%d");
	if (NULL == plist) {
		printf("[system]: list_file_init %s: %s\n", list_path, strerror(errno));
		return 2;
	}

	pthread_mutex_init(&g_front_lock, NULL);
	pthread_mutex_init(&g_server_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_front_list);
	double_list_init(&g_front_list1);
	double_list_init(&g_server_list);
	double_list_init(&g_lost_list);

	list_num = list_file_get_item_num(plist);
	pitem = (MIDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<list_num; i++) {
		pserver = (BACK_SVR*)malloc(sizeof(BACK_SVR));
		if (NULL == pserver) {
			printf("[system]: fail to allocate memory for back server\n");
			list_file_free(plist);
			return 3;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		pserver->prefix_len = strlen(pserver->prefix);
		strcpy(pserver->ip_addr, pitem[i].ip_addr);
		pserver->port = pitem[i].port;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (j=0; j<g_conn_num; j++) {
	       pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
		    if (NULL != pback) {
			    pback->node.pdata = pback;
				pback->sockd = -1;
				pback->psvr = pserver;
	            double_list_append_as_tail(&g_lost_list, &pback->node);
		    }
		}
	}
	list_file_free(plist);

	signal(SIGPIPE, SIG_IGN);

    /* Create a Unix domain stream socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == listenfd) {
        printf("[system]: fail to create listen socket\n");
		return 4;
    }

    unlink(CS_PATH);

    /* Fill in socket address structure */
    memset(&unix_addr, 0, sizeof (unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, CS_PATH);
    len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path);

    /* Bind the name to the descriptor */
    if (bind(listenfd, (struct sockaddr*)&unix_addr, len) < 0) {
        close(listenfd);
		printf("[system]: bind %s: %s\n", unix_addr.sun_path, strerror(errno));
		return 5;
    }


    if (chmod(CS_PATH, 0666) < 0) {
        close(listenfd);
        printf("[system]: fail to change access mode of %s\n", CS_PATH);
		return 6;
    }

    if (listen(listenfd, 5) < 0) {
        printf("[system]: fail to listen!\n");
        close(listenfd);
		return 7;
    }

	thr_ids = malloc(g_conn_num*sizeof(pthread_t));

	for (i=0; i<g_conn_num; i++) {
		if (0 != pthread_create(&thr_ids[i], NULL, thread_work_func, NULL)) {
			printf("[system]: fail to creat pool thread\n");
			break;
		}
	}

	if (i != g_conn_num) {
		for (i-=1; i>=0; i--) {
			pthread_cancel(thr_ids[i]);
		}
		close(listenfd);
		return 8;
	}


	if (0 != pthread_create(&accept_id, NULL, accept_work_func,
		(void*)(long)listenfd)) {
		printf("[system]: fail to create accept thread\n");
		close(listenfd);
		for (i=0; i<g_conn_num; i++) {
			pthread_cancel(thr_ids[i]);
		}
		return 9;
	}

	if (0 != pthread_create(&scan_id, NULL, scan_work_func, NULL)) {
		printf("[system]: fail to create scan thread\n");
		close(listenfd);
		for (i=0; i<g_conn_num; i++) {
			pthread_cancel(thr_ids[i]);
		}
		return 10;
	}

    g_notify_stop = 0;
    signal(SIGTERM, term_handler);

    printf("[system]: AMIDB is now running\n");

    while (0 == g_notify_stop) {
		sleep(1);
	}

    close(listenfd);

	for (i=0; i<g_conn_num; i++) {
		pthread_cancel(thr_ids[i]);
	}

	pthread_join(scan_id, NULL);

	while ((pnode = double_list_get_from_head(&g_front_list1)) != NULL) {
		pfront = (FRONT_CONN*)pnode->pdata;
		close(pfront->sockd);
		free(pfront);
	}

	while ((pnode = double_list_get_from_head(&g_front_list)) != NULL) {
		pfront = (FRONT_CONN*)pnode->pdata;
		close(pfront->sockd);
		if (NULL != pfront->pback) {
			write(pfront->pback->sockd, "QUIT\r\n", 6);
			close(pfront->pback->sockd);
			free(pfront->pback);
		}
		free(pfront);
	}

	while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
		free(pnode->pdata);

	while ((pnode = double_list_get_from_head(&g_server_list)) != NULL) {
		pserver = (BACK_SVR*)pnode->pdata;
		while ((pnode = double_list_get_from_head(&pserver->conn_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "QUIT\r\n", 6);
			close(pback->sockd);
			free(pback);
		}
		free(pserver);
	}

	pthread_mutex_destroy(&g_front_lock);
	pthread_mutex_destroy(&g_server_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);

	return 0;
}


static void* accept_work_func(void *param)
{
	FRONT_CONN *pfront;
	int len, clifd, listenfd;
    struct sockaddr_un unix_addr;


	listenfd = (int)(long)param;

	while (0 == g_notify_stop) {
		len = sizeof(unix_addr);
	    memset(&unix_addr, 0, sizeof(unix_addr));
		clifd = accept(listenfd, (struct sockaddr*)&unix_addr, &len);
		if (-1 == clifd) {
			continue;
		}
        len -= sizeof(unix_addr.sun_family);
        unix_addr.sun_path[len] = '\0';
        unlink(unix_addr.sun_path);

        pfront = (FRONT_CONN*)malloc(sizeof(FRONT_CONN));
		if (NULL == pfront) {
			close(clifd);
			continue;
		}

		pthread_mutex_lock(&g_front_lock);

		if (double_list_get_nodes_num(&g_front_list) + 1 + 
			double_list_get_nodes_num(&g_front_list1) >= g_conn_num) {
			pthread_mutex_unlock(&g_front_lock);
			free(pfront);
			close(clifd);
			continue;
		}


        pfront->node.pdata = pfront;
        pfront->sockd = clifd;
        pfront->offset = 0;
		pfront->pback = NULL;
        double_list_append_as_tail(&g_front_list1, &pfront->node);
		pthread_mutex_unlock(&g_front_lock);
		
		pthread_cond_signal(&g_waken_cond);
    }

	pthread_exit(0);

}


static void *scan_work_func(void *param)
{
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *pnode1;
	BACK_SVR *pserver;
	BACK_CONN *pback;
	time_t now_time;
	char temp_buff[1024];
	fd_set myset;
	struct timeval tv;


	double_list_init(&temp_list);

	while (0 == g_notify_stop) {
		pthread_mutex_lock(&g_server_lock);
		time(&now_time);
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			ptail = double_list_get_tail(&pserver->conn_list);
			while ((pnode1 = double_list_get_from_head(&pserver->conn_list)) != NULL) {
				pback = (BACK_CONN*)pnode1->pdata;
				if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
					double_list_append_as_tail(&temp_list, &pback->node);
				} else {
					double_list_append_as_tail(&pserver->conn_list,
						&pback->node);
				}

				if (pnode1 == ptail) {
					break;
				}
			}
		}
		pthread_mutex_unlock(&g_server_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "PING\r\n", 6);
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(pback->sockd, &myset);
			if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0 ||
				read(pback->sockd, temp_buff, 1024) <= 0) {
				close(pback->sockd);
				pback->sockd = -1;
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_server_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
			}
		}

		pthread_mutex_lock(&g_server_lock);
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_server_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_midb(pback->psvr->ip_addr,
							pback->psvr->port);
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
			} else {
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_server_lock);
			}
		}
		sleep(1);
	}
	return NULL;
}

static char* parse_prefix(const char *cmd_line, char *buff)
{
	const char *pspace;

	pspace = strchr(cmd_line + 7, ' ');
	if (NULL == pspace) {
		pspace = cmd_line + strlen(cmd_line);
	}

	if (pspace - cmd_line - 7 < 0 || pspace - cmd_line - 7 > 255) {
		return NULL;
	}

	memcpy(buff, cmd_line + 7, pspace - cmd_line - 7);
	buff[pspace - cmd_line - 7] = '\0';
	HX_strrtrim(buff);
	HX_strltrim(buff);
	return buff;
}

static BACK_CONN *get_connection(const char *prefix)
{
	int i;
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;


	for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
		pnode=double_list_get_after(&g_server_list, pnode)) {
		pserver = (BACK_SVR*)pnode->pdata;
		if (0 == strncmp(pserver->prefix, prefix, pserver->prefix_len)) {
			break;
		}
	}

	if (NULL == pnode) {
		return NULL;
	}
	
	pthread_mutex_lock(&g_server_lock);
	pnode = double_list_get_from_head(&pserver->conn_list);
	pthread_mutex_unlock(&g_server_lock);

	if (NULL == pnode) {
		for (i=0; i<SOCKET_TIMEOUT; i++) {
			sleep(1);
			pthread_mutex_lock(&g_server_lock);
			pnode = double_list_get_from_head(&pserver->conn_list);
			pthread_mutex_unlock(&g_server_lock);
			if (NULL != pnode) {
				break;
			} 
		}
		if (NULL == pnode) {
			return NULL;
		}
	}

	return (BACK_CONN*)pnode->pdata;
}

static void *thread_work_func(void *param)
{
	int type;
	int length;
	BACK_CONN *pback;
	FRONT_CONN *pfront;
	char prefix[256];
	DOUBLE_LIST_NODE *pnode;

	
NEXT_LOOP:
	pthread_mutex_lock(&g_cond_mutex);
	pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
	pthread_mutex_unlock(&g_cond_mutex);


	pthread_mutex_lock(&g_front_lock);
	pnode = double_list_get_from_head(&g_front_list1);
	if (NULL != pnode) {
		double_list_append_as_tail(&g_front_list, pnode);
	}
	pthread_mutex_unlock(&g_front_lock);

	if (NULL == pnode) {
		goto NEXT_LOOP;
	}

	pfront = (FRONT_CONN*)pnode->pdata;


	while (1) {
		if (0 != read_line(pfront)) {
			pthread_mutex_lock(&g_front_lock);
			double_list_remove(&g_front_list, &pfront->node);
			pthread_mutex_unlock(&g_front_lock);
			close(pfront->sockd);
			free(pfront);
			goto NEXT_LOOP;
		}

		if (0 == strcasecmp(pfront->buff, "QUIT")) {
			write(pfront->sockd, "BYE\r\n", 5);
			pthread_mutex_lock(&g_front_lock);
			double_list_remove(&g_front_list, &pfront->node);
			pthread_mutex_unlock(&g_front_lock);
			close(pfront->sockd);
			free(pfront);
			goto NEXT_LOOP;
		}

		if (0 == strncasecmp(pfront->buff, "M-QUTA ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-SUMY ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-FREE ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-LIST ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "M-UIDL ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "M-MTCH ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-INST ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-DELE ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-MOVE ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-COPY ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-UPDT ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-MAKF ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-REMF ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-RENF ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-PING ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "M-INFO ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "M-ENUM ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "M-CKFL ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-OFST ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-UNID ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-FDDT ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-SUBF ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-UNSF ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-SUBL ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "P-SIML ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "P-DELL ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "P-SIMU ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "P-DTLU ", 7)) {
			type = 1;
		} else if (0 == strncasecmp(pfront->buff, "P-SFLG ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-RFLG ", 7)) {
			type = 0;
		} else if (0 == strncasecmp(pfront->buff, "P-GFLG ", 7)) {
			type = 0;
		} else {
			write(pfront->sockd, "FALSE 0\r\n", 9);
			continue;
		}

		if (NULL == parse_prefix(pfront->buff, prefix)) {
			write(pfront->sockd, "FALSE 0\r\n", 9);
			continue;
		}

		pback = get_connection(prefix);
		if (NULL == pback) {
			pthread_mutex_lock(&g_front_lock);
			double_list_remove(&g_front_list, &pfront->node);
			pthread_mutex_unlock(&g_front_lock);
			write(pfront->sockd, "FALSE\r\n", 7);
			close(pfront->sockd);
			free(pfront);
			goto NEXT_LOOP;
		}
		pfront->pback = pback;

		length = strlen(pfront->buff);
		memcpy(pfront->buff + length, "\r\n", 2);
		length += 2;
		write(pback->sockd, pfront->buff, length); 

		if (0 != transfer_response(pfront->sockd, pback->sockd, type)) {
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pfront->pback = NULL;
			pthread_mutex_unlock(&g_server_lock);

			pthread_mutex_lock(&g_front_lock);
			double_list_remove(&g_front_list, &pfront->node);
			pthread_mutex_unlock(&g_front_lock);
			write(pfront->sockd, "FALSE\r\n", 7);
			close(pfront->sockd);
			free(pfront);
			goto NEXT_LOOP;
		} else {
			time(&pfront->pback->last_time);
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pfront->pback = NULL;
			pthread_mutex_unlock(&g_server_lock);
		}

    }
	return NULL;
}

static int transfer_response(int f_sockd, int b_sockd, int type)
{
	int i;
	int lines;
	int count;
	int offset;
	int last_pos;
	int read_len;
	fd_set myset;
	struct timeval tv;
	char num_buff[32];
	char buff[257*1024];


	offset = 0;
	if (0 == type) {
		while (1) {
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(b_sockd, &myset);
			if (select(b_sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
				return -1;
			}
			read_len = read(b_sockd, buff + offset, 257*1024 - offset);
			if (read_len <= 0) {
				return -1;
			}
			offset += read_len;
			if (offset >= 2 && '\r' == buff[offset - 2] &&
				'\n' == buff[offset - 1]) {
				write(f_sockd, buff, offset);
				return 0;
			}
			if (257*1024 == offset) {
				return -1;
			}
		}
	} else {
		count = 0;
		lines = -1;
		while (1) {
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(b_sockd, &myset);
			if (select(b_sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
				return -1;
			}
			read_len = read(b_sockd, buff + offset, 257*1024 - offset);
			if (read_len <= 0) {
				return -1;
			}
			offset += read_len;
			buff[offset] = '\0';
			if (-1 == lines) {
				for (i=0; i<offset-1&&i<36; i++) {
					if ('\r' == buff[i] && '\n' == buff[i + 1]) {
						if (0 == strncmp(buff, "TRUE ", 5)) {
							memcpy(num_buff, buff + 5, i - 5);
							num_buff[i - 5] = '\0';
							lines = atoi(num_buff);
							if (lines < 0) {
								return -1;
							}
							last_pos = i + 2;
							break;
						} else if (0 == strncmp(buff, "FALSE ", 6)) {
							write(f_sockd, buff, offset);
							return 0;
						}
					}
				}
				if (-1 == lines) {
					if (offset > 1024) {
						return -1;
					}
					continue;
				}
			}

			for (i=last_pos; i<offset; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					count ++;
				}
			}

			if (count >= lines) {
				write(f_sockd, buff, offset);
				return 0;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (257*1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					write(f_sockd, buff, offset);
					offset = 0;
				} else {
					write(f_sockd, buff, offset - 1);
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}

}

static int read_line(FRONT_CONN *pconnection)
{
	fd_set myset;
	int read_len;
	struct timeval tv;

	while (1) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return -1;
		}
		read_len = read(pconnection->sockd, pconnection->buff + 
					pconnection->offset, 257*1024 - pconnection->offset);
		if (read_len <= 0) {
			return -1;
		}
		pconnection->offset += read_len;
		if (pconnection->offset >= 2 &&
			'\r' == pconnection->buff[pconnection->offset - 2] &&
			'\n' == pconnection->buff[pconnection->offset - 1]) {
			pconnection->offset -= 2;
			pconnection->buff[pconnection->offset] = '\0';
			pconnection->offset = 0;
			return 0;
		}
		if (257*1024 == pconnection->offset) {
			return -1;
		}
	}
}


static int connect_midb(const char *ip_addr, int port)
{
    int sockd;
    int read_len;
	fd_set myset;
	struct timeval tv;
    char temp_buff[1024];
    struct sockaddr_in servaddr;


    sockd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
    if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        close(sockd);
        return -1;
    }
	tv.tv_usec = 0;
	tv.tv_sec = SOCKET_TIMEOUT;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
        close(sockd);
        return -1;
	}
	read_len = read(sockd, temp_buff, 1024);
	if (read_len <= 0) {
        close(sockd);
        return -1;
	}
	temp_buff[read_len] = '\0';
	if (0 != strcasecmp(temp_buff, "OK\r\n")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static void term_handler(int signo)
{
    g_notify_stop = 1;
}


