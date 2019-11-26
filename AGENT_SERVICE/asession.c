#include "double_list.h"
#include "config_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
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


#define ASESSION_VERSION        "1.0"

#define CS_PATH                 "/var/pandora/token/asession"

#define SOCKET_TIMEOUT          60


typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
} BACK_CONN;

typedef struct _FRONT_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
    int offset;
    char buff[1024];
    struct _BACK_CONN *pback;
} FRONT_CONN;


static void* scan_work_func(void *param);

static void* accept_work_func(void *param);

static void* thread_work_func(void *param);

static int read_line(int sockd, FRONT_CONN *pconnection);

static int connect_session();

static void term_handler(int signo);

static int g_conn_num;
static int g_notify_stop;
static char g_session_ip[16];
static int g_session_port;
static pthread_mutex_t g_front_lock;
static pthread_mutex_t g_back_lock;
static pthread_mutex_t g_cond_mutex;
static pthread_cond_t g_waken_cond;
static DOUBLE_LIST g_front_list;
static DOUBLE_LIST g_front_list1;
static DOUBLE_LIST g_back_list;
static DOUBLE_LIST g_lost_list;



int main(int argc, char **argv)
{
    char *ptr;
    int listenfd;
	char *str_value;
    int clifd, i, len;
	pthread_t *thr_ids;
	pthread_t scan_id;
	pthread_t accept_id;
    struct sockaddr_un unix_addr;
    BACK_CONN *pback;
    FRONT_CONN *pfront;
    DOUBLE_LIST_NODE *pnode;
	CONFIG_FILE *pconfig;


	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", ASESSION_VERSION);
		return 0;
	}
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return -1;
	}
	str_value = config_file_get_value(pconfig, "SESSION_LISTEN_IP");
	if (NULL == str_value) {
		strcpy(g_session_ip, "127.0.0.1");
		config_file_set_value(pconfig, "SESSION_LISTEN_IP", "127.0.0.1");
	} else {
		strcpy(g_session_ip, str_value);
	}
	printf("[system]: session listen ip is %s\n", g_session_ip);

	str_value = config_file_get_value(pconfig, "SESSION_LISTEN_PORT");
	if (NULL == str_value) {
		g_session_port = 9999;
		config_file_set_value(pconfig, "SESSION_LISTEN_PORT", "9999");
	} else {
		g_session_port = atoi(str_value);
		if (g_session_port <= 0) {
			g_session_port = 9999;
		}
	}
	printf("[system]: session listen port is %d\n", g_session_port);


	str_value = config_file_get_value(pconfig, "SESSION_CONNECTION_NUM");
	if (NULL == str_value) {
		g_conn_num = 10;
		config_file_set_value(pconfig, "SESSION_CONNECTION_NUM", "10");
	} else {
		g_conn_num = atoi(str_value);
		if (g_conn_num < 10 || g_conn_num > 100) {
			g_conn_num = 10;
		}
	}

	printf("[system]: session connection number is %d\n", g_conn_num);

	g_conn_num ++;

	config_file_save(pconfig);
	config_file_free(pconfig);


	signal(SIGPIPE, SIG_IGN);


    /* Create a Unix domain stream socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == listenfd) {
        printf("[system]: fail to create listen socket\n");
        return -2;
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
        printf("[system]: fail to bind listen socket\n");
        return -3;
    }


    if (chmod(CS_PATH, 0666) < 0) {
        close(listenfd);
        printf("[system]: fail to change access mode of %s\n", CS_PATH);
        return -4;
    }

    if (listen(listenfd, 5) < 0) {
        printf("[system]: fail to listen!\n");
        close(listenfd);
        return -5;
    }

	pthread_mutex_init(&g_front_lock, NULL);
	pthread_mutex_init(&g_back_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_front_list);
	double_list_init(&g_front_list1);
	double_list_init(&g_back_list);
	double_list_init(&g_lost_list);

    for (i=0; i<g_conn_num; i++) {
        pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
        if (NULL != pback) {
            pback->node.pdata = pback;
			pback->sockd = -1;
            double_list_append_as_tail(&g_lost_list, &pback->node);
        }
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
		return -6;
	}


	if (0 != pthread_create(&accept_id, NULL, accept_work_func,
		(void*)(long)listenfd)) {
		printf("[system]: fail to create accept thread\n");
		close(listenfd);
		for (i=0; i<g_conn_num; i++) {
			pthread_cancel(thr_ids[i]);
		}
		return -7;
	}

	if (0 != pthread_create(&scan_id, NULL, scan_work_func, NULL)) {
		printf("[system]: fail to create scan thread\n");
		close(listenfd);
		for (i=0; i<g_conn_num; i++) {
			pthread_cancel(thr_ids[i]);
		}
		return -8;
	}


    g_notify_stop = 0;
    signal(SIGTERM, term_handler);


    printf("[system]: ASESSION is now running\n");

    while (0 == g_notify_stop) {
		sleep(1);
	}

    close(listenfd);

	for (i=0; i<g_conn_num; i++) {
		pthread_cancel(thr_ids[i]);
	}

	pthread_join(scan_id, NULL);


	while (pnode=double_list_get_from_head(&g_front_list1)) {
		pfront = (FRONT_CONN*)pnode->pdata;
		close(pfront->sockd);
		free(pfront);
	}

	while (pnode=double_list_get_from_head(&g_front_list)) {
		pfront = (FRONT_CONN*)pnode->pdata;
		close(pfront->sockd);
		if (NULL != pfront->pback) {
			write(pfront->pback->sockd, "QUIT\r\n", 6);
			close(pfront->pback->sockd);
			free(pfront->pback);
		}
		free(pfront);
	}

	while (pnode=double_list_get_from_head(&g_lost_list)) {
		free(pnode->pdata);
	}

	while (pnode=double_list_get_from_head(&g_back_list)) {
		pback = (BACK_CONN*)pnode->pdata;
		write(pback->sockd, "QUIT\r\n", 6);
		close(pback->sockd);
		free(pback);
	}


	pthread_mutex_destroy(&g_front_lock);
	pthread_mutex_destroy(&g_back_lock);
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
	BACK_CONN *pback;
	time_t now_time;
	char temp_buff[1024];
	fd_set myset;
	struct timeval tv;


	double_list_init(&temp_list);

	while (0 == g_notify_stop) {
		pthread_mutex_lock(&g_back_lock);
		time(&now_time);
		ptail = double_list_get_tail(&g_back_list);
		while (pnode=double_list_get_from_head(&g_back_list)) {
			pback = (BACK_CONN*)pnode->pdata;
			if (now_time - pback->last_time >= SOCKET_TIMEOUT - 3) {
				double_list_append_as_tail(&temp_list, &pback->node);
			} else {
				double_list_append_as_tail(&g_back_list, &pback->node);
			}

			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_unlock(&g_back_lock);


		while (pnode=double_list_get_from_head(&temp_list)) {
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
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			}
		}

		pthread_mutex_lock(&g_back_lock);
		while (pnode=double_list_get_from_head(&g_lost_list)) {
			double_list_append_as_tail(&temp_list, pnode);
		}
		pthread_mutex_unlock(&g_back_lock);

		while (pnode=double_list_get_from_head(&temp_list)) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_session();
			if (-1 != pback->sockd) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			} else {
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			}
		}
		sleep(1);
	}
	return NULL;
}


static void *thread_work_func(void *param)
{
	int i, len;
	BACK_CONN *pback;
	FRONT_CONN *pfront;
	char temp_buff[1024];
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
		if (0 != read_line(pfront->sockd, pfront)) {
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
		
		if (strlen(pfront->buff) > 1000) {
			write(pfront->sockd, "FALSE\r\n", 7);
			continue;
		}

		pthread_mutex_lock(&g_back_lock);
		pnode = double_list_get_from_head(&g_back_list);
		pthread_mutex_unlock(&g_back_lock);

		if (NULL == pnode) {
			for (i=0; i<SOCKET_TIMEOUT; i++) {
				sleep(1);
				pthread_mutex_lock(&g_back_lock);
				pnode = double_list_get_from_head(&g_back_list);
				pthread_mutex_unlock(&g_back_lock);
				if (NULL != pnode) {
					break;
				} 
			}
			if (i == SOCKET_TIMEOUT) {
				pthread_mutex_lock(&g_front_lock);
				double_list_remove(&g_front_list, &pfront->node);
				pthread_mutex_unlock(&g_front_lock);
				write(pfront->sockd, "FALSE\r\n", 7);
				close(pfront->sockd);
				free(pfront);
				goto NEXT_LOOP;
			}
		}

		pfront->pback = (BACK_CONN*)pnode->pdata;

		len = sprintf(temp_buff, "%s\r\n", pfront->buff);
		write(pfront->pback->sockd, temp_buff, len);
		if (0 != read_line(pfront->pback->sockd, pfront)) {

			close(pfront->pback->sockd);
			pfront->pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pfront->pback->node);
			pthread_mutex_unlock(&g_back_lock);

			pthread_mutex_lock(&g_front_lock);
			double_list_remove(&g_front_list, &pfront->node);
			pthread_mutex_unlock(&g_front_lock);
			write(pfront->sockd, "FALSE\r\n", 7);
			close(pfront->sockd);
			free(pfront);
			goto NEXT_LOOP;
		}
		time(&pfront->pback->last_time);
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pfront->pback->node);
		pfront->pback = NULL;
		pthread_mutex_unlock(&g_back_lock);

		len = snprintf(temp_buff, 1024, "%s\r\n", pfront->buff);
		write(pfront->sockd, temp_buff, len);
    }
	return NULL;
}

static int read_line(int sockd, FRONT_CONN *pconnection)
{
	fd_set myset;
	int read_len;
	struct timeval tv;

	while (1) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return -1;
		}
		read_len = read(sockd, pconnection->buff + pconnection->offset,
					1024 - pconnection->offset);
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
		if (1024 == pconnection->offset) {
			return -1;
		}
	}
}


static int connect_session()
{
    int sockd;
    int offset;
    int read_len;
	fd_set myset;
	struct timeval tv;
    char temp_buff[1024];
    struct sockaddr_in servaddr;


    sockd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(g_session_port);
    inet_pton(AF_INET, g_session_ip, &servaddr.sin_addr);
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


