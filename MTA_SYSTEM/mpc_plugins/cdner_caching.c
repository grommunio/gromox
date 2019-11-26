#include <stdbool.h>
#include "hook_common.h"
#include "double_list.h"
#include "config_file.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#define SOCKET_TIMEOUT			60

DECLARE_API;

typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
} BACK_CONN;

static int g_conn_num;
static int g_host_port;
static char g_host_ip[16];
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_back_list;
static pthread_mutex_t g_back_lock;



static void* scan_work_func(void *param);

static BACK_CONN *get_connection();

static BOOL read_line(int sockd, char *buff, int length);

static int connect_cdner(const char *ip_addr, int port);

static BOOL (*check_domain_list)(const char *domainname);

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext);

static void console_talk(int argc, char **argv, char *result, int length);

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	int i;
	char *psearch;
	char *str_value;
    BACK_CONN *pback;
	char file_name[256];
	CONFIG_FILE *pconfig;
	char config_path[256];
    DOUBLE_LIST_NODE *pnode;
	
    /* path conatins the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		check_domain_list = query_service("check_domain");
		if (NULL == check_domain_list) {
			printf("[cdner_caching]: fail to get \"check_domain\" service\n");
			return FALSE;
		}

		g_notify_stop = TRUE;
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig = config_file_init(config_path);
		if (NULL == pconfig) {
			printf("[cdner_caching]: fail to open config file!!!\n");
			return FALSE;
		}
		
		str_value = config_file_get_value(pconfig, "CONNECTION_NUM");
		if (NULL == str_value) {
			g_conn_num = 0;
		} else {
			g_conn_num = atoi(str_value);
			if (g_conn_num < 0) {
				g_conn_num = 0;
			} else if (g_conn_num > 20) {
				g_conn_num = 5;
				config_file_set_value(pconfig, "CONNECTION_NUM", "5");
			}
		}
		if (0 == g_conn_num) {
			printf("[cdner_caching]: module is switched off\n");
		} else {
			printf("[cdner_caching]: cdner connection number is %d\n",
				g_conn_num);
		}
		
		str_value = config_file_get_value(pconfig, "CDNER_HOST_IP");
		if (NULL == str_value) {
			strcpy(g_host_ip, "127.0.0.1");
		} else {
			strcpy(g_host_ip, str_value);
		}
		printf("[cdner_caching]: cdner host is %s\n", g_host_ip);
		
		str_value = config_file_get_value(pconfig, "CDNER_HOST_PORT");
		if (NULL == str_value) {
			g_host_port = 10001;
			config_file_set_value(pconfig, "CDNER_HOST_PORT", "10001");
		} else {
			g_host_port = atoi(str_value);
			if (g_host_port <= 0) {
				g_host_port = 10001;
				config_file_set_value(pconfig, "CDNER_HOST_PORT", "10001");
			}
		}
		printf("[cdner_caching]: cdner port is %d\n", g_host_port);

		config_file_save(pconfig);
		config_file_free(pconfig);

		register_talk(console_talk);
	
		if (0 == g_conn_num) {
			return TRUE;
		}
		double_list_init(&g_back_list);
		double_list_init(&g_lost_list);
		pthread_mutex_init(&g_back_lock, NULL);

		for (i=0; i<g_conn_num; i++) {
			pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
			if (NULL != pback) {
				pback->node.pdata = pback;
				pback->sockd = -1;
				double_list_append_as_tail(&g_lost_list, &pback->node);
			}
		}

		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
			printf("[cdner_caching]: fail to create cdner scan thread\n");
			g_notify_stop = TRUE;
			return FALSE;
		}

		if (FALSE == register_hook(mail_hook)) {
			printf("[cdner_caching]: fail to register the hook function\n");
			return FALSE;
		}


		printf("[cdner_caching]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
		if (0 == g_conn_num) {
			return 0;
		}
	
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_join(g_scan_id, NULL);
		}

		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			free(pnode->pdata);

		while ((pnode = double_list_get_from_head(&g_back_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			write(pback->sockd, "QUIT\r\n", 6);
			close(pback->sockd);
			free(pback);
		}

		double_list_free(&g_lost_list);
		double_list_free(&g_back_list);

		pthread_mutex_destroy(&g_back_lock);
		
        return TRUE;
    }
	return false;
}

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext)
{
	int length;
	MAIL *pmail;
	char *pdomain;
	char buff[1024];
	BACK_CONN *pback;
	char rcpt_to[256];
	MESSAGE_CONTEXT *pcontext1;

	if (0 == g_conn_num) {
		return FALSE;
	}


	while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		if (NULL == pdomain) {
			continue;
		}
		pdomain ++;
		if (FALSE == check_domain_list(pdomain)) {
			continue;
		}
		
		pback = get_connection();
		if (NULL == pback) {
			return FALSE;
		}

		length = snprintf(buff, 1024, "CHECK %s\r\n", rcpt_to);
		if (length != write(pback->sockd, buff, length)) {
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}

		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}

		if (0 == strcasecmp(buff, "TRUE")) {
			/* do nothing */
		} else if (0 == strcasecmp(buff, "FALSE")) {
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;	
		} else {
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}

		if (TRUE == mail_check_dot(pcontext->pmail)) {
			pcontext1 = get_context();
			if (NULL != pcontext1) {
				if (FALSE == mail_transfer_dot(pcontext->pmail, pcontext1->pmail)) {
					put_context(pcontext1);
					pcontext1 = NULL;
				}
			}
		} else {
			pcontext1 = NULL;
		}

		if (NULL != pcontext1) {
			pmail = pcontext1->pmail;
		} else {
			pmail = pcontext->pmail;
		}

		length = snprintf(buff, 1024, "CACHE %s %d\r\n",
					rcpt_to, mail_get_length(pmail));
		if (length != write(pback->sockd, buff, length)) {
			if (NULL != pcontext1) {
				put_context(pcontext1);
			}
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}

		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			if (NULL != pcontext1) {
				put_context(pcontext1);
			}
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}
		if (0 == strcasecmp(buff, "+CONTINUE")) {
			/* do nothing */
		} else if (0 == strcasecmp(buff, "FALSE")) {
			if (NULL != pcontext1) {
				put_context(pcontext1);
			}
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;	
		} else {
			if (NULL != pcontext1) {
				put_context(pcontext1);
			}
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}
		mail_to_file(pmail, pback->sockd);

		if (NULL != pcontext1) {
			put_context(pcontext1);
		}

		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}
		
		if (0 == strcasecmp(buff, "TRUE")) {
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
		} else if (0 == strcasecmp(buff, "FALSE")) {
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;	
		} else {
			close(pback->sockd);
			pback->sockd = -1;
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_lost_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return FALSE;
		}

	}
	
	return FALSE;
}


/*
 *	string table's console talk
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments value
 *		result [out]	buffer for retrieving result
 *		length			result buffer length
 */
static void console_talk(int argc, char **argv, char *result, int length)
{
	int alive_num;
	char help_string[] = "250 cdn cache help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --print the cdner server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		if (0 == g_conn_num) {
			alive_num = 0;
		} else {
			alive_num = double_list_get_nodes_num(&g_back_list);
		}
		snprintf(result, length,
			"250 cdn cache information:\r\n"
			"\ttotal connections       %d\r\n"
			"\tavailable connections   %d",
			g_conn_num, alive_num);
		result[length - 1] = '\0';
		return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
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

	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_back_lock);
		time(&now_time);
		ptail = double_list_get_tail(&g_back_list);
		while ((pnode = double_list_get_from_head(&g_back_list)) != NULL) {
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
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
			} else {
				time(&pback->last_time);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list,
					&pback->node);
				pthread_mutex_unlock(&g_back_lock);
			}
		}

		pthread_mutex_lock(&g_back_lock);
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_back_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_cdner(g_host_ip, g_host_port);
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

static BACK_CONN *get_connection()
{
	int i;
	DOUBLE_LIST_NODE *pnode;

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
		if (NULL == pnode) {
			return NULL;
		}
	}
	return (BACK_CONN*)pnode->pdata;
}


static BOOL read_line(int sockd, char *buff, int length)
{
	int offset;
	fd_set myset;
	int read_len;
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
		
		read_len = read(sockd, buff + offset,  length - offset);
		if (read_len <= 0) {
			return FALSE;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == buff[offset - 2] &&
			'\n' == buff[offset - 1]) {
			offset -= 2;
			buff[offset] = '\0';
			return TRUE;
		}
		if (length == offset) {
			return FALSE;
		}
	}
	
}

static int connect_cdner(const char *ip_addr, int port)
{
    int sockd;
    int read_len;
	fd_set myset;
	struct timeval tv;
    char temp_buff[1024];
    struct sockaddr_in servaddr;


    sockd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
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

