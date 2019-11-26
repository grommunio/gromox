#include <stdbool.h>
#include "service_common.h"
#include "util.h"
#include "single_list.h"
#include "array.h"
#include "list_file.h"
#include "config_file.h"
#include "double_list.h"
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

#define CDNER_RESULT_OK			0
#define CDNER_NO_SERVER			1
#define CDNER_RDWR_ERROR		2
#define CDNER_RESULT_ERROR		3

typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
} BACK_CONN;

typedef struct _MSG_UNIT {
	SINGLE_LIST_NODE node;
	size_t size;
	char file_name[128];
	BOOL b_deleted;
} MSG_UNIT;

static void* scan_work_func(void *param);

static BOOL read_line(int sockd, char *buff, int length);

static int connect_cdner(const char *ip_addr, int port);

static int list_cdn_mail(const char *username, ARRAY *parray);

static int delete_cdn_mail(const char *username, SINGLE_LIST *plist);

static BOOL check_cdn_user(const char *username);

static BOOL auth_cdn_user(const char *username, const char *password);

static void create_cdn_user(const char *username);

static void console_talk(int argc, char **argv, char *result, int length);

static int g_conn_num;
static int g_host_port;
static char g_host_ip[16];
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_back_list;
static pthread_mutex_t g_back_lock;
static pthread_mutex_t g_crypt_lock;

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	int i;
	char *psearch;
	char *str_value;
    BACK_CONN *pback;
	char file_name[256];
	CONFIG_FILE *pconfig;
	char config_path[256];
    DOUBLE_LIST_NODE *pnode;

	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		
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
			printf("[cdner_agent]: fail to open config file!!!\n");
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
			printf("[cdner_agent]: module is switched off\n");
		} else {
			printf("[cdner_agent]: cdner connection number is %d\n",
				g_conn_num);
		}
		
		str_value = config_file_get_value(pconfig, "CDNER_HOST_IP");
		if (NULL == str_value) {
			strcpy(g_host_ip, "127.0.0.1");
		} else {
			strcpy(g_host_ip, str_value);
		}
		printf("[cdner_agent]: cdner host is %s\n", g_host_ip);
		
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
		printf("[cdner_agent]: cdner port is %d\n", g_host_port);

		config_file_save(pconfig);
		config_file_free(pconfig);

		if (0 == g_conn_num) {
			return TRUE;
		}

		double_list_init(&g_back_list);
		double_list_init(&g_lost_list);
		pthread_mutex_init(&g_back_lock, NULL);
		pthread_mutex_init(&g_crypt_lock, NULL);


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
			printf("[cdner_agent]: fail to create scan thread\n");
			return FALSE;
		}

		if (FALSE == register_service("cdn_uidl", list_cdn_mail) ||
			FALSE == register_service("cdn_remove", delete_cdn_mail) ||
			FALSE == register_service("cdn_check", check_cdn_user) ||
			FALSE == register_service("cdn_auth", auth_cdn_user) ||
			FALSE == register_service("cdn_create", create_cdn_user)) {
			printf("[cdner_agent]: fail to register services\n");
			return FALSE;
		}

		if (FALSE == register_talk(console_talk)) {
			printf("[cdner_agent]: fail to register console talk\n");
			return FALSE;
		}

		return TRUE;
	case PLUGIN_FREE:
		if (0 == g_conn_num) {
			return TRUE;
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
		pthread_mutex_destroy(&g_crypt_lock);
		
		return TRUE;
	}
	return false;
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

static BOOL check_cdn_user(const char *username)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	pback = get_connection();
	if (NULL == pback) {
		return FALSE;
	}

	length = snprintf(buff, 1024, "CHECK %s\r\n", username);
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
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return TRUE;
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

static BOOL auth_cdn_user(const char *username, const char *password)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	pback = get_connection();
	if (NULL == pback) {
		return FALSE;
	}

	length = snprintf(buff, 1024, "INFO %s\r\n", username);
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

	if (0 == strncasecmp(buff, "TRUE ", 5)) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);

		pthread_mutex_lock(&g_crypt_lock);
		if (0 == strcmp(crypt(password, buff + 5), buff + 5)) {
			pthread_mutex_unlock(&g_crypt_lock);
			return TRUE;
		} else {
			pthread_mutex_unlock(&g_crypt_lock);
			return FALSE;
		}
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

static void create_cdn_user(const char *username)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	pback = get_connection();
	if (NULL == pback) {
		return;
	}

	length = snprintf(buff, 1024, "CREATE %s\r\n", username);
	if (length != write(pback->sockd, buff, length)) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		return;
	}

	if (0 == strcasecmp(buff, "TRUE") ||
		0 == strcasecmp(buff, "FALSE")) {
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_back_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
	} else {
		close(pback->sockd);
		pback->sockd = -1;
		pthread_mutex_lock(&g_back_lock);
		double_list_append_as_tail(&g_lost_list, &pback->node);
		pthread_mutex_unlock(&g_back_lock);
	}

}

static int list_cdn_mail(const char *username, ARRAY *parray)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	fd_set myset;
	MSG_UNIT msg;
	char *pspace;
	BACK_CONN *pback;
	struct timeval tv;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];


	pback = get_connection();
	if (NULL == pback) {
		return CDNER_NO_SERVER;
	}

	length = snprintf(buff, 1024, "UIDL %s\r\n", username);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pback->sockd, &myset);
		if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
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
							goto RDWR_ERROR;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						pthread_mutex_lock(&g_back_lock);
						double_list_append_as_tail(&g_back_list,
							&pback->node);
						pthread_mutex_unlock(&g_back_lock);
						return CDNER_RESULT_ERROR;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					goto RDWR_ERROR;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				pspace = memchr(temp_line, ' ', line_pos);
				if (NULL == pspace) {
					goto RDWR_ERROR;
				}
				*pspace = '\0';
				if (strlen(temp_line) > 127) {
					goto RDWR_ERROR;
				}
				pspace ++;
				temp_line[line_pos] = '\0';

				strcpy(msg.file_name, temp_line);
				msg.size = atoi(pspace);
				msg.b_deleted = FALSE;
				array_append(parray, &msg);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 256) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pback->node);
			pthread_mutex_unlock(&g_back_lock);
			return CDNER_RESULT_OK;
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_back_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_back_lock);
	return CDNER_RDWR_ERROR;
}

static int delete_cdn_mail(const char *username, SINGLE_LIST *plist)
{
	int length;
	int cmd_len;
	int temp_len;
	MSG_UNIT *pmsg;
	BACK_CONN *pback;
	char buff[128*1025];
	SINGLE_LIST_NODE *pnode;


	if (0 == single_list_get_nodes_num(plist)) {
		return CDNER_RESULT_OK;
	}
	
	pback = get_connection();
	if (NULL == pback) {
		return CDNER_NO_SERVER;
	}

	length = snprintf(buff, 1024, "REMOVE %s", username);
	cmd_len = length;
	
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		pmsg = (MSG_UNIT*)pnode->pdata;
		buff[length] = ' ';
		length ++;
		temp_len = strlen(pmsg->file_name);
		memcpy(buff + length, pmsg->file_name, temp_len);
		length += temp_len;
		if (length > 128*1024) {
			buff[length] = '\r';
			length ++;
			buff[length] = '\n';
			length ++;
			if (length != write(pback->sockd, buff, length)) {
				goto DELETE_ERROR;
			}
			if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
				goto DELETE_ERROR;
			} else {
				if (0 == strncmp(buff, "TRUE", 4)) {
					length = snprintf(buff, 1024, "REMOVE %s", username);
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pthread_mutex_lock(&g_back_lock);
					double_list_append_as_tail(&g_back_list, &pback->node);
					pthread_mutex_unlock(&g_back_lock);
					return CDNER_RESULT_ERROR;	
				} else {
					goto DELETE_ERROR;
				}
			}
		}
	}

	if (length > cmd_len) {
		buff[length] = '\r';
		length ++;
		buff[length] = '\n';
		length ++;
		if (length != write(pback->sockd, buff, length)) {
			goto DELETE_ERROR;
		}
		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			goto DELETE_ERROR;
		} else {
			if (0 == strncmp(buff, "TRUE", 4)) {
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
				return CDNER_RESULT_OK;
			} else if (0 == strncmp(buff, "FALSE ", 6)) {
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pback->node);
				pthread_mutex_unlock(&g_back_lock);
				return CDNER_RESULT_ERROR;	
			} else {
				goto DELETE_ERROR;
			}
		}
	}


DELETE_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_back_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_back_lock);
	return CDNER_RDWR_ERROR;
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

static void console_talk(int argc, char **argv, char *result, int length)
{
	int alive_num;
	char help_string[] = "250 cdner agent help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --print the cdner server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		if (0 == g_conn_num) {
			alive_num = 0;
		} else {
			alive_num = double_list_get_nodes_num(&g_back_list);
		}
		snprintf(result, length,
			"250 agent information of cdner:\r\n"
			"\ttotal connections       %d\r\n"
			"\tavailable connections   %d",
			g_conn_num, alive_num);
			result[length - 1] = '\0';
			return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

