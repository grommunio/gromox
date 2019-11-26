#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "hook_common.h"
#include "list_file.h"
#include "config_file.h"
#include "util.h"
#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>


#define MAX_DIGLEN				256*1024

#define DEF_MODE				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define SOCKET_TIMEOUT			60

typedef struct _CIDB_ITEM {
	char prefix[128];
	char ip_addr[16];
	int port;
} CIDB_ITEM;

typedef struct _BACK_SVR {
	DOUBLE_LIST_NODE node;
	char prefix[128];
	char ip_addr[16];
	int port;
	DOUBLE_LIST conn_list;
	int conn_num;
} BACK_SVR;

typedef struct _BACK_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
	BACK_SVR *psvr;
} BACK_CONN;


static int g_conn_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static char g_list_path[256];
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_server_list;
static DOUBLE_LIST g_server_list1;
static pthread_mutex_t g_server_lock;


static BOOL (*backup_list_check)(const char*);

static BOOL (*domain_list_check)(const char*);

static BOOL archive_process(MESSAGE_CONTEXT *pcontext);

static int connect_cidb(const char *ip_addr, int port);

static BACK_CONN* get_connection(const char *pdomain);

static void* scan_work_func(void *param);

static BOOL load_list();

static void console_talk(int argc, char **argv, char *result, int length);

DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	char *psearch;
	char *str_value;
	BACK_CONN *pback;
	BACK_SVR *pserver;
	char file_name[256];
	CONFIG_FILE *pconfig;
	char config_path[256];
	DOUBLE_LIST_NODE *pnode;
	
	
	/* path conatins the config files directory */
	switch (reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		
		backup_list_check = query_service("backup_list_check");
		if (NULL == backup_list_check) {
			domain_list_check = query_service("check_domain");
			if (NULL == domain_list_check) {
				printf("[archive_agent]: fail to get \"check_domain\" service\n");
				return FALSE;
			}
		}
		
		double_list_init(&g_server_list);
		double_list_init(&g_server_list1);
		double_list_init(&g_lost_list);
		pthread_mutex_init(&g_server_lock, NULL);

		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig = config_file_init(config_path);
		if (NULL == pconfig) {
			printf("[archive_agent]: fail to open config file!!!\n");
			return FALSE;
		}
		
		sprintf(g_list_path, "%s/cidb_list.txt", get_data_path());
		str_value = config_file_get_value(pconfig, "CONNECTION_NUM");
		if (NULL == str_value) {
			g_conn_num = 5;
			config_file_set_value(pconfig, "CONNECTION_NUM", "5");
		} else {
			g_conn_num = atoi(str_value);
			if (g_conn_num < 2 || g_conn_num > 20) {
				g_conn_num = 5;
				config_file_set_value(pconfig, "CONNECTION_NUM", "5");
			}
		}

		printf("[archive_agent]: cidb connection number is %d\n", g_conn_num);

		config_file_save(pconfig);
		config_file_free(pconfig);

		if (FALSE == load_list()) {
			printf("[archive_agent]: fail to load cidb list\n");
			return FALSE;
		}
		
		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
			printf("[archive_agent]: fail to create scan thread\n");
			return FALSE;
		}
		
		register_talk(console_talk);
		
		if (FALSE == register_hook(archive_process)) {
			printf("[archive_agent]: fail to register the hook function\n");
			return FALSE;
		}
		return TRUE;
	case PLUGIN_FREE:
		if (FALSE == g_notify_stop) {
			g_notify_stop = TRUE;
			pthread_join(g_scan_id, NULL);
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

		while ((pnode = double_list_get_from_head(&g_server_list1)) != NULL) {
			pserver = (BACK_SVR*)pnode->pdata;
			while ((pnode = double_list_get_from_head(&pserver->conn_list)) != NULL) {
				pback = (BACK_CONN*)pnode->pdata;
				if (-1 != pback->sockd) {
					write(pback->sockd, "QUIT\r\n", 6);
					close(pback->sockd);
				}
				free(pback);
			}
			free(pserver);
		}

		double_list_free(&g_lost_list);
		double_list_free(&g_server_list);
		double_list_free(&g_server_list1);

		pthread_mutex_destroy(&g_server_lock);
		
		return TRUE;
	case SYS_THREAD_CREATE:
		return TRUE;
	case SYS_THREAD_DESTROY:
		return TRUE;
	}
	return false;
}



static BOOL archive_process(MESSAGE_CONTEXT *pcontext)
{
	int fd;
	int length;
	int offset;
	MAIL *pmail;
	MIME *phead;
	char *ptoken;
	fd_set myset;
	int read_len;
	char *pdomain;
	BOOL b_archive;
	char path[128];
	int64_t mail_id;
	BACK_CONN *pback;
	size_t encode_len;
	struct timeval tv;
	char rcpt_buff[256];
	char temp_path[256];
	MESSAGE_CONTEXT *pcontext1;
	char envelop_buff[128*1024];
	char temp_buff[2*MAX_DIGLEN];
	

	if (BOUND_IN != pcontext->pcontrol->bound_type &&
		BOUND_OUT != pcontext->pcontrol->bound_type &&
		BOUND_RELAY != pcontext->pcontrol->bound_type) {
		return FALSE;
	}
	if (0 == strcasecmp(pcontext->pcontrol->from,
		"system-monitor@system.mail")) {
		return FALSE;	
	}
	
	b_archive = FALSE;
	pdomain = strchr(pcontext->pcontrol->from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (NULL != backup_list_check) {
			if (TRUE == backup_list_check(pdomain)) {
				b_archive = TRUE;
			}
		} else {
			if (TRUE == domain_list_check(pdomain)) {
				b_archive = TRUE;
			}
		}
	}
	
	if (FALSE == b_archive) {
		while (MEM_END_OF_FILE != mem_file_readline(
			&pcontext->pcontrol->f_rcpt_to, rcpt_buff, 256)) {
			pdomain = strchr(rcpt_buff, '@');
			if (NULL == pdomain) {
				continue;
			}
			pdomain ++;
			if (NULL != backup_list_check) {
				if (TRUE == backup_list_check(pdomain)) {
					b_archive = TRUE;
					break;
				}
			} else {
				if (TRUE == domain_list_check(pdomain)) {
					b_archive = TRUE;
					break;
				}
			}
		}
	}
	
	if (FALSE == b_archive) {
		return FALSE;
	}
	
	offset = snprintf(envelop_buff, sizeof(envelop_buff),
						"%s", pcontext->pcontrol->from);
	offset ++;
	
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		 MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_buff, 256)) {
		offset += snprintf(envelop_buff + offset,
			sizeof(envelop_buff) - offset, "%s", rcpt_buff);
		if (offset >= sizeof(envelop_buff) - 1) {
			return FALSE;
		}
		offset ++;
	}
	
	envelop_buff[offset] = '\0';
	offset ++;


	pmail = pcontext->pmail;
	phead = mail_get_head(pmail);
	if (NULL == phead || TRUE == mime_get_field(
		phead, "X-CIDB-ARCHIVED", temp_buff, 32)) {
		return FALSE;
	}
	if (TRUE == mail_check_dot(pcontext->pmail)) {
		pcontext1 = get_context();
		if (NULL != pcontext1) {
			if (TRUE == mail_transfer_dot(
				pcontext->pmail, pcontext1->pmail)) {
				pmail = pcontext1->pmail;
			} else {
				put_context(pcontext1);
				pcontext1 = NULL;
			}
		}
	} else {
		pcontext1 = NULL;
	}


	length = sprintf(temp_buff, "A-INST ");
	encode64(envelop_buff, offset, temp_buff + length,
		sizeof(temp_buff) - length, &encode_len);
	length += encode_len;

	temp_buff[length] = ' ';
	length ++;
	
	length += sprintf(temp_buff + length, "{\"file\":\"\",");

	if (1 != mail_get_digest(pmail, &encode_len,
		temp_buff + length, sizeof(temp_buff) - length - 2)) {
		if (NULL != pcontext1) {
			put_context(pcontext1);
		}
		return FALSE;
	}

	length += strlen(temp_buff + length);
	memcpy(temp_buff + length, "}\r\n", 3);
	length += 3;
	
	pback = get_connection(pdomain);
	if (NULL == pback) {
		if (NULL != pcontext1) {
			put_context(pcontext1);
		}
		return FALSE;
	}
	
	if (length != write(pback->sockd, temp_buff, length)) {
		goto RDWR_ERROR;
	}
	
	offset = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pback->sockd, &myset);
		if (select(pback->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, temp_buff + offset, 1024 - offset);
		if (read_len <= 0) {
			goto RDWR_ERROR;
		}
		offset += read_len;
		if (offset >= 2 && '\r' == temp_buff[offset - 2] &&
			'\n' == temp_buff[offset - 1]) {
			if (offset > 7 && 0 == strncasecmp("TRUE ", temp_buff, 5)) {
				time(&pback->last_time);
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				temp_buff[offset - 2] = '\0';
				ptoken = strchr(temp_buff + 5, ' ');
				if (NULL == ptoken) {
					if (NULL != pcontext1) {
						put_context(pcontext1);
					}
					return FALSE;
				}
				
				*ptoken = '\0';
				mail_id = atoll(temp_buff + 5);
				strncpy(path, ptoken + 1, 128);
				snprintf(temp_path, 256, "%s%s/%lld", pback->psvr->prefix,
					path, mail_id);
				fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, DEF_MODE);
				if (-1 != fd) {
					mail_to_file(pmail, fd);
					close(fd);
				}
				if (NULL != pcontext1) {
					put_context(pcontext1);
				}
				return FALSE;					
			} else {
				goto RDWR_ERROR;
			}
		}
		if (1024 == offset) {
			goto RDWR_ERROR;
		}
	}

RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	if (NULL != pcontext1) {
		put_context(pcontext1);
	}
	return FALSE;
	
	
}

static int connect_cidb(const char *ip_addr, int port)
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

	while (FALSE == g_notify_stop) {
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
		while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			/* check if cidb server is still available in list */
			for (pnode1=double_list_get_head(&g_server_list); NULL!=pnode1;
				pnode1=double_list_get_after(&g_server_list, pnode1)) {
				if (pback->psvr == (BACK_SVR*)pnode1->pdata) {
					break;
				}
			}
			if (NULL == pnode1) {
				double_list_append_as_tail(&pback->psvr->conn_list, pnode1);
			} else {
				double_list_append_as_tail(&temp_list, pnode);
			}
		}
		pthread_mutex_unlock(&g_server_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pback = (BACK_CONN*)pnode->pdata;
			pback->sockd = connect_cidb(pback->psvr->ip_addr,
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
		
		pthread_mutex_lock(&g_server_lock);
		if (0 != double_list_get_nodes_num(&g_server_list1)) {
			ptail = double_list_get_tail(&g_server_list1);
			while ((pnode = double_list_get_from_head(&g_server_list1)) != NULL) {
				pserver = (BACK_SVR*)pnode->pdata;
				if (pserver->conn_num == double_list_get_nodes_num(&pserver->conn_list)) {
					while ((pnode1 = double_list_get_from_head(&pserver->conn_list)) != NULL) {
						pback = (BACK_CONN*)pnode1->pdata;
						if (-1 != pback->sockd) {
							write(pback->sockd, "QUIT\r\n", 6);
							close(pback->sockd);
						}
						free(pback);
					}
					free(pserver);	
				} else {
					double_list_append_as_tail(&g_server_list1, pnode);
				}
				if (pnode == ptail) {
					break;
				}
			}
		}
		pthread_mutex_unlock(&g_server_lock);
		
		sleep(1);
	}
	return NULL;
}

static BACK_CONN *get_connection(const char *pdomain)
{
	int i, len, num;
	char tmp_buff[9];
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	

	len = strlen(pdomain);
	if (len >= 8) {
		memcpy(tmp_buff, pdomain, 8);
		tmp_buff[8] = '\0';
	} else {
		memcpy(tmp_buff, pdomain, len);
		memset(tmp_buff + len, 0, 9 - len);
	}

	lower_string(tmp_buff);

	pthread_mutex_lock(&g_server_lock);
	if (0 == double_list_get_nodes_num(&g_server_list)) {
		pthread_mutex_unlock(&g_server_lock);
		return NULL;
	}

	num = (*(uint64_t*)tmp_buff) % double_list_get_nodes_num(&g_server_list);

	pnode = double_list_get_head(&g_server_list);
	for (i=0; i<num; i++) {
		pnode = double_list_get_after(&g_server_list, pnode);
	}	
	pserver = (BACK_SVR*)pnode->pdata;
	pnode = double_list_get_from_head(&pserver->conn_list);
	pthread_mutex_unlock(&g_server_lock);
	if (NULL == pnode) {
		return NULL;
	}
	return (BACK_CONN*)pnode->pdata;
}

static BOOL load_list()
{
	int i, j;
	int list_num;
	CIDB_ITEM *pitem;
	LIST_FILE *plist;
	BACK_CONN *pback;
	BACK_SVR *pserver;
	
	plist = list_file_init(g_list_path, "%s:128%s:16%d");
	if (NULL == plist) {
		return FALSE;
	}


	list_num = list_file_get_item_num(plist);
	pitem = (CIDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<list_num; i++) {
		pserver = (BACK_SVR*)malloc(sizeof(BACK_SVR));
		if (NULL == pserver) {
			continue;
		}
		pserver->node.pdata = pserver;
		strcpy(pserver->prefix, pitem[i].prefix);
		strcpy(pserver->ip_addr, pitem[i].ip_addr);
		pserver->port = pitem[i].port;
		pserver->conn_num = 0;
		double_list_init(&pserver->conn_list);
		double_list_append_as_tail(&g_server_list, &pserver->node);
		for (j=0; j<g_conn_num; j++) {
		   pback = (BACK_CONN*)malloc(sizeof(BACK_CONN));
			if (NULL != pback) {
				pback->node.pdata = pback;
				pback->sockd = -1;
				pback->psvr = pserver;
				double_list_append_as_tail(&g_lost_list, &pback->node);
				pserver->conn_num ++;
			}
		}
	}
	list_file_free(plist);

	return TRUE;
	
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	int i;
	BOOL b_locked;
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	char help_string[] = "250 cidb agent help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the cidb list\r\n"
						 "\t%s echo mp-path\r\n"
						 "\t    --print the cidb server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		b_locked = FALSE;
		for (i=1; i<SOCKET_TIMEOUT; i++) {
			pthread_mutex_lock(&g_server_lock);
			if (0 != double_list_get_nodes_num(&g_server_list1)) {
				pthread_mutex_unlock(&g_server_lock);
				sleep(1);
				continue;
			} else {
				b_locked = TRUE;
				break;
			}
		}
		
		if (FALSE == b_locked) {
			strncpy(result, "550 backup server list not empty", length);
			return;
		}
		
		while ((pnode = double_list_get_from_head(&g_server_list)) != NULL)
			double_list_append_as_tail(&g_server_list1, pnode);
		
		if (FALSE == load_list()) {
			while ((pnode = double_list_get_from_head(&g_server_list1)) != NULL)
				double_list_append_as_tail(&g_server_list, pnode);
			pthread_mutex_unlock(&g_server_lock);
			strncpy(result, "550 reload cidb list fail", length);
			return;
		}
		
		pthread_mutex_unlock(&g_server_lock);
		
		strncpy(result, "250 server list reload OK", length);
		return;
		
	}
	
	if (3 == argc && 0 == strcmp("echo", argv[1])) {
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			if (0 == strcmp(argv[2], pserver->prefix)) {
				snprintf(result, length,
				"250 agent information of cidb(prefix:%s ip:%s port:%d):\r\n"
				"\ttotal connections       %d\r\n"
				"\tavailable connections   %d",
				pserver->prefix, pserver->ip_addr, pserver->port,
				g_conn_num, double_list_get_nodes_num(&pserver->conn_list));
				result[length - 1] = '\0';
				return;
			}
		}
		snprintf(result, length, "250 no agent inforamtion of cidb(prefix:%s)", 
			argv[2]);
		return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


