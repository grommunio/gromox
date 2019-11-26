#include <stdbool.h>
#include <gromox/mrasvc_common.h>
#include "util.h"
#include "single_list.h"
#include "array.h"
#include "xarray.h"
#include "mem_file.h"
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>

#define SOCKET_TIMEOUT			60

#define MIDB_RESULT_OK			0
#define MIDB_NO_SERVER			1
#define MIDB_RDWR_ERROR			2
#define MIDB_RESULT_ERROR		3

#define FLAG_RECENT				0x1
#define FLAG_ANSWERED			0x2
#define FLAG_FLAGGED			0x4
#define FLAG_DELETED			0x8
#define FLAG_SEEN				0x10
#define FLAG_DRAFT				0x20

#define FLAG_LOADED				0x80

typedef struct _MIDB_ITEM {
	char prefix[256];
	char ip_addr[16];
	int port;
} MIDB_ITEM;

typedef struct _MITEM {
	SINGLE_LIST_NODE node;
	char mid[128];
	int id;
	int uid;
	char flag_bits;
	MEM_FILE f_digest;
} MITEM;

typedef struct _SQUENCE_NODE {
	DOUBLE_LIST_NODE node;
	int min;
	int max;
} SQUENCE_NODE;

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

typedef struct _MSG_UNIT {
	SINGLE_LIST_NODE node;
	size_t size;
	char file_name[128];
	BOOL b_deleted;
} MSG_UNIT;

static void* scan_work_func(void *param);

static BOOL read_line(int sockd, char *buff, int length);

static int connect_midb(const char *ip_addr, int port);
static BOOL get_digest_string(const char *src, int length, const char *tag, char *buff, int buff_len);
static BOOL get_digest_integer(const char *src, int length, const char *tag, int *pinteger);
static int list_mail(const char *path, const char *folder, ARRAY *parray, int *pnum, uint64_t *psize);
static int delete_mail(const char *path, const char *folder, SINGLE_LIST *plist);
static int get_mail_id(char *path, char *folder, char *mid_string,
	unsigned int *pid);

static int get_mail_uid(char *path, char *folder, char *mid_string,
	unsigned int *puid);

static int summary_folder(char *path, char *folder, int *pexists, 
	int *precent, int *punseen, unsigned long *puidvalid,
	unsigned int *puidnext, int *pfirst_seen, int *perrno);
	
static int make_folder(char *path, char *folder, int *perrno);

static int remove_folder(char *path, char *folder, int *perrno);

static int ping_mailbox(char *path, int *perrno);

static int rename_folder(char *path, char *src_name, char *dst_name,
	int *perrno);

static int subscribe_folder(char *path, char *folder, int *perrno);

static int unsubscribe_folder(char *path, char *folder, int *perrno);

static int enum_folders(char *path, MEM_FILE *pfile, int *perrno);

static int enum_subscriptions(char *path, MEM_FILE *pfile, int *perrno);

static int insert_mail(char *path, char *folder, char *file_name,
	char *flags_string, long time_stamp, int *perrno);

static int remove_mail(char *path, char *folder, SINGLE_LIST *plist,
	int *perrno);

static int list_simple(char *path, char *folder, XARRAY *pxarray,
	int *perrno);
	
static int list_deleted(char *path, char *folder, XARRAY *pxarray,
	int *perrno);

static int list_detail(char *path, char *folder, XARRAY *pxarray,
	int *perrno);

static void free_result(XARRAY *pxarray);

static int fetch_simple(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno);

static int fetch_detail(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno);
	
static int fetch_simple_uid(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno);
	
static int fetch_detail_uid(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno);

static int set_mail_flags(char *path, char *folder, char *mid_string,
	int flag_bits, int *perrno);
	
static int unset_mail_flags(char *path, char *folder, char *mid_string,
	int flag_bits, int *perrno);
	
static int get_mail_flags(char *path, char *folder, char *mid_string,
	int *pflag_bits, int *perrno);
	
static int copy_mail(char *path, char *src_folder, char *mid_string,
	char *dst_folder, char *dst_mid, int *perrno);

static int imap_search(char *path, char *folder, char *charset,
	int argc, char **argv, char *ret_buff, int *plen, int *perrno);

static int imap_search_uid(char *path, char *folder, char *charset,
	int argc, char **argv, char *ret_buff, int *plen, int *perrno);

static void console_talk(int argc, char **argv, char *result, int length);

static int g_conn_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static DOUBLE_LIST g_lost_list;
static DOUBLE_LIST g_server_list;
static pthread_mutex_t g_server_lock;
static LIB_BUFFER *g_file_allocator;
static int g_file_ratio;

DECLARE_API;

BOOL SVC_LibMain(int reason, void **ppdata)
{
	int i, j;
	int list_num;
	char *psearch;
	char *str_value;
	char file_name[256];
	char list_path[256];
	char config_path[256];
    BACK_CONN *pback;
	BACK_SVR *pserver;
	LIST_FILE *plist;
	MIDB_ITEM *pitem;
	CONFIG_FILE *pconfig;
    DOUBLE_LIST_NODE *pnode;

	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		
		g_notify_stop = TRUE;

		double_list_init(&g_server_list);
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
			printf("[midb_agent]: fail to open config file!!!\n");
			return FALSE;
		}
		
		sprintf(list_path, "%s/midb_list.txt", get_data_path());
		str_value = config_file_get_value(pconfig, "CONNECTION_NUM");
		if (NULL == str_value) {
			g_conn_num = 5;
			config_file_set_value(pconfig, "CONNECTION_NUM", "5");
		} else {
			g_conn_num = atoi(str_value);
			if (g_conn_num < 2 || g_conn_num > 100) {
				g_conn_num = 5;
				config_file_set_value(pconfig, "CONNECTION_NUM", "5");
			}
		}
		printf("[midb_agent]: midb connection number is %d\n", g_conn_num);
		
		str_value = config_file_get_value(pconfig, "CONTEXT_AVERAGE_MEM");
		if (NULL == str_value) {
			g_file_ratio = 0;
		} else {
			g_file_ratio = atoi(str_value);
		}
		
		if (g_file_ratio > 0) {
			printf("[midb_agent]: context average number is %d\n", g_file_ratio);
		} else {
			printf("[midb_agent]: memory pool is switched off\n");
		}

		config_file_save(pconfig);
		config_file_free(pconfig);

		plist = list_file_init(list_path, "%s:256%s:16%d");
		if (NULL == plist) {
			printf("[midb_agent]: fail to open midb list file\n");
			return FALSE;
		}


		list_num = list_file_get_item_num(plist);
		pitem = (MIDB_ITEM*)list_file_get_list(plist);
		for (i=0; i<list_num; i++) {
			pserver = (BACK_SVR*)malloc(sizeof(BACK_SVR));
			if (NULL == pserver) {
				printf("[midb_agent]: fail to allocate memory for midb\n");
				list_file_free(plist);
				return FALSE;
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
		
		if (g_file_ratio > 0) {
			g_file_allocator = lib_buffer_init(FILE_ALLOC_SIZE, 
								get_context_num()*g_file_ratio, TRUE);
			
			if (NULL == g_file_allocator) {
				printf("[midb_agent]: fail to init memory pool\n");
				return FALSE;
			}
		}

		g_notify_stop = FALSE;
		if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
			printf("[midb_agent]: fail to create scan thread\n");
			return FALSE;
		}

		if (FALSE == register_service("list_mail", list_mail) ||
			FALSE == register_service("delete_mail", delete_mail) ||
			FALSE == register_service("get_mail_id", get_mail_id) ||
			FALSE == register_service("get_mail_uid", get_mail_uid) ||
			FALSE == register_service("summary_folder", summary_folder) ||
			FALSE == register_service("make_folder", make_folder) ||
			FALSE == register_service("remove_folder", remove_folder) ||
			FALSE == register_service("ping_mailbox", ping_mailbox) ||
			FALSE == register_service("rename_folder", rename_folder) ||
			FALSE == register_service("subscribe_folder", subscribe_folder) ||
			FALSE == register_service("unsubscribe_folder", unsubscribe_folder) ||
			FALSE == register_service("enum_folders", enum_folders) ||
			FALSE == register_service("enum_subscriptions", enum_subscriptions) ||
			FALSE == register_service("insert_mail", insert_mail) ||
			FALSE == register_service("remove_mail", remove_mail) ||
			FALSE == register_service("list_simple", list_simple) ||
			FALSE == register_service("list_deleted", list_deleted) ||
			FALSE == register_service("list_detail", list_detail) ||
			FALSE == register_service("fetch_simple", fetch_simple) ||
			FALSE == register_service("fetch_detail", fetch_detail) ||
			FALSE == register_service("fetch_simple_uid", fetch_simple_uid) ||
			FALSE == register_service("fetch_detail_uid", fetch_detail_uid) ||
			FALSE == register_service("free_result", free_result) ||
			FALSE == register_service("set_mail_flags", set_mail_flags) ||
			FALSE == register_service("unset_mail_flags", unset_mail_flags) ||
			FALSE == register_service("get_mail_flags", get_mail_flags) ||
			FALSE == register_service("copy_mail", copy_mail) ||
			FALSE == register_service("imap_search", imap_search) ||
			FALSE == register_service("imap_search_uid", imap_search_uid)) {
			printf("[midb_agent]: fail to register services\n");
			return FALSE;
		}

		if (FALSE == register_talk(console_talk)) {
			printf("[midb_agent]: fail to register console talk\n");
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

		double_list_free(&g_lost_list);
		double_list_free(&g_server_list);

		pthread_mutex_destroy(&g_server_lock);
		
		if (NULL != g_file_allocator) {
			lib_buffer_free(g_file_allocator);
			g_file_allocator = NULL;
		}

		return TRUE;
	}
	return false;
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
	int tv_msec;
	char temp_buff[1024];
	struct pollfd pfd_read;


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
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec) ||
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

static int list_mail(const char *path, const char *folder, ARRAY *parray,
	int *pnum, uint64_t *psize)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	BOOL b_fail;
	int last_pos;
	int read_len;
	int line_pos;
	MSG_UNIT msg;
	char *pspace;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-UIDL %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	*psize = 0;
	count = 0;
	offset = 0;
	lines = -1;
	b_fail = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
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
						*pnum = lines;
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						pthread_mutex_lock(&g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						pthread_mutex_unlock(&g_server_lock);
						return MIDB_RESULT_ERROR;
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
				*psize += msg.size;
				msg.b_deleted = FALSE;
				if (array_append(parray, &msg) < 0) {
					b_fail = TRUE;
				}
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
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			if (TRUE == b_fail) {
				array_clear(parray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
			}
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
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	array_clear(parray);
	return MIDB_RDWR_ERROR;
}

static int delete_mail(const char *path, const char *folder, SINGLE_LIST *plist)
{
	int length;
	int cmd_len;
	int temp_len;
	MSG_UNIT *pmsg;
	BACK_CONN *pback;
	char buff[128*1025];
	SINGLE_LIST_NODE *pnode;


	if (0 == single_list_get_nodes_num(plist)) {
		return MIDB_RESULT_OK;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-DELE %s %s", path, folder);
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
					length = snprintf(buff, 1024, "M-DELE %s %s", path, folder);
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pthread_mutex_lock(&g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list,
						&pback->node);
					pthread_mutex_unlock(&g_server_lock);
					return MIDB_RESULT_ERROR;	
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
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				return MIDB_RESULT_OK;
			} else if (0 == strncmp(buff, "FALSE ", 6)) {
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				return MIDB_RESULT_ERROR;	
			} else {
				goto DELETE_ERROR;
			}
		}
	}


DELETE_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int imap_search(char *path, char *folder, char *charset,
	int argc, char **argv, char *ret_buff, int *plen, int *perrno)
{
	int i;
	int length;
	int length1;
	BACK_CONN *pback;
	size_t encode_len;
	char buff[256*1025];
	char buff1[16*1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, sizeof(buff), "P-SRHL %s %s %s ",
				path, folder, charset);
	length1 = 0;
	for (i=0; i<argc; i++) {
		length1 += snprintf(buff1 + length1, sizeof(buff1) - length1,
					"%s", argv[i]) + 1;
	}
	buff1[length1] = '\0';
	length1 ++;
	encode64(buff1, length1, buff + length, sizeof(buff) - length,
		&encode_len);
	length += encode_len;
	
	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			length = strlen(buff + 4);
			if (0 == length) {
				*plen = 0;
				return MIDB_RESULT_OK;
			}
			/* trim the first space */
			length --;
			if (length > *plen) {
				length = *plen;
			} else {
				*plen = length;
			}
			/* ignore the first space */
			memcpy(ret_buff, buff + 4 + 1, length);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;

}

static int imap_search_uid(char *path, char *folder, char *charset,
	int argc, char **argv, char *ret_buff, int *plen, int *perrno)
{
	int i;
	int length;
	int length1;
	BACK_CONN *pback;
	size_t encode_len;
	char buff[256*1025];
	char buff1[16*1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, sizeof(buff), "P-SRHU %s %s %s ",
				path, folder, charset);
	length1 = 0;
	for (i=0; i<argc; i++) {
		length1 += snprintf(buff1 + length1, sizeof(buff1) - length1,
					"%s", argv[i]) + 1;
	}
	buff1[length1] = '\0';
	length1 ++;
	encode64(buff1, length1, buff + length, sizeof(buff) - length,
		&encode_len);
	length += encode_len;
	
	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			length = strlen(buff + 4);
			if (0 == length) {
				*plen = 0;
				return MIDB_RESULT_OK;
			}
			/* trim the first space */
			length --;
			if (length > *plen) {
				length = *plen;
			} else {
				*plen = length;
			}
			/* ignore the first space */
			memcpy(ret_buff, buff + 4 + 1, length);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;

}


static int get_mail_id(char *path, char *folder, char *mid_string,
	unsigned int *pid)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-OFST %s %s %s UID ASC\r\n",
				path, folder, mid_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			*pid = atoi(buff + 5) + 1;
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;

}

static int get_mail_uid(char *path, char *folder, char *mid_string,
	unsigned int *puid)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-UNID %s %s %s\r\n",
				path, folder, mid_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			*puid = atoi(buff + 5);
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int summary_folder(char *path, char *folder, int *pexists, 
	int *precent, int *punseen, unsigned long *puidvalid,
	unsigned int *puidnext, int *pfirst_unseen, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	int exists, recent;
	int unseen, first_unseen;
	unsigned long uidvalid;
	unsigned int uidnext;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-FDDT %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			if (6 != sscanf(buff, "TRUE %d %d %d %ld %d %d", &exists,
				&recent, &unseen, &uidvalid, &uidnext, &first_unseen)) {
				*perrno = -1;
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				return MIDB_RESULT_ERROR;
			}
			if (NULL != pexists) {
				*pexists = exists;
			}
			if (NULL != precent) {
				*precent = recent;
			}
			if (NULL != punseen) {
				*punseen = unseen;
			}
			if (NULL != puidvalid) {
				*puidvalid = uidvalid;
			}
			if (NULL != puidnext) {
				*puidnext = uidnext;
			}
			if (NULL != pfirst_unseen) {
				*pfirst_unseen = first_unseen + 1;
			}
			
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}
	
static int make_folder(char *path, char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-MAKF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int remove_folder(char *path, char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-REMF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int ping_mailbox(char *path, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-PING %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int rename_folder(char *path, char *src_name, char *dst_name,
	int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-RENF %s %s %s\r\n", path,
				src_name, dst_name);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int subscribe_folder(char *path, char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-SUBF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int unsubscribe_folder(char *path, char *folder, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-UNSF %s %s\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int enum_folders(char *path, MEM_FILE *pfile, int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-ENUM %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
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
						pthread_mutex_lock(&g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						pthread_mutex_unlock(&g_server_lock);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					} else {
						goto RDWR_ERROR;
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
				temp_line[line_pos] = '\0';
				mem_file_writeline(pfile, temp_line);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 512) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
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
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;

}

static int enum_subscriptions(char *path, MEM_FILE *pfile, int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	struct pollfd pfd_read;
	

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-SUBL %s\r\n", path);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
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
						pthread_mutex_lock(&g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						pthread_mutex_unlock(&g_server_lock);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
					} else {
						goto RDWR_ERROR;
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
				temp_line[line_pos] = '\0';
				mem_file_writeline(pfile, temp_line);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos > 150) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
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
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;

}

static int insert_mail(char *path, char *folder, char *file_name,
	char *flags_string, long time_stamp, int *perrno)
{
	int length;
	char buff[1024];
	BACK_CONN *pback;

	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, sizeof(buff), "M-INST %s %s %s %s %ld\r\n",
				path, folder, file_name, flags_string, time_stamp);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}

RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int remove_mail(char *path, char *folder, SINGLE_LIST *plist,
	int *perrno)
{
	int length;
	int cmd_len;
	int temp_len;
	MITEM *pitem;
	BACK_CONN *pback;
	char buff[128*1025];
	SINGLE_LIST_NODE *pnode;

	if (0 == single_list_get_nodes_num(plist)) {
		return MIDB_RESULT_OK;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-DELE %s %s", path, folder);
	cmd_len = length;
	
	for (pnode=single_list_get_head(plist); NULL!=pnode;
		pnode=single_list_get_after(plist, pnode)) {
		pitem = (MITEM*)pnode->pdata;
		buff[length] = ' ';
		length ++;
		temp_len = strlen(pitem->mid);
		memcpy(buff + length, pitem->mid, temp_len);
		length += temp_len;
		if (length > 128*1024) {
			buff[length] = '\r';
			length ++;
			buff[length] = '\n';
			length ++;
			if (length != write(pback->sockd, buff, length)) {
				goto RDWR_ERROR;
			}
			if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
				goto RDWR_ERROR;
			} else {
				if (0 == strncmp(buff, "TRUE", 4)) {
					length = snprintf(buff, 1024, "M-DELE %s %s", path, folder);
				} else if (0 == strncmp(buff, "FALSE ", 6)) {
					pthread_mutex_lock(&g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list,
						&pback->node);
					pthread_mutex_unlock(&g_server_lock);
					*perrno = atoi(buff + 6);
					return MIDB_RESULT_ERROR;	
				} else {
					goto RDWR_ERROR;
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
			goto RDWR_ERROR;
		}
		if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
			goto RDWR_ERROR;
		} else {
			if (0 == strncmp(buff, "TRUE", 4)) {
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				return MIDB_RESULT_OK;
			} else if (0 == strncmp(buff, "FALSE ", 6)) {
				pthread_mutex_lock(&g_server_lock);
				double_list_append_as_tail(&pback->psvr->conn_list,
					&pback->node);
				pthread_mutex_unlock(&g_server_lock);
				*perrno = atoi(buff + 6);
				return MIDB_RESULT_ERROR;	
			} else {
				goto RDWR_ERROR;
			}
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int list_simple(char *path, char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	char *pspace;
	char *pspace1;
	MITEM mitem;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	BOOL b_format_error;
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-SIML %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
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
						pthread_mutex_lock(&g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						pthread_mutex_unlock(&g_server_lock);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
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
				temp_line[line_pos] = '\0';
				pspace = strchr(temp_line, ' ');
				if (NULL != pspace) {
					pspace1 = strchr(pspace + 1, ' ');
					if (NULL != pspace1) {
						*pspace = '\0';
						*pspace1 = '\0';
						pspace ++;
						pspace1 ++;
						strncpy(mitem.mid, temp_line, sizeof(mitem.mid));
						mitem.id = count;
						mitem.uid = atoi(pspace);
						mitem.flag_bits = 0;
						if (NULL != strchr(pspace1, 'A')) {
							mitem.flag_bits |= FLAG_ANSWERED;
						}
						if (NULL != strchr(pspace1, 'U')) {
							mitem.flag_bits |= FLAG_DRAFT;
						}
						if (NULL != strchr(pspace1, 'F')) {
							mitem.flag_bits |= FLAG_FLAGGED;
						}
						if (NULL != strchr(pspace1, 'D')) {
							mitem.flag_bits |= FLAG_DELETED;
						}
						if (NULL != strchr(pspace1, 'S')) {
							mitem.flag_bits |= FLAG_SEEN;
						}
						if (NULL != strchr(pspace1, 'R')) {
							mitem.flag_bits |= FLAG_RECENT;
						}
						xarray_append(pxarray, &mitem, mitem.uid);
					} else {
						b_format_error = TRUE;
					}
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 128) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			if (TRUE == b_format_error) {
				*perrno = -1;
				xarray_clear(pxarray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
			}
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
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int list_deleted(char *path, char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	char *pspace;
	char *pspace1;
	MITEM mitem;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	BOOL b_format_error;
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-DELL %s %s UID ASC\r\n", path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
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
						pthread_mutex_lock(&g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						pthread_mutex_unlock(&g_server_lock);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
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
				temp_line[line_pos] = '\0';
				pspace = strchr(temp_line, ' ');
				if (NULL != pspace) {
					pspace1 = strchr(pspace + 1, ' ');
					if (NULL != pspace1) {
						*pspace = '\0';
						*pspace1 = '\0';
						pspace ++;
						pspace1 ++;
						strncpy(mitem.mid, pspace, sizeof(mitem.mid));
						mitem.id = atoi(temp_line) + 1;
						mitem.uid = atoi(pspace1);
						mitem.flag_bits = FLAG_DELETED;
						xarray_append(pxarray, &mitem, mitem.uid);
					} else {
						b_format_error = TRUE;
					}
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 128) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			if (TRUE == b_format_error) {
				*perrno = -1;
				xarray_clear(pxarray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
			}
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
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int list_detail(char *path, char *folder, XARRAY *pxarray,
	int *perrno)
{
	int i, num;
	int value;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	MITEM mitem;
	MITEM *pitem;
	int tv_msec;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	struct pollfd pfd_read;

	if (NULL == g_file_allocator) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-LIST %s %s UID ASC\r\n",
				path, folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	
	count = 0;
	offset = 0;
	lines = -1;
	b_format_error = FALSE;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pback->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			goto RDWR_ERROR;
		}
		read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
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
						pthread_mutex_lock(&g_server_lock);
						double_list_append_as_tail(&pback->psvr->conn_list,
							&pback->node);
						pthread_mutex_unlock(&g_server_lock);
						*perrno = atoi(buff + 6);
						return MIDB_RESULT_ERROR;
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
				if (TRUE == get_digest_string(temp_line, line_pos, "file",
					mitem.mid, sizeof(mitem.mid)) && TRUE == get_digest_integer(
					temp_line, line_pos, "uid", &mitem.uid)) {
					mitem.id = count;
					mitem.flag_bits = FLAG_LOADED;
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"replied", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_ANSWERED;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"unsent", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_DRAFT;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"flag", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_FLAGGED;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"deleted", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_DELETED;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"read", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_SEEN;
					}
					
					if (TRUE == get_digest_integer(temp_line, line_pos,
						"recent", &value) && 1 == value) {
						mitem.flag_bits |= FLAG_RECENT;
					}
					
					mem_file_init(&mitem.f_digest, g_file_allocator);
					mem_file_write(&mitem.f_digest, temp_line, line_pos);
					xarray_append(pxarray, &mitem, mitem.uid);
				} else {
					b_format_error = TRUE;
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 257*1024) {
						goto RDWR_ERROR;
					}
				}
			}
		}

		if (count >= lines) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			if (TRUE == b_format_error) {
				num = xarray_get_capacity(pxarray);
				for (i=0; i<num; i++) {
					pitem = xarray_get_item(pxarray, i);
					if (NULL != pitem) {
						mem_file_free(&pitem->f_digest);
					}
				}
				*perrno = -1;
				xarray_clear(pxarray);
				return MIDB_RESULT_ERROR;
			} else {
				return MIDB_RESULT_OK;
				
			}
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

		if (64*1024 == offset) {
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
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		pitem = xarray_get_item(pxarray, i);
		if (NULL != pitem) {
			mem_file_free(&pitem->f_digest);
		}
	}
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static void free_result(XARRAY *pxarray)
{
	int i, num;
	MITEM *pitem;
	
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		pitem = xarray_get_item(pxarray, i);
		if (NULL != pitem) {
			mem_file_free(&pitem->f_digest);
		}
	}
}

static int fetch_simple(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno)
{
	int i;
	int uid;
	int num;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	MITEM mitem;
	MITEM *pitem;
	char *pspace;
	char *pspace1;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[1024];
	char temp_line[1024];
	BOOL b_format_error;
	struct pollfd pfd_read;
	DOUBLE_LIST_NODE *pnode;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		if (-1 == ((SQUENCE_NODE*)pnode->pdata)->max) {
			if (-1 == ((SQUENCE_NODE*)pnode->pdata)->min) {
				length = snprintf(buff, 1024, "P-SIML %s %s UID ASC -1 1\r\n",
						path, folder);
			} else {
				length = snprintf(buff, 1024, "P-SIML %s %s UID ASC %d "
						"1000000000\r\n", path, folder,
						((SQUENCE_NODE*)pnode->pdata)->min - 1);
			}
		} else {
			length = snprintf(buff, 1024, "P-SIML %s %s UID ASC %d %d\r\n",
						path, folder, ((SQUENCE_NODE*)pnode->pdata)->min - 1,
						((SQUENCE_NODE*)pnode->pdata)->max - 
						((SQUENCE_NODE*)pnode->pdata)->min + 1);
		}
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 1024 - offset);
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
							pthread_mutex_lock(&g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							pthread_mutex_unlock(&g_server_lock);
							*perrno = atoi(buff + 6);
							return MIDB_RESULT_ERROR;
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
					temp_line[line_pos] = '\0';
					pspace = strchr(temp_line, ' ');
					if (NULL != pspace) {
						pspace1 = strchr(pspace + 1, ' ');
						if (NULL != pspace1) {
							*pspace = '\0';
							*pspace1 = '\0';
							pspace ++;
							pspace1 ++;
							uid = atoi(pspace);
							if (xarray_append(pxarray, &mitem, uid) >= 0) {
								num = xarray_get_capacity(pxarray);
								pitem = xarray_get_item(pxarray, num - 1);
								pitem->uid = uid;
								pitem->id = ((SQUENCE_NODE*)pnode->pdata)->min +
												count - 1;
								strncpy(pitem->mid, temp_line, sizeof(pitem->mid));
								pitem->flag_bits = 0;
								if (NULL != strchr(pspace1, 'A')) {
									pitem->flag_bits |= FLAG_ANSWERED;
								}
								if (NULL != strchr(pspace1, 'U')) {
									pitem->flag_bits |= FLAG_DRAFT;
								}
								if (NULL != strchr(pspace1, 'F')) {
									pitem->flag_bits |= FLAG_FLAGGED;
								}
								if (NULL != strchr(pspace1, 'D')) {
									pitem->flag_bits |= FLAG_DELETED;
								}
								if (NULL != strchr(pspace1, 'S')) {
									pitem->flag_bits |= FLAG_SEEN;
								}
								if (NULL != strchr(pspace1, 'R')) {
									pitem->flag_bits |= FLAG_RECENT;
								}
							}
						} else {
							b_format_error = TRUE;
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 128) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {	
					pthread_mutex_lock(&g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					pthread_mutex_unlock(&g_server_lock);
					*perrno = -1;
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}
	
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RESULT_OK;


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int fetch_detail(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno)
{
	int i;
	int num;
	int value;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	MITEM mitem;
	MITEM *pitem;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	DOUBLE_LIST_NODE *pnode;
	struct pollfd pfd_read;

	if (NULL == g_file_allocator) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		if (-1 == ((SQUENCE_NODE*)pnode->pdata)->max) {
			if (-1 == ((SQUENCE_NODE*)pnode->pdata)->min) {
				length = snprintf(buff, 1024, "M-LIST %s %s UID ASC -1 1\r\n",
						path, folder);
			} else {
				length = snprintf(buff, 1024, "M-LIST %s %s UID ASC %d "
						"1000000000\r\n", path, folder,
						((SQUENCE_NODE*)pnode->pdata)->min - 1);
			}
		} else {
			length = snprintf(buff, 1024, "M-LIST %s %s UID ASC %d %d\r\n",
						path, folder, ((SQUENCE_NODE*)pnode->pdata)->min - 1,
						((SQUENCE_NODE*)pnode->pdata)->max - 
						((SQUENCE_NODE*)pnode->pdata)->min + 1);
		}
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
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
							pthread_mutex_lock(&g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							pthread_mutex_unlock(&g_server_lock);
							*perrno = atoi(buff + 6);
							num = xarray_get_capacity(pxarray);
							for (i=0; i<num; i++) {
								pitem = xarray_get_item(pxarray, i);
								mem_file_free(&pitem->f_digest);
							}
							xarray_clear(pxarray);
							return MIDB_RESULT_ERROR;
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
					if (TRUE == get_digest_string(temp_line, line_pos, "file",
						mitem.mid, sizeof(mitem.mid)) && TRUE == get_digest_integer(
						temp_line, line_pos, "uid", &mitem.uid)) {
						if (xarray_append(pxarray, &mitem, mitem.uid) >= 0) {
							num = xarray_get_capacity(pxarray);
							pitem = xarray_get_item(pxarray, num - 1);
							pitem->id = ((SQUENCE_NODE*)pnode->pdata)->min +
											count - 1;
							pitem->flag_bits = FLAG_LOADED;
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"replied", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_ANSWERED;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"unsent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DRAFT;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"flag", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_FLAGGED;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"deleted", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DELETED;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"read", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_SEEN;
							}
							
							if (TRUE == get_digest_integer(temp_line, line_pos,
								"recent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_RECENT;
							}
							
							mem_file_init(&pitem->f_digest, g_file_allocator);
							mem_file_write(&pitem->f_digest, temp_line, line_pos);
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 257*1024) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {
					pthread_mutex_lock(&g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					pthread_mutex_unlock(&g_server_lock);
					*perrno = -1;
					num = xarray_get_capacity(pxarray);
					for (i=0; i<num; i++) {
						pitem = xarray_get_item(pxarray, i);
						mem_file_free(&pitem->f_digest);
					}
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (64*1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}
	
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RESULT_OK;

RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		pitem = xarray_get_item(pxarray, i);
		mem_file_free(&pitem->f_digest);
	}
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}

static int fetch_simple_uid(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno)
{
	int i;
	int uid;
	int num;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int tv_msec;
	MITEM mitem;
	MITEM *pitem;
	char *pspace;
	char *pspace1;
	char *pspace2;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[1024];
	char temp_line[1024];
	BOOL b_format_error;
	DOUBLE_LIST_NODE *pnode;
	struct pollfd pfd_read;


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		length = snprintf(buff, 1024, "P-SIMU %s %s UID ASC %d %d\r\n", path, folder,
					((SQUENCE_NODE*)pnode->pdata)->min,
					((SQUENCE_NODE*)pnode->pdata)->max);
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 1024 - offset);
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
							pthread_mutex_lock(&g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							pthread_mutex_unlock(&g_server_lock);
							*perrno = atoi(buff + 6);
							return MIDB_RESULT_ERROR;
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
					temp_line[line_pos] = '\0';
					pspace = strchr(temp_line, ' ');
					if (NULL != pspace) {
						pspace1 = strchr(pspace + 1, ' ');
						if (NULL != pspace1) {
							pspace2 = strchr(pspace1 + 1, ' ');
							if (NULL != pspace2) {
								*pspace = '\0';
								*pspace1 = '\0';
								*pspace2 = '\0';
								pspace ++;
								pspace1 ++;
								pspace2 ++;
								uid = atoi(pspace1);
								if (xarray_append(pxarray, &mitem, uid) >= 0) {
									num = xarray_get_capacity(pxarray);
									pitem = xarray_get_item(pxarray, num - 1);
									pitem->uid = uid;
									pitem->id = atoi(temp_line) + 1;
									strncpy(pitem->mid, pspace, sizeof(pitem->mid));
									pitem->flag_bits = 0;
									if (NULL != strchr(pspace2, 'A')) {
										pitem->flag_bits |= FLAG_ANSWERED;
									}
									if (NULL != strchr(pspace2, 'U')) {
										pitem->flag_bits |= FLAG_DRAFT;
									}
									if (NULL != strchr(pspace2, 'F')) {
										pitem->flag_bits |= FLAG_FLAGGED;
									}
									if (NULL != strchr(pspace2, 'D')) {
										pitem->flag_bits |= FLAG_DELETED;
									}
									if (NULL != strchr(pspace2, 'S')) {
										pitem->flag_bits |= FLAG_SEEN;
									}
									if (NULL != strchr(pspace2, 'R')) {
										pitem->flag_bits |= FLAG_RECENT;
									}
								}
							} else {
								b_format_error = TRUE;
							}
						} else {
							b_format_error = TRUE;
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 128) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {	
					pthread_mutex_lock(&g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					pthread_mutex_unlock(&g_server_lock);
					*perrno = -1;
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}
	
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RESULT_OK;


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}

static int fetch_detail_uid(char *path, char *folder, DOUBLE_LIST *plist,
	XARRAY *pxarray, int *perrno)
{
	int i;
	int num;
	int value;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	int temp_len;
	char *pspace;
	int tv_msec;
	MITEM mitem;
	MITEM *pitem;
	BACK_CONN *pback;
	char num_buff[32];
	char buff[64*1025];
	char temp_line[257*1024];
	BOOL b_format_error;
	DOUBLE_LIST_NODE *pnode;
	struct pollfd pfd_read;

	if (NULL == g_file_allocator) {
		*perrno = -2;
		return MIDB_RESULT_ERROR;
	}
	
	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		length = snprintf(buff, 1024, "P-DTLU %s %s UID ASC %d %d\r\n", path,
					folder, ((SQUENCE_NODE*)pnode->pdata)->min,
					((SQUENCE_NODE*)pnode->pdata)->max);
		if (length != write(pback->sockd, buff, length)) {
			goto RDWR_ERROR;
		}
		
		count = 0;
		offset = 0;
		lines = -1;
		b_format_error = FALSE;
		while (TRUE) {
			tv_msec = SOCKET_TIMEOUT * 1000;
			pfd_read.fd = pback->sockd;
			pfd_read.events = POLLIN|POLLPRI;
			if (1 != poll(&pfd_read, 1, tv_msec)) {
				goto RDWR_ERROR;
			}
			read_len = read(pback->sockd, buff + offset, 64*1024 - offset);
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
							pthread_mutex_lock(&g_server_lock);
							double_list_append_as_tail(&pback->psvr->conn_list,
								&pback->node);
							pthread_mutex_unlock(&g_server_lock);
							*perrno = atoi(buff + 6);
							num = xarray_get_capacity(pxarray);
							for (i=0; i<num; i++) {
								pitem = xarray_get_item(pxarray, i);
								mem_file_free(&pitem->f_digest);
							}
							xarray_clear(pxarray);
							return MIDB_RESULT_ERROR;
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
					pspace = search_string(temp_line, " ", 16);
					temp_len = line_pos - (pspace + 1 - temp_line);
					if (NULL != pspace && TRUE == get_digest_string(pspace,
						temp_len, "file", mitem.mid, sizeof(mitem.mid)) && 
						TRUE == get_digest_integer(pspace, temp_len, "uid",
						&mitem.uid)) {
						*pspace = '\0';
						pspace ++;
						if (xarray_append(pxarray, &mitem, mitem.uid) >= 0) {
							num = xarray_get_capacity(pxarray);
							pitem = xarray_get_item(pxarray, num - 1);
							pitem->id = atoi(temp_line) + 1;
							pitem->flag_bits = FLAG_LOADED;
							if (TRUE == get_digest_integer(pspace, temp_len,
								"replied", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_ANSWERED;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"unsent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DRAFT;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"flag", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_FLAGGED;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"deleted", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_DELETED;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"read", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_SEEN;
							}
							
							if (TRUE == get_digest_integer(pspace, temp_len,
								"recent", &value) && 1 == value) {
								pitem->flag_bits |= FLAG_RECENT;
							}
							
							mem_file_init(&pitem->f_digest, g_file_allocator);
							mem_file_write(&pitem->f_digest, pspace, temp_len);
						}
					} else {
						b_format_error = TRUE;
					}
					line_pos = 0;
				} else {
					if ('\r' != buff[i] || i != offset - 1) {
						temp_line[line_pos] = buff[i];
						line_pos ++;
						if (line_pos >= 257*1024) {
							goto RDWR_ERROR;
						}
					}
				}
			}

			if (count >= lines) {
				if (TRUE == b_format_error) {
					pthread_mutex_lock(&g_server_lock);
					double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
					pthread_mutex_unlock(&g_server_lock);
					*perrno = -1;
					num = xarray_get_capacity(pxarray);
					for (i=0; i<num; i++) {
						pitem = xarray_get_item(pxarray, i);
						mem_file_free(&pitem->f_digest);
					}
					return MIDB_RESULT_ERROR;
				}
				break;
			}

			if ('\r' == buff[offset - 1]) {
				last_pos = offset - 1;
			} else {
				last_pos = offset;
			}

			if (64*1024 == offset) {
				if ('\r' != buff[offset - 1]) {
					offset = 0;
				} else {
					buff[0] = '\r';
					offset = 1;
				}
				last_pos = 0;
			}
		}
	}
	
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RESULT_OK;

RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	num = xarray_get_capacity(pxarray);
	for (i=0; i<num; i++) {
		pitem = xarray_get_item(pxarray, i);
		mem_file_free(&pitem->f_digest);
	}
	xarray_clear(pxarray);
	return MIDB_RDWR_ERROR;
}



static int set_mail_flags(char *path, char *folder, char *mid_string,
	int flag_bits, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	char flags_string[16];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	flags_string[0] = '(';
	length = 1;
	if (flag_bits & FLAG_ANSWERED) {
		flags_string[length] = 'A';
		length ++;
	}
	
	if (flag_bits & FLAG_DRAFT) {
		flags_string[length] = 'U';
		length ++;
	}
	
	if (flag_bits & FLAG_FLAGGED) {
		flags_string[length] = 'F';
		length ++;
	}
	
	if (flag_bits & FLAG_DELETED) {
		flags_string[length] = 'D';
		length ++;
	}
	
	if (flag_bits & FLAG_SEEN) {
		flags_string[length] = 'S';
		length ++;
	}
	
	if (flag_bits & FLAG_RECENT) {
		flags_string[length] = 'R';
		length ++;
	}
	flags_string[length] = ')';
	length ++;
	flags_string[length] = '\0';
	
	length = snprintf(buff, 1024, "P-SFLG %s %s %s %s\r\n",
				path, folder, mid_string, flags_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}
	
static int unset_mail_flags(char *path, char *folder, char *mid_string,
	int flag_bits, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];
	char flags_string[16];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	flags_string[0] = '(';
	length = 1;
	if (flag_bits & FLAG_ANSWERED) {
		flags_string[length] = 'A';
		length ++;
	}
	
	if (flag_bits & FLAG_DRAFT) {
		flags_string[length] = 'U';
		length ++;
	}
	
	if (flag_bits & FLAG_FLAGGED) {
		flags_string[length] = 'F';
		length ++;
	}
	
	if (flag_bits & FLAG_DELETED) {
		flags_string[length] = 'D';
		length ++;
	}
	
	if (flag_bits & FLAG_SEEN) {
		flags_string[length] = 'S';
		length ++;
	}
	
	if (flag_bits & FLAG_RECENT) {
		flags_string[length] = 'R';
		length ++;
	}
	flags_string[length] = ')';
	length ++;
	flags_string[length] = '\0';
	
	
	length = snprintf(buff, 1024, "P-RFLG %s %s %s %s\r\n",
				path, folder, mid_string, flags_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;
}
	
static int get_mail_flags(char *path, char *folder, char *mid_string,
	int *pflag_bits, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "P-GFLG %s %s %s\r\n",
				path, folder, mid_string);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*pflag_bits = 0;
			if (NULL != strchr(buff + 5, 'A')) {
				*pflag_bits |= FLAG_ANSWERED;
			}
			if (NULL != strchr(buff + 5, 'U')) {
				*pflag_bits |= FLAG_DRAFT;
			}
			if (NULL != strchr(buff + 5, 'F')) {
				*pflag_bits |= FLAG_FLAGGED;
			}
			if (NULL != strchr(buff + 5, 'D')) {
				*pflag_bits |= FLAG_DELETED;
			}
			if (NULL != strchr(buff + 5, 'S')) {
				*pflag_bits |= FLAG_SEEN;
			}
			if (NULL != strchr(buff + 5, 'R')) {
				*pflag_bits |= FLAG_RECENT;
			}
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;


}
	
static int copy_mail(char *path, char *src_folder, char *mid_string,
	char *dst_folder, char *dst_mid, int *perrno)
{
	int length;
	BACK_CONN *pback;
	char buff[1024];


	pback = get_connection(path);
	if (NULL == pback) {
		return MIDB_NO_SERVER;
	}

	length = snprintf(buff, 1024, "M-COPY %s %s %s %s\r\n",
				path, src_folder, mid_string, dst_folder);
	if (length != write(pback->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	if (FALSE == read_line(pback->sockd, buff, sizeof(buff))) {
		goto RDWR_ERROR;
	} else {
		if (0 == strncmp(buff, "TRUE", 4)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list,
				&pback->node);
			pthread_mutex_unlock(&g_server_lock);
			strcpy(dst_mid, buff + 5);
			return MIDB_RESULT_OK;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			pthread_mutex_lock(&g_server_lock);
			double_list_append_as_tail(&pback->psvr->conn_list, &pback->node);
			pthread_mutex_unlock(&g_server_lock);
			*perrno = atoi(buff + 6);
			return MIDB_RESULT_ERROR;	
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pback->sockd);
	pback->sockd = -1;
	pthread_mutex_lock(&g_server_lock);
	double_list_append_as_tail(&g_lost_list, &pback->node);
	pthread_mutex_unlock(&g_server_lock);
	return MIDB_RDWR_ERROR;

}


static BOOL read_line(int sockd, char *buff, int length)
{
	int offset;
	int tv_msec;
	int read_len;
	struct pollfd pfd_read;

	offset = 0;
	while (TRUE) {
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
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

static int connect_midb(const char *ip_addr, int port)
{
    int sockd;
	int tv_msec;
    int read_len;
    char temp_buff[1024];
	struct pollfd pfd_read;
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
	tv_msec = SOCKET_TIMEOUT * 1000;
	pfd_read.fd = sockd;
	pfd_read.events = POLLIN|POLLPRI;
	if (1 != poll(&pfd_read, 1, tv_msec)) {
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
	BACK_SVR *pserver;
	DOUBLE_LIST_NODE *pnode;
	char help_string[] = "250 midb agent help information:\r\n"
						 "\t%s echo mp-path\r\n"
						 "\t    --print the midb server information";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] = '\0';
		return;
	}
	
	if (3 == argc && 0 == strcmp("echo", argv[1])) {
		for (pnode=double_list_get_head(&g_server_list); NULL!=pnode;
			pnode=double_list_get_after(&g_server_list, pnode)) {
			pserver = (BACK_SVR*)pnode->pdata;
			if (0 == strcmp(argv[2], pserver->prefix)) {
				snprintf(result, length,
				"250 agent information of midb(mp:%s ip:%s port:%d):\r\n"
				"\ttotal connections       %d\r\n"
				"\tavailable connections   %d",
				pserver->prefix, pserver->ip_addr, pserver->port,
				g_conn_num, double_list_get_nodes_num(&pserver->conn_list));
				result[length - 1] = '\0';
				return;
			}
		}
		snprintf(result, length, "250 no agent inforamtion of midb(mp:%s)", 
			argv[2]);
		return;
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

static BOOL get_digest_string(const char *src, int length, const char *tag,
    char *buff, int buff_len)
{
	int len;
	char *ptr1, *ptr2;
	char temp_tag[256];
	
	len = snprintf(temp_tag, 255, "\"%s\"", tag);
	ptr1 = search_string(src, temp_tag, length);
	if (NULL == ptr1) {
		return FALSE;
	}

	ptr1 += len;
	ptr1 = memchr(ptr1, ':', length - (ptr1 - src));
	if (NULL == ptr1) {
		return FALSE;
	}
	ptr1 ++;
	while (' ' == *ptr1 || '\t' == *ptr1) {
		ptr1 ++;
		if (ptr1 - src >= length) {
			return FALSE;
		}
	}
	ptr2 = ptr1;
	if ('"' == *ptr2) {
		do {
			ptr2 ++;
			if (ptr2 - src >= length) {
				return FALSE;
			}
		} while ('"' != *ptr2 || '\\' == *(ptr2 - 1));
	}
	while (',' != *ptr2 && '}' != *ptr2) {
		ptr2 ++;
		if (ptr2 - src >= length) {
			return FALSE;
		}
	}

	if (ptr2 - ptr1 <= buff_len - 1) {
		len = ptr2 - ptr1;
	} else {
		len = buff_len - 1;
	}
	memcpy(buff, ptr1, len);
	buff[len] = '\0';
	if ('"' == buff[0]) {
		len --;
		memmove(buff, buff + 1, len);
		buff[len] = '\0';
	}
	if ('"' == buff[len - 1]) {
		buff[len - 1] = '\0';
	}
	return TRUE;
}

static BOOL get_digest_integer(const char *src, int length, const char *tag, int *pinteger)
{
	char num_buff[32];
	
	if (TRUE == get_digest_string(src, length, tag, num_buff, 32)) {
		*pinteger = atoi(num_buff);
		return TRUE;
	}
	return FALSE;
}

