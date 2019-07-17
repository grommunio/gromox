/*
mailbox(username)     
	|
	|			   ___inbox.list (first line version number)
	|____ info ___|
	|             |___user.cfg (LAST_LOGIN, PASSWORD)
	|
	|
	|               ___ xxxx.xxx.xx
	|              |
	|____ inbox ___|___ xxxx.xxx.xx
	|              |
	|              |___ ...
	|
	|            ___ xxxxxxxxxxx
	|           | 
	|____ md5 __|___ xxxxxxxxxxx
	|           |
	|           |___ ...
	|
	|              __ xxx
	|____ sync ___|
	|             |__ ...

*/

#include "util.h"
#include "str_hash.h"
#include "list_file.h"
#include "mail_func.h"
#include "config_file.h"
#include "double_list.h"
#include <zlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/md5.h>

#define CDNER_VERSION		"1.0"

#define SOCKET_TIMEOUT      60

#define SCAN_INTERVAL		60


enum {
	SUCCESS = 0,
	ERROR_SOCKET,
	ERROR_EXCUTE
};

typedef struct _MSG_NODE {
	DOUBLE_LIST_NODE node;
	char mid[128];
	int size;
} MSG_NODE;

typedef struct _USER_ITEM {
	int version;
	char password[128];
	time_t last_login;
	time_t last_cleaning;
	BOOL b_sync;
	BOOL b_lock;
} USER_ITEM;

typedef struct _SYNC_NODE {
	DOUBLE_LIST_NODE node;
	char username[128];
	USER_ITEM *puser;
} SYNC_NODE;

typedef struct _MSG_UNIT {
	char mid[128];
	int size;
} MSG_UNIT;

typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;

typedef struct _THREAD_NODE {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
} THREAD_NODE;

typedef struct _CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
	int sockd;
	int offset;
	char buffer[256*1024];
	char line[256*1024 + 1];
} CONNECTION_NODE;

typedef struct _CDND_HOST {
	char ip[16];
	int port;
} CDND_HOST;

typedef struct _CDND_NODE {
	DOUBLE_LIST_NODE node;
	char ip[16];
	int port;
} CDND_NODE;


static int g_hash_cap;
static int g_cdnd_port;
static int g_squence_id;
static int g_notify_stop;
static char g_cdnd_ip[16];
static int g_valid_interval;
static char g_list_path[256];
static char g_cache_path[256];
static DOUBLE_LIST g_acl_list;
static DOUBLE_LIST g_sync_list;
static DOUBLE_LIST g_cdnd_list;
static DOUBLE_LIST g_sync_thread_list;
static STR_HASH_TABLE *g_user_hash;
static pthread_mutex_t g_hash_lock;
static pthread_mutex_t g_sync_lock;
static DOUBLE_LIST g_connection_list;
static pthread_mutex_t g_squence_lock;
static pthread_mutex_t g_connection_lock;


static void *accept_work_func(void *param);

static void *thread_work_func(void *param);

static void *scan_work_func(void *param);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static void term_handler(int signo);

static void* sync_work_func(void *param);

static int connect_cdnd(char *ip_addr, int *pport);

static int remote_mailbox(int sockd, const char *username);

static int remote_info(int sockd, int *pversion, char *password);

static int remote_uidl(int sockd, int *pversion, DOUBLE_LIST *plist);

static int remote_get(int sockd, const char *remote_file,
	const char *local_path);

static int remote_md5_msg(int sockd, const char *remote_file,
	char *md5_buff);
	
static int remote_command(int sockd, const char *command, int length);

static BOOL read_line(int sockd, char *buff, int length);

static void remove_inode(const char *path);

static BOOL unzip_file(const char *src_path, const char *dst_path);

static void lock_mailbox(const char *username);

static void unlock_mailbox(const char *username);

static BOOL md5_msg_file(const char *path, char *digest);

static int get_squence();

int main(int argc, char **argv)
{
	DIR *dirp;
	int optval;
	int i, num;
	int thr_num;
	char *pitem;
	ACL_ITEM *pacl;
	int listen_port;
	char *str_value;
	MSG_UNIT *punit;
	CDND_HOST *phost;
	CDND_NODE *pcdnd;
	LIST_FILE *plist;
	int sockd, status;
	char listen_ip[16];
	char temp_path[256];
	char cdnd_path[256];
	char temp_buff[128];
	struct in_addr addr;
	USER_ITEM temp_item;
	CONFIG_FILE *pconfig;
	THREAD_NODE *pthread;
	pthread_t scan_thrid;
	pthread_t accept_thrid;
	struct dirent *direntp;
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in my_name;
	CONNECTION_NODE *pconnection;

	
	umask(0);
	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", CDNER_VERSION);
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
		strcpy(cdnd_path, "../data/cdnd_list.txt");
		strcpy(g_list_path, "../data/cdner_acl.txt");
	} else {
		snprintf(cdnd_path, 255, "%s/cdnd_list.txt", str_value);
		snprintf(g_list_path, 255, "%s/cdner_acl.txt", str_value);
	}
	printf("[system]: acl file path is %s\n", g_list_path);
	printf("[system]: cdnd list path is %s\n", cdnd_path);

	str_value = config_file_get_value(pconfig, "CDNER_MAX_NUM");
	if (NULL == str_value) {
		g_hash_cap = 1000;
		config_file_set_value(pconfig, "CDNER_MAX_NUM", "1000");
	} else {
		g_hash_cap = atoi(str_value);
		if (g_hash_cap <= 0) {
			g_hash_cap = 1000;
			config_file_set_value(pconfig, "CDNER_MAX_NUM", "1000");
		}
	}
	printf("[system]: maximum hash size is %d\n", g_hash_cap);
	
	str_value = config_file_get_value(pconfig, "CDNER_CACHE_PATH");
	if (NULL == str_value) {
		strcpy(g_cache_path, "/tmp");
		config_file_set_value(pconfig, "CDNER_CACHE_PATH", "/tmp");
    } else {
        strcpy(g_cache_path, str_value);
    }
    printf("[system]: cdner cache path is %s\n", g_cache_path);

	str_value = config_file_get_value(pconfig, "CDNER_LISTEN_IP");
	if (NULL == str_value) {
		listen_ip[0] = '\0';
		printf("[system]: listen ip is ANY\n");
	} else {
		strncpy(listen_ip, str_value, 16);
		g_list_path[0] = '\0';
		printf("[system]: listen ip is %s\n", listen_ip);
	}

	str_value = config_file_get_value(pconfig, "CDNER_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 10001;
		config_file_set_value(pconfig, "CDNER_LISTEN_PORT", "10001");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 10001;
			config_file_set_value(pconfig, "CDNER_LISTEN_PORT", "10001");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);

	str_value = config_file_get_value(pconfig, "CDNER_THREADS_NUM");
	if (NULL == str_value) {
		thr_num = 5;
		config_file_set_value(pconfig, "CDNER_THREADS_NUM", "5");
	} else {
		thr_num = atoi(str_value);
		if (thr_num <= 0 || thr_num >= 100) {
			thr_num = 5;
			config_file_set_value(pconfig, "CDNER_THREADS_NUM", "5");
		}
	}
	printf("[system]: sync threads number is %d\n", thr_num);

	str_value = config_file_get_value(pconfig, "CDNER_VALID_INTERVAL");
	if (NULL == str_value) {
		config_file_set_value(pconfig, "CDNER_VALID_INTERVAL", "30days");
		g_valid_interval = 30*24*60*60;
	} else {
		g_valid_interval = atoitvl(str_value);
		if (g_valid_interval < 24*60*60) {
			config_file_set_value(pconfig, "CDNER_VALID_INTERVAL", "30days");
			g_valid_interval = 30*24*60*60;
		}
	}
	itvltoa(g_valid_interval, temp_buff);
	printf("[system]: cdn mailbox cache valid interval is %s\n", temp_buff);

	config_file_save(pconfig);
	config_file_free(pconfig);

	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) {
        printf("[system]: fail to create socket for listening\n");
		return -3;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
		sizeof(int));
	
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
		return -4;
    }
	
	status = listen(sockd, 5);

	if (-1 == status) {
		printf("[system]: fail to listen socket\n");
		close(sockd);
		return -5;
	}

	plist = list_file_init(cdnd_path, "%s:16%d");
	if (NULL == plist) {
		printf("[system]: fail to open cdnd list %s\n", cdnd_path);
		close(sockd);
		return -6;
	}

	num = list_file_get_item_num(plist);
	if (0 == num) {
		list_file_free(plist);
		printf("[system]: cdnd list %s is empty!\n", cdnd_path);
		close(sockd);
		return -6;
	}
	phost = list_file_get_list(plist);

	for (i=0; i<num; i++) {
		pcdnd = (CDND_NODE*)malloc(sizeof(CDND_NODE));
		if (NULL == pcdnd) {
			list_file_free(plist);
			printf("[system]: fail to init cdnd list %s\n", cdnd_path);
			close(sockd);
			return -6;
		}
		pcdnd->node.pdata = pcdnd;
		strcpy(pcdnd->ip, phost[i].ip);
		pcdnd->port = phost[i].port;
		double_list_append_as_tail(&g_cdnd_list, &pcdnd->node);
	}
	list_file_free(plist);

	if ('\0' != g_list_path[0]) {
		plist = list_file_init(g_list_path, "%s:16");
		if (NULL == plist) {
			printf("[system]: fail to open acl file %s\n", g_list_path);
			close(sockd);
			return -6;
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
	
	g_squence_id = 0;
	
	g_user_hash = str_hash_init(g_hash_cap, sizeof(USER_ITEM), NULL);
	if (NULL == g_user_hash) {
		printf("[system]: fail to init user hash table\n");
		close(sockd);
		return -7;
	}
	
	dirp = opendir(g_cache_path);
	if (NULL == dirp) {
		printf("[system]: fail to open cache directory %s\n", g_cache_path);
		str_hash_free(g_user_hash);
		close(sockd);
		return -8;
	}

	temp_item.b_lock = FALSE;
	temp_item.b_sync = FALSE;
	temp_item.last_cleaning = 0;
	while (NULL != (direntp = readdir(dirp))) {
		if (NULL == strchr(direntp->d_name, '@')) {
			continue;
		}
		snprintf(temp_path, 256, "%s/%s/info/user.cfg",
			g_cache_path, direntp->d_name);
		pconfig = config_file_init(temp_path);
		if (NULL == pconfig) {
			temp_item.password[0] = '\0';
		} else {
			str_value = config_file_get_value(pconfig, "PASSWORD");
			if (NULL == str_value) {
				temp_item.password[0] = '\0';
			} else {
				strncpy(temp_item.password, str_value, 128);
			}

			str_value = config_file_get_value(pconfig, "LAST_LOGIN");
			if (NULL == str_value) {
				time(&temp_item.last_login);
				sprintf(temp_buff, "%d", temp_item.last_login);
				config_file_set_value(pconfig, "LAST_LOGIN", temp_buff);
				config_file_save(pconfig);
			} else {
				temp_item.last_login = atoi(str_value);
			}
			config_file_free(pconfig);
		}

		snprintf(temp_path, 256, "%s/%s/info/inbox.list",
			g_cache_path, direntp->d_name);
		plist = list_file_init(temp_path, "%s:128%d");
		if (NULL == plist) {
			temp_item.version = 0;
		} else {
			punit = list_file_get_list(plist);
			if (list_file_get_item_num(plist) == 0) {
				temp_item.version = 0;
			} else {
				temp_item.version = atoi(punit[0].mid);
			}
			list_file_free(plist);
		}

		str_hash_add(g_user_hash, direntp->d_name, &temp_item);
	}
	closedir(dirp);

	pthread_mutex_init(&g_squence_lock, NULL);
	pthread_mutex_init(&g_sync_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
	pthread_mutex_init(&g_hash_lock, NULL);

	double_list_init(&g_sync_list);
	double_list_init(&g_sync_thread_list);
	double_list_init(&g_connection_list);

	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);


	if (0 != pthread_create(&scan_thrid, NULL, scan_work_func, NULL)) {
		printf("[system]: fail to create scanning thread\n");
		close(sockd);
		double_list_free(&g_connection_list);
		double_list_free(&g_sync_thread_list);
		double_list_free(&g_sync_list);
		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_sync_lock);
		pthread_mutex_destroy(&g_hash_lock);
		pthread_mutex_destroy(&g_squence_lock);
		str_hash_free(g_user_hash);
		return -9;
	}
	
	if (0 != pthread_create(&accept_thrid, NULL, accept_work_func,
		(void*)(long)sockd)) {
		printf("[system]: fail to create accepting thread\n");
		close(sockd);
		g_notify_stop = TRUE;
		pthread_join(scan_thrid, NULL);
		double_list_free(&g_connection_list);
		double_list_free(&g_sync_thread_list);
		double_list_free(&g_sync_list);
		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_sync_lock);
		pthread_mutex_destroy(&g_hash_lock);
		pthread_mutex_destroy(&g_squence_lock);
		str_hash_free(g_user_hash);
		return -10;
	}
	
	for (i=0; i<thr_num; i++) {
		pthread = (THREAD_NODE*)malloc(sizeof(THREAD_NODE));
		if (NULL == pthread) {
			printf("[system]: fail to allocate memory for sync thread\n");
			continue;
		}
		pthread->node.pdata = pthread;
		if (0 != pthread_create(&pthread->thr_id, NULL, sync_work_func, NULL)) {
			free(pthread);
			printf("[system]: fail to create sync thread\n");
			continue;
		}
		double_list_append_as_tail(&g_sync_thread_list, &pthread->node);
	}

	while (FALSE == g_notify_stop) {
		sleep(1);
	}

	close(sockd);
	
	while (pnode=double_list_get_from_head(&g_connection_list)) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		pthread_cancel(pconnection->thr_id);
		close(pconnection->sockd);
		free(pconnection);
	}

	double_list_free(&g_connection_list);
	
	pthread_join(scan_thrid, NULL);
	
	while (pnode=double_list_get_from_head(&g_sync_thread_list)) {
		pthread = (THREAD_NODE*)pnode->pdata;
		pthread_cancel(pthread->thr_id);
		free(pthread);
	}
	double_list_free(&g_sync_thread_list);
	
	pthread_mutex_destroy(&g_sync_lock);
	pthread_mutex_destroy(&g_connection_lock);
	pthread_mutex_destroy(&g_hash_lock);
	pthread_mutex_destroy(&g_squence_lock);

	str_hash_free(g_user_hash);
	
	return 0;
}

static void *scan_work_func(void *param)
{
	int count;
	SYNC_NODE *psync;
	USER_ITEM *puser;
	char temp_user[128];
	STR_HASH_ITER *iter;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;


	count = SCAN_INTERVAL - 1;

	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		sleep(1);
		count ++;
		if (count < SCAN_INTERVAL) {
			continue;
		}

		pthread_mutex_lock(&g_hash_lock);
		iter = str_hash_iter_init(g_user_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			puser = (USER_ITEM*)str_hash_iter_get_value(iter, temp_user);
			if (TRUE == puser->b_sync) {
				continue;
			}
			psync = (SYNC_NODE*)malloc(sizeof(SYNC_NODE));
			if (NULL == psync) {
				continue;
			}
			psync->node.pdata = psync;
			strncpy(psync->username, temp_user, 128);
			psync->puser = puser;
			double_list_append_as_tail(&temp_list, &psync->node);
			puser->b_sync = TRUE;
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_hash_lock);
		
		pthread_mutex_lock(&g_sync_lock);
		while (pnode = double_list_get_from_head(&temp_list)) {
			double_list_append_as_tail(&g_sync_list, pnode);
		}
		pthread_mutex_unlock(&g_sync_lock);

		count = 0;
	}
				

}

static void* sync_work_func(void *param)
{
	int fd;
	DIR *dirp;
	int sockd;
	int i, num;
	int offset;
	int result;
	int version;
	int cdnd_port;
	MSG_NODE *pmsg;
	char *str_value;
	time_t cur_time;
	SYNC_NODE *psync;
	USER_ITEM *puser;
	LIST_FILE *plist;
	char cdnd_ip[16];
	char password[128];
	char buff[256*1024];
	char temp_path[256];
	char temp_path1[256];
	DOUBLE_LIST msg_list;
	CONFIG_FILE *pconfig;
	DOUBLE_LIST msg_list1;
	struct stat node_stat;
	struct dirent *direntp;
	DOUBLE_LIST_NODE *pnode;
	char md5_buff[2*MD5_DIGEST_LENGTH + 1];


	sockd = -1;
	cdnd_ip[0] = '\0';
	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_sync_lock);
		pnode = double_list_get_from_head(&g_sync_list);
		pthread_mutex_unlock(&g_sync_lock);

		if (NULL == pnode) {
			sleep(1);
			continue;
		}

		psync = (SYNC_NODE*)pnode->pdata;

		while (TRUE) {
			if (-1 == sockd) {
				sockd = connect_cdnd(cdnd_ip, &cdnd_port);
				if (-1 == sockd) {
					sleep(60);
					continue;
				}
			}
			
			result = remote_mailbox(sockd, psync->username);
			if (ERROR_SOCKET == result) {
				close(sockd);
				sockd = -1;
				continue;
			} else if (ERROR_EXCUTE == result) {
				/* mailbox not exists any more */
				snprintf(temp_path, 256, "%s/%s",
					g_cache_path, psync->username);
				lock_mailbox(psync->username);
				remove_inode(temp_path);
				/* do not need to unlock mailbox,
				   remove it from hash directly */
				pthread_mutex_lock(&g_hash_lock);
				str_hash_remove(g_user_hash, psync->username);
				pthread_mutex_unlock(&g_hash_lock);
				break;
			}

			if (0 == psync->puser->version ||
				'\0' == psync->puser->password[0]) {
FULL_SYNC:
				/* new created mailbox */
				double_list_init(&msg_list);
				result = remote_uidl(sockd, &version, &msg_list);
				if (ERROR_SOCKET == result) {
					close(sockd);
					sockd = -1;
					while (pnode = double_list_get_from_head(&msg_list)) {
						free(pnode->pdata);
					}
					double_list_free(&msg_list);
					continue;
				} else if (ERROR_EXCUTE == result) {
					while (pnode = double_list_get_from_head(&msg_list)) {
						free(pnode->pdata);
					}
					double_list_free(&msg_list);
					break;
				}

				snprintf(temp_path, 256, "%s/%s/info/inbox.list.tmp",
					g_cache_path, psync->username);
				fd = open(temp_path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
				if (-1 == fd) {
					while (pnode = double_list_get_from_head(&msg_list)) {
						free(pnode->pdata);
					}
					double_list_free(&msg_list);
					break;
				}

				snprintf(temp_path1, 256, "%s/%s/inbox",
					g_cache_path, psync->username);

				offset = snprintf(buff, 1024, "%d 0\n", version);
				while (pnode = double_list_get_from_head(&msg_list)) {
					pmsg = (MSG_NODE*)pnode->pdata;
					snprintf(temp_path, 256, "%s/%s/inbox/%s", g_cache_path,
						psync->username, pmsg->mid);
					if (0 != stat(temp_path, &node_stat)) {
						result = remote_get(sockd, pmsg->mid, temp_path1);					
						if (ERROR_SOCKET == result) {
							close(sockd);
							sockd = -1;
							free(pmsg);
							break;
						} else if (ERROR_EXCUTE == result) {
							free(pmsg);
							continue;
						}
					}
					offset += snprintf(buff + offset, sizeof(buff) - offset,
								"%s %d\n", pmsg->mid, pmsg->size);
					if (offset >= sizeof(buff) - 256) {
						write(fd, buff, offset);
						offset = 0;
					}
					free(pmsg);
				}

				if (offset > 0) {
					write(fd, buff, offset);
				}
				close(fd);
				
				if (-1 == sockd) {
					snprintf(temp_path, 256, "%s/%s/info/inbox.list.tmp",
						g_cache_path, psync->username);
					remove(temp_path);
					while (pnode = double_list_get_from_head(&msg_list)) {
						free(pnode->pdata);
					}
					double_list_free(&msg_list);
					continue;
				}
				double_list_free(&msg_list);
				snprintf(temp_path, 256, "%s/%s/info/inbox.list.tmp",
					g_cache_path, psync->username);
				snprintf(temp_path1, 256, "%s/%s/info/inbox.list",
					g_cache_path, psync->username);
				remove(temp_path1);
				rename(temp_path, temp_path1);

				psync->puser->version = version;

				result = remote_info(sockd, &version, password);
				if (ERROR_SOCKET == result ||
					ERROR_EXCUTE == result) {
					close(sockd);
					sockd = -1;
					continue;
				}
				
				if (SUCCESS == result) {
					snprintf(temp_path, 256, "%s/%s/info/user.cfg.tmp",
						g_cache_path, psync->username);
					snprintf(temp_path1, 256, "%s/%s/info/user.cfg",
						g_cache_path, psync->username);
					fd = open(temp_path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
					if (-1 != fd) {
						offset = snprintf(buff, 1024,
									"LAST_LOGIN = %d\nPASSWORD = %s\n",
									psync->puser->last_login, password);
						write(fd, buff, offset);
						close(fd);
						remove(temp_path1);
						rename(temp_path, temp_path1);

						strncpy(psync->puser->password, password, 128);
					}
				}
			} else {
				time(&cur_time);
				if (cur_time > psync->puser->last_login &&
					cur_time - psync->puser->last_login > g_valid_interval) {
					lock_mailbox(psync->username);
					snprintf(temp_path, 256, "%s/%s",
						g_cache_path, psync->username);
					remove_inode(temp_path);
					/* do not need to unlock mailbox,
					   remove it from hash directly */
					pthread_mutex_lock(&g_hash_lock);
					str_hash_remove(g_user_hash, psync->username);
					pthread_mutex_unlock(&g_hash_lock);
					break;
				}
				
				result = remote_info(sockd, &version, password); 
				if (ERROR_SOCKET == result ||
					ERROR_EXCUTE == result) {
					close(sockd);
					sockd = -1;
					continue;
				}
				if (psync->puser->version != version) {
					double_list_init(&msg_list);
					result = remote_uidl(sockd, &version, &msg_list);
					if (ERROR_SOCKET == result) {
						close(sockd);
						sockd = -1;
						continue;
					} else if (ERROR_EXCUTE == result) {
						break;
					}
					
					snprintf(temp_path, 256, "%s/%s/inbox",
						g_cache_path, psync->username);	
					dirp = opendir(temp_path);
					if (NULL != dirp) {
						while (direntp = readdir(dirp)) {
							if (0 == strcmp(direntp->d_name, ".") ||
								0 == strcmp(direntp->d_name, "..")) {
								continue;
							}
							for (pnode=double_list_get_head(&msg_list); NULL!=pnode;
								pnode=double_list_get_after(&msg_list, pnode)) {
								pmsg = (MSG_NODE*)pnode->pdata;
								if (0 == strcmp(pmsg->mid, direntp->d_name)) {
									break;
								}
							}
							
							if (NULL == pnode) {
								snprintf(temp_path, 256, "%s/%s/inbox/%s",
									g_cache_path, psync->username, direntp->d_name);
								remove(temp_path);
							}
						}
						closedir(dirp);
					}
						
					double_list_init(&msg_list1);
					
					while (pnode = double_list_get_from_head(&msg_list)) {
						pmsg = (MSG_NODE*)pnode->pdata;
						snprintf(temp_path, 256, "%s/%s/deleted/%s",
							g_cache_path, psync->username, pmsg->mid);
						snprintf(temp_path1, 256, "%s/%s/inbox/%s",
							g_cache_path, psync->username, pmsg->mid);
						if (0 == stat(temp_path, &node_stat)) {
							/* alread deleted do nothing */
						} else if (0 == stat(temp_path1, &node_stat)) {
							double_list_append_as_tail(&msg_list1, pnode);
							continue;
						} else {
							/* check md5 directory if alread exists */
							result = remote_md5_msg(sockd, pmsg->mid,
										md5_buff);
							if (ERROR_SOCKET == result) {
								close(sockd);
								sockd = -1;
								free(pmsg);
								break;
							}

							if (SUCCESS == result) {
								snprintf(temp_path1, 256, "%s/%s/md5/%s",
									g_cache_path, psync->username, md5_buff);
								if (0 == stat(temp_path1, &node_stat)) {
									snprintf(temp_path, 256, "%s/%s/inbox/%s",
										g_cache_path, psync->username,
										pmsg->mid);
									rename(temp_path1, temp_path);
									double_list_append_as_tail(&msg_list1, pnode);
									continue;
								}
							}
							
							snprintf(temp_path, 256, "%s/%s/inbox",
								g_cache_path, psync->username);
							result = remote_get(sockd, pmsg->mid, temp_path);
							if (ERROR_SOCKET == result) {
								close(sockd);
								sockd = -1;
								free(pmsg);
								break;
							}

							if (SUCCESS == result) {
								double_list_append_as_tail(&msg_list1, pnode);
								continue;
							}
						}
						free(pmsg);
					}
					
					if (-1 == sockd) {
						while (pnode = double_list_get_from_head(&msg_list)) {
							free(pnode->pdata);
						}
						double_list_free(&msg_list);
						while (pnode = double_list_get_from_head(&msg_list1)) {
							free(pnode->pdata);
						}
						continue;
					}
					
					double_list_free(&msg_list);
					
					snprintf(temp_path1, 256, "%s/%s/info/inbox.list.tmp",
						g_cache_path, psync->username);
					lock_mailbox(psync->username);
					fd = open(temp_path1, O_CREAT|O_WRONLY|O_TRUNC, 0666);
					if (-1 == fd) {
						unlock_mailbox(psync->username);
						while (pnode=double_list_get_from_head(&msg_list1)) {
							free(pnode->pdata);
						}
						double_list_free(&msg_list1);
						break;
					}
					offset = snprintf(buff, 1024, "%d 0\n", version);
					while (pnode=double_list_get_from_head(&msg_list1)) {
						pmsg = (MSG_NODE*)pnode->pdata;
						snprintf(temp_path, 256, "%s/%s/deleted/%s",
							g_cache_path, psync->username, pmsg->mid);
						if (0 != stat(temp_path, &node_stat)) {
							offset += snprintf(buff + offset,
										sizeof(buff) - offset, "%s %d\n",
										pmsg->mid, pmsg->size);
							if (offset > sizeof(buff) - 256) {							
								write(fd, buff, offset);
								offset = 0;
							}
						}
						free(pmsg);
					}
					double_list_free(&msg_list1);
					if (offset > 0) {
						write(fd, buff, offset);
					}
					close(fd);
					snprintf(temp_path, 256, "%s/%s/info/inbox.list",
						g_cache_path, psync->username);
					remove(temp_path);
					rename(temp_path1, temp_path);
					psync->puser->version = version;
					unlock_mailbox(psync->username);
				}

				if (0 != strcmp(psync->puser->password, password)) {
					lock_mailbox(psync->username);
					snprintf(temp_path1, 256, "%s/%s/info/user.cfg",
						g_cache_path, psync->username);
					pconfig = config_file_init(temp_path1);
					if (NULL != pconfig) {
						config_file_set_value(pconfig, "PASSWORD", password);
						config_file_save(pconfig);
						config_file_free(pconfig);
					}
					strncpy(psync->puser->password, password, 128);
					unlock_mailbox(psync->username);
				}
				
				snprintf(temp_path, 256, "%s/%s/sync", g_cache_path,
					psync->username);
				dirp = opendir(temp_path);
				if (NULL != dirp) {
					while (direntp = readdir(dirp)) {
						if (0 == strcmp(direntp->d_name, ".") ||
							0 == strcmp(direntp->d_name, "..")) {
							continue;
						}
						snprintf(temp_path1, 256, "%s/%s",
							temp_path, direntp->d_name);
						fd = open(temp_path1, O_RDONLY);
						if (-1 != fd) {
							offset = read(fd, buff, sizeof(buff));
							close(fd);
							if (offset > 2 && '\r' == buff[offset - 2] &&
								'\n' == buff[offset -1]) {
								if (SUCCESS == remote_command(sockd,
									buff, offset)) {
									remove(temp_path1);
								}
							}
						}
						
					}
					closedir(dirp);
				}
				
				time(&cur_time);
				if (cur_time - psync->puser->last_cleaning >= 24*60*60) {
					snprintf(temp_path, 256, "%s/%s/md5", g_cache_path,
						psync->username);
					dirp = opendir(temp_path);
					if (NULL != dirp) {
						while (direntp = readdir(dirp)) {
							if (0 == strcmp(direntp->d_name, ".") ||
								0 == strcmp(direntp->d_name, "..")) {
								continue;
							}
							snprintf(temp_path1, 256, "%s/%s",
								temp_path, direntp->d_name);
							if (0 == stat(temp_path1, &node_stat) &&
								cur_time - node_stat.st_mtime  > 72*60*60) {
								remove(temp_path1);
							}
						}
						closedir(dirp);
					}

					snprintf(temp_path, 256, "%s/%s/deleted", g_cache_path,
						psync->username);
					dirp = opendir(temp_path);
					if (NULL != dirp) {
						while (direntp = readdir(dirp)) {
							if (0 == strcmp(direntp->d_name, ".") ||
								0 == strcmp(direntp->d_name, "..")) {
								continue;
							}
							snprintf(temp_path1, 256, "%s/%s",
								temp_path, direntp->d_name);
							if (0 == stat(temp_path1, &node_stat) &&
								cur_time - node_stat.st_mtime  > 72*60*60) {
								remove(temp_path1);
							}
						}
						closedir(dirp);
					}

					psync->puser->last_cleaning = cur_time;
				}
			}

			break;
		}
		pthread_mutex_lock(&g_hash_lock);
		puser = str_hash_query(g_user_hash, psync->username);
		if (NULL != puser) {
			puser->b_sync = FALSE;
		}
		pthread_mutex_unlock(&g_hash_lock);
		free(psync);
		
	}

}



static void *accept_work_func(void *param)
{
	ACL_ITEM *pacl;
	int sockd, sockd2;
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

		pconnection->node.pdata = pconnection;
		pconnection->offset = 0;
		pconnection->sockd = sockd2;
		
		if (0 != pthread_create(&pconnection->thr_id, NULL, thread_work_func,
			(void*)pconnection)) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			free(pconnection);
			continue;
		}
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_connection_lock);

	}
	
	pthread_exit(0);

}

static void *thread_work_func(void *param)
{
	int fd;
	int fd1;
	char *ptr;
	int i, num;
	int offset;
	int tmp_len;
	char *parray;
	fd_set myset;
	int read_len;
	int squence_id;
	MSG_UNIT *punit;
	char *str_value;
	USER_ITEM *puser;
	LIST_FILE *plist;
	struct timeval tv;
	char num_buff[32];
	char buff[256*1024];
	USER_ITEM temp_item;
	char temp_user[128];
	char temp_path[256];
	char temp_path1[256];
	CONFIG_FILE *pconfig;
	struct stat node_stat;
	CONNECTION_NODE *pconnection;


	pconnection = (CONNECTION_NODE*)param;

	write(pconnection->sockd, "OK\r\n", 4);
	
	while (TRUE) {
		if (FALSE == read_mark(pconnection)) {
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			pthread_detach(pthread_self());
			pthread_exit(0);
		}

		if (0 == strncasecmp(pconnection->line, "CHECK ", 6) &&
			strlen(pconnection->line) > 6) {
			strncpy(temp_user, pconnection->line + 6, 128);
			lower_string(temp_user);
			pthread_mutex_lock(&g_hash_lock);
			if (NULL == str_hash_query(g_user_hash, temp_user)) {
				pthread_mutex_unlock(&g_hash_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			pthread_mutex_unlock(&g_hash_lock);
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "INFO ", 5) &&
			strlen(pconnection->line) > 5) {
			strncpy(temp_user, pconnection->line + 5, 128);
			lower_string(temp_user);
			pthread_mutex_lock(&g_hash_lock);
			puser = str_hash_query(g_user_hash, temp_user);
			if (NULL != puser) {
				strncpy(temp_item.password, puser->password, 128);
				time(&puser->last_login);
				temp_item.last_login = puser->last_login;
			}
			pthread_mutex_unlock(&g_hash_lock);

			if (NULL == puser || '\0' == temp_item.password[0]) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			snprintf(temp_path, 256, "%s/%s/info/user.cfg",
				g_cache_path, temp_user);
			if (0 == stat(temp_path, &node_stat) &&
				0 != S_ISREG(node_stat.st_mode)) {
				lock_mailbox(temp_user);
				pconfig = config_file_init(temp_path);
				if (NULL != pconfig) {
					snprintf(num_buff, 32, "%d", temp_item.last_login);
					config_file_set_value(pconfig, "LAST_LOGIN", num_buff);
					config_file_save(pconfig);
					config_file_free(pconfig);
				}
				unlock_mailbox(temp_user);
			}
			tmp_len = snprintf(buff, 1024, "TRUE %s\r\n", temp_item.password);
			write(pconnection->sockd, buff, tmp_len);
		} else if (0 == strncasecmp(pconnection->line, "CREATE ", 7) &&
			strlen(pconnection->line) > 7) {
			strncpy(temp_user, pconnection->line + 7, 128);
			lower_string(temp_user);
			temp_item.b_lock = FALSE;
			temp_item.b_sync = FALSE;
			time(&temp_item.last_cleaning);
			temp_item.version = 0;
			temp_item.password[0] = '\0';
			time(&temp_item.last_login);
			pthread_mutex_lock(&g_hash_lock);
			if (NULL != str_hash_query(g_user_hash, temp_user)) {
				pthread_mutex_unlock(&g_hash_lock);
				write(pconnection->sockd, "TRUE\r\n", 6);
				continue;
			}
			str_hash_add(g_user_hash, temp_user, &temp_item);
			pthread_mutex_unlock(&g_hash_lock);
			snprintf(temp_path, 256, "%s/%s", g_cache_path, temp_user);
			if (0 == stat(temp_path, &node_stat)) {
				if (0 == S_ISDIR(node_stat.st_mode)) {
					remove_inode(temp_path);
					mkdir(temp_path, 0777);
				}
			} else {
				mkdir(temp_path, 0777);
			}
			snprintf(temp_path1, 256, "%s/info", temp_path);
			if (0 != stat(temp_path1, &node_stat)) {
				mkdir(temp_path1, 0777);
			}
			snprintf(temp_path1, 256, "%s/inbox", temp_path);
			if (0 != stat(temp_path1, &node_stat)) {
				mkdir(temp_path1, 0777);
			}
			snprintf(temp_path1, 256, "%s/deleted", temp_path);
			if (0 != stat(temp_path1, &node_stat)) {
				mkdir(temp_path1, 0777);
			}
			snprintf(temp_path1, 256, "%s/md5", temp_path);
			if (0 != stat(temp_path1, &node_stat)) {
				mkdir(temp_path1, 0777);
			}
			snprintf(temp_path1, 256, "%s/sync", temp_path);
			if (0 != stat(temp_path1, &node_stat)) {
				mkdir(temp_path1, 0777);
			}
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "UIDL ", 5)) {
			strncpy(temp_user, pconnection->line + 5, 128);
			lower_string(temp_user);
			snprintf(temp_path, 256, "%s/%s/info/user.cfg",
				g_cache_path, temp_user);
			if (0 != stat(temp_path, &node_stat) ||
				0 == S_ISREG(node_stat.st_mode)) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			snprintf(temp_path, 256, "%s/%s/info/inbox.list",
				g_cache_path, temp_user);
			lock_mailbox(temp_user);
			plist = list_file_init(temp_path, "%s:128%d");
			if (NULL == plist) {
				unlock_mailbox(temp_user);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			num = list_file_get_item_num(plist);
			if (0 == num) {
				list_file_free(plist);
				unlock_mailbox(temp_user);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			punit = list_file_get_list(plist);
			offset = snprintf(buff, 1024, "TRUE %d\r\n", num - 1);
			for (i=1; i<num; i++) {
				offset += snprintf(buff + offset, sizeof(buff) - offset,
								"%s %d\r\n", punit[i].mid, punit[i].size);
				if (offset > sizeof(buff) - 256) {
					write(pconnection->sockd, buff, offset);
					offset = 0;
				}
			}
			list_file_free(plist);
			unlock_mailbox(temp_user);
			if (offset > 0) {
				write(pconnection->sockd, buff, offset);
			}
		} else if (0 == strncasecmp(pconnection->line, "REMOVE ", 7)) {
			ptr = strchr(pconnection->line + 7, ' ');
			if (NULL == ptr || ptr == pconnection->line + 7) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			*ptr = '\0';
			ptr ++;
			if ('\0' == *ptr) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			parray = ptr;
			strncpy(temp_user, pconnection->line + 7, 128);
			lower_string(temp_user);
			
			for (;'\0'!=*ptr; ptr++) {
				if (' ' == *ptr) {
					*ptr = '\0';
				}
			}
			
			*(ptr + 1) = '\0';
			
			snprintf(temp_path, 256, "%s/%s/info/inbox.list",
				g_cache_path, temp_user);
			snprintf(temp_path1, 256, "%s/%s/info/inbox.list.tmp",
				g_cache_path, temp_user);
			lock_mailbox(temp_user);
			plist = list_file_init(temp_path, "%s:128%d");
			if (NULL == plist) {
				unlock_mailbox(temp_user);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			fd = open(temp_path1, O_CREAT|O_WRONLY|O_TRUNC, 0666);
			if (-1 == fd) {
				list_file_free(plist);
				unlock_mailbox(temp_user);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			num = list_file_get_item_num(plist);
			punit = list_file_get_list(plist);

			offset = 0;
			/* first line with version number should be included */
			for (i=0; i<num; i++) {
				ptr = parray;
				while ('\0' != *ptr) {
					tmp_len = strlen(ptr);
					if (0 == memcmp(punit[i].mid, ptr, tmp_len + 1)) {
						break;
					}
					ptr += tmp_len + 1;
				}
				
				if ('\0' != *ptr) {
					continue;
				}
				offset += snprintf(buff + offset, sizeof(buff) - offset,
								"%s %d\n", punit[i].mid, punit[i].size);
				if (offset > sizeof(buff) - 256) {
					write(fd, buff, offset);
					offset = 0;
				}
			}
			if (offset > 0) {
				write(fd, buff, offset);
			}
			close(fd);
			list_file_free(plist);
			remove(temp_path);
			rename(temp_path1, temp_path);
			unlock_mailbox(temp_user);
			squence_id = get_squence();
			strcpy(buff, "REMOVE");
			offset = 6;
			ptr = parray;
			while ('\0' != *ptr) {
				tmp_len = strlen(ptr);
				offset += snprintf(buff + offset, sizeof(buff) - offset,
							" %s", ptr);
				snprintf(temp_path, 256, "%s/%s/deleted/%s", g_cache_path,
					temp_user, ptr);
				fd1 = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
				if (-1 != fd1) {
					close(fd1);
				}
				ptr += tmp_len + 1;
			}
			buff[offset] = '\r';
			offset ++;
			buff[offset] = '\n';
			offset ++;
			snprintf(temp_path, 256, "%s/%s/sync/%d", g_cache_path,
				temp_user, squence_id);
			fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (-1 != fd) {
				write(fd, buff, offset);
				close(fd);
			}
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strncasecmp(pconnection->line, "CACHE ", 6)) {
			ptr = strchr(pconnection->line + 6, ' ');
			if (NULL == ptr || 0 == strlen(ptr + 1)) {
				write(pconnection->sockd, "FALSE\r\n", 7);
			}

			*ptr = '\0';
			ptr ++;
			strncpy(temp_user, pconnection->line + 6, 128);
			lower_string(temp_user);
			tmp_len = atoi(ptr);
			if (tmp_len <= 0) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			pthread_mutex_lock(&g_hash_lock);
			if (NULL == str_hash_query(g_user_hash, temp_user)) {
				pthread_mutex_unlock(&g_hash_lock);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			pthread_mutex_unlock(&g_hash_lock);

			squence_id = get_squence();

			snprintf(temp_path, 256, "%s/%s/md5/%d", g_cache_path,
				temp_user, squence_id);
			fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (-1 == fd) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			offset = 0;
			write(pconnection->sockd, "+CONTINUE\r\n", 11);

			while (offset < tmp_len) {
				tv.tv_usec = 0;
				tv.tv_sec = SOCKET_TIMEOUT;
				FD_ZERO(&myset);
				FD_SET(pconnection->sockd, &myset);
				if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
					close(fd);
					remove(temp_path);
					close(pconnection->sockd);
					pthread_mutex_lock(&g_connection_lock);
					double_list_remove(&g_connection_list, &pconnection->node);
					pthread_mutex_unlock(&g_connection_lock);
					free(pconnection);
					pthread_detach(pthread_self());
					pthread_exit(0);
				}
				read_len = read(pconnection->sockd, buff, sizeof(buff));
				if (read_len <= 0) {
					close(fd);
					remove(temp_path);
					close(pconnection->sockd);
					pthread_mutex_lock(&g_connection_lock);
					double_list_remove(&g_connection_list, &pconnection->node);
					pthread_mutex_unlock(&g_connection_lock);
					free(pconnection);
					pthread_detach(pthread_self());
					pthread_exit(0);
				}
				write(fd, buff, read_len);
				offset += read_len;
			}
			close(fd);
			if (TRUE == md5_msg_file(temp_path, buff)) {
				snprintf(temp_path1, 256, "%s/%s/md5/%s",
					g_cache_path, temp_user, buff);
				rename(temp_path, temp_path1);
			} else {
				remove(temp_path);
			}
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strcasecmp(pconnection->line, "PING")) {
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			write(pconnection->sockd, "BYE\r\n", 5);
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			pthread_detach(pthread_self());
			pthread_exit(0);
		} else {
			write(pconnection->sockd, "FALSE\r\n", 7);
		}

	}

	pthread_detach(pthread_self());
	pthread_exit(0);
}



static void remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != lstat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
		remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}


static int connect_cdnd(char *ip_addr, int *pport)
{
    int sockd;
    int read_len;
	fd_set myset;
	CDND_NODE *pcdnd;
	struct timeval tv;
    char temp_buff[1024];
	DOUBLE_LIST_NODE *pnode;
	struct timeval timeout_val;
    struct sockaddr_in servaddr;


	if ('\0' == ip_addr[0]) {
		pnode = double_list_get_head(&g_cdnd_list);
		pcdnd = (CDND_NODE*)pnode->pdata;
		strcpy(ip_addr, pcdnd->ip);
		*pport = pcdnd->port;
	} else {
		for (pnode=double_list_get_head(&g_cdnd_list); NULL!=pnode;
			pnode=double_list_get_after(&g_cdnd_list, pnode)) {
			pcdnd = (CDND_NODE*)pnode->pdata;
			if (0 == strcmp(pcdnd->ip, ip_addr) && pcdnd->port == *pport) {
				break;
			}
		}

		pnode=double_list_get_after(&g_cdnd_list, pnode);
		if (NULL == pnode) {
			pnode=double_list_get_head(&g_cdnd_list);
		}

		pcdnd = (CDND_NODE*)pnode->pdata;
		strcpy(ip_addr, pcdnd->ip);
		*pport = pcdnd->port;
	}
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	timeout_val.tv_sec = SOCKET_TIMEOUT;
	timeout_val.tv_usec = 0;
	setsockopt(sockd, SOL_SOCKET, SO_RCVTIMEO, &timeout_val,
		sizeof(struct timeval));
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(*pport);
	inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr,
		sizeof(servaddr))) {
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

static int remote_mailbox(int sockd, const char *username)
{
	int offset;
    char temp_buff[1024];
	
	
	offset = snprintf(temp_buff, 1024, "MAILBOX %s\r\n", username);
	if (offset != write(sockd, temp_buff, offset)) {
		return ERROR_SOCKET;
	}

	if (FALSE == read_line(sockd, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}

	if (0 == strcasecmp(temp_buff, "TRUE")) {
		return SUCCESS;
	} else if (0 == strcasecmp(temp_buff, "FALSE")) {
		return ERROR_EXCUTE;
	} else {
		return ERROR_SOCKET;
	}

}

static int remote_info(int sockd, int *pversion, char *password)
{
	int offset;
	char *pspace;
    char temp_buff[1024];
	
	
	if (6 != write(sockd, "INFO\r\n", 6)) {
		return ERROR_SOCKET;
	}

	if (FALSE == read_line(sockd, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}

	if (0 == strncasecmp(temp_buff, "TRUE ", 5)) {
		pspace = strchr(temp_buff + 5, ' ');
		if (NULL == pspace) {
			return ERROR_SOCKET;
		}
		*pspace = '\0';
		pspace ++;
		*pversion = atoi(temp_buff + 5);
		strncpy(password, pspace, 128);
		return SUCCESS;
	} else if (0 == strncasecmp(temp_buff, "FALSE", 5)) {
		return ERROR_EXCUTE;
	} else {
		return ERROR_SOCKET;
	}

}

static int remote_uidl(int sockd, int *pversion, DOUBLE_LIST *plist)
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
	char *pspace;
	MSG_NODE *pmsg;
	struct timeval tv;
	char num_buff[32];
	char temp_line[256];
	char buff[256*1025];
	


	if (6 != write(sockd, "UIDL\r\n", 6)) {
		return ERROR_SOCKET;
	}

	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return ERROR_SOCKET;
		}
		read_len = read(sockd, buff + offset, sizeof(buff) - offset);
		if (read_len <= 0) {
			return ERROR_SOCKET;
		}
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncasecmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						pspace = strchr(num_buff, ' ');
						if (NULL == pspace) {
							return ERROR_SOCKET;
						}
						*pspace = '\0';
						pspace ++;
						*pversion = atoi(num_buff);
						lines = atoi(pspace);
						if (lines < 0) {
							return ERROR_SOCKET;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncasecmp(buff, "FALSE", i)) {
						return ERROR_EXCUTE;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					return ERROR_SOCKET;
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
					return ERROR_SOCKET;
				}
				*pspace = '\0';
				if (strlen(temp_line) > 127) {
					return ERROR_SOCKET;
				}
				pspace ++;
				temp_line[line_pos] = '\0';

				pmsg = (MSG_NODE*)malloc(sizeof(MSG_NODE));
				if (NULL != pmsg) {
					pmsg->node.pdata = pmsg;
					strcpy(pmsg->mid, temp_line);
					pmsg->size = atoi(pspace);
					double_list_append_as_tail(plist, &pmsg->node);
				}
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 256) {
						return ERROR_SOCKET;
					}
				}
			}
		}

		if (count >= lines) {
			return SUCCESS;
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

		if (sizeof(buff) == offset) {
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


static int remote_get(int sockd, const char *remote_file,
	const char *local_path)
{
	int i, fd;
	int offset;
	size_t length;
	int last_pos;
    fd_set myset;
    int read_len;
	BOOL b_first;
	size_t tmp_len;
    struct timeval tv;
	char buff[256*1024];
	char temp_path[256];
	char temp_path1[256];



	offset = snprintf(buff, 1024, "GET %s\r\n", remote_file);
	if (offset != write(sockd, buff, offset)) {
		return ERROR_SOCKET;
	}

	offset = 0;
	fd = -1;
	b_first = FALSE;
    while (TRUE) {
        tv.tv_usec = 0;
        tv.tv_sec = SOCKET_TIMEOUT;
        FD_ZERO(&myset);
        FD_SET(sockd, &myset);
        if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			if (-1 != fd) {
				close(fd);
			}
            return ERROR_SOCKET;
        }
        read_len = read(sockd, buff + offset, sizeof(buff) - offset);
        if (read_len <= 0) {
			if (-1 != fd) {
				close(fd);
			}
            return ERROR_SOCKET;
        }
        offset += read_len;

		if (FALSE == b_first) {
			for (i=0; i<offset; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					buff[i] = '\0';
					if (0 == strcasecmp(buff, "FALSE")) {
						return ERROR_EXCUTE;
					} else if (0 == strncasecmp(buff, "TRUE gzip ", 10)) {

						snprintf(temp_path, 256, "%s/%s.gz", local_path,
							remote_file);
						snprintf(temp_path1, 256, "%s/%s", local_path,
							remote_file);
						fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
						if (-1 == fd) {
							return ERROR_SOCKET;
						}
						b_first = TRUE;
						length = atol(buff + 10);
						tmp_len = offset - (i + 2);
						write(fd, buff + i + 2, tmp_len);
						if (tmp_len >= length) {
							close(fd);
							unzip_file(temp_path, temp_path1);
							return SUCCESS;
						}
						offset = 0;
						break;
					} else {
						return ERROR_SOCKET;
					}
				}
			}
		} else {
			write(fd, buff, offset);
			tmp_len += offset;
			offset = 0;
			if (tmp_len >= length) {
				close(fd);
				unzip_file(temp_path, temp_path1);
				return SUCCESS;
			}
		}
	}
	
}


static int remote_md5_msg(int sockd, const char *remote_file, char *md5_buff)
{
	int offset;
    char temp_buff[1024];
	
	
	offset = snprintf(temp_buff, 1024, "MD5-MSG %s\r\n", remote_file);
	if (offset != write(sockd, temp_buff, offset)) {
		return ERROR_SOCKET;
	}

	if (FALSE == read_line(sockd, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}

	if (0 == strncasecmp(temp_buff, "TRUE ", 5)) {
		strncpy(md5_buff, temp_buff + 5, 2*MD5_DIGEST_LENGTH + 1);
		return SUCCESS;
	} else if (0 == strncasecmp(temp_buff, "FALSE", 5)) {
		return ERROR_EXCUTE;
	} else {
		return ERROR_SOCKET;
	}

}

static int remote_command(int sockd, const char *command, int length)
{
	char temp_buff[1024];
	
	if (length != write(sockd, command, length)) {
		return ERROR_SOCKET;
	}

	if (FALSE == read_line(sockd, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}

	if (0 == strncasecmp(temp_buff, "TRUE", 4)) {
		return SUCCESS;
	} else if (0 == strncasecmp(temp_buff, "FALSE", 5)) {
		return ERROR_EXCUTE;
	} else {
		return ERROR_SOCKET;
	}
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
        read_len = read(sockd, buff + offset, length - offset);
        if (read_len <= 0) {
            return FALSE;
        }
        offset += read_len;
		if ('\r' == buff[offset - 2] && '\n' == buff[offset - 1]) {
			buff[offset - 2] = '\0';
			return TRUE;
        }
		if (offset == length) {
			return FALSE;
		}
    }
}


static BOOL unzip_file(const char *src_path, const char *dst_path)
{
	int fd;
	gzFile gz_fd;
	int read_len;
	char buff[256*1024];
	
	gz_fd = gzopen(src_path, "r");
	if (Z_NULL == gz_fd) {
		remove(src_path);
		return FALSE;
	}

	fd = open(dst_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		gzclose(gz_fd);
		remove(src_path);
		return FALSE;
	}

	while ((read_len = gzread(gz_fd, buff, sizeof(buff))) > 0) {
		write(fd, buff, read_len);
    }
	close(fd);
	gzclose(gz_fd);
	remove(src_path);
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
					pconnection->offset, sizeof(pconnection->buffer) -
					pconnection->offset);
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
		if (sizeof(pconnection->buffer) == pconnection->offset) {
			return FALSE;
		}
		
	}
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

static int get_squence()
{
	int squence_id;

	pthread_mutex_lock(&g_squence_lock);
	if (0xFFFFFFF == g_squence_id) {
		g_squence_id = 0;
	}
	g_squence_id ++;
	squence_id = g_squence_id;
	pthread_mutex_unlock(&g_squence_lock);
	return squence_id;
}

static void lock_mailbox(const char *username)
{
	USER_ITEM *pitem;
	char temp_user[128];

	strncpy(temp_user, username, 128);
	lower_string(temp_user);

BEGIN_LOCK:
	pthread_mutex_lock(&g_hash_lock);
	pitem = str_hash_query(g_user_hash, temp_user);
	if (NULL != pitem) {
		if (TRUE == pitem->b_lock) {
			pthread_mutex_unlock(&g_hash_lock);
			sleep(1);
			goto BEGIN_LOCK;
		}
		pitem->b_lock = TRUE;
	}
	pthread_mutex_unlock(&g_hash_lock);
}

static void unlock_mailbox(const char *username)
{
	USER_ITEM *pitem;
	char temp_user[128];

	strncpy(temp_user, username, 128);
	lower_string(temp_user);

	pthread_mutex_lock(&g_hash_lock);
	pitem = str_hash_query(g_user_hash, temp_user);
	if (NULL != pitem) {
		pitem->b_lock = FALSE;
	}
	pthread_mutex_unlock(&g_hash_lock);
}

static BOOL md5_msg_file(const char *path, char *digest)
{
	int offset;
	char *pbuff;
	MD5_CTX ctx;
	int i, len, fd;
	MIME_FIELD mime_field;
	struct stat node_stat;
	unsigned char md[MD5_DIGEST_LENGTH];


	if (0 != stat(path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}
	
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return FALSE;
	}

	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		return FALSE;
	}

	close(fd);

	offset = 0;
	while (len = parse_mime_field(pbuff + offset,
		node_stat.st_size - offset, &mime_field)) {
		if ((8 == mime_field.field_name_len &&
			0 == strncasecmp("Received", mime_field.field_name, 8)) ||
			(9 == mime_field.field_name_len &&
			0 == strncasecmp("X-Lasthop", mime_field.field_name, 9)) ||
			(18 ==mime_field.field_name_len &&
			 0 == strncasecmp("X-Penetrate-Bounce",
				mime_field.field_name, 18))) {
			offset += len;
			continue;
		}
		break;
	}

	MD5_Init(&ctx);
	MD5_Update(&ctx, (void*)pbuff + offset,
		node_stat.st_size - offset);
	MD5_Final(md, &ctx);

	free(pbuff);
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		sprintf(digest + 2*i, "%02x", md[i]);
	}

	return TRUE;

}

