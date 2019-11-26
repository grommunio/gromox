#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <libHX/option.h>
#include <libHX/string.h>
#include "util.h"
#include "str_hash.h"
#include "list_file.h"
#include "mail_func.h"
#include "config_file.h"
#include "double_list.h"
#include <time.h>
#include <zlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <stddef.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/un.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <mysql/mysql.h>
#define SOCKET_TIMEOUT		60

#define SCAN_INTERVAL		60


typedef struct _CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
	int sockd;
	int offset;
	char username[128];
	char buffer[256*1024];
	char line[256*1024 + 1];
} CONNECTION_NODE;

typedef struct _ACL_ITEM {
	DOUBLE_LIST_NODE node;
	char ip_addr[16];
} ACL_ITEM;

typedef struct _MYSQL_CONN {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	MYSQL *pmysql;
} MYSQL_CONN;

typedef struct _USER_ITEM {
	time_t last_time;
	time_t last_visit;
	char password[128];
	char maildir[128];
	BOOL b_lock;
	int version;
	STR_HASH_TABLE *phash;
} USER_ITEM;

typedef struct _USER_NODE {
	DOUBLE_LIST_NODE node;
	char username[128];
	USER_ITEM *puser;
} USER_NODE;

typedef struct _MSG_UNIT {
	char mid[128];
	int size;
} MSG_UNIT;

typedef struct _MIDB_ITEM {
	char prefix[256];
	char ip_addr[16];
	int port;
} MIDB_ITEM;

typedef struct _MIDB_SVR {
	DOUBLE_LIST_NODE node;
	char prefix[256];
	int prefix_len;
	char ip_addr[16];
	int port;
	DOUBLE_LIST conn_list;
} MIDB_SVR;

typedef struct _MIDB_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
	time_t last_time;
	MIDB_SVR *psvr;
} MIDB_CONN;

typedef struct _SYNC_NODE {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
} SYNC_NODE;


static int g_hash_cap;
static int g_mysql_port;
static BOOL g_notify_stop;
static int g_mysql_timeout;
static char g_db_name[256];
static char g_mysql_host[256];
static char g_mysql_user[256];
static DOUBLE_LIST g_acl_list;
static DOUBLE_LIST g_midb_list;
static DOUBLE_LIST g_sync_list;
static DOUBLE_LIST g_user_list;
static DOUBLE_LIST g_mysql_list;
static char g_mysql_password[256];
static STR_HASH_TABLE *g_user_hash;
static pthread_mutex_t g_midb_lock;
static pthread_mutex_t g_hash_lock;
static pthread_mutex_t g_user_lock;
static pthread_mutex_t g_mysql_lock;
static DOUBLE_LIST g_midb_lost_list;
static DOUBLE_LIST g_mysql_lost_list;
static DOUBLE_LIST g_connection_list;
static pthread_mutex_t g_connection_lock;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static MYSQL_CONN* get_mysql_connection();

static void put_mysql_connection(MYSQL_CONN *pmyconn);

static MIDB_CONN *get_midb_connection(const char *prefix);

static void put_midb_connection(MIDB_CONN *pmidbconn);

static int connect_midb(const char *ip_addr, int port);

static void encode_squote(const char *in, char *out);

static void *accept_work_func(void *param);

static void *sync_work_func(void *param);

static void *scan_work_func(void *param);

static void *thread_work_func(void *param);

static void term_handler(int signo);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static BOOL md5_msg_file(const char *path, char *digest);

static BOOL midb_remove(char *path, char *mids);

static STR_HASH_TABLE *list_mail(const char *path);
static void save_hash(const char *maildir, int version,
	STR_HASH_TABLE *phash);

static int compare_hash(STR_HASH_TABLE *phash, STR_HASH_TABLE *phash1);

static USER_ITEM* lock_mailbox(const char *username);

void unlock_mailbox(USER_ITEM *puser);

int main(int argc, const char **argv)
{
	int optval;
	int thr_num;
	int i, j, num;
	ACL_ITEM *pacl;
	int listen_port;
	MIDB_SVR *pmidb;
	LIST_FILE *plist;
	SYNC_NODE *psync;
	int sockd, status;
	char acl_path[256];
	char midb_path[256];
	MYSQL_CONN *pmyconn;
	MIDB_CONN *pmidbconn;
	CONFIG_FILE *pconfig;
	pthread_t scan_thrid;
	MIDB_ITEM *pmidb_item;
	pthread_t accept_thrid;
	char *str_value, *pitem;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	struct sockaddr_in my_name;
	CONNECTION_NODE *pconnection;

	umask(0);
	opt_config_file = config_default_path("cdnd.cfg");
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
		strcpy(acl_path, "../data/cdnd_acl.txt");
		strcpy(midb_path, "../data/midb_list.txt");
	} else {
		snprintf(acl_path, 255, "%s/cdnd_acl.txt", str_value);
		snprintf(midb_path, 255, "%s/midb_list.txt", str_value);
	}
	printf("[system]: acl file path is %s\n", acl_path);
	printf("[system]: midb list file path is %s\n", midb_path);

	str_value = config_file_get_value(pconfig, "CDND_MAX_NUM");
	if (NULL == str_value) {
		g_hash_cap = 1000;
		config_file_set_value(pconfig, "CDND_MAX_NUM", "1000");
	} else {
		g_hash_cap = atoi(str_value);
		if (g_hash_cap <= 0) {
			g_hash_cap = 1000;
			config_file_set_value(pconfig, "CDND_MAX_NUM", "1000");
		}
	}
	printf("[system]: maximum hash size is %d\n", g_hash_cap);
	
	str_value = config_file_get_value(pconfig, "CDND_THREAD_NUM");
	if (NULL == str_value) {
		thr_num = 5;
		config_file_set_value(pconfig, "CDND_THREAD_NUM", "5");
	} else {
		thr_num = atoi(str_value);
		if (thr_num <= 0 || thr_num >= 20) {
			thr_num = 5;
			config_file_set_value(pconfig, "CDND_THREAD_NUM", "5");
		}
	}
	printf("[system]: sync threads number is %d\n", thr_num);

	str_value = config_file_get_value(pconfig, "CDND_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 10000;
		config_file_set_value(pconfig, "CDND_LISTEN_PORT", "10000");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 10000;
			config_file_set_value(pconfig, "CDND_LISTEN_PORT", "10000");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);
	
	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(g_mysql_host, "localhost");
		config_file_set_value(pconfig, "MYSQL_HOST", "localhost");
	} else {
		strcpy(g_mysql_host, str_value);
	}
	printf("[system]: mysql host is %s\n", g_mysql_host);

	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		g_mysql_port = 3306;
		config_file_set_value(pconfig, "MYSQL_PORT", "3306");
	} else {
		g_mysql_port = atoi(str_value);
		if (g_mysql_port <= 0) {
			g_mysql_port = 3306;
		}
	}
	printf("[system]: mysql port is %d\n", g_mysql_port);

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		strcpy(g_mysql_user, "athena");
		config_file_set_value(pconfig, "MYSQL_USERNAME", "athena");
	} else {
		strcpy(g_mysql_user, str_value);
	}
	printf("[system]: mysql username is %s\n", g_mysql_user);


	str_value = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	if (NULL == str_value) {
		strcpy(g_mysql_password, "athena");
		config_file_set_value(pconfig, "MYSQL_PASSWORD", "athena");
	} else {
		strcpy(g_mysql_password, str_value);
	}
	printf("[system]: mysql password is ********\n");

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(g_db_name, "email");
		config_file_set_value(pconfig, "MYSQL_DBNAME", "email");
	} else {
		strcpy(g_db_name, str_value);
	}
	printf("[system]: mysql database name is %s\n", g_db_name);
	
	str_value = config_file_get_value(pconfig, "MYSQL_RDWR_TIMEOUT");
	if (NULL == str_value) {
		g_mysql_timeout = 0;
	} else {
		g_mysql_timeout = atoi(str_value);
		if (g_mysql_timeout < 0) {
			g_mysql_timeout = 0;
		}
	}
	
	if (g_mysql_timeout > 0) {
		printf("[system]: mysql read write timeout is %d\n", g_mysql_timeout);
	}
	
	config_file_save(pconfig);
	config_file_free(pconfig);
	
	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) {
        printf("[system]: fail to create socket for listening\n");
		return 3;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
		sizeof(int));
	
	/* socket binding */
	memset(&my_name, 0, sizeof(my_name));
	my_name.sin_family = AF_INET;
	my_name.sin_addr.s_addr = INADDR_ANY;   
	my_name.sin_port = htons(listen_port);
	
	status = bind(sockd, (struct sockaddr*)&my_name, sizeof(my_name));
	if (-1 == status) {
		printf("[system]: bind *:%u: %s\n", listen_port, strerror(errno));
        close(sockd);
		return 4;
    }
	
	status = listen(sockd, 5);

	if (-1 == status) {
		printf("[system]: fail to listen socket\n");
		close(sockd);
		return 5;
	}

	plist = list_file_init(acl_path, "%s:16");
    if (NULL == plist) {
		printf("[system]: fail to open acl file %s\n", acl_path);
		close(sockd);
		return 6;
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

	
	g_user_hash = str_hash_init(g_hash_cap, sizeof(USER_ITEM), NULL);
	if (NULL == g_user_hash) {
		printf("[system]: fail to init user hash table\n");
		close(sockd);
		list_file_free(plist);
		return 7;
	}

	plist = list_file_init(midb_path, "%s:256%s:16%d");
	if (NULL == plist) {
		printf("[system]: fail to open list file %s\n", midb_path);
		close(sockd);
		str_hash_free(g_user_hash);
		return 8;
	}

	double_list_init(&g_midb_list);
	double_list_init(&g_midb_lost_list);
	
	num = list_file_get_item_num(plist);
	pmidb_item = (MIDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<num; i++) {
		pmidb = (MIDB_SVR*)malloc(sizeof(MIDB_SVR));
		if (NULL == pmidb) {
			printf("[system]: fail to allocate memory for midb server\n");
			list_file_free(plist);
			close(sockd);
			str_hash_free(g_user_hash);
			return 9;
		}
		pmidb->node.pdata = pmidb;
		strcpy(pmidb->prefix, pmidb_item[i].prefix);
		pmidb->prefix_len = strlen(pmidb->prefix);
		strcpy(pmidb->ip_addr, pmidb_item[i].ip_addr);
		pmidb->port = pmidb_item[i].port;
		double_list_init(&pmidb->conn_list);
		double_list_append_as_tail(&g_midb_list, &pmidb->node);
		for (j=0; j<thr_num; j++) {
	       pmidbconn = (MIDB_CONN*)malloc(sizeof(MIDB_CONN));
		    if (NULL != pmidbconn) {
			    pmidbconn->node.pdata = pmidbconn;
				pmidbconn->sockd = -1;
				pmidbconn->psvr = pmidb;
	            double_list_append_as_tail(&g_midb_lost_list, &pmidbconn->node);
		    }
		}
	}
	list_file_free(plist);
	
	double_list_init(&g_mysql_list);
	double_list_init(&g_mysql_lost_list);
	for (i=0; i<thr_num; i++) {
		pmyconn = (MYSQL_CONN*)malloc(sizeof(MYSQL_CONN));
		if (NULL == pmyconn) {
			continue;
		}
		pmyconn->node.pdata = pmyconn;
		pmyconn->node_temp.pdata = pmyconn;
		pmyconn->pmysql = NULL;
		double_list_append_as_tail(&g_mysql_lost_list, &pmyconn->node);
	}
	
	double_list_init(&g_connection_list);
	double_list_init(&g_user_list);
	
	pthread_mutex_init(&g_mysql_lock, NULL);
	pthread_mutex_init(&g_midb_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
	pthread_mutex_init(&g_hash_lock, NULL);
	pthread_mutex_init(&g_user_lock, NULL);

	
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	
	if (0 != pthread_create(&scan_thrid, NULL, scan_work_func, NULL)) {
		close(sockd);
		str_hash_free(g_user_hash);
		while ((pnode = double_list_get_from_head(&g_midb_list)) != NULL) {
			pmidb = (MIDB_SVR*)pnode->pdata;
			double_list_free(&pmidb->conn_list);
			free(pmidb);
		}
		double_list_free(&g_midb_list);
		while ((pnode = double_list_get_from_head(&g_midb_lost_list)) != NULL)
			free(pnode->pdata);
		double_list_free(&g_midb_lost_list);
		while ((pnode = double_list_get_from_head(&g_mysql_lost_list)) != NULL)
			free(pnode->pdata);
		double_list_free(&g_mysql_lost_list);
		double_list_free(&g_mysql_list);
		double_list_free(&g_connection_list);
		double_list_free(&g_user_list);
		pthread_mutex_destroy(&g_mysql_lock);
		pthread_mutex_destroy(&g_midb_lock);
		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_hash_lock);
		pthread_mutex_destroy(&g_user_lock);
		printf("[system]: fail to create accept thread\n");
		return 10;
	}
	
	if (0 != pthread_create(&accept_thrid, NULL, accept_work_func, (void*)(long)sockd)) {
		g_notify_stop = TRUE;
		close(sockd);
		pthread_join(scan_thrid, NULL);
		while ((pnode = double_list_get_from_head(&g_midb_list)) != NULL) {
			pmidb = (MIDB_SVR*)pnode->pdata;
			while ((pnode1 = double_list_get_from_head(&pmidb->conn_list)) != NULL) {
				pmidbconn = (MIDB_CONN*)pnode1->pdata;
				close(pmidbconn->sockd);
				free(pmidbconn);
			}
			double_list_free(&pmidb->conn_list);
			free(pmidb);
		}
		double_list_free(&g_midb_list);
		while ((pnode = double_list_get_from_head(&g_mysql_list)) != NULL) {
			pmyconn = (MYSQL_CONN*)pnode->pdata;
			mysql_close(pmyconn->pmysql);
			free(pmyconn);
		}
		double_list_free(&g_mysql_list);
		while ((pnode = double_list_get_from_head(&g_midb_lost_list)) != NULL)
			free(pnode->pdata);
		double_list_free(&g_midb_lost_list);
		while ((pnode = double_list_get_from_head(&g_mysql_lost_list)) != NULL)
			free(pnode->pdata);
		double_list_free(&g_mysql_lost_list);
		str_hash_free(g_user_hash);
		double_list_free(&g_connection_list);
		double_list_free(&g_user_list);
		pthread_mutex_destroy(&g_mysql_lock);
		pthread_mutex_destroy(&g_midb_lock);
		pthread_mutex_destroy(&g_connection_lock);
		pthread_mutex_destroy(&g_hash_lock);
		pthread_mutex_destroy(&g_user_lock);
		printf("[system]: fail to create accept thread\n");
		return 11;
	}
	
	for (i=0; i<thr_num; i++) {
		psync = (SYNC_NODE*)malloc(sizeof(SYNC_NODE));
		if (NULL == psync) {
			continue;
		}
		psync->node.pdata = psync;
		if (0 != pthread_create(&psync->thr_id, NULL, sync_work_func, NULL)) {
			free(psync);
			printf("[system]: fail to create sync thread\n");
			continue;
		}
		double_list_append_as_tail(&g_sync_list, &psync->node);
	}
	
	printf("[system]: CDND is now rinning\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}

	close(sockd);
	pthread_cancel(accept_thrid);
	pthread_join(scan_thrid, NULL);
	
	while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		pthread_cancel(pconnection->thr_id);
		close(pconnection->sockd);
		free(pconnection);
	}
	double_list_free(&g_connection_list);
	
	while ((pnode = double_list_get_from_head(&g_sync_list)) != NULL) {
		psync = (SYNC_NODE*)pnode->pdata;
		pthread_cancel(psync->thr_id);
		free(psync);
	}
	
	while ((pnode = double_list_get_from_head(&g_midb_list)) != NULL) {
		pmidb = (MIDB_SVR*)pnode->pdata;
		while ((pnode1 = double_list_get_from_head(&pmidb->conn_list)) != NULL) {
			pmidbconn = (MIDB_CONN*)pnode1->pdata;
			close(pmidbconn->sockd);
			free(pmidbconn);
		}
		double_list_free(&pmidb->conn_list);
		free(pmidb);
	}
	double_list_free(&g_midb_list);
	while ((pnode = double_list_get_from_head(&g_mysql_list)) != NULL) {
		pmyconn = (MYSQL_CONN*)pnode->pdata;
		mysql_close(pmyconn->pmysql);
		free(pmyconn);
	}
	double_list_free(&g_mysql_list);
	while ((pnode = double_list_get_from_head(&g_midb_lost_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&g_midb_lost_list);
	while ((pnode = double_list_get_from_head(&g_mysql_lost_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&g_mysql_lost_list);	
	double_list_free(&g_user_list);
	str_hash_free(g_user_hash);
	
	double_list_free(&g_connection_list);
	pthread_mutex_destroy(&g_mysql_lock);
	pthread_mutex_destroy(&g_midb_lock);
	pthread_mutex_destroy(&g_hash_lock);
	pthread_mutex_destroy(&g_user_lock);

	return 0;
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


		pconnection = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
		if (NULL == pconnection) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			continue;
		}

		pconnection->node.pdata = pconnection;
		pconnection->offset = 0;
		pconnection->username[0] = '\0';
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
	int len;
	char *ptr;
	int *psize;
	int offset;
	char *pbuff;
	char *parray;
	gzFile gz_fd;
	MYSQL_ROW myrow;
	USER_ITEM *puser;
	MYSQL_RES *pmyres;
	char username[128];
	USER_ITEM temp_user;
	char temp_name[256];
	char buff[256*1024];
	char temp_path[256];
	MYSQL_CONN *pmyconn;
	STR_HASH_ITER *iter;
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

		if (0 == strncasecmp(pconnection->line, "MAILBOX ", 8) &&
			strlen(pconnection->line) > 8) {
			strncpy(username, pconnection->line + 8, 128);
			HX_strlower(username);
			pthread_mutex_lock(&g_hash_lock);
			puser = str_hash_query(g_user_hash, username);
			if (NULL != puser) {
				time(&puser->last_visit);
				strncpy(temp_user.password, puser->password, 128);
				strncpy(temp_user.maildir, puser->maildir, 128);
			}
			pthread_mutex_unlock(&g_hash_lock);
			
			if (NULL == puser) {
				encode_squote(username, temp_name);
				snprintf(buff, 1024, "SELECT password, maildir, "
					"address_status FROM users WHERE username='%s'",
					temp_name);
				pmyconn = get_mysql_connection();
				/* if no mysql connection, return TRUE 
				 * to CDNER for not deleting the cache
				 */
				if (NULL == pmyconn) {
					write(pconnection->sockd, "TRUE\r\n", 6);
					continue;
				}
	
				/* if mysql excution error, return TRUE 
				 * to CDNER for not deleting the cache
				 */
				if (0 != mysql_query(pmyconn->pmysql, buff) ||
					NULL == (pmyres = mysql_store_result(pmyconn->pmysql))) {
					mysql_close(pmyconn->pmysql);
					pmyconn->pmysql = NULL;
					put_mysql_connection(pmyconn);
					write(pconnection->sockd, "TRUE\r\n", 6);
					continue;
				}

				if (1 != mysql_num_rows(pmyres)) {
					put_mysql_connection(pmyconn);
					mysql_free_result(pmyres);
					write(pconnection->sockd, "FALSE\r\n", 7);
					continue;
				}

				put_mysql_connection(pmyconn);

				myrow = mysql_fetch_row(pmyres);
				if (0 != atoi(myrow[2])) {
					mysql_free_result(pmyres);
					write(pconnection->sockd, "FALSE\r\n", 7);
					continue;
				}

				if (0 != stat(myrow[1], &node_stat) ||
					0 == S_ISDIR(node_stat.st_mode)) {
					mysql_free_result(pmyres);
					write(pconnection->sockd, "FALSE\r\n", 7);
					continue;
				}

				strncpy(temp_user.password, myrow[0], 128);
				strncpy(temp_user.maildir, myrow[1], 128);
				temp_user.b_lock = FALSE;
				temp_user.version = 0 ;
				temp_user.last_time = 0;
				time(&temp_user.last_visit);
				temp_user.phash = NULL;
				mysql_free_result(pmyres);
				
				pthread_mutex_lock(&g_hash_lock);
				str_hash_add(g_user_hash, username, &temp_user); 
				pthread_mutex_unlock(&g_hash_lock);
			}

			strncpy(pconnection->username, username, 128);
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if (0 == strcasecmp(pconnection->line, "INFO")) {
			if ('\0' == pconnection->username[0]) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			pthread_mutex_lock(&g_hash_lock);
			puser = str_hash_query(g_user_hash, pconnection->username);
			if (NULL != puser) {
				time(&puser->last_visit);
				strncpy(temp_user.password, puser->password, 128);
				strncpy(temp_user.maildir, puser->maildir, 128);
				temp_user.version = puser->version;
			}
			pthread_mutex_unlock(&g_hash_lock);

			if (NULL == puser) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			len = snprintf(buff, 1024, "TRUE %d %s\r\n", temp_user.version,
					temp_user.password);
			write(pconnection->sockd, buff, len);
		} else if (0 == strncasecmp(pconnection->line, "REMOVE ", 7)) {
			if ('\0' == pconnection->username[0]) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			ptr = pconnection->line + 7;
			if ('\0' == *ptr) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			parray = ptr;
			
			for (;'\0'!=*ptr; ptr++) {
				if (' ' == *ptr) {
					*ptr = '\0';
				}
			}
			
			*(ptr + 1) = '\0';
			
			puser = lock_mailbox(pconnection->username);
			if (NULL == puser) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			
			if (NULL == puser->phash) {
				unlock_mailbox(puser);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			
			if (FALSE == midb_remove(puser->maildir, parray)) {
				unlock_mailbox(puser);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			

			ptr = parray;
			while ('\0' != *ptr) {
				len = strlen(ptr);
				str_hash_remove(puser->phash, ptr);
				ptr += len + 1;
			}

			snprintf(temp_path, 256, "%s/tmp/inbox.list", puser->maildir);
			len = snprintf(buff, 1024, "%d 0\n", puser->version);
			fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (-1 != fd) {
				iter = str_hash_iter_init(puser->phash);
				for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
					str_hash_iter_forward(iter)) {
					psize = str_hash_iter_get_value(iter, temp_name);
					len += snprintf(buff + len, sizeof(buff) - len,
							"%s %d\n", temp_name, *psize);
					if (len >= sizeof(buff) - 256) {
						write(fd, buff, len);
						len = 0;
					}
				}
				str_hash_iter_free(iter);
				if (len > 0) {
					write(fd, buff, len);
				}
				close(fd);
			}

			unlock_mailbox(puser);

			ptr = parray;

			while ('\0' != *ptr) {
				len = strlen(ptr);
				snprintf(temp_path, 256, "%s/eml/%s",
					temp_user.maildir, ptr);
				remove(temp_path);
				ptr += len + 1;
			}
			write(pconnection->sockd, "TRUE\r\n", 6);
		} else if(0 == strncasecmp(pconnection->line, "MD5-MSG ",8)) {
			if ('\0' == pconnection->username[0]) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			pthread_mutex_lock(&g_hash_lock);
			puser = str_hash_query(g_user_hash, pconnection->username);
			if (NULL != puser) {
				strncpy(temp_user.maildir, puser->maildir, 128);
			}
			pthread_mutex_unlock(&g_hash_lock);
			if (NULL == puser) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			snprintf(temp_path, 256, "%s/eml/%s", temp_user.maildir,
				pconnection->line + 8);

			strcpy(buff, "TRUE ");
			if (FALSE == md5_msg_file(temp_path, buff + 5)) {
				write(pconnection->sockd, "FALSE\r\n", 7);
			} else {
				offset = strlen(buff);
				buff[offset] = '\r';
				offset ++;
				buff[offset] = '\n';
				offset ++;
				write(pconnection->sockd, buff, offset);
			}
		} else if (0 == strncasecmp(pconnection->line, "GET ", 4)) {
			if ('\0' == pconnection->username[0]) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			pthread_mutex_lock(&g_hash_lock);
			puser = str_hash_query(g_user_hash, pconnection->username);
			if (NULL != puser) {
				strncpy(temp_user.maildir, puser->maildir, 128);
			}
			pthread_mutex_unlock(&g_hash_lock);
			if (NULL == puser) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			snprintf(temp_path, 256, "%s/eml/%s", temp_user.maildir,
				pconnection->line + 4);
			if (0 != stat(temp_path, &node_stat) ||
				0 == S_ISREG(node_stat.st_mode)) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			if (node_stat.st_size > sizeof(buff)) {
				pbuff = malloc(node_stat.st_size);
				if (NULL == pbuff) {
					close(fd);
					write(pconnection->sockd, "FALSE\r\n", 7);
					continue;
				}
			} else {
				pbuff = buff;
			}

			if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
				close(fd);
				if (node_stat.st_size > sizeof(buff)) {
					free(pbuff);
				}
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			close(fd);
			
			strcat(temp_path, ".gz");
			gz_fd = gzopen(temp_path, "wb");
			if (Z_NULL == gz_fd) {
				close(fd);
				if (node_stat.st_size > sizeof(buff)) {
					free(pbuff);
				}
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			if (node_stat.st_size != gzwrite(gz_fd, pbuff,
				node_stat.st_size)) {
				if (node_stat.st_size > sizeof(buff)) {
					free(pbuff);
				}
				gzclose(gz_fd);
				remove(temp_path);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			if (node_stat.st_size > sizeof(buff)) {
				free(pbuff);
			}
			gzclose(gz_fd);

			if (0 != stat(temp_path, &node_stat)) {
				remove(temp_path);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			if (node_stat.st_size + 128 > sizeof(buff)) {
				pbuff = malloc(node_stat.st_size + 128);
				if (NULL == pbuff) {
					remove(temp_path);
					write(pconnection->sockd, "FALSE\r\n", 7);
					continue;
				}
			} else {
				pbuff = buff;
			}

			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				remove(temp_path);
				if (node_stat.st_size + 128 > sizeof(buff)) {
					free(pbuff);
				}
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			offset = sprintf(pbuff, "TRUE gzip %d\r\n", node_stat.st_size);
			if (node_stat.st_size != read(fd, pbuff + offset,
				node_stat.st_size)) {
				close(fd);
				remove(temp_path);
				if (node_stat.st_size + 128 > sizeof(buff)) {
					free(pbuff);
				}
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			offset += node_stat.st_size;
			close(fd);
			remove(temp_path);
			write(pconnection->sockd, pbuff, offset);
			if (node_stat.st_size + 128 > sizeof(buff)) {
				free(pbuff);
			}
			continue;
		} else if (0 == strcasecmp(pconnection->line, "UIDL")) {
			if ('\0' == pconnection->username[0]) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			puser = lock_mailbox(pconnection->username);
			if (NULL == puser) {
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}
			
			if (NULL == puser->phash) {
				unlock_mailbox(puser);
				write(pconnection->sockd, "FALSE\r\n", 7);
				continue;
			}

			len = snprintf(buff, 1024, "TRUE %d %d\r\n", puser->version,
					puser->phash->item_num);
			
			iter = str_hash_iter_init(puser->phash);
			for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
				str_hash_iter_forward(iter)) {
				psize = str_hash_iter_get_value(iter, temp_name);
				len += snprintf(buff + len, sizeof(buff) - len, "%s %d\r\n",
						temp_name, *psize);
				if (len >= sizeof(buff) - 256) {
					write(pconnection->sockd, buff, len);
					len = 0;
				}
			}
			str_hash_iter_free(iter);

			if (len > 0) {
				write(pconnection->sockd, buff, len);
			}
			unlock_mailbox(puser);
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

static void* sync_work_func(void *param)
{
	int result;
	MYSQL_ROW myrow;
	USER_ITEM *puser;
	USER_NODE *punode;
	MYSQL_RES *pmyres;
	MYSQL_CONN *pmyconn;
	struct stat node_stat;
	char sql_string[1024];
	STR_HASH_TABLE *phash;
	DOUBLE_LIST_NODE *pnode;


	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_user_lock);
		pnode = double_list_get_from_head(&g_user_list);
		pthread_mutex_unlock(&g_user_lock);

		if (NULL == pnode) {
			sleep(1);
			continue;
		}

		pmyconn = get_mysql_connection();
		if (NULL == pmyconn) {
			pthread_mutex_lock(&g_user_lock);
			double_list_append_as_tail(&g_user_list, pnode);
			pthread_mutex_unlock(&g_user_lock);
			continue;
		}

		punode = (USER_NODE*)pnode->pdata;
		puser = punode->puser;

		snprintf(sql_string, 1024, "SELECT password, maildir, "
			"address_status FROM users WHERE username='%s'",
			punode->username);
		if (0 != mysql_query(pmyconn->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmyconn->pmysql))) {
			mysql_close(pmyconn->pmysql);
			pmyconn->pmysql = NULL;
			put_mysql_connection(pmyconn);

			pthread_mutex_lock(&g_user_lock);
			double_list_append_as_tail(&g_user_list, pnode);
			pthread_mutex_unlock(&g_user_lock);
			continue;
		}

		if (1 != mysql_num_rows(pmyres)) {
			put_mysql_connection(pmyconn);

			mysql_free_result(pmyres);

			pthread_mutex_lock(&g_hash_lock);
			str_hash_remove(g_user_hash, punode->username);
			pthread_mutex_unlock(&g_hash_lock);

			if (NULL != puser->phash) {
				str_hash_free(puser->phash);
			}
			free(punode);
			continue;
		}

		put_mysql_connection(pmyconn);

		myrow = mysql_fetch_row(pmyres);
		if (0 != atoi(myrow[2]) ||
			0 != stat(myrow[1], &node_stat) ||
			0 == S_ISDIR(node_stat.st_mode)) {

			mysql_free_result(pmyres);

			pthread_mutex_lock(&g_hash_lock);
			str_hash_remove(g_user_hash, punode->username);
			pthread_mutex_unlock(&g_hash_lock);

			if (NULL != puser->phash) {
				str_hash_free(puser->phash);
			}
			free(punode);
			continue;
		}

		strncpy(puser->password, myrow[0], 128);
		strncpy(puser->maildir, myrow[1], 128);
		
		mysql_free_result(pmyres);

		phash = list_mail(puser->maildir);
		result = 1;
		if (NULL != phash && (NULL == puser->phash ||
			0 != (result = compare_hash(phash, puser->phash)))) {
			if (NULL != puser->phash) {
				str_hash_free(puser->phash);
			}
			puser->phash = phash;
			puser->version ++;
			save_hash(puser->maildir, puser->version, puser->phash);
		}

		if (0 == result) {
			str_hash_free(phash);
		}
		time(&puser->last_time);
		puser->b_lock = FALSE;
		free(punode);
		
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


static void *scan_work_func(void *param)
{
	fd_set myset;
	time_t cur_time;
	MIDB_SVR *pmidb;
	time_t now_time;
	USER_ITEM *puser;
	USER_NODE *punode;
	struct timeval tv;
	MYSQL_CONN *pmyconn;
	STR_HASH_ITER *iter;
	char temp_buff[1024];
	MIDB_CONN *pmidbconn;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *phead, *ptail;
	DOUBLE_LIST_NODE *pnode, *pnode1;
	

	double_list_init(&temp_list);
	while (0 == g_notify_stop) {
		pthread_mutex_lock(&g_mysql_lock);
		phead = double_list_get_head(&g_mysql_lost_list);
		ptail = double_list_get_tail(&g_mysql_lost_list);
		pthread_mutex_unlock(&g_mysql_lock);
		for (pnode=phead; NULL!=pnode; pnode=double_list_get_after(
			&g_mysql_lost_list, pnode)) {
			pmyconn = (MYSQL_CONN*)pnode->pdata;
			pmyconn->pmysql = mysql_init(NULL);
			if (NULL != pmyconn->pmysql) {
				if (g_mysql_timeout > 0) {
					mysql_options(pmyconn->pmysql, MYSQL_OPT_READ_TIMEOUT,
						&g_mysql_timeout);
					mysql_options(pmyconn->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
						&g_mysql_timeout);
				}
				if (NULL != mysql_real_connect(pmyconn->pmysql, g_mysql_host,
					g_mysql_user, g_mysql_password, g_db_name, g_mysql_port, NULL, 0)) {
					double_list_append_as_tail(&temp_list, &pmyconn->node_temp);
				} else {
					mysql_close(pmyconn->pmysql);
					pmyconn->pmysql = NULL;
				}
			}
			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_lock(&g_mysql_lock);
		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pmyconn = (MYSQL_CONN*)pnode->pdata;
			double_list_remove(&g_mysql_lost_list, &pmyconn->node);
			double_list_append_as_tail(&g_mysql_list, &pmyconn->node);
		}
		pthread_mutex_unlock(&g_mysql_lock);
		
		pthread_mutex_lock(&g_midb_lock);
		time(&now_time);
		for (pnode=double_list_get_head(&g_midb_list); NULL!=pnode;
			pnode=double_list_get_after(&g_midb_list, pnode)) {
			pmidb = (MIDB_SVR*)pnode->pdata;
			ptail = double_list_get_tail(&pmidb->conn_list);
			while ((pnode1 = double_list_get_from_head(&pmidb->conn_list)) != NULL) {
				pmidbconn = (MIDB_CONN*)pnode1->pdata;
				if (now_time - pmidbconn->last_time >= SOCKET_TIMEOUT - 3) {
					double_list_append_as_tail(&temp_list, &pmidbconn->node);
				} else {
					double_list_append_as_tail(&pmidb->conn_list,
						&pmidbconn->node);
				}

				if (pnode1 == ptail) {
					break;
				}
			}
		}
		pthread_mutex_unlock(&g_midb_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pmidbconn = (MIDB_CONN*)pnode->pdata;
			write(pmidbconn->sockd, "PING\r\n", 6);
			tv.tv_usec = 0;
			tv.tv_sec = SOCKET_TIMEOUT;
			FD_ZERO(&myset);
			FD_SET(pmidbconn->sockd, &myset);
			if (select(pmidbconn->sockd + 1, &myset, NULL, NULL, &tv) <= 0 ||
				read(pmidbconn->sockd, temp_buff, 1024) <= 0) {
				close(pmidbconn->sockd);
				pmidbconn->sockd = -1;
				put_midb_connection(pmidbconn);
			} else {
				time(&pmidbconn->last_time);
				put_midb_connection(pmidbconn);
			}
		}

		pthread_mutex_lock(&g_midb_lock);
		while ((pnode = double_list_get_from_head(&g_midb_lost_list)) != NULL)
			double_list_append_as_tail(&temp_list, pnode);
		pthread_mutex_unlock(&g_midb_lock);

		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pmidbconn = (MIDB_CONN*)pnode->pdata;
			pmidbconn->sockd = connect_midb(pmidbconn->psvr->ip_addr,
								pmidbconn->psvr->port);
			if (-1 != pmidbconn->sockd) {
				time(&pmidbconn->last_time);
			}
			put_midb_connection(pmidbconn);
		}

		pthread_mutex_lock(&g_hash_lock);
		time(&cur_time);
		iter = str_hash_iter_init(g_user_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			puser = str_hash_iter_get_value(iter, temp_buff);
			if (FALSE == puser->b_lock &&
				cur_time - puser->last_time >= SCAN_INTERVAL) {
				punode = (USER_NODE*)malloc(sizeof(USER_NODE));
				if (NULL != punode) {
					punode->node.pdata = punode;
					puser->b_lock = TRUE;
					punode->puser = puser;
					strncpy(punode->username, temp_buff, 128);
					pthread_mutex_lock(&g_user_lock);
					double_list_append_as_tail(&g_user_list, &punode->node);
					pthread_mutex_unlock(&g_user_lock);
				}
			}
			
			if (cur_time - puser->last_visit > 24*60*60) {
				if (NULL != puser->phash) {
					str_hash_free(puser->phash);
				}
				str_hash_iter_remove(iter);
			}
			
		}
		str_hash_iter_free(iter);

		pthread_mutex_unlock(&g_hash_lock);

		sleep(1);
	}
	return NULL;
}


static MYSQL_CONN* get_mysql_connection()
{
	int i;
	DOUBLE_LIST_NODE *pnode;

	pthread_mutex_lock(&g_mysql_lock);
	pnode = double_list_get_from_head(&g_mysql_list);
	pthread_mutex_unlock(&g_mysql_lock);

	if (NULL == pnode) {
		for (i=0; i<SOCKET_TIMEOUT; i++) {
			sleep(1);
			pthread_mutex_lock(&g_mysql_lock);
			pnode = double_list_get_from_head(&g_mysql_list);
			pthread_mutex_unlock(&g_mysql_lock);
			if (NULL != pnode) {
				break;
			}
		}
		if (i == SOCKET_TIMEOUT) {
			return NULL;
		}
	}

	return (MYSQL_CONN*)pnode->pdata;
}

static void put_mysql_connection(MYSQL_CONN *pmyconn)
{
	if (NULL != pmyconn->pmysql) {
		pthread_mutex_lock(&g_mysql_lock);
		double_list_append_as_tail(&g_mysql_list, &pmyconn->node);
		pthread_mutex_unlock(&g_mysql_lock);
	} else {
		pthread_mutex_lock(&g_mysql_lock);
		double_list_append_as_tail(&g_mysql_lost_list, &pmyconn->node);
		pthread_mutex_unlock(&g_mysql_lock);
	}
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
	while ((len = parse_mime_field(pbuff + offset,
	       node_stat.st_size - offset, &mime_field)) != 0) {
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

static void encode_squote(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if ('\'' == in[i] || '\\' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}


static MIDB_CONN *get_midb_connection(const char *prefix)
{
	int i;
	MIDB_SVR *pmidb;
	DOUBLE_LIST_NODE *pnode;


	for (pnode=double_list_get_head(&g_midb_list); NULL!=pnode;
		pnode=double_list_get_after(&g_midb_list, pnode)) {
		pmidb = (MIDB_SVR*)pnode->pdata;
		if (0 == strncmp(pmidb->prefix, prefix, pmidb->prefix_len)) {
			break;
		}
	}

	if (NULL == pnode) {
		return NULL;
	}
	
	pthread_mutex_lock(&g_midb_lock);
	pnode = double_list_get_from_head(&pmidb->conn_list);
	pthread_mutex_unlock(&g_midb_lock);

	if (NULL == pnode) {
		for (i=1; i<SOCKET_TIMEOUT; i++) {
			sleep(1);
			pthread_mutex_lock(&g_midb_lock);
			pnode = double_list_get_from_head(&pmidb->conn_list);
			pthread_mutex_unlock(&g_midb_lock);
			if (NULL != pnode) {
				break;
			} 
		}
		if (NULL == pnode) {
			return NULL;
		}
	}

	return (MIDB_CONN*)pnode->pdata;
}


static void put_midb_connection(MIDB_CONN *pmidbconn)
{
	if (-1 == pmidbconn->sockd) {
		pthread_mutex_lock(&g_midb_lock);
		double_list_append_as_tail(&g_midb_lost_list, &pmidbconn->node);
		pthread_mutex_unlock(&g_midb_lock);
	} else {
		time(&pmidbconn->last_time);
		pthread_mutex_lock(&g_midb_lock);
		double_list_append_as_tail(&pmidbconn->psvr->conn_list,
			&pmidbconn->node);
		pthread_mutex_unlock(&g_midb_lock);
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


static BOOL midb_remove(char *path, char *mids)
{
	char *ptr;
	int length;
	int tmp_len;
	char buff[256*1025];
	MIDB_CONN *pmidbconn;
	
	pmidbconn = get_midb_connection(path);
	if (NULL == pmidbconn) {
		return FALSE;
	}

	length = snprintf(buff, 1024, "M-DELE %s inbox", path);

	 ptr = mids;
	 while ('\0' != *ptr) {
		 tmp_len = strlen(ptr);
		 buff[length] = ' ';
		 length ++;
		 memcpy(buff + length, ptr, tmp_len);
		 length += tmp_len;
		 ptr += tmp_len + 1;
	}

	buff[length] = '\r';
	length ++;
	buff[length] = '\n';
	length ++;
	if (length != write(pmidbconn->sockd, buff, length)) {
		goto RDWR_ERROR;
	}
	
	length = read(pmidbconn->sockd, buff, 1024);
	if (length <= 0) {
		goto RDWR_ERROR;
	} else {
		buff[length] = '\0';
		if (0 == strcmp(buff, "TRUE\r\n")) {
			put_midb_connection(pmidbconn);
			return TRUE;
		} else if (0 == strncmp(buff, "FALSE ", 6)) {
			put_midb_connection(pmidbconn);
			return FALSE;	
		} else {
			goto RDWR_ERROR;
		}
	}


RDWR_ERROR:
	close(pmidbconn->sockd);
	pmidbconn->sockd = -1;
	put_midb_connection(pmidbconn);
	return FALSE;
}

static STR_HASH_TABLE *list_mail(const char *path)
{
	int i;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int msg_size;
	int line_pos;
	fd_set myset;
	char *pspace;
	struct timeval tv;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	STR_HASH_TABLE *phash;
	MIDB_CONN *pmidbconn;


	pmidbconn = get_midb_connection(path);
	if (NULL == pmidbconn) {
		return NULL;
	}

	length = snprintf(buff, 1024, "M-UIDL %s inbox\r\n", path);
	if (length != write(pmidbconn->sockd, buff, length)) {
		goto RDWR_ERROR;
	}

	count = 0;
	offset = 0;
	lines = -1;
	phash = NULL;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pmidbconn->sockd, &myset);
		if (select(pmidbconn->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			goto RDWR_ERROR;
		}
		read_len = read(pmidbconn->sockd, buff + offset, 256*1024 - offset);
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
						phash = str_hash_init(lines + 1, sizeof(int), NULL);
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						put_midb_connection(pmidbconn);
						return NULL;
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

				msg_size = atoi(pspace);
				str_hash_add(phash, temp_line, &msg_size);

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
			put_midb_connection(pmidbconn);
			return phash;
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
	close(pmidbconn->sockd);
	pmidbconn->sockd = -1;
	put_midb_connection(pmidbconn);
	if (NULL != phash) {
		str_hash_free(phash);
	}
	return NULL;
}

static void save_hash(const char *maildir, int version,
	STR_HASH_TABLE *phash)
{
	int *psize;
	int len, fd;
	char temp_path[256];
	char temp_name[128];
	char buff[256*1024];
	STR_HASH_ITER *iter;

	snprintf(temp_path, 256, "%s/tmp/inbox.list", maildir);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		return;
	}
	len = snprintf(buff, 1024, "%d 0\n", version);
	iter = str_hash_iter_init(phash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		psize = str_hash_iter_get_value(iter, temp_name);
		len += snprintf(buff + len, sizeof(buff) - len, "%s %d\n",
				temp_name, *psize);
		if (len >= sizeof(buff) - 256) {
			write(fd, buff, len);
			len = 0;
		}
	}

	str_hash_iter_free(iter);
	if (len > 0) {
		write(fd, buff, len);
	}
	close(fd);
}

static int compare_hash(STR_HASH_TABLE *phash, STR_HASH_TABLE *phash1)
{
	char temp_name[128];
	STR_HASH_ITER *iter;

	if (phash->item_num > phash1->item_num) {
		return 1;
	} else if (phash->item_num < phash1->item_num) {
		return -1;
	}

	iter = str_hash_iter_init(phash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, temp_name);
		if (NULL == str_hash_query(phash1, temp_name)) {
			str_hash_iter_free(iter);
			return 1;
		}
	}
	str_hash_iter_free(iter);

	iter = str_hash_iter_init(phash1);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, temp_name);
		if (NULL == str_hash_query(phash, temp_name)) {
			str_hash_iter_free(iter);
			return -1;
		}
	}
	str_hash_iter_free(iter);

	return 0;

}

static USER_ITEM* lock_mailbox(const char *username)
{
	int count;
	USER_ITEM *puser;
	char temp_user[128];

	count = 1;
	strncpy(temp_user, username, 128);
	HX_strlower(temp_user);

TRY_LOCK:
	pthread_mutex_lock(&g_hash_lock);
	puser = str_hash_query(g_user_hash, temp_user);
	if (NULL == puser || TRUE == puser->b_lock) {
		pthread_mutex_unlock(&g_hash_lock);
		if (count >= SOCKET_TIMEOUT) {
			return NULL;
		}
		sleep(1);
		count ++;
		goto TRY_LOCK;
	}
	puser->b_lock = TRUE;
	pthread_mutex_unlock(&g_hash_lock);
	return puser;
}

void unlock_mailbox(USER_ITEM *puser)
{
	puser->b_lock = FALSE;
}

