#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include "util.h"
#include "double_list.h"
#include "config_file.h"
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
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <crypt.h>
#include <mysql/mysql.h>
#define CS_PATH                         "/var/pandora/token/amysql"

#define SOCKET_TIMEOUT                  60

#define ADDRESS_TYPE_NORMAL             0

#define ADDRESS_TYPE_ALIAS              1




typedef struct _MYSQL_CONN {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	MYSQL *pmysql;
} MYSQL_CONN;


typedef struct _FRONT_CONN {
    DOUBLE_LIST_NODE node;
    int sockd;
    int offset;
    char buff[1024];
    struct _MYSQL_CONN *pconn;
} FRONT_CONN;


static void* scan_work_func(void *param);

static void* accept_work_func(void *param);

static void* thread_work_func(void *param);

static int read_line(int sockd, FRONT_CONN *pconnection);

static MYSQL_CONN* get_connection();

static void term_handler(int signo);

static void encode_squote(const char *in, char *out);


static int g_port;
static int g_conn_num;
static int g_notify_stop;
static char g_host[256];
static char g_user[256];
static char g_password[256];
static char g_db_name[256];
static int g_timeout;
static pthread_mutex_t g_crypt_lock;
static pthread_mutex_t g_front_lock;
static pthread_mutex_t g_back_lock;
static pthread_mutex_t g_cond_mutex;
static pthread_cond_t g_waken_cond;
static DOUBLE_LIST g_front_list;
static DOUBLE_LIST g_front_list1;
static DOUBLE_LIST g_back_list;
static DOUBLE_LIST g_lost_list;

int main(int argc, const char **argv)
{
    int listenfd;
	char *str_value;
	int i, len;
	pthread_t *thr_ids;
	pthread_t scan_id;
	pthread_t accept_id;
    struct sockaddr_un unix_addr;
    MYSQL_CONN *pconn;
    FRONT_CONN *pfront;
    DOUBLE_LIST_NODE *pnode;
	CONFIG_FILE *pconfig;

	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return 1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return 1;
	}
	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(g_host, "localhost");
		config_file_set_value(pconfig, "MYSQL_HOST", "localhost");
	} else {
		strcpy(g_host, str_value);
	}

	printf("[system]: mysql host is %s\n", g_host);

	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		g_port = 3306;
		config_file_set_value(pconfig, "MYSQL_PORT", "3306");
	} else {
		g_port = atoi(str_value);
		if (g_port <= 0) {
			g_port = 3306;
		}
	}
	printf("[system]: mysql port is %d\n", g_port);

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		strcpy(g_user, "pandora");
		config_file_set_value(pconfig, "MYSQL_USERNAME", "pandora");
	} else {
		strcpy(g_user, str_value);
	}
	printf("[system]: mysql username is %s\n", g_user);


	str_value = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	if (NULL == str_value) {
		strcpy(g_password, "pandora");
		config_file_set_value(pconfig, "MYSQL_PASSWORD", "pandora");
	} else {
		strcpy(g_password, str_value);
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
		g_timeout = 0;
	} else {
		g_timeout = atoi(str_value);
		if (g_timeout < 0) {
			g_timeout = 0;
		}
	}
	if (g_timeout > 0) {
		printf("[system]: mysql read write timeout is %d\n", g_timeout);
	}

	str_value = config_file_get_value(pconfig, "MYSQL_CONNECTION_NUM");
	if (NULL == str_value) {
		g_conn_num = 10;
		config_file_set_value(pconfig, "MYSQL_CONNECTION_NUM", "10");
	} else {
		g_conn_num = atoi(str_value);
		if (g_conn_num < 10 || g_conn_num > 100) {
			g_conn_num = 10;
		}
	}
	printf("[system]: mysql connectedtion number is %d\n", g_conn_num);

	config_file_save(pconfig);
	config_file_free(pconfig);


	signal(SIGPIPE, SIG_IGN);


    /* Create a Unix domain stream socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == listenfd) {
        printf("[system]: fail to create listen socket\n");
		return 2;
    }

    unlink(CS_PATH);

    /* Fill in socket address structure */
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, CS_PATH);
    len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path);

    /* Bind the name to the descriptor */
    if (bind(listenfd, (struct sockaddr*)&unix_addr, len) < 0) {
        close(listenfd);
        printf("[system]: fail to bind listen socket\n");
		return 3;
    }


    if (chmod(CS_PATH, 0666) < 0) {
        close(listenfd);
        printf("[system]: fail to change access mode of %s\n", CS_PATH);
		return 4;
    }

    if (listen(listenfd, 5) < 0) {
        printf("[system]: fail to listen!\n");
        close(listenfd);
		return 5;
    }

	pthread_mutex_init(&g_crypt_lock, NULL);
	pthread_mutex_init(&g_front_lock, NULL);
	pthread_mutex_init(&g_back_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);

	double_list_init(&g_front_list);
	double_list_init(&g_front_list1);
	double_list_init(&g_back_list);
	double_list_init(&g_lost_list);

    for (i=0; i<g_conn_num; i++) {
        pconn = (MYSQL_CONN*)malloc(sizeof(MYSQL_CONN));
        if (NULL != pconn) {
            pconn->node.pdata = pconn;
			pconn->node_temp.pdata = pconn;
			pconn->pmysql = NULL;
            double_list_append_as_tail(&g_lost_list, &pconn->node);
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
		return 6;
	}


	if (0 != pthread_create(&accept_id, NULL, accept_work_func,
		(void*)(long)listenfd)) {
		printf("[system]: fail to create accept thread\n");
		close(listenfd);
		for (i=0; i<g_conn_num; i++) {
			pthread_cancel(thr_ids[i]);
		}
		return 7;
	}

	if (0 != pthread_create(&scan_id, NULL, scan_work_func, NULL)) {
		printf("[system]: fail to create scan thread\n");
		close(listenfd);
		for (i=0; i<g_conn_num; i++) {
			pthread_cancel(thr_ids[i]);
		}
		return 8;
	}


    g_notify_stop = 0;
    signal(SIGTERM, term_handler);


    printf("[system]: AMYSQL is now running\n");

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
		if (NULL != pfront->pconn) {
			mysql_close(pfront->pconn->pmysql);
			free(pfront->pconn);
		}
		free(pfront);
	}

	while ((pnode = double_list_get_from_head(&g_lost_list)) != NULL)
		free(pnode->pdata);

	while ((pnode = double_list_get_from_head(&g_back_list)) != NULL) {
		pconn = (MYSQL_CONN*)pnode->pdata;
		mysql_close(pconn->pmysql);
		free(pconn);
	}


	pthread_mutex_destroy(&g_crypt_lock);
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

		if (double_list_get_nodes_num(&g_front_list)  + 
			double_list_get_nodes_num(&g_front_list1) >= g_conn_num) {
			pthread_mutex_unlock(&g_front_lock);
			free(pfront);
			close(clifd);
			continue;
		}


        pfront->node.pdata = pfront;
        pfront->sockd = clifd;
        pfront->offset = 0;
		pfront->pconn = NULL;
        double_list_append_as_tail(&g_front_list1, &pfront->node);
		pthread_mutex_unlock(&g_front_lock);
		
		pthread_cond_signal(&g_waken_cond);
    }

	pthread_exit(0);

}


static void *scan_work_func(void *param)
{
	DOUBLE_LIST temp_list;
	MYSQL_CONN *pconn;
	DOUBLE_LIST_NODE *phead, *ptail, *pnode;

	double_list_init(&temp_list);
	while (0 == g_notify_stop) {
		pthread_mutex_lock(&g_back_lock);
		phead = double_list_get_head(&g_lost_list);
		ptail = double_list_get_tail(&g_lost_list);
		pthread_mutex_unlock(&g_back_lock);
		for (pnode=phead; NULL!=pnode;
			pnode=double_list_get_after(&g_lost_list, pnode)) {
			pconn = (MYSQL_CONN*)pnode->pdata;
			pconn->pmysql = mysql_init(NULL);
			if (NULL != pconn->pmysql) {
				if (g_timeout > 0) {
					mysql_options(pconn->pmysql, MYSQL_OPT_READ_TIMEOUT,
						&g_timeout);
					mysql_options(pconn->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
						&g_timeout);
				}
				if (NULL != mysql_real_connect(pconn->pmysql, g_host,
					g_user, g_password, g_db_name, g_port, NULL, 0)) {
					double_list_append_as_tail(&temp_list, &pconn->node_temp);
				} else {
					mysql_close(pconn->pmysql);
					pconn->pmysql = NULL;
				}
			}
			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_lock(&g_back_lock);
		while ((pnode = double_list_get_from_head(&temp_list)) != NULL) {
			pconn = (MYSQL_CONN*)pnode->pdata;
			double_list_remove(&g_lost_list, &pconn->node);
			double_list_append_as_tail(&g_back_list, &pconn->node);
		}
		pthread_mutex_unlock(&g_back_lock);
		sleep(1);
	}
	return NULL;
}



static void *thread_work_func(void *param)
{
	int i, j;
	int rows;
	int rows1;
	char *pat;
	size_t len;
	char *pspace;
	char *pdomain;
	int domain_id;
	int temp_type;
	MYSQL *pmysql;
	int temp_status;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	FRONT_CONN *pfront;
	char homedir[256];
	char temp_user[256];
	char temp_pass[256];
	char temp_real[512];
	char temp_nick[512];
	char temp_lang[64];
	char temp_zone[128];
	char username[1024];
	char password[1024];
	char temp_title[512];
	char temp_buff[1024];
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	char virtual_address[256];

	
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
		


		if (0 == strncasecmp(pfront->buff, "USER-LOGIN ", 11)) {
			pspace = strchr(pfront->buff + 11, ' ');
			if (NULL == pspace) {
				write(pfront->sockd, "FALSE\r\n", 7);
				continue;
			}

			len = pspace - pfront->buff - 11;

			memcpy(temp_buff, pfront->buff + 11, len);
			if (0 != decode64(temp_buff, len, username, &len) ||
				0 != decode64(pspace + 1, strlen(pspace + 1), password,
				&len) || strlen(username) > 128 || strlen(password) > 32) {
				write(pfront->sockd, "FALSE\r\n", 7);
				continue;
			}

			pdomain = strchr(username, '@');
			if (NULL == pdomain) {
				write(pfront->sockd, "FALSE\r\n", 7);
				continue;
			}

			if (NULL == (pfront->pconn = get_connection())) {
				pthread_mutex_lock(&g_front_lock);
				double_list_remove(&g_front_list, &pfront->node);
				pthread_mutex_unlock(&g_front_lock);
				write(pfront->sockd, "FALSE\r\n", 7);
				close(pfront->sockd);
				free(pfront);
				goto NEXT_LOOP;
			}

			pmysql = pfront->pconn->pmysql;

			encode_squote(pdomain + 1, temp_buff);
			sprintf(sql_string, "SELECT id, title, homedir FROM domains WHERE "
				"domainname='%s'", temp_buff);
			if (0 != mysql_query(pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pmysql))) {
				mysql_close(pmysql);
				pmysql = mysql_init(NULL);
				if (NULL == pmysql) {
					pthread_mutex_lock(&g_back_lock);
					pfront->pconn->pmysql = NULL;
					double_list_append_as_tail(&g_lost_list,
						&pfront->pconn->node);
					pfront->pconn = NULL;
					pthread_mutex_unlock(&g_back_lock);

					pthread_mutex_lock(&g_front_lock);
					double_list_remove(&g_front_list, &pfront->node);
					pthread_mutex_unlock(&g_front_lock);
					write(pfront->sockd, "FALSE\r\n", 7);
					close(pfront->sockd);
					free(pfront);
					goto NEXT_LOOP;
				}

				if (g_timeout > 0) {
					mysql_options(pmysql, MYSQL_OPT_READ_TIMEOUT, &g_timeout);
					mysql_options(pmysql, MYSQL_OPT_WRITE_TIMEOUT, &g_timeout);
				}

				if (NULL == mysql_real_connect(pmysql, g_host,
					g_user, g_password, g_db_name, g_port, NULL, 0) ||
					0 != mysql_query(pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(pmysql))) {
					mysql_close(pmysql);
					pthread_mutex_lock(&g_back_lock);
					pfront->pconn->pmysql = NULL;
					double_list_append_as_tail(&g_lost_list,
						&pfront->pconn->node);
					pfront->pconn = NULL;
					pthread_mutex_unlock(&g_back_lock);

					pthread_mutex_lock(&g_front_lock);
					double_list_remove(&g_front_list, &pfront->node);
					pthread_mutex_unlock(&g_front_lock);
					write(pfront->sockd, "FALSE\r\n", 7);
					close(pfront->sockd);
					free(pfront);
					goto NEXT_LOOP;
				} else {
					pfront->pconn->pmysql = pmysql;
				}
			}

			if (1 != mysql_num_rows(pmyres)) {
				mysql_free_result(pmyres);
				write(pfront->sockd, "TRUE DOMAIN-EMPTY\r\n", 19);
				pthread_mutex_lock(&g_back_lock);
				double_list_append_as_tail(&g_back_list, &pfront->pconn->node);
				pfront->pconn = NULL;
				pthread_mutex_unlock(&g_back_lock);
				continue;
			}
			myrow = mysql_fetch_row(pmyres);
			domain_id = atoi(myrow[0]);
			len = strlen(myrow[1]);
			if (0 == len) {
				strcpy(temp_title, "NIL");
			} else {
				encode64(myrow[1], len, temp_title, 512, NULL);
			}
			strcpy(homedir, myrow[2]);
			mysql_free_result(pmyres);


			strcpy(temp_buff, username);
			encode_squote(temp_buff, username);

			sprintf(sql_string, "SELECT id, password, address_type, "
				"address_status, real_name, nickname, group_id, maildir, "
				"max_size, max_file, privilege_bits, lang, timezone "
				"FROM users WHERE username='%s'", username);
			
			if (0 != mysql_query(pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pmysql))) {
				mysql_close(pmysql);
				pmysql = mysql_init(NULL);
				if (NULL == pmysql) {
					pthread_mutex_lock(&g_back_lock);
					pfront->pconn->pmysql = NULL;
					double_list_append_as_tail(&g_lost_list,
						&pfront->pconn->node);
					pfront->pconn = NULL;
					pthread_mutex_unlock(&g_back_lock);

					pthread_mutex_lock(&g_front_lock);
					double_list_remove(&g_front_list, &pfront->node);
					pthread_mutex_unlock(&g_front_lock);
					write(pfront->sockd, "FALSE\r\n", 7);
					close(pfront->sockd);
					free(pfront);
					goto NEXT_LOOP;
						
				}

				if (g_timeout > 0) {
					mysql_options(pmysql, MYSQL_OPT_READ_TIMEOUT, &g_timeout);
					mysql_options(pmysql, MYSQL_OPT_WRITE_TIMEOUT, &g_timeout);
				}

				if (NULL == mysql_real_connect(pmysql, g_host,
					g_user, g_password, g_db_name, g_port, NULL, 0) ||
					0 != mysql_query(pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(pmysql))) {
					mysql_close(pmysql);
					pthread_mutex_lock(&g_back_lock);
					pfront->pconn->pmysql = NULL;
					double_list_append_as_tail(&g_lost_list,
						&pfront->pconn->node);
					pfront->pconn = NULL;
					pthread_mutex_unlock(&g_back_lock);

					pthread_mutex_lock(&g_front_lock);
					double_list_remove(&g_front_list, &pfront->node);
					pthread_mutex_unlock(&g_front_lock);
					write(pfront->sockd, "FALSE\r\n", 7);
					close(pfront->sockd);
					free(pfront);
					goto NEXT_LOOP;
				} else {
					pfront->pconn->pmysql = pmysql;
				}
			}

			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pfront->pconn->node);
			pfront->pconn = NULL;
			pthread_mutex_unlock(&g_back_lock);
			

			if (1 != mysql_num_rows(pmyres)) {
				mysql_free_result(pmyres);
				write(pfront->sockd, "TRUE USER-EMPTY\r\n", 17);
				continue;
			}
			myrow = mysql_fetch_row(pmyres);
			temp_type = atoi(myrow[2]);
			temp_status = atoi(myrow[3]);
			if (ADDRESS_TYPE_NORMAL != temp_type &&
				ADDRESS_TYPE_ALIAS != temp_type) {
				mysql_free_result(pmyres);
				write(pfront->sockd, "TRUE TYPE-ERROR\r\n", 17);	
				continue;
			}
			
			if (0 != temp_status) {
				mysql_free_result(pmyres);
				if (0 != (temp_status&0x30)) {
					write(pfront->sockd, "TRUE DOMAIN-DISABLED\r\n", 22);
				} else if (0 != (temp_status&0xC)) {
					write(pfront->sockd, "TRUE GROUP-DISABLED\r\n", 21);		
				} else {
					write(pfront->sockd, "TRUE USER-DISABLED\r\n", 20);
				}
				continue;
			}

			if ('\0' == myrow[1][0]) {
				mysql_free_result(pmyres);
				write(pfront->sockd, "TRUE PASSWORD-EMPTY\r\n", 21);
				continue;
			}

			pthread_mutex_lock(&g_crypt_lock);
			strcpy(temp_buff, crypt(password, myrow[1]));
			pthread_mutex_unlock(&g_crypt_lock);
			if (0 != strcmp(temp_buff, myrow[1])) {
				mysql_free_result(pmyres);
				write(pfront->sockd, "TRUE PASSWORD-WRONG\r\n", 21);
			} else {
				len = strlen(myrow[4]);
				if (0 == len) {
					strcpy(temp_real, "NIL");
				} else {
					encode64(myrow[4], len, temp_real, 512, NULL);
				}
				len = strlen(myrow[5]);
				if (0 == len) {
					strcpy(temp_nick, "NIL");
				} else {
					encode64(myrow[5], len, temp_nick, 512, NULL);
				}
				len = strlen(myrow[11]);
				if (0 == len) {
					strcpy(temp_lang, "NIL");
				} else {
					encode64(myrow[11], len, temp_lang, 64, NULL);
				}
				len = strlen(myrow[12]);
				if (0 == len) {
					strcpy(temp_zone, "NIL");
				} else {
					encode64(myrow[12], len, temp_zone, 128, NULL);
				}
				len = sprintf(temp_buff, "TRUE OK %s %s %s %s %s %s %d %s "
						"%s %s %s %s %s\r\n", myrow[0], temp_real, temp_nick,
						temp_lang, temp_zone, temp_title, domain_id, myrow[6],
						myrow[7], homedir, myrow[8], myrow[9], myrow[10]);
				write(pfront->sockd, temp_buff, len);
				mysql_free_result(pmyres);
			}

		} else if (0 == strncasecmp(pfront->buff, "USER-PASSWORD ", 14)) {
			pspace = strchr(pfront->buff + 14, ' ');
			if (NULL == pspace) {
				write(pfront->sockd, "FALSE\r\n", 7);
				continue;
			}

			len = pspace - pfront->buff - 14;

			memcpy(temp_buff, pfront->buff + 14, len);
			if (0 != decode64(temp_buff, len, username, &len) ||
				0 != decode64(pspace + 1, strlen(pspace + 1), password,
				&len) || strlen(username) > 128 || strlen(password) > 32) {
				write(pfront->sockd, "FALSE\r\n", 7);
				continue;
			}

			pdomain = strchr(username, '@');
			if (NULL == pdomain) {
				write(pfront->sockd, "FALSE\r\n", 7);
				continue;
			}

			if (NULL == (pfront->pconn = get_connection())) {
				pthread_mutex_lock(&g_front_lock);
				double_list_remove(&g_front_list, &pfront->node);
				pthread_mutex_unlock(&g_front_lock);
				write(pfront->sockd, "FALSE\r\n", 7);
				close(pfront->sockd);
				free(pfront);
				goto NEXT_LOOP;
			}

			pmysql = pfront->pconn->pmysql;
			
			
			pthread_mutex_lock(&g_crypt_lock);
			strcpy(temp_pass, md5_crypt_wrapper(password));
			pthread_mutex_unlock(&g_crypt_lock);
			
			encode_squote(username, temp_user);

			snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
				"username='%s'", temp_pass, temp_user);
			if (0 != mysql_query(pmysql, sql_string)) {
				mysql_close(pmysql);
				pthread_mutex_lock(&g_back_lock);
				pfront->pconn->pmysql = NULL;
				double_list_append_as_tail(&g_lost_list,
					&pfront->pconn->node);
				pfront->pconn = NULL;
				pthread_mutex_unlock(&g_back_lock);

				pthread_mutex_lock(&g_front_lock);
				double_list_remove(&g_front_list, &pfront->node);
				pthread_mutex_unlock(&g_front_lock);
				write(pfront->sockd, "FALSE\r\n", 7);
				close(pfront->sockd);
				free(pfront);
				goto NEXT_LOOP;
			}

			snprintf(sql_string, 1024, "SELECT aliasname FROM aliases WHERE "
				"mainname='%s'", temp_user);
			if (0 != mysql_query(pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pmysql))) {
				mysql_close(pmysql);
				pthread_mutex_lock(&g_back_lock);
				pfront->pconn->pmysql = NULL;
				double_list_append_as_tail(&g_lost_list,
					&pfront->pconn->node);
				pfront->pconn = NULL;
				pthread_mutex_unlock(&g_back_lock);

				pthread_mutex_lock(&g_front_lock);
				double_list_remove(&g_front_list, &pfront->node);
				pthread_mutex_unlock(&g_front_lock);
				write(pfront->sockd, "FALSE\r\n", 7);
				close(pfront->sockd);
				free(pfront);
				goto NEXT_LOOP;
			}

			encode_squote(pdomain + 1, temp_buff);
			snprintf(sql_string, 1024, "SELECT aliasname FROM aliases WHERE "
				"mainname='%s'", temp_buff);
			if (0 != mysql_query(pmysql, sql_string) ||
				NULL == (pmyres1 = mysql_store_result(pmysql))) {
				mysql_close(pmysql);
				pthread_mutex_lock(&g_back_lock);
				pfront->pconn->pmysql = NULL;
				double_list_append_as_tail(&g_lost_list,
					&pfront->pconn->node);
				pfront->pconn = NULL;
				pthread_mutex_unlock(&g_back_lock);

				pthread_mutex_lock(&g_front_lock);
				double_list_remove(&g_front_list, &pfront->node);
				pthread_mutex_unlock(&g_front_lock);
				write(pfront->sockd, "FALSE\r\n", 7);
				close(pfront->sockd);
				free(pfront);
				goto NEXT_LOOP;
			}

			rows = mysql_num_rows(pmyres);
			rows1 = mysql_num_rows(pmyres1);

			for (j=0; j<rows1; j++) {
				myrow1 = mysql_fetch_row(pmyres1);
				strcpy(virtual_address, username);
				pat = strchr(virtual_address, '@') + 1;
				strcpy(pat, myrow1[0]);
				encode_squote(virtual_address, temp_user);
				snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
					"username='%s'", temp_pass, temp_user);
				mysql_query(pmysql, sql_string);
			}

			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				encode_squote(myrow[0], temp_user);
				snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
					"username='%s'", temp_pass, temp_user);
				mysql_query(pmysql, sql_string);

				mysql_data_seek(pmyres1, 0);
				for (j=0; j<rows1; j++) {
					myrow1 = mysql_fetch_row(pmyres1);
					strcpy(virtual_address, myrow[0]);
					pat = strchr(virtual_address, '@') + 1;
					strcpy(pat, myrow1[0]);
					encode_squote(virtual_address, temp_user);
					snprintf(sql_string, 1024, "UPDATE users SET password='%s' "
						"WHERE username='%s'", temp_pass, temp_user);
					mysql_query(pmysql, sql_string);
				}
			}
			
			pthread_mutex_lock(&g_back_lock);
			double_list_append_as_tail(&g_back_list, &pfront->pconn->node);
			pfront->pconn = NULL;
			pthread_mutex_unlock(&g_back_lock);
		
			mysql_free_result(pmyres1);
			mysql_free_result(pmyres);
			write(pfront->sockd, "TRUE\r\n", 6);
		} else {
			write(pfront->sockd, "FALSE\r\n", 7);
		}
    }
	return NULL;
}

static MYSQL_CONN* get_connection()
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
		if (i == SOCKET_TIMEOUT) {
			return NULL;
		}
	}

	return (MYSQL_CONN*)pnode->pdata;
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

static void term_handler(int signo)
{
    g_notify_stop = 1;
}

