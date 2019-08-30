#include "mysql_adaptor.h"
#include "double_list.h"
#include "util.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <mysql/mysql.h>

#define ADDRESS_TYPE_NORMAL				0
#define ADDRESS_TYPE_ALIAS				1
#define ADDRESS_TYPE_MLIST				2
#define ADDRESS_TYPE_VIRTUAL			3

#define USER_PRIVILEGE_POP3_IMAP		0x1


typedef struct _CONNECTION_NODE {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	MYSQL *pmysql;
} CONNECTION_NODE;

static int g_conn_num;
static int g_scan_interval;
static int g_port;
static int g_timeout;
static char g_host[256];
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];
static pthread_mutex_t g_list_lock;
static pthread_mutex_t g_crypt_lock;
static DOUBLE_LIST g_connection_list;
static DOUBLE_LIST g_invalid_list;
static pthread_t g_thread_id;
static BOOL g_notify_stop = TRUE;

static void *thread_work_func(void *param);

static void mysql_adaptor_encode_squote(const char *in, char *out);

void mysql_adaptor_init(int conn_num, int scan_interval, const char *host,
	int port, const char *user, const char *password, const char *db_name,
	int timeout)
{
	g_notify_stop = TRUE;
	g_conn_num = conn_num;
	g_scan_interval = scan_interval;
	strcpy(g_host, host);
	g_port = port;
	g_timeout = timeout;
	strcpy(g_user, user);
	if (NULL == password || '\0' == password[0]) {
		g_password = NULL;
	} else {
		strcpy(g_password_buff, password);
		g_password = g_password_buff;
	}
	strcpy(g_db_name, db_name);
	double_list_init(&g_connection_list);
	double_list_init(&g_invalid_list);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_crypt_lock, NULL);
}

int mysql_adaptor_run()
{
	int i;
	CONNECTION_NODE *pconnection;

	
	for (i=0; i<g_conn_num; i++) {
		pconnection = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
		if (NULL == pconnection) {
			continue;
		}
		pconnection->node.pdata = pconnection;
		pconnection->node_temp.pdata = pconnection;
		pconnection->pmysql = mysql_init(NULL);
		if (NULL != pconnection->pmysql) {
			if (g_timeout > 0) {
				mysql_options(pconnection->pmysql, MYSQL_OPT_READ_TIMEOUT,
					&g_timeout);
				mysql_options(pconnection->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
					&g_timeout);
			}
			if (NULL != mysql_real_connect(pconnection->pmysql, g_host, g_user,
				g_password, g_db_name, g_port, NULL, 0)) {
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
			} else {
				printf("[mysql_adaptor]: fail to connect to mysql server, "
					"reason: %s\n", mysql_error(pconnection->pmysql));
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			}
		} else {
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
		}
	}

	if (0 == double_list_get_nodes_num(&g_connection_list) &&
		0 == double_list_get_nodes_num(&g_invalid_list)) {
		printf("[mysql_adaptor]: fail to init connection list\n");
		return -1;
	}
	
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_thread_id, NULL, thread_work_func, NULL)) {
		g_notify_stop = TRUE;
		printf("[mysql_adaptor]: fail to create scanning thread\n");
		return -2;
	}

	return 0;

}

int mysql_adaptor_stop()
{
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;

	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_thread_id, NULL);
	}
	
	while (pnode=double_list_get_from_head(&g_connection_list)) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		if (NULL != pconnection->pmysql) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
		}
		free(pconnection);
	}
	
	while (pnode=double_list_get_from_head(&g_invalid_list)) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		free(pconnection);
	}
	
	return 0;
}

void mysql_adaptor_free()
{
	double_list_free(&g_connection_list);
	double_list_free(&g_invalid_list);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_crypt_lock);
}

BOOL mysql_adaptor_login(const char *username, const char *password,
	char *maildir, char *lang, char *reason, int length)
{
	int i, j, k;
	int temp_type;
	int temp_status;
	int rows, rows1;
	char *pdomain, *pat;
	char temp_name[512];
	char sql_string[1024];
	char encrypt_passwd[40];
	char virtual_address[256];
	MYSQL *pmysql;
	MYSQL_ROW myrow, myrow1;
	DOUBLE_LIST_NODE *pnode;
	MYSQL_RES *pmyres, *pmyres1;
	CONNECTION_NODE *pconnection;
	
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		snprintf(reason, length, "these's no database connection"
				" alive, please contact system administrator!");
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		snprintf(reason, length, "system too busy, "
			"no free database connection available");
		return FALSE;
	}
	pthread_mutex_lock(&g_list_lock);
	pnode = double_list_get_from_head(&g_connection_list);
	pthread_mutex_unlock(&g_list_lock);
	
	if (NULL == pnode) {
		i ++;
		sleep(1);
		goto RETRYING;
	}

	pconnection = (CONNECTION_NODE*)pnode->pdata;
	
	snprintf(sql_string, 1024, "SELECT password, address_type, address_status, "
		"privilege_bits, maildir, lang FROM users WHERE username='%s'", temp_name);
	
	if (0 != mysql_query(pconnection->pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
		/* try to reconnect mysql database */
		mysql_close(pconnection->pmysql);
		pconnection->pmysql = mysql_init(NULL);
		if (NULL == pconnection->pmysql) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			i ++;
			sleep(1);
			goto RETRYING;
		}

		if (g_timeout > 0) {
			mysql_options(pconnection->pmysql, MYSQL_OPT_READ_TIMEOUT,
				&g_timeout);
			mysql_options(pconnection->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
				&g_timeout);
		}

		if (NULL == mysql_real_connect(pconnection->pmysql, g_host, g_user,
			g_password, g_db_name, g_port, NULL, 0) ||
			0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			i ++;
			sleep(1);
			goto RETRYING;
		}
	}
	
	
	pthread_mutex_lock(&g_list_lock);
	double_list_append_as_tail(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_list_lock);

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		snprintf(reason, length, "user \"%s\" not exists, please check if "
			"it is right composed", username);
		return FALSE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	temp_type = atoi(myrow[1]);
	if (ADDRESS_TYPE_NORMAL != temp_type && ADDRESS_TYPE_ALIAS != temp_type) {
		snprintf(reason, length, "\"%s\" is not a real user or alias user, "
			"please correct the account name and try again", username);
		mysql_free_result(pmyres);
		return FALSE;
	}
	temp_status = atoi(myrow[2]);
	if (0 != temp_status) {
		if (0 != (temp_status&0x30)) {
			snprintf(reason, length, "domain of user \"%s\" is disabled!",
				username);
		} else if (0 != (temp_status&0xC)) {
			snprintf(reason, length, "group of user \"%s\" is disabled!",
				username);
		} else {
			snprintf(reason, length, "user \"%s\" is disabled!", username);
		}
		mysql_free_result(pmyres);
		return FALSE;
	}
	
	if (0 == (atoi(myrow[3])&USER_PRIVILEGE_POP3_IMAP)) {
		mysql_free_result(pmyres);
		strncpy(reason, "you are not authorized to download email through POP3 or IMAP"
			"server", length);
		return FALSE;

	}

	strncpy(encrypt_passwd, myrow[0], sizeof(encrypt_passwd));
	strcpy(maildir, myrow[4]);
	if (NULL != lang) {
		strcpy(lang, myrow[5]);
	}
	encrypt_passwd[sizeof(encrypt_passwd) - 1] = '\0';
	mysql_free_result(pmyres);

	if ('\0' == encrypt_passwd[0]) {
		pdomain = strchr(username, '@');
		if (NULL == pdomain) {
			strncpy(reason, "domain name should be included!", length);
			return FALSE;
		}
		pdomain ++;
		
		pthread_mutex_lock(&g_crypt_lock);
		strcpy(encrypt_passwd, md5_crypt_wrapper(password));
		pthread_mutex_unlock(&g_crypt_lock);

		pmysql = mysql_init(NULL);
		if (NULL == pmysql) {
			strncpy(reason, "database error, please try later!", length);
			return FALSE;
		}

		if (g_timeout > 0) {
			mysql_options(pmysql, MYSQL_OPT_READ_TIMEOUT, &g_timeout);
			mysql_options(pmysql, MYSQL_OPT_WRITE_TIMEOUT, &g_timeout);
		}
			
		if (NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
			g_db_name, g_port, NULL, 0)) {
			mysql_close(pmysql);
			strncpy(reason, "database error, please try later!", length);
			return FALSE;
		}

		snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
			"username='%s'", encrypt_passwd, temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			mysql_close(pmysql);
			strncpy(reason, "database error, please try later!", length);
			return FALSE;
		}

		snprintf(sql_string, 1024, "SELECT aliasname FROM aliases WHERE "
			"mainname='%s'", temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			mysql_close(pmysql);
			strncpy(reason, "database error, please try later!", length);
			return FALSE;
		}

		mysql_adaptor_encode_squote(pdomain, temp_name);
		snprintf(sql_string, 1024, "SELECT aliasname FROM aliases WHERE "
			"mainname='%s'", temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			strncpy(reason, "database error, please try later!", length);
			return FALSE;
		}
		rows = mysql_num_rows(pmyres);
		rows1 = mysql_num_rows(pmyres1);

		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			strcpy(virtual_address, username);
			pat = strchr(virtual_address, '@') + 1;
			strcpy(pat, myrow1[0]);
			mysql_adaptor_encode_squote(virtual_address, temp_name);
			snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
				"username='%s'", encrypt_passwd, temp_name);
			mysql_query(pmysql, sql_string);
		}

		for (j=0; j<rows; j++) {
			myrow = mysql_fetch_row(pmyres);
			mysql_adaptor_encode_squote(myrow[0], temp_name);
			snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
				"username='%s'", encrypt_passwd, temp_name);
			mysql_query(pmysql, sql_string);

			mysql_data_seek(pmyres1, 0);
			for (k=0; k<rows1; k++) {
				myrow1 = mysql_fetch_row(pmyres1);
				strcpy(virtual_address, myrow[0]);
				pat = strchr(virtual_address, '@') + 1;
				strcpy(pat, myrow1[0]);
				mysql_adaptor_encode_squote(virtual_address, temp_name);
				snprintf(sql_string, 1024, "UPDATE users SET password='%s' "
					"WHERE username='%s'", encrypt_passwd, temp_name);
				mysql_query(pmysql, sql_string);

			}
		}

		mysql_free_result(pmyres1);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return TRUE;

	} else {
		pthread_mutex_lock(&g_crypt_lock);
		if (0 == strcmp(crypt(password, encrypt_passwd), encrypt_passwd)) {
			pthread_mutex_unlock(&g_crypt_lock);
			return TRUE;
		} else {
			pthread_mutex_unlock(&g_crypt_lock);
			snprintf(reason, length, "password error, please check it "
				"and retry");
			return FALSE;
		}
	}
}

static void* thread_work_func(void *arg)
{
	int i;
	CONNECTION_NODE *pconnection;
	DOUBLE_LIST_NODE *phead, *ptail, *pnode;
	DOUBLE_LIST temp_list;
	
	i = 0;
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		if (i < g_scan_interval) {
			sleep(1);
			i ++;
			continue;
		}
		pthread_mutex_lock(&g_list_lock);
		phead = double_list_get_head(&g_invalid_list);
		ptail = double_list_get_tail(&g_invalid_list);
		pthread_mutex_unlock(&g_list_lock);
		for (pnode=phead; NULL!=pnode; pnode=double_list_get_after(
			&g_invalid_list, pnode)) {
			pconnection = (CONNECTION_NODE*)pnode->pdata;
			pconnection->pmysql = mysql_init(NULL);
			if (NULL != pconnection->pmysql) {
				if (g_timeout > 0) {
					mysql_options(pconnection->pmysql, MYSQL_OPT_READ_TIMEOUT,
						&g_timeout);
					mysql_options(pconnection->pmysql, MYSQL_OPT_WRITE_TIMEOUT,
						&g_timeout);
				}
				if (NULL != mysql_real_connect(pconnection->pmysql, g_host,
					g_user, g_password, g_db_name, g_port, NULL, 0)) {
					double_list_append_as_tail(&temp_list,
						&pconnection->node_temp);
				} else {
					mysql_close(pconnection->pmysql);
					pconnection->pmysql = NULL;
				}
			}
			if (pnode == ptail) {
				break;
			}
		}
		pthread_mutex_lock(&g_list_lock);
		while (pnode=double_list_get_from_head(&temp_list)) {
			pconnection = (CONNECTION_NODE*)pnode->pdata;
			double_list_remove(&g_invalid_list, &pconnection->node);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
		}
		pthread_mutex_unlock(&g_list_lock);
		i = 0;
	}
	double_list_free(&temp_list);
}

int mysql_adaptor_get_param(int param)
{
	if (MYSQL_ADAPTOR_SCAN_INTERVAL == param) {
		return g_scan_interval;
	} else if (MYSQL_ADAPTOR_CONNECTION_NUMBER == param) {
		return g_conn_num;
	} else if (MYSQL_ADAPTOR_ALIVECONN_NUMBER == param) {
		return double_list_get_nodes_num(&g_connection_list);
	}
	return 0;

}

void mysql_adaptor_set_param(int param, int value)
{
	if (MYSQL_ADAPTOR_SCAN_INTERVAL == param) {
		g_scan_interval = value;
		return;
	}
}

static void mysql_adaptor_encode_squote(const char *in, char *out)
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


