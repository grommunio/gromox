#include "cdner_agent.h"
#include "mysql_adaptor.h"
#include "uncheck_domains.h"
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
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_ROOM */
#define ADDRESS_TYPE_ROOM				4
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_EQUIPMENT */
#define ADDRESS_TYPE_EQUIPMENT			5

#define SUB_TYPE_USER					0
#define SUB_TYPE_ROOM					1
#define SUB_TYPE_EQUIPMENT				2

#define MLIST_TYPE_NORMAL				0
#define MLIST_TYPE_GROUP				1
#define MLIST_TYPE_DOMAIN				2
#define MLIST_TYPE_CLASS				3

#define MLIST_PRIVILEGE_ALL				0
#define MLIST_PRIVILEGE_INTERNAL		1
#define MLIST_PRIVILEGE_DOMAIN			2
#define MLIST_PRIVILEGE_SPECIFIED		3
#define MLIST_PRIVILEGE_OUTGOING		4

#define MLIST_RESULT_OK					0
#define MLIST_RESULT_NONE				1
#define MLIST_RESULT_PRIVIL_DOMAIN		2
#define MLIST_RESULT_PRIVIL_INTERNAL	3
#define MLIST_RESULT_PRIVIL_SPECIFIED	4

#define USER_PRIVILEGE_SMTP				0x2



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

static BOOL mysql_adaptor_expand_hierarchy(
	MYSQL *pmysql, MEM_FILE *pfile, int class_id);

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
	strcpy(g_user, user);
	if (NULL == password || '\0' == password[0]) {
		g_password = NULL;
	} else {
		strcpy(g_password_buff, password);
		g_password = g_password_buff;
	}
	strcpy(g_db_name, db_name);
	g_timeout = timeout;
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

BOOL mysql_adaptor_login(const char *username,
	const char *password, char *reason, int length)
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
	
	
	if (TRUE == cdner_agent_check_user(username) &&
		TRUE == cdner_agent_login(username, password)) {
		return TRUE;
	}
	
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		snprintf(reason, length, "these's no database connection"
				" alive, please contact system administrator!");
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT password, address_type,"
			" address_status, privilege_bits FROM users WHERE "
			"username='%s'", temp_name);
	
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
			mysql_options(pconnection->pmysql,
				MYSQL_OPT_READ_TIMEOUT, &g_timeout);
			mysql_options(pconnection->pmysql,
				MYSQL_OPT_WRITE_TIMEOUT, &g_timeout);
		}
		if (NULL == mysql_real_connect(pconnection->pmysql, g_host,
			g_user, g_password, g_db_name, g_port, NULL, 0) ||
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
		snprintf(reason, length, "user \"%s\" not exists, "
			"please check if it is right composed", username);
		return FALSE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	temp_type = atoi(myrow[1]);
	if (ADDRESS_TYPE_NORMAL != temp_type && ADDRESS_TYPE_ALIAS != temp_type) {
		snprintf(reason, length, "\"%s\" is not a real or alias user, "
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

	if (0 == (atoi(myrow[3])&USER_PRIVILEGE_SMTP)) {
		mysql_free_result(pmyres);
		strncpy(reason, "you are not authorized to send email through SMTP "
			"server", length);
		return FALSE;
	}

	strncpy(encrypt_passwd, myrow[0], sizeof(encrypt_passwd));
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
			snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
				" WHERE username='%s'", encrypt_passwd, temp_name);
			mysql_query(pmysql, sql_string);
		}

		for (j=0; j<rows; j++) {
			myrow = mysql_fetch_row(pmyres);
			mysql_adaptor_encode_squote(myrow[0], temp_name);
			snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
				" WHERE username='%s'", encrypt_passwd, temp_name);
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
			cdner_agent_create_user(username);
			return TRUE;
		} else {
			pthread_mutex_unlock(&g_crypt_lock);
			snprintf(reason, length, "password "
				"error, please check it and retry");
			return FALSE;
		}
	}
}

void mysql_adaptor_disable_smtp(const char *username)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return;
	}
	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
RETRYING:
	if (i > 3) {
		return;
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
	
	snprintf(sql_string, 1024, "UPDATE users SET"
		" privilege_bits=privilege_bits&%u WHERE"
		" username='%s'", ~USER_PRIVILEGE_SMTP, temp_name);
	
	if (0 != mysql_query(pconnection->pmysql, sql_string)) {
		/* try to reconnect mysql database */
		mysql_close(pconnection->pmysql);
		pconnection->pmysql = mysql_init(NULL);
		if (NULL == pconnection->pmysql) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(
				&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			i ++;
			sleep(1);
			goto RETRYING;
		}

		if (g_timeout > 0) {
			mysql_options(pconnection->pmysql,
				MYSQL_OPT_READ_TIMEOUT, &g_timeout);
			mysql_options(pconnection->pmysql,
				MYSQL_OPT_WRITE_TIMEOUT, &g_timeout);
		}

		if (NULL == mysql_real_connect(pconnection->pmysql, g_host,
			g_user, g_password, g_db_name, g_port, NULL, 0) ||
			0 != mysql_query(pconnection->pmysql, sql_string)) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(
				&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			i ++;
			sleep(1);
			goto RETRYING;
		}
	}
	pthread_mutex_lock(&g_list_lock);
	double_list_append_as_tail(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_list_lock);
	return;
}

BOOL mysql_adaptor_check_user(const char *username, char *path)
{
	int i;
	char *pdomain;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	pdomain = strchr(username, '@');
	if (NULL != pdomain && TRUE == uncheck_domains_query(pdomain + 1)) {
		if (NULL != path) {
			path[0] = '\0';
		}
		return TRUE;
	}
	/* 
	 * if no valid connection node available, it means the
	 * database is down, return TRUE immediately!!!
	 */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		if (NULL != path) {
			path[0] = '\0';
		}
		return TRUE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		/* database may break down, so return TRUE to avoid checking problem */
		if (NULL != path) {
			path[0] = '\0';
		}
		return TRUE;
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
	
	snprintf(sql_string, 1024, "SELECT address_status, maildir FROM users "
		"WHERE username='%s'", temp_name);
	
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
		return FALSE;
	} else {
		myrow = mysql_fetch_row(pmyres);
		if (0 != atoi(myrow[0])) {
			if (NULL != path) {
				strcpy(path, myrow[1]);
			}
			mysql_free_result(pmyres);
			return FALSE;
		} else {
			if (NULL != path) {
				strcpy(path, myrow[1]);
			}
			mysql_free_result(pmyres);
			return TRUE;
		}
	}
}

BOOL mysql_adaptor_get_lang(const char *username, char *lang)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT lang FROM users "
		"WHERE username='%s'", temp_name);
	
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
		lang[0] = '\0';	
	} else {
		myrow = mysql_fetch_row(pmyres);
		strcpy(lang, myrow[0]);
	}
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_get_timezone(const char *username, char *timezone)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT timezone FROM users "
		"WHERE username='%s'", temp_name);
	
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
		timezone[0] = '\0';	
	} else {
		myrow = mysql_fetch_row(pmyres);
		strcpy(timezone, myrow[0]);
	}
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_get_user_info(const char *username,
	char *maildir, char *lang, char *timezone)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT maildir, address_status, "
		"lang, timezone FROM users WHERE username='%s'", temp_name);
	
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
		maildir[0] = '\0';	
	} else {
		myrow = mysql_fetch_row(pmyres);
		if (0 == atoi(myrow[1])) {
			strcpy(maildir, myrow[0]);
			strcpy(lang, myrow[2]);
			strcpy(timezone, myrow[3]);
		} else {
			maildir[0] = '\0';	
		}	
	}
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_get_user_ids(const char *username,
	int *puser_id, int *pdomain_id, int *paddress_type)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT id, domain_id, address_type, "
				"sub_type FROM users WHERE username='%s'", temp_name);
	
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
		return FALSE;	
	}
	myrow = mysql_fetch_row(pmyres);
	*puser_id = atoi(myrow[0]);
	*pdomain_id = atoi(myrow[1]);
	*paddress_type = atoi(myrow[2]);
	if (ADDRESS_TYPE_NORMAL == *paddress_type) {
		switch (atoi(myrow[3])) {
		case SUB_TYPE_ROOM:
			*paddress_type = ADDRESS_TYPE_ROOM;
			break;
		case SUB_TYPE_EQUIPMENT:
			*paddress_type = ADDRESS_TYPE_EQUIPMENT;
			break;
		}
	}
	mysql_free_result(pmyres);
	return TRUE;
}


BOOL mysql_adaptor_get_username(int user_id, char *username)
{
	int i;
	MYSQL *pmysql;
	MYSQL_ROW myrow;
	MYSQL_RES *pmyres;
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* 
	 * if no valid connection node available, it means the
	 * database is down, return immediately!!!
	 */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT username FROM users "
		"WHERE id=%d", user_id);
	
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
		return FALSE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	strncpy(username, myrow[0], 256);
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_get_homedir(const char *domainname, char *homedir)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	mysql_adaptor_encode_squote(domainname, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT homedir, domain_status FROM domains "
		"WHERE domainname='%s'", temp_name);
	
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
		homedir[0] = '\0';	
	} else {
		myrow = mysql_fetch_row(pmyres);
		if (0 == atoi(myrow[1])) {
			strcpy(homedir, myrow[0]);
		} else {
			homedir[0] = '\0';	
		}
	}
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_check_same_org2(
	const char *domainname1, const char *domainname2)
{
	int i;
	int org_id1;
	int org_id2;
	MYSQL *pmysql;
	MYSQL_ROW myrow;
	MYSQL_RES *pmyres;
	char temp_name1[512];
	char temp_name2[512];
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* 
	 * if no valid connection node available, it means the
	 * database is down, return immediately!!!
	 */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}
	
	mysql_adaptor_encode_squote(domainname1, temp_name1);
	mysql_adaptor_encode_squote(domainname2, temp_name2);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT org_id FROM domains "
				"WHERE domainname='%s' OR domainname='%s'",
				temp_name1, temp_name2);
	
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

	if (2 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		return FALSE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	org_id1 = atoi(myrow[0]);
	myrow = mysql_fetch_row(pmyres);
	org_id2 = atoi(myrow[0]);
	mysql_free_result(pmyres);
	if (0 == org_id1 || 0 == org_id2 || org_id1 != org_id2) {
		return FALSE;
	}
	return TRUE;
}

BOOL mysql_adaptor_get_groupname(const char *username, char *groupname)
{
	int i, group_id;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}
	
	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT group_id, address_status FROM users "
		"WHERE username='%s'", temp_name);
	
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
		
	if (1 != mysql_num_rows(pmyres)) {
		groupname[0] = '\0';
		mysql_free_result(pmyres);
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (0 != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		groupname[0] = '\0';
		return TRUE;
	}
	group_id = atoi(myrow[0]);
	mysql_free_result(pmyres);
	
	if (0 == group_id) {
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		groupname[0] = '\0';
		return TRUE;
	}

	snprintf(sql_string, 1024, "SELECT groupname FROM groups WHERE id=%d",
		group_id);
	
	if (0 != mysql_query(pconnection->pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
		mysql_close(pconnection->pmysql);
		pconnection->pmysql = NULL;
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_invalid_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		return FALSE;
	}
	
	pthread_mutex_lock(&g_list_lock);
	double_list_append_as_tail(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_list_lock);

	if (1 != mysql_num_rows(pmyres)) {
		groupname[0] = '\0';
	} else {
		myrow = mysql_fetch_row(pmyres);
		strcpy(groupname, myrow[0]);
	}
	mysql_free_result(pmyres);	
	return TRUE;
}

BOOL mysql_adaptor_get_forward(const char *username, int *ptype,
	char *destination)
{
	int i;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		return FALSE;
	}

	mysql_adaptor_encode_squote(username, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
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
	
	snprintf(sql_string, 1024, "SELECT destination, forward_type FROM "
		"forwards WHERE username='%s'", temp_name);
	
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
		destination[0] = '\0';
	} else {
		myrow = mysql_fetch_row(pmyres);
		strcpy(destination, myrow[0]);
		*ptype = atoi(myrow[1]);
	}
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_get_mlist(const char *username,
	const char *from, int *presult, MEM_FILE *pfile)
{
	int i, id, rows;
	int type, privilege;
	int group_id;
	int domain_id;
	int class_id;
	BOOL b_chkintl, b_same;
	char *pdomain, *pfrom_domain;
	char *pencode_domain;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MEM_FILE file_temp;
	MEM_FILE file_temp1;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		*presult = MLIST_RESULT_NONE;
		return TRUE;
	}

	pdomain ++;

	pfrom_domain = strchr(from, '@');
	if (NULL == pfrom_domain) {
		*presult = MLIST_RESULT_NONE;
		return TRUE;
	}

	pfrom_domain ++;

	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		*presult = MLIST_RESULT_NONE;
		return FALSE;
	}
	
	mysql_adaptor_encode_squote(username, temp_name);
	pencode_domain = strchr(temp_name, '@') + 1;
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		*presult = MLIST_RESULT_NONE;
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
	
	snprintf(sql_string, 1024, "SELECT id, list_type, list_privilege"
		" FROM mlists WHERE listname='%s'", temp_name);
	
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
	
	
	
	if (1 != mysql_num_rows(pmyres)) {
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		mysql_free_result(pmyres);
		*presult = MLIST_RESULT_NONE;
		return TRUE;	
	}
	myrow = mysql_fetch_row(pmyres);
	
	id = atoi(myrow[0]);
	type = atoi(myrow[1]);
	privilege = atoi(myrow[2]);

	mysql_free_result(pmyres);

	b_chkintl = FALSE;
	
	switch (type) {
	case MLIST_TYPE_NORMAL:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (0 != mysql_query(pconnection->pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_NONE;
				return FALSE;
			}

			rows = mysql_num_rows(pmyres);
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			mysql_free_result(pmyres);

			if (i == rows) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		default:
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list,
				&pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		snprintf(sql_string, 1024, "SELECT username "
			"FROM associations WHERE list_id=%d", id);
		if (0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}

		rows = mysql_num_rows(pmyres);

		if (TRUE == b_chkintl) {
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (0 == strcasecmp(myrow[0], from)) {
					b_chkintl = FALSE;
					break;
				}
			}
		}

		if (TRUE == b_chkintl) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			mysql_free_result(pmyres);
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		
		mysql_data_seek(pmyres, 0);
		
		for (i=0; i<rows; i++) {
			myrow = mysql_fetch_row(pmyres);
			mem_file_writeline(pfile, myrow[0]);
		}
		mysql_free_result(pmyres);
		
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		*presult = MLIST_RESULT_OK;
		return TRUE;
	case MLIST_TYPE_GROUP:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (0 != mysql_query(pconnection->pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_NONE;
				return FALSE;
			}

			rows = mysql_num_rows(pmyres);
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			mysql_free_result(pmyres);

			if (i == rows) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		default:
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		snprintf(sql_string, 1024, "SELECT id FROM "
			"groups WHERE groupname='%s'", temp_name);
		if (0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}
		if (1 != mysql_num_rows(pmyres)) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list,
				&pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			mysql_free_result(pmyres);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		myrow = mysql_fetch_row(pmyres);
		group_id = atoi(myrow[0]);
		mysql_free_result(pmyres);
		
		snprintf(sql_string, 1024, "SELECT username, address_type,"
				" sub_type FROM users WHERE group_id=%d", group_id);

		if (0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}
		
		rows = mysql_num_rows(pmyres);
		
		if (TRUE == b_chkintl) {
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
					&& SUB_TYPE_USER == atoi(myrow[2]) &&
					0 == strcasecmp(myrow[0], from)) {
					b_chkintl = FALSE;
					break;
				}
			}
		}

		if (TRUE == b_chkintl) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			mysql_free_result(pmyres);
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		
		mysql_data_seek(pmyres, 0);
		
		for (i=0; i<rows; i++) {
			myrow = mysql_fetch_row(pmyres);
			if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
				&& SUB_TYPE_USER == atoi(myrow[2])) {
				mem_file_writeline(pfile, myrow[0]);
			}
		}
		mysql_free_result(pmyres);

		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		*presult = MLIST_RESULT_OK;
		return TRUE;
	case MLIST_TYPE_DOMAIN:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (0 != mysql_query(pconnection->pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_NONE;
				return FALSE;
			}

			rows = mysql_num_rows(pmyres);
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			mysql_free_result(pmyres);

			if (i == rows) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		default:
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		snprintf(sql_string, 1024, "SELECT id FROM domains"
				" WHERE domainname='%s'", pencode_domain);
		if (0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}
		if (1 != mysql_num_rows(pmyres)) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			mysql_free_result(pmyres);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		myrow = mysql_fetch_row(pmyres);
		domain_id = atoi(myrow[0]);
		mysql_free_result(pmyres);
		
		snprintf(sql_string, 1024, "SELECT username, address_type,"
			" sub_type FROM users WHERE domain_id=%d", domain_id);

		if (0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}
		
		rows = mysql_num_rows(pmyres);

		if (TRUE == b_chkintl) {
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
					&& SUB_TYPE_USER == atoi(myrow[2]) &&
					0 == strcasecmp(myrow[0], from)) {
					b_chkintl = FALSE;
					break;
				}
			}
		}

		if (TRUE == b_chkintl) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			mysql_free_result(pmyres);
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		
		mysql_data_seek(pmyres, 0);
		
		for (i=0; i<rows; i++) {
			myrow = mysql_fetch_row(pmyres);
			if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
				&& SUB_TYPE_USER == atoi(myrow[2])) {
				mem_file_writeline(pfile, myrow[0]);
			}
		}
		mysql_free_result(pmyres);

		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		*presult = MLIST_RESULT_OK;
		return TRUE;
	case MLIST_TYPE_CLASS:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (0 != mysql_query(pconnection->pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_NONE;
				return FALSE;
			}

			rows = mysql_num_rows(pmyres);
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			mysql_free_result(pmyres);

			if (i == rows) {
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_connection_list,
					&pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;		
			}
			b_chkintl = FALSE;
			break;
		default:
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		snprintf(sql_string, 1024, "SELECT id FROM "
			"classes WHERE listname='%s'", temp_name);
		if (0 != mysql_query(pconnection->pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}
		if (1 != mysql_num_rows(pmyres)) {
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_connection_list,
				&pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			mysql_free_result(pmyres);
			*presult = MLIST_RESULT_NONE;
			return TRUE;		
		}
		myrow = mysql_fetch_row(pmyres);
		class_id = atoi(myrow[0]);
		mysql_free_result(pmyres);
		
		mem_file_init(&file_temp, pfile->allocator);
		mem_file_write(&file_temp, (char*)&class_id, sizeof(int));	
		if (FALSE == mysql_adaptor_expand_hierarchy(
			pconnection->pmysql, &file_temp, class_id)) {
			mem_file_free(&file_temp);
			mysql_close(pconnection->pmysql);
			pconnection->pmysql = NULL;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_invalid_list, &pconnection->node);
			pthread_mutex_unlock(&g_list_lock);
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}
		
		mem_file_init(&file_temp1, pfile->allocator);
		mem_file_seek(&file_temp, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(&file_temp,
			&class_id, sizeof(int))) {
			snprintf(sql_string, 1024, "SELECT username "
				"FROM members WHERE class_id=%d", class_id);
			if (0 != mysql_query(pconnection->pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
				mem_file_free(&file_temp);
				mem_file_free(&file_temp1);
				mysql_close(pconnection->pmysql);
				pconnection->pmysql = NULL;
				pthread_mutex_lock(&g_list_lock);
				double_list_append_as_tail(&g_invalid_list, &pconnection->node);
				pthread_mutex_unlock(&g_list_lock);
				*presult = MLIST_RESULT_NONE;
				return FALSE;
			}
			
			rows = mysql_num_rows(pmyres);
		
			for (i=0; i<rows; i++) {
				myrow = mysql_fetch_row(pmyres);
				mem_file_seek(&file_temp1, MEM_FILE_READ_PTR, 0,
					MEM_FILE_SEEK_BEGIN);
				b_same = FALSE;
				while (MEM_END_OF_FILE != mem_file_readline(&file_temp1,
					temp_name, 256)) {
					if (0 == strcasecmp(myrow[0], temp_name)) {
						b_same = TRUE;
						break;
					}
				}
				if (FALSE == b_same) {
					mem_file_writeline(&file_temp1, myrow[0]);
				}
			}
			
			mysql_free_result(pmyres);
		}
		mem_file_free(&file_temp);
		if (TRUE == b_chkintl) {
			while (MEM_END_OF_FILE != mem_file_readline(&file_temp1,
				temp_name, 256)) {
				if (0 == strcasecmp(temp_name, from)) {
					b_chkintl = FALSE;
				}
			}
		}
		
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);

		if (TRUE == b_chkintl) {
			mem_file_free(&file_temp1);
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
			
		}
		mem_file_seek(&file_temp1, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_readline(&file_temp1,
			temp_name, 256)) {
			mem_file_writeline(pfile, temp_name);
		}
		mem_file_free(&file_temp1);
		*presult = MLIST_RESULT_OK;
		return TRUE;
	default:
		pthread_mutex_lock(&g_list_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_list_lock);
		*presult = MLIST_RESULT_NONE;
		return TRUE;
	}
	
}

static BOOL mysql_adaptor_expand_hierarchy(
	MYSQL *pmysql, MEM_FILE *pfile, int class_id)
{
	int i, rows;
	int temp_id;
	int child_id;
	BOOL b_include;
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	
	snprintf(sql_string, 1024, "SELECT child_id FROM"
		" hierarchy WHERE class_id=%d", class_id);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		return FALSE;
	}
	rows = mysql_num_rows(pmyres);

	for (i=0; i<rows; i++) {
		myrow = mysql_fetch_row(pmyres);
		child_id = atoi(myrow[0]);
		b_include = FALSE;
		mem_file_seek(pfile, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_read(pfile, &temp_id, sizeof(int))) {
			if (temp_id == child_id) {
				b_include = TRUE;
				break;
			}
		}
		if (FALSE == b_include) {
			mem_file_write(pfile, (char*)&child_id, sizeof(int));
			if (FALSE == mysql_adaptor_expand_hierarchy(
				pmysql, pfile, child_id)) {
				mysql_free_result(pmyres);
				return FALSE;
			}
		}
	}
	mysql_free_result(pmyres);
	return TRUE;
}

BOOL mysql_adaptor_check_virtual(const char *username, const char *from,
	BOOL *pb_expanded, MEM_FILE *pfile)
{
	int i;
	int result;
	BOOL b_ret;
	int privilege;
	char temp_name[512];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	DOUBLE_LIST_NODE *pnode;
	CONNECTION_NODE *pconnection;
	
	
	/* if no valid connection node available, return immediately */
	if (g_conn_num == double_list_get_nodes_num(&g_invalid_list)) {
		*pb_expanded = FALSE;
		return FALSE;
	}
	
	mysql_adaptor_encode_squote(from, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		*pb_expanded = FALSE;
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
	
	snprintf(sql_string, 1024, "SELECT list_privilege FROM "
		"mlists WHERE listname='%s'", temp_name);
	
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
		*pb_expanded = FALSE;
		return TRUE;	
	}
	myrow = mysql_fetch_row(pmyres);
	privilege = atoi(myrow[0]);
	mysql_free_result(pmyres);
	
	if (MLIST_PRIVILEGE_OUTGOING != privilege) {
		*pb_expanded = FALSE;
		return TRUE;
	}
	
	b_ret = mysql_adaptor_get_mlist(from, username, &result, pfile);
	
	if (MLIST_RESULT_OK == result) {
		*pb_expanded = TRUE;
	} else {
		*pb_expanded = FALSE;
	}
	return b_ret;
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

