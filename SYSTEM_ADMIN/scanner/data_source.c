#include <unistd.h>
#include <mysql/mysql.h>
#include "data_source.h"
#include <gromox/system_log.h>
#include <string.h>

static char g_host[256];
static int g_port;
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name)
{
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
}

BOOL data_source_get_datadir(char *path_buff)
{
	int i;
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
		
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	strcpy(sql_string, "SHOW variables LIKE 'datadir'");
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	if (1 != mysql_num_rows(pmyres)) {
		 mysql_free_result(pmyres);
		 mysql_close(pmysql);
		 return FALSE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	strcpy(path_buff, myrow[1]);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;

}

void* data_source_lock_flush()
{
	int i;
	char sql_string[1024];
	MYSQL *pmysql;
		
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		return NULL;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	strcpy(sql_string, "FLUSH TABLES WITH READ LOCK");
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to lock and flush mysql tables, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	return pmysql;
}

void data_source_unlock(void *pmysql)
{
	mysql_query(pmysql, "UNLOCK TABLES");
	mysql_close((MYSQL*)pmysql);
}

