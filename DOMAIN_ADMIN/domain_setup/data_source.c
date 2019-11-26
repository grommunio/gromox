#include <unistd.h>
#include "data_source.h"
#include "system_log.h"
#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_host[256];
static int g_port;
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];

static void data_source_encode_squote(const char *in, char *out);

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

int data_source_run()
{

	/* do nothing */
	return 0;
}

int data_source_stop()
{
	/* do nothing */
	return 0;
}

void data_source_free()
{
	/* do nothing */
}

BOOL data_source_get_homedir(const char *domainname, char *path_buff)
{
	int i;
	char temp_name[128];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	path_buff[0] = '\0';
	
	data_source_encode_squote(domainname, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		system_log_info("[data_source]: fail to connect to mysql server, "
			"reason: %s", mysql_error(pmysql));
		i ++;
		sleep(1);
		goto RETRYING;
	}

	data_source_encode_squote(domainname, temp_name);
	
	sprintf(sql_string, "SELECT homedir FROM domains "
		"WHERE domainname='%s'", temp_name);
	
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
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);

	strcpy(path_buff, myrow[0]);

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	return TRUE;
}

BOOL data_source_get_password(const char *domainname, char *password_buff,
	BOOL *presult)
{
	int i;
	char temp_name[128];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	*presult = FALSE;
	password_buff[0] = '\0';
	
	data_source_encode_squote(domainname, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		system_log_info("[data_source]: fail to connect to mysql server, "
			"reason: %s", mysql_error(pmysql));
		i ++;
		sleep(1);
		goto RETRYING;
	}

	sprintf(sql_string, "SELECT password FROM domains "
		"WHERE domainname='%s'", temp_name);
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (1 == mysql_num_rows(pmyres)) {
		myrow = mysql_fetch_row(pmyres);
		strcpy(password_buff, myrow[0]);
		*presult = TRUE;
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_set_password(const char *domainname, const char *password)
{
	int i, j, rows;
	char temp_name[128];
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
		system_log_info("[data_source]: fail to connect to mysql server, "
			"reason: %s", mysql_error(pmysql));
		i ++;
		sleep(1);
		goto RETRYING;
	}

	data_source_encode_squote(domainname, temp_name);
	sprintf(sql_string, "SELECT aliasname FROM aliases WHERE mainname='%s'",
		temp_name);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	rows = mysql_num_rows(pmyres);

	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		data_source_encode_squote(myrow[0], temp_name);
		sprintf(sql_string, "UPDATE domains SET password='%s' "
			"WHERE domainname='%s'", password, temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}

	}
	
	mysql_free_result(pmyres);
	

	data_source_encode_squote(domainname, temp_name);
	sprintf(sql_string, "UPDATE domains SET password='%s' "
		"WHERE domainname='%s'", password, temp_name);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	return TRUE;
}

BOOL data_source_info_domain(const char *domainname, int *pprivilege_bits)
{
	int i;
	char temp_name[128];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;

	*pprivilege_bits = 0;

	data_source_encode_squote(domainname, temp_name);
	
	i = 0;

RETRYING:
	if (i > 3) {
		return FALSE;
	}


	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		system_log_info("[data_source]: fail to connect to mysql server, "
			"reason: %s", mysql_error(pmysql));
		i ++;
		sleep(1);
		goto RETRYING;
	}

	sprintf(sql_string, "SELECT privilege_bits FROM domains "
		"WHERE domainname='%s'", temp_name);

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
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);

	*pprivilege_bits = atoi(myrow[0]);

	mysql_free_result(pmyres);
	mysql_close(pmysql);

	return TRUE;
}

static void data_source_encode_squote(const char *in, char *out)
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

