#include <unistd.h>
#include "data_source.h"
#include <gromox/system_log.h>
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

BOOL data_source_domain_info(const char *domainname, time_t *pcreate_day,
	time_t *pend_day, int *pmax_size, int *pactual_size, int *pmax_user,
	int *pactual_user, int *palias_num, int *pgroup_num, int *pmlist_num,
	int *pprivilege_bits)
{
	int i, j, rows;
	int domain_id;
	char temp_name[128];
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm temp_tm;
	
	data_source_encode_squote(domainname, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	*pcreate_day = 0;
	*pend_day = 0;
	*pmax_size = 0;
	*pactual_size = 0;
	*pmax_user = 0;
	*pactual_user = 0;
	*palias_num = 0;
	*pgroup_num = 0;
	*pmlist_num = 0;
	*pprivilege_bits = 0;
	
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		system_log_info("[data_source]: fail to connect to mysql server, "
			"reason: %s", mysql_error(pmysql));
		i ++;
		sleep(1);
		goto RETRYING;
	}

	sprintf(sql_string, "SELECT id, max_size, max_user, create_day, end_day, "
		"privilege_bits FROM domains WHERE domainname='%s'", temp_name);
	
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

	domain_id = atoi(myrow[0]);
	
	*pmax_size = atoi(myrow[1]);
	*pmax_user = atoi(myrow[2]);
	memset(&temp_tm, 0, sizeof(temp_tm));
	strptime(myrow[3], "%Y-%m-%d", &temp_tm);
	*pcreate_day = mktime(&temp_tm);
	strptime(myrow[4], "%Y-%m-%d", &temp_tm);
	*pend_day = mktime(&temp_tm);
	*pprivilege_bits = atoi(myrow[5]);

	mysql_free_result(pmyres);
	
	sprintf(sql_string, "SELECT address_type, max_size FROM users WHERE "
		"domain_id=%d", domain_id);
	
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
		switch (atoi(myrow[0])) {
		case ADDRESS_TYPE_NORMAL:
			*pactual_user += 1;
			*pactual_size += atoi(myrow[1]);
			break;
		case ADDRESS_TYPE_ALIAS:
			*palias_num += 1;
			break;
		case ADDRESS_TYPE_MLIST:
			*pmlist_num += 1;
			break;
		}
	}
	
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT count(*) FROM groups WHERE domain_id=%d",
		domain_id);
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
		*pgroup_num = atoi(myrow[0]);
	}
	
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

