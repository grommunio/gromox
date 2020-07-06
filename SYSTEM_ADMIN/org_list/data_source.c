#include "data_source.h"
#include <gromox/system_log.h>
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql/mysql.h>


static char g_host[256];
static int g_port;
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];

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

DATA_COLLECT* data_source_collect_init()
{
	DATA_COLLECT *pcollect;

	pcollect = (DATA_COLLECT*)malloc(sizeof(DATA_COLLECT));
	if (NULL == pcollect) {
		return NULL;
	}
	double_list_init(&pcollect->list);
	pcollect->pnode = NULL;
	return pcollect;
}

void data_source_collect_free(DATA_COLLECT *pcollect)
{
	ORG_ITEM *porg;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;

	if (NULL == pcollect) {
		return;
	}

	while ((pnode = double_list_get_from_head(&pcollect->list)) != NULL) {
		porg = (ORG_ITEM*)pnode->pdata;
		while ((pnode1 = double_list_get_from_head(&porg->collect.list)) != NULL)
			free(pnode1->pdata);
		double_list_free(&porg->collect.list);
		free(pnode->pdata);
	}
	double_list_free(&pcollect->list);
	free(pcollect);
}

int data_source_collect_total(DATA_COLLECT *pcollect)
{
	return double_list_get_nodes_num(&pcollect->list);
}

void data_source_collect_begin(DATA_COLLECT *pcollect)
{
	pcollect->pnode = double_list_get_head(&pcollect->list);

}

int data_source_collect_done(DATA_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return 1;
	}
	return 0;
}

int data_source_collect_forward(DATA_COLLECT *pcollect)
{
	DOUBLE_LIST_NODE *pnode;


	pnode = double_list_get_after(&pcollect->list, pcollect->pnode);
	if (NULL == pnode) {
		pcollect->pnode = NULL;
		return -1;
	}
	pcollect->pnode = pnode;
	return 1;
}

void* data_source_collect_get_value(DATA_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return NULL;
	}
	return pcollect->pnode->pdata;
}


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

BOOL data_source_query(DATA_COLLECT *pcollect)
{
	int i, j;
	int rows, rows1;
	char sql_string[128];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	ORG_ITEM *porg;
	DOMAIN_ITEM *pdomain;
	

	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		return FALSE;
	}
	
	strcpy(sql_string, "SELECT id, memo FROM orgs");
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return FALSE;
	}
	
	rows = mysql_num_rows(pmyres);
	for (i=0; i<rows; i++) {
		myrow = mysql_fetch_row(pmyres);
		porg = malloc(sizeof(ORG_ITEM));
		if (NULL == porg) {
			continue;
		}
		porg->node.pdata = porg;
		double_list_init(&porg->collect.list);
		porg->collect.pnode = NULL;
		porg->org_id = atoi(myrow[0]);
		strcpy(porg->memo, myrow[1]);
		sprintf(sql_string, "SELECT id, domainname, title "
			"FROM domains WHERE org_id=%d", porg->org_id);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			return FALSE;
		}
		rows1 = mysql_num_rows(pmyres1);
		for (j=0; j<rows1; j++) {
			myrow1 = mysql_fetch_row(pmyres1);
			pdomain = malloc(sizeof(DOMAIN_ITEM));
			if (NULL == pdomain) {
				continue;
			}
			pdomain->node.pdata = pdomain;
			pdomain->domain_id = atoi(myrow1[0]);
			strcpy(pdomain->domainname, myrow1[1]);
			strcpy(pdomain->title, myrow1[2]);
			double_list_append_as_tail(&porg->collect.list, &pdomain->node);
		}
		mysql_free_result(pmyres1);
		double_list_insert_as_head(&pcollect->list, &porg->node);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);

	return TRUE;
}

void data_source_add_domain(const char *domainname, int org_id)
{
	MYSQL *pmysql;
	MYSQL_RES *pmyres;
	char temp_domain[256];
	char sql_string[1024];
	
	data_source_encode_squote(domainname, temp_domain);
	sprintf(sql_string, "SELECT count(*) FROM orgs WHERE id=%d", org_id);
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		return;
	}
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return;
	}
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return;
	}
	mysql_free_result(pmyres);
	snprintf(sql_string, 1024, "UPDATE domains SET org_id=%d WHERE domainname='%s'",
		org_id, temp_domain);
	mysql_query(pmysql, sql_string);
	mysql_close(pmysql);
}

void data_source_remove_domain(int domain_id, int org_id)
{
	MYSQL *pmysql;
	MYSQL_ROW myrow;
	MYSQL_RES *pmyres;
	char sql_string[1024];
	
	sprintf(sql_string, "SELECT org_id FROM domains WHERE id=%d", domain_id);
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		return;
	}
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return;
	}
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return;
	}
	myrow = mysql_fetch_row(pmyres);
	if (atoi(myrow[0]) != org_id) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return;
	}
	mysql_free_result(pmyres);
	snprintf(sql_string, 1024, "UPDATE domains SET org_id=0 WHERE id=%d", domain_id);
	mysql_query(pmysql, sql_string);
	mysql_close(pmysql);
}

void data_source_add_org(const char *memo)
{
	MYSQL *pmysql;
	MYSQL_ROW myrow;
	MYSQL_RES *pmyres;
	char temp_memo[256];
	char sql_string[1024];
	
	data_source_encode_squote(memo, temp_memo);
	sprintf(sql_string, "SELECT count(*) FROM orgs WHERE memo='%s'", temp_memo);
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		return;
	}
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return;
	}
	myrow = mysql_fetch_row(pmyres);
	if (atoi(myrow[0]) > 0) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return;
	}
	mysql_free_result(pmyres);
	snprintf(sql_string, 1024, "INSERT INTO orgs (memo) VALUES ('%s')", temp_memo);
	mysql_query(pmysql, sql_string);
	mysql_close(pmysql);
}

void data_source_remove_org(int org_id)
{
	MYSQL *pmysql;
	char sql_string[1024];
	
	sprintf(sql_string, "UPDATE domains SET org_id=0 WHERE org_id='%d'", org_id);
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		return;
	}
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return;
	}
	snprintf(sql_string, 1024, "DELETE FROM orgs WHERE id=%d", org_id);
	mysql_query(pmysql, sql_string);
	mysql_close(pmysql);
}


