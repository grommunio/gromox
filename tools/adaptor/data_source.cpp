// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "data_source.h"
#include <gromox/system_log.h>
#include <gromox/util.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mysql.h>
#define DOMAIN_PRIVILEGE_SUBSYSTEM          0x8

#define DOMAIN_PRIVILEGE_NETDISK            0x10

#define DOMAIN_PRIVILEGE_EXTPASSWD          0x20
#define GROUP_PRIVILEGE_DOMAIN_MONITOR		0x200

static char g_host[256];
static int g_port;
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];


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
	DOUBLE_LIST_NODE *pnode;

	if (NULL == pcollect) {
		return;
	}
	while ((pnode = double_list_pop_front(&pcollect->list)) != nullptr) {
		free(pnode->pdata);
		free(pnode);
	}
	double_list_free(&pcollect->list);
	free(pcollect);
}

void data_source_collect_clear(DATA_COLLECT *pcollect)
{
	DOUBLE_LIST_NODE *pnode;

	if (NULL == pcollect) {
		return;
	}
	while ((pnode = double_list_pop_front(&pcollect->list)) != nullptr) {
		free(pnode->pdata);
		free(pnode);
	}
	pcollect->pnode = NULL;
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
	HX_strlcpy(g_host, host, GX_ARRAY_SIZE(g_host));
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

BOOL data_source_get_domain_list(DATA_COLLECT *pcollect)
{
	int i, rows;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	DOMAIN_ITEM *pitem;
	
	
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

	sprintf(sql_string, "SELECT domainname, homedir FROM domains "
		"WHERE domain_status=0");
	
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

	for (i=0; i<rows; i++) {
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (DOMAIN_ITEM*)malloc(sizeof(DOMAIN_ITEM));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		myrow = mysql_fetch_row(pmyres);
		HX_strlcpy(pitem->domainname, myrow[0], GX_ARRAY_SIZE(pitem->domainname));
		HX_strlower(pitem->domainname);
		HX_strlcpy(pitem->homedir, myrow[1], GX_ARRAY_SIZE(pitem->homedir));
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_alias_list(DATA_COLLECT *pcollect)
{
	int i, rows;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	ALIAS_ITEM *pitem;
	
	
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

	sprintf(sql_string, "SELECT aliasname, mainname FROM aliases");
	
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

	for (i=0; i<rows; i++) {
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (ALIAS_ITEM*)malloc(sizeof(ALIAS_ITEM));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		
		myrow = mysql_fetch_row(pmyres);
		HX_strlcpy(pitem->aliasname, myrow[0], GX_ARRAY_SIZE(pitem->aliasname));
		HX_strlower(pitem->aliasname);
		HX_strlcpy(pitem->mainname, myrow[1], GX_ARRAY_SIZE(pitem->mainname));
		HX_strlower(pitem->mainname);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}
