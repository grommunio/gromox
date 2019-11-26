#include <unistd.h>
#include "data_source.h"
#include "system_log.h"
#include "locker_client.h"
#include "util.h"
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

static BOOL data_source_remove_class(MYSQL *pmysql, int parent_id, int class_id);

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

	while (pnode = double_list_get_from_head(&pcollect->list)) {
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

	while (pnode = double_list_get_from_head(&pcollect->list)) {
		free(pnode->pdata);
		free(pnode);
	}
	pcollect->pnode = NULL;
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

BOOL data_source_add_class(const char *domainname, const char *classname,
	int *presult)
{
	int i, j;
	int num, rows;
	LOCKD lockd;
	int domain_id;
	int class_id;
	char temp_buff[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	

	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: fail to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}
	data_source_encode_squote(domainname, temp_buff);
	snprintf(sql_string, 4096, "SELECT id, domain_type FROM domains WHERE "
		"domainname='%s'", temp_buff);

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
		*presult = ADD_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);
	

	snprintf(sql_string, 4096, "SELECT classname, group_id FROM classes WHERE "
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

	num = 0;	
	rows = mysql_num_rows(pmyres);
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (0 != atoi(myrow[1])) {
			continue;
		}
		if (0 == strcasecmp(myrow[0], classname)) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = ADD_RESULT_EXIST;
			locker_client_unlock(lockd);
			return TRUE;
		}
		num ++;
	}
	mysql_free_result(pmyres);

	if (num > MAXIMUM_CLASS_NUM) {
		mysql_close(pmysql);
		*presult = ADD_RESULT_FULL;
		locker_client_unlock(lockd);
		return TRUE;
	}

	data_source_encode_squote(classname, temp_buff);
	snprintf(sql_string, 4096, "INSERT INTO classes (classname, domain_id, "
		"group_id) VALUES ('%s', %d, 0)", temp_buff, domain_id);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	snprintf(sql_string, 4096, "SELECT id, group_id, classname FROM classes "
		"WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	class_id = 0;
	rows = mysql_num_rows(pmyres);
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (0 == atoi(myrow[1]) &&
			0 == strcasecmp(myrow[2], classname)) {
			class_id = atoi(myrow[0]);
			break;
		}
	}
	mysql_free_result(pmyres);
	
	if (0 == class_id) {
		mysql_close(pmysql);
		*presult = ADD_RESULT_CLASSERR;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	snprintf(sql_string, 4096, "INSERT INTO hierarchy (class_id, child_id, "
		"domain_id, group_id) VALUES (0, %d, %d, 0)", class_id,
		domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	mysql_close(pmysql);
	*presult = ADD_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_rename_class(const char *domainname, int class_id,
	const char *new_name, int *presult)
{
	int i, j, rows;
	int domain_id;
	char temp_buff[256];
	char sql_string[4096];
	char resource_name[256];
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
			system_log_info("[data_source]: fail to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}
	data_source_encode_squote(domainname, temp_buff);
	snprintf(sql_string, 4096, "SELECT id, domain_type FROM domains WHERE "
		"domainname='%s'", temp_buff);

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
		*presult = RENAME_RESULT_NODOMAIN;
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = RENAME_RESULT_DOMAINNOTMAIN;
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);
	

	snprintf(sql_string, 4096, "SELECT domain_id, group_id FROM classes "
		"WHERE id=%d", class_id);
		
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
		*presult = RENAME_RESULT_NOCLASS;
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	if (domain_id != atoi(myrow[0]) ||
		0 != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = RENAME_RESULT_CLASSERR;
		return TRUE;
	}

	mysql_free_result(pmyres);

	snprintf(sql_string, 4096, "SELECT group_id, classname FROM classes WHERE "
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
		if (0 == atoi(myrow[0]) &&
			0 == strcasecmp(myrow[1], new_name)) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = RENAME_RESULT_EXIST;
			return TRUE;
		}
	}
	mysql_free_result(pmyres);


	data_source_encode_squote(new_name, temp_buff);
	snprintf(sql_string, 4096, "UPDATE classes SET classname='%s' WHERE "
		"id=%d", temp_buff, class_id);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	mysql_close(pmysql);
	*presult = RENAME_RESULT_OK;
	return TRUE;
}

BOOL data_source_link_class(const char *domainname, int parent_id,
	int class_id, int *presult)
{
	LOCKD lockd;
	int domain_id;
	int group_id;
	int i, j, rows;
	char temp_buff[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	

	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: fail to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}
	data_source_encode_squote(domainname, temp_buff);
	snprintf(sql_string, 4096, "SELECT id, domain_type FROM domains WHERE "
		"domainname='%s'", temp_buff);

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
		*presult = LINK_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = LINK_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);
	

	snprintf(sql_string, 4096, "SELECT domain_id, group_id FROM classes "
		"WHERE id=%d", parent_id);
		
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
		*presult = LINK_RESULT_NOPARENT;
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	if (domain_id != atoi(myrow[0]) ||
		0 != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = LINK_RESULT_PARENTERR;
		locker_client_unlock(lockd);
		return TRUE;
	}
	mysql_free_result(pmyres);
	

	snprintf(sql_string, 4096, "SELECT domain_id, group_id FROM classes "
		"WHERE id=%d", class_id);
		
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
		*presult = LINK_RESULT_NOCLASS;
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	if (domain_id != atoi(myrow[0]) ||
		0 == atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = LINK_RESULT_CLASSERR;
		locker_client_unlock(lockd);
		return TRUE;
	}

	mysql_free_result(pmyres);

	snprintf(sql_string, 4096, "SELECT class_id, child_id, group_id FROM "
		"hierarchy WHERE domain_id=%d", domain_id);
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
		if (0 != atoi(myrow[2])) {
			continue;
		}
		if (parent_id == atoi(myrow[0]) &&
			class_id == atoi(myrow[1])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult =  LINK_RESULT_EXIST;
			locker_client_unlock(lockd);
			return TRUE;
		}
	}
	mysql_free_result(pmyres);

	
	snprintf(sql_string, 4096, "INSERT INTO hierarchy (class_id, child_id, "
		"domain_id, group_id) VALUES (%d, %d, %d, 0)", parent_id, class_id,
		domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	mysql_close(pmysql);
	*presult = LINK_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_unlink_class(const char *domainname, int parent_id,
	int class_id)
{
	LOCKD lockd;
	int i, domain_id;
	char temp_buff[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	

	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		locker_client_unlock(lockd);
		return FALSE;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: fail to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}
	data_source_encode_squote(domainname, temp_buff);
	snprintf(sql_string, 4096, "SELECT id, domain_type FROM domains WHERE "
		"domainname='%s'", temp_buff);

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
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);	

	if (0 != parent_id) {
		snprintf(sql_string, 4096, "SELECT domain_id, group_id FROM classes "
			"WHERE id=%d", parent_id);
		
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
			locker_client_unlock(lockd);
			return TRUE;
		}

		myrow = mysql_fetch_row(pmyres);
		if (domain_id != atoi(myrow[0]) ||
			0 != atoi(myrow[1])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			return TRUE;
		}
		mysql_free_result(pmyres);
	}

	snprintf(sql_string, 4096, "SELECT domain_id, group_id FROM classes "
		"WHERE id=%d", class_id);
		
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
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	if (domain_id != atoi(myrow[0]) ||
		(0 != parent_id && 0 == atoi(myrow[1]))) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}

	mysql_free_result(pmyres);

	if (FALSE == data_source_remove_class(pmysql, parent_id, class_id)) {
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
	
}

static BOOL data_source_remove_class(MYSQL *pmysql, int parent_id, int class_id)
{
	int i, id, rows;
	int list_id;
	char *pdomain, *pat;
	char sql_string[512];
	char listname[256];
	char temp_buff[256];
	char virtual_address[128];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;

	
	snprintf(sql_string, 512, "SELECT id, class_id FROM hierarchy "
		"WHERE child_id=%d", class_id);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		return FALSE;
	}

	rows = mysql_num_rows(pmyres);

	for (i=0, id=0; i<rows; i++) {
		myrow = mysql_fetch_row(pmyres);
		if (parent_id == atoi(myrow[1])) {
			id = atoi(myrow[0]);
			break;
		}
	}
	mysql_free_result(pmyres);

	if (0 != id) {
		snprintf(sql_string, 512, "DELETE FROM hierarchy WHERE id=%d", id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			return FALSE;
		}
	}
	
	if (0 != id && 1 == rows) {
		snprintf(sql_string, 512, "SELECT child_id FROM hierarchy WHERE "
			"class_id=%d", class_id);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			return FALSE;
		}
		rows = mysql_num_rows(pmyres);
		for (i=0; i<rows; i++) {
			myrow = mysql_fetch_row(pmyres);
			if (FALSE == data_source_remove_class(pmysql, class_id,
				atoi(myrow[0]))) {
				mysql_free_result(pmyres);
				return FALSE;
			}
		}
		mysql_free_result(pmyres);

		snprintf(sql_string, 512, "DELETE FROM members WHERE class_id=%d",
			class_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			return FALSE;
		}

		snprintf(sql_string, 512, "SELECT listname FROM classes "
			"WHERE id=%d", class_id);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			return FALSE;
		}
		myrow = mysql_fetch_row(pmyres);
		if (NULL != myrow[0]) {
			strcpy(listname, myrow[0]);
			pdomain = strchr(listname, '@') + 1;
			mysql_free_result(pmyres);
			data_source_encode_squote(listname, temp_buff);
			snprintf(sql_string, 4096, "SELECT id FROM mlists WHERE "
				"listname='%s'", temp_buff);
			if (0 != mysql_query(pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(pmysql))) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				return FALSE;
			}
			if (1 == mysql_num_rows(pmyres)) {
				myrow = mysql_fetch_row(pmyres);
				list_id = atoi(myrow[0]);
				mysql_free_result(pmyres);
			
				data_source_encode_squote(pdomain, temp_buff);
				snprintf(sql_string, 512, "SELECT aliasname FROM aliases "
					"WHERE mainname='%s'", temp_buff);
				if (0 != mysql_query(pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(pmysql))) {
					system_log_info("[data_source]: fail to query mysql server, "
						"reason: %s", mysql_error(pmysql));
					return FALSE;
				}
				
				rows = mysql_num_rows(pmyres);
				for (i=0; i<rows; i++) {
					myrow = mysql_fetch_row(pmyres);
					strcpy(virtual_address, listname);
					pat = strchr(virtual_address, '@') + 1;
					strcpy(pat, myrow[0]);
					data_source_encode_squote(virtual_address, temp_buff);
					sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
						temp_buff);
					if (0 != mysql_query(pmysql, sql_string)) {
						system_log_info("[data_source]: fail to query mysql "
							"server, reason: %s", mysql_error(pmysql));
						system_log_info("[data_source]: fail to delete "
							"virtual address %s of mlist from database",
							virtual_address);
					}
				}

				mysql_free_result(pmyres);

				data_source_encode_squote(listname, temp_buff);
				snprintf(sql_string, 512, "DELETE FROM users WHERE "
					"username='%s'", temp_buff);
				if (0 != mysql_query(pmysql, sql_string)) {
					system_log_info("[data_source]: fail to query mysql server, "
						"reason: %s", mysql_error(pmysql));
					return FALSE;
				}
				
				snprintf(sql_string, 512, "DELETE FROM specifieds WHERE "
					"list_id=%d", list_id);
				if (0 != mysql_query(pmysql, sql_string)) {
					system_log_info("[data_source]: fail to query mysql server, "
						"reason: %s", mysql_error(pmysql));
					return FALSE;
				}
			} else {
				mysql_free_result(pmyres);
			}

			snprintf(sql_string, 512, "DELETE FROM mlists WHERE id=%d",
				list_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				return FALSE;
			}
		} else {
			mysql_free_result(pmyres);
		}

		snprintf(sql_string, 512, "DELETE FROM classes WHERE id=%d", class_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			return FALSE;
		}
	}
	return TRUE;
}


BOOL data_source_get_class_list(const char *domainname, DATA_COLLECT *pcollect)
{
	int domain_id;
	int i, j, k;
	int rows, rows1;
	char temp_buff[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;

	
	i = 0;

RETRYING:
	if (i > 3) {
		return FALSE;
	}

	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: fail to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	data_source_encode_squote(domainname, temp_buff);
	sprintf(sql_string, "SELECT id FROM domains WHERE domainname='%s'",
		temp_buff);
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
	mysql_free_result(pmyres);
	
	sprintf(sql_string, "SELECT id, title FROM groups WHERE domain_id=%d",
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

	rows = mysql_num_rows(pmyres);
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		sprintf(sql_string, "SELECT id, classname FROM classes WHERE "
			"group_id=%s", myrow[0]);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			continue;
		}
		rows1 = mysql_num_rows(pmyres1);
		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				continue;
			}
			pnode->pdata = (CLASS_ITEM*)malloc(sizeof(CLASS_ITEM));
			if (NULL == pnode->pdata) {
				free(pnode);
				continue;
			}
			((CLASS_ITEM*)(pnode->pdata))->class_id = atoi(myrow1[0]);
			snprintf(((CLASS_ITEM*)(pnode->pdata))->classname, 32,
				"%s:%s", myrow[1], myrow1[1]);
			double_list_append_as_tail(&pcollect->list, pnode);		
		}
		mysql_free_result(pmyres1);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}


BOOL data_source_get_childrent_list(const char *domainname, int class_id,
	DATA_COLLECT *pcollect)
{
	int domain_id;
	int group_id;
	int i, j, rows;
	char classname[32];
	char group_title[128];
	char temp_buff[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;

	
	i = 0;

RETRYING:
	if (i > 3) {
		return FALSE;
	}

	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: fail to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	data_source_encode_squote(domainname, temp_buff);
	sprintf(sql_string, "SELECT id FROM domains WHERE domainname='%s'",
		temp_buff);
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
	mysql_free_result(pmyres);
	
	if (0 != class_id) {
		sprintf(sql_string, "SELECT domain_id, group_id FROM classes WHERE "
			"id=%d", class_id);
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
		if (domain_id != atoi(myrow[0]) ||
			0 != atoi(myrow[1])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			return TRUE;
		}
		mysql_free_result(pmyres);
	}
	
	sprintf(sql_string, "SELECT group_id, class_id, child_id FROM hierarchy "
		"WHERE domain_id=%d", domain_id);
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
		if (0 != atoi(myrow[0])) {
			continue;
		}
		if (class_id == atoi(myrow[1])) {
			sprintf(sql_string, "SELECT classname, group_id FROM classes WHERE "
				"id=%s", myrow[2]);
			if (0 != mysql_query(pmysql, sql_string) ||
				NULL == (pmyres1 = mysql_store_result(pmysql))) {
				system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
				continue;
			}
			if (1 != mysql_num_rows(pmyres1)) {
				mysql_free_result(pmyres1);
				continue;
			}
			myrow1 = mysql_fetch_row(pmyres1);
			strcpy(classname, myrow1[0]);
			group_id = atoi(myrow1[1]);
			mysql_free_result(pmyres1);

			if (0 != group_id) {
				sprintf(sql_string, "SELECT title FROM groups WHERE id=%d",
					group_id);
				if (0 != mysql_query(pmysql, sql_string) ||
					NULL == (pmyres1 = mysql_store_result(pmysql))) {
					system_log_info("[data_source]: fail to query "
						"mysql server, reason: %s", mysql_error(pmysql));
					continue;
				}
				if (1 != mysql_num_rows(pmyres1)) {
					mysql_free_result(pmyres1);
					continue;
				}
				myrow1 = mysql_fetch_row(pmyres1);
				strcpy(group_title, myrow1[0]);
				mysql_free_result(pmyres1);
			} else {
				group_title[0] = '\0';
			}
			
			pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				continue;
			}
			pnode->pdata = (CLASS_ITEM*)malloc(sizeof(CLASS_ITEM));
			if (NULL == pnode->pdata) {
				free(pnode);
				continue;
			}
			((CLASS_ITEM*)(pnode->pdata))->class_id = atoi(myrow[2]);
			if ('\0' == group_title[0]) {
				strcpy(((CLASS_ITEM*)(pnode->pdata))->classname, classname);
			} else {
				snprintf(((CLASS_ITEM*)(pnode->pdata))->classname, 32, "%s:%s",
					group_title, classname);
			}
			double_list_append_as_tail(&pcollect->list, pnode);	
		}
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

