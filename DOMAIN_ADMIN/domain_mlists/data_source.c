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

BOOL data_source_add_clist(int class_id, const char *listname,
	int list_privilege, int *presult)
{
	LOCKD lockd;
	int i, j, rows;
	int group_id;
	int domain_id;
	int temp_status;
	int group_status;
	int domain_status;
	time_t now_time;
	char *pat, *pdomain;
	char str_create[16];
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	char virtual_address[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm tmp_tm;

	time(&now_time);
	localtime_r(&now_time, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);

	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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

	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT id, domain_status, domain_type FROM domains "
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
		*presult = ADD_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);

	if (DOMAIN_TYPE_NORMAL != atoi(myrow[2])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}

	domain_id = atoi(myrow[0]);
	domain_status = atoi(myrow[1]);
	mysql_free_result(pmyres);

	
	sprintf(sql_string, "SELECT listname, domain_id, group_id FROM classes "
		"WHERE id=%d", class_id);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, reason: %s",
			mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	myrow = mysql_fetch_row(pmyres);

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_NOCLASS;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	if (NULL != myrow[0]) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_EXIST;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	if (domain_id != atoi(myrow[1])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_CLASSERR;
		locker_client_unlock(lockd);
		return TRUE;
	}

	group_id = atoi(myrow[2]);
	mysql_free_result(pmyres);
	
	if (0 != group_id) {
		sprintf(sql_string, "SELECT group_status FROM groups WHERE id=%d",
			group_id);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}

		myrow = mysql_fetch_row(pmyres);

		if (1 != mysql_num_rows(pmyres)) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = ADD_RESULT_CLASSERR;
			locker_client_unlock(lockd);
			return TRUE;
		}

		group_status = atoi(myrow[0]);
		mysql_free_result(pmyres);
	} else {
		group_status = 0;
	}
	
	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id FROM users WHERE username='%s'", temp_name);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (0 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_USERNAME;
		locker_client_unlock(lockd);
		return TRUE;
	}

	mysql_free_result(pmyres);


	temp_status = (domain_status<<4) | (group_status<<2);
	
	data_source_encode_squote(listname, temp_name);
	lower_string(temp_name);
	sprintf(sql_string, "INSERT INTO users (username, password, real_name, "
		"domain_id, group_id, maildir, max_size, max_file, create_day, "
		"mobile_phone, privilege_bits, address_status, address_type) "
		"VALUES ('%s', '$1$fQ.Dcv6P$IsPEm8ZpBkjcT8AlHh9ua.', 'mlist', "
		"%d, %d, '', 0, 0, '%s', '', 0, %d, 2)", temp_name, domain_id,
		group_id, str_create, temp_status);

	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	data_source_encode_squote(pdomain, temp_name);
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
		strcpy(virtual_address, listname);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow[0]);
		data_source_encode_squote(virtual_address, temp_name);
		lower_string(temp_name);
		sprintf(sql_string, "INSERT INTO users (username, password, real_name, "
			"domain_id, group_id, maildir, max_size, max_file, create_day, "
			"mobile_phone, privilege_bits, address_status, address_type) "
			"VALUES ('%s', '$1$fQ.Dcv6P$IsPEm8ZpBkjcT8AlHh9ua.', 'mlist', "
			"%d, %d, '', 0, 0, '%s', '', 0, %d, 3)", temp_name,
			domain_id, group_id, str_create, temp_status);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to insert virtual "
				"address %s of mlist into database", virtual_address);
		}
		
	}

	mysql_free_result(pmyres);
	
	data_source_encode_squote(listname, temp_name);
	lower_string(temp_name);
	snprintf(sql_string, 4096, "INSERT INTO mlists (listname, domain_id, "
		"list_type, list_privilege) VALUES ('%s', %d, 3, %d)", temp_name,
	domain_id, list_privilege);

	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	snprintf(sql_string, 4096, "UPDATE classes SET listname='%s' WHERE "
		"id=%d", temp_name, class_id);

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

BOOL data_source_add_mlist(const char *listname, int list_type,
	int list_privilege, int *presult)
{
	LOCKD lockd;
	int i, j, rows;
	int list_num;
	int group_id;
	int domain_id;
	int temp_status;
	int group_status;
	int domain_status;
	time_t now_time;
	char *pat, *pdomain;
	char str_create[16];
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	char virtual_address[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm tmp_tm;

	time(&now_time);
	localtime_r(&now_time, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);
	
	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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
	
	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT id, domain_status, domain_type FROM domains "
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
		*presult = ADD_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[2])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	domain_id = atoi(myrow[0]);
	domain_status = atoi(myrow[1]);
	mysql_free_result(pmyres);

	if (MLIST_TYPE_GROUP == list_type) {
		data_source_encode_squote(listname, temp_name);
		sprintf(sql_string, "SELECT id, group_status FROM groups WHERE "
			"groupname='%s'", temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
		
		myrow = mysql_fetch_row(pmyres);
		
		if (1 != mysql_num_rows(pmyres)) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = ADD_RESULT_NOGROUP;
			locker_client_unlock(lockd);
			return TRUE;
		}

		group_id = atoi(myrow[0]);
		group_status = atoi(myrow[1]);

		mysql_free_result(pmyres);
	} else {
		group_id = 0;
		group_status = 0;
	}
	
	sprintf(sql_string, "SELECT listname, list_type FROM mlists WHERE "
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
	list_num = 0;
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (0 == strcasecmp(listname, myrow[0])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = ADD_RESULT_EXIST;
			locker_client_unlock(lockd);
			return TRUE;
		}
		if (MLIST_TYPE_NORMAL == atoi(myrow[1])) {
			list_num ++;
		}
	}
	
	mysql_free_result(pmyres);

	if (MLIST_TYPE_NORMAL == list_type && list_num >= MAXIMUM_MLIST_NUM) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_FULL;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id FROM users WHERE username='%s'", temp_name);
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	if (0 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_USERNAME;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	mysql_free_result(pmyres);
	
	temp_status = (domain_status<<4) | (group_status<<2);
	
	data_source_encode_squote(listname, temp_name);
	lower_string(temp_name);
	sprintf(sql_string, "INSERT INTO users (username, password, real_name, "
		"domain_id, group_id, maildir, max_size, max_file, create_day, "
		"mobile_phone, privilege_bits, address_status, address_type) "
		"VALUES ('%s', '$1$fQ.Dcv6P$IsPEm8ZpBkjcT8AlHh9ua.', 'mlist', "
		"%d, %d, '', 0, 0, '%s', '', 0, %d, 2)", temp_name, domain_id,
		group_id, str_create, temp_status);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	data_source_encode_squote(pdomain, temp_name);
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
		strcpy(virtual_address, listname);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow[0]);
		data_source_encode_squote(virtual_address, temp_name);
		lower_string(temp_name);
		sprintf(sql_string, "INSERT INTO users (username, password, real_name, "
			"domain_id, group_id, maildir, max_size, max_file, create_day, "
			"mobile_phone, privilege_bits, address_status, address_type) "
			"VALUES ('%s', '$1$fQ.Dcv6P$IsPEm8ZpBkjcT8AlHh9ua.', 'mlist', "
			"%d, %d, '', 0, 0, '%s', '', 0, %d, 3)", temp_name,
			domain_id, group_id, str_create, temp_status);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to insert virtual "
				"address %s of mlist into database", virtual_address);
		}
			
	}

	mysql_free_result(pmyres);

	data_source_encode_squote(listname, temp_name);
	lower_string(temp_name);
	snprintf(sql_string, 4096, "INSERT INTO mlists (listname, domain_id, "
		"list_type, list_privilege) VALUES ('%s', %d, %d, %d)", temp_name,
		domain_id, list_type, list_privilege);
	
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


BOOL data_source_get_mlists(const char *domainname, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	int domain_id;
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	MLIST_ITEM *pitem;
	DOUBLE_LIST_NODE *pnode;
	
	data_source_encode_squote(domainname, temp_name);
	
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

	sprintf(sql_string, "SELECT id FROM domains WHERE domainname='%s'",
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

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT listname, list_type, list_privilege "
		"FROM mlists WHERE domain_id=%d", domain_id);
	
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
		
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (MLIST_ITEM*)malloc(sizeof(MLIST_ITEM));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		strcpy(pitem->listname, myrow[0]);
		pitem->list_type = atoi(myrow[1]);
		pitem->list_privilege = atoi(myrow[2]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}


BOOL data_source_edit_mlist(const char *listname, int list_privilege)
{
	int i;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL *pmysql;
	
	data_source_encode_squote(listname, temp_name);
	
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
	
	sprintf(sql_string, "UPDATE mlists SET list_privilege=%d WHERE "
		"listname='%s'", list_privilege, temp_name);

	if (0 != mysql_query(pmysql, sql_string)) {
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_remove_mlist(const char *listname)
{
	int i, j;
	int rows;
	int list_id;
	int list_type;
	char *pat, *pdomain;
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	char virtual_address[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	LOCKD lockd;
	
	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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
	
	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT domain_type FROM domains WHERE "
		"domainname='%s'", temp_name);

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
	
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[0])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	mysql_free_result(pmyres);

	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id, list_type FROM mlists WHERE listname='%s'",
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
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	list_id = atoi(myrow[0]);
	list_type = atoi(myrow[1]);
	mysql_free_result(pmyres);

	data_source_encode_squote(pdomain, temp_name);
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
		strcpy(virtual_address, listname);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow[0]);
		data_source_encode_squote(virtual_address, temp_name);
		sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
			temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to delete virtual address %s "
				"of mlist from database", virtual_address);
		}
	}
	
	mysql_free_result(pmyres);

	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "DELETE FROM users WHERE username='%s'", temp_name);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	

	if (MLIST_TYPE_NORMAL == list_type) {
		sprintf(sql_string, "DELETE FROM associations WHERE list_id=%d",
			list_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
	} else if (MLIST_TYPE_CLASS == list_type) {
		data_source_encode_squote(listname, temp_name);
		sprintf(sql_string, "UPDATE classes SET listname=NULL WHERE "
			"listname='%s'", temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
	}

	sprintf(sql_string, "DELETE FROM specifieds WHERE list_id=%d", list_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	sprintf(sql_string, "DELETE FROM mlists WHERE id=%d", list_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_expand_mlist(const char *listname, DATA_COLLECT *pcollect)
{
	int i, j;
	int rows;
	int list_id;
	int list_type;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	
	data_source_encode_squote(listname, temp_name);
	
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
	
	sprintf(sql_string, "SELECT id, list_type FROM mlists WHERE listname='%s'",
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
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	list_id = atoi(myrow[0]);
	list_type = atoi(myrow[1]);
	mysql_free_result(pmyres);

	if (MLIST_TYPE_NORMAL != list_type) {
		mysql_close(pmysql);
		return TRUE;
	}

	sprintf(sql_string, "SELECT username FROM associations WHERE list_id=%d",
		list_id);
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
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pnode->pdata = malloc(128);
		if (NULL == pnode->pdata) {
			free(pnode);
			continue;
		}
		strcpy(pnode->pdata, myrow[0]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_expand_specified(const char *listname, DATA_COLLECT *pcollect)
{
	int i, j;
	int rows;
	int list_id;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	
	data_source_encode_squote(listname, temp_name);
	
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
	
	sprintf(sql_string, "SELECT id FROM mlists WHERE listname='%s'", temp_name);
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
	list_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT username FROM specifieds WHERE list_id=%d",
		list_id);
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
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pnode->pdata = malloc(128);
		if (NULL == pnode->pdata) {
			free(pnode);
			continue;
		}
		strcpy(pnode->pdata, myrow[0]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_mlist_del(const char *listname, const char *address)
{
	LOCKD lockd;
	int i, j, rows;
	int list_id;
	int domain_id;
	char *pdomain;
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;

	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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
	
	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT id, domain_type FROM domains "
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

	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id, domain_id FROM mlists WHERE listname='%s'",
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

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	
	if (domain_id != atoi(myrow[1])) {
		system_log_info("[data_source]: fatal error! seems domain_id of mlist "
			"%s in table \"mlists\" is different from %s's id in table "
			"\"domains\"", listname, pdomain);
	}
	
	list_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT id, username FROM associations WHERE "
		"list_id=%d", list_id);

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
		if (0 == strcasecmp(address, myrow[1])) {
			sprintf(sql_string, "DELETE FROM associations WHERE id=%s",
				myrow[0]);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				mysql_free_result(pmyres);
				mysql_close(pmysql);
				i ++;
				sleep(1);
				goto RETRYING;		
			}
			break;
		}
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_mlist_insert(const char *listname, const char *address)
{
	LOCKD lockd;
	int j, rows;
	int i, list_id;
	int domain_id;
	char *pdomain;
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;

	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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
	
	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT id, domain_type FROM domains "
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

	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id, domain_id FROM mlists WHERE listname='%s'",
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

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	
	if (domain_id != atoi(myrow[1])) {
		system_log_info("[data_source]: fatal error! seems domain_id of mlist "
			"%s in table \"mlists\" is different from %s's id in table "
			"\"domains\"", listname, pdomain);
	}
	
	list_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT username FROM associations WHERE "
		"list_id=%d", list_id);

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

	if (rows >= MAXIMUM_MLIST_ITEMS) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (0 == strcasecmp(address, myrow[0])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			return TRUE;
		}
	}

	mysql_free_result(pmyres);

	data_source_encode_squote(address, temp_name);
	lower_string(temp_name);
	sprintf(sql_string, "INSERT INTO associations (username, list_id) "
		"VALUES ('%s', %d)", temp_name, list_id);

	if (0 != mysql_query(pmysql, sql_string)) {
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_specified_del(const char *listname, const char *address)
{
	LOCKD lockd;
	int i, j, rows;
	int list_id;
	int domain_id;
	char *pdomain;
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;

	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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
	
	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT id, domain_type FROM domains "
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

	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id, domain_id FROM mlists WHERE listname='%s'",
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

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);

	if (domain_id != atoi(myrow[1])) {
		system_log_info("[data_source]: fatal error! seems domain_id of mlist "
			"%s in table \"mlists\" is different from %s's id in table "
			"\"domains\"", listname, pdomain);
	}
	
	list_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT id, username FROM specifieds WHERE "
		"list_id=%d", list_id);

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
		if (0 == strcasecmp(address, myrow[1])) {
			sprintf(sql_string, "DELETE FROM specifieds WHERE id=%s",
				myrow[0]);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				mysql_free_result(pmyres);
				mysql_close(pmysql);
				i ++;
				sleep(1);
				goto RETRYING;		
			}
			break;
		}
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_specified_insert(const char *listname, const char *address)
{
	LOCKD lockd;
	int i, list_id;
	int domain_id;
	char *pdomain;
	char temp_name[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;

	pdomain = strchr(listname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
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
	
	data_source_encode_squote(pdomain, temp_name);
	sprintf(sql_string, "SELECT id, domain_type FROM domains "
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

	data_source_encode_squote(listname, temp_name);
	sprintf(sql_string, "SELECT id, domain_id FROM mlists WHERE listname='%s'",
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

	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	
	if (domain_id != atoi(myrow[1])) {
		system_log_info("[data_source]: fatal error! seems domain_id of mlist "
			"%s in table \"mlists\" is different from %s's id in table "
			"\"domains\"", listname, pdomain);
	}
	
	list_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	data_source_encode_squote(address, temp_name);
	lower_string(temp_name);
	sprintf(sql_string, "INSERT INTO specifieds (username, list_id) "
		"VALUES ('%s', %d)", temp_name, list_id);

	if (0 != mysql_query(pmysql, sql_string)) {
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_get_groups(const char *domainname, DATA_COLLECT *pcollect)
{
	int i, j;
	int rows;
	int domain_id;
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	GROUP_ITEM *pitem;
	
	data_source_encode_squote(domainname, temp_name);
	
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
	
	sprintf(sql_string, "SELECT id FROM domains WHERE domainname='%s'",
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
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT groupname, title FROM groups WHERE "
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
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (GROUP_ITEM*)malloc(sizeof(GROUP_ITEM));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;

		strcpy(pitem->groupname, myrow[0]);
		strcpy(pitem->title, myrow[1]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_classes(const char *domainname, DATA_COLLECT *pcollect)
{
	int domain_id;
	int i, j, k;
	int rows, rows1;
	char temp_buff[256];
	char group_title[128];
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

	sprintf(sql_string, "SELECT id, classname, group_id, listname FROM "
		"classes WHERE domain_id=%d", domain_id);
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
		group_title[0] = '\0';
		myrow = mysql_fetch_row(pmyres);
		if (NULL != myrow[3]) {
			continue;
		}
		if (0 != atoi(myrow[2])) {
			sprintf(sql_string, "SELECT title FROM groups WHERE id=%s",
				myrow[2]);
			if (0 == mysql_query(pmysql, sql_string) &&
				NULL != (pmyres1 = mysql_store_result(pmysql))) {
				if (1 != mysql_num_rows(pmyres1)) {
					mysql_free_result(pmyres1);
					continue;
				}
				myrow1 = mysql_fetch_row(pmyres1);
				strcpy(group_title, myrow1[0]);
				mysql_free_result(pmyres1);
			}
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
		((CLASS_ITEM*)(pnode->pdata))->class_id = atoi(myrow[0]);
		if ('\0' == group_title[0]) {
			strcpy(((CLASS_ITEM*)(pnode->pdata))->classname, myrow[1]);
		} else {
			snprintf(((CLASS_ITEM*)(pnode->pdata))->classname, 32,
				"%s:%s", myrow1[0], myrow[1]);
		}
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_info_mlist(const char *listname, int *plist_privilege)
{
	int i;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	
	*plist_privilege = 0;
	
	data_source_encode_squote(listname, temp_name);
	
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
	
	sprintf(sql_string, "SELECT list_privilege FROM mlists WHERE listname='%s'",
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
	
	if (1 == mysql_num_rows(pmyres)) {
		myrow = mysql_fetch_row(pmyres);
		*plist_privilege = atoi(myrow[0]);
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


