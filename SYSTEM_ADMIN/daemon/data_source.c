#include "data_source.h"
#include "system_log.h"
#include "locker_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql/mysql.h>


#define RECORD_STATUS_NORMAL                0

#define RECORD_STATUS_SUSPEND               1

#define RECORD_STATUS_OUTOFDATE             2

#define RECORD_STATUS_DELETED               3

#define ADDRESS_TYPE_NORMAL                 0

#define ADDRESS_TYPE_ALIAS                  1

#define ADDRESS_TYPE_MLIST                  2

#define ADDRESS_TYPE_VIRTUAL                3

#define MLIST_TYPE_NORMAL					0

#define DOMAIN_PRIVILEGE_EXTPASSWD			0x20

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


BOOL data_source_clean_deleted_alias()
{
	LOCKD lockd;
	int i, j, k;
	int domain_id;
	int rows, rows1;
	char *pdomain;
	char mainname[128];
	char temp_name[128];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
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

	sprintf(sql_string, "SELECT domainname FROM domains WHERE domain_status=3 "
		"AND domain_type=1");
	
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
		sprintf(sql_string, "SELECT mainname FROM aliases WHERE aliasname='%s'",
			temp_name);
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
		strcpy(mainname, myrow1[0]);
		mysql_free_result(pmyres1);
		
		sprintf(resource_name, "DATABASE-%s", mainname);
		upper_string(resource_name);
		lockd = locker_client_lock(resource_name);
		data_source_encode_squote(mainname, temp_name);
		sprintf(sql_string, "SELECT id FROM domains WHERE domainname='%s'",
			temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			locker_client_unlock(lockd);
			continue;
		}
		if (1 != mysql_num_rows(pmyres1)) {
			mysql_free_result(pmyres1);
			locker_client_unlock(lockd);
			continue;
		}
		myrow1 = mysql_fetch_row(pmyres1);
		domain_id = atoi(myrow1[0]);
		mysql_free_result(pmyres1);

		sprintf(sql_string, "SELECT username, address_type FROM users WHERE "
			"domain_id=%d", domain_id);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			locker_client_unlock(lockd);
			continue;
		}
		rows1 = mysql_num_rows(pmyres1);
		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			if (ADDRESS_TYPE_VIRTUAL != atoi(myrow1[1])) {
				continue;
			}
			pdomain = strchr(myrow1[0], '@');
			if (NULL == pdomain || 0 != strcasecmp(pdomain+1, myrow[0])) {
				continue;
			}
			data_source_encode_squote(myrow1[0], temp_name);
			sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
				temp_name);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to delete "
					"alias-domain-user %s", myrow1[0]);
			}
		}
		mysql_free_result(pmyres1);
		
		data_source_encode_squote(myrow[0], temp_name);
		sprintf(sql_string, "DELETE FROM aliases WHERE aliasname='%s'",
			temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to delete "
				"alias-domain %s from aliases table", myrow[0]);
			locker_client_unlock(lockd);
			continue;
		}
		
		sprintf(sql_string, "DELETE FROM domains WHERE domainname='%s'",
			temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to delete "
				"alias-domain %s from domains table", myrow[0]);
		}
		locker_client_unlock(lockd);	
		
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}


BOOL data_source_get_deleted_domain(DATA_COLLECT *pcollect)
{
	int i, j, rows;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	DELETED_DOMAIN *pitem;
	
	
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

	sprintf(sql_string, "SELECT domainname, homedir FROM domains "
		"WHERE domain_status=3 AND domain_type=0");
	
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
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (DELETED_DOMAIN*)malloc(sizeof(DELETED_DOMAIN));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		myrow = mysql_fetch_row(pmyres);
		
		strcpy(pitem->domainname, myrow[0]);
		strcpy(pitem->homedir, myrow[1]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_extpasswd_domain(DATA_COLLECT *pcollect)
{
	int i, rows;
	int privilege_bits;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	EXTPASSWD_DOMAIN *pitem;
	
	
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

	sprintf(sql_string, "SELECT domainname, homedir, privilege_bits "
		"FROM domains WHERE domain_status=0 AND domain_type=0");
	
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
		myrow = mysql_fetch_row(pmyres);
		privilege_bits = atoi(myrow[2]);
		if ((privilege_bits & DOMAIN_PRIVILEGE_EXTPASSWD) == 0) {
			continue;
		}
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (EXTPASSWD_DOMAIN*)malloc(sizeof(EXTPASSWD_DOMAIN));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		
		strcpy(pitem->domainname, myrow[0]);
		strcpy(pitem->homedir, myrow[1]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}


BOOL data_source_get_media_domain(int type, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	int row_type, num;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	MEDIA_DOMAIN *pitem;
	
	if (MEDIA_TYPE_LIVING != type &&
		MEDIA_TYPE_IMMIGRATION != type &&
		MEDIA_TYPE_EMIGRATION != type) {
		return FALSE;
	}
	
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

	sprintf(sql_string, "SELECT domainname, homedir, media FROM domains "
		"WHERE domain_type=0 AND media!=''");
	
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

		if (0 == strncmp(myrow[2], "=>", 2) ||
			0 == strncmp(myrow[2], ">>", 2)) {
			row_type = MEDIA_TYPE_IMMIGRATION;
		} else if (0 == strncmp(myrow[2], "<=", 2) ||
			0 == strncmp(myrow[2], "<<", 2)) {
			row_type = MEDIA_TYPE_EMIGRATION;
		} else {
			row_type = MEDIA_TYPE_LIVING;
		}

		if (type != row_type) {
			continue;
		}

		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (MEDIA_DOMAIN*)malloc(sizeof(MEDIA_DOMAIN));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		
		strcpy(pitem->domainname, myrow[0]);
		strcpy(pitem->homedir, myrow[1]);
		if (MEDIA_TYPE_LIVING == type) {
			strcpy(pitem->media, myrow[2]);
		} else {
			strcpy(pitem->media, myrow[2] + 2);
		}
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_status_media(const char *domainname, int status)
{
	int i;
	LOCKD lockd;
	int domain_id;
	char media[64];
	char temp_name[128];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	
	if (MEDIA_STATUS_IMMIGRATED != status &&
		MEDIA_STATUS_EMIGRATED != status &&
		MEDIA_STATUS_IMMIGRATING != status &&
		MEDIA_STATUS_EMIGRATING != status) {
		return FALSE;
	}

	
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
	
	data_source_encode_squote(domainname, temp_name);
	
	sprintf(sql_string, "SELECT id, media FROM domains WHERE domainname='%s'",
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
	domain_id = atoi(myrow[0]);
	if (0 == strncmp(myrow[1], "=>", 2) ||
		0 == strncmp(myrow[1], ">>", 2) ||
		0 == strncmp(myrow[1], "<=", 2) ||
		0 == strncmp(myrow[1], "<<", 2)) {
		strcpy(media, myrow[1] + 2);
		if ('\0' == media[0]) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			system_log_info("[data_source]: status of \"media\" filed of "
				"domain %s error", domainname);
			return TRUE;
		}
	} else {
		strcpy(media, myrow[1]);
	}
	mysql_free_result(pmyres);

	switch (status) {
	case MEDIA_STATUS_IMMIGRATED:
		if ('\0' == media[0]) {
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			system_log_info("[data_source]: status of \"media\" filed of "
				"domain %s error", domainname);
			return TRUE;
		}
		sprintf(sql_string, "UPDATE domains SET media='%s' "
			"WHERE id=%d", media, domain_id);
		break;
	case MEDIA_STATUS_EMIGRATED:
		sprintf(sql_string, "UPDATE domains SET media='' "
			"WHERE id=%d", domain_id);
		break;
	case MEDIA_STATUS_IMMIGRATING:
		if ('\0' == media[0]) {
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			system_log_info("[data_source]: status of \"media\" filed of "
				"domain %s error", domainname);
			return TRUE;
		}
		sprintf(sql_string, "UPDATE domains SET media='>>%s' "
			"WHERE id=%d", media, domain_id);
		break;
	case MEDIA_STATUS_EMIGRATING:
		if ('\0' == media[0]) {
			mysql_close(pmysql);
			locker_client_unlock(lockd);
			system_log_info("[data_source]: status of \"media\" filed of "
				"domain %s error", domainname);
			return TRUE;
		}
		sprintf(sql_string, "UPDATE domains SET media='<<%s' "
			"WHERE id=%d", media, domain_id);
		break;
	}

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


BOOL data_source_get_domain_list(DATA_COLLECT *pcollect)
{
	int i, j, rows;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	DOMAIN_INFO *pitem;
	struct tm tmp_tm;
	
	
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

	sprintf(sql_string, "SELECT domainname, homedir, end_day, domain_status "
		"FROM domains WHERE (domain_status=0 OR domain_status=2) AND "
		"domain_type=0");
	
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
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (DOMAIN_INFO*)malloc(sizeof(DOMAIN_INFO));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		myrow = mysql_fetch_row(pmyres);
		
		strcpy(pitem->domainname, myrow[0]);
		strcpy(pitem->homedir, myrow[1]);
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		strptime(myrow[2], "%Y-%m-%d", &tmp_tm);
		pitem->end_day = mktime(&tmp_tm);
		pitem->status = atoi(myrow[3]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_user_list(const char *domainname, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	int domain_id;
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	USER_INFO *pitem;
	struct tm tmp_tm;
	
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
	
	sprintf(sql_string, "SELECT username, maildir, password, address_type "
		"FROM users WHERE domain_id=%d", domain_id);
	
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
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[3])) {
			continue;
		}
		pnode = (DOUBLE_LIST_NODE*)malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pitem = (USER_INFO*)malloc(sizeof(USER_INFO));
		if (NULL == pitem) {
			free(pnode);
			continue;
		}
		pnode->pdata = pitem;
		
		strcpy(pitem->username, myrow[0]);
		strcpy(pitem->maildir, myrow[1]);
		strcpy(pitem->password, myrow[2]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_delete_domain(const char *domainname)
{
	int i, j, rows;
	int domain_id;
	char *pdomain;
	char temp_name[128];
	char sql_string[4096];
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
	
	strcpy(sql_string, "SELECT id, username FROM forwards");

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
		pdomain = strchr(myrow[1], '@');
		if (NULL == pdomain) {
			continue;
		}
		pdomain ++;
		if (0 != strcasecmp(pdomain, domainname)) {
			continue;
		}
		sprintf(sql_string, "DELETE FROM forwards WHERE id=%s", myrow[0]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}
	mysql_free_result(pmyres);

	strcpy(sql_string, "SELECT id, aliasname FROM aliases");

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
		pdomain = strchr(myrow[1], '@');
		if (NULL == pdomain) {
			continue;
		}
		pdomain ++;
		if (0 != strcasecmp(pdomain, domainname)) {
			continue;
		}
		sprintf(sql_string, "DELETE FROM aliases WHERE id=%s", myrow[0]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}
	mysql_free_result(pmyres);

	data_source_encode_squote(domainname, temp_name);
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
		goto CLEAN_ALIAS_DOMAIN;
	}
	
	myrow = mysql_fetch_row(pmyres);
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);


	sprintf(sql_string, "SELECT id, list_type FROM mlists WHERE domain_id=%d",
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
		sprintf(sql_string, "DELETE FROM specifieds WHERE list_id=%s",
			myrow[0]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		if (atoi(myrow[1]) != MLIST_TYPE_NORMAL) {
			continue;
		}
		sprintf(sql_string, "DELETE FROM associations WHERE list_id=%s",
			myrow[0]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}
	mysql_free_result(pmyres);

	
	sprintf(sql_string, "DELETE FROM mlists WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}

	sprintf(sql_string, "DELETE FROM members WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}

	sprintf(sql_string, "DELETE FROM hierarchy WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	sprintf(sql_string, "DELETE FROM classes WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	sprintf(sql_string, "DELETE FROM users WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	sprintf(sql_string, "DELETE FROM groups WHERE domain_id=%d", domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
CLEAN_ALIAS_DOMAIN:
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
		sprintf(sql_string, "DELETE FROM domains WHERE domainname='%s'", 
			temp_name);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}
	mysql_free_result(pmyres);
		
	data_source_encode_squote(domainname, temp_name);
	sprintf(sql_string, "DELETE FROM aliases WHERE mainname='%s'", temp_name);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	sprintf(sql_string, "DELETE FROM domains WHERE domainname='%s'", temp_name);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_make_outofdate(const char *domainname)
{
	LOCKD lockd;
	int i, j, rows;
	int domain_id;
	int temp_id;
	int temp_status;
	char temp_name[128];
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
	
	data_source_encode_squote(domainname, temp_name);
	
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
		locker_client_unlock(lockd);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	
	sprintf(sql_string, "SELECT id, group_status FROM groups "
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
		temp_id = atoi(myrow[0]);
		temp_status = atoi(myrow[1]);
		temp_status |= (RECORD_STATUS_OUTOFDATE << 2);
		snprintf(sql_string, 4096, "UPDATE groups SET group_status=%d "
			"WHERE id=%d", temp_status, temp_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}	
	}

	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT id, address_status FROM users "
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
		temp_id = atoi(myrow[0]);
		temp_status = atoi(myrow[1]);
		temp_status |= (RECORD_STATUS_OUTOFDATE << 4);
		snprintf(sql_string, 4096, "UPDATE users SET address_status=%d "
			"WHERE id=%d", temp_status, temp_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}

	mysql_free_result(pmyres);
	
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
		
		sprintf(sql_string, "UPDATE domains SET domain_status=2 WHERE "
			"domainname='%s'", myrow[0]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}

	mysql_free_result(pmyres);
		

	sprintf(sql_string, "UPDATE domains SET domain_status=2 WHERE id=%d",
		domain_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}


BOOL data_source_update_userpasswd(const char *username, const char *password)
{
	int i, j, k;
	int rows, rows1;
	char temp_domain[256];
	char temp_user[256];
	char temp_alias[256];
	char temp_address[256];
	char virtual_address[128];
	char *pat, *pdomain;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	
	
	pdomain = strchr(username, '@') + 1;
	
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

	data_source_encode_squote(username, temp_user);
	snprintf(sql_string, 4096, "UPDATE users SET password='%s' WHERE username='%s'",
		password, temp_user);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	sprintf(sql_string, "SELECT aliasname FROM aliases WHERE mainname='%s'",
		temp_user);
	
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

	data_source_encode_squote(pdomain, temp_domain);
	sprintf(sql_string, "SELECT aliasname FROM aliases WHERE mainname='%s'",
		temp_domain);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres1 = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	rows1 = mysql_num_rows(pmyres1);

	for (k=0; k<rows1; k++) {
		myrow1 = mysql_fetch_row(pmyres1);
		strcpy(virtual_address, username);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow1[0]);
		data_source_encode_squote(virtual_address, temp_address);
		snprintf(sql_string, 4096, "UPDATE users SET password='%s'"
			" WHERE username='%s'", password, temp_address);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to update virtual address "
				"%s in database", virtual_address);
		}
	}

	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		data_source_encode_squote(myrow[0], temp_alias);
		snprintf(sql_string, 4096, "UPDATE users SET password='%s'"
			" WHERE username='%s'", password, temp_alias);	
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to update alias address %s "
				"in database", myrow[0]);
		}
		mysql_data_seek(pmyres1, 0);
		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			strcpy(virtual_address, myrow[0]);
			pat = strchr(virtual_address, '@') + 1;
			strcpy(pat, myrow1[0]);
			data_source_encode_squote(virtual_address, temp_address);
			snprintf(sql_string, 4096, "UPDATE users SET password='%s'"
				" WHERE username='%s'", password, temp_address);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to update alias address %s "
					"in database", virtual_address);
			}
		}
	}

	mysql_free_result(pmyres);
	mysql_free_result(pmyres1);	
	
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


