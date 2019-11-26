#include <unistd.h>
#include <libHX/string.h>
#include "data_source.h"
#include <gromox/system_log.h>
#include <gromox/locker_client.h>
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
	while ((pnode = double_list_get_from_head(&pcollect->list)) != NULL) {
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
	while ((pnode = double_list_get_from_head(&pcollect->list)) != NULL) {
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

BOOL data_source_add_group(const char *groupname, const char *password,
	int max_size, int max_user, const char *title, int privilege_bits,
	int group_status, int *presult)
{
	LOCKD lockd;
	time_t now_time;
	int i, j, rows;
	int domain_id;
	int domain_size;
	int domain_user;
	int temp_status;
	int domain_status;
	int temp_privilege;
	int domain_privilege;
	char temp_domain[256];
	char temp_group[256];
	char temp_title[256];
	char *pdomain;
	char sql_string[4096];
	char str_create[16];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm tmp_tm;
	
	time(&now_time);
	localtime_r(&now_time, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);

	pdomain = strchr(groupname, '@') + 1;
	sprintf(resource_name, "DATABASE-%s", pdomain);
	HX_strupper(resource_name);
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
	data_source_encode_squote(pdomain, temp_domain);
	sprintf(sql_string, "SELECT id, max_size, max_user, privilege_bits, "
		"domain_status, domain_type FROM domains WHERE domainname='%s'",
		temp_domain);

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
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[5])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	domain_size = atoi(myrow[1]);
	domain_user = atoi(myrow[2]);
	temp_privilege = atoi(myrow[3]);
	domain_privilege = temp_privilege << 8;
	temp_status = atoi(myrow[4]);
	domain_status = temp_status << 2;
	mysql_free_result(pmyres);

	if (max_user > domain_user) {
		mysql_close(pmysql);
		*presult = ADD_RESULT_SIZEEXCEED;
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (max_size > domain_size) {
		mysql_close(pmysql);
		*presult = ADD_RESULT_USREXCEED;
		locker_client_unlock(lockd);
		return TRUE;
	}

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
	
	if (rows >= domain_user) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_FULL;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (0 == strcasecmp(myrow[0], groupname) ||
			0 == strcasecmp(myrow[1], title)) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = ADD_RESULT_EXIST;
			locker_client_unlock(lockd);
			return TRUE;	
		}
	}
	
	mysql_free_result(pmyres);
	

	temp_status = (domain_status|group_status);
	temp_privilege = (domain_privilege|privilege_bits);

	data_source_encode_squote(groupname, temp_group);
	lower_string(temp_group);
	data_source_encode_squote(title, temp_title);
	snprintf(sql_string, 4096, "INSERT INTO groups (groupname, password,"
		"domain_id, max_size, max_user, title, create_day, privilege_bits, "
		"group_status) VALUES ('%s', '%s', %d, %d, %d, '%s', '%s', %d, %d)",
		temp_group, password, domain_id, max_size, max_user, temp_title,
		str_create, temp_privilege, temp_status);
	
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

BOOL data_source_info_group(const char *groupname, GROUP_ITEM *pitem,
	int *pactual_size, int *pactual_user)
{
	int i, j, rows;
	int group_id;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm tmp_tm;
	
	
	data_source_encode_squote(groupname, temp_name);
	
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

	sprintf(sql_string, "SELECT id, max_size, max_user, title, "
		"create_day, privilege_bits, group_status FROM groups WHERE "
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

	if (1 != mysql_num_rows(pmyres)) {
		pitem->groupname[0] = '\0';
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	
	group_id = atoi(myrow[0]);
	strcpy(pitem->groupname, groupname);
	pitem->max_size = atoi(myrow[1]);
	pitem->max_user = atoi(myrow[2]);
	strcpy(pitem->title, myrow[3]);
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	strptime(myrow[4], "%Y-%m-%d", &tmp_tm);
	pitem->create_day = mktime(&tmp_tm);
	/* keep the domain privilege_bits */
	pitem->privilege_bits = atoi(myrow[5]);
	pitem->group_status = atoi(myrow[6])&0x3;
	
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT address_type, max_size FROM users WHERE "
		"group_id=%d", group_id);
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	*pactual_size = 0;
	*pactual_user = 0;
	rows = mysql_num_rows(pmyres);
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[0])) {
			continue;
		}
		*pactual_user += 1;
		*pactual_size += atoi(myrow[1]);
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_domain_homedir(const char *domainname, char *path_buff)
{
	int i;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
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

	sprintf(sql_string, "SELECT homedir FROM domains WHERE domainname='%s'",
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
		path_buff[0] = '\0';
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

BOOL data_source_info_domain(const char *domainname, int *pprivilege_bites)
{
	int i;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	*pprivilege_bites = 0;
	
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

	sprintf(sql_string, "SELECT privilege_bits FROM domains WHERE "
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
	
	if (1 == mysql_num_rows(pmyres)) {
		myrow = mysql_fetch_row(pmyres);
		*pprivilege_bites = atoi(myrow[0]);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_edit_group(const char *groupname, const char *password,
	int max_size, int max_user, const char *title, int privilege_bits,
	int group_status, int *presult)
{
	int i, j, rows;
	int domain_id;
	int domain_size;
	int domain_user;
	int group_id;
	int user_id;
	int original_status;
	int temp_status;
	int original_privilege;
	int temp_privilege;
	char *pdomain;
	char temp_domain[256];
	char temp_group[256];
	char temp_title[256];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	LOCKD lockd;
	
	pdomain = strchr(groupname, '@') + 1;

	sprintf(resource_name, "DATABASE-%s", pdomain);
	HX_strupper(resource_name);
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

	data_source_encode_squote(pdomain, temp_domain);
	sprintf(sql_string, "SELECT id, max_size, max_user, domain_type FROM "
		"domains WHERE domainname='%s'", temp_domain);
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
		*presult = EDIT_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	domain_id = atoi(myrow[0]);
	domain_size = atoi(myrow[1]);
	domain_user = atoi(myrow[2]);
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[3])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = EDIT_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	mysql_free_result(pmyres);

	if (max_size > domain_size) {
		*presult = EDIT_RESULT_SIZEEXCEED;
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (max_user > domain_user) {
		*presult = EDIT_RESULT_USREXCEED;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	data_source_encode_squote(groupname, temp_group);
	sprintf(sql_string, "SELECT id, domain_id, privilege_bits, group_status "
		"FROM groups WHERE groupname='%s'", temp_group);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	if (mysql_num_rows(pmyres) != 1) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = EDIT_RESULT_NOEXIST;
		locker_client_unlock(lockd);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	if (domain_id != atoi(myrow[1])) {
		system_log_info("[data_source]: fatal error! seems domain_id of %s "
			" in table \"groups\" is different from %s's id in "
			"table \"domains\"", groupname, pdomain);
	}
	group_id = atoi(myrow[0]);
	original_privilege = atoi(myrow[2]);
	original_status = atoi(myrow[3]);
	temp_privilege = original_privilege&0xFF;
	temp_status = original_status&0x3;
	mysql_free_result(pmyres);
	
	if (temp_privilege != privilege_bits || temp_status != group_status) {
		
		sprintf(sql_string, "SELECT id, privilege_bits, address_status "
			"FROM users WHERE group_id=%d", group_id);
		
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
			user_id = atoi(myrow[0]);
			temp_privilege = atoi(myrow[1]);
			temp_privilege &= 0xFF00FF;
			temp_privilege |= (privilege_bits << 8);
			temp_status = atoi(myrow[2]);
			temp_status &= 0x33;
			temp_status |= (group_status << 2);
			sprintf(sql_string, "UPDATE users SET privilege_bits=%d, "
				"address_status=%d WHERE id=%d", temp_privilege, temp_status,
				user_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to update privilege_bits "
					"and address_status belonging to %s", groupname); 
			}
		}
		
		mysql_free_result(pmyres);
	}

	temp_privilege = (original_privilege & 0xFF00) | privilege_bits;
	temp_status = (original_status & 0xC) | group_status;
	data_source_encode_squote(title, temp_title);
	if ('\0' == password[0]) {
		snprintf(sql_string, 4096, "UPDATE groups SET max_size=%d, "
			"max_user=%d, title='%s', privilege_bits=%d, group_status=%d "
			"WHERE id='%d'", max_size, max_user, temp_title, temp_privilege,
			temp_status, group_id);
	} else {
		snprintf(sql_string, 4096, "UPDATE groups SET password='%s', "
			"max_size=%d, max_user=%d, title='%s', privilege_bits=%d, "
			"group_status=%d WHERE id='%d'", password, max_size, max_user,
			temp_title, temp_privilege, temp_status, group_id);
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
	*presult = EDIT_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_get_group_list(const char *domainname, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	int domain_id;
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	GROUP_ITEM *pitem;
	DOUBLE_LIST_NODE *pnode;
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

	sprintf(sql_string, "SELECT groupname, max_size, max_user, title, "
		"create_day, privilege_bits, group_status FROM groups WHERE "
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
		pitem->max_size = atoi(myrow[1]);
		pitem->max_user = atoi(myrow[2]);
		strcpy(pitem->title, myrow[3]);
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		strptime(myrow[4], "%Y-%m-%d", &tmp_tm);
		pitem->create_day = mktime(&tmp_tm);
		pitem->privilege_bits = atoi(myrow[5])&0xFF;
		pitem->group_status = atoi(myrow[6])&0x3;
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}


BOOL data_source_get_group_users(const char *groupname, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	int group_id;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DOUBLE_LIST_NODE *pnode;
	USER_INFO *pitem;
	
	data_source_encode_squote(groupname, temp_name);
	
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

	sprintf(sql_string, "SELECT id FROM groups WHERE groupname='%s'",
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
	group_id = atoi(myrow[0]);
	
	mysql_free_result(pmyres);
	
	sprintf(sql_string, "SELECT username, maildir FROM users WHERE group_id=%d",
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
	
	rows = mysql_num_rows(pmyres);

	for (j=0; j<rows; j++) {
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
		myrow = mysql_fetch_row(pmyres);
		
		strcpy(pitem->username, myrow[0]);
		strcpy(pitem->maildir, myrow[1]);
		double_list_append_as_tail(&pcollect->list, pnode);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_remove_group(const char *groupname, int *presult)
{
	int i, j, rows;
	int group_id;
	int domain_id;
	char *pdomain;
	char temp_name[256];
	char domainname[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	
	/* do not lock data here, it will be locked outside by caller */
	
	pdomain = strchr(groupname, '@') + 1;
	strcpy(domainname, pdomain);
	
	
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
	data_source_encode_squote(groupname, temp_name);
	sprintf(sql_string, "SELECT id, domain_id FROM groups WHERE groupname='%s'",
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
		*presult = REMOVE_RESULT_NOTEXIST;
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	group_id = atoi(myrow[0]);
	domain_id = atoi(myrow[1]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT domainname FROM domains WHERE id=%d",
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
	
	if (1 != mysql_num_rows(pmyres)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = REMOVE_RESULT_NODOMAIN;
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	if (0 != strcasecmp(myrow[0], domainname)) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = REMOVE_RESULT_DOMAINERR;
		return TRUE;
	}

	mysql_free_result(pmyres);

	data_source_encode_squote(groupname, temp_name);
	sprintf(sql_string, "SELECT id, list_type FROM mlists WHERE "
		"listname='%s'", temp_name);
	
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
		if (MLIST_TYPE_GROUP == atoi(myrow[1])) {
			sprintf(sql_string, "DELETE FROM mlists WHERE id=%s", myrow[0]);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
			}
		}
		
	}
	mysql_free_result(pmyres);
	
	
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
		data_source_encode_squote(myrow[1], temp_name);
		sprintf(sql_string, "SELECT group_id FROM users WHERE username='%s'",
			temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			continue;
		}
		
		if (1 == mysql_num_rows(pmyres1)) {
			myrow1 = mysql_fetch_row(pmyres1);
			if (group_id != atoi(myrow1[0])) {
				mysql_free_result(pmyres1);
				continue;
			}
		}
		mysql_free_result(pmyres1);
		
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
		data_source_encode_squote(myrow[1], temp_name);
		sprintf(sql_string, "SELECT group_id FROM users WHERE username='%s'",
			temp_name);
		if (0 != mysql_query(pmysql, sql_string) ||
			NULL == (pmyres1 = mysql_store_result(pmysql))) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			continue;
		}
		
		if (1 == mysql_num_rows(pmyres1)) {
			myrow1 = mysql_fetch_row(pmyres1);
			if (group_id != atoi(myrow1[0])) {
				mysql_free_result(pmyres1);
				continue;
			}
		}
		mysql_free_result(pmyres1);
		
		sprintf(sql_string, "DELETE FROM aliases WHERE id=%s", myrow[0]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}
	mysql_free_result(pmyres);

	sprintf(sql_string, "DELETE FROM members WHERE group_id=%d", group_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}

	sprintf(sql_string, "SELECT listname FROM classes WHERE group_id=%d",
		group_id);
	if (0 == mysql_query(pmysql, sql_string) &&
		NULL != (pmyres = mysql_store_result(pmysql))) {
		rows = mysql_num_rows(pmyres);
		for (j=0; j<rows; j++) {
			myrow = mysql_fetch_row(pmyres);
			if (NULL != myrow[0]) {
				data_source_encode_squote(myrow[0], temp_name);
				sprintf(sql_string, "DELETE FROM mlists WHERE listname='%s'",
					temp_name);
				if (0 != mysql_query(pmysql, sql_string)) {
					system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				}
			}
		}
		mysql_free_result(pmyres);
	}

	sprintf(sql_string, "SELECT id FROM classes WHERE group_id=%d", group_id);
	if (0 == mysql_query(pmysql, sql_string) &&
		NULL != (pmyres = mysql_store_result(pmysql))) {
		rows = mysql_num_rows(pmyres);
		for (j=0; j<rows; j++) {
			myrow = mysql_fetch_row(pmyres);
			sprintf(sql_string, "DELETE FROM hierarchy WHERE child_id=%s",
				myrow[0]);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			}
		}
		mysql_free_result(pmyres);
	}



	sprintf(sql_string, "DELETE FROM classes WHERE group_id=%d", group_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}

	sprintf(sql_string, "DELETE FROM hierarchy WHERE group_id=%d", group_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
	sprintf(sql_string, "DELETE FROM users WHERE group_id=%d", group_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}

	
	sprintf(sql_string, "DELETE FROM groups WHERE id='%d'", group_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
	}
	
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

