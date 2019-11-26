#include <unistd.h>
#include "data_source.h"
#include "locker_client.h"
#include "system_log.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>


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

USER_ITEM* data_source_collect_get_value(DATA_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
		return NULL;
	}
	return &((DATA_NODE*)(pcollect->pnode->pdata))->item;
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

BOOL data_source_query(const char *domainname, const char *username,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, int group_id, int size_min, int size_max,
	time_t create_min, time_t create_max, int address_status,
	int address_type, DATA_COLLECT *pcollect)
{
	char *pat;
	int sub_type;
	int domain_id;
	int i, j, k;
	int rows, rows1;
	char temp_local[128];
	char temp_local1[128];
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	DATA_NODE *pdata;
	struct tm tmp_tm;
	time_t temp_time;

	i = 0;
	if (ADDRESS_TYPE_ROOM == address_type) {
		address_type = ADDRESS_TYPE_NORMAL;
		sub_type = SUB_TYPE_ROOM;
	} else if (ADDRESS_TYPE_EQUIPMENT == address_type) {
		address_type = ADDRESS_TYPE_NORMAL;
		sub_type = SUB_TYPE_EQUIPMENT;
	} else {
		sub_type = -1;
	}
	data_source_encode_squote(domainname, temp_name);
	if (NULL != username) {
		strncpy(temp_local, username, 128);
		pat = strchr(temp_local, '@');
		if (NULL != pat) {
			*pat = '\0';
		}
	}
	
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
	
	sprintf(sql_string, "SELECT id, title FROM "
		"groups WHERE domain_id='%d'", domain_id);
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres1 = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	rows1 = mysql_num_rows(pmyres1);

	
	sprintf(sql_string, "SELECT username, real_name, group_id, max_size, "
		"create_day, privilege_bits, address_status, address_type, maildir,"
		" memo, nickname, tel, cell, homeaddress, title, sub_type FROM users"
		" WHERE domain_id=%d", domain_id);
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_free_result(pmyres1);
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	rows = mysql_num_rows(pmyres);

	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[7]) &&
			ADDRESS_TYPE_ALIAS != atoi(myrow[7])) {
			continue;
		}
		if (NULL != username) {
			strncpy(temp_local1, myrow[0], 128);
			pat = strchr(temp_local1, '@');
			if (NULL != pat) {
				*pat = '\0';
			}
			if (NULL == strcasestr(temp_local1, temp_local)) {
				continue;
			}
		}
		if (NULL != title && NULL == strcasestr(myrow[14], title)) {
			continue;
		}
		if (NULL != real_name && NULL == strcasestr(myrow[1], real_name)) {
			continue;
		}
		if (NULL != memo && NULL == strcasestr(myrow[9], memo)) {
			continue;
		}
		if (NULL != nickname && NULL == strcasestr(myrow[10], nickname)) {
			continue;
		}
		if (NULL != tel  && NULL == strcasestr(myrow[11], tel)) {
			continue;
		}
		if (NULL != cell && NULL == strcasestr(myrow[12], cell)) {
			continue;
		}
		if (NULL != homeaddress && NULL == strcasestr(myrow[13], homeaddress)) {
			continue;
		}
		if (group_id >= 0 && group_id != atoi(myrow[2])) {
			continue;
		}
		if (size_min > 0 && size_min > atoi(myrow[3])) {
			continue;
		}
		if (size_max > 0 && size_max < atoi(myrow[3])) {
			continue;
		}
		if (create_min > 0) {
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			strptime(myrow[4], "%Y-%m-%d", &tmp_tm);
			temp_time = mktime(&tmp_tm);
			if (create_min > temp_time) {
				continue;
			}
		}

		if (create_max > 0) {
			memset(&tmp_tm, 0, sizeof(tmp_tm));
			strptime(myrow[4], "%Y-%m-%d", &tmp_tm);
			temp_time = mktime(&tmp_tm);
			if (create_max < temp_time) {
				continue;
			}
		}

		if (address_status >= 0 && address_status != (atoi(myrow[6])&0x3)) {
			continue;
		}
		
		if (address_type >= 0 && address_type != atoi(myrow[7])) {
			continue;
		}
		
		if (sub_type >= 0 && sub_type != atoi(myrow[15])) {
			continue;
		}
		
		pdata = (DATA_NODE*)malloc(sizeof(DATA_NODE));
		if (NULL == pdata) {
			continue;
		}
		pdata->node.pdata = pdata;
		strcpy(pdata->item.username, myrow[0]);
		strcpy(pdata->item.title, myrow[14]);
		strcpy(pdata->item.real_name, myrow[1]);
		strcpy(pdata->item.memo, myrow[9]);
		strcpy(pdata->item.nickname, myrow[10]);
		strcpy(pdata->item.tel, myrow[11]);
		strcpy(pdata->item.cell, myrow[12]);
		strcpy(pdata->item.homeaddress, myrow[13]);
		pdata->item.group_id = atoi(myrow[2]);
		pdata->item.group_title[0] = '\0';
		strcpy(pdata->item.maildir, myrow[8]);
		mysql_data_seek(pmyres1, 0);
		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			if (pdata->item.group_id == atoi(myrow1[0])) {
				strcpy(pdata->item.group_title, myrow1[1]);
				break;
			}
		}
		pdata->item.max_size = atoi(myrow[3]);
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		strptime(myrow[4], "%Y-%m-%d", &tmp_tm);
		pdata->item.create_day = mktime(&tmp_tm);
		pdata->item.privilege_bits = (atoi(myrow[5])&0xFF);
		pdata->item.address_status = (atoi(myrow[6])&0x3);
		pdata->item.address_type = atoi(myrow[7]);
		pdata->item.sub_type = atoi(myrow[15]);
		double_list_append_as_tail(&pcollect->list, &pdata->node);
	}
	
	mysql_free_result(pmyres);
	mysql_free_result(pmyres1);
	mysql_close(pmysql);

	return TRUE;
}

BOOL data_source_add_user(const char *username, const char *password,
	const char *lang, const char *title, const char *real_name,
	const char *nickname, const char *tel, const char *cell,
	const char *homeaddress, const char *memo, int group_id,
	const char *maildir, int max_size, int max_file,
	int privilege_bits, int address_status, int sub_type,
	int *presult, int *puser_id)
{
	LOCKD lockd;
	time_t now_time;
	int i, j, rows;
	int domain_id;
	int total_users;
	int total_size;
	int domain_size;
	int domain_user;
	int temp_status;
	int domain_status;
	int group_status;
	int temp_privilege;
	int domain_privilege;
	int group_privilege;
	char *pat, *pdomain;
	char temp_domain[256];
	char temp_user[256];
	char temp_address[256];
	char temp_title[256];
	char temp_real[256];
	char temp_nick[256];
	char temp_tel[40];
	char temp_cell[40];
	char temp_home[256];
	char temp_memo[256];
	char sql_string[4096];
	char str_create[16];
	char resource_name[256];
	char virtual_address[128];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm tmp_tm;
	
	time(&now_time);
	localtime_r(&now_time, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);

	pdomain = strchr(username, '@') + 1;
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
	domain_privilege = temp_privilege << 16;
	temp_status = atoi(myrow[4]);
	domain_status = temp_status << 4;
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT max_size, address_type FROM users "
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

	total_users = 0;
	total_size = 0;

	rows = mysql_num_rows(pmyres);
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL != atoi(myrow[1])) {
			continue;
		}
		total_users ++;
		total_size += atoi(myrow[0]);
	}
	mysql_free_result(pmyres);

	if (total_users >= domain_user) {
		mysql_close(pmysql);
		*presult = ADD_RESULT_USERFULL;
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (total_size + max_size > domain_size) {
		mysql_close(pmysql);
		*presult = ADD_RESULT_SIZEFULL;
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (0 != group_id) {
		sprintf(sql_string, "SELECT domain_id, privilege_bits, group_status "
			"FROM groups WHERE id=%d", group_id);
	
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
			*presult = ADD_RESULT_NOGROUP;	
			locker_client_unlock(lockd);
			return TRUE;
		}

		myrow = mysql_fetch_row(pmyres);
		if (domain_id != atoi(myrow[0])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = ADD_RESULT_GROUPERR;	
			locker_client_unlock(lockd);
			return TRUE;
		}
		temp_privilege = atoi(myrow[1]);
		temp_privilege &= 0xFF;
		group_privilege = temp_privilege << 8;
		temp_status = atoi(myrow[2]);
		temp_status &= 0x3;
		group_status = temp_status << 2;
		mysql_free_result(pmyres);
	} else {
		group_privilege = 0xFF00;
		group_status = 0;
	}

	data_source_encode_squote(username, temp_user);
	lower_string(temp_user);
	sprintf(sql_string, "SELECT address_type FROM"
		" users WHERE username='%s'", temp_user);

	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql"
				" server, reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (mysql_num_rows(pmyres) > 0) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_MLIST == atoi(myrow[0])) {
			*presult = ADD_RESULT_MLIST;
		} else {
			*presult = ADD_RESULT_EXIST;
		}
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	mysql_free_result(pmyres);

	temp_status = (domain_status|group_status|address_status);
	temp_privilege = (domain_privilege|group_privilege|privilege_bits);

	data_source_encode_squote(title, temp_title);
	data_source_encode_squote(real_name, temp_real);
	data_source_encode_squote(nickname, temp_nick);
	data_source_encode_squote(tel, temp_tel);
	data_source_encode_squote(cell, temp_cell);
	data_source_encode_squote(homeaddress, temp_home);
	data_source_encode_squote(memo, temp_memo);
	snprintf(sql_string, 4096, "INSERT INTO users (username, password, lang, "
		"title, real_name, nickname, tel, cell, homeaddress, memo, domain_id,"
		" group_id, maildir, max_size, max_file, create_day, privilege_bits, "
		"address_status, address_type, sub_type) VALUES ('%s', '%s', '%s', '%s',"
		"'%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', %d, %d, '%s', %d, %d,"
		"0, %d)", temp_user, password, lang, temp_title, temp_real, temp_nick,
		temp_tel, temp_cell, temp_home, temp_memo, domain_id, group_id, maildir,
		max_size, max_file, str_create, temp_privilege, temp_status, sub_type);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	*puser_id = mysql_insert_id(pmysql);
	sprintf(sql_string, "SELECT aliasname FROM aliases WHERE mainname='%s'",
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
	
	rows = mysql_num_rows(pmyres);

	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		strcpy(virtual_address, username);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow[0]);
		data_source_encode_squote(virtual_address, temp_address);
		lower_string(temp_address);
		snprintf(sql_string, 4096, "INSERT INTO users (username, password, "
			"lang, title, real_name, nickname, tel, cell, homeaddress, memo,"
			" domain_id, group_id, maildir, max_size, max_file, create_day, "
			"privilege_bits, address_status, address_type) VALUES ('%s', '%s',"
			" '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', "
			"%d, %d, '%s', %d, %d, 3)", temp_address, password, lang, temp_title,
			temp_real, temp_nick, temp_tel, temp_cell, temp_home, temp_memo,
			domain_id, group_id, maildir, max_size, max_file, str_create,
			temp_privilege, temp_status);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to insert virtual address %s "
				"into database", virtual_address);
		}
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	*presult = ADD_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_add_alias(const char *username, const char *alias,
	int *presult)
{
	int i, j, rows;
	int domain_id;
	int group_id;
	int max_size;
	int max_file;
	int domain_user;
	int total_alias;
	int address_type;
	int address_status;
	int privilege_bits;
	char maildir[128];
	char password[40];
	char real_name[256];
	char nickname[256];
	char title[256];
	char tel[40];
	char cell[40];
	char homeaddress[256];
	char memo[256];
	char create_day[16];
	char mobile_phone[20];
	char temp_domain[256];
	char temp_user[256];
	char temp_alias[256];
	char temp_address[256];
	char virtual_address[128];
	char *pat, *pdomain;
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	LOCKD lockd;
	
	pdomain = strchr(username, '@') + 1;
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
	
	data_source_encode_squote(pdomain, temp_domain);
	sprintf(sql_string, "SELECT id, max_user, domain_type FROM domains WHERE "
		"domainname='%s'", temp_domain);
	
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
		*presult = ALIAS_RESULT_NODOMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[2])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ALIAS_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	domain_user = atoi(myrow[1]);
	mysql_free_result(pmyres);
	
	sprintf(sql_string, "SELECT address_type FROM users WHERE domain_id=%d",
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
	
	total_alias = 0;
	
	rows = mysql_num_rows(pmyres);
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_ALIAS == atoi(myrow[0])) {
			total_alias ++;
		}
	}
	mysql_free_result(pmyres);

	if (total_alias >= domain_user) {
		mysql_close(pmysql);
		*presult = ALIAS_RESULT_FULL;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	data_source_encode_squote(alias, temp_alias);
	lower_string(temp_alias);
	sprintf(sql_string, "SELECT id, address_type FROM users WHERE "
		"username='%s'", temp_alias);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (mysql_num_rows(pmyres) > 0) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_MLIST == atoi(myrow[0])) {
			*presult = ALIAS_RESULT_MLIST;
		} else {
			*presult = ALIAS_RESULT_EXIST;
		}
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}

	mysql_free_result(pmyres);
	
	data_source_encode_squote(username, temp_user);
	lower_string(temp_user);
	sprintf(sql_string, "SELECT password, real_name, domain_id, group_id, "
		"maildir, max_size, max_file, create_day, mobile_phone, "
		"privilege_bits, address_status, address_type, memo, nickname, "
		"tel, cell, homeaddress, title FROM users WHERE username='%s'", temp_user);
	
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
		*presult = ALIAS_RESULT_NOEXIST;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	
	strcpy(password, myrow[0]);
	data_source_encode_squote(myrow[1], real_name);
	data_source_encode_squote(myrow[12], memo);
	data_source_encode_squote(myrow[13], nickname);
	data_source_encode_squote(myrow[14], tel);
	data_source_encode_squote(myrow[15], cell);
	data_source_encode_squote(myrow[16], homeaddress);
	data_source_encode_squote(myrow[17], title);
	if (atoi(myrow[2]) != domain_id) {
		system_log_info("[data_source]: fatal error! seems domain_id of %s "
			" in table \"users\" is different from %s's id in "
			"table \"domains\"", username, pdomain);
		domain_id = atoi(myrow[2]);
	}
	group_id = atoi(myrow[3]);
	strcpy(maildir, myrow[4]);
	max_size = atoi(myrow[5]);
	max_file = atoi(myrow[6]);
	strcpy(create_day, myrow[7]);
	strcpy(mobile_phone, myrow[8]);
	privilege_bits = atoi(myrow[9]);
	address_status = atoi(myrow[10]);
	address_type = atoi(myrow[11]);
	
	mysql_free_result(pmyres);

	if (ADDRESS_TYPE_NORMAL != address_type) {
		mysql_close(pmysql);
		*presult = ALIAS_RESULT_NOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	snprintf(sql_string, 4096, "INSERT INTO users (username, password, "
		"title, real_name, nickname, tel, cell, homeaddress, memo, domain_id, "
		"group_id, maildir, max_size, max_file, create_day, mobile_phone, "
		"privilege_bits, address_status, address_type) VALUES ('%s', '%s', "
		"'%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', %d, %d, "
		"'%s', '%s', %d, %d, 1)", temp_alias, password, title, real_name,
		nickname, tel, cell, homeaddress, memo, domain_id, group_id, maildir,
		max_size, max_file, create_day, mobile_phone, privilege_bits,
		address_status);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	snprintf(sql_string, 4096, "INSERT INTO aliases (aliasname, mainname) "
		"VALUES ('%s', '%s')", temp_alias, temp_user);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	sprintf(sql_string, "SELECT aliasname FROM aliases WHERE mainname='%s'",
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
	
	rows = mysql_num_rows(pmyres);

	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		strcpy(virtual_address, alias);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow[0]);
		data_source_encode_squote(virtual_address, temp_address);
		lower_string(temp_address);
		snprintf(sql_string, 4096, "INSERT INTO users (username, password, "
			"title, real_name, nickname, tel, cell, homeaddress, memo, domain_id, "
			"group_id, maildir, max_size, max_file, create_day, mobile_phone, "
			"privilege_bits, address_status, address_type) VALUES ('%s', '%s', "
			"'%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', %d, %d, "
			"'%s', '%s', %d, %d, 3)", temp_address, password, title, real_name,
			nickname, tel, cell, homeaddress, memo, domain_id, group_id,
			maildir, max_size, max_file, create_day, mobile_phone,
			privilege_bits, address_status);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to insert virtual address %s "
				"into database", virtual_address);
		}
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	*presult = ALIAS_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_get_username_by_alias(const char *username, char *user_buff)
{
	int i;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	data_source_encode_squote(username, temp_name);
		
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
	
	sprintf(sql_string, "SELECT mainname FROM aliases WHERE "
		"aliasname='%s'", temp_name);
	

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
		user_buff[0] = '\0';
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	strcpy(user_buff, myrow[0]);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_edit_user(const char *username, const char *password,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, int group_id, int max_size, int privilege_bits,
	int address_status, int *presult)
{
	int i, j, k;
	int rows, rows1;
	int domain_id;
	int domain_size;
	int user_id;
	int pregroup_id;
	int total_size;
	int address_type;
	int group_status;
	int group_privilege;
	int domain_status;
	int domain_privilege;
	char temp_alias[256];
	char temp_domain[256];
	char temp_user[256];
	char temp_title[256];
	char temp_real[256];
	char temp_nick[256];
	char temp_tel[40];
	char temp_cell[40];
	char temp_home[256];
	char temp_memo[256];
	char temp_address[256];
	char virtual_address[128];
	char *pat, *pdomain;
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	LOCKD lockd;

	pdomain = strchr(username, '@') + 1;

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

	data_source_encode_squote(pdomain, temp_domain);
	sprintf(sql_string, "SELECT id, max_size, domain_type FROM domains WHERE "
		"domainname='%s'", temp_domain);
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
	if (DOMAIN_TYPE_NORMAL != atoi(myrow[2])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = EDIT_RESULT_DOMAINNOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	mysql_free_result(pmyres);

	group_status = 0x0;
	group_privilege = 0xFF00;
	if (0 != group_id) {
		sprintf(sql_string, "SELECT domain_id, privilege_bits, group_status "
			"FROM groups WHERE id=%d", group_id);

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
			*presult = EDIT_RESULT_NOGROUP;
			locker_client_unlock(lockd);
			return TRUE;
		}
		
		myrow = mysql_fetch_row(pmyres);
		if (domain_id != atoi(myrow[0])) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = EDIT_RESULT_GROUPERR;
			locker_client_unlock(lockd);
			return TRUE;
		}
		group_privilege = (atoi(myrow[1]) & 0xFF) << 8;
		group_status = (atoi(myrow[2]) & 0x3) << 2;
		mysql_free_result(pmyres);
	}
	data_source_encode_squote(username, temp_user);
	sprintf(sql_string, "SELECT id, domain_id, max_size, privilege_bits, "
		"address_status, address_type, group_id FROM users WHERE username='%s'",
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
			" in table \"users\" is different from %s's id in "
			"table \"domains\"", username, pdomain);
	}
	if (max_size != atoi(myrow[2])) {
		sprintf(sql_string, "SELECT max_size, address_type FROM users "
			"WHERE domain_id=%d", domain_id);

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

		total_size = 0;

		rows1 = mysql_num_rows(pmyres1);
		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			if (ADDRESS_TYPE_NORMAL != atoi(myrow1[1])) {
				continue;
			}
			total_size += atoi(myrow1[0]);
		}
		mysql_free_result(pmyres1);
		if (max_size + total_size - atoi(myrow[2]) > domain_size) {
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			*presult = EDIT_RESULT_SIZEFULL;
			locker_client_unlock(lockd);
			return TRUE;
		}

	}
	user_id = atoi(myrow[0]);
	domain_privilege = atoi(myrow[3]) & 0xFF0000;
	domain_status = atoi(myrow[4]) & 0x30;
	privilege_bits |= domain_privilege | group_privilege;
	address_status |= domain_status | group_status;
	address_type = atoi(myrow[5]);
	pregroup_id = atoi(myrow[6]);
	mysql_free_result(pmyres);
	
	if (ADDRESS_TYPE_NORMAL != address_type) {
		*presult = EDIT_RESULT_NOTMAIN;
		system_log_info("[data_source]: user %s is an alias user, cannot "
			"be edited directly", username);
		locker_client_unlock(lockd);
		return TRUE;
	}

	data_source_encode_squote(title, temp_title);
	data_source_encode_squote(real_name, temp_real);
	data_source_encode_squote(nickname, temp_nick);
	data_source_encode_squote(tel, temp_tel);
	data_source_encode_squote(cell, temp_cell);
	data_source_encode_squote(homeaddress, temp_home);
	data_source_encode_squote(memo, temp_memo);

	if ('\0' == password[0]) {
		snprintf(sql_string, 4096, "UPDATE users SET title='%s', "
			"real_name='%s', nickname='%s', tel='%s', cell='%s', "
			"homeaddress='%s', memo='%s', group_id=%d, max_size=%d, "
			"privilege_bits=%d, address_status=%d WHERE id='%d'",
			temp_title, temp_real, temp_nick, temp_tel, temp_cell,
			temp_home, temp_memo, group_id, max_size, privilege_bits,
			address_status, user_id);
	} else {
		snprintf(sql_string, 4096, "UPDATE users SET password='%s', "
			"title='%s', real_name='%s', nickname='%s', tel='%s', cell='%s', "
			"homeaddress='%s', memo='%s', group_id=%d, max_size=%d, "
			"privilege_bits=%d, address_status=%d WHERE id='%d'", password,
			temp_title, temp_real, temp_nick, temp_tel, temp_cell, temp_home,
			temp_memo, group_id, max_size, privilege_bits, address_status,
			user_id);
	}
	
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
		if ('\0' == password[0]) {
			snprintf(sql_string, 4096, "UPDATE users SET title='%s', "
				"real_name='%s', nickname='%s', tel='%s', cell='%s', "
				"homeaddress='%s', memo='%s', group_id=%d, max_size=%d, "
				"privilege_bits=%d, address_status=%d WHERE username='%s'",
				temp_title, temp_real, temp_nick, temp_tel, temp_cell,
				temp_home, temp_memo, group_id, max_size, privilege_bits,
				address_status, temp_address);
		} else {
			snprintf(sql_string, 4096, "UPDATE users SET password='%s', "
				"title='%s', real_name='%s', nickname='%s', tel='%s', "
				"cell='%s', homeaddress='%s', memo='%s', group_id=%d, "
				"max_size=%d, privilege_bits=%d, address_status=%d WHERE "
				"username='%s'", password, temp_title, temp_real, temp_nick,
				temp_tel, temp_cell, temp_home, temp_memo, group_id, max_size,
				privilege_bits, address_status, temp_address);
		}
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
		if ('\0' == password[0]) {
			snprintf(sql_string, 4096, "UPDATE users SET title='%s', "
				"real_name='%s', nickname='%s', tel='%s', cell='%s', "
				"homeaddress='%s', memo='%s', group_id=%d, max_size=%d, "
				"privilege_bits=%d, address_status=%d WHERE username='%s'",
				temp_title, temp_real, temp_nick, temp_tel, temp_cell,
				temp_home, temp_memo, group_id, max_size, privilege_bits,
				address_status, temp_alias);
		} else {
			snprintf(sql_string, 4096, "UPDATE users SET password='%s', "
				"title='%s', real_name='%s', nickname='%s', tel='%s', "
				"cell='%s', homeaddress='%s', memo='%s', group_id=%d, "
				"max_size=%d, privilege_bits=%d, address_status=%d WHERE "
				"username='%s'", password, temp_title, temp_real, temp_nick,
				temp_tel, temp_cell, temp_home, temp_memo, group_id,
				max_size, privilege_bits, address_status, temp_alias);
		}
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
			if ('\0' == password[0]) {
				snprintf(sql_string, 4096, "UPDATE users SET title='%s', "
					"real_name='%s', nickname='%s', tel='%s', cell='%s', "
					"homeaddress='%s', memo='%s', group_id=%d, max_size=%d, "
					"privilege_bits=%d, address_status=%d WHERE username='%s'",
					temp_title, temp_real, temp_nick, temp_tel, temp_cell,
					temp_home, temp_memo, group_id, max_size, privilege_bits,
					address_status, temp_address);
			} else {
				snprintf(sql_string, 4096, "UPDATE users SET password='%s', "
					"title='%s', real_name='%s', nickname='%s', tel='%s', "
					"cell='%s', homeaddress='%s', memo='%s', group_id=%d, "
					"max_size=%d, privilege_bits=%d, address_status=%d WHERE "
					"username='%s'", password, temp_title, temp_real, temp_nick,
					temp_tel, temp_cell, temp_home, temp_memo, group_id,
					max_size, privilege_bits, address_status, temp_address);
			}
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

	if (group_id != pregroup_id) {
		data_source_encode_squote(username, temp_user);
		sprintf(sql_string, "DELETE FROM members WHERE username='%s'",
			temp_user);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
	}
	
	mysql_close(pmysql);
	*presult = EDIT_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_remove_user(const char *username, BOOL *pb_alias,
	DATA_COLLECT *pcollect)
{
	int i, j, k;
	int rows, rows1;
	int user_id;
	int address_type;
	char *pdomain, *pat;
	char temp_user[256];
	char temp_alias[256];
	char temp_domain[256];
	char temp_address[256];
	char virtual_address[128];
	char sql_string[4096];
	char resource_name[256];
	MYSQL *pmysql;
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	LOCKD lockd;
	DATA_NODE *pdata;
	

	pdomain = strchr(username, '@') + 1;
	data_source_encode_squote(pdomain, temp_domain);
	
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
	
	data_source_encode_squote(username, temp_user);
	snprintf(sql_string, 4096, "SELECT id, address_type FROM users "
		"WHERE username='%s'", temp_user);
	

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
		locker_client_unlock(lockd);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	user_id = atoi(myrow[0]);
	address_type = atoi(myrow[1]);
	
	mysql_free_result(pmyres);

	if (ADDRESS_TYPE_ALIAS == address_type) {
		sprintf(sql_string, "SELECT aliasname FROM aliases WHERE mainname='%s'",
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
		
		rows = mysql_num_rows(pmyres);
		
		for (j=0; j<rows; j++) {
			myrow = mysql_fetch_row(pmyres);
			strcpy(virtual_address, username);
			pat = strchr(virtual_address, '@') + 1;
			strcpy(pat, myrow[0]);
			data_source_encode_squote(virtual_address, temp_address);
			sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
				temp_address);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to delete virtual address "
					"%s from database", virtual_address);
			}
		}

		mysql_free_result(pmyres);

		sprintf(sql_string, "DELETE FROM aliases WHERE aliasname='%s'",
			temp_user);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
		
		sprintf(sql_string, "DELETE FROM associations WHERE username='%s'",
			temp_user);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
		
		sprintf(sql_string, "DELETE FROM users WHERE username='%s'", temp_user);
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
		*pb_alias = TRUE;
		return TRUE;
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

	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		data_source_encode_squote(myrow[0], temp_alias);
		sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
			temp_alias);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to delete alias address %s "
				"in database", myrow[0]);
		}
		mysql_data_seek(pmyres1, 0);
		for (k=0; k<rows1; k++) {
			myrow1 = mysql_fetch_row(pmyres1);
			strcpy(virtual_address, myrow[0]);
			pat = strchr(virtual_address, '@') + 1;
			strcpy(pat, myrow1[0]);
			data_source_encode_squote(virtual_address, temp_address);
			sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
				temp_address);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to delete alias address "
					"%s in database", virtual_address);
			}
		}
		if (NULL != pcollect) {
			pdata = (DATA_NODE*)malloc(sizeof(DATA_NODE));
			if (NULL == pdata) {
				continue;
			}
			pdata->node.pdata = pdata;
			strcpy(pdata->item.username, myrow[0]);
			double_list_append_as_tail(&pcollect->list, &pdata->node);
		}
	}
	mysql_free_result(pmyres);

	mysql_data_seek(pmyres1, 0);
	for (k=0; k<rows1; k++) {
		myrow1 = mysql_fetch_row(pmyres1);
		strcpy(virtual_address, username);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow1[0]);
		data_source_encode_squote(virtual_address, temp_address);
		sprintf(sql_string, "DELETE FROM users WHERE username='%s'",
			temp_address);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to delete virtual address "
				"%s in database", virtual_address);
		}
	}
	mysql_free_result(pmyres1);	

	sprintf(sql_string, "DELETE FROM forwards WHERE username='%s'", temp_user);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	sprintf(sql_string, "DELETE FROM aliases WHERE mainname='%s'", temp_user);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	sprintf(sql_string, "DELETE FROM associations WHERE username='%s'",
		temp_user);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	sprintf(sql_string, "DELETE FROM members WHERE username='%s'", temp_user);
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
	sprintf(sql_string, "DELETE FROM users WHERE username='%s'", temp_user);
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
	if (NULL != pb_alias) {
		*pb_alias = FALSE;
	}
	return TRUE;
		
}


BOOL data_source_get_aliases(const char *username, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DATA_NODE *pdata;
	
	data_source_encode_squote(username, temp_name);
	
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

	sprintf(sql_string, "SELECT aliasname FROM aliases "
		"WHERE mainname='%s'", temp_name);
	
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
		pdata = (DATA_NODE*)malloc(sizeof(DATA_NODE));
		if (NULL == pdata) {
			continue;
		}
		pdata->node.pdata = pdata;
		myrow = mysql_fetch_row(pmyres);
		
		strcpy(pdata->item.username, myrow[0]);
		double_list_append_as_tail(&pcollect->list, &pdata->node);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_num_user(const char *domainname, int *pnum)
{
	int i, j, rows;
	int domain_id;
	char temp_name[128];
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
		*pnum = 0;
		return TRUE;
	}

	myrow = mysql_fetch_row(pmyres);
	domain_id = atoi(myrow[0]);
	mysql_free_result(pmyres);

	sprintf(sql_string, "SELECT address_type FROM users "
		"WHERE domain_id='%d'", domain_id);
	
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
	*pnum = 0;
	
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL == atoi(myrow[0]) ||
			ADDRESS_TYPE_ALIAS == atoi(myrow[0])) {
			*pnum += 1;
		}
	}

	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_user_maildir(const char *username, char *path_buff)
{
	int i;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	data_source_encode_squote(username, temp_name);
	
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

	sprintf(sql_string, "SELECT maildir FROM users WHERE username='%s'",
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

BOOL data_source_get_domain_homedir(const char *domainname, char *path_buff)
{
	int i;
	char temp_name[128];
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

BOOL data_source_get_groups(const char *domainname, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	int domain_id;
	char temp_name[256];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DATA_NODE *pdata;
	
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
		
		pdata = (DATA_NODE*)malloc(sizeof(DATA_NODE));
		if (NULL == pdata) {
			continue;
		}
		pdata->node.pdata = pdata;
		pdata->item.group_id = atoi(myrow[0]);
		strcpy(pdata->item.group_title, myrow[1]);
		double_list_append_as_tail(&pcollect->list, &pdata->node);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_grouptitle(int group_id, char *title_buff)
{
	int i;
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

	sprintf(sql_string, "SELECT title FROM groups WHERE id='%d'", group_id);

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
	strcpy(title_buff, myrow[0]);
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_domain_privilege(const char *domainname, int *pprivilege)
{
	int i;
	char temp_name[128];
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

	if (1 != mysql_num_rows(pmyres)) {
		*pprivilege = -1;
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	*pprivilege = atoi(myrow[0]);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_check_domain_migration(const char *domainname,
	BOOL *pb_migrating, char *media_area)
{
	int i;
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	
	*pb_migrating = FALSE;
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

	sprintf(sql_string, "SELECT media FROM domains WHERE "
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
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	if (0 == strncmp(myrow[0], "<<", 2) ||
		0 == strncmp(myrow[0], ">>", 2)) {
		*pb_migrating = TRUE;
	} else {
		if (NULL != media_area) {
			media_area[0] = '\0';
			if ('\0' != myrow[0][0]) {
				if (0 == strncmp(myrow[0], "<=", 2)) {
					strcpy(media_area, myrow[0] + 2);
				} else if (0 != strncmp(myrow[0], "=>", 2)) {
					strcpy(media_area, myrow[0]);
				}
			}
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

