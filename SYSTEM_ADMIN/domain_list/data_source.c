#include <unistd.h>
#include "data_source.h"
#include "locker_client.h"
#include "system_log.h"
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

static void data_source_convert_wildcard(const char *original, char *dest);

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

DOMAIN_ITEM* data_source_collect_get_value(DATA_COLLECT *pcollect)
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

BOOL data_source_query(const char *domainname, int size_min, int size_max,
	int user_min, int user_max, const char *title, const char *address,
	const char *admin_name, const char *tel, time_t create_min,
	time_t create_max, time_t end_min, time_t end_max, int domain_status,
	int domain_type, DATA_COLLECT *pcollect)
{
	int i, j, len, offset, rows;
	char encode_buff[256];
	char sql_string[4096];
	char where_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	DATA_NODE *pdata;
	struct tm tmp_tm;
	
	offset = 0;
	
	data_source_encode_squote(domainname, encode_buff);
	len = strlen(encode_buff);

	if (0 != len) {
		strcpy(where_string, "domainname like '%");
		offset = 18;
		data_source_convert_wildcard(encode_buff,
			where_string + offset);
		offset += len;
		where_string[offset] = '%';
		offset ++;
		where_string[offset] = '\'';
		offset ++;
	}

	if (size_min > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		offset += sprintf(where_string + offset, "max_size>=%d", size_min);
	}
	
	if (size_max > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		offset += sprintf(where_string + offset, "max_size<=%d", size_max);
	}
	
	if(user_min > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		offset += sprintf(where_string + offset, "max_user>=%d", user_min);
	}

	if (user_max > 0) {
		if (0 != offset) {
			sprintf(where_string + offset, " AND ");
			offset += 5;
		}
		offset += sprintf(where_string + offset, "max_user<=%d", user_max);
	}

	data_source_encode_squote(title, encode_buff);
	len = strlen(encode_buff);

	if (0 != len) {
		if (0 != offset) {
			sprintf(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "title like '%");
		offset += 13;
		data_source_convert_wildcard(encode_buff, where_string + offset);
		offset += len;
		where_string[offset] = '%';
		offset ++;
		where_string[offset] = '\'';
		offset ++;
	}

	data_source_encode_squote(address, encode_buff);
	len = strlen(encode_buff);

	if (0 != len) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "address like '%");
		offset += 15;
		data_source_convert_wildcard(encode_buff, where_string + offset);
		offset += len;
		where_string[offset] = '%';
		offset ++;
		where_string[offset] = '\'';
		offset ++;
	}

	data_source_encode_squote(admin_name, encode_buff);
	len = strlen(encode_buff);

	if (0 != len) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "admin_name like '%");
		offset += 18;
		data_source_convert_wildcard(encode_buff, where_string + offset);
		offset += len;
		where_string[offset] = '%';
		offset ++;
		where_string[offset] = '\'';
		offset ++;
	}

	data_source_encode_squote(tel, encode_buff);
	len = strlen(encode_buff);

	if (0 != len) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "tel like '%");
		offset += 11;
		data_source_convert_wildcard(encode_buff, where_string + offset);
		offset += len;
		where_string[offset] = '%';
		offset ++;
		where_string[offset] = '\'';
		offset ++;
	}

	if (create_min > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "create_day>='");
		offset += 13;
		localtime_r(&create_min, &tmp_tm);
		offset += strftime(where_string + offset, 4096 - offset,
			"%Y-%m-%d", &tmp_tm);
		where_string[offset] = '\'';
		offset ++;
	}
	
	if (create_max > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "create_day<='");
		offset += 13;
		localtime_r(&create_max, &tmp_tm);
		offset += strftime(where_string + offset, 4096 - offset,
			"%Y-%m-%d", &tmp_tm);
		where_string[offset] = '\'';
		offset ++;
	}
	
	if (end_min > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "end_day>='");
		offset += 10;
		localtime_r(&end_min, &tmp_tm);
		offset += strftime(where_string + offset, 4096 - offset,
			"%Y-%m-%d", &tmp_tm);
		where_string[offset] = '\'';
		offset ++;
	}
	
	if (end_max > 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		strcpy(where_string + offset, "end_day<='");
		offset += 10;
		localtime_r(&end_max, &tmp_tm);
		offset += strftime(where_string + offset, 4096 - offset,
			"%Y-%m-%d", &tmp_tm);
		where_string[offset] = '\'';
		offset ++;
	}

	if (domain_status >= 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		offset += sprintf(where_string + offset, "domain_status=%d",
						domain_status);
	}

	if (domain_type >= 0) {
		if (0 != offset) {
			strcpy(where_string + offset, " AND ");
			offset += 5;
		}
		offset += sprintf(where_string + offset, "domain_type=%d", domain_type);
	}
	
	
	where_string[offset] = '\0';
	
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

	len = sprintf(sql_string, "SELECT domainname, max_size, max_user, title, "
		"address, admin_name, tel, create_day, end_day, privilege_bits, "
		"domain_status, domain_type, media FROM domains");
	if (offset > 0) {
		len += sprintf(sql_string + len, " WHERE %s", where_string);
	}
	
	sprintf(sql_string + len, " ORDER BY create_day");
	
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
		
		strcpy(pdata->item.domainname, myrow[0]);
		pdata->item.max_size = atoi(myrow[1]);
		pdata->item.max_user = atoi(myrow[2]);
		strcpy(pdata->item.title, myrow[3]);
		strcpy(pdata->item.address, myrow[4]);
		strcpy(pdata->item.admin_name, myrow[5]);
		strcpy(pdata->item.tel, myrow[6]);
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		strptime(myrow[7], "%Y-%m-%d", &tmp_tm);
		pdata->item.create_day = mktime(&tmp_tm);
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		strptime(myrow[8], "%Y-%m-%d", &tmp_tm);
		pdata->item.end_day = mktime(&tmp_tm);
		pdata->item.privilege_bits = atoi(myrow[9]);
		pdata->item.domain_status = atoi(myrow[10]);
		pdata->item.domain_type = atoi(myrow[11]);
		strcpy(pdata->item.media, myrow[12]);
		
		double_list_append_as_tail(&pcollect->list, &pdata->node);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);

	return TRUE;
}

BOOL data_source_info_domain(const char *domainname, DOMAIN_ITEM *pitem,
	int *pactual_size, int *pactual_user)
{
	int i, j, rows;
	int domain_id;
	char temp_name[128];
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	struct tm tmp_tm;
	int total_size;
	int total_user;
	
	
	*pactual_size = 0;
	*pactual_user = 0;

	data_source_encode_squote(domainname, temp_name);
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		pitem->domainname[0] = '\0';
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
	
	sprintf(sql_string, "SELECT id, domainname, max_size, max_user, title, "
		"address, admin_name, tel, create_day, end_day, privilege_bits, "
		"domain_status, domain_type, media FROM domains WHERE domainname='%s'",
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
		pitem->domainname[0] = '\0';
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);

	domain_id = atoi(myrow[0]);
	strcpy(pitem->domainname, myrow[1]);
	pitem->max_size = atoi(myrow[2]);
	pitem->max_user = atoi(myrow[3]);
	strcpy(pitem->title, myrow[4]);
	strcpy(pitem->address, myrow[5]);
	strcpy(pitem->admin_name, myrow[6]);
	strcpy(pitem->tel, myrow[7]);
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	strptime(myrow[8], "%Y-%m-%d", &tmp_tm);
	pitem->create_day = mktime(&tmp_tm);
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	strptime(myrow[9], "%Y-%m-%d", &tmp_tm);
	pitem->end_day = mktime(&tmp_tm);
	pitem->privilege_bits = atoi(myrow[10]);
	pitem->domain_status = atoi(myrow[11]);
	pitem->domain_type = atoi(myrow[12]);
	strcpy(pitem->media, myrow[13]);
	
	mysql_free_result(pmyres);

	if (DOMAIN_TYPE_ALIAS == pitem->domain_type) {
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
		if (1 == mysql_num_rows(pmyres)) {
			myrow = mysql_fetch_row(pmyres);
			data_source_encode_squote(myrow[0], temp_name);
			sprintf(sql_string, "SELECT id FROM domains WHERE domainname='%s'",
				temp_name);
			mysql_free_result(pmyres);
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
				domain_id = atoi(myrow[0]);
			}
		}
		mysql_free_result(pmyres);
	}
	
	sprintf(sql_string, "SELECT max_size, address_type FROM users WHERE "
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
	total_size = 0;
	total_user = 0;
	for (j=0; j<rows; j++) {
		myrow = mysql_fetch_row(pmyres);
		if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])) {
			total_size += atoi(myrow[0]);
			total_user ++;
		}
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	*pactual_size = total_size;
	*pactual_user = total_user;
	return TRUE;
}

BOOL data_source_add_domain(const char *domainname, const char *homedir,
	const char *media, int max_size, int max_user, const char *title,
	const char *address, const char *admin_name, const char *tel,
	time_t create_day, time_t end_day, int privilege_bits,
	int domain_status, int *presult, int *pdomain_id)
{
	int i;
	char temp_domain[128];
	char temp_title[256];
	char temp_address[256];
	char temp_admin[64];
	char temp_tel[128];
	char sql_string[4096];
	char str_end[16];
	char str_create[16];
	MYSQL_RES *pmyres;
	MYSQL *pmysql;
	struct tm tmp_tm;
	
	
	localtime_r(&create_day, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);

	localtime_r(&end_day, &tmp_tm);
	strftime(str_end, 16, "%Y-%m-%d", &tmp_tm);

	data_source_encode_squote(domainname, temp_domain);
	lower_string(temp_domain);
	data_source_encode_squote(title, temp_title);
	data_source_encode_squote(address, temp_address);
	data_source_encode_squote(admin_name, temp_admin);
	data_source_encode_squote(tel, temp_tel);
	
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
	
	sprintf(sql_string, "SELECT domainname FROM domains WHERE "
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
	
	if (mysql_num_rows(pmyres) > 0) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ADD_RESULT_EXIST;
		return TRUE;
	}
	
	mysql_free_result(pmyres);
	

	snprintf(sql_string, 4096, "INSERT INTO domains (domainname, homedir, "
		"media, max_size, max_user, title, address, admin_name, tel, "
		"create_day, end_day, privilege_bits, domain_status, domain_type) "
		"VALUES ('%s', '%s', '%s', %d, %d, '%s', '%s', '%s', '%s', '%s', "
		"'%s', %d, %d, 0)", temp_domain, homedir, media, max_size, max_user,
		temp_title, temp_address, temp_admin, temp_tel, str_create, str_end,
		privilege_bits, domain_status);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	*pdomain_id = mysql_insert_id(pmysql);
	mysql_close(pmysql);
	*presult = ADD_RESULT_OK;
	return TRUE;
}


BOOL data_source_add_alias(const char *domainname, const char *alias,
	int *presult)
{
	int i, j;
	int rows;
	int domain_id;
	int max_size;
	int max_user;
	int domain_type;
	int domain_status;
	int privilege_bits;
	char temp_domain[128];
	char temp_alias[128];
	char homedir[128];
	char password[40];
	char create_day[16];
	char end_day[16];
	char title[256];
	char address[256];
	char admin_name[64];
	char tel[128], *pat;
	char sql_string[4096];
	char temp_address[256];
	char temp_real[64];
	char temp_nick[64];
	char temp_tel[40];
	char temp_cell[40];
	char temp_home[256];
	char temp_memo[256];
	char alias_address[128];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	LOCKD lockd;
	struct tm tmp_tm;
	
	
	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);

	data_source_encode_squote(domainname, temp_domain);
	lower_string(temp_domain);
	data_source_encode_squote(alias, temp_alias);
	lower_string(temp_alias);
	
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
	
	sprintf(sql_string, "SELECT domainname FROM domains WHERE "
		"domainname='%s'", temp_alias);
	
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
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ALIAS_RESULT_EXIST;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	mysql_free_result(pmyres);
	
	sprintf(sql_string, "SELECT id, password, homedir, max_size, max_user, "
		"title, address, admin_name, tel, create_day, end_day, privilege_bits, "
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
	
	if (mysql_num_rows(pmyres) != 1) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = ALIAS_RESULT_NOEXIST;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	
	domain_id = atoi(myrow[0]);
	strcpy(password, myrow[1]);
	strcpy(homedir, myrow[2]);
	max_size = atoi(myrow[3]);
	max_user = atoi(myrow[4]);
	data_source_encode_squote(myrow[5], title);
	data_source_encode_squote(myrow[6], address);
	data_source_encode_squote(myrow[7], admin_name);
	data_source_encode_squote(myrow[8], tel);
	strcpy(create_day, myrow[9]);
	strcpy(end_day, myrow[10]);
	privilege_bits = atoi(myrow[11]);
	domain_status = atoi(myrow[12]);
	domain_type = atoi(myrow[13]);
	
	mysql_free_result(pmyres);

	if (DOMAIN_TYPE_NORMAL != domain_type) {
		mysql_close(pmysql);
		*presult = ALIAS_RESULT_NOTMAIN;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	snprintf(sql_string, 4096, "INSERT INTO domains (domainname, password, "
		"homedir, max_size, max_user, title, address, admin_name, tel, "
		"create_day, end_day, privilege_bits, domain_status, domain_type) "
		"VALUES ('%s', '%s', '%s', %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', "
		"%d, %d, 1)", temp_alias, password, homedir, max_size, max_user, title,
		address, admin_name, tel, create_day, end_day, privilege_bits,
		domain_status);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	snprintf(sql_string, 4096, "INSERT INTO aliases (aliasname, mainname) "
		"VALUES ('%s', '%s')", temp_alias, temp_domain);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	snprintf(sql_string, 4096, "SELECT username, password, real_name, "
		"group_id, maildir, max_size, max_file, create_day, mobile_phone, "
		"privilege_bits, address_status, address_type, memo, nickname, "
		"tel, cell, homeaddress FROM users WHERE domain_id=%d", domain_id);

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
		if (ADDRESS_TYPE_VIRTUAL == atoi(myrow[11])) {
			continue;
		}
		strcpy(alias_address, myrow[0]);
		pat = strchr(alias_address, '@');
		if (NULL == pat) {
			continue;
		}
		strcpy(pat + 1, alias);
		data_source_encode_squote(alias_address, temp_address);
		lower_string(temp_address);
		data_source_encode_squote(myrow[2], temp_real);
		data_source_encode_squote(myrow[12], temp_memo);
		data_source_encode_squote(myrow[13], temp_nick);
		data_source_encode_squote(myrow[14], temp_tel);
		data_source_encode_squote(myrow[15], temp_cell);
		data_source_encode_squote(myrow[16], temp_home);
		snprintf(sql_string, 4096, "INSERT INTO users (username, password, "
			"real_name, nickname, tel, cell, homeaddress, memo, domain_id, "
			"group_id, maildir, max_size, max_file, create_day, mobile_phone, "
			"privilege_bits, address_status, address_type) VALUES ('%s', "
			"'%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %s, '%s', %s, "
			"%s, '%s', '%s', %s, %s, 3)", temp_address, myrow[1], temp_real,
			temp_nick, temp_tel, temp_cell, temp_home, temp_memo, domain_id,
			myrow[3], myrow[4], myrow[5], myrow[6], myrow[7], myrow[8],
			myrow[9], myrow[10]);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to insert virtual user %s "
				"into database", alias_address);
		}	
	}
	mysql_free_result(pmyres);
	
	mysql_close(pmysql);
	*presult = ALIAS_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_get_domain_by_alias(const char *domainname, char *domain_buff)
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
		domain_buff[0] = '\0';
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	strcpy(domain_buff, myrow[0]);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_edit_domain(const char *domainname, const char *media,
	int max_size, int max_user, const char *title, const char *address,
	const char *admin_name, const char *tel, time_t create_day,
	time_t end_day, int privilege_bits, int domain_status, int *presult)
{
	int rows;
	int rows1;
	int i, j, k;
	int domain_id;
	int temp_id;
	int temp_status;
	int temp_status1;
	int temp_privilege;
	int temp_privilege1;
	int fake_status;
	int domain_type;
	int original_status;
	int original_privilege;
	char old_media[128];
	char to_media[128];
	char temp_alias[128];
	char temp_domain[128];
	char temp_title[256];
	char temp_address[256];
	char temp_admin[64];
	char temp_tel[128];
	char sql_string[4096];
	char str_end[16];
	char str_create[16];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_RES *pmyres1;
	MYSQL_ROW myrow;
	MYSQL_ROW myrow1;
	MYSQL *pmysql;
	LOCKD lockd;
	time_t now_time;
	struct tm tmp_tm;
	
	
	
	localtime_r(&create_day, &tmp_tm);
	strftime(str_create, 16, "%Y-%m-%d", &tmp_tm);

	localtime_r(&end_day, &tmp_tm);
	strftime(str_end, 16, "%Y-%m-%d", &tmp_tm);
	
	time(&now_time);

	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	data_source_encode_squote(domainname, temp_domain);
	data_source_encode_squote(title, temp_title);
	data_source_encode_squote(address, temp_address);
	data_source_encode_squote(admin_name, temp_admin);
	data_source_encode_squote(tel, temp_tel);
	
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
	
	sprintf(sql_string, "SELECT id, privilege_bits, domain_status, "
		"domain_type, media FROM domains WHERE domainname='%s'", temp_domain);
	

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
	domain_id = atoi(myrow[0]);
	original_privilege = atoi(myrow[1]);
	original_status = atoi(myrow[2]);
	domain_type = atoi(myrow[3]);
	strcpy(old_media, myrow[4]);
	mysql_free_result(pmyres);

	if (0 == strcmp(media, "nochange")) {
		strcpy(to_media, old_media);
		goto DOMAIN_UPDATE;
	}

	if (0 == strncmp(old_media, "<<", 2) ||
		0 == strncmp(old_media, ">>", 2)) {
		mysql_close(pmysql);
		*presult = EDIT_RESULT_MIGRATING;
		system_log_info("[data_source]: cannot change domain %s' storage "
			"from one media to another directly", domainname);
		locker_client_unlock(lockd);
		return TRUE;
	}

	if ('\0' != old_media[0] && '\0' != media[0] &&
		0 != strcmp(old_media + 2, media)) {
		mysql_close(pmysql);
		*presult = EDIT_RESULT_ERROR;
		system_log_info("[data_source]: cannot change domain %s' storage "
			"from one media to another directly", domainname);
		locker_client_unlock(lockd);
		return TRUE;
	}

	to_media[0] = '\0';
	if ('\0' == old_media[0] && '\0' != media[0]) {
		sprintf(to_media, "=>%s", media);
	} else if ('\0' != old_media[0] && '\0' == media[0]) {
		if (0 == strncmp(old_media, "=>", 2)) {
			to_media[0] = '\0';
		} else if (0 == strncmp(old_media, "<=", 2)) {
			strcpy(to_media, old_media);
		} else {
			sprintf(to_media, "<=%s", old_media);
		}
	} else if ('\0' != old_media[0] && '\0' != media[0]) {
		if (0 == strncmp(old_media, "<=", 2)) {
			strcpy(to_media, media);		
		} else if (0 == strncmp(old_media, "=>", 2)) {
			strcpy(to_media, old_media);
		}
	}
	
DOMAIN_UPDATE:
	
	if (DOMAIN_TYPE_NORMAL != domain_type) {
		mysql_close(pmysql);
		*presult = EDIT_RESULT_ERROR;
		system_log_info("[data_source]: domain %s is an alias domain, cannot "
			"be edited directly", domainname);
		locker_client_unlock(lockd);
		return TRUE;
	}

	if (RECORD_STATUS_OUTOFDATE == original_status && end_day > now_time) {
		domain_status = RECORD_STATUS_NORMAL;
	}
	
	snprintf(sql_string, 4096, "UPDATE domains SET media='%s', max_size=%d, "
		"max_user=%d, title='%s', address='%s', admin_name='%s', tel='%s', "
		"create_day='%s', end_day='%s', privilege_bits=%d, domain_status=%d "
		"WHERE id='%d'", to_media, max_size, max_user, temp_title,
		temp_address, temp_admin, temp_tel, str_create, str_end,
		privilege_bits, domain_status, domain_id);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	/* 
	 * update all group and user status belonging to the domain,
	 * if status changes or privilege changes
	 */ 
	if (original_privilege != privilege_bits ||
		original_status != domain_status) {
		snprintf(sql_string, 4096, "SELECT id, privilege_bits, group_status "
			"FROM groups WHERE domain_id=%d", domain_id);
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
			temp_privilege = atoi(myrow[1]);
			temp_privilege &= 0xFF;
			temp_privilege1 = privilege_bits << 8;
			temp_privilege |= temp_privilege1;
			temp_status = atoi(myrow[2]);
			temp_status &= 0x3;
			temp_status1 = domain_status << 2;
			temp_status |= temp_status1;
			snprintf(sql_string, 4096, "UPDATE groups SET privilege_bits=%d, "
				"group_status=%d WHERE id=%d", temp_privilege, temp_status,
				temp_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to update privilege_bits "
					"and group_status of group belonging to %s", domainname);
			}
		}
		mysql_free_result(pmyres);

		snprintf(sql_string, 4096, "SELECT id, privilege_bits, address_status "
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
			temp_id = atoi(myrow[0]);
			temp_privilege = atoi(myrow[1]);
			temp_privilege &= 0xFFFF;
			temp_privilege1 = privilege_bits << 16;
			temp_privilege |= temp_privilege1;
			temp_status = atoi(myrow[2]);
			temp_status &= 0xF;
			temp_status1 = domain_status << 4;
			temp_status |= temp_status1;
			snprintf(sql_string, 4096, "UPDATE users SET privilege_bits=%d, "
				"address_status=%d WHERE id=%d", temp_privilege, temp_status,
				temp_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to update privilege_bits "
					"and address_status of user belonging to %s", domainname);
			}
		}
		mysql_free_result(pmyres);	
	}
	
	/* update alias' record */
	snprintf(sql_string, 4096, "SELECT aliasname FROM aliases WHERE "
		"mainname='%s'", temp_domain);
	
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
		data_source_encode_squote(myrow[0], temp_alias);
		snprintf(sql_string, 4096, "SELECT id, domain_status FROM "
			"domains WHERE domainname='%s'", temp_alias);
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
		
		myrow1 = mysql_fetch_row(pmyres1);
		domain_id = atoi(myrow1[0]);
		original_status = atoi(myrow1[1]);
		mysql_free_result(pmyres1);
		
		if (RECORD_STATUS_DELETED == original_status) {
			fake_status = RECORD_STATUS_DELETED;
		} else {
			fake_status = domain_status;
		}
		
		snprintf(sql_string, 4096, "UPDATE domains SET max_size=%d, "
		"max_user=%d, title='%s', address='%s', admin_name='%s', tel='%s', "
		"create_day='%s', end_day='%s', privilege_bits=%d, domain_status=%d "
		"WHERE id='%d'", max_size, max_user, temp_title, temp_address,
		temp_admin, temp_tel, str_create, str_end, privilege_bits,
		fake_status, domain_id);

		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_free_result(pmyres);
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
	}
	
	mysql_free_result(pmyres);	
	mysql_close(pmysql);
	*presult = EDIT_RESULT_OK;
	locker_client_unlock(lockd);
	return TRUE;
}

BOOL data_source_remove_domain(const char *domainname)
{
	int rows;
	int rows1;
	int i, j, k;
	int temp_id;
	int domain_id;
	int domain_type;
	int temp_status;
	int temp_status1;
	char temp_domain[128];
	char temp_alias[128];
	char *pat, mainname[128];
	char alias_address[128];
	char sql_string[4096];
	char resource_name[256];
	MYSQL *pmysql;
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	LOCKD lockd;
	

	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	data_source_encode_squote(domainname, temp_domain);
	
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

	snprintf(sql_string, 4096, "SELECT id, domain_type FROM domains "
		"WHERE domainname='%s'", temp_domain);
	

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
	domain_id = atoi(myrow[0]);
	domain_type = atoi(myrow[1]);
	
	mysql_free_result(pmyres);
		
	snprintf(sql_string, 4096, "UPDATE domains SET domain_status=3 "
		"WHERE id='%d'", domain_id);

	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	if (DOMAIN_TYPE_ALIAS == domain_type) {
		snprintf(sql_string, 4096, "SELECT mainname FROM aliases WHERE "
			"aliasname='%s'", temp_domain);
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
		data_source_encode_squote(myrow[0], mainname);
		mysql_free_result(pmyres);
		
		snprintf(sql_string, 4096, "SELECT id FROM domains WHERE "
			"domainname='%s'", mainname);
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
		domain_id = atoi(myrow[0]);
		mysql_free_result(pmyres);
		snprintf(sql_string, 4096, "SELECT id, username, address_status, "
			"address_type FROM users WHERE domain_id=%d", domain_id);
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
			if (ADDRESS_TYPE_VIRTUAL != atoi(myrow[3])) {
				continue;
			}
			temp_id = atoi(myrow[0]);
			strcpy(alias_address, myrow[1]);
			pat = strchr(alias_address, '@');
			if (NULL == pat || 0 != strcasecmp(pat + 1, domainname)) {
				continue;
			}
			temp_status = atoi(myrow[2]);
			temp_status &= 0xF;
			temp_status1 = RECORD_STATUS_DELETED << 4;
			temp_status |= temp_status1;
			snprintf(sql_string, 4096, "UPDATE users SET address_status=%d "
				"WHERE id=%d", temp_status, temp_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to update address_status "
					"of address belonging to %s", domainname);
			}
		}
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	/* update all group belonging to the domain */ 
	snprintf(sql_string, 4096, "SELECT id, group_status FROM groups "
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
		temp_status &= 0x3;
		temp_status1 = RECORD_STATUS_DELETED << 2;
		temp_status |= temp_status1;
		snprintf(sql_string, 4096, "UPDATE groups SET group_status=%d "
			"WHERE id=%d", temp_status, temp_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to update group_status "
				"of group belonging to %s", domainname);
		}
	}
	mysql_free_result(pmyres);
	
	snprintf(sql_string, 4096, "SELECT id, address_status FROM users "
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
		temp_status &= 0xF;
		temp_status1 = RECORD_STATUS_DELETED << 4;
		temp_status |= temp_status1;
		snprintf(sql_string, 4096, "UPDATE users SET address_status=%d "
			"WHERE id=%d", temp_status, temp_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to update address_status "
				"of address belonging to %s", domainname);
		}
	}
	mysql_free_result(pmyres);
	
	
	/* update alias' record */
	snprintf(sql_string, 4096, "SELECT aliasname FROM aliases WHERE "
		"mainname='%s'", temp_domain);
	
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
		data_source_encode_squote(myrow[0], temp_alias);
		snprintf(sql_string, 4096, "UPDATE domains SET domain_status=3 "
			"WHERE domainname='%s'", temp_alias);

		if (0 != mysql_query(pmysql, sql_string)) {
			mysql_free_result(pmyres);
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}
	}
	
	mysql_free_result(pmyres);	
	mysql_close(pmysql);
	locker_client_unlock(lockd);
	return TRUE;
}


BOOL data_source_restore_domain(const char *domainname, int *presult,
	int *pstatus)
{
	int i, j, rows;
	int temp_id;
	int domain_id;
	int fake_status;
	int temp_status;
	int temp_status1;
	int domain_type;
	char temp_domain[128];
	char temp_alias[128];
	char *pat, mainname[128];
	char alias_address[128];
	char sql_string[4096];
	char resource_name[256];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	LOCKD lockd;
	
	
	sprintf(resource_name, "DATABASE-%s", domainname);
	upper_string(resource_name);
	lockd = locker_client_lock(resource_name);
	
	data_source_encode_squote(domainname, temp_domain);
	
	i = 0;

	fake_status = RECORD_STATUS_NORMAL;
	
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
	
	snprintf(sql_string, 4096, "SELECT id, domain_type, domain_status FROM "
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
	
	if (mysql_num_rows(pmyres) != 1) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = RESTORE_RESULT_ERROR;
		locker_client_unlock(lockd);
		return TRUE;
	}
	myrow = mysql_fetch_row(pmyres);
	if (RECORD_STATUS_DELETED != atoi(myrow[2])) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = RESTORE_RESULT_ERROR;
		locker_client_unlock(lockd);
		return TRUE;
	}
	domain_id = atoi(myrow[0]);
	domain_type = atoi(myrow[1]);
	mysql_free_result(pmyres);

	if (DOMAIN_TYPE_ALIAS == domain_type) {
		/* check if the main domain is deleted? */
		snprintf(sql_string, 4096, "SELECT mainname FROM aliases WHERE "
			"aliasname='%s'", temp_domain);
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
			*presult = RESTORE_RESULT_ERROR;
			system_log_info("[data_source]: row number of alias %s in aliases "
				"table does not match", domainname);
			locker_client_unlock(lockd);
			return TRUE;
		}
		myrow = mysql_fetch_row(pmyres);
		data_source_encode_squote(myrow[0], mainname);
		mysql_free_result(pmyres);
		snprintf(sql_string, 4096, "SELECT id, domain_status FROM domains "
			"WHERE domainname='%s'", mainname);
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
			*presult = RESTORE_RESULT_ERROR;
			system_log_info("[data_source]: cannot find and information of "
				"domain %s in domains table", domainname);
			locker_client_unlock(lockd);
			return TRUE;
		}
		myrow = mysql_fetch_row(pmyres);
		domain_id = atoi(myrow[0]);
		fake_status = atoi(myrow[1]);
		mysql_free_result(pmyres);
		
		if (RECORD_STATUS_DELETED == fake_status) {
			mysql_close(pmysql);
			*presult = RESTORE_RESULT_ALIAS;
			locker_client_unlock(lockd);
			return TRUE;
		}
		
		snprintf(sql_string, 4096, "SELECT id, username, address_status, "
			"address_type FROM users WHERE domain_id=%d", domain_id);
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
			if (ADDRESS_TYPE_VIRTUAL != atoi(myrow[3])) {
				continue;
			}
			temp_id = atoi(myrow[0]);
			strcpy(alias_address, myrow[1]);
			pat = strchr(alias_address, '@');
			if (NULL == pat || 0 != strcasecmp(pat + 1, domainname)) {
				continue;
			}
			temp_status = atoi(myrow[2]);
			temp_status &= 0xF;
			temp_status1 = RECORD_STATUS_NORMAL << 4;
			temp_status |= temp_status1;
			snprintf(sql_string, 4096, "UPDATE users SET address_status=%d "
				"WHERE id=%d", temp_status, temp_id);
			if (0 != mysql_query(pmysql, sql_string)) {
				system_log_info("[data_source]: fail to query mysql server, "
					"reason: %s", mysql_error(pmysql));
				system_log_info("[data_source]: fail to update address_status "
					"of address belonging to %s", domainname);
			}
		}
		mysql_free_result(pmyres);	
		
		snprintf(sql_string, 4096, "UPDATE domains SET domain_status=%d "
			"WHERE domainname='%s'", fake_status, temp_domain);
		
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			mysql_close(pmysql);
			i ++;
			sleep(1);
			goto RETRYING;
		}

		mysql_close(pmysql);
		*presult = RESTORE_RESULT_OK;
		*pstatus = fake_status;
		locker_client_unlock(lockd);
		return TRUE;
	}
	
	/* update all group and user status */ 
	snprintf(sql_string, 4096, "SELECT id, group_status FROM groups "
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
		temp_status &= 0x3;
		temp_status1 = RECORD_STATUS_NORMAL << 2;
		temp_status |= temp_status1;
		snprintf(sql_string, 4096, "UPDATE groups SET group_status=%d "
			"WHERE id=%d", temp_status, temp_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to update group_status "
				"of group belonging to %s", domainname);
		}
	}
	mysql_free_result(pmyres);
	
	snprintf(sql_string, 4096, "SELECT id, address_status FROM users "
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
		temp_status &= 0xF;
		temp_status1 = RECORD_STATUS_NORMAL << 4;
		temp_status |= temp_status1;
		snprintf(sql_string, 4096, "UPDATE users SET address_status=%d "
			"WHERE id=%d", temp_status, temp_id);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[data_source]: fail to update address_status "
				"of address belonging to %s", domainname);
		}
	}
	mysql_free_result(pmyres);	
	
	snprintf(sql_string, 4096, "UPDATE domains SET domain_status=0 "
		"WHERE id=%d", domain_id);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}

	mysql_close(pmysql);
	*presult = RESTORE_RESULT_OK;
	*pstatus = 0;
	locker_client_unlock(lockd);
	return TRUE;
}


BOOL data_source_get_alias(const char *domainname, DATA_COLLECT *pcollect)
{
	int i, j, rows;
	char temp_name[128];
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
		
		strcpy(pdata->item.domainname, myrow[0]);
		double_list_append_as_tail(&pcollect->list, &pdata->node);
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_num_domain(int *pnum)
{
	int i;
	char sql_string[128];
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

	sprintf(sql_string, "SELECT count(*) FROM domains");
	
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
		i ++;
		sleep(1);
		goto RETRYING;
	}
	myrow = mysql_fetch_row(pmyres);
	*pnum = atoi(myrow[0]);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_domain_password(const char *domainname, const char *encryt_pw,
	int *presult)
{
	int i, j, rows;
	char temp_name[128];
	char temp_alias[128];
	char sql_string[1024];
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
		*presult = PASSWORD_RESULT_NOEXIST;
		return TRUE;
	}
	
	myrow = mysql_fetch_row(pmyres);
	if (atoi(myrow[0]) != DOMAIN_TYPE_NORMAL) {
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		*presult = PASSWORD_RESULT_ALIAS;
		return TRUE;
	}
	
	mysql_free_result(pmyres);
	sprintf(sql_string, "UPDATE domains SET password='%s' WHERE "
		"domainname='%s'", encryt_pw, temp_name);
	
	if (0 != mysql_query(pmysql, sql_string)) {
		system_log_info("[data_source]: fail to query mysql server, "
			"reason: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		i ++;
		sleep(1);
		goto RETRYING;
	}
	
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
		data_source_encode_squote(myrow[0], temp_alias);
		sprintf(sql_string, "UPDATE domains SET password='%s' WHERE "
			"domainname='%s'", encryt_pw, temp_alias);
		if (0 != mysql_query(pmysql, sql_string)) {
			system_log_info("[data_source]: fail to query mysql server, "
				"reason: %s", mysql_error(pmysql));
			system_log_info("[system_log]: fail to unpdate password of alias "
				"domain %s", myrow[0]);
		}
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	*presult = PASSWORD_RESULT_OK;
	return TRUE;
}

static void data_source_convert_wildcard(const char *original, char *dest)
{
	int i, len;

	len = strlen(original);

	for (i=0; i<len; i++) {
		if ('*' == original[i]) {
			dest[i] = '%';
		} else if ('?' == original[i]) {
			dest[i] = '_';
		} else {
			dest[i] = original[i];
		}
	}
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

