#include "data_source.h"
#include "system_log.h"
#include <mysql/mysql.h>
#include <string.h>

#define RECORD_STATUS_NORMAL                0

#define RECORD_STATUS_SUSPEND               1

#define RECORD_STATUS_OUTOFDATE             2

#define RECORD_STATUS_DELETED               3

#define DOMAIN_TYPE_NORMAL                  0

#define DOMAIN_TYPE_ALIAS                   1

#define ADDRESS_TYPE_NORMAL                 0

#define ADDRESS_TYPE_ALIAS                  1

#define ADDRESS_TYPE_MLIST                  2

#define ADDRESS_TYPE_VIRTUAL                3

#define DOMAIN_PRIVILEGE_BACKUP             0x1

#define DOMAIN_PRIVILEGE_MONITOR            0x2

#define DOMAIN_PRIVILEGE_UNCHECKUSR         0x4

#define DOMAIN_PRIVILEGE_SUBSYSTEM          0x8

#define DOMAIN_PRIVILEGE_NETDISK            0x10

#define DOMAIN_PRIVILEGE_EXTPASSWD          0x20

static char g_host[256];
static int g_port;
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];


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

BOOL data_source_system_info(int *preal_domains, int *pbackup, int *pmonitor,
	int *punchkusr, int *psubsys, int *psms, int *pextpasswd, int *palias_domains,
	int *poutofdate, int *pdeleted, int *psuspend, int *pgroups,
	int *palloc_addresses, int *preal_addresses, int *palias_address,
	int *pmlists, long *ptotal_space)
{
	int i, j, rows;
	int temp_type;
	int temp_status;
	int temp_privileges;
	char sql_string[1024];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	
	i = 0;
	
RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	*preal_domains = 0;
	*pbackup = 0;
	*pmonitor = 0;
	*punchkusr = 0;
	*psubsys = 0;
	*psms = 0;
	*pextpasswd = 0;
	*palias_domains = 0;
	*poutofdate = 0;
	*pdeleted = 0;
	*psuspend = 0;
	*pgroups = 0;
	*palloc_addresses = 0;
	*preal_addresses = 0;
	*palias_address = 0;
	*pmlists = 0;
	*ptotal_space = 0;
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		system_log_info("[data_source]: fail to connect to mysql server, "
			"reason: %s", mysql_error(pmysql));
		i ++;
		sleep(1);
		goto RETRYING;
	}

	strcpy(sql_string, "SELECT max_size, max_user, privilege_bits, "
		"domain_status, domain_type FROM domains");
	
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
		temp_privileges = atoi(myrow[2]);
		temp_status = atoi(myrow[3]);
		temp_type = atoi(myrow[4]);
		if (DOMAIN_TYPE_NORMAL == temp_type) {
			*ptotal_space += atoi(myrow[0]);
			*palloc_addresses += atoi(myrow[1]);
			switch (temp_status) {
			case RECORD_STATUS_NORMAL:
				*preal_domains += 1;
				if (temp_privileges & DOMAIN_PRIVILEGE_BACKUP) {
					*pbackup += 1;
				}
				if (temp_privileges & DOMAIN_PRIVILEGE_MONITOR) {
					*pmonitor += 1;
				}
				if (temp_privileges & DOMAIN_PRIVILEGE_UNCHECKUSR) {
					*punchkusr += 1;
				}
				if (temp_privileges & DOMAIN_PRIVILEGE_SUBSYSTEM) {
					*psubsys += 1;
				}
				if (temp_privileges & DOMAIN_PRIVILEGE_NETDISK) {
					*psms += 1;
				}
				if (temp_privileges & DOMAIN_PRIVILEGE_EXTPASSWD) {
					*pextpasswd += 1;
				}
				break;
			case RECORD_STATUS_SUSPEND:
				*psuspend += 1;
				break;
			case RECORD_STATUS_OUTOFDATE:
				*poutofdate += 1;
				break;
			case RECORD_STATUS_DELETED:
				*pdeleted += 1;
				break;
			}
		} else {
			*palias_domains += 1;
		}
	}
	
	mysql_free_result(pmyres);

	strcpy(sql_string, "SELECT count(*) FROM groups");
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
		*pgroups = atoi(myrow[0]);
	}
	mysql_free_result(pmyres);

	strcpy(sql_string, "SELECT count(*) FROM users WHERE (address_status=0 OR "
		"address_status=1) AND address_type=0");
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
		*preal_addresses = atoi(myrow[0]);
	}
	mysql_free_result(pmyres);
	
	strcpy(sql_string, "SELECT count(*) FROM users WHERE (address_status=0 OR "
		"address_status=1) AND address_type=1");
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
		*palias_address = atoi(myrow[0]);
	}
	mysql_free_result(pmyres);

	strcpy(sql_string, "SELECT count(*) FROM mlists");
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
		*pmlists = atoi(myrow[0]);
	}
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

