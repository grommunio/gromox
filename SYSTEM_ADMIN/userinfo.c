#include "config_file.h"
#include <mysql/mysql.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char **argv)
{
	char mysql_host[256];
	int mysql_port;
	char mysql_user[256];
	char *mysql_passwd;
	char db_name[256];
	char *str_value;
	char sql_string[1024];
	CONFIG_FILE *pconfig;
	MYSQL *pmysql;
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	

	if (2 != argc) {
		printf("usage: %s address\n", argv[0]);
		return 1;
	}

	if (0 == strcmp(argv[1], "--help")) {
		printf("usage: %s address\n", argv[0]);
		exit(0);
	}

	pconfig = config_file_init("../config/athena.cfg");
	if (NULL == pconfig) {
		printf("fail to init config file\n");
		return 2;
	}

	str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		strcpy(mysql_host, str_value);
	}
	
	str_value = config_file_get_value(pconfig, "MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
		}
	}

	str_value = config_file_get_value(pconfig, "MYSQL_USERNAME");
	if (NULL == str_value) {
		mysql_user[0] = '\0';
	} else {
		strcpy(mysql_user, str_value);
	}

	mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");

	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
	} else {
		strcpy(db_name, str_value);
	}



	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("fail to init mysql object\n");
		config_file_free(pconfig);
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		config_file_free(pconfig);
		printf("fail to connect database\n");
		return 4;
	}
	
	config_file_free(pconfig);

	sprintf(sql_string, "SELECT max_size, maildir, "
		"create_day, address_type, address_status "
		"FROM users WHERE username='%s'", argv[1]);
	
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		return 5;
	}
		
	if (1 != mysql_num_rows(pmyres)) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 6;
	}

	myrow = mysql_fetch_row(pmyres);

	printf("information:\n"
		   "-------------------------------------------------\n"
		   "username             %s\n"
		   "maximum size         %sM\n"
		   "maildir              %s\n"
		   "created date         %s\n"
           "type                 %s\n"
		   "status               %s\n",
		   argv[1], myrow[0], myrow[1], myrow[2], myrow[3], myrow[4]);

	mysql_free_result(pmyres);
	mysql_close(pmysql);

	exit(0);
}



