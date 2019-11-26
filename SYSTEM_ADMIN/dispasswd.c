#include "list_file.h"
#include "config_file.h"
#include <mysql/mysql.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	int i, fd;
	char *pitem;
	int len, num;
	MYSQL *pmysql;
	int mysql_port;
	char *str_value;
	MYSQL_ROW myrow;
	LIST_FILE *plist;
	char db_name[256];
	MYSQL_RES *pmyres;
	char *mysql_passwd;
	char tmp_line[1024];
	CONFIG_FILE *pconfig;
	char mysql_host[256];
	char mysql_user[256];
	char sql_string[1024];
	
	
	if (2 != argc) {
		printf("usage: %s address\n", argv[0]);
		exit(-1);
	}

	if (0 == strcmp(argv[1], "--help")) {
		printf("usage: %s address\n", argv[0]);
		exit(0);
	}
	
	plist = list_file_init("../data/tmp_password.txt", "%s:128%s:128");
	if (NULL != plist) {
		pitem = list_file_get_list(plist);
		num = list_file_get_item_num(plist);
		for (i=0; i<num; i++) {
			if (0 == strcasecmp(pitem + 256*i, argv[1])) {
				list_file_free(plist);
				printf("%s has already been disabled password, "
					"if you wish to disable the password forcibly,"
					" please delete %s from tmp_password.txt\n",
					argv[1], argv[1]);
				exit(0);
			}
		}
		list_file_free(plist);
	}
	pconfig = config_file_init("../config/athena.cfg");
	if (NULL == pconfig) {
		printf("fail to init config file\n");
		exit(-2);
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
		exit(-3);
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		config_file_free(pconfig);
		printf("fail to connect database\n");
		exit(-4);
	}
	config_file_free(pconfig);
	
	sprintf(sql_string, "SELECT password FROM"
		" users WHERE username='%s'", argv[1]);
	if (0 != mysql_query(pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		exit(-5);
	}
	if (1 != mysql_num_rows(pmyres)) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		exit(-6);
	}
	myrow = mysql_fetch_row(pmyres);
	len = sprintf(tmp_line, "%s\t%s\n", argv[1], myrow[0]);
	mysql_free_result(pmyres);
	fd = open("../data/tmp_password.txt",
		O_CREAT|O_APPEND|O_WRONLY, 0666);
	if (-1 == fd) {
		printf("cannot record original password "
			"information into tmp_password.txt\n");
		mysql_close(pmysql);
		exit(-7);
	}
	if (len != write(fd, tmp_line, len)) {
		printf("cannot record original password "
			"information into tmp_password.txt\n");
		close(fd);
		mysql_close(pmysql);
		exit(-7);
	}
	close(fd);
	sprintf(sql_string, "UPDATE users SET password=''"
		" WHERE username='%s'", argv[1]);
	if (0 != mysql_query(pmysql, sql_string)) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		exit(-8);
	}
	mysql_close(pmysql);
	printf("%s's password has been disabled temporarily,"
		" please use \"enpasswd\" command to enable the "
		"original password back\n", argv[1]);
	exit(0);
}

