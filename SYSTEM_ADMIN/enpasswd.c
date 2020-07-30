#include <errno.h>
#include <libHX/defs.h>
#include <gromox/paths.h>
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

int main(int argc, const char **argv)
{
	int i, fd;
	int len, num;
	MYSQL *pmysql;
	int mysql_port;
	char *str_value;
	LIST_FILE *plist;
	char db_name[256];
	char password[128];
	char *mysql_passwd;
	char tmp_line[1024];
	CONFIG_FILE *pconfig;
	char mysql_host[256];
	char mysql_user[256];
	char sql_string[1024];
	struct pwitem { char user[128], pass[128]; };	
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (2 != argc) {
		printf("usage: %s address\n", argv[0]);
		return 1;
	}

	if (0 == strcmp(argv[1], "--help")) {
		printf("usage: %s address\n", argv[0]);
		exit(0);
	}

	plist = list_file_init(PKGDATASADIR "/tmp_password.txt", "%s:128%s:128");
	if (NULL == plist) {
		printf("Cannot read %s: %s\n", PKGDATASADIR, strerror(errno));
		return 1;
	}
	const struct pwitem *pitem = reinterpret_cast(struct pwitem *, list_file_get_list(plist));
	num = list_file_get_item_num(plist);
	for (i=0; i<num; i++) {
		if (strcasecmp(pitem[i].user, argv[1]) == 0) {
			strcpy(password, pitem[i].pass);
			break;
		}
	}
	if (i >= num) {
		list_file_free(plist);
		printf("cannot find password information from tmp_password.txt\n");
		return 2;
	}
	fd = open("../data/tmp_password.tmp", O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		list_file_free(plist);
		printf("failed to create ../data/tmp_password.tmp: %s\n", strerror(errno));
		return 3;
	}
	for (i=0; i<num; i++) {
		if (strcasecmp(pitem[i].user, argv[1]) == 0)
			continue;
		snprintf(tmp_line, sizeof(tmp_line), "%s\t%s", pitem[i].user, pitem[i].pass);
		len = strlen(tmp_line);
		if (len != write(fd, tmp_line, len)) {
			close(fd);
			list_file_free(plist);
			printf("fail to write temp file\n");
			return 4;
		}
	}
	list_file_free(plist);
	close(fd);
	pconfig = config_file_init2(NULL, PKGSYSCONFDIR "/sa.cfg");
	if (NULL == pconfig) {
		printf("config_file_init %s: %s\n", PKGSYSCONFDIR "/sa.cfg", strerror(errno));
		return 5;
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
		printf("Failed to init mysql object\n");
		config_file_free(pconfig);
		return 6;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		config_file_free(pconfig);
		printf("Failed to connect to the database\n");
		return 7;
	}
	config_file_free(pconfig);
	
	sprintf(sql_string, "UPDATE users SET password='%s'"
		" WHERE username='%s'", password, argv[1]);
	if (0 != mysql_query(pmysql, sql_string)) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		return 8;
	}
	mysql_close(pmysql);
	remove("../data/tmp_password.txt");
	link("../data/tmp_password.tmp", "../data/tmp_password.txt");
	remove("../data/tmp_password.tmp");
	printf("%s's password has been changed back "
			"to the original content\n", argv[1]);
	exit(0);
}
