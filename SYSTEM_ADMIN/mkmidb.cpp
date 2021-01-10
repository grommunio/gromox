// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <gromox/database.h>
#include <gromox/paths.h>
#include <gromox/config_file.hpp>
#include <ctime>
#include <cstdio>
#include <fcntl.h>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mysql/mysql.h>
#define CONFIG_ID_USERNAME				1

int main(int argc, const char **argv)
{
	int fd;
	int str_size;
	char *err_msg;
	MYSQL *pmysql;
	char dir[256];
	int mysql_port;
	char *str_value;
	MYSQL_ROW myrow;
	sqlite3 *psqlite;
	char db_name[256];
	MYSQL_RES *pmyres;
	char *mysql_passwd;
	char tmp_sql[1024];
	char temp_path[256];
	sqlite3_stmt* pstmt;
	char mysql_host[256];
	char mysql_user[256];
	CONFIG_FILE *pconfig;
	struct stat node_stat;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return 1;
	}
	pconfig = config_file_init2(NULL, PKGSYSCONFDIR "/sa.cfg");
	if (NULL == pconfig) {
		printf("config_file_init %s: %s\n", PKGSYSCONFDIR "/sa.cfg", strerror(errno));
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
		printf("Failed to init mysql object\n");
		config_file_free(pconfig);
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		config_file_free(pconfig);
		printf("Failed to connect to the database\n");
		return 3;
	}
	
	config_file_free(pconfig);

	sprintf(tmp_sql, "SELECT address_type, address_status,"
		" maildir FROM users WHERE username='%s'", argv[1]);
	
	if (0 != mysql_query(pmysql, tmp_sql) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		return 3;
	}
		
	if (1 != mysql_num_rows(pmyres)) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 3;
	}

	myrow = mysql_fetch_row(pmyres);
	
	if (0 != atoi(myrow[0])) {
		printf("address type is not normal\n");
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 4;
	}
	
	if (0 != atoi(myrow[1])) {
		printf("warning: address status is not alive!\n");
	}
	strcpy(dir, myrow[2]);
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	snprintf(temp_path, 256, "%s/exmdb", dir);
	if (0 != stat(temp_path, &node_stat)) {
		mkdir(temp_path, 0777);
	}
	
	snprintf(temp_path, 256, "%s/exmdb/midb.sqlite3", dir);
	if (0 == stat(temp_path, &node_stat)) {
		printf("can not create sotre database,"
			" %s already exits\n", temp_path);
		return 6;
	}
	
	if (0 != stat(PKGDATASADIR "/doc/sqlite3_midb.txt", &node_stat)) {
		printf("can not find store template"
			" file \"sqlite3_midb.txt\"\n");	
		return 7;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		printf("\"sqlite3_midb.txt\" is not a regular file\n");
		return 7;
	}
	str_size = node_stat.st_size;
	
	auto sql_string = static_cast<char *>(malloc(str_size + 1));
	if (NULL == sql_string) {
		printf("Failed to allocate memory\n");
		return 8;
	}
	fd = open(PKGDATASADIR "/doc/sqlite3_midb.txt", O_RDONLY);
	if (-1 == fd) {
		printf("Failed to open \"sqlite3_midb.txt\": %s\n", strerror(errno));
		free(sql_string);
		return 7;
	}
	if (str_size != read(fd, sql_string, str_size)) {
		printf("fail to read content from store"
			" template file \"sqlite3_midb.txt\"\n");
		close(fd);
		free(sql_string);
		return 7;
	}
	close(fd);
	sql_string[str_size] = '\0';
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		free(sql_string);
		return 9;
	}
	if (SQLITE_OK != sqlite3_open_v2(temp_path, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		printf("fail to create store database\n");
		free(sql_string);
		sqlite3_shutdown();
		return 9;
	}
	chmod(temp_path, 0666);
	/* begin the transaction */
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, &err_msg)) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		free(sql_string);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	free(sql_string);
	
	const char *csql_string = "INSERT INTO configurations VALUES (?, ?)";
	if (!gx_sql_prep(psqlite, csql_string, &pstmt)) {
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_USERNAME);
	sqlite3_bind_text(pstmt, 2, argv[1], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	
	sqlite3_finalize(pstmt);
	
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_close(psqlite);
	sqlite3_shutdown();
	exit(0);
}
