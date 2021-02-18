// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
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
#include <mysql.h>
#define CONFIG_ID_USERNAME				1

using namespace gromox;

static char *opt_config_file, *opt_datadir;
static const struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	char *err_msg;
	MYSQL *pmysql;
	char dir[256];
	int mysql_port;
	MYSQL_ROW myrow;
	sqlite3 *psqlite;
	char db_name[256];
	MYSQL_RES *pmyres;
	char tmp_sql[1024];
	char temp_path[256];
	sqlite3_stmt* pstmt;
	char mysql_host[256];
	char mysql_user[256];
	struct stat node_stat;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return 1;
	}
	auto pconfig = config_file_prg(opt_config_file, "sa.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	auto str_value = config_file_get_value(pconfig, "MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		HX_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
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

	auto mysql_passwd = config_file_get_value(pconfig, "MYSQL_PASSWORD");
	str_value = config_file_get_value(pconfig, "MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
	} else {
		HX_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));
	}
	const char *datadir = opt_datadir != nullptr ? opt_datadir :
	                      config_file_get_value(pconfig, "data_file_path");
	if (datadir == nullptr)
		datadir = PKGDATADIR;
	
	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("Failed to init mysql object\n");
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		printf("Failed to connect to the database\n");
		return 3;
	}
	
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
	HX_strlcpy(dir, myrow[2], GX_ARRAY_SIZE(dir));
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	snprintf(temp_path, 256, "%s/exmdb", dir);
	if (mkdir(temp_path, 0777) != 0)
		/* cov-ignore */;
	snprintf(temp_path, 256, "%s/exmdb/midb.sqlite3", dir);
	if (0 == stat(temp_path, &node_stat)) {
		printf("can not create sotre database,"
			" %s already exits\n", temp_path);
		return 6;
	}

	auto filp = fopen_sd("sqlite3_midb.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_midb.txt: %s\n", strerror(errno));
		return 7;
	}
	auto sql_string = slurp_file(filp.get());
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		return 9;
	}
	if (SQLITE_OK != sqlite3_open_v2(temp_path, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		printf("fail to create store database\n");
		sqlite3_shutdown();
		return 9;
	}
	chmod(temp_path, 0666);
	/* begin the transaction */
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	
	if (sqlite3_exec(psqlite, sql_string.c_str(), nullptr, nullptr,
	    &err_msg) != SQLITE_OK) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return 9;
	}
	
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
