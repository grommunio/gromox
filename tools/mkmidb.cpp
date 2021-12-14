// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <memory>
#include <string>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
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
#include "exch/mysql_adaptor/mysql_adaptor.h"
#include "mkshared.hpp"
#define CONFIG_ID_USERNAME				1

using namespace std::string_literals;
using namespace gromox;

static char *opt_config_file, *opt_datadir;
static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	HXOPT_AUTOHELP,
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
	char mysql_host[256];
	char mysql_user[256];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return 1;
	}
	auto pconfig = config_file_prg(opt_config_file, "sa.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;
	auto str_value = pconfig->get_value("MYSQL_HOST");
	if (str_value == nullptr)
		strcpy(mysql_host, "localhost");
	else
		gx_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
	
	str_value = pconfig->get_value("MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = strtol(str_value, nullptr, 0);
		if (mysql_port <= 0)
			mysql_port = 3306;
	}

	str_value = pconfig->get_value("MYSQL_USERNAME");
	gx_strlcpy(mysql_user, str_value != nullptr ? str_value : "root", GX_ARRAY_SIZE(mysql_user));
	auto mysql_passwd = pconfig->get_value("MYSQL_PASSWORD");
	str_value = pconfig->get_value("MYSQL_DBNAME");
	if (str_value == nullptr)
		strcpy(db_name, "email");
	else
		gx_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));

	const char *datadir = opt_datadir != nullptr ? opt_datadir :
	                      pconfig->get_value("data_file_path");
	if (datadir == nullptr)
		datadir = PKGDATADIR;
	
	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("Failed to init mysql object\n");
		return 3;
	}

	if (NULL == mysql_real_connect(pmysql, mysql_host, mysql_user,
		mysql_passwd, db_name, mysql_port, NULL, 0)) {
		mysql_close(pmysql);
		printf("Failed to connect to the database %s@%s/%s\n",
		       mysql_user, mysql_host, db_name);
		return 3;
	}
	
	auto qstr =
		"SELECT up.propval_str AS dtypx, u.address_status, u.maildir "
		"FROM users AS u "
		"LEFT JOIN user_properties AS up ON u.id=up.user_id AND up.proptag=956628995 " /* PR_DISPLAY_TYPE_EX */
		"WHERE username='"s + argv[1] + "'";
	if (mysql_query(pmysql, qstr.c_str()) != 0 ||
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
	auto dtypx = DT_MAILUSER;
	if (myrow[0] != nullptr)
		dtypx = static_cast<enum display_type>(strtoul(myrow[0], nullptr, 0));
	if (dtypx != DT_MAILUSER && dtypx != DT_ROOM && dtypx != DT_EQUIPMENT) {
		printf("Refusing to create a private store for mailing lists, groups and aliases. "
		       "(PR_DISPLAY_TYPE=%xh)\n", dtypx);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 4;
	}

	auto address_status = strtoul(myrow[1], nullptr, 0);
	if (address_status != AF_USER_NORMAL && address_status != AF_USER_SHAREDMBOX)
		printf("Warning: Address status is not \"alive\"(0) but %lu\n", address_status);
	gx_strlcpy(dir, myrow[2], GX_ARRAY_SIZE(dir));
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	auto temp_path = dir + "/exmdb"s;
	if (mkdir(temp_path.c_str(), 0777) != 0 && errno != EEXIST) {
		fprintf(stderr, "E-1337: mkdir %s: %s\n", temp_path.c_str(), strerror(errno));
		return 6;
	}
	temp_path += "/midb.sqlite3";
	/*
	 * sqlite3_open does not expose O_EXCL, so let's create the file under
	 * EXCL semantics ahead of time.
	 */
	auto tfd = open(temp_path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
	if (tfd >= 0) {
		adjust_rights(tfd);
		close(tfd);
	} else if (errno == EEXIST) {
		printf("can not create store database, %s already exists\n", temp_path.c_str());
		return 6;
	}

	auto filp = fopen_sd("sqlite3_midb.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_midb.txt: %s\n", strerror(errno));
		return 7;
	}
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(fileno(filp.get()), nullptr));
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		return 9;
	}
	auto cl_0 = make_scope_exit([]() { sqlite3_shutdown(); });
	if (sqlite3_open_v2(temp_path.c_str(), &psqlite,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		printf("fail to create store database\n");
		return 9;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	auto sql_transact = gx_sql_begin_trans(psqlite);
	if (sqlite3_exec(psqlite, slurp_data.get(), nullptr, nullptr,
	    &err_msg) != SQLITE_OK) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		return 9;
	}
	slurp_data.reset();
	
	const char *csql_string = "INSERT INTO configurations VALUES (?, ?)";
	auto pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr)
		return 9;
	
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_USERNAME);
	sqlite3_bind_text(pstmt, 2, argv[1], -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	
	pstmt.finalize();
	sql_transact.commit();
	return EXIT_SUCCESS;
}
