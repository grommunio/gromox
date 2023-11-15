// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <mysql.h>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <unistd.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/database_mysql.hpp>
#include <gromox/dbop.h>
#include <gromox/defs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include "mkshared.hpp"
using namespace std::string_literals;
using namespace gromox;

enum {
	CONFIG_ID_USERNAME = 1, /* obsolete */
};

static unsigned int opt_force, opt_create_old, opt_upgrade;
static unsigned int opt_verbose, opt_integ;
static char *opt_config_file;

static constexpr HXoption g_options_table[] = {
	{"integrity", 0, HXTYPE_NONE, &opt_integ, nullptr, nullptr, 0, "Perform integrity SQLite check"},
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'f', HXTYPE_NONE, &opt_force, nullptr, nullptr, 0, "Allow overwriting midb.sqlite3"},
	{nullptr, 'U', HXTYPE_NONE, &opt_upgrade, nullptr, nullptr, 0, "Perform schema upgrade"},
	{nullptr, 'v', HXTYPE_NONE, &opt_verbose, nullptr, nullptr, 0, "Bump verbosity"},
	{"create-old", 0, HXTYPE_NONE, &opt_create_old, nullptr, nullptr, 0, "Create SQLite database tables version 0"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr cfg_directive mkmidb_cfg_defaults[] = {
	{"mysql_dbname", "email"},
	{"mysql_host", "localhost"},
	{"mysql_port", "3306"},
	{"mysql_username", "root"},
	CFG_TABLE_END,
};

int main(int argc, const char **argv)
{
	sqlite3 *psqlite;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <username>\n", argv[0]);
		return EXIT_FAILURE;
	}
	auto pconfig = config_file_prg(opt_config_file, "mysql_adaptor.cfg",
	               mkmidb_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;
	std::string mysql_host = znul(pconfig->get_value("mysql_host"));
	uint16_t mysql_port = pconfig->get_ll("mysql_port");
	std::string mysql_user = znul(pconfig->get_value("mysql_username"));
	std::optional<std::string> mysql_pass;
	if (auto s = pconfig->get_value("mysql_password"))
		mysql_pass.emplace(s);
	std::string db_name = znul(pconfig->get_value("mysql_dbname"));

	std::unique_ptr<MYSQL, mysql_delete> conn(mysql_init(nullptr));
	if (conn == nullptr) {
		printf("Failed to init mysql object\n");
		return EXIT_FAILURE;
	}

	if (mysql_real_connect(conn.get(), mysql_host.c_str(), mysql_user.c_str(),
	    mysql_pass.has_value() ? mysql_pass->c_str() : nullptr,
	    db_name.c_str(), mysql_port, nullptr, 0) == nullptr) {
		printf("Failed to connect to the MariaDB/MySQL database %s@%s/%s\n",
		       mysql_user.c_str(), mysql_host.c_str(), db_name.c_str());
		return EXIT_FAILURE;
	} else if (mysql_set_character_set(conn.get(), "utf8mb4") != 0) {
		fprintf(stderr, "\"utf8mb4\" not available: %s", mysql_error(conn.get()));
		return EXIT_FAILURE;
	}
	
	auto qstr =
		"SELECT up.propval_str AS dtypx, u.address_status, u.maildir "
		"FROM users AS u "
		"LEFT JOIN user_properties AS up ON u.id=up.user_id AND up.proptag=956628995 " /* PR_DISPLAY_TYPE_EX */
		"WHERE username='"s + argv[1] + "'";
	if (mysql_query(conn.get(), qstr.c_str()) != 0) {
		fprintf(stderr, "%s: %s\n", qstr.c_str(), mysql_error(conn.get()));
		return EXIT_FAILURE;
	}
	DB_RESULT myres = mysql_store_result(conn.get());
	if (myres == nullptr) {
		printf("store_result failed\n");
		return EXIT_FAILURE;
	}
	auto myrow = myres.fetch_row();
	if (myrow == nullptr || myres.num_rows() > 1) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	auto dtypx = DT_MAILUSER;
	if (myrow[0] != nullptr)
		dtypx = static_cast<enum display_type>(strtoul(myrow[0], nullptr, 0));
	if (dtypx != DT_MAILUSER && dtypx != DT_ROOM && dtypx != DT_EQUIPMENT) {
		printf("Refusing to create a private store for mailing lists, groups and aliases. "
		       "(PR_DISPLAY_TYPE=%xh)\n", dtypx);
		return EXIT_FAILURE;
	}

	unsigned int address_status = strtoul(myrow[1], nullptr, 0);
	if (!afuser_store_present(address_status))
		printf("Warning: Account status (0x%x) indicates this user object normally does not have a mailbox. Proceeding anyway for now...\n", address_status);
	std::string dir = znul(myrow[2]);
	myres.clear();
	conn.reset();
	
	auto temp_path = dir + "/exmdb"s;
	if (mkdir(temp_path.c_str(), 0777) != 0 && errno != EEXIST) {
		fprintf(stderr, "E-1337: mkdir %s: %s\n", temp_path.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	adjust_rights(temp_path.c_str());
	temp_path += "/midb.sqlite3";
	if (!opt_upgrade && !opt_integ) {
		auto ret = mbop_truncate_chown(argv[0], temp_path.c_str(), opt_force);
		if (ret != 0)
			return EXIT_FAILURE;
	}
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("Failed to initialize sqlite engine\n");
		return EXIT_FAILURE;
	}
	auto cl_0 = make_scope_exit([]() { sqlite3_shutdown(); });
	if (sqlite3_open_v2(temp_path.c_str(), &psqlite,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		printf("fail to create store database\n");
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit([&]() { sqlite3_close(psqlite); });
	if (opt_integ)
		return dbop_sqlite_integcheck(psqlite, LV_ERR) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	unsigned int flags = 0;
	if (opt_upgrade) {
		auto ret = dbop_sqlite_upgrade(psqlite, temp_path.c_str(),
		           sqlite_kind::midb, flags | DBOP_VERBOSE);
		if (ret != 0) {
			fprintf(stderr, "dbop_sqlite_upgrade: %s\n", strerror(-ret));
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}
	auto sql_transact = gx_sql_begin_trans(psqlite);
	if (!sql_transact)
		return EXIT_FAILURE;
	if (opt_create_old)
		flags |= DBOP_SCHEMA_0;
	if (opt_verbose)
		flags |= DBOP_VERBOSE;
	auto ret = dbop_sqlite_create(psqlite, sqlite_kind::midb, flags);
	if (ret != 0) {
		fprintf(stderr, "dbop_sqlite_create_top: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}
	return sql_transact.commit() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
