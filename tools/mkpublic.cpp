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
#include <vector>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/list_file.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/pcl.hpp>
#include <gromox/proptags.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include "mkshared.hpp"
#include "exch/mysql_adaptor/mysql_adaptor.h"

using LLU = unsigned long long;
using namespace std::string_literals;
using namespace gromox;

static uint32_t g_last_art;
static uint64_t g_last_cn = CHANGE_NUMBER_BEGIN;
static uint64_t g_last_eid = ALLOCATED_EID_RANGE;
static char *opt_config_file, *opt_datadir;
static unsigned int opt_force;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
	{nullptr, 'f', HXTYPE_NONE, &opt_force, nullptr, nullptr, 0, "Allow overwriting exchange.sqlite3"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static BOOL create_generic_folder(sqlite3 *psqlite,
	uint64_t folder_id, uint64_t parent_id, int domain_id,
	const char *pdisplayname, const char *pcontainer_class)
{
	uint64_t cur_eid;
	uint64_t max_eid;
	uint32_t art_num;
	uint64_t change_num;
	char sql_string[256];
	
	cur_eid = g_last_eid + 1;
	g_last_eid += ALLOCATED_EID_RANGE;
	max_eid = g_last_eid;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO allocated_eids"
	        " VALUES (%llu, %llu, %lld, 1)", LLU(cur_eid),
	        LLU(max_eid), static_cast<long long>(time(nullptr)));
	if (gx_sql_exec(psqlite, sql_string) != SQLITE_OK)
		return FALSE;
	g_last_cn ++;
	change_num = g_last_cn;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folders "
				"(folder_id, parent_id, change_number, "
				"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (parent_id == 0)
		sqlite3_bind_null(pstmt, 2);
	else
		sqlite3_bind_int64(pstmt, 2, parent_id);
	sqlite3_bind_int64(pstmt, 3, change_num);
	sqlite3_bind_int64(pstmt, 4, cur_eid);
	sqlite3_bind_int64(pstmt, 5, max_eid);
	if (sqlite3_step(pstmt) != SQLITE_DONE)
		return FALSE;
	pstmt.finalize();
	g_last_art ++;
	art_num = g_last_art;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO "
	          "folder_properties VALUES (%llu, ?, ?)", LLU(folder_id));
	pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	if (!add_folderprop_iv(pstmt, art_num, true) ||
	    !add_folderprop_sv(pstmt, pdisplayname, pcontainer_class) ||
	    !add_folderprop_tv(pstmt) ||
	    !add_changenum(pstmt, CN_DOMAIN, domain_id, change_num))
		return false;
	return TRUE;
}

int main(int argc, const char **argv) try
{
	int i;
	MYSQL *pmysql;
	uint16_t propid;
	MYSQL_ROW myrow;
	uint64_t nt_time;
	sqlite3 *psqlite;
	MYSQL_RES *pmyres;
	char mysql_string[1024];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <domainname>\n", argv[0]);
		return EXIT_FAILURE;
	}
	auto pconfig = config_file_prg(opt_config_file, "mysql_adaptor.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;
	static constexpr cfg_directive mkpublic_cfg_defaults[] = {
		{"mysql_host", "localhost"},
		{"mysql_port", "3306"},
		{"mysql_username", "root"},
		{"mysql_dbname", "email"},
		CFG_TABLE_END,
	};
	config_file_apply(*pconfig, mkpublic_cfg_defaults);
	std::string mysql_host = znul(pconfig->get_value("mysql_host"));
	uint16_t mysql_port = pconfig->get_ll("mysql_port");
	std::string mysql_user = znul(pconfig->get_value("mysql_username"));
	std::optional<std::string> mysql_pass;
	if (auto s = pconfig->get_value("mysql_password"))
		mysql_pass.emplace(s);
	std::string db_name = znul(pconfig->get_value("mysql_dbname"));

	pconfig = config_file_prg(opt_config_file, "sa.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;
	const char *datadir = opt_datadir != nullptr ? opt_datadir :
	                      pconfig->get_value("data_file_path");
	if (datadir == nullptr)
		datadir = PKGDATADIR;
	
	if (NULL == (pmysql = mysql_init(NULL))) {
		printf("Failed to init mysql object\n");
		return EXIT_FAILURE;
	}

	if (mysql_real_connect(pmysql, mysql_host.c_str(), mysql_user.c_str(),
	    mysql_pass.has_value() ? mysql_pass->c_str() : nullptr,
	    db_name.c_str(), mysql_port, nullptr, 0) == nullptr) {
		mysql_close(pmysql);
		printf("Failed to connect to the database %s@%s/%s\n",
		       mysql_user.c_str(), mysql_host.c_str(), db_name.c_str());
		return EXIT_FAILURE;
	}
	if (mysql_set_character_set(pmysql, "utf8mb4") != 0) {
		fprintf(stderr, "\"utf8mb4\" not available: %s", mysql_error(pmysql));
		mysql_close(pmysql);
		return EXIT_FAILURE;
	}
	
	snprintf(mysql_string, arsizeof(mysql_string), "SELECT 0, homedir, 0, "
		"domain_status, id FROM domains WHERE domainname='%s'", argv[1]);
	
	if (0 != mysql_query(pmysql, mysql_string) ||
		NULL == (pmyres = mysql_store_result(pmysql))) {
		printf("fail to query database\n");
		mysql_close(pmysql);
		return EXIT_FAILURE;
	}
		
	if (1 != mysql_num_rows(pmyres)) {
		printf("cannot find information from database "
				"for username %s\n", argv[1]);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return EXIT_FAILURE;
	}

	myrow = mysql_fetch_row(pmyres);
	auto domain_status = strtoul(myrow[3], nullptr, 0);
	if (domain_status != AF_DOMAIN_NORMAL)
		printf("Warning: Domain status is not \"alive\"(0) but %lu\n", domain_status);
	
	std::string dir = znul(myrow[1]);
	int domain_id = strtol(myrow[4], nullptr, 0);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	if (!make_mailbox_hierarchy(dir))
		return EXIT_FAILURE;
	/*
	 * sqlite3_open does not expose O_EXCL, so let's create the file under
	 * EXCL semantics ahead of time.
	 */
	auto temp_path = dir + "/exmdb/exchange.sqlite3";
	unsigned int tfdflags = O_RDWR | O_CREAT | O_EXCL;
	if (opt_force) {
		tfdflags = ~O_EXCL;
		tfdflags |= O_TRUNC;
	}
	auto tfd = open(temp_path.c_str(), tfdflags, 0660);
	if (tfd >= 0) {
		adjust_rights(tfd);
		close(tfd);
	} else if (errno == EEXIST) {
		printf("mkpublic: %s already exists\n", temp_path.c_str());
		printf("mkpublic: Use the -f option to force overwrite.\n");
		return EXIT_FAILURE;
	}
	
	auto filp = fopen_sd("sqlite3_common.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_common.txt: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	std::string sql_string;
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(fileno(filp.get()), &slurp_len));
	if (slurp_data != nullptr)
		sql_string.append(slurp_data.get(), slurp_len);
	filp = fopen_sd("sqlite3_public.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_public.txt: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	slurp_data.reset(HX_slurp_fd(fileno(filp.get()), &slurp_len));
	if (slurp_data != nullptr)
		sql_string.append(slurp_data.get(), slurp_len);
	slurp_data.reset();
	filp.reset();
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
	auto sql_transact = gx_sql_begin_trans(psqlite);
	if (gx_sql_exec(psqlite, sql_string.c_str()) != SQLITE_OK)
		return EXIT_FAILURE;
	
	std::vector<std::string> namedprop_list;
	auto ret = list_file_read_fixedstrings("propnames.txt", datadir, namedprop_list);
	if (ret == -ENOENT) {
	} else if (ret < 0) {
		fprintf(stderr, "list_file_initd propnames.txt: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}
	auto pstmt = gx_sql_prep(psqlite, "INSERT INTO named_properties VALUES (?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	
	i = 0;
	for (const auto &name : namedprop_list) {
		propid = 0x8001 + i++;
		sqlite3_bind_int64(pstmt, 1, propid);
		sqlite3_bind_text(pstmt, 2, name.c_str(), -1, SQLITE_STATIC);
		ret = sqlite3_step(pstmt);
		if (ret != SQLITE_DONE) {
			printf("sqlite3_step on namedprop \"%s\": %s\n",
			       name.c_str(), sqlite3_errstr(ret));
			return EXIT_FAILURE;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	
	pstmt = gx_sql_prep(psqlite, "INSERT INTO store_properties VALUES (?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	nt_time = rop_util_unix_to_nttime(time(NULL));
	std::pair<uint32_t, uint64_t> storeprops[] = {
		{PR_CREATION_TIME, nt_time},
		{PR_MESSAGE_SIZE_EXTENDED, 0},
		{PR_ASSOC_MESSAGE_SIZE_EXTENDED, 0},
		{PR_NORMAL_MESSAGE_SIZE_EXTENDED, 0},
	};
	for (const auto &e : storeprops) {
		sqlite3_bind_int64(pstmt, 1, e.first);
		sqlite3_bind_int64(pstmt, 2, e.second);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return EXIT_FAILURE;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	static constexpr struct {
		uint64_t parent = 0, fid = 0;
		const char *name = nullptr;
	} generic_folders[] = {
		{0, PUBLIC_FID_ROOT, "Root Container"},
		{PUBLIC_FID_ROOT, PUBLIC_FID_IPMSUBTREE, "IPM_SUBTREE"},
		{PUBLIC_FID_ROOT, PUBLIC_FID_NONIPMSUBTREE, "NON_IPM_SUBTREE"},
		{PUBLIC_FID_NONIPMSUBTREE, PUBLIC_FID_EFORMSREGISTRY, "EFORMS REGISTRY"},
	};
	for (const auto &e : generic_folders) {
		if (!create_generic_folder(psqlite, e.fid, e.parent,
		    domain_id, e.name, nullptr)) {
			printf("Failed to create \"%s\" folder\n", e.name);
			return EXIT_FAILURE;
		}
	}

	pstmt = gx_sql_prep(psqlite, "INSERT INTO configurations VALUES (?, ?)");
	if (pstmt == nullptr)
		return EXIT_FAILURE;
	char tmp_bguid[GUIDSTR_SIZE];
	GUID::random_new().to_str(tmp_bguid, arsizeof(tmp_bguid));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_bguid, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return EXIT_FAILURE;
	}
	sqlite3_reset(pstmt);
	std::pair<uint32_t, uint64_t> confprops[] = {
		{CONFIG_ID_CURRENT_EID, 0x100},
		{CONFIG_ID_MAXIMUM_EID, ALLOCATED_EID_RANGE},
		{CONFIG_ID_LAST_CHANGE_NUMBER, g_last_cn},
		{CONFIG_ID_LAST_CID, 0},
		{CONFIG_ID_LAST_ARTICLE_NUMBER, g_last_art},
		{CONFIG_ID_SEARCH_STATE, 0},
		{CONFIG_ID_DEFAULT_PERMISSION, frightsReadAny | frightsCreate | frightsVisible | frightsEditOwned | frightsDeleteOwned},
		{CONFIG_ID_ANONYMOUS_PERMISSION, 0},
	};
	for (const auto &e : confprops) {
		sqlite3_bind_int64(pstmt, 1, e.first);
		sqlite3_bind_int64(pstmt, 2, e.second);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return EXIT_FAILURE;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	sql_transact.commit();
	return EXIT_SUCCESS;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}
