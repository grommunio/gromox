// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <string>
#include <vector>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/config_file.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/list_file.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/proptags.hpp>
#include <gromox/guid.hpp>
#include <gromox/pcl.hpp>
#include <gromox/scope.hpp>
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
#define LLU(x) static_cast<unsigned long long>(x)

using namespace std::string_literals;
using namespace gromox;

static uint32_t g_last_art;
static uint64_t g_last_cn = CHANGE_NUMBER_BEGIN;
static uint64_t g_last_eid = ALLOCATED_EID_RANGE;
static char *opt_config_file, *opt_datadir;

static const struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{nullptr, 'd', HXTYPE_STRING, &opt_datadir, nullptr, nullptr, 0, "Data directory", "DIR"},
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
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		return FALSE;
	}
	g_last_cn ++;
	change_num = g_last_cn;
	snprintf(sql_string, arsizeof(sql_string), "INSERT INTO folders "
				"(folder_id, parent_id, change_number, "
				"cur_eid, max_eid) VALUES (?, ?, ?, ?, ?)");
	auto pstmt = gx_sql_prep(psqlite, sql_string);
	if (pstmt == nullptr)
		return FALSE;
	sqlite3_bind_int64(pstmt, 1, folder_id);
	if (0 == parent_id) {
		sqlite3_bind_null(pstmt, 2);
	} else {
		sqlite3_bind_int64(pstmt, 2, parent_id);
	}
	sqlite3_bind_int64(pstmt, 3, change_num);
	sqlite3_bind_int64(pstmt, 4, cur_eid);
	sqlite3_bind_int64(pstmt, 5, max_eid);
	if (SQLITE_DONE != sqlite3_step(pstmt)) {
		return FALSE;
	}
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
	    !add_changenum(pstmt, domain_id, change_num))
		return false;
	return TRUE;
}

int main(int argc, const char **argv)
{
	int i;
	int domain_id;
	char *err_msg;
	MYSQL *pmysql;
	char dir[256];
	GUID tmp_guid;
	int mysql_port;
	int store_ratio;
	uint16_t propid;
	MYSQL_ROW myrow;
	uint64_t nt_time;
	sqlite3 *psqlite;
	char db_name[256];
	uint64_t max_size;
	MYSQL_RES *pmyres;
	char tmp_buff[256];
	char mysql_host[256];
	char mysql_user[256];
	char mysql_string[1024];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (2 != argc) {
		printf("usage: %s <domainname>\n", argv[0]);
		return 1;
	}
	auto pconfig = config_file_prg(opt_config_file, "sa.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;
	auto str_value = pconfig->get_value("PUBLIC_STORE_RATIO");
	if (NULL == str_value) {
		store_ratio = 10;
	} else {
		store_ratio = atoi(str_value);
		if (store_ratio <= 0 || store_ratio >= 1000) {
			store_ratio = 10;
		}
	}
	str_value = pconfig->get_value("MYSQL_HOST");
	if (NULL == str_value) {
		strcpy(mysql_host, "localhost");
	} else {
		gx_strlcpy(mysql_host, str_value, GX_ARRAY_SIZE(mysql_host));
	}
	
	str_value = pconfig->get_value("MYSQL_PORT");
	if (NULL == str_value) {
		mysql_port = 3306;
	} else {
		mysql_port = atoi(str_value);
		if (mysql_port <= 0) {
			mysql_port = 3306;
		}
	}

	str_value = pconfig->get_value("MYSQL_USERNAME");
	gx_strlcpy(mysql_user, str_value != nullptr ? str_value : "root", GX_ARRAY_SIZE(mysql_user));
	auto mysql_passwd = pconfig->get_value("MYSQL_PASSWORD");
	str_value = pconfig->get_value("MYSQL_DBNAME");
	if (NULL == str_value) {
		strcpy(db_name, "email");
	} else {
		gx_strlcpy(db_name, str_value, GX_ARRAY_SIZE(db_name));
	}
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
	
	sprintf(mysql_string, "SELECT max_size, homedir, domain_type, "
		"domain_status, id FROM domains WHERE domainname='%s'", argv[1]);
	
	if (0 != mysql_query(pmysql, mysql_string) ||
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
	auto domain_type = strtoul(myrow[2], nullptr, 0);
	if (domain_type != 0) {
		printf("Error: Domain type is not \"normal\"(0) but %lu\n", domain_type);
		mysql_free_result(pmyres);
		mysql_close(pmysql);
		return 4;
	}
	
	auto domain_status = strtoul(myrow[3], nullptr, 0);
	if (domain_status != AF_DOMAIN_NORMAL)
		printf("Warning: Domain status is not \"alive\"(0) but %lu\n", domain_status);
	
	max_size = atoll(myrow[0])*1024/store_ratio;
	if (max_size > 0x7FFFFFFF) {
		max_size = 0x7FFFFFFF;
	}
	gx_strlcpy(dir, myrow[1], GX_ARRAY_SIZE(dir));
	domain_id = atoi(myrow[4]);
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	
	auto temp_path = dir + "/exmdb"s;
	if (mkdir(temp_path.c_str(), 0777) && errno != EEXIST) {
		fprintf(stderr, "E-1398: mkdir %s: %s\n", temp_path.c_str(), strerror(errno));
		return 6;
	}
	temp_path += "/exchange.sqlite3";
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
	
	auto filp = fopen_sd("sqlite3_common.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_common.txt: %s\n", strerror(errno));
		return 7;
	}
	auto sql_string = slurp_file(filp.get());
	filp = fopen_sd("sqlite3_public.txt", datadir);
	if (filp == nullptr) {
		fprintf(stderr, "fopen_sd sqlite3_public.txt: %s\n", strerror(errno));
		return 7;
	}
	sql_string += slurp_file(filp.get());
	filp.reset();
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
	/* begin the transaction */
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	
	if (sqlite3_exec(psqlite, sql_string.c_str(), nullptr, nullptr,
	    &err_msg) != SQLITE_OK) {
		printf("fail to execute table creation sql, error: %s\n", err_msg);
		return 9;
	}
	
	std::vector<std::string> namedprop_list;
	auto ret = list_file_read_fixedstrings("propnames.txt", datadir, namedprop_list);
	if (ret == -ENOENT) {
	} else if (ret < 0) {
		fprintf(stderr, "list_file_initd propnames.txt: %s\n", strerror(-ret));
		return 7;
	}
	const char *csql_string = "INSERT INTO named_properties VALUES (?, ?)";
	auto pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	
	i = 0;
	for (const auto &name : namedprop_list) {
		propid = 0x8001 + i;
		sqlite3_bind_int64(pstmt, 1, propid);
		sqlite3_bind_text(pstmt, 2, name.c_str(), -1, SQLITE_STATIC);
		if (sqlite3_step(pstmt) != SQLITE_DONE) {
			printf("fail to step sql inserting\n");
			return 9;
		}
		sqlite3_reset(pstmt);
	}
	pstmt.finalize();
	
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	csql_string = "INSERT INTO store_properties VALUES (?, ?)";
	pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	
	nt_time = rop_util_unix_to_nttime(time(NULL));
	sqlite3_bind_int64(pstmt, 1, PR_CREATION_TIME);
	sqlite3_bind_int64(pstmt, 2, nt_time);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_PROHIBIT_RECEIVE_QUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_PROHIBIT_SEND_QUOTA);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_STORAGE_QUOTA_LIMIT);
	sqlite3_bind_int64(pstmt, 2, max_size);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_MESSAGE_SIZE_EXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_ASSOC_MESSAGE_SIZE_EXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, PR_NORMAL_MESSAGE_SIZE_EXTENDED);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	pstmt.finalize();
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_ROOT,
		0, domain_id, "Root Container", NULL)) {
		printf("fail to create \"root\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_IPMSUBTREE,
		PUBLIC_FID_ROOT, domain_id, "IPM_SUBTREE", NULL)) {
		printf("fail to create \"ipmsubtree\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_NONIPMSUBTREE,
		PUBLIC_FID_ROOT, domain_id, "NON_IPM_SUBTREE", NULL)) {
		printf("fail to create \"ipmsubtree\" folder\n");
		return 10;
	}
	if (FALSE == create_generic_folder(psqlite, PUBLIC_FID_EFORMSREGISTRY,
		PUBLIC_FID_NONIPMSUBTREE, domain_id, "EFORMS REGISTRY", NULL)) {
		printf("fail to create \"ipmsubtree\" folder\n");
		return 10;
	}
	
	csql_string = "INSERT INTO configurations VALUES (?, ?)";
	pstmt = gx_sql_prep(psqlite, csql_string);
	if (pstmt == nullptr) {
		return 9;
	}
	tmp_guid = guid_random_new();
	guid_to_string(&tmp_guid, tmp_buff, sizeof(tmp_buff));
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAILBOX_GUID);
	sqlite3_bind_text(pstmt, 2, tmp_buff, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_CURRENT_EID);
	sqlite3_bind_int64(pstmt, 2, 0x100);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_MAXIMUM_EID);
	sqlite3_bind_int64(pstmt, 2, ALLOCATED_EID_RANGE);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CHANGE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_cn);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_CID);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_LAST_ARTICLE_NUMBER);
	sqlite3_bind_int64(pstmt, 2, g_last_art);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_SEARCH_STATE);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_DEFAULT_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, frightsReadAny | frightsCreate |
		frightsVisible | frightsEditOwned | frightsDeleteOwned);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	sqlite3_reset(pstmt);
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_ANONYMOUS_PERMISSION);
	sqlite3_bind_int64(pstmt, 2, 0);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		return 9;
	}
	pstmt.finalize();
	
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	return EXIT_SUCCESS;
}
