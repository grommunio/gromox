// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "data_source.h"
#include <gromox/system_log.h>
#include <gromox/util.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mysql.h>
#define DOMAIN_PRIVILEGE_SUBSYSTEM          0x8

#define DOMAIN_PRIVILEGE_NETDISK            0x10

#define DOMAIN_PRIVILEGE_EXTPASSWD          0x20
#define GROUP_PRIVILEGE_DOMAIN_MONITOR		0x200

using namespace gromox;

static char g_host[256];
static uint16_t g_port;
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];

void data_source_init(const char *host, uint16_t port, const char *user,
	const char *password, const char *db_name)
{
	gx_strlcpy(g_host, host, GX_ARRAY_SIZE(g_host));
	g_port = port;
	gx_strlcpy(g_user, user, GX_ARRAY_SIZE(g_user));
	if (NULL == password || '\0' == password[0]) {
		g_password = NULL;
	} else {
		gx_strlcpy(g_password_buff, password, GX_ARRAY_SIZE(g_password_buff));
		g_password = g_password_buff;
	}
	gx_strlcpy(g_db_name, db_name, GX_ARRAY_SIZE(g_db_name));
}

BOOL data_source_get_domain_list(std::vector<DOMAIN_ITEM> &pcollect)
{
	int i, rows;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	i = 0;
	
 RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	snprintf(sql_string, arsizeof(sql_string), "SELECT domainname, homedir FROM domains "
		"WHERE domain_status=0");
	
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
	for (i = 0; i < rows; ++i) try {
		myrow = mysql_fetch_row(pmyres);
		std::string domainname = myrow[0];
		std::string homedir = myrow[1];
		HX_strlower(domainname.data());
		pcollect.emplace_back(DOMAIN_ITEM{std::move(domainname), std::move(homedir)});
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "W-1: ENOMEM\n");
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}

BOOL data_source_get_alias_list(std::vector<ALIAS_ITEM> &pcollect)
{
	int i, rows;
	char sql_string[4096];
	MYSQL_RES *pmyres;
	MYSQL_ROW myrow;
	MYSQL *pmysql;
	
	i = 0;
	
 RETRYING:
	if (i > 3) {
		return FALSE;
	}
	
	if (NULL == (pmysql = mysql_init(NULL)) ||
		NULL == mysql_real_connect(pmysql, g_host, g_user, g_password,
		g_db_name, g_port, NULL, 0)) {
		if (NULL != pmysql) {
			system_log_info("[data_source]: Failed to connect to mysql server, "
				"reason: %s", mysql_error(pmysql));
		}
		i ++;
		sleep(1);
		goto RETRYING;
	}

	snprintf(sql_string, arsizeof(sql_string), "SELECT aliasname, mainname FROM aliases");
	
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
	for (i = 0; i < rows; ++i) try {
		myrow = mysql_fetch_row(pmyres);
		std::string aliasname = myrow[0], mainname = myrow[1];
		HX_strlower(aliasname.data());
		HX_strlower(mainname.data());
		pcollect.emplace_back(ALIAS_ITEM{std::move(aliasname), std::move(mainname)});
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "W-2: ENOMEM\n");
	}
	
	mysql_free_result(pmyres);
	mysql_close(pmysql);
	return TRUE;
}
