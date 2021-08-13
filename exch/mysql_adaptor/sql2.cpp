// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/dbop.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <mysql.h>
#include <errmsg.h>
#include "mysql_adaptor.h"
#include "sql2.hpp"

using namespace gromox;
using aliasmap_t = std::multimap<std::string, std::string, std::less<>>;
using propmap_t  = std::multimap<unsigned int, std::pair<unsigned int, std::string>>;
mysql_adaptor_init_param g_parm;
struct sqlconnpool g_sqlconn_pool;

static inline const char *z_null(const char *s)
{
	return s != nullptr ? s : "";
}

static bool connection_severed(int e)
{
#ifdef ER_CONNECTION_KILLED
	/* server got sigterm */
	if (e == ER_CONNECTION_KILLED)
		return true;
#endif
	return e == CR_SERVER_LOST || e == CR_SERVER_GONE_ERROR;
}

static bool db_upgrade_check_2(MYSQL *conn)
{
	auto recent = dbop_mysql_recentversion();
	auto current = dbop_mysql_schemaversion(conn);
	if (current < 0)
		return false;
	if (current >= recent)
		return true;
	printf("[mysql_adaptor]: Current schema n%d. Update available: n%d. Configured action: ",
	       current, recent);
	static constexpr const char *msg =
		"The upgrade either needs to be manually done with gromox-dbop(8gx), "
		"or configure mysql_adaptor(4gx) [see warning in manpage] to do it.";
	if (g_parm.schema_upgrade == S_SKIP) {
		printf("skip.\n");
		puts(msg);
		return true;
	} else if (g_parm.schema_upgrade != S_AUTOUP) {
		printf("abort.\n");
		puts(msg);
		return false;
	}
	printf("autoupgrade (now).\n");
	return dbop_mysql_upgrade(conn) == EXIT_SUCCESS;
}

bool db_upgrade_check()
{
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	return db_upgrade_check_2(conn.res.get());
}

MYSQL *sql_make_conn()
{
	MYSQL *conn = mysql_init(nullptr);
	if (conn == nullptr)
		return nullptr;
	if (g_parm.timeout > 0) {
		mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &g_parm.timeout);
		mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &g_parm.timeout);
	}
	mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	if (mysql_real_connect(conn, g_parm.host.c_str(), g_parm.user.c_str(),
	    g_parm.pass.size() != 0 ? g_parm.pass.c_str() : nullptr,
	    g_parm.dbname.c_str(), g_parm.port, nullptr, 0) != nullptr)
		return conn;
	printf("[mysql_adaptor]: Failed to connect to mysql server: %s\n",
	       mysql_error(conn));
	mysql_close(conn);
	return nullptr;
}

sqlconn &sqlconn::operator=(sqlconn &&o)
{
	mysql_close(m_conn);
	m_conn = o.m_conn;
	o.m_conn = nullptr;
	return *this;
}

bool sqlconn::query(const char *q)
{
	if (m_conn == nullptr) {
		m_conn = sql_make_conn();
		if (m_conn == nullptr)
			return false;
		if (mysql_query(m_conn, q) == 0)
			return true;
		fprintf(stderr, "[mysql_adaptor]: Query \"%s\" failed: %s\n", q, mysql_error(m_conn));
		return false;
	}
	auto ret = mysql_query(m_conn, q);
	if (ret == 0)
		return true;
	auto sev = connection_severed(mysql_errno(m_conn));
	auto ers = mysql_error(m_conn);
	if (!sev) {
		/* Problem with query itself, connection likely good */
		fprintf(stderr, "[mysql_adaptor]: Query \"%s\" failed: %s\n", q, ers);
		return false;
	}
	m_conn = sql_make_conn();
	if (m_conn == nullptr) {
		fprintf(stderr, "[mysql_adaptor]: %s, and immediate reconnect unsuccessful: %s\n", ers, mysql_error(m_conn));
		return false;
	}
	ret = mysql_query(m_conn, q);
	if (ret == 0)
		return true;
	fprintf(stderr, "[mysql_adaptor]: Query \"%s\" failed: %s\n", q, mysql_error(m_conn));
	return false;
}

resource_pool<sqlconn>::token sqlconnpool::get_wait()
{
	auto c = resource_pool::get_wait();
	if (c.res == nullptr)
		c.res = sql_make_conn();
	return c;
}

static std::vector<std::string>
aliasmap_extract(aliasmap_t &amap, const char *username)
{
	std::vector<std::string> v;
	auto stop = amap.upper_bound(username);
	for (auto it = amap.lower_bound(username); it != stop; ) {
		auto next = std::next(it);
		auto node = amap.extract(it);
		v.push_back(std::move(node.mapped()));
		it = next;
	}
	return v;
}

static bool aliasmap_load(sqlconn &conn, const char *query, aliasmap_t &out)
{
	if (!conn.query(query))
		return false;
	DB_RESULT res = mysql_store_result(conn.get());
	if (res == nullptr)
		return false;
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr)
		out.emplace(row[0], row[1]);
	return true;
}

static std::map<unsigned int, std::string>
propmap_extract(propmap_t &pmap, unsigned int user_id)
{
	std::map<unsigned int, std::string> v;
	auto stop = pmap.upper_bound(user_id);
	for (auto it = pmap.lower_bound(user_id); it != stop; ) {
		auto next = std::next(it);
		auto node = pmap.extract(it);
		v.emplace(node.mapped().first, std::move(node.mapped().second));
		it = next;
	}
	return v;
}

static bool propmap_load(sqlconn &conn, const char *query, propmap_t &out)
{
	if (!conn.query(query))
		return false;
	DB_RESULT res = mysql_store_result(conn.get());
	if (res == nullptr)
		return false;
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr) {
		if (row[2] == nullptr && row[3] == nullptr)
			continue;
		auto len = res.row_lengths();
		unsigned int id = strtoul(row[0], nullptr, 0);
		unsigned int pt = strtoul(row[1], nullptr, 0);
		auto data = row[2] != nullptr ? std::string(row[2], len[2]) : std::string(row[3]);
		out.emplace(id, std::make_pair(pt, std::move(data)));
	}
	return true;
}

static int userlist_parse(sqlconn &conn, const char *query,
    aliasmap_t &amap, propmap_t &pmap, std::vector<sql_user> &pfile)
{
	if (!conn.query(query))
		return false;
	DB_RESULT result = mysql_store_result(conn.get());
	if (result == nullptr)
		return false;

	for (size_t i = 0; i < result.num_rows(); ++i) {
		auto row = result.fetch_row();
		auto adrtype = strtoul(row[2], nullptr, 0);
		auto subtype = strtoul(row[3], nullptr, 0);
		if (adrtype == ADDRESS_TYPE_NORMAL && subtype == SUB_TYPE_ROOM)
			adrtype = ADDRESS_TYPE_ROOM;
		else if (adrtype == ADDRESS_TYPE_NORMAL && subtype == SUB_TYPE_EQUIPMENT)
			adrtype = ADDRESS_TYPE_EQUIPMENT;

		sql_user u;
		u.addr_type = adrtype;
		u.id = strtoul(row[0], nullptr, 0);
		u.username = row[1];
		u.aliases = aliasmap_extract(amap, row[1]);
		u.propvals = propmap_extract(pmap, u.id);
		u.maildir = row[4];
		if (adrtype == ADDRESS_TYPE_MLIST) {
			u.list_type = strtoul(z_null(row[5]), nullptr, 0);
			u.list_priv = strtoul(z_null(row[6]), nullptr, 0);
			/* no overwrite of propval is intended */
			if (u.list_type == MLIST_TYPE_CLASS && row[7] != nullptr)
				u.propvals.emplace(PR_DISPLAY_NAME, row[7]);
			else if (u.list_type == MLIST_TYPE_GROUP && row[8] != nullptr)
				u.propvals.emplace(PR_DISPLAY_NAME, row[8]);
		}
		pfile.push_back(std::move(u));
	}
	return pfile.size();
}

int mysql_adaptor_get_class_users(int class_id, std::vector<sql_user> &pfile) try
{
	char query[360];

	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.username, a.aliasname FROM users AS u "
	         "INNER JOIN aliases AS a ON u.username=a.mainname "
	         "INNER JOIN members AS m ON m.class_id=%d AND m.username=u.username", class_id);
	aliasmap_t amap;
	aliasmap_load(conn.res, query, amap);

	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.id, p.proptag, p.propval_bin, p.propval_str FROM users AS u "
	         "INNER JOIN user_properties AS p ON u.id=p.user_id "
	         "INNER JOIN members AS m ON m.class_id=%d AND m.username=u.username "
	         "ORDER BY p.user_id, p.proptag, p.order_id", class_id);
	propmap_t pmap;
	propmap_load(conn.res, query, pmap);

	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.id, u.username, u.address_type, u.sub_type, "
	         "u.maildir, z.list_type, z.list_privilege, "
	         "cl.classname, gr.title FROM users AS u "
	         "INNER JOIN members AS m ON m.class_id=%d AND m.username=u.username "
	         "LEFT JOIN mlists AS z ON u.username=z.listname "
	         "LEFT JOIN classes AS cl ON u.username=cl.listname "
	         "LEFT JOIN groups AS gr ON u.username=gr.groupname", class_id);
	return userlist_parse(conn.res, query, amap, pmap, pfile);
} catch (const std::exception &e) {
	printf("[mysql_adaptor]: %s %s\n", __func__, e.what());
	return false;
}

int mysql_adaptor_get_domain_users(int domain_id, std::vector<sql_user> &pfile) try
{
	char query[328];

	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.username, a.aliasname FROM users AS u "
	         "INNER JOIN aliases AS a ON u.domain_id=%d AND u.username=a.mainname", domain_id);
	aliasmap_t amap;
	aliasmap_load(conn.res, query, amap);

	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.id, p.proptag, p.propval_bin, p.propval_str FROM users AS u "
	         "INNER JOIN user_properties AS p ON u.domain_id=%d AND u.id=p.user_id "
	         "ORDER BY p.user_id, p.proptag, p.order_id", domain_id);
	propmap_t pmap;
	propmap_load(conn.res, query, pmap);

	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.id, u.username, u.address_type, u.sub_type, "
	         "u.maildir, z.list_type, z.list_privilege, "
	         "cl.classname, gr.title FROM users AS u "
	         "LEFT JOIN mlists AS z ON u.username=z.listname "
	         "LEFT JOIN classes AS cl ON u.username=cl.listname "
	         "LEFT JOIN groups AS gr ON u.username=gr.groupname "
	         "WHERE u.domain_id=%u AND u.group_id=0", domain_id);
	return userlist_parse(conn.res, query, amap, pmap, pfile);
} catch (const std::exception &e) {
	printf("[mysql_adaptor]: %s %s\n", __func__, e.what());
	return false;
}

int mysql_adaptor_get_group_users(int group_id, std::vector<sql_user> &pfile) try
{
	char query[388];

	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.username, a.aliasname FROM users AS u "
	         "INNER JOIN aliases AS a ON u.username=a.mainname "
	         "WHERE u.group_id=%d AND (SELECT COUNT(*) AS num "
	         "FROM members AS m WHERE u.username=m.username)=0",
	         group_id);
	aliasmap_t amap;
	aliasmap_load(conn.res, query, amap);

	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.id, p.proptag, p.propval_bin, p.propval_str FROM users AS u "
	         "INNER JOIN user_properties AS p ON u.group_id=%d AND u.id=p.user_id "
	         "WHERE (SELECT COUNT(*) AS num FROM members AS m WHERE u.username=m.username)=0 "
	         "ORDER BY p.user_id, p.proptag, p.order_id",
	         group_id);
	propmap_t pmap;
	propmap_load(conn.res, query, pmap);

	snprintf(query, GX_ARRAY_SIZE(query),
	         "SELECT u.id, u.username, u.address_type, u.sub_type, "
	         "u.maildir, z.list_type, z.list_privilege, "
	         "cl.classname, gr.title FROM users AS u "
	         "LEFT JOIN mlists AS z ON u.username=z.listname "
	         "LEFT JOIN classes AS cl ON u.username=cl.listname "
	         "LEFT JOIN groups AS gr ON u.username=gr.groupname "
	         "WHERE u.group_id=%d AND (SELECT COUNT(*) AS num "
	         "FROM members AS m WHERE u.username=m.username)=0", group_id);
	return userlist_parse(conn.res, query, amap, pmap, pfile);
} catch (const std::exception &e) {
	printf("[mysql_adaptor]: %s %s\n", __func__, e.what());
	return false;
}

bool mysql_adaptor_reload_config(const char *path,
    const char *host_id, const char *prog_id) try
{
	mysql_adaptor_init_param par;
	auto pfile = config_file_initd("mysql_adaptor.cfg", path);
	if (pfile == nullptr) {
		printf("[mysql_adaptor]: config_file_initd mysql_adaptor.cfg: %s\n",
		       strerror(errno));
		return false;
	}
	auto v = config_file_get_value(pfile, "connection_num");
	par.conn_num = v != nullptr ? strtoul(v, nullptr, 0) : 8;
	v = config_file_get_value(pfile, "mysql_host");
	par.host = v != nullptr ? v : "";
	v = config_file_get_value(pfile, "mysql_port");
	par.port = v != nullptr ? strtoul(v, nullptr, 0) : 3306;
	v = config_file_get_value(pfile, "mysql_username");
	par.user = v != nullptr ? v : "root";
	v = config_file_get_value(pfile, "mysql_password");
	par.pass = v != nullptr ? v : "";
	v = config_file_get_value(pfile, "mysql_dbname");
	par.dbname = v != nullptr ? v : "email";
	v = config_file_get_value(pfile, "mysql_rdwr_timeout");
	par.timeout = v != nullptr ? strtoul(v, nullptr, 0) : 0;
	printf("[mysql_adaptor]: host [%s]:%d, #conn=%d timeout=%d, db=%s\n",
	       par.host.size() == 0 ? "*" : par.host.c_str(), par.port,
	       par.conn_num, par.timeout, par.dbname.c_str());
	v = config_file_get_value(pfile, "schema_upgrades");
	par.schema_upgrade = S_SKIP;
	if (v != nullptr && strncmp(v, "host:", 5) == 0 &&
	    prog_id != nullptr && strcmp(prog_id, "http") == 0 &&
	    strcmp(v + 5, host_id) == 0) {
		par.schema_upgrade = S_AUTOUP;
	} else if (v != nullptr && strcmp(v, "skip") == 0) {
		par.schema_upgrade = S_SKIP;
	} else if (v != nullptr && strcmp(v, "autoupgrade") == 0) {
		par.schema_upgrade = S_AUTOUP;
	}

	v = config_file_get_value(pfile, "enable_firsttime_password");
	par.enable_firsttimepw = v != nullptr && strcmp(v, "yes") == 0;
	mysql_adaptor_init(std::move(par));
	return true;
} catch (const std::bad_alloc &) {
	return false;
}

void mysql_adaptor_init(mysql_adaptor_init_param &&parm)
{
	g_parm = std::move(parm);
	g_sqlconn_pool.resize(g_parm.conn_num);
	g_sqlconn_pool.bump();
}
