// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errmsg.h>
#include <map>
#include <mysql.h>
#include <set>
#include <string>
#include <typeinfo>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/dbop.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "sql2.hpp"
#define JOIN_WITH_DISPLAYTYPE "LEFT JOIN user_properties AS dt ON u.id=dt.user_id AND dt.proptag=956628995 " /* PR_DISPLAY_TYPE_EX */

using namespace std::string_literals;

DECLARE_SVC_API();

using namespace gromox;
using aliasmap_t = std::multimap<std::string, std::string, std::less<>>;
using propmap_t  = std::multimap<unsigned int, std::pair<unsigned int, std::string>>;
mysql_adaptor_init_param g_parm;
struct sqlconnpool g_sqlconn_pool;

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
	if (current >= recent) {
		mlog(LV_NOTICE, "mysql_adaptor: Current schema n%d is recent.", current);
		return true;
	}
	bool not_me = g_parm.schema_upgrade == SSU_NOT_ME;
	mlog(not_me ? LV_INFO : LV_NOTICE, "mysql_adaptor: Current schema n%d. Update available: n%d.",
	       current, recent);
	if (not_me)
		return true;
	static constexpr const char *msg =
		"The upgrade either needs to be manually done with gromox-dbop(8gx), "
		"or configure mysql_adaptor(4gx) [see warning in manpage] to do it.";
	if (g_parm.schema_upgrade == SSU_NOT_ENABLED) {
		mlog(LV_INFO, "mysql_adaptor: Configured action: disabled. %s", msg);
		return true;
	}
	mlog(LV_INFO, "mysql_adaptor: Configured action: autoupgrade (now).");
	return dbop_mysql_upgrade(conn) == EXIT_SUCCESS;
}

bool db_upgrade_check()
{
	auto conn = g_sqlconn_pool.get_wait();
	if (*conn == nullptr)
		return false;
	return db_upgrade_check_2(conn->get());
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
	if (mysql_real_connect(conn, g_parm.host.c_str(), g_parm.user.c_str(),
	    g_parm.pass.size() != 0 ? g_parm.pass.c_str() : nullptr,
	    g_parm.dbname.c_str(), g_parm.port, nullptr, 0) == nullptr) {
		mlog(LV_ERR, "mysql_adaptor: Failed to connect to mysql server: %s",
		       mysql_error(conn));
		mysql_close(conn);
		return nullptr;
	}
	if (mysql_set_character_set(conn, "utf8mb4") != 0) {
		mlog(LV_ERR, "mysql_adaptor: \"utf8mb4\" not available: %s",
		        mysql_error(conn));
		mysql_close(conn);
		return nullptr;
	}
	return conn;
}

sqlconn &sqlconn::operator=(sqlconn &&o) noexcept
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
		mlog(LV_ERR, "mysql_adaptor: Query \"%s\" failed: %s", q, mysql_error(m_conn));
		return false;
	}
	auto ret = mysql_query(m_conn, q);
	if (ret == 0)
		return true;
	auto sev = connection_severed(mysql_errno(m_conn));
	auto ers = mysql_error(m_conn);
	if (!sev) {
		/* Problem with query itself, connection likely good */
		mlog(LV_ERR, "mysql_adaptor: Query \"%s\" failed: %s", q, ers);
		return false;
	}
	m_conn = sql_make_conn();
	if (m_conn == nullptr) {
		mlog(LV_ERR, "mysql_adaptor: %s, and immediate reconnect unsuccessful: %s", ers, mysql_error(m_conn));
		return false;
	}
	ret = mysql_query(m_conn, q);
	if (ret == 0)
		return true;
	mlog(LV_ERR, "mysql_adaptor: Query \"%s\" failed: %s", q, mysql_error(m_conn));
	return false;
}

resource_pool<sqlconn>::token sqlconnpool::get_wait()
{
	auto c = resource_pool::get_wait();
	if (*c == nullptr)
		*c = sql_make_conn();
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
		sql_user u;
		u.dtypx = DT_MAILUSER;
		if (row[2] != nullptr)
			u.dtypx = static_cast<enum display_type>(strtoul(row[2], nullptr, 0));
		if (u.dtypx == DT_MAILUSER &&
		    strtoul(row[3], nullptr, 0) == AF_USER_CONTACT)
			u.dtypx = DT_REMOTE_MAILUSER;
		u.id = strtoul(row[0], nullptr, 0);
		u.username = row[1];
		u.aliases = aliasmap_extract(amap, row[1]);
		u.propvals = propmap_extract(pmap, u.id);
		u.maildir = row[4];
		auto it = u.propvals.find(PR_ATTR_HIDDEN_GROMOX);
		if (it != u.propvals.end()) {
			u.hidden = strtoul(it->second.c_str(), nullptr, 0);
		} else {
			it = u.propvals.find(PR_ATTR_HIDDEN);
			if (it != u.propvals.end())
				u.hidden = strtoul(it->second.c_str(), nullptr, 0) ? AB_HIDE__DEFAULT : 0;
		}
		if (u.dtypx == DT_DISTLIST) {
			u.list_type = static_cast<enum mlist_type>(strtoul(znul(row[5]), nullptr, 0));
			u.list_priv = strtoul(znul(row[6]), nullptr, 0);
			/* no overwrite of propval is intended */
			if (u.list_type == mlist_type::dyngroup && row[7] != nullptr)
				u.propvals.emplace(PR_DISPLAY_NAME, row[7]);
			else if (u.list_type == mlist_type::group && row[8] != nullptr)
				u.propvals.emplace(PR_DISPLAY_NAME, row[8]);
		}
		pfile.push_back(std::move(u));
	}
	return pfile.size();
}

int mysql_adaptor_get_domain_users(unsigned int domain_id,
    std::vector<sql_user> &pfile) try
{
	char query[430];

	auto conn = g_sqlconn_pool.get_wait();
	if (*conn == nullptr)
		return false;
	gx_snprintf(query, std::size(query),
	         "SELECT u.username, a.aliasname FROM users AS u "
	         "INNER JOIN aliases AS a ON u.domain_id=%d AND u.username=a.mainname", domain_id);
	aliasmap_t amap;
	aliasmap_load(*conn, query, amap);

	gx_snprintf(query, std::size(query),
	         "SELECT u.id, p.proptag, p.propval_bin, p.propval_str FROM users AS u "
	         "INNER JOIN user_properties AS p ON u.domain_id=%d AND u.id=p.user_id "
	         "ORDER BY p.user_id, p.proptag, p.order_id", domain_id);
	propmap_t pmap;
	propmap_load(*conn, query, pmap);

	gx_snprintf(query, std::size(query),
	         "SELECT u.id, u.username, dt.propval_str AS dtypx, u.address_status, "
	         "u.maildir, z.list_type, z.list_privilege, "
	         "cl.classname, gr.title FROM users AS u "
	         JOIN_WITH_DISPLAYTYPE
	         "LEFT JOIN mlists AS z ON u.username=z.listname "
	         "LEFT JOIN classes AS cl ON u.username=cl.listname "
	         "LEFT JOIN `groups` AS `gr` ON `u`.`username`=`gr`.`groupname` "
	         "WHERE u.domain_id=%u AND u.group_id=0", domain_id);
	return userlist_parse(*conn, query, amap, pmap, pfile);
} catch (const std::exception &e) {
	mlog(LV_ERR, "mysql_adaptor: %s %s", __func__, e.what());
	return false;
}

int mysql_adaptor_get_group_users(unsigned int group_id,
    std::vector<sql_user> &pfile) try
{
	char query[491];

	auto conn = g_sqlconn_pool.get_wait();
	if (*conn == nullptr)
		return false;
	snprintf(query, std::size(query),
	         "SELECT u.username, a.aliasname FROM users AS u "
	         "INNER JOIN aliases AS a ON u.username=a.mainname "
	         "WHERE u.group_id=%d",
	         group_id);
	aliasmap_t amap;
	aliasmap_load(*conn, query, amap);

	snprintf(query, std::size(query),
	         "SELECT u.id, p.proptag, p.propval_bin, p.propval_str FROM users AS u "
	         "INNER JOIN user_properties AS p ON u.group_id=%d AND u.id=p.user_id "
	         "ORDER BY p.user_id, p.proptag, p.order_id",
	         group_id);
	propmap_t pmap;
	propmap_load(*conn, query, pmap);

	snprintf(query, std::size(query),
	         "SELECT u.id, u.username, dt.propval_str AS dtypx, u.address_status, "
	         "u.maildir, z.list_type, z.list_privilege, "
	         "cl.classname, gr.title FROM users AS u "
	         JOIN_WITH_DISPLAYTYPE
	         "LEFT JOIN mlists AS z ON u.username=z.listname "
	         "LEFT JOIN classes AS cl ON u.username=cl.listname "
	         "LEFT JOIN `groups` AS `gr` ON `u`.`username`=`gr`.`groupname` "
	         "WHERE u.group_id=%d", group_id);
	return userlist_parse(*conn, query, amap, pmap, pfile);
} catch (const std::exception &e) {
	mlog(LV_ERR, "mysql_adaptor: %s %s", __func__, e.what());
	return false;
}

errno_t mysql_adaptor_scndstore_hints(unsigned int pri,
    std::vector<sql_user> &hints) try
{
	char query[233];
	snprintf(query, std::size(query),
	         "SELECT u.id, u.username, u.maildir, up.propval_str "
	         "FROM secondary_store_hints AS s "
	         "INNER JOIN users AS u ON s.`secondary`=u.id "
	         "LEFT JOIN user_properties AS up ON u.id=up.user_id AND up.proptag=0x3001001f "
	         "WHERE s.`primary`=%u", pri);
	auto conn = g_sqlconn_pool.get_wait();
	if (*conn == nullptr || !conn->query(query))
		return EIO;
	DB_RESULT result = mysql_store_result(conn->get());
	if (result == nullptr)
		return ENOMEM;
	DB_ROW row;
	while ((row = result.fetch_row()) != nullptr) {
		sql_user u;
		u.id = strtoul(row[0], nullptr, 0);
		u.username = znul(row[1]);
		u.maildir = znul(row[2]);
		if (row[3] != nullptr)
			u.propvals.emplace(PR_DISPLAY_NAME, row[3]);
		hints.push_back(std::move(u));
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1638: ENOMEM");
	return ENOMEM;
}

static int mysql_adaptor_domain_list_query(const char *domain) try
{
	char qdom[UDOM_SIZE*2];
	mysql_adaptor_encode_squote(domain, qdom);
	char query[576];
	snprintf(query, std::size(query), "SELECT 1 FROM domains WHERE domain_status=0 AND domainname='%s'", qdom);
	auto conn = g_sqlconn_pool.get_wait();
	if (*conn == nullptr || !conn->query(query))
		return -EIO;
	DB_RESULT res = mysql_store_result(conn->get());
	if (res == nullptr)
		return -ENOMEM;
	return res.fetch_row() != nullptr;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1647: ENOMEM");
	return -ENOMEM;
}

static errno_t mysql_adaptor_homeserver(const char *entity, bool is_pvt,
    std::pair<std::string, std::string> &servers) try
{
	char qent[UADDR_SIZE*2];
	mysql_adaptor_encode_squote(entity, qent);
	auto qstr = is_pvt ?
	            "SELECT sv.hostname, sv.extname FROM users AS u "
	            "LEFT JOIN servers AS sv ON u.homeserver=sv.id "
	            "WHERE u.username='"s + qent + "' LIMIT 2" :
	            "SELECT sv.hostname, sv.extname FROM domains AS d "
	            "LEFT JOIN servers AS sv ON d.homeserver=sv.id "
	            "WHERE d.domainname='"s + qent + "' LIMIT 2";
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn->query(qstr.c_str()))
		return EIO;
	DB_RESULT res = mysql_store_result(conn->get());
	if (res == nullptr)
		return ENOMEM;
	conn.finish();
	if (res.num_rows() != 1)
		return ENOENT;
	auto row = res.fetch_row();
	servers.first  = znul(row[0]);
	servers.second = znul(row[1]);
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1210: ENOMEM");
	return -ENOMEM;
}

void mysql_adaptor_init(mysql_adaptor_init_param &&parm)
{
	g_parm = std::move(parm);
	g_sqlconn_pool.resize(g_parm.conn_num);
	g_sqlconn_pool.bump();

	auto qstr = "SELECT u.id FROM users AS u LEFT JOIN user_properties "
	            "AS up ON u.id=up.user_id AND up.proptag=0x39050003 "
	            "WHERE u.domain_id > 0 AND up.proptag IS NULL";
	auto conn = g_sqlconn_pool.get_wait();
	if (conn->query(qstr)) {
		DB_RESULT res = mysql_store_result(conn->get());
		if (res != nullptr && res.num_rows() > 0)
			mlog(LV_ERR, "mysql_adaptor: "
			        "There are %zu users with no PR_DISPLAY_TYPE_EX set, "
			        "which makes their existence _undefined_.",
			        res.num_rows());
	}
}

static constexpr cfg_directive mysql_adaptor_cfg_defaults[] = {
	{"connection_num", "8", CFG_SIZE},
	{"enable_firsttime_password", "no", CFG_BOOL},
	{"mysql_dbname", "email"},
	{"mysql_host", "localhost"},
	{"mysql_password", ""},
	{"mysql_port", "3306"},
	{"mysql_rdwr_timeout", "0", CFG_TIME},
	{"mysql_username", "root"},
	CFG_TABLE_END,
};

static bool mysql_adaptor_reload_config(std::shared_ptr<CONFIG_FILE> cfg) try
{
	if (cfg == nullptr)
		cfg = config_file_initd("mysql_adaptor.cfg", get_config_path(),
		      mysql_adaptor_cfg_defaults);
	if (cfg == nullptr) {
		mlog(LV_ERR, "mysql_adaptor: config_file_initd mysql_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	mysql_adaptor_init_param par;
	par.conn_num = cfg->get_ll("connection_num");
	par.host = cfg->get_value("mysql_host");
	par.port = cfg->get_ll("mysql_port");
	par.user = cfg->get_value("mysql_username");
	par.pass = cfg->get_value("mysql_password");
	auto p2 = cfg->get_value("mysql_password_mode_id107");
	if (p2 != nullptr)
		par.pass = zstd_decompress(base64_decode(p2));
	p2 = cfg->get_value("mysql_password_mode_id555");
	if (p2 != nullptr)
		par.pass = sss_obf_reverse(base64_decode(p2));
	par.dbname = cfg->get_value("mysql_dbname");
	par.timeout = cfg->get_ll("mysql_rdwr_timeout");
	mlog(LV_INFO, "mysql_adaptor: host [%s]:%d, #conn=%d timeout=%d, db=%s",
	       par.host.size() == 0 ? "*" : par.host.c_str(), par.port,
	       par.conn_num, par.timeout, par.dbname.c_str());
	auto v = cfg->get_value("schema_upgrade");
	if (v == nullptr)
		v = cfg->get_value("schema_upgrades");
	par.schema_upgrade = SSU_NOT_ENABLED;
	auto prog_id = get_prog_id();
	auto host_id = get_host_ID();
	if (prog_id == nullptr || strcmp(prog_id, "http") != 0)
		par.schema_upgrade = SSU_NOT_ME;
	else if (v != nullptr && strncmp(v, "host:", 5) == 0 &&
	    prog_id != nullptr && strcmp(&v[5], host_id) == 0)
		par.schema_upgrade = SSU_AUTOUPGRADE;

	par.enable_firsttimepw = cfg->get_ll("enable_firsttime_password");
	mysql_adaptor_init(std::move(par));
	return true;
} catch (const cfg_error &) {
	return false;
}

/**
 * @brief      Get aliases of user
 *
 * @param      username  User to get aliases for
 * @param      aliases   [out] List of aliases retrieved
 *
 * @return     true if successful, false otherwise
 */
bool mysql_adaptor_get_user_aliases(const char *username, std::vector<std::string>& aliases) try
{
	char temp_name[UADDR_SIZE*2];
	mysql_adaptor_encode_squote(username, temp_name);

	auto conn = g_sqlconn_pool.get_wait();
	auto qstr = fmt::format("SELECT aliasname FROM aliases WHERE mainname='{}'", temp_name);
	DB_RESULT res;
	if(!conn->query(qstr.c_str()) || !(res = mysql_store_result(conn->get())))
		return false;

	aliases.clear();
	aliases.reserve(res.num_rows());
	for(DB_ROW row = res.fetch_row(); row; row = res.fetch_row())
		aliases.emplace_back(row[0]);
	return true;

} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
	return false;
}

/**
 * @brief     Get user properties from MySQL
 *
 * Unsupported multi-value or binary properties are omitted.
 * The resulting properties structure must be properly freed.
 *
 * @param      username     User to get aliases for
 * @param      properties   [out] Tagged propvals retrieved
 *
 * @return     true if successful, false otherwise
 */
bool mysql_adaptor_get_user_properties(const char* username, TPROPVAL_ARRAY& properties) try
{
	char temp_name[UADDR_SIZE*2];
	mysql_adaptor_encode_squote(username, temp_name);

	auto qstr = fmt::format("SELECT u.id, p.proptag, p.propval_bin, p.propval_str "
	                        "FROM users AS u "
	                        "INNER JOIN user_properties AS p ON u.id=p.user_id "
	                        "WHERE u.username='{}'", temp_name);

	auto conn = g_sqlconn_pool.get_wait();
	DB_RESULT res;
	if(!conn->query(qstr.c_str()) || !(res = mysql_store_result(conn->get())))
		return false;

	for(DB_ROW row = res.fetch_row(); row; row = res.fetch_row())
	{
		uint32_t tag = uint32_t(strtoul(row[1], nullptr, 0));
		const char* strval = row[3];
		if(!strval) // Binary values are currently not supported
			continue;

		switch(PROP_TYPE(tag))
		{
		case PT_BOOLEAN: {
			uint8_t converted = uint8_t(strtoul(strval, nullptr, 0));
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_SHORT: {
			uint16_t converted = uint16_t(strtoul(strval, nullptr, 0));
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_LONG:
		case PT_ERROR: {
			uint32_t converted = uint32_t(strtoul(strval, nullptr, 0));
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_I8:
		case PT_CURRENCY:
		case PT_SYSTIME: {
			uint64_t converted = strtoull(strval, nullptr, 0);
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_FLOAT: {
			float converted = strtof(strval, nullptr);
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_DOUBLE:
		case PT_APPTIME: {
			float converted = strtof(strval, nullptr);
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_STRING8:
		case PT_UNICODE:
			if(!row[3])
				continue;
			if (properties.set(tag, strval) != 0)
				return false;
			break;
		}
	}
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
	return false;
}

static BOOL svc_mysql_adaptor(int reason, void **data)
{
	if (reason == PLUGIN_FREE) {
		mysql_adaptor_stop();
		return TRUE;
	} else if (reason == PLUGIN_RELOAD) {
		mysql_adaptor_reload_config(nullptr);
		return TRUE;
	} else if (reason != PLUGIN_INIT) {
		return TRUE;
	}

	LINK_SVC_API(data);
	auto cfg = config_file_initd("mysql_adaptor.cfg", get_config_path(),
	           mysql_adaptor_cfg_defaults);
	if (cfg == nullptr) {
		mlog(LV_ERR, "mysql_adaptor: config_file_initd mysql_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	if (!mysql_adaptor_reload_config(cfg))
		return false;
	if (mysql_adaptor_run() != 0) {
		mlog(LV_ERR, "mysql_adaptor: failed to startup");
		return false;
	}
#define E(f, s) do { \
	if (!register_service((s), mysql_adaptor_ ## f)) { \
		mlog(LV_ERR, "mysql_adaptor: failed to register the \"%s\" service", (s)); \
		return false; \
	} \
} while (false)
	E(meta, "mysql_auth_meta");
	E(login2, "mysql_auth_login2");
	E(setpasswd, "set_password");
	E(get_username_from_id, "get_username_from_id");
	E(get_id_from_username, "get_id_from_username");
	E(get_id_from_maildir, "get_id_from_maildir");
	E(get_user_displayname, "get_user_displayname");
	E(get_user_privilege_bits, "get_user_privilege_bits");
	E(get_user_lang, "get_user_lang");
	E(set_user_lang, "set_user_lang");
	E(get_timezone, "get_timezone");
	E(set_timezone, "set_timezone");
	E(get_maildir, "get_maildir");
	E(get_homedir, "get_homedir");
	E(get_homedir_by_id, "get_homedir_by_id");
	E(get_id_from_homedir, "get_id_from_homedir");
	E(get_user_ids, "get_user_ids");
	E(get_domain_ids, "get_domain_ids");
	E(get_mlist_ids, "get_mlist_ids");
	E(get_org_domains, "get_org_domains");
	E(get_domain_info, "get_domain_info");
	E(check_same_org, "check_same_org");
	E(get_domain_groups, "get_domain_groups");
	E(get_group_users, "get_group_users");
	E(get_domain_users, "get_domain_users");
	E(check_mlist_include, "check_mlist_include");
	E(check_same_org2, "check_same_org2");
	E(check_user, "check_user");
	E(get_mlist_memb, "get_mlist_memb");
	E(get_user_info, "get_user_info");
	E(get_user_aliases, "get_user_aliases");
	E(get_user_properties, "get_user_properties");
	E(scndstore_hints, "scndstore_hints");
	E(domain_list_query, "domain_list_query");
	E(homeserver, "get_homeserver");
#undef E
	return TRUE;
}
SVC_ENTRY(svc_mysql_adaptor);
