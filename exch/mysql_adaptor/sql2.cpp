// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <algorithm>
#include <cctype>
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
#if defined(HAVE_CRYPT_H)
#	include <crypt.h>
#endif
#ifdef __OpenBSD__
#	include <pwd.h>
#endif
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
DECLARE_SVC_API(mysql_adaptor, extern);
using namespace mysql_adaptor;

using namespace gromox;
using aliasmap_t = std::multimap<std::string, std::string, std::less<>>;
using propmap_t  = std::multimap<unsigned int, std::pair<unsigned int, std::string>>;
mysql_adaptor_init_param g_parm;
struct sqlconnpool g_sqlconn_pool;

#ifdef __OpenBSD__
#elif defined(__sun)
static std::string crypt_estar(const char *a, const char *b)
{
	auto r = crypt(a, b); /* uses thread-local storage */
	return r != nullptr ? r : "*0";
}
#else
static std::string crypt_estar(const char *a, const char *b)
{
	struct crypt_data cd{};
	auto r = crypt_r(a, b, &cd);
	return r != nullptr ? r : "*0";
}
#endif

std::string sql_crypt_newhash(const char *pw)
{
#if defined(__OpenBSD__)
	static char ret[_PASSWORD_LEN];
	if (crypt_newhash(pw, "bcrypt", ret, sizeof(ret)) != 0)
		return "*0";
	return ret;
#else
	static char crypt_salt[65]=
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
	char salt[21] = "$6$";
	randstring(salt + 3, 16, crypt_salt);
	salt[19] = '$';
	salt[20] = '\0';
	auto ret = crypt_estar(pw, salt);
	if (ret[0] == '$')
		return ret;
	salt[1] = '1';
	return crypt_estar(pw, salt);
#endif
}

bool sql_crypt_verify(const char *p, const char *enc)
{
#ifdef __OpenBSD__
	return crypt_checkpass(p, enc) == 0;
#else
	return crypt_estar(p, enc) == enc;
#endif
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
	if (current >= recent) {
		mlog(LV_NOTICE, "mysql_adaptor: Current schema n%d is recent.", current);
		return true;
	}
	mlog(LV_NOTICE, "mysql_adaptor: Current schema n%d. Update available: n%d.",
	       current, recent);
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
	if (!conn)
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

std::string sqlconn::quote(std::string_view sv)
{
	std::string out;
	out.resize(sv.size() * 2);
	out.resize(mysql_real_escape_string(m_conn, out.data(), sv.data(), sv.size()));
	return out;
}

bool sqlconn::query(std::string_view qv)
{
	if (m_conn == nullptr) {
		m_conn = sql_make_conn();
		if (m_conn == nullptr)
			return false;
		if (mysql_real_query(m_conn, qv.data(), qv.size()) == 0)
			return true;
		mlog(LV_ERR, "mysql_adaptor: Query \"%.*s\" failed: %s",
			static_cast<int>(qv.size()), qv.data(), mysql_error(m_conn));
		return false;
	}
	auto ret = mysql_real_query(m_conn, qv.data(), qv.size());
	if (ret == 0)
		return true;
	auto sev = connection_severed(mysql_errno(m_conn));
	auto ers = mysql_error(m_conn);
	if (!sev) {
		/* Problem with query itself, connection likely good */
		mlog(LV_ERR, "mysql_adaptor: Query \"%.*s\" failed: %s",
			static_cast<int>(qv.size()), qv.data(), ers);
		return false;
	}
	m_conn = sql_make_conn();
	if (m_conn == nullptr) {
		mlog(LV_ERR, "mysql_adaptor: %s, and immediate reconnect unsuccessful: %s", ers, mysql_error(m_conn));
		return false;
	}
	ret = mysql_real_query(m_conn, qv.data(), qv.size());
	if (ret == 0)
		return true;
	mlog(LV_ERR, "mysql_adaptor: Query \"%.*s\" failed: %s",
		static_cast<int>(qv.size()), qv.data(), mysql_error(m_conn));
	return false;
}

resource_pool<sqlconn>::token sqlconnpool::get_wait()
{
	auto c = resource_pool::get_wait();
	if (!c)
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
	auto res = conn.store_result();
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
	auto res = conn.store_result();
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
	auto result = conn.store_result();
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
	if (!conn)
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
	if (!conn)
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
	if (!conn || !conn->query(query))
		return EIO;
	auto result = conn->store_result();
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

int mysql_adaptor_domain_list_query(const char *domain) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return -EIO;
	auto qstr = "SELECT 1 FROM domains WHERE domain_status=0 AND domainname='" +
	            conn->quote(domain) + "'";
	if (!conn->query(qstr))
		return -EIO;
	auto res = conn->store_result();
	if (res == nullptr)
		return -ENOMEM;
	return res.fetch_row() != nullptr;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1647: ENOMEM");
	return -ENOMEM;
}

errno_t mysql_adaptor_get_homeserver(const char *entity, bool is_pvt,
    std::pair<std::string, std::string> &servers) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return EIO;
	auto qent = conn->quote(entity);
	auto qstr = is_pvt ?
	            "SELECT sv.hostname, sv.extname FROM users AS u "
	            "LEFT JOIN servers AS sv ON u.homeserver=sv.id "
	            "LEFT JOIN altnames AS alt ON u.id=alt.user_id "
	            "AND alt.altname='" + qent + "' "
	            "WHERE u.username='" + qent + "' OR "
	            "alt.altname='" + qent + "' LIMIT 2" :
	            "SELECT sv.hostname, sv.extname FROM domains AS d "
	            "LEFT JOIN servers AS sv ON d.homeserver=sv.id "
	            "WHERE d.domainname='" + qent + "' LIMIT 2";
	if (!conn->query(qstr))
		return EIO;
	auto res = conn->store_result();
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
	mlog(LV_ERR, "E-2132: ENOMEM");
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
	if (!conn) {
		mlog(LV_ERR, "SQL connections are unobtainium");
		return;
	}
	if (conn->query(qstr)) {
		auto res = conn->store_result();
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

static bool mysql_adaptor_reload_config(std::shared_ptr<CONFIG_FILE> &&cfg)
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
	if (!str_isascii(username))
		return true;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "SELECT aliasname FROM aliases WHERE mainname='" +
	            conn->quote(username) + "'";
	DB_RESULT res;
	if (!conn->query(qstr) || !(res = conn->store_result()))
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
bool mysql_adaptor_get_user_properties(const char *username, TPROPVAL_ARRAY &properties) try
{
	if (!str_isascii(username))
		return true; /* same as 0 rows */
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "SELECT u.id, p.proptag, p.propval_bin, p.propval_str "
	            "FROM users AS u "
	            "INNER JOIN user_properties AS p ON u.id=p.user_id "
	            "WHERE u.username='" + conn->quote(username) + "'";
	DB_RESULT res;
	if (!conn->query(qstr) || !(res = conn->store_result()))
		return false;

	for(DB_ROW row = res.fetch_row(); row; row = res.fetch_row())
	{
		uint32_t tag = strtoul(row[1], nullptr, 0);
		const char* strval = row[3];
		if(!strval) // Binary values are currently not supported
			continue;

		switch(PROP_TYPE(tag))
		{
		case PT_BOOLEAN: {
			uint8_t converted = strtoul(strval, nullptr, 0);
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_SHORT: {
			uint16_t converted = strtoul(strval, nullptr, 0);
			if (properties.set(tag, &converted) != 0)
				return false;
			break;
		}
		case PT_LONG:
		case PT_ERROR: {
			uint32_t converted = strtoul(strval, nullptr, 0);
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

BOOL SVC_mysql_adaptor(enum plugin_op reason, const struct dlfuncs &data)
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
	if (!mysql_adaptor_reload_config(std::move(cfg)))
		return false;
	if (mysql_adaptor_run() != 0) {
		mlog(LV_ERR, "mysql_adaptor: failed to startup");
		return false;
	}
	return TRUE;
}

int mysql_adaptor_mbop_userlist(std::vector<sql_user> &out) try
{
	auto qstr = "SELECT u.id, u.username, u.address_status, u.maildir, "
	            "dt.propval_str AS dtypx, sv.hostname, u.homeserver "
	            "FROM users AS u " JOIN_WITH_DISPLAYTYPE
	            "LEFT JOIN servers AS sv ON u.homeserver=sv.id";
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn || !conn->query(qstr)) {
		mlog(LV_ERR, "Error obtaining user list");
		return ENOMEM;
	}
	auto result = conn->store_result();
	if (result == nullptr)
		return ENOMEM;
	std::vector<sql_user> gv(result.num_rows());
	for (size_t i = 0; i < gv.size(); ) {
		auto row = result.fetch_row();
		gv[i].id = strtoul(row[0], nullptr, 0);
		gv[i].username = row[1];
		gv[i].addr_status = strtoul(row[2], nullptr, 0);
		gv[i].maildir = znul(row[3]);
		if (row[4] == nullptr) {
			gv.pop_back();
			continue;
		}
		gv[i].dtypx = static_cast<enum display_type>(strtoul(znul(row[4]), nullptr, 0));
		gv[i].homeserver_id = strtoul(row[6], nullptr, 0);
		gv[i++].homeserver = znul(row[5]);
	}
	out = std::move(gv);
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}
