// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
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
#include <optional>
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
#include <gromox/flat_set.hpp>
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

std::optional<mysql_plugin> le_mysql_plugin;

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

bool mysql_plugin::db_upgrade_check_2(MYSQL *conn)
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

bool mysql_plugin::db_upgrade_check()
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	return db_upgrade_check_2(conn->get());
}

MYSQL *mysql_plugin::sql_make_conn()
{
	MYSQL *conn = mysql_init(nullptr);
	if (conn == nullptr)
		return nullptr;
	if (g_parm.timeout > 0) {
		mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &g_parm.timeout);
		mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &g_parm.timeout);
	}
	if (!g_parm.certfile.empty())
		mysql_options(conn, MYSQL_OPT_SSL_CERT, g_parm.certfile.c_str());
	if (!g_parm.keyfile.empty())
		mysql_options(conn, MYSQL_OPT_SSL_KEY, g_parm.keyfile.c_str());
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

/**
 * Notes to self:
 *
 * CR_COMMANDS_OUT_OF_SYNC comes about when the programmer forgets to call
 * store_result(), which can happen if if(conn->query(..)) check is erroneously
 * inverted for example.
 */
bool sqlconn::query(std::string_view qv)
{
	if (m_conn == nullptr) {
		m_conn = le_mysql_plugin->sql_make_conn();
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
	m_conn = le_mysql_plugin->sql_make_conn();
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
		*c = le_mysql_plugin->sql_make_conn();
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

static ssize_t userlist_parse(sqlconn &conn, const char *query,
    aliasmap_t &amap, propmap_t &pmap, std::vector<sql_user> &pfile, unsigned int domain_id=0)
{
	if (!conn.query(query))
		return -1;
	auto result = conn.store_result();
	if (result == nullptr)
		return -1;

	for (size_t i = 0; i < result.num_rows(); ++i) {
		auto row = result.fetch_row();
		sql_user u;
		u.domain_id = domain_id;
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
			u.cloak_bits = strtoul(it->second.c_str(), nullptr, 0);
		} else {
			it = u.propvals.find(PR_ATTR_HIDDEN);
			if (it != u.propvals.end())
				u.cloak_bits = strtoul(it->second.c_str(), nullptr, 0) ? AB_HIDE__DEFAULT : 0;
		}
		if (u.dtypx == DT_DISTLIST) {
			u.list_type = static_cast<enum mlist_type>(strtoul(znul(row[5]), nullptr, 0));
			u.list_priv = strtoul(znul(row[6]), nullptr, 0);
		}
		pfile.push_back(std::move(u));
	}
	return pfile.size();
}

int mysql_plugin::get_domain_users(unsigned int domain_id,
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
	return userlist_parse(*conn, query, amap, pmap, pfile, domain_id) >= 0;
} catch (const std::exception &e) {
	mlog(LV_ERR, "mysql_adaptor: %s %s", __func__, e.what());
	return false;
}

errno_t mysql_plugin::scndstore_hints(unsigned int pri,
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

int mysql_plugin::domain_list_query(const char *domain) try
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

errno_t mysql_plugin::get_homeserver(const char *entity, bool is_pvt,
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
	return ENOMEM;
}

void mysql_plugin::init(mysql_adaptor_init_param &&parm)
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
	{"mysql_tls_cert", ""},
	{"mysql_tls_key", ""},
	{"mysql_username", "root"},
	CFG_TABLE_END,
};

bool mysql_plugin::reload_config(std::shared_ptr<config_file> &&cfg)
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
	par.certfile = cfg->get_value("mysql_tls_cert");
	par.keyfile  = cfg->get_value("mysql_tls_key");
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
	if (prog_id == nullptr || strcmp(prog_id, "istore") != 0)
		par.schema_upgrade = SSU_NOT_ME;
	else if (v != nullptr && strncmp(v, "host:", 5) == 0 &&
	    prog_id != nullptr && strcmp(&v[5], host_id) == 0)
		par.schema_upgrade = SSU_AUTOUPGRADE;

	par.enable_firsttimepw = cfg->get_ll("enable_firsttime_password");
	init(std::move(par));
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
bool mysql_plugin::get_user_aliases(const char *username,
    std::vector<std::string> &aliases) try
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
	for (DB_ROW row = res.fetch_row(); row; row = res.fetch_row())
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
bool mysql_plugin::get_user_props(const char *username,
    TPROPVAL_ARRAY &properties) try
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

	for (DB_ROW row = res.fetch_row(); row; row = res.fetch_row()) {
		uint32_t tag = strtoul(row[1], nullptr, 0);
		const char* strval = row[3];
		if(!strval) // Binary values are currently not supported
			continue;

		switch (PROP_TYPE(tag)) {
		case PT_BOOLEAN: {
			uint8_t converted = strtoul(strval, nullptr, 0);
			if (properties.set(tag, &converted) != ecSuccess)
				return false;
			break;
		}
		case PT_SHORT: {
			uint16_t converted = strtoul(strval, nullptr, 0);
			if (properties.set(tag, &converted) != ecSuccess)
				return false;
			break;
		}
		case PT_LONG:
		case PT_ERROR: {
			uint32_t converted = strtoul(strval, nullptr, 0);
			if (properties.set(tag, &converted) != ecSuccess)
				return false;
			break;
		}
		case PT_I8:
		case PT_CURRENCY:
		case PT_SYSTIME: {
			uint64_t converted = strtoull(strval, nullptr, 0);
			if (properties.set(tag, &converted) != ecSuccess)
				return false;
			break;
		}
		case PT_FLOAT: {
			float converted = strtof(strval, nullptr);
			if (properties.set(tag, &converted) != ecSuccess)
				return false;
			break;
		}
		case PT_DOUBLE:
		case PT_APPTIME: {
			double converted = strtod(strval, nullptr);
			if (properties.set(tag, &converted) != ecSuccess)
				return false;
			break;
		}
		case PT_STRING8:
		case PT_UNICODE:
			if(!row[3])
				continue;
			if (properties.set(tag, strval) != ecSuccess)
				return false;
			break;
		}
	}
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
	return false;
}

BOOL SVC_mysql_adaptor(enum plugin_op reason, const struct dlfuncs &data) try
{
	if (reason == PLUGIN_FREE) {
		le_mysql_plugin.reset();
		return TRUE;
	} else if (reason == PLUGIN_RELOAD) {
		if (le_mysql_plugin.has_value())
			le_mysql_plugin->reload_config(nullptr);
		return TRUE;
	} else if (reason != PLUGIN_INIT) {
		return TRUE;
	}

	le_mysql_plugin.emplace();
	LINK_SVC_API(data);
	auto cfg = config_file_initd("mysql_adaptor.cfg", get_config_path(),
	           mysql_adaptor_cfg_defaults);
	if (cfg == nullptr) {
		mlog(LV_ERR, "mysql_adaptor: config_file_initd mysql_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	if (!le_mysql_plugin->reload_config(std::move(cfg)))
		return false;
	if (le_mysql_plugin->run() != 0) {
		mlog(LV_ERR, "mysql_adaptor: failed to startup");
		return false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

int mysql_plugin::mbop_userlist(std::vector<sql_user> &out) try
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

errno_t mysql_plugin::mda_alias_list(sql_alias_map &newmap, size_t &n_aliases) try
{
	auto qstr = "SELECT aliasname, mainname FROM aliases";
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return ENOMEM;
	if (!conn->query(qstr))
		return EAGAIN;
	auto result = conn->store_result();
	if (result == nullptr)
		return EAGAIN;
	DB_ROW row;
	while ((row = result.fetch_row()) != nullptr)
		if (row[0] != nullptr && *row[0] != '\0' && row[1] != nullptr && *row[1] != '\0')
			newmap.emplace(row[0], row[1]);
	n_aliases = newmap.size();

	qstr =  "select u.username, uv.propval_str "
		"from users as u inner join user_properties as up "
		// require PR_DISPLAY_TYPE(_EX)==DT_REMOTE_MAILUSER
		"on u.id=up.user_id and up.proptag=0x39050003 and up.propval_str=6 "
		"inner join user_properties as uv "
		// extract PR_SMTP_ADDRESS
		"on u.id=uv.user_id and uv.proptag=0x39fe001f";
	if (!conn->query(qstr))
		return EAGAIN;
	result = conn->store_result();
	if (result == nullptr)
		return EAGAIN;
	while ((row = result.fetch_row()) != nullptr)
		if (row[0] != nullptr && *row[0] != '\0' && row[1] != nullptr && *row[1] != '\0')
			newmap.emplace(row[0], row[1]);
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

errno_t mysql_plugin::mda_domain_list(sql_domain_set &newdom) try
{
	auto qstr = "SELECT username FROM users UNION SELECT aliasname FROM aliases";
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return ENOMEM;
	if (!conn->query(qstr))
		return EAGAIN;
	auto result = conn->store_result();
	DB_ROW row;
	while ((row = result.fetch_row()) != nullptr) {
		if (row[0] == nullptr)
			continue;
		auto p = strchr(row[0], '@');
		if (p == nullptr)
			continue;
		newdom.emplace(&p[1]);
	}
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

errno_t mysql_plugin::mda_alias_resolve(std::string &addr /* inplace */) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return ENOMEM;
	auto qstr =
		"SELECT uv.propval_str AS mainname"
		" FROM users AS u INNER JOIN user_properties AS up"
		" ON u.id=up.user_id AND u.address_status=" + std::to_string(AF_USER_CONTACT) +
		" AND up.proptag=" + std::to_string(PR_DISPLAY_TYPE_EX) +
		" AND up.propval_str=" + std::to_string(DT_REMOTE_MAILUSER) +
		" INNER JOIN user_properties AS uv"
		" ON u.id=uv.user_id AND uv.proptag=" + std::to_string(PR_SMTP_ADDRESS) +
		" WHERE username='" + conn->quote(addr) + "' UNION "
		"SELECT a.mainname FROM aliases AS a INNER JOIN users AS u"
		" ON u.address_status IN (" + std::to_string(AF_USER_NORMAL) + "," +
		std::to_string(AF_USER_SHAREDMBOX) +
		" AND u.username=a.mainname AND a.aliasname='" + conn->quote(addr) + "' LIMIT 2";
	if (!conn->query(qstr))
		return EIO;
	auto result = conn->store_result();
	if (result == nullptr)
		return EIO;
	if (result.num_rows() == 0)
		return 0; /* No alias */
	if (result.num_rows() > 1)
		return ELOOP; /* Too many results */
	auto row = result.fetch_row();
	if (row == nullptr)
		return EIO;
	addr = znul(row[0]);
	return 0;
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

errno_t mysql_plugin::mda_group_expand(sqlconn &conn, const std::string &group,
    std::vector<std::string> &exp, std::set<std::string> &seen,
    unsigned int depth)
{
	if (depth >= 8)
		return ELOOP; /* too many groups nested */
	seen.emplace(group);
	auto qstr = "SELECT list_id FROM mlists WHERE listname='" + conn.quote(group) + "'";
	if (!conn.query(qstr))
		return EIO;
	auto result = conn.store_result();
	if (result == nullptr)
		return EIO;
	auto row = result.fetch_row();
	if (row == nullptr)
		return ENOENT; /* not a group */
	auto list_id = strtoul(row[0], nullptr, 0);

	qstr = "SELECT username FROM associations WHERE list_id=" + std::to_string(list_id);
	if (!conn.query(qstr))
		return EIO;
	result = conn.store_result();
	if (result == nullptr)
		return EIO;
	while ((row = result.fetch_row()) != nullptr) {
		std::string member = znul(row[0]);
		if (member.empty())
			continue;
		auto err = mda_alias_resolve(member);
		if (err != 0)
			continue; /* problem with user */
		err = mda_group_expand(conn, member, exp, seen, depth + 1);
		if (err == ENOENT) {
			/* not a group */
			exp.emplace_back(member);
			continue;
		}
		if (seen.find(member) != seen.end())
			return ELOOP; /* very bad */
		seen.emplace(member);
	}
	return 0;
}

errno_t mysql_plugin::mda_group_expand(const std::string &group,
    std::vector<std::string> &exp) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return ENOMEM;
	std::set<std::string> seen;
	return mda_group_expand(*conn, group, exp, seen, 0);
} catch (const std::bad_alloc &) {
	return ENOMEM;
}

/**
 * @brief     Compare domains based on (case-insensitive) domain name
 *
 * @param     o   Other domain
 *
 * @return    Result of lexicographic comparison
 */
std::weak_ordering sql_domain::operator<=>(const sql_domain& o) const {
	auto r = strcasecmp(name.c_str(), o.name.c_str());
	return r < 0? std::weak_ordering::less : r == 0? std::weak_ordering::equivalent : std::weak_ordering::greater;
}

/**
 * @brief     Compare users based on (case-insensitive) display name
 *
 * Missing display names are substituted with the username.
 *
 * @param     Other user
 *
 * @return    Result of lexicographic comparison
 */
std::weak_ordering sql_user::operator<=>(const sql_user &o) const {
	auto i = propvals.find(PR_DISPLAY_NAME);
	auto name_this = i != propvals.end() ? i->second.c_str() : username.c_str();
	i = o.propvals.find(PR_DISPLAY_NAME);
	auto name_other = i != o.propvals.end() ? i->second.c_str() : o.username.c_str();
	auto r = strcasecmp(name_this, name_other);
	return r == 0? std::weak_ordering::equivalent : r < 0 ? std::weak_ordering::less : std::weak_ordering::greater;
}

/**
 * Resolve @mlist_name to a list id.
 * List 0 is never used, and so 0 is used as a placeholder for notfound/error.
 */
static std::pair<uint32_t, mlist_type>
resolve_list_id(sqlconn &conn, const char *mlist_name)
{
	if (!str_isascii(mlist_name))
		return {};
	auto q_mlist = conn.quote(mlist_name);
	auto qstr = "SELECT id, list_type FROM mlists WHERE listname='" + q_mlist + "'";
	if (!conn.query(qstr))
		return {};
	auto res = conn.store_result();
	if (res == nullptr)
		return {};
	auto nrows = res.num_rows();
	if (nrows == 0)
		return {};
	auto row = res.fetch_row();
	return {strtoul(row[0], nullptr, 0), static_cast<mlist_type>(strtoul(row[1], nullptr, 0))};
}

/**
 * Check list @id whether it contains @account as a member.
 * Scans subordinate lists for @depth.
 */
static bool mlist_contains(sqlconn &conn, uint32_t list_id, mlist_type mtype,
    const char *account, unsigned int depth)
{
	auto qstr = "SELECT username FROM associations WHERE list_id=" +
		    std::to_string(list_id) + " AND username='" +
		    conn.quote(account) + "'";
	if (!conn.query(qstr))
		return false;
	auto res = conn.store_result();
	if (res == nullptr)
		return false;
	if (res.num_rows() > 0)
		return true;
	if (depth == 0)
		return false;
	--depth;

	qstr = "SELECT ml.id, ml.list_type FROM associations AS a INNER JOIN mlists AS ml "
	       "ON a.username=ml.listname WHERE a.list_id=" + std::to_string(list_id);
	if (!conn.query(qstr))
		return false;
	res = conn.store_result();
	if (res == nullptr)
		return false;
	auto nrows = res.num_rows();
	for (size_t i = 0; i < nrows; ++i) {
		auto row = res.fetch_row();
		if (row == nullptr)
			break;
		uint32_t sub_id = strtoul(row[0], nullptr, 0);
		auto sub_type = static_cast<mlist_type>(strtoul(row[1], nullptr, 0));
		if (mlist_contains(conn, sub_id, sub_type, account, depth))
			return true;
	}
	return false;
}

/**
 * Check list @mlist_name whether it contains @account as a member. (With
 * recursion up to @max_depth tries.)
 */
bool mysql_plugin::check_mlist_include(const char *mlist_name,
    const char *account, unsigned int max_depth) try
{
	if (max_depth == 0)
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return 0;
	auto [id, type] = resolve_list_id(*conn, mlist_name);
	if (id == 0)
		return false;
	if (type == mlist_type::domain)
		return mlist_domain_contains(&*conn, mlist_name, account);
	return mlist_contains(*conn, id, type, account, max_depth - 1);
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1729", e.what());
	return false;
}

errno_t mysql_plugin::get_user_groups_rec(const char *username, std::vector<std::string> &groups) try
{
	gromox::maybe_flat_set<uint32_t> seen_ml;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return EIO;
	groups.clear();
	groups.emplace_back(username);
	size_t rescan_begin = 0, rescan_end = 1;
	for (size_t i = rescan_begin; i < rescan_end; ++i) {
		auto qstr = "SELECT DISTINCT m.id, m.listname FROM associations AS a "
			    "INNER JOIN mlists AS m ON a.list_id=m.id "
			    "WHERE a.username='" + conn->quote(groups[i]) + "'";
		if (!conn->query(qstr))
			return EIO;
		auto result = conn->store_result();
		DB_ROW row;
		++rescan_begin;
		while ((row = result.fetch_row()) != nullptr) {
			if (row[1] == nullptr)
				continue;
			auto list_id = strtoul(row[0], nullptr, 0);
			if (seen_ml.contains(list_id))
				continue;
			seen_ml.emplace(list_id);
			groups.emplace_back(row[1]);
			++rescan_end;
		}
	}
	groups.erase(groups.begin());
	return 0;
} catch (const std::bad_alloc &e) {
	mlog(LV_ERR, "E-1731: ENOMEM");
	return ENOMEM;
}

errno_t mysql_adaptor_meta(const char *u, unsigned int p, sql_meta_result &r)
{
	return le_mysql_plugin->meta(u, p, r);
}

bool mysql_adaptor_login2(const char *u, const char *p, const std::string &w, std::string &e)
{
	return le_mysql_plugin->login2(u, p, w, e);
}

bool mysql_adaptor_setpasswd(const char *u, const char *p, const char *n)
{
	return le_mysql_plugin->setpasswd(u, p, n);
}

ec_error_t mysql_adaptor_userid_to_name(unsigned int id, std::string &name)
{
	return le_mysql_plugin->userid_to_name(id, name);
}

bool mysql_adaptor_get_id_from_maildir(const char *dir, unsigned int *id)
{
	return le_mysql_plugin->get_id_from_maildir(dir, id);
}

bool mysql_adaptor_get_user_displayname(const char *u, std::string &dn)
{
	return le_mysql_plugin->get_user_displayname(u, dn);
}

bool mysql_adaptor_get_user_aliases(const char *u, std::vector<std::string> &a)
{
	return le_mysql_plugin->get_user_aliases(u, a);
}

bool mysql_adaptor_get_user_properties(const char *u, TPROPVAL_ARRAY &p)
{
	return le_mysql_plugin->get_user_props(u, p);
}

bool mysql_adaptor_get_user_privilege_bits(const char *u, uint32_t *b)
{
	return le_mysql_plugin->get_user_privbits(u, b);
}

bool mysql_adaptor_set_user_lang(const char *u, const char *l)
{
	return le_mysql_plugin->set_user_lang(u, l);
}

bool mysql_adaptor_set_timezone(const char *u, const char *z)
{
	return le_mysql_plugin->set_timezone(u, z);
}

bool mysql_adaptor_get_homedir(const char *dom, char *dir, size_t z)
{
	return le_mysql_plugin->get_homedir(dom, dir, z);
}

bool mysql_adaptor_get_homedir_by_id(unsigned int dom, char *dir, size_t z)
{
	return le_mysql_plugin->get_homedir_by_id(dom, dir, z);
}

bool mysql_adaptor_get_id_from_homedir(const char *dir, unsigned int *id)
{
	return le_mysql_plugin->get_id_from_homedir(dir, id);
}

bool mysql_adaptor_get_user_ids(const char *u, unsigned int *i, unsigned int *d, enum display_type *t)
{
	return le_mysql_plugin->get_user_ids(u, i, d, t);
}

bool mysql_adaptor_get_domain_ids(const char *d, unsigned int *i, unsigned int *w)
{
	return le_mysql_plugin->get_domain_ids(d, i, w);
}

bool mysql_adaptor_get_org_domains(unsigned int org, std::vector<unsigned int> &v)
{
	return le_mysql_plugin->get_org_domains(org, v);
}

bool mysql_adaptor_get_domain_info(unsigned int id, sql_domain &d)
{
	return le_mysql_plugin->get_domain_info(id, d);
}

bool mysql_adaptor_check_same_org(unsigned int a, unsigned int b)
{
	return le_mysql_plugin->check_same_org(a, b);
}

bool mysql_adaptor_get_domain_groups(unsigned int id, std::vector<sql_group> &v)
{
	return le_mysql_plugin->get_domain_groups(id, v);
}

int mysql_adaptor_get_domain_users(unsigned int id, std::vector<sql_user> &v)
{
	return le_mysql_plugin->get_domain_users(id, v);
}

bool mysql_adaptor_check_mlist_include(const char *m, const char *a)
{
	return le_mysql_plugin->check_mlist_include(m, a);
}

bool mysql_adaptor_check_same_org2(const char *a, const char *b)
{
	return le_mysql_plugin->check_same_org2(a, b);
}

bool mysql_adaptor_get_mlist_memb(const char *u, const char *f, int *r,
    std::vector<std::string> &v)
{
	return le_mysql_plugin->get_mlist_memb(u, f, r, v);
}

gromox::errno_t mysql_adaptor_get_homeserver(const char *e, bool p,
    std::pair<std::string, std::string> &v)
{
	return le_mysql_plugin->get_homeserver(e, p, v);
}

gromox::errno_t mysql_adaptor_scndstore_hints(unsigned int pri, std::vector<sql_user> &hints)
{
	return le_mysql_plugin->scndstore_hints(pri, hints);
}

int mysql_adaptor_domain_list_query(const char *dom)
{
	return le_mysql_plugin->domain_list_query(dom);
}

int mysql_adaptor_mbop_userlist(std::vector<sql_user> &v)
{
	return le_mysql_plugin->mbop_userlist(v);
}

errno_t mysql_adaptor_mda_alias_list(sql_alias_map &v, size_t &a)
{
	return le_mysql_plugin->mda_alias_list(v, a);
}

errno_t mysql_adaptor_mda_domain_list(sql_domain_set &v)
{
	return le_mysql_plugin->mda_domain_list(v);
}

errno_t mysql_adaptor_get_user_groups_rec(const char *user, std::vector<std::string> &groups)
{
	return le_mysql_plugin->get_user_groups_rec(user, groups);
}

errno_t mysql_adaptor_mda_alias_resolve(std::string &addr)
{
	return le_mysql_plugin->mda_alias_resolve(addr);
}

errno_t mysql_adaptor_mda_group_expand(const std::string &addr, std::vector<std::string> &exp)
{
	return le_mysql_plugin->mda_group_expand(addr, exp);
}
