// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mysql.h>
#include <set>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fmt/core.h>
#include <libHX/string.h>
#include <gromox/database_mysql.hpp>
#include <gromox/defs.h>
#include <gromox/icase.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "sql2.hpp"

/**
 * @domain:	only users in the same domain may send to the mlist
 * @specified:	only allowed users may send to the mlist (tbl: "specifieds")
 */
enum class mlist_priv {
	all = 0, internal, domain, specified, outgoing,
};

#define MLIST_RESULT_OK					0
#define MLIST_RESULT_NONE				1
#define MLIST_RESULT_PRIVIL_DOMAIN		2
#define MLIST_RESULT_PRIVIL_INTERNAL	3
#define MLIST_RESULT_PRIVIL_SPECIFIED	4
#define JOIN_WITH_DISPLAYTYPE "LEFT JOIN user_properties AS dt ON u.id=dt.user_id AND dt.proptag=956628995" /* PR_DISPLAY_TYPE_EX */
#define JOIN_ALTNAMES "LEFT JOIN altnames AS alt ON u.id=alt.user_id AND alt.altname='{0}'"

/*
 * Terminology you might encounter in this file
 *
 * "maildir": a private store's location
 * "homedir": a public store's location
 */

using namespace std::string_literals;
using namespace gromox;
DECLARE_SVC_API(mysql_adaptor, );
using namespace mysql_adaptor;

int mysql_adaptor_run()
{
	if (g_parm.schema_upgrade == SSU_NOT_ME)
		return 0;
	if (!db_upgrade_check())
		return -1;
	return 0;
}

void mysql_adaptor_stop()
{
	g_sqlconn_pool.clear();
}

errno_t mysql_adaptor_meta(const char *username, unsigned int wantpriv,
    sql_meta_result &mres) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return EIO;
	auto q_user = conn->quote(username);
	std::string q_where = str_isascii(username) ?
	                      ("u.username='" + q_user + "'") : "0"s;
	auto qstr =
		"(SELECT u.password, dt.propval_str AS dtypx, u.address_status, "
		"u.privilege_bits, u.maildir, u.lang, u.externid, "
		"op1.value, op2.value, op3.value, op4.value, op5.value, op6.value, "
		"u.username, u.timezone, u.id FROM users AS u " JOIN_WITH_DISPLAYTYPE
		" LEFT JOIN domains AS d ON u.domain_id=d.id"
		" LEFT JOIN orgs ON d.org_id=orgs.id"
		" LEFT JOIN orgparam AS op1 ON orgs.id=op1.org_id AND op1.key='ldap_uri'"
		" LEFT JOIN orgparam AS op2 ON orgs.id=op2.org_id AND op2.key='ldap_binddn'"
		" LEFT JOIN orgparam AS op3 ON orgs.id=op3.org_id AND op3.key='ldap_bindpw'"
		" LEFT JOIN orgparam AS op4 ON orgs.id=op4.org_id AND op4.key='ldap_basedn'"
		" LEFT JOIN orgparam AS op5 ON orgs.id=op5.org_id AND op5.key='ldap_mail_attr'"
		" LEFT JOIN orgparam AS op6 ON orgs.id=op6.org_id AND op6.key='ldap_start_tls'"
		" LEFT JOIN altnames AS alt ON u.id=alt.user_id AND alt.altname='" +
		q_user + "' WHERE " + q_where + " LIMIT 2) UNION"
		"(SELECT u.password, dt.propval_str AS dtypx, u.address_status, "
		"u.privilege_bits, u.maildir, u.lang, u.externid, "
		"op1.value, op2.value, op3.value, op4.value, op5.value, op6.value, "
		"u.username, u.timezone, u.id FROM users AS u " JOIN_WITH_DISPLAYTYPE
		" LEFT JOIN domains AS d ON u.domain_id=d.id"
		" LEFT JOIN orgs ON d.org_id=orgs.id"
		" LEFT JOIN orgparam AS op1 ON orgs.id=op1.org_id AND op1.key='ldap_uri'"
		" LEFT JOIN orgparam AS op2 ON orgs.id=op2.org_id AND op2.key='ldap_binddn'"
		" LEFT JOIN orgparam AS op3 ON orgs.id=op3.org_id AND op3.key='ldap_bindpw'"
		" LEFT JOIN orgparam AS op4 ON orgs.id=op4.org_id AND op4.key='ldap_basedn'"
		" LEFT JOIN orgparam AS op5 ON orgs.id=op5.org_id AND op5.key='ldap_mail_attr'"
		" LEFT JOIN orgparam AS op6 ON orgs.id=op6.org_id AND op6.key='ldap_start_tls'"
		" LEFT JOIN altnames AS alt ON u.id=alt.user_id AND alt.altname='" + q_user + "'"
		" WHERE alt.altname='" + q_user + "' LIMIT 2) LIMIT 2";
	if (!conn->query(qstr))
		return EIO;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr) {
		mres.errstr = "Could not store SQL result";
		return ENOMEM;
	}
	conn.finish();
	if (pmyres.num_rows() > 1) {
		mres.errstr = fmt::format("Login name is ambiguous", username);
		return ENOENT;
	} else if (pmyres.num_rows() != 1) {
		mres.errstr = fmt::format("No such user", username);
		return ENOENT;
	}

	auto myrow = pmyres.fetch_row();
	uint32_t dtypx;
	if (myrow[1] == nullptr) {
		mres.errstr = "PR_DISPLAY_TYPE_EX is missing for this user";
		return EINVAL;
	}
	dtypx = static_cast<enum display_type>(strtoul(myrow[1], nullptr, 0));
	if (dtypx != DT_MAILUSER && !(wantpriv & WANTPRIV_METAONLY)) {
		mres.errstr = "Object is not a DT_MAILUSER";
		return EACCES;
	}
	auto address_status = strtoul(myrow[2], nullptr, 0);
	if (!afuser_login_allowed(address_status) && !(wantpriv & WANTPRIV_METAONLY)) {
		auto uval = address_status & AF_USER__MASK;
		if (address_status & AF_DOMAIN__MASK)
			mres.errstr = "User's domain is disabled";
		else if (uval == AF_USER_SHAREDMBOX)
			mres.errstr = "Login operation disabled for shared mailboxes";
		else if (uval != 0)
			mres.errstr = "User account is disabled";
		return EACCES;
	}
	wantpriv &= ~WANTPRIV_METAONLY;

	mres.privbits = strtoul(myrow[3], nullptr, 0);
	if (!(mres.privbits & USER_PRIVILEGE_DETAIL1))
		mres.privbits |= USER_PRIVILEGE_DETAIL1 | USER_PRIVILEGE_WEB |
		                 USER_PRIVILEGE_EAS | USER_PRIVILEGE_DAV;
	if (wantpriv != 0 && !(mres.privbits & wantpriv)) {
		mres.errstr = fmt::format("Not authorized to use service(s) {:x}h", wantpriv);
		return EACCES;
	}
	mres.maildir    = myrow[4];
	mres.lang       = znul(myrow[5]);
	mres.enc_passwd = myrow[0];
	mres.have_xid   = myrow[6] != nullptr;
	mres.ldap_uri    = znul(myrow[7]);
	mres.ldap_binddn = znul(myrow[8]);
	mres.ldap_bindpw = znul(myrow[9]);
	mres.ldap_basedn = znul(myrow[10]);
	mres.ldap_mail_attr = znul(myrow[11]);
	mres.ldap_start_tls = parse_bool(znul(myrow[12]));
	mres.username       = znul(myrow[13]);
	mres.timezone       = znul(myrow[14]);
	mres.user_id        = strtoul(znul(myrow[15]), nullptr, 0);
	return 0;
} catch (const std::bad_alloc &e) {
	mlog(LV_ERR, "E-2007: ENOMEM");
	return ENOMEM;
} catch (const std::exception &e) {
	mlog(LV_ERR, "E-2008: %s", e.what());
	return EIO;
}

/*
 * @password:       just-entered password, plain
 * @encrypt_passwd: the previously stored password, encoded
 */
bool mysql_adaptor_login2(const char *username, const char *password,
    const std::string &encrypt_passwd, std::string &errstr) try
{
	if (!str_isascii(username)) {
		errstr = "Incorrect password";
		return false;
	}
	if (g_parm.enable_firsttimepw && encrypt_passwd.empty()) {
		auto encp = sql_crypt_newhash(password);
		auto conn = g_sqlconn_pool.get_wait();
		if (!conn)
			return false;
		auto qstr = "UPDATE users SET password='"s + conn->quote(encp) +
			    "' WHERE username='" + conn->quote(username) + "'";
		if (conn->query(qstr))
			return true;
		errstr = "Password update failed";
	} else {
		if (sql_crypt_verify(password, encrypt_passwd.c_str()))
			return true;
		errstr = "Incorrect password";
	}
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1702: ENOMEM");
	return false;
}

bool mysql_adaptor_setpasswd(const char *username,
	const char *password, const char *new_password) try
{
	if (!str_isascii(username))
		return false;

	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto q_user = conn->quote(username);
	auto qstr =
		"SELECT u.password, dt.propval_str AS dtypx, u.address_status, "
		"u.privilege_bits FROM users AS u " JOIN_WITH_DISPLAYTYPE
		" WHERE u.username='" + q_user + "' LIMIT 2";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	auto dtypx = DT_MAILUSER;
	if (myrow[1] != nullptr)
		dtypx = static_cast<enum display_type>(strtoul(myrow[1], nullptr, 0));
	if (dtypx != DT_MAILUSER)
		return false;
	auto address_status = strtoul(myrow[2], nullptr, 0);
	if (address_status != 0)
		return false;
	if (!(strtoul(myrow[3], nullptr, 0) & USER_PRIVILEGE_CHGPASSWD))
		return false;

	if (*znul(myrow[0]) != '\0' && !sql_crypt_verify(password, myrow[0]))
		return false;
	qstr = "UPDATE users SET password='" + conn->quote(sql_crypt_newhash(new_password)) +
	       "' WHERE username='" + q_user + "'";
	if (!conn->query(qstr))
		return false;
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1703", e.what());
	return false;
}

ec_error_t mysql_adaptor_userid_to_name(unsigned int user_id,
    std::string &username) try
{
	auto qstr = "SELECT username FROM users WHERE id=" + std::to_string(user_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return ecRpcFailed;
	if (!conn->query(qstr))
		return ecRpcFailed;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return ecServerOOM;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return ecNotFound;
	auto myrow = pmyres.fetch_row();
	if (myrow == nullptr || myrow[0] == nullptr)
		return ecNotFound;
	username = myrow[0];
	return ecSuccess;
} catch (const std::bad_alloc &e) {
	mlog(LV_ERR, "%s: %s", "E-1704", e.what());
	return ecServerOOM;
}

bool mysql_adaptor_get_id_from_maildir(const char *maildir, unsigned int *puser_id) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr =
		"SELECT u.id FROM users AS u " JOIN_WITH_DISPLAYTYPE
		" WHERE u.maildir='" + conn->quote(maildir) +
		"' AND dt.propval_str IN (0,7,8) LIMIT 2";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	*puser_id = strtoul(myrow[0], nullptr, 0);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1706", e.what());
	return false;
}

bool mysql_adaptor_get_user_displayname(const char *username,
    char *pdisplayname, size_t dsize) try
{
	if (!str_isascii(username))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto q_user = conn->quote(username);
	auto qstr = fmt::format(
		"(SELECT u2.propval_str AS real_name, "
		"u3.propval_str AS nickname, dt.propval_str AS dtypx FROM users AS u "
		JOIN_WITH_DISPLAYTYPE " "
		"LEFT JOIN user_properties AS u2 ON u.id=u2.user_id AND u2.proptag=805371935 " /* PR_DISPLAY_NAME */
		"LEFT JOIN user_properties AS u3 ON u.id=u3.user_id AND u3.proptag=978255903 " /* PR_NICKNAME */
		JOIN_ALTNAMES " "
		"WHERE u.username='{0}' LIMIT 2) UNION"
		"(SELECT u2.propval_str AS real_name, "
		"u3.propval_str AS nickname, dt.propval_str AS dtypx FROM users AS u "
		JOIN_WITH_DISPLAYTYPE " "
		"LEFT JOIN user_properties AS u2 ON u.id=u2.user_id AND u2.proptag=805371935 " /* PR_DISPLAY_NAME */
		"LEFT JOIN user_properties AS u3 ON u.id=u3.user_id AND u3.proptag=978255903 " /* PR_NICKNAME */
		JOIN_ALTNAMES " "
		"WHERE alt.altname='{0}' LIMIT 2) LIMIT 2",
		q_user);
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	auto dtypx = DT_MAILUSER;
	if (myrow[2] != nullptr)
		dtypx = static_cast<enum display_type>(strtoul(myrow[2], nullptr, 0));
	gx_strlcpy(pdisplayname,
	       dtypx == DT_DISTLIST ? username :
	       myrow[0] != nullptr && *myrow[0] != '\0' ? myrow[0] :
	       myrow[1] != nullptr && *myrow[1] != '\0' ? myrow[1] :
	       username, dsize);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1707", e.what());
	return false;
}

bool mysql_adaptor_get_user_privilege_bits(const char *username,
    uint32_t *pprivilege_bits) try
{
	if (!str_isascii(username))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto q_user = conn->quote(username);
	auto qstr = fmt::format(
		"(SELECT privilege_bits FROM users AS u "
		JOIN_ALTNAMES " "
		"WHERE u.username='{0}' LIMIT 2) UNION"
		"(SELECT privilege_bits FROM users AS u "
		JOIN_ALTNAMES " "
		"WHERE alt.altname='{0}' LIMIT 2) LIMIT 2",
		q_user);
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	*pprivilege_bits = strtoul(myrow[0], nullptr, 0);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1708", e.what());
	return false;
}

bool mysql_adaptor_set_user_lang(const char *username, const char *lang) try
{
	if (!str_isascii(username))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "UPDATE users set lang='" + conn->quote(lang) +
		    "' WHERE username='" + conn->quote(username) + "'";
	if (!conn->query(qstr))
		return false;
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1710", e.what());
	return false;
}

bool mysql_adaptor_set_timezone(const char *username, const char *zone) try
{
	if (!str_isascii(username))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "UPDATE users set timezone='" + conn->quote(zone) +
	            "' WHERE username='" + conn->quote(username) + "'";
	if (!conn->query(qstr))
		return false;
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1713", e.what());
	return false;
}

bool mysql_adaptor_get_homedir(const char *domainname, char *homedir, size_t dsize) try
{
	if (!str_isascii(domainname))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "SELECT homedir, domain_status FROM domains WHERE domainname='" +
	            conn->quote(domainname) + "'";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	gx_strlcpy(homedir, myrow[0], dsize);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1716", e.what());
	return false;
}

bool mysql_adaptor_get_homedir_by_id(unsigned int domain_id, char *homedir,
    size_t dsize) try
{
	auto qstr = "SELECT homedir FROM domains WHERE id=" + std::to_string(domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	gx_strlcpy(homedir, myrow[0], dsize);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1717", e.what());
	return false;
}

bool mysql_adaptor_get_id_from_homedir(const char *homedir, unsigned int *pdomain_id) try
{
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "SELECT id FROM domains WHERE homedir='" +
	            conn->quote(homedir) + "'";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	*pdomain_id = strtoul(myrow[0], nullptr, 0);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1718", e.what());
	return false;
}

bool mysql_adaptor_get_user_ids(const char *username, unsigned int *puser_id,
    unsigned int *pdomain_id, enum display_type *dtypx) try
{
	if (!str_isascii(username))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto q_user = conn->quote(username);
	auto qstr = fmt::format(
		"(SELECT u.id, u.domain_id, dt.propval_str AS dtypx"
		" FROM users AS u " JOIN_WITH_DISPLAYTYPE " " JOIN_ALTNAMES
		" WHERE u.username='{0}' LIMIT 2) UNION"
		" (SELECT u.id, u.domain_id, dt.propval_str AS dtypx"
		" FROM users AS u " JOIN_WITH_DISPLAYTYPE " " JOIN_ALTNAMES
		" WHERE alt.altname='{0}' LIMIT 2) LIMIT 2",
		q_user);
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	if (puser_id != nullptr)
		*puser_id = strtoul(myrow[0], nullptr, 0);
	if (pdomain_id != nullptr)
		*pdomain_id = strtoul(myrow[1], nullptr, 0);
	if (dtypx != nullptr) {
		*dtypx = DT_MAILUSER;
		if (myrow[2] != nullptr)
			*dtypx = static_cast<enum display_type>(strtoul(myrow[2], nullptr, 0));
	}
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1719", e.what());
	return false;
}

bool mysql_adaptor_get_domain_ids(const char *domainname,
    unsigned int *pdomain_id, unsigned int *porg_id) try
{
	if (!str_isascii(domainname))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr =
		"SELECT d.id, d.org_id FROM domains AS d "
		"LEFT JOIN users AS u ON d.id=u.domain_id "
		"WHERE domainname='" + conn->quote(domainname) + "' LIMIT 1";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	if (pdomain_id != nullptr)
		*pdomain_id = strtoul(myrow[0], nullptr, 0);
	if (porg_id != nullptr)
		*porg_id = strtoul(myrow[1], nullptr, 0);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1720", e.what());
	return false;
}

bool mysql_adaptor_get_org_domains(unsigned int org_id,
    std::vector<unsigned int> &pfile) try
{
	auto qstr = "SELECT id FROM domains WHERE org_id=" + std::to_string(org_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	size_t i, rows = pmyres.num_rows();
	pfile = std::vector<unsigned int>(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		pfile[i] = strtoul(myrow[0], nullptr, 0);
	}
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1722", e.what());
	return false;
}

bool mysql_adaptor_get_domain_info(unsigned int domain_id, sql_domain &dinfo) try
{
	auto qstr = "SELECT domainname, title, address, homedir "
	            "FROM domains WHERE id=" + std::to_string(domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return false;
	auto myrow = pmyres.fetch_row();
	if (myrow == nullptr)
		return false;
	dinfo.name = myrow[0];
	dinfo.title = myrow[1];
	dinfo.address = myrow[2];
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1723", e.what());
	return false;
}

bool mysql_adaptor_check_same_org(unsigned int domain_id1, unsigned int domain_id2) try
{
	if (domain_id1 == domain_id2)
		return true;
	auto qstr = "SELECT org_id FROM domains WHERE id=" + std::to_string(domain_id1) +
	            " OR id=" + std::to_string(domain_id2);
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 2)
		return false;
	auto myrow = pmyres.fetch_row();
	auto org_id1 = strtoul(myrow[0], nullptr, 0);
	myrow = pmyres.fetch_row();
	auto org_id2 = strtoul(myrow[0], nullptr, 0);
	if (0 == org_id1 || 0 == org_id2 || org_id1 != org_id2) {
		return false;
	}
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1724", e.what());
	return false;
}

bool mysql_adaptor_get_domain_groups(unsigned int domain_id,
    std::vector<sql_group> &pfile) try
{
	auto qstr = "SELECT `id`, `groupname`, `title` FROM `groups` "
	            "WHERE `domain_id`=" + std::to_string(domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	size_t i, rows = pmyres.num_rows();
	std::vector<sql_group> gv(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		gv[i].id = strtoul(myrow[0], nullptr, 0);
		gv[i].name = myrow[1];
		gv[i].title = myrow[2];
	}
	pfile = std::move(gv);
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1725", e.what());
	return false;
}

bool mysql_adaptor_check_mlist_include(const char *mlist_name,
    const char *account) try
{
	if (!str_isascii(mlist_name) || !str_isascii(account))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto q_mlist = conn->quote(mlist_name);
	const char *pencode_domain = strchr(q_mlist.c_str(), '@');
	if (pencode_domain == nullptr)
		return false;
	++pencode_domain;
	auto qstr = "SELECT id, list_type FROM mlists WHERE listname='" + q_mlist + "'";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	if (pmyres.num_rows() != 1)
		return false;

	auto myrow = pmyres.fetch_row();
	unsigned int id = strtoul(myrow[0], nullptr, 0);
	auto type = static_cast<mlist_type>(strtoul(myrow[1], nullptr, 0));
	bool b_result = false;
	switch (type) {
	case mlist_type::normal:
		qstr = "SELECT username FROM associations WHERE list_id=" +
		       std::to_string(id) + " AND username='" +
		       conn->quote(account) + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() > 0)
			b_result = true;
		return b_result;
	case mlist_type::group: {
		qstr = "SELECT `id` FROM `groups` WHERE `groupname`='" + q_mlist + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1)
			return false;
		myrow = pmyres.fetch_row();
		unsigned int group_id = strtoul(myrow[0], nullptr, 0);
		qstr = "SELECT username FROM users WHERE group_id=" +
		       std::to_string(group_id) + " AND username='" +
		       conn->quote(account) + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() > 0)
			b_result = true;
		return b_result;
	}
	case mlist_type::domain: {
		qstr = "SELECT id FROM domains WHERE domainname='"s + pencode_domain + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1)
			return false;
		myrow = pmyres.fetch_row();
		unsigned int domain_id = strtoul(myrow[0], nullptr, 0);
		qstr = "SELECT username FROM users WHERE domain_id=" +
		       std::to_string(domain_id) + " AND username='" +
		       conn->quote(account) + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() > 0)
			b_result = true;
		return b_result;
	}
	case mlist_type::dyngroup: {
		return false;
	}
	default:
		return false;
	}
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1729", e.what());
	return false;
}

bool mysql_adaptor_check_same_org2(const char *domainname1,
    const char *domainname2) try
{
	if (strcasecmp(domainname1, domainname2) == 0)
		return true;
	if (!str_isascii(domainname1) || !str_isascii(domainname2))
		return false;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto qstr = "SELECT org_id FROM domains WHERE domainname='" +
	            conn->quote(domainname1) + "' OR domainname='" +
	            conn->quote(domainname2) + "'";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 2)
		return false;
	auto myrow = pmyres.fetch_row();
	auto org_id1 = strtoul(myrow[0], nullptr, 0);
	myrow = pmyres.fetch_row();
	auto org_id2 = strtoul(myrow[0], nullptr, 0);
	if (0 == org_id1 || 0 == org_id2 || org_id1 != org_id2) {
		return false;
	}
	return true;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1730", e.what());
	return false;
}

/**
 * @username:	Recipient address; mailing list
 * @from:	From address
 * @pfile:	Output array - append, NO truncate
 */
bool mysql_adaptor_get_mlist_memb(const char *username, const char *from,
    int *presult, std::vector<std::string> &pfile) try
{
	if (!str_isascii(username))
		return false;
	int i, rows;
	bool b_chkintl;

	*presult = MLIST_RESULT_NONE;
	const char *pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		return true;
	}

	pdomain++;
	const char *pfrom_domain = strchr(from, '@');
	if (NULL == pfrom_domain) {
		return true;
	}

	pfrom_domain++;
	auto conn = g_sqlconn_pool.get_wait();
	if (!conn)
		return false;
	auto q_user = conn->quote(username);
	auto pencode_domain = strchr(q_user.c_str(), '@');
	if (pencode_domain == nullptr)
		return true;
	++pencode_domain;

	auto qstr = "SELECT id, list_type, list_privilege FROM mlists "
	            "WHERE listname='" + q_user + "'";
	if (!conn->query(qstr))
		return false;
	auto pmyres = conn->store_result();
	if (pmyres == nullptr)
		return false;
	if (pmyres.num_rows() != 1) {
		*presult = MLIST_RESULT_NONE;
		return true;
	}
	auto myrow = pmyres.fetch_row();
	unsigned int id = strtoul(myrow[0], nullptr, 0);
	auto type = static_cast<mlist_type>(strtoul(myrow[1], nullptr, 0));
	auto privilege = static_cast<mlist_priv>(strtoul(myrow[2], nullptr, 0));

	switch (privilege) {
	case mlist_priv::all:
	case mlist_priv::outgoing:
		b_chkintl = false;
		break;
	case mlist_priv::internal:
		b_chkintl = true;
		break;
	case mlist_priv::domain:
		if (0 != strcasecmp(pdomain, pfrom_domain)) {
			*presult = MLIST_RESULT_PRIVIL_DOMAIN;
			return true;
		}
		b_chkintl = false;
		break;
	case mlist_priv::specified:
		qstr = "SELECT username FROM specifieds WHERE list_id=" + std::to_string(id);
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			if (0 == strcasecmp(myrow[0], from) ||
				0 == strcasecmp(myrow[0], pfrom_domain)) {
				break;
			}
		}
		if (i == rows) {
			*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
			return true;
		}
		b_chkintl = false;
		break;
	default:
		*presult = MLIST_RESULT_NONE;
		return true;
	}

	switch (type) {
	case mlist_type::normal:
		qstr = "SELECT username FROM associations WHERE list_id=" + std::to_string(id);
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		if (b_chkintl) {
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (0 == strcasecmp(myrow[0], from)) {
					b_chkintl = false;
					break;
				}
			}
		}
		if (b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return true;
		}
		mysql_data_seek(pmyres.get(), 0);
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			pfile.push_back(myrow[0]);
		}
		*presult = MLIST_RESULT_OK;
		return true;
	case mlist_type::group: {
		qstr = "SELECT `id` FROM `groups` WHERE `groupname`='" + q_user + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1) {
			*presult = MLIST_RESULT_NONE;
			return true;
		}
		myrow = pmyres.fetch_row();
		unsigned int group_id = strtoul(myrow[0], nullptr, 0);
		qstr = "SELECT u.username, dt.propval_str AS dtypx FROM users AS u "
		       JOIN_WITH_DISPLAYTYPE " WHERE u.group_id=" + std::to_string(group_id);
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		if (b_chkintl) {
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				auto dtypx = DT_MAILUSER;
				if (myrow[1] != nullptr)
					dtypx = static_cast<enum display_type>(strtoul(myrow[1], nullptr, 0));
				if (dtypx == DT_MAILUSER && strcasecmp(myrow[0], from) == 0) {
					b_chkintl = false;
					break;
				}
			}
		}
		if (b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return true;
		}
		mysql_data_seek(pmyres.get(), 0);
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			auto dtypx = DT_MAILUSER;
			if (myrow[1] != nullptr)
				dtypx = static_cast<enum display_type>(strtoul(myrow[1], nullptr, 0));
			if (dtypx == DT_MAILUSER)
				pfile.push_back(myrow[0]);
		}
		*presult = MLIST_RESULT_OK;
		return true;
	}
	case mlist_type::domain: {
		qstr = "SELECT id FROM domains WHERE domainname='"s + pencode_domain + "'";
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1) {
			*presult = MLIST_RESULT_NONE;
			return true;
		}
		myrow = pmyres.fetch_row();
		unsigned int domain_id = strtoul(myrow[0], nullptr, 0);
		qstr = "SELECT u.username, dt.propval_str AS dtypx FROM users AS u "
		       JOIN_WITH_DISPLAYTYPE " WHERE u.domain_id=" + std::to_string(domain_id);
		if (!conn->query(qstr))
			return false;
		pmyres = conn->store_result();
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		if (b_chkintl) {
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				auto dtypx = DT_MAILUSER;
				if (myrow[1] != nullptr)
					dtypx = static_cast<enum display_type>(strtoul(myrow[1], nullptr, 0));
				if (dtypx == DT_MAILUSER && strcasecmp(myrow[0], from) == 0) {
					b_chkintl = false;
					break;
				}
			}
		}
		if (b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return true;
		}
		mysql_data_seek(pmyres.get(), 0);
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			auto dtypx = DT_MAILUSER;
			if (myrow[1] != nullptr)
				dtypx = static_cast<enum display_type>(strtoul(myrow[1], nullptr, 0));
			if (dtypx == DT_MAILUSER)
				pfile.push_back(myrow[0]);
		}
		*presult = MLIST_RESULT_OK;
		return true;
	}
	case mlist_type::dyngroup: {
		*presult = MLIST_RESULT_OK;
		return true;
	}
	default:
		*presult = MLIST_RESULT_NONE;
		return true;
	}
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", "E-1732", e.what());
	return false;
}
