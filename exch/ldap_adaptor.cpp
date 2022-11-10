// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ldap.h>
#include <memory>
#include <string>
#include <typeinfo>
#include <utility>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/resource_pool.hpp>
#include <gromox/svc_common.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "ldap_adaptor.hpp"

using namespace gromox;
using namespace std::string_literals;

namespace {
struct ldapfree {
	void operator()(LDAP *ld) const { ldap_unbind_ext_s(ld, nullptr, nullptr); }
	void operator()(LDAPMessage *m) const { ldap_msgfree(m); }
};
}

using ldap_msg = std::unique_ptr<LDAPMessage, ldapfree>;
using ldap_ptr = std::unique_ptr<LDAP, ldapfree>;

namespace {
struct twoconn {
	ldap_ptr meta, bind;
};
}

static std::string g_ldap_host, g_search_base, g_mail_attr;
static std::string g_bind_user, g_bind_pass;
static bool g_use_tls;
static unsigned int g_edir_workaround; /* server sends garbage sometimes */
static resource_pool<twoconn> g_conn_pool;

static constexpr const char *no_attrs[] = {nullptr};
static constexpr cfg_directive ldap_adaptor_cfg_defaults[] = {
	{"data_connections", "4", CFG_SIZE, "1"},
	{"ldap_bind_pass", ""},
	{"ldap_bind_user", ""},
	{"ldap_edirectory_workaround", "false", CFG_BOOL},
	{"ldap_host", "ldapi:///"},
	{"ldap_mail_attr", "mail"},
	{"ldap_search_base", ""},
	{"ldap_start_tls", "false", CFG_BOOL},
	CFG_TABLE_END,
};

/**
 * Make sure the response has exactly one entry and at most
 * one optional informational search trailer.
 */
static bool validate_response(LDAP *ld, LDAPMessage *result)
{
	if (result == nullptr) {
		mlog(LV_ERR, "ldap_adaptor: ldap_search yielded success, but result is null?!");
		return false;
	}
	auto count = ldap_count_messages(ld, result);
	if (count == 0) {
		mlog(LV_ERR, "ldap_adaptor: result set has 0 messages");
		return false;
	}
	auto msg = ldap_first_message(ld, result);
	if (msg == nullptr) {
		mlog(LV_ERR, "ldap_adaptor: ldap_search result set has no first message");
		return false;
	} else if (ldap_msgtype(msg) != LDAP_RES_SEARCH_ENTRY) {
		mlog(LV_ERR, "ldap_adaptor: ldap_search: result set's 1st message is not a "
		        "LDAP_RES_SEARCH_ENTRY (%d) but %d",
		        static_cast<int>(LDAP_RES_SEARCH_ENTRY), ldap_msgtype(msg));
		return false;
	}
	int i = 0;
	while ((msg = ldap_next_message(ld, msg)) != nullptr) {
		auto mtype = ldap_msgtype(msg);
		switch (mtype) {
		case LDAP_RES_SEARCH_REFERENCE:
			/* ignore referrals */
			continue;
		case LDAP_RES_SEARCH_RESULT:
			/*
			 * this is the part that appears in ldapsearch(1) as
			 * # search result
			 * search: 2
			 * result: 0 Success
			 */
			continue;
		case LDAP_RES_SEARCH_ENTRY:
			mlog(LV_ERR, "ldap_adaptor: ldap_search yielded ambiguous result "
			        "(msg %d/%d is also LDAP_RES_SEARCH_ENTRY)", i, count);
			return false;
		default:
			mlog(LV_ERR, "ldap_adaptor: ldap_search yielded a result with "
			        "msg %d/%d of unexpected type %d", i, count, mtype);
			return false;
		}
	}
	return true;
}

static ldap_ptr make_conn(const std::string &uri, const char *bind_user,
    const char *bind_pass,  bool perform_bind)
{
	ldap_ptr ld;
	auto ret = ldap_initialize(&unique_tie(ld), uri.empty() ? nullptr : uri.c_str());
	if (ret != LDAP_SUCCESS)
		return {};
	static constexpr int version = LDAP_VERSION3;
	ret = ldap_set_option(ld.get(), LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ret != LDAP_SUCCESS)
		return {};
	ret = ldap_set_option(ld.get(), LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	if (ret != LDAP_SUCCESS)
		return {};
	if (g_use_tls) {
		ret = ldap_start_tls_s(ld.get(), nullptr, nullptr);
		if (ret != LDAP_SUCCESS) {
			mlog(LV_ERR, "ldap_start_tls_s: %s", ldap_err2string(ret));
			return {};
		}
	}
	if (!perform_bind)
		return ld;

	struct berval cred{};
	if (*bind_user != '\0') {
		cred.bv_val = deconst(bind_pass);
		cred.bv_len = strlen(znul(bind_pass));
	} else {
		bind_user = nullptr;
	}
	ret = ldap_sasl_bind_s(ld.get(), bind_user, LDAP_SASL_SIMPLE, &cred,
	      nullptr, nullptr, nullptr);
	if (ret != LDAP_SUCCESS) {
		mlog(LV_ERR, "ldap_adaptor: bind as \"%s\" on \"%s\": %s",
		        znul(bind_user), uri.c_str(), ldap_err2string(ret));
		return {};
	}
	return ld;
}

static constexpr bool AVOID_BIND = false, DO_BIND = true;

static int gx_ldap_bind(ldap_ptr &ld, const char *dn, struct berval *bv)
{
	if (ld == nullptr)
		ld = make_conn(g_ldap_host, nullptr, nullptr, AVOID_BIND);
	if (ld == nullptr)
		return LDAP_SERVER_DOWN;
	auto ret = ldap_sasl_bind_s(ld.get(), dn, LDAP_SASL_SIMPLE, bv,
		   nullptr, nullptr, nullptr);
	if (ret == LDAP_LOCAL_ERROR && g_edir_workaround)
		/* try full reconnect */;
	else if (ret != LDAP_SERVER_DOWN)
		return ret;
	ld = make_conn(g_ldap_host, nullptr, nullptr, AVOID_BIND);
	if (ld == nullptr)
		return ret;
	return ldap_sasl_bind_s(ld.get(), dn, LDAP_SASL_SIMPLE, bv,
	       nullptr, nullptr, nullptr);
}

static int gx_ldap_search(ldap_ptr &ld, const char *base, const char *filter,
    char **attrs, LDAPMessage **msg)
{
	if (ld == nullptr)
		ld = make_conn(g_ldap_host, g_bind_user.c_str(),
		     g_bind_pass.c_str(), DO_BIND);
	if (ld == nullptr)
		return LDAP_SERVER_DOWN;
	auto ret = ldap_search_ext_s(ld.get(), base, LDAP_SCOPE_SUBTREE,
	           filter, attrs, true, nullptr, nullptr, nullptr, 2, msg);
	if (ret == LDAP_LOCAL_ERROR && g_edir_workaround)
		/* try full reconnect */;
	else if (ret != LDAP_SERVER_DOWN)
		return ret;
	ld = make_conn(g_ldap_host, g_bind_user.c_str(),
	     g_bind_pass.c_str(), DO_BIND);
	if (ld == nullptr)
		return ret;
	return ldap_search_ext_s(ld.get(), base, LDAP_SCOPE_SUBTREE,
	       filter, attrs, true, nullptr, nullptr, nullptr, 2, msg);
}

static BOOL ldaplogin_host(ldap_ptr &tok_meta, ldap_ptr &tok_bind,
    const char *username, const char *password, const std::string &base_dn)
{
	ldap_msg msg;
	std::unique_ptr<char[], stdlib_delete> freeme;
	auto quoted = HX_strquote(username, HXQUOTE_LDAPRDN, &unique_tie(freeme));
	auto filter = g_mail_attr + "="s + quoted;
	auto ret = gx_ldap_search(tok_meta,
	           base_dn.size() > 0 ? base_dn.c_str() : nullptr,
	      filter.c_str(), const_cast<char **>(no_attrs), &unique_tie(msg));
	if (ret != LDAP_SUCCESS) {
		mlog(LV_ERR, "ldap_adaptor: search with base \"%s\" filter \"%s\": %s",
		        base_dn.c_str(), filter.c_str(), ldap_err2string(ret));
		return FALSE;
	}
	if (!validate_response(tok_meta.get(), msg.get()))
		return FALSE;
	auto firstmsg = ldap_first_message(tok_meta.get(), msg.get());
	if (firstmsg == nullptr)
		return FALSE;
	auto dn = ldap_get_dn(tok_meta.get(), firstmsg);
	if (dn == nullptr)
		return FALSE;

	struct berval bv;
	bv.bv_val = deconst(znul(password));
	bv.bv_len = password != nullptr ? strlen(password) : 0;
	ret = gx_ldap_bind(tok_bind, dn, &bv);
	if (ret == LDAP_SUCCESS)
		return TRUE;
	mlog(LV_ERR, "ldap_adaptor: ldap_simple_bind %s: %s", dn, ldap_err2string(ret));
	return FALSE;
}

static BOOL ldaplogin_dpool(const char *username, const char *password)
{
	auto tok = g_conn_pool.get_wait();
	return ldaplogin_host(tok->meta, tok->bind, username, password,
	       g_search_base);
}

BOOL ldap_adaptor_login3(const char *user, const char *pass, const sql_meta_result &m)
{
	auto z = g_conn_pool.capacity();
	if (m.ldap_uri.empty() && z > 0)
		return ldaplogin_dpool(user, pass);
	/*
	 * Keeping a pool per LDAP server can quickly exhaust file descriptors,
	 * so don't even go there when multiple LDAP servers are in use.
	 */
	if (z > 0) {
		mlog(LV_NOTICE, "ldap_adaptor: Pooling is now disabled (would use too many resources in multi-LDAP)");
		g_conn_pool.resize(0);
		g_conn_pool.clear();
	}
	if (m.ldap_uri.empty()) {
		auto conn = make_conn(g_ldap_host.c_str(), g_bind_user.c_str(),
		            g_bind_pass.c_str(), true);
		return ldaplogin_host(conn, conn, user, pass, g_search_base.c_str());
	}
	auto conn = make_conn(m.ldap_uri.c_str(), m.ldap_binddn.c_str(),
	            m.ldap_bindpw.c_str(), true);
	return ldaplogin_host(conn, conn, user, pass, m.ldap_basedn);
}

static bool ldap_adaptor_load() try
{
	auto pfile = config_file_initd("ldap_adaptor.cfg", get_config_path(),
	             ldap_adaptor_cfg_defaults);
	if (pfile == nullptr) {
		mlog(LV_ERR, "ldap_adaptor: config_file_initd ldap_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	unsigned int dataconn_num = pfile->get_ll("data_connections");
	g_ldap_host = pfile->get_value("ldap_host");
	g_bind_user = pfile->get_value("ldap_bind_user");
	g_bind_pass = pfile->get_value("ldap_bind_pass");
	auto p2 = pfile->get_value("ldap_bind_pass_mode_id107");
	if (p2 != nullptr)
		g_bind_pass = zstd_decompress(base64_decode(p2));
	p2 = pfile->get_value("ldap_bind_pass_mode_id555");
	if (p2 != nullptr)
		g_bind_pass = sss_obf_reverse(base64_decode(p2));
	g_use_tls = pfile->get_ll("ldap_start_tls");
	g_mail_attr = pfile->get_value("ldap_mail_attr");
	g_search_base = pfile->get_value("ldap_search_base");
	g_edir_workaround = pfile->get_ll("ldap_edirectory_workaround");
	mlog(LV_NOTICE, "ldap_adaptor: default host <%s>%s%s, base <%s>, #conn=%d, mailattr=%s",
	       g_ldap_host.c_str(), g_use_tls ? " +TLS" : "",
	       g_edir_workaround ? " +EDIRECTORY_WORKAROUNDS" : "",
	       g_search_base.c_str(), 2 * dataconn_num, g_mail_attr.c_str());
	g_conn_pool.resize(dataconn_num);
	g_conn_pool.bump();
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1455: ENOMEM");
	return false;
}

static BOOL svc_ldap_adaptor(int reason, void **ppdata) try
{
	if (reason == PLUGIN_FREE) {
		g_conn_pool.clear();
		return TRUE;
	} else if (reason == PLUGIN_RELOAD) {
		ldap_adaptor_load();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;

	LINK_SVC_API(ppdata);
	if (!ldap_adaptor_load())
		return false;
	if (!register_service("ldap_auth_login3", ldap_adaptor_login3)) {
		mlog(LV_ERR, "ldap_adaptor: failed to register services");
		return false;
	}
	return TRUE;
} catch (...) {
	return false;
}
SVC_ENTRY(svc_ldap_adaptor);
