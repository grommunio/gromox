// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
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
#include <gromox/resource_pool.hpp>
#include <gromox/svc_common.h>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "ldap_adaptor.hpp"
#include "mysql_adaptor/mysql_adaptor.h"

using namespace gromox;
using namespace std::string_literals;

namespace {
struct ldapfree {
	void operator()(LDAP *ld) { ldap_unbind_ext_s(ld, nullptr, nullptr); }
	void operator()(LDAPMessage *m) { ldap_msgfree(m); }
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
static unsigned int g_dataconn_num = 4;
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
	auto msg = ldap_first_message(ld, result);
	if (msg == nullptr || ldap_msgtype(msg) != LDAP_RES_SEARCH_ENTRY)
		return false;
	while ((msg = ldap_next_message(ld, msg)) != nullptr)
		if (ldap_msgtype(msg) != LDAP_RES_SEARCH_RESULT &&
		    ldap_msgtype(msg) != LDAP_RES_SEARCH_REFERENCE)
			return false;
	return true;
}

static ldap_ptr make_conn(bool perform_bind)
{
	ldap_ptr ld;
	auto host = g_ldap_host.c_str();
	auto ret = ldap_initialize(&unique_tie(ld), *host == '\0' ? nullptr : host);
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
			fprintf(stderr, "ldap_start_tls_s: %s\n", ldap_err2string(ret));
			return {};
		}
	}
	if (!perform_bind)
		return ld;

	struct berval cred{};
	const char *binduser = nullptr;
	if (g_bind_user.size() != 0) {
		cred.bv_val = deconst(g_bind_pass.c_str());
		cred.bv_len = g_bind_pass.size();
		binduser = g_bind_user.c_str();
	}
	ret = ldap_sasl_bind_s(ld.get(), binduser, LDAP_SASL_SIMPLE, &cred,
	      nullptr, nullptr, nullptr);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "[ldap_adaptor]: bind as \"%s\": %s\n",
		       g_bind_user.c_str(), ldap_err2string(ret));
		return {};
	}
	return ld;
}

static constexpr bool AVOID_BIND = false, DO_BIND = true;

static int gx_ldap_bind(ldap_ptr &ld, const char *dn, struct berval *bv)
{
	if (ld == nullptr)
		ld = make_conn(AVOID_BIND);
	if (ld == nullptr)
		return LDAP_SERVER_DOWN;
	auto ret = ldap_sasl_bind_s(ld.get(), dn, LDAP_SASL_SIMPLE, bv,
		   nullptr, nullptr, nullptr);
	if (ret == LDAP_LOCAL_ERROR && g_edir_workaround)
		/* try full reconnect */;
	else if (ret != LDAP_SERVER_DOWN)
		return ret;
	ld = make_conn(AVOID_BIND);
	if (ld == nullptr)
		return ret;
	return ldap_sasl_bind_s(ld.get(), dn, LDAP_SASL_SIMPLE, bv,
	       nullptr, nullptr, nullptr);
}

static int gx_ldap_search(ldap_ptr &ld, const char *base, const char *filter,
    char **attrs, LDAPMessage **msg)
{
	if (ld == nullptr)
		ld = make_conn(DO_BIND);
	if (ld == nullptr)
		return LDAP_SERVER_DOWN;
	auto ret = ldap_search_ext_s(ld.get(), base, LDAP_SCOPE_SUBTREE,
	           filter, attrs, true, nullptr, nullptr, nullptr, 2, msg);
	if (ret == LDAP_LOCAL_ERROR && g_edir_workaround)
		/* try full reconnect */;
	else if (ret != LDAP_SERVER_DOWN)
		return ret;
	ld = make_conn(DO_BIND);
	if (ld == nullptr)
		return ret;
	return ldap_search_ext_s(ld.get(), base, LDAP_SCOPE_SUBTREE,
	       filter, attrs, true, nullptr, nullptr, nullptr, 2, msg);
}

BOOL ldap_adaptor_login2(const char *username, const char *password)
{
	auto tok = g_conn_pool.get_wait();
	ldap_msg msg;
	std::unique_ptr<char[], stdlib_delete> freeme;
	auto quoted = HX_strquote(username, HXQUOTE_LDAPRDN, &unique_tie(freeme));
	auto filter = g_mail_attr + "="s + quoted;
	auto ret = gx_ldap_search(tok->meta,
	      g_search_base.size() != 0 ? g_search_base.c_str() : nullptr,
	      filter.c_str(), const_cast<char **>(no_attrs), &unique_tie(msg));
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "[ldap_adaptor]: search with filter %s: %s\n",
		       filter.c_str(), ldap_err2string(ret));
		return FALSE;
	}
	if (!validate_response(tok->meta.get(), msg.get())) {
		fprintf(stderr, "[ldap_adaptor]: filter %s was ambiguous\n", filter.c_str());
		return FALSE;
	}

	auto firstmsg = ldap_first_message(tok->meta.get(), msg.get());
	if (firstmsg == nullptr)
		return FALSE;
	auto dn = ldap_get_dn(tok->meta.get(), firstmsg);
	if (dn == nullptr)
		return FALSE;

	struct berval bv;
	bv.bv_val = deconst(znul(password));
	bv.bv_len = password != nullptr ? strlen(password) : 0;
	ret = gx_ldap_bind(tok->bind, dn, &bv);
	if (ret == LDAP_SUCCESS)
		return TRUE;
	fprintf(stderr, "[ldap_adaptor]: ldap_simple_bind %s: %s\n", dn, ldap_err2string(ret));
	return FALSE;
}

static bool ldap_adaptor_load() try
{
	auto pfile = config_file_initd("ldap_adaptor.cfg", get_config_path(),
	             ldap_adaptor_cfg_defaults);
	if (pfile == nullptr) {
		fprintf(stderr, "[ldap_adaptor]: config_file_initd ldap_adaptor.cfg: %s\n",
		       strerror(errno));
		return false;
	}
	g_dataconn_num = pfile->get_ll("data_connections");
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
	fprintf(stderr, "[ldap_adaptor]: hosts <%s>%s%s, base <%s>, #conn=%d, mailattr=%s\n",
	       g_ldap_host.c_str(), g_use_tls ? " +TLS" : "",
	       g_edir_workaround ? " +EDIRECTORY_WORKAROUNDS" : "",
	       g_search_base.c_str(), 2 * g_dataconn_num, g_mail_attr.c_str());
	g_conn_pool.resize(g_dataconn_num);
	g_conn_pool.bump();
	return true;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "[ldap_adaptor]: E-1455: ENOMEM\n");
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
	if (!register_service("ldap_auth_login2", ldap_adaptor_login2)) {
		fprintf(stderr, "[ldap_adaptor]: failed to register services\n");
		return false;
	}
	return TRUE;
} catch (...) {
	return false;
}
SVC_ENTRY(svc_ldap_adaptor);
