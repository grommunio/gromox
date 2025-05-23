// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ldap.h>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/authmgr.hpp>
#include <gromox/config_file.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/plugin.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/tie.hpp>

using namespace gromox;

static char *g_auth_user, *g_ldap_uri;
static unsigned int g_direct_ldap, g_ldap_tls;
static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'H', HXTYPE_STRING, &g_ldap_uri, {}, {}, 0, "LDAP server", "URI"},
	{nullptr, 'L', HXTYPE_NONE, &g_direct_ldap, {}, {}, 0, "Pure LDAP bind without gromox-authmgr"},
	{nullptr, 'Z', HXTYPE_NONE, &g_ldap_tls, {}, {}, 0, "Enable LDAP TLS (only for -L)"},
	{nullptr, 'u', HXTYPE_STRING, &g_auth_user, {}, {}, 0, "User for authentication", "USERNAME"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};
static constexpr static_module g_dfl_svc_plugins[] = {
	{"libgxs_mysql_adaptor.so", SVC_mysql_adaptor},
	{"libgromox_auth.so/ldap", SVC_ldap_adaptor},
	{"libgromox_auth.so/mgr", SVC_authmgr},
};
static constexpr cfg_directive no_defaults[] = {
	{"config_file_path", PKGSYSCONFDIR "/http:" PKGSYSCONFDIR},
	{"data_file_path", PKGDATADIR "/http:" PKGDATADIR},
	CFG_TABLE_END,
};

namespace {
struct ldapfree {
	void operator()(LDAP *ld) const { ldap_unbind_ext_s(ld, nullptr, nullptr); }
	void operator()(LDAPMessage *m) const { ldap_msgfree(m); }
};
}

static int direct_ldap(const char *uri, const char *bind_user,
    const char *bind_pass)
{
	std::unique_ptr<LDAP, ldapfree> ld;
	auto ret = ldap_initialize(&unique_tie(ld), *znul(uri) == '\0' ? nullptr : uri);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "ldap_initialize failed: %s\n", ldap_err2string(ret));
		return EXIT_FAILURE;
	}
	static constexpr int version = LDAP_VERSION3;
	if ((ret = ldap_set_option(ld.get(), LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_SUCCESS ||
	   (ret = ldap_set_option(ld.get(), LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) != LDAP_SUCCESS) {
		fprintf(stderr, "ldap_set_option failed: %s\n", ldap_err2string(ret));
		return EXIT_FAILURE;
	}
	if (g_ldap_tls) {
		ret = ldap_start_tls_s(ld.get(), nullptr, nullptr);
		if (ret != LDAP_SUCCESS) {
			fprintf(stderr, "ldap_start_tls_s: %s\n", ldap_err2string(ret));
			return EXIT_FAILURE;
		}
	}
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
		fprintf(stderr, "ldap_adaptor: bind as \"%s\" on \"%s\": %s\n",
		        znul(bind_user), znul(uri), ldap_err2string(ret));
		return EXIT_FAILURE;
	}
	printf(
		"LDAP bind successful:\n"
		"\tDN = %s\n",
		znul(bind_user));

	std::unique_ptr<LDAPMessage, ldapfree> msg;
	ret = ldap_search_ext_s(ld.get(), bind_user, LDAP_SCOPE_BASE,
	           nullptr, nullptr, false, nullptr, nullptr, nullptr, 1,
	           &unique_tie(msg));
	printf("Locating my own object: %s\n", ldap_err2string(ret));
	return EXIT_SUCCESS;
}


int main(int argc, char **argv)
{
	if (HX_getopt5(g_options_table, argv, nullptr, nullptr,
	    HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (g_auth_user == nullptr) {
		fprintf(stderr, "The -u option is mandatory\n");
		return EXIT_FAILURE;
	}
	auto password = getenv("PASS");
	if (password == nullptr)
		fprintf(stderr, "To convey a password, use the PASS environment variable. "
			"Currently proceeding with NULL password.\n");
	if (g_direct_ldap)
		return direct_ldap(g_ldap_uri, g_auth_user, password);

	auto cfg = config_file_prg(nullptr, "http.cfg", no_defaults);
	if (cfg == nullptr)
		return EXIT_FAILURE; /* permission error */
	service_init({std::move(cfg), g_dfl_svc_plugins, 0, "authtest"});
	auto cl_1 = HX::make_scope_exit(service_stop);
	if (service_run_early() != 0) {
		fprintf(stderr, "service_run_early failed\n");
		return EXIT_FAILURE;
	} else if (service_run() != 0) { 
		fprintf(stderr, "service_run failed\n");
		return EXIT_FAILURE;
	}
	authmgr_login_t alogin = reinterpret_cast<authmgr_login_t>(service_query("auth_login_gen", "system", typeid(decltype(*alogin))));
	if (alogin == nullptr) {
		fprintf(stderr, "auth_login_gen missing\n");
		return EXIT_FAILURE;
	}
	auto cl_2 = HX::make_scope_exit([&]() { service_release("auth_login_gen", "system"); });
	sql_meta_result mres;
	if (!alogin(g_auth_user, password, WANTPRIV_BASIC, mres)) {
		fprintf(stderr, "Auth failed: %s\n", mres.errstr.c_str());
		return EXIT_FAILURE;
	}
	printf(
		"Auth successful:\n"
		"\tusername = %s\n"
		"\tmaildir  = %s\n"
		"\tlang, tz = %s, %s\n"
		"\tLDAP     = uri=%s, binddn=%s, basedn=%s, mailattr=%s, tls=%u\n"
		"\thave_xid = %u\n"
		"\tprivbits = 0x%x\n",
		mres.username.c_str(), mres.maildir.c_str(), mres.lang.c_str(),
		mres.timezone.c_str(), mres.ldap_uri.c_str(),
		mres.ldap_binddn.c_str(), mres.ldap_basedn.c_str(),
		mres.ldap_mail_attr.c_str(), mres.ldap_start_tls,
		mres.have_xid, mres.privbits);
	return EXIT_SUCCESS;
}
