// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "ldap_adaptor.hpp"

using namespace std::string_literals;
using namespace gromox;
enum { A_DENY_ALL, A_ALLOW_ALL, A_EXTERNID };

static decltype(mysql_adaptor_meta) *fptr_mysql_meta;
static decltype(mysql_adaptor_login2) *fptr_mysql_login;
static decltype(ldap_adaptor_login3) *fptr_ldap_login;
static unsigned int am_choice = A_EXTERNID;

static bool login_gen(const char *username, const char *password,
    char *maildir, size_t msize, char *lang, size_t lsize, char *reason,
    size_t length, unsigned int wantpriv) try
{
	sql_meta_result mres;
	bool auth = false;
	auto err = fptr_mysql_meta(username, password, wantpriv, mres);
	gx_strlcpy(maildir, mres.maildir.c_str(), msize);
	gx_strlcpy(lang, mres.lang.c_str(), lsize);
	gx_strlcpy(reason, mres.errstr.c_str(), length);
	if (err != 0 || mres.have_xid == 0xFF)
		sleep(1);
	else if (am_choice == A_DENY_ALL)
		auth = false;
	else if (am_choice == A_ALLOW_ALL)
		auth = true;
	else if (am_choice == A_EXTERNID && mres.have_xid > 0)
		auth = fptr_ldap_login(username, password, mres);
	else if (am_choice == A_EXTERNID)
		auth = fptr_mysql_login(username, password,
		       mres.enc_passwd, mres.errstr);
	auth = auth && err == 0;
	if (!auth && *reason == '\0')
		mres.errstr = "Authentication rejected";
	safe_memset(mres.enc_passwd.data(), 0, mres.enc_passwd.size());
	return auth;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1701: ENOMEM\n");
	return false;
}

static bool authmgr_reload()
{
	auto pfile = config_file_initd("authmgr.cfg", get_config_path(), nullptr);
	if (pfile == nullptr) {
		fprintf(stderr, "[authmgr]: confing_file_initd authmgr.cfg: %s\n",
		        strerror(errno));
		return false;
	}

	auto val = pfile->get_value("auth_backend_selection");
	if (val == nullptr) {
	} else if (strcmp(val, "deny_all") == 0) {
		am_choice = A_DENY_ALL;
		fprintf(stderr, "[authmgr]: \e[31mAll authentication requests will be denied\e[0m\n");
	} else if (strcmp(val, "allow_all") == 0) {
		am_choice = A_ALLOW_ALL;
		fprintf(stderr, "[authmgr]: \e[1;31mArbitrary passwords will be accepted for authentication\e[0m\n");
	} else if (strcmp(val, "always_mysql") == 0 || strcmp(val, "always_ldap") == 0) {
		am_choice = A_EXTERNID;
		fprintf(stderr, "[authmgr]: \e[1;33mauth_backend_selection=always_mysql/always_ldap is obsolete; switching to =externid\e[0m\n");
	} else if (strcmp(val, "externid") == 0) {
		am_choice = A_EXTERNID;
	}

	if (fptr_ldap_login == nullptr) {
		query_service2("ldap_auth_login3", fptr_ldap_login);
		if (fptr_ldap_login == nullptr) {
			fprintf(stderr, "[authmgr]: ldap_adaptor plugin not loaded yet\n");
			return false;
		}
	}
	return true;
}

static bool authmgr_init()
{
	if (!authmgr_reload())
		return false;
	query_service2("mysql_auth_meta", fptr_mysql_meta);
	query_service2("mysql_auth_login2", fptr_mysql_login);
	if (fptr_mysql_meta == nullptr ||
	    fptr_mysql_login == nullptr) {
		fprintf(stderr, "[authmgr]: mysql_adaptor plugin not loaded yet\n");
		return false;
	}
	if (!register_service("auth_login_gen", login_gen)) {
		fprintf(stderr, "[authmgr]: failed to register auth services\n");
		return false;
	}
	return true;
}

static BOOL svc_authmgr(int reason, void **datap) try
{
	if (reason == PLUGIN_RELOAD) {
		authmgr_reload();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(datap);
	return authmgr_init() ? TRUE : false;
} catch (...) {
	return false;
}
SVC_ENTRY(svc_authmgr);
