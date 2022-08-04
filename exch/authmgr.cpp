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
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>
#include "authmgr.hpp"
#include "ldap_adaptor.hpp"
#include "mysql_adaptor/mysql_adaptor.h"

using namespace std::string_literals;
using namespace gromox;
enum { A_DENY_ALL, A_ALLOW_ALL, A_MYSQL, A_LDAP, A_EXTERNID };

static decltype(mysql_adaptor_meta) *fptr_mysql_meta;
static decltype(mysql_adaptor_login2) *fptr_mysql_login;
static decltype(ldap_adaptor_login2) *fptr_ldap_login;
static unsigned int am_choice = A_EXTERNID;

static bool login_gen(const char *username, const char *password,
    char *maildir, size_t msize, char *lang, size_t lsize, char *reason,
    size_t length, unsigned int wantpriv)
{
	char ep[107]{};
	uint8_t have_xid = 0xFF;
	bool auth = false;
	*reason = '\0';
	auto meta = fptr_mysql_meta(username, password, maildir, msize,
	            lang, lsize, reason,
	            length, wantpriv, ep, sizeof(ep), &have_xid);
	if (!meta || have_xid == 0xFF)
		sleep(1);
	else if (am_choice == A_DENY_ALL)
		auth = false;
	else if (am_choice == A_ALLOW_ALL)
		auth = true;
	else if (am_choice == A_MYSQL)
		auth = fptr_mysql_login(username, password, ep, sizeof(ep),
		       reason, length);
	else if (am_choice == A_LDAP)
		auth = fptr_ldap_login(username, password);
	else if (am_choice == A_EXTERNID && have_xid > 0)
		auth = fptr_ldap_login(username, password);
	else if (am_choice == A_EXTERNID)
		auth = fptr_mysql_login(username, password, ep, sizeof(ep),
		       reason, length);
	auth = auth && meta;
	if (!auth && *reason == '\0')
		gx_strlcpy(reason, "Authentication rejected", length);
	safe_memset(ep, 0, std::size(ep));
	return auth;
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
	if (val == nullptr)
		/* nothing */;
	else if (strcmp(val, "deny_all") == 0)
		am_choice = A_DENY_ALL;
	else if (strcmp(val, "allow_all") == 0)
		am_choice = A_ALLOW_ALL;
	else if (strcmp(val, "always_mysql") == 0)
		am_choice = A_MYSQL;
	else if (strcmp(val, "always_ldap") == 0)
		am_choice = A_LDAP;
	else if (strcmp(val, "externid") == 0)
		am_choice = A_EXTERNID;
	fprintf(stderr, "[authmgr]: backend selection %s\n",
	        val != nullptr ? val : "none");

	if (fptr_ldap_login == nullptr && am_choice >= A_LDAP) {
		query_service2("ldap_auth_login2", fptr_ldap_login);
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
