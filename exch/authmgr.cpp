// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <gromox/svc_common.h>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include "ldap_adaptor.hpp"
#include "mysql_adaptor/mysql_adaptor.h"

using namespace std::string_literals;
enum { A_DENY_ALL, A_ALLOW_ALL, A_MYSQL, A_LDAP, A_EXTERNID };

static decltype(mysql_adaptor_meta) *fptr_mysql_meta;
static decltype(mysql_adaptor_login2) *fptr_mysql_login;
static decltype(ldap_adaptor_login2) *fptr_ldap_login;
static unsigned int am_choice = A_EXTERNID;

static BOOL login_gen(const char *username, const char *password,
    char *maildir, char *lang, char *reason, int length, unsigned int mode)
{
	char ep[107]{};
	uint8_t have_xid = 0xFF;
	BOOL auth = false;
	auto meta = fptr_mysql_meta(username, password, maildir, lang, reason,
	            length, mode, ep, sizeof(ep), &have_xid);
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
	return meta && auth ? TRUE : false;
}

static BOOL login_exch(const char *username, const char *password,
	char *maildir, char *lang, char *reason, int length)
{
	return login_gen(username, password, maildir, lang, reason, length, 0);
}

static BOOL login_pop3(const char *username, const char *password,
	char *maildir, char *lang, char *reason, int length)
{
	return login_gen(username, password, maildir, lang,
	       reason, length, USER_PRIVILEGE_POP3_IMAP);
}

static BOOL login_smtp(const char *username, const char *password,
    char *reason, int length)
{
	char maildir[256], lang[32];
	return login_gen(username, password, maildir, lang,
	       reason, length, USER_PRIVILEGE_SMTP);
}

static bool authmgr_reload()
{
	auto pfile = config_file_initd("authmgr.cfg", get_config_path());
	if (pfile == nullptr) {
		printf("[authmgr]: confing_file_initd authmgr.cfg: %s\n", strerror(errno));
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
	printf("[authmgr]: backend selection %s\n", val != nullptr ? val : "none");

	if (fptr_ldap_login == nullptr && am_choice >= A_LDAP) {
		query_service2("ldap_auth_login2", fptr_ldap_login);
		if (fptr_ldap_login == nullptr) {
			printf("[authmgr]: ldap_adaptor plugin not loaded yet\n");
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
		printf("[authmgr]: mysql_adaptor plugin not loaded yet\n");
		return false;
	}
	if (!register_service("auth_login_exch", login_exch) ||
	    !register_service("auth_login_pop3", login_pop3) ||
	    !register_service("auth_login_smtp", login_smtp)) {
		printf("[authmgr]: failed to register auth services\n");
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
	LINK_API(datap);
	return authmgr_init() ? TRUE : false;
} catch (...) {
	return false;
}
SVC_ENTRY(svc_authmgr);
