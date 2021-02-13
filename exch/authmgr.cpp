// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#define DECLARE_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <gromox/svc_common.h>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include "mysql_adaptor/mysql_adaptor.h"

using namespace std::string_literals;
enum { A_MYSQL, A_LDAP, A_EXTERNID };

static decltype(mysql_adaptor_meta) *fptr_mysql_meta;
static decltype(mysql_adaptor_login2) *fptr_mysql_login, *fptr_ldap_login;
static unsigned int am_choice = A_MYSQL;

static BOOL login_gen(const char *username, const char *password,
    char *maildir, char *lang, char *reason, int length, unsigned int mode)
{
	char ep[40];
	uint8_t xip = false;
	auto ret = fptr_mysql_meta(username, password, maildir, lang, reason,
	           length, mode, ep, sizeof(ep), &xip);
	if (ret == FALSE)
		return FALSE;
	if (am_choice == A_MYSQL)
		return fptr_mysql_login(username, password, ep, sizeof(ep),
		       reason, length, mode);
	else if (am_choice == A_LDAP)
		return fptr_ldap_login(username, password, ep, sizeof(ep),
		       reason, length, mode);
	if (xip)
		return fptr_ldap_login(username, password, ep, sizeof(ep),
		       reason, length, mode);
	return fptr_mysql_login(username, password, ep, sizeof(ep),
	       reason, length, mode);
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

static BOOL authmgr_init()
{
	auto pfile = config_file_initd("authmgr.cfg", get_config_path());
	if (pfile == nullptr) {
		printf("[authmgr]: confing_file_initd authmgr.cfg: %s\n", strerror(errno));
		return false;
	}

	auto val = config_file_get_value(pfile, "auth_backend_selection");
	if (val == nullptr)
		/* nothing */;
	else if (strcmp(val, "always_mysql") == 0)
		am_choice = A_MYSQL;
	else if (strcmp(val, "always_ldap") == 0)
		am_choice = A_LDAP;
	else if (strcmp(val, "externid") == 0)
		am_choice = A_EXTERNID;

	fptr_mysql_meta = reinterpret_cast<decltype(fptr_mysql_meta)>(query_service("mysql_auth_meta"));
	if (fptr_mysql_meta == nullptr) {
		printf("[authmgr]: mysql_adaptor plugin not loaded yet\n");
		return false;
	}
	if (am_choice >= A_LDAP) {
		auto fload = reinterpret_cast<bool (*)()>(query_service("ldap_adaptor_load"));
		fptr_ldap_login = reinterpret_cast<decltype(fptr_ldap_login)>(query_service("ldap_auth_login2"));
		if (fload == nullptr || fptr_ldap_login == nullptr) {
			printf("[authmgr]: ldap_adaptor plugin not loaded yet\n");
			return false;
		}
		if (!fload())
			return false;
	}
	fptr_mysql_login = reinterpret_cast<decltype(fptr_mysql_login)>(query_service("mysql_auth_login2"));
	if (fptr_mysql_login == nullptr) {
		printf("[authmgr]: mysql_adaptor plugin not loaded yet\n");
		return false;
	}
	if (!register_service("auth_login_exch", reinterpret_cast<void *>(login_exch)) ||
	    !register_service("auth_login_pop3", reinterpret_cast<void *>(login_pop3)) ||
	    !register_service("auth_login_smtp", reinterpret_cast<void *>(login_smtp))) {
		printf("[authmgr]: failed to register auth services\n");
		return false;
	}
	return TRUE;
}

static BOOL svc_authmgr(int reason, void **datap) try
{
	if (reason == PLUGIN_FREE)
		return TRUE;
	if (reason != PLUGIN_INIT)
		return false;
	LINK_API(datap);
	return authmgr_init();
} catch (...) {
	return false;
}
SVC_ENTRY(svc_authmgr);
