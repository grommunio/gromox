#include <cstdio>
#include <gromox/svc_common.h>
#include "common_types.h"
#include "mysql_adaptor/mysql_adaptor.h"
#include "../../MTA_SYSTEM/service_plugins/esmtp_auth/service_auth.h"

DECLARE_API;
static decltype(mysql_adaptor_meta) *fptr_mysql_meta;
static decltype(mysql_adaptor_login2) *fptr_mysql_login;

static bool is_mta()
{
	auto i = static_cast<const char *>(query_service("_program_identifier"));
	return strcmp(i, "smtp") == 0 || strcmp(i, "delivery") == 0;
}

static BOOL login_gen(const char *username, const char *password,
    char *maildir, char *lang, char *reason, int length, unsigned int mode)
{
	char ep[40];
	auto ret = fptr_mysql_meta(username, password, maildir, lang, reason,
	           length, mode, ep, sizeof(ep));
	if (ret == FALSE)
		return FALSE;
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

BOOL SVC_LibMain(int reason, void **datap)
{
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_API(datap);
		fptr_mysql_meta = reinterpret_cast<decltype(fptr_mysql_meta)>(query_service("mysql_auth_meta"));
		if (fptr_mysql_meta == nullptr) {
			printf("[authn_mysql]: mysql_adaptor plugin not loaded yet\n");
			return false;
		}
		fptr_mysql_login = reinterpret_cast<decltype(fptr_mysql_login)>(query_service("mysql_auth_login2"));
		if (fptr_mysql_login == nullptr) {
			printf("[authn_mysql]: mysql_adaptor plugin not loaded yet\n");
			return false;
		}
		if (is_mta())
			service_auth_init(get_context_num(), login_smtp);
		if (is_mta() && service_auth_run() != 0) {
			printf("[authn_mysql]: failed to run service auth\n");
			return false;
		}
		if (!register_service("auth_login_exch", reinterpret_cast<void *>(login_exch)) ||
		    !register_service("auth_login_pop3", reinterpret_cast<void *>(login_pop3)) ||
		    !register_service("auth_ehlo", reinterpret_cast<void *>(service_auth_ehlo)) ||
		    !register_service("auth_process", reinterpret_cast<void *>(service_auth_process)) ||
		    !register_service("auth_retrieve", reinterpret_cast<void *>(service_auth_retrieve)) ||
		    !register_service("auth_clear", reinterpret_cast<void *>(service_auth_clear))) {
			printf("[authn_mysql]: failed to register auth services\n");
			return false;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		return TRUE;
	}
	return false;
}
