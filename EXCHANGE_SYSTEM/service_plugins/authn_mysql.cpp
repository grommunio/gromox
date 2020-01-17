#include <cstdio>
#include <gromox/svc_common.h>
#include "common_types.h"
#include "mysql_adaptor/mysql_adaptor.h"
#include "../../MTA_SYSTEM/service_plugins/esmtp_auth/service_auth.h"

DECLARE_API;

static bool is_mta()
{
	auto i = static_cast<const char *>(query_service("_program_identifier"));
	return strcmp(i, "smtp") == 0 || strcmp(i, "delivery") == 0;
}

BOOL SVC_LibMain(int reason, void **datap)
{
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_API(datap);
		auto aexch = reinterpret_cast<decltype(mysql_adaptor_login_exch) *>(query_service("mysql_auth_login_exch"));
		auto apop  = reinterpret_cast<decltype(mysql_adaptor_login_pop3) *>(query_service("mysql_auth_login_pop3"));
		auto asmtp = reinterpret_cast<decltype(mysql_adaptor_login_smtp) *>(query_service("mysql_auth_login_smtp"));
		if (aexch == nullptr || apop == nullptr || asmtp == nullptr) {
			printf("[authn_mysql]: mysql_adaptor plugin not loaded yet\n");
			return false;
		}
		if (is_mta())
			service_auth_init(get_context_num(), asmtp);
		if (is_mta() && service_auth_run() != 0) {
			printf("[authn_mysql]: failed to run service auth\n");
			return false;
		}
		if (!register_service("auth_login_exch", reinterpret_cast<void *>(aexch)) ||
		    !register_service("auth_login_pop3", reinterpret_cast<void *>(apop)) ||
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
