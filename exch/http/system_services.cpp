// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <gromox/authmgr.hpp>
#include <gromox/defs.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "system_services.hpp"

using namespace gromox;

decltype(system_services_judge_ip) system_services_judge_ip;
BOOL (*system_services_judge_user)(const char*);
BOOL (*system_services_add_user_into_temp_list)(const char *, int);
decltype(system_services_auth_login) system_services_auth_login;

int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(decltype(*(f))))); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "system_services: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)
#define E2(f, s) ((f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(decltype(*(f))))))

	E2(system_services_judge_ip, "ip_filter_judge");
	E2(system_services_judge_user, "user_filter_judge");
	E2(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_auth_login, "auth_login_gen");
	return 0;
#undef E
#undef E2
}

void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("user_filter_add", "system");
	service_release("auth_login_gen", "system");
}
