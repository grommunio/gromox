// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <typeinfo>
#include <gromox/defs.h>
#include "service.h"
#include "system_services.h"

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_user)
E(add_user_into_temp_list)
E(check_user)
E(check_full)
E(log_info)
#undef E

int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(decltype(*(f))))); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)
#define E2(f, s) ((f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(decltype(*(f))))))

	E(system_services_log_info, "log_info");
	E2(system_services_judge_user, "user_filter_judge");
	E2(system_services_add_user_into_temp_list, "user_filter_add");
	E2(system_services_check_user, "check_user");
	E2(system_services_check_full, "check_full");
	return 0;
#undef E
#undef E2
}

void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("ip_filter_add", "system");
	service_release("user_filter_add", "system");
	if (NULL != system_services_check_user) {
		service_release("check_user", "system");
	}
	if (system_services_check_full != nullptr)
		service_release("check_full", "system");
	service_release("log_info", "system");
}
