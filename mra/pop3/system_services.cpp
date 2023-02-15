// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <gromox/defs.h>
#include <gromox/svc_loader.hpp>
#include "pop3.hpp"

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_ip)
E(judge_user)
E(container_add_ip)
E(container_remove_ip)
E(add_user_into_temp_list)
E(auth_login)
E(list_mail)
E(delete_mail)
E(broadcast_event)
#undef E

int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)
#define E2(f, s) \
	((f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))))

	E2(system_services_judge_ip, "ip_filter_judge");
	E2(system_services_container_add_ip, "ip_container_add");
	E2(system_services_container_remove_ip, "ip_container_remove");
	E2(system_services_judge_user, "user_filter_judge");
	E2(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_list_mail, "list_mail");
	E(system_services_delete_mail, "delete_mail");
	E2(system_services_broadcast_event, "broadcast_event");
	return 0;
#undef E
#undef E2
}

void system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("ip_container_add", "system");
	service_release("ip_container_remove", "system");
	service_release("ip_filter_add", "system");
	service_release("user_filter_add", "system");
	service_release("log_info", "system");
	service_release("auth_login_gen", "system");
	service_release("list_mail", "system");
	service_release("delete_mail", "system");
	service_release("broadcast_event", "system");
}
