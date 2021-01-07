// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/defs.h>
#include "system_services.h"
#include "service.h"
#include <stdio.h>

BOOL (*system_services_judge_ip)(const char*);
BOOL (*system_services_judge_user)(const char*);
BOOL (*system_services_container_add_ip)(const char*);
BOOL (*system_services_container_remove_ip)(const char*);
int (*system_services_add_ip_into_temp_list)(const char*, int);
int (*system_services_add_user_into_temp_list)(const char*, int);
BOOL (*system_services_check_domain)(const char*);
BOOL (*system_services_check_user)(const char*, char*);
BOOL (*system_services_check_full)(const char*);
void (*system_services_log_info)(int, const char *, ...);
void (*system_services_etrn_process)(const char*, int, char*, int);
void (*system_services_vrfy_process)(const char*, int, char*, int);

/*
 *	run system services module
 *	@return
 *		0		OK
 *		<>0		fail
 */
int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system")); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)
#define E2(f, s) ((f) = reinterpret_cast<decltype(f)>(service_query((s), "system")))

	E(system_services_judge_ip, "ip_filter_judge");
	E(system_services_add_ip_into_temp_list, "ip_filter_add");
	E(system_services_container_add_ip, "ip_container_add");
	E(system_services_container_remove_ip, "ip_container_remove");
	E(system_services_log_info, "log_info");
	E(system_services_judge_user, "user_filter_judge");
	E(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_check_domain, "check_domain");
	E2(system_services_check_user, "check_user");
	E2(system_services_check_full, "check_full");
	E2(system_services_etrn_process, "etrn_process");
	E2(system_services_vrfy_process, "vrfy_process");
	return 0;
#undef E
#undef E2
}

/*
 *	stop the system services
 *	@return
 *		0		OK
 *		<>0		fail
 */
int system_services_stop()
{
	service_release("ip_filter_judge", "system");
	service_release("user_filter_judge", "system");
	service_release("ip_container_add", "system");
	service_release("ip_container_remove", "system");
	service_release("ip_filter_add", "system");
	service_release("user_filer_add", "system");
	service_release("check_domain", "system");
	if (NULL != system_services_check_user) {
		service_release("check_user", "system");
	}
	if (NULL != system_services_etrn_process) {
		service_release("etrn_process", "system");
	}
	if (NULL != system_services_vrfy_process) {
		service_release("vrfy_process", "system");
	}
	service_release("log_info", "system");
	return 0;
}
