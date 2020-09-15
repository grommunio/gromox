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
BOOL (*system_services_check_relay)(const char*);
BOOL (*system_services_check_domain)(const char*);
BOOL (*system_services_check_user)(const char*, char*);
BOOL (*system_services_check_full)(const char*);
void (*system_services_log_info)(int, const char *, ...);
const char* (*system_services_auth_ehlo)();
int (*system_services_auth_process)(int,const char*, int, char*, int);
BOOL (*system_services_auth_retrieve)(int, char*, int);
void (*system_services_auth_clear)(int);
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
	(f) = service_query((s), "system"); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "system_services", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_judge_ip, "ip_filter_judge");
	E(system_services_add_ip_into_temp_list, "ip_filter_add");
	E(system_services_container_add_ip, "ip_container_add");
	E(system_services_container_remove_ip, "ip_container_remove");
	E(system_services_check_relay, "check_relay");
	E(system_services_log_info, "log_info");
	E(system_services_judge_user, "user_filter_judge");
	E(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_auth_ehlo, "auth_ehlo");
	if (NULL != system_services_auth_ehlo) {
		E(system_services_auth_process, "auth_process");
		E(system_services_auth_retrieve, "auth_retrieve");
		E(system_services_auth_clear, "auth_clear");
	}
	E(system_services_check_domain, "check_domain");
	system_services_check_user = service_query("check_user", "system");
	system_services_check_full = service_query("check_full", "system");
	system_services_etrn_process = service_query("etrn_process", "system");
	system_services_vrfy_process = service_query("vrfy_process", "system");
	return 0;
#undef E
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
	service_release("check_relay", "system");
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
	if (NULL != system_services_auth_ehlo) {
		service_release("auth_ehlo", "system");
		service_release("auth_process", "system");
		service_release("auth_retrieve", "system");
		service_release("auth_clear", "system");
	}
	return 0;
}
