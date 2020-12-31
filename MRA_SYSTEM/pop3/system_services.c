// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/defs.h>
#include "system_services.h"
#include "service.h"
#include <stdio.h>

BOOL (*system_services_judge_ip)(const char*);
BOOL (*system_services_judge_user)(const char*);
BOOL (*system_services_container_add_ip)(const char*);
BOOL (*system_services_container_remove_ip)(const char*);
int (*system_services_add_user_into_temp_list)(const char*, int);
BOOL (*system_services_auth_login)(const char*, const char*, char*, char*, char*, int);
int (*system_services_list_mail)(const char *, const char *, ARRAY *, int *pnum, uint64_t *psize);
int (*system_services_delete_mail)(const char *, const char *, SINGLE_LIST *);
int (*system_services_list_cdn_mail)(char*, ARRAY*);
int (*system_services_delete_cdn_mail)(char*, SINGLE_LIST*);
BOOL (*system_services_auth_cdn_user)(const char*, const char*);
int (*system_services_check_cdn_user)(const char*);
int (*system_services_create_cdn_user)(const char*);
void (*system_services_broadcast_event)(const char*);
void (*system_services_log_info)(int, const char *, ...);

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
	E(system_services_container_add_ip, "ip_container_add");
	E(system_services_container_remove_ip, "ip_container_remove");
	E(system_services_log_info, "log_info");
	E(system_services_judge_user, "user_filter_judge");
	E(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_auth_login, "auth_login_pop3");
	E(system_services_list_mail, "list_mail");
	E(system_services_delete_mail, "delete_mail");
	system_services_list_cdn_mail = service_query("cdn_uidl", "system");
	system_services_delete_cdn_mail = service_query("cdn_remove", "system");
	system_services_check_cdn_user = service_query("cdn_check", "system");
	system_services_auth_cdn_user = service_query("cdn_auth", "system");
	system_services_create_cdn_user = service_query("cdn_create", "system");
	system_services_broadcast_event = service_query("broadcast_event", "system");
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
	service_release("log_info", "system");
	service_release("info_user", "system");
	service_release("auth_login_pop3", "system");
	service_release("list_mail", "system");
	service_release("delete_mail", "system");
	service_release("broadcast_event", "system");
	if (NULL != system_services_check_cdn_user) {
		service_release("cdn_uidl", "system");
		service_release("cdn_remove", "system");
		service_release("cdn_check", "system");
		service_release("cdn_auth", "system");
		service_release("cdn_create", "system");
	}
	return 0;
}
