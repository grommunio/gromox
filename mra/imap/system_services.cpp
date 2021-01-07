// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/defs.h>
#include "system_services.h"
#include "service.h"
#include <cstdio>

BOOL (*system_services_judge_ip)(const char*);
BOOL (*system_services_judge_user)(const char*);
BOOL (*system_services_container_add_ip)(const char*);
BOOL (*system_services_container_remove_ip)(const char*);
int (*system_services_add_user_into_temp_list)(const char*, int);
BOOL (*system_services_auth_login)(const char*, const char*, char*, char*, char*, int);
int (*system_services_get_id)(const char*, const char*, const char*, unsigned int*);
int (*system_services_get_uid)(const char*, const char*, const char*, unsigned int*);
int (*system_services_summary_folder)(const char*, const char*, int *, int*, int*,
	unsigned long*, unsigned int*, int *, int*);
int (*system_services_make_folder)(const char*, const char*, int*);
int (*system_services_remove_folder)(const char*, const char*, int*);
int (*system_services_rename_folder)(const char*, const char*, const char*, int*);
int (*system_services_ping_mailbox)(const char*, int*);
int (*system_services_subscribe_folder)(const char*, const char*, int*);
int (*system_services_unsubscribe_folder)(const char*, const char*, int*);
int (*system_services_enum_folders)(const char*, MEM_FILE*, int*);
int (*system_services_enum_subscriptions)(const char*, MEM_FILE*, int*);
int (*system_services_insert_mail)(const char*, const char*, const char*, const char*, long, int*);
int (*system_services_remove_mail)(const char*, const char*, SINGLE_LIST*, int*);
int (*system_services_list_simple)(const char*, const char*, XARRAY*, int*);
int (*system_services_list_deleted)(const char*, const char*, XARRAY*, int*);
int (*system_services_list_detail)(const char*, const char*, XARRAY*, int*);
int (*system_services_fetch_simple)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
int (*system_services_fetch_detail)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
int (*system_services_fetch_simple_uid)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
int (*system_services_fetch_detail_uid)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
void (*system_services_free_result)(XARRAY*);
int (*system_services_set_flags)(const char*, const char*, const char*, int, int*);
int (*system_services_unset_flags)(const char*, const char*, const char*, int, int*);
int (*system_services_get_flags)(const char*, const char*, const char*, int*, int*);
int (*system_services_copy_mail)(const char*, const char*, const char*,
	const char*, char*, int*);
int (*system_services_search)(const char*, const char*, const char*, int, char**, char*, int*, int*);
int (*system_services_search_uid)(const char*, const char*, const char*, int, char**, char*, int*, int*);
void (*system_services_install_event_stub)(void *);
void (*system_services_broadcast_event)(const char*);
void (*system_services_broadcast_select)(const char*, const char*);
void (*system_services_broadcast_unselect)(const char*, const char*);
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
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system")); \
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
	E(system_services_get_id, "get_mail_id");
	E(system_services_get_uid, "get_mail_uid");
	E(system_services_summary_folder, "summary_folder");
	E(system_services_make_folder, "make_folder");
	E(system_services_remove_folder, "remove_folder");
	E(system_services_rename_folder, "rename_folder");
	E(system_services_ping_mailbox, "ping_mailbox");
	E(system_services_subscribe_folder, "subscribe_folder");
	E(system_services_unsubscribe_folder, "unsubscribe_folder");
	E(system_services_enum_folders, "enum_folders");
	E(system_services_enum_subscriptions, "enum_subscriptions");
	E(system_services_insert_mail, "insert_mail");
	E(system_services_remove_mail, "remove_mail");
	E(system_services_list_simple, "list_simple");
	E(system_services_list_deleted, "list_deleted");
	E(system_services_list_detail, "list_detail");
	E(system_services_free_result, "free_result");
	E(system_services_fetch_simple, "fetch_simple");
	E(system_services_fetch_detail, "fetch_detail");
	E(system_services_fetch_simple_uid, "fetch_simple_uid");
	E(system_services_fetch_detail_uid, "fetch_detail_uid");
	E(system_services_set_flags, "set_mail_flags");
	E(system_services_unset_flags, "unset_mail_flags");
	E(system_services_get_flags, "get_mail_flags");
	E(system_services_copy_mail, "copy_mail");
	E(system_services_search, "imap_search");
	E(system_services_search_uid, "imap_search_uid");
	E(system_services_install_event_stub, "install_event_stub");
	E(system_services_broadcast_event, "broadcast_event");
	E(system_services_broadcast_select, "broadcast_select");
	E(system_services_broadcast_unselect, "broadcast_unselect");
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
	service_release("get_mail_id", "system");
	service_release("get_mail_uid", "system");
	service_release("summary_folder", "system");
	service_release("make_folder", "system");
	service_release("remove_folder", "system");
	service_release("rename_folder", "system");
	service_release("subscribe_folder", "system");
	service_release("unsubscribe_folder", "system");
	service_release("enum_folders", "system");
	service_release("enum_subscriptions", "system");
	service_release("insert_mail", "system");
	service_release("remove_mail", "system");
	service_release("list_simple", "system");
	service_release("list_detail", "system");
	service_release("free_list", "system");
	service_release("fetch_simple", "system");
	service_release("fetch_detail", "system");
	service_release("fetch_simple_uid", "system");
	service_release("fetch_detail_uid", "system");
	service_release("free_fetch", "system");
	service_release("set_mail_flags", "system");
	service_release("unset_mail_flags", "system");
	service_release("get_mail_flags", "system");
	service_release("copy_mail", "system");
	service_release("imap_search", "system");
	service_release("imap_search_uid", "system");
	service_release("install_event_stub", "system");
	service_release("broadcast_event", "system");
	service_release("broadcast_select", "system");
	service_release("broadcast_unselect", "system");
	return 0;
}
