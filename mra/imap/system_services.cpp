// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <gromox/defs.h>
#include <gromox/svc_loader.hpp>
#include "imap.hpp"

#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(judge_ip)
E(judge_user)
E(container_add_ip)
E(container_remove_ip)
E(add_user_into_temp_list)
E(auth_login)
E(get_id)
E(get_uid)
E(summary_folder)
E(make_folder)
E(remove_folder)
E(rename_folder)
E(ping_mailbox)
E(subscribe_folder)
E(unsubscribe_folder)
E(enum_folders)
E(enum_subscriptions)
E(insert_mail)
E(remove_mail)
E(list_simple)
E(list_deleted)
E(list_detail)
E(fetch_simple)
E(fetch_detail)
E(fetch_simple_uid)
E(fetch_detail_uid)
E(free_result)
E(set_flags)
E(unset_flags)
E(get_flags)
E(copy_mail)
E(search)
E(search_uid)
E(install_event_stub)
E(broadcast_event)
E(broadcast_select)
E(broadcast_unselect)
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

	E2(system_services_judge_ip, "ip_filter_judge");
	E2(system_services_container_add_ip, "ip_container_add");
	E2(system_services_container_remove_ip, "ip_container_remove");
	E2(system_services_judge_user, "user_filter_judge");
	E2(system_services_add_user_into_temp_list, "user_filter_add");
	E(system_services_auth_login, "auth_login_gen");
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
	service_release("get_mail_id", "system");
	service_release("get_mail_uid", "system");
	service_release("summary_folder", "system");
	service_release("make_folder", "system");
	service_release("remove_folder", "system");
	service_release("rename_folder", "system");
	service_release("ping_mailbox", "system");
	service_release("subscribe_folder", "system");
	service_release("unsubscribe_folder", "system");
	service_release("enum_folders", "system");
	service_release("enum_subscriptions", "system");
	service_release("insert_mail", "system");
	service_release("remove_mail", "system");
	service_release("list_simple", "system");
	service_release("list_deleted", "system");
	service_release("list_detail", "system");
	service_release("free_result", "system");
	service_release("fetch_simple", "system");
	service_release("fetch_detail", "system");
	service_release("fetch_simple_uid", "system");
	service_release("fetch_detail_uid", "system");
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
}
