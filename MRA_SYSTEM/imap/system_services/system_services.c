#include "system_services.h"
#include "service.h"
#include <stdio.h>

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
void (*system_services_log_info)(int, char*, ...);

/*
 *	module's construct function
 */
void system_services_init()
{
	/* do nothing */
}

/*
 *	run system services module
 *	@return
 *		0		OK
 *		<>0		fail
 */
int system_services_run()
{
	system_services_judge_ip = service_query("ip_filter_judge", "system");
	if (NULL == system_services_judge_ip) {
		printf("[system_services]: fail to get \"ip_filter_judge\" service\n");
		return -1;
	}
	system_services_container_add_ip = service_query("ip_container_add",
												"system");
	if (NULL == system_services_container_add_ip) {
		printf("[system_services]: fail to get \"ip_container_add\" service\n");
		return -2;
	}
	system_services_container_remove_ip = service_query("ip_container_remove",
												"system");
	if (NULL == system_services_container_remove_ip) {
		printf("[system_services]: fail to get \"ip_container_remove\" "
			"service\n");
		return -3;
	}
	system_services_log_info = service_query("log_info", "system");
	if (NULL == system_services_log_info) {
		printf("[system_services]: fail to get \"log_info\" service\n");
		return -4;
	}
	system_services_judge_user = service_query("user_filter_judge", "system");
	if (NULL == system_services_judge_user) {
		printf("[system_services]: fail to get \"user_filter_judge\" service\n");
		return -5;
	}
	system_services_add_user_into_temp_list = service_query("user_filter_add", 
												"system");
	if (NULL == system_services_add_user_into_temp_list) {
		printf("[system_services]: fail to get \"user_filter_add\" service\n");
		return -6;
	}
	system_services_auth_login = service_query("auth_login", "system");
	if (NULL == system_services_auth_login) {
		printf("[system_services]: fail to get \"auth_login\" service\n");
		return -7;
	}
	
	system_services_get_id = service_query("get_mail_id", "system");
	if (NULL == system_services_get_id ) {
		printf("[system_services]: fail to get \"get_mail_id\" service\n");
		return -8;
	}
	
	system_services_get_uid = service_query("get_mail_uid", "system");
	if (NULL == system_services_get_uid ) {
		printf("[system_services]: fail to get \"get_mail_uid\" service\n");
		return -9;
	}
	
	system_services_summary_folder = service_query("summary_folder", "system");
	if (NULL == system_services_summary_folder) {
		printf("[system_services]: fail to get \"summary_folder\" service\n");
		return -10;
	}
	
	system_services_make_folder = service_query("make_folder", "system");
	if (NULL == system_services_make_folder) {
		printf("[system_services]: fail to get \"make_folder\" service\n");
		return -11;
	}
	
	system_services_remove_folder = service_query("remove_folder", "system");
	if (NULL == system_services_remove_folder) {
		printf("[system_services]: fail to get \"remove_folder\" service\n");
		return -12;
	}
	
	system_services_rename_folder = service_query("rename_folder", "system");
	if (NULL == system_services_rename_folder) {
		printf("[system_services]: fail to get \"rename_folder\" service\n");
		return -13;
	}
	
	system_services_ping_mailbox = service_query("ping_mailbox", "system");
	if (NULL == system_services_ping_mailbox) {
		printf("[system_services]: fail to get \"ping_mailbox\" service\n");
		return -13;
	}
	
	system_services_subscribe_folder = service_query("subscribe_folder", "system");
	if (NULL == system_services_subscribe_folder) {
		printf("[system_services]: fail to get \"subscribe_folder\" service\n");
		return -13;
	}
	
	system_services_unsubscribe_folder = service_query("unsubscribe_folder", "system");
	if (NULL == system_services_unsubscribe_folder) {
		printf("[system_services]: fail to get \"unsubscribe_folder\" service\n");
		return -14;
	}
	
	system_services_enum_folders = service_query("enum_folders", "system");
	if (NULL == system_services_enum_folders) {
		printf("[system_services]: fail to get \"enum_folders\" service\n");
		return -15;
	}
	
	system_services_enum_subscriptions = service_query("enum_subscriptions", "system");
	if (NULL == system_services_enum_subscriptions) {
		printf("[system_services]: fail to get \"enum_subscriptions\" service\n");
		return -16;
	}
	
	system_services_insert_mail = service_query("insert_mail", "system");
	if (NULL == system_services_insert_mail) {
		printf("[system_services]: fail to get \"insert_mail\" service\n");
		return -17;
	}
	
	system_services_remove_mail = service_query("remove_mail", "system");
	if (NULL == system_services_remove_mail) {
		printf("[system_services]: fail to get \"remove_mail\" service\n");
		return -18;
	}
	
	system_services_list_simple = service_query("list_simple", "system");
	if (NULL == system_services_list_simple) {
		printf("[system_services]: fail to get \"list_simple\" service\n");
		return -19;
	}
	
	system_services_list_deleted = service_query("list_deleted", "system");
	if (NULL == system_services_list_deleted) {
		printf("[system_services]: fail to get \"list_deleted\" service\n");
		return -20;
	}
	
	system_services_list_detail = service_query("list_detail", "system");
	if (NULL == system_services_list_detail) {
		printf("[system_services]: fail to get \"list_detail\" service\n");
		return -21;
	}
	
	system_services_free_result = service_query("free_result", "system");
	if (NULL == system_services_free_result) {
		printf("[system_services]: fail to get \"free_result\" service\n");
		return -22;
	}
	
	system_services_fetch_simple = service_query("fetch_simple", "system");
	if (NULL == system_services_fetch_simple) {
		printf("[system_services]: fail to get \"fetch_simple\" service\n");
		return -23;
	}
	
	system_services_fetch_detail = service_query("fetch_detail", "system");
	if (NULL == system_services_fetch_detail) {
		printf("[system_services]: fail to get \"fetch_detail\" service\n");
		return -24;
	}
	
	system_services_fetch_simple_uid = service_query("fetch_simple_uid", "system");
	if (NULL == system_services_fetch_simple_uid) {
		printf("[system_services]: fail to get \"fetch_simple_uid\" service\n");
		return -25;
	}
	
	system_services_fetch_detail_uid = service_query("fetch_detail_uid", "system");
	if (NULL == system_services_fetch_detail_uid) {
		printf("[system_services]: fail to get \"fetch_detail_uid\" service\n");
		return -26;
	}
	
	system_services_set_flags = service_query("set_mail_flags", "system");
	if (NULL == system_services_set_flags) {
		printf("[system_services]: fail to get \"set_mail_flags\" service\n");
		return -27;
	}
	
	system_services_unset_flags = service_query("unset_mail_flags", "system");
	if (NULL == system_services_unset_flags) {
		printf("[system_services]: fail to get \"unset_mail_flags\" service\n");
		return -28;
	}
	
	system_services_get_flags = service_query("get_mail_flags", "system");
	if (NULL == system_services_get_flags) {
		printf("[system_services]: fail to get \"get_mail_flags\" service\n");
		return -29;
	}
	
	system_services_copy_mail = service_query("copy_mail", "system");
	if (NULL == system_services_copy_mail) {
		printf("[system_services]: fail to get \"copy_mail\" service\n");
		return -30;
	}

	system_services_search = service_query("imap_search", "system");
	if (NULL == system_services_search) {
		printf("[system_services]: fail to get \"imap_search\" service\n");
		return -31;
	}
	
	system_services_search_uid = service_query("imap_search_uid", "system");
	if (NULL == system_services_search_uid) {
		printf("[system_services]: fail to get \"imap_search_uid\" service\n");
		return -32;
	}
	
	system_services_install_event_stub = service_query("install_event_stub", "system");
	if (NULL == system_services_install_event_stub) {
		printf("[system_services]: fail to get \"install_event_stub\" service\n");
		return -33;
	}
	
	system_services_broadcast_event = service_query("broadcast_event", "system");
	if (NULL == system_services_broadcast_event) {
		printf("[system_services]: fail to get \"broadcast_event\" service\n");
		return -34;
	}
	
	system_services_broadcast_select = service_query("broadcast_select", "system");
	if (NULL == system_services_broadcast_select) {
		printf("[system_services]: fail to get \"broadcast_select\" service\n");
		return -35;
	}
	
	system_services_broadcast_unselect = service_query("broadcast_unselect", "system");
	if (NULL == system_services_broadcast_unselect) {
		printf("[system_services]: fail to get \"broadcast_unselect\" service\n");
		return -36;
	}
	return 0;
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
	service_release("auth_login", "system");
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

/*
 *	module's destruct function
 */
void system_services_free()
{
	/* do nothing */

}


