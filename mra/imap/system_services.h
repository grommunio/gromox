#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/xarray.hpp>
#include <gromox/double_list.hpp>
#include <gromox/single_list.hpp>

extern int system_services_run();
extern int system_services_stop();

extern BOOL (*system_services_judge_ip)(const char*);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern BOOL (*system_services_auth_login)(const char*, const char*, char*, char*, char*, int);
extern int (*system_services_get_id)(const char*, const char*, const char*, unsigned int*);
extern int (*system_services_get_uid)(const char*, const char*, const char*, unsigned int*);
extern int (*system_services_summary_folder)(const char*, const char*, int *, int*, int*,
	unsigned long*, unsigned int*, int *, int*);
extern int (*system_services_make_folder)(const char*, const char*, int*);
extern int (*system_services_remove_folder)(const char*, const char*, int*);
extern int (*system_services_rename_folder)(const char*, const char*, const char*, int*);
extern int (*system_services_ping_mailbox)(const char*, int*);
extern int (*system_services_subscribe_folder)(const char*, const char*, int*);
extern int (*system_services_unsubscribe_folder)(const char*, const char*, int*);
extern int (*system_services_enum_folders)(const char*, MEM_FILE*, int*);
extern int (*system_services_enum_subscriptions)(const char*, MEM_FILE*, int*);
extern int (*system_services_insert_mail)(const char*, const char*, const char*, const char*, long, int*);
extern int (*system_services_remove_mail)(const char*, const char*, SINGLE_LIST*, int*);
extern int (*system_services_list_simple)(const char*, const char*, XARRAY*, int*);
extern int (*system_services_list_deleted)(const char*, const char*, XARRAY*, int*);
extern int (*system_services_list_detail)(const char*, const char*, XARRAY*, int*);
extern int (*system_services_fetch_simple)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
extern int (*system_services_fetch_detail)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
extern int (*system_services_fetch_simple_uid)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
extern int (*system_services_fetch_detail_uid)(const char*, const char*, DOUBLE_LIST*, XARRAY*, int*);
extern void (*system_services_free_result)(XARRAY*);
extern int (*system_services_set_flags)(const char*, const char*, const char*, int, int*);
extern int (*system_services_unset_flags)(const char*, const char*, const char*, int, int*);
extern int (*system_services_get_flags)(const char*, const char*, const char*, int*, int*);
extern int (*system_services_copy_mail)(const char*, const char*, const char*,
	const char*, char*, int*);
extern int (*system_services_search)(const char*, const char*, const char*, int, char**, char*, int*, int*);
extern int (*system_services_search_uid)(const char*, const char*, const char*, int, char**, char*, int*, int*);
extern void (*system_services_install_event_stub)(void (*)(char *));
extern void (*system_services_broadcast_event)(const char*);
extern void (*system_services_broadcast_select)(const char*, const char*);
extern void (*system_services_broadcast_unselect)(const char*, const char*);
extern void (*system_services_log_info)(int, const char *, ...);
