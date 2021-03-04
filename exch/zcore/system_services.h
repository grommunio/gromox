#pragma once
#include <gromox/common_types.hpp>
#include "../mysql_adaptor/mysql_adaptor.h"

extern int system_services_run();
extern int system_services_stop();

extern BOOL (*system_services_get_user_lang)(const char*, char*);
extern BOOL (*system_services_set_user_lang)(const char*, const char*);
extern BOOL (*system_services_get_maildir)(const char*, char*);
extern BOOL (*system_services_get_homedir)(const char*, char*);
extern BOOL (*system_services_get_timezone)(const char*, char *);
extern BOOL (*system_services_set_timezone)(const char*, const char *);
extern BOOL (*system_services_get_username_from_id)(int, char*);
extern BOOL (*system_services_get_id_from_username)(const char*, int*);
extern BOOL (*system_services_get_domain_ids)(const char *, int*, int*);
extern BOOL (*system_services_get_user_ids)(const char*, int*, int*, int*);
extern BOOL (*system_services_lang_to_charset)(const char*, char*);
extern const char* (*system_services_cpid_to_charset)(uint32_t);
extern uint32_t (*system_services_charset_to_cpid)(const char*);
extern const char* (*system_services_lcid_to_ltag)(uint32_t);
extern uint32_t (*system_services_ltag_to_lcid)(const char*);
extern const char* (*system_services_mime_to_extension)(const char*);
extern const char* (*system_services_extension_to_mime)(const char*);
extern BOOL (*system_services_auth_login)(const char*,
	const char*, char*, char*, char*, int);
extern BOOL (*system_services_set_password)(
	const char*, const char*, const char*);
extern BOOL (*system_services_get_user_displayname)(const char*, char*);
extern BOOL (*system_services_get_user_privilege_bits)(const char*, uint32_t*);
extern decltype(mysql_adaptor_get_org_domains) *system_services_get_org_domains;
extern decltype(mysql_adaptor_get_domain_info) *system_services_get_domain_info;
extern decltype(mysql_adaptor_get_domain_groups) *system_services_get_domain_groups;
extern decltype(mysql_adaptor_get_group_classes) *system_services_get_group_classes;
extern decltype(mysql_adaptor_get_sub_classes) *system_services_get_sub_classes;
extern decltype(mysql_adaptor_get_class_users) *system_services_get_class_users;
extern decltype(mysql_adaptor_get_group_users) *system_services_get_group_users;
extern decltype(mysql_adaptor_get_domain_users) *system_services_get_domain_users;
extern BOOL (*system_services_get_mlist_ids)(int, int*, int*);
extern BOOL (*system_services_get_lang)(uint32_t, const char*, char*, int);
extern BOOL (*system_services_check_same_org)(int, int);
extern int (*system_services_add_timer)(const char *, int);
extern void (*system_services_log_info)(int, const char *, ...) __attribute__((format(printf, 2, 3)));
