#ifndef _H_SYSTEM_SERVICES_
#define _H_SYSTEM_SERVICES_
#include "common_types.h"
#include "mem_file.h"

void system_services_init();

int system_services_run();

int system_services_stop();

void system_services_free();

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
extern BOOL (*system_services_get_org_domains)(int, MEM_FILE*);
extern BOOL (*system_services_get_domain_info)(int, char*, char*, char*);
extern BOOL (*system_services_get_domain_groups)(int, MEM_FILE*);
extern BOOL (*system_services_get_group_classes)(int, MEM_FILE*);
extern BOOL (*system_services_get_sub_classes)(int, MEM_FILE*);
extern int (*system_services_get_class_users)(int, MEM_FILE*);
extern int (*system_services_get_group_users)(int, MEM_FILE*);
extern int (*system_services_get_domain_users)(int, MEM_FILE*);
extern BOOL (*system_services_get_mlist_ids)(int, int*, int*);
extern BOOL (*system_services_get_lang)(uint32_t, const char*, char*, int);
extern BOOL (*system_services_check_same_org)(int, int);
extern int (*system_services_add_timer)(const char *, int);
extern void (*system_services_log_info)(int, char*, ...);
#endif /* _H_SYSTEM_SERVICES_ */
