#include "system_services.h"
#include "service.h"
#include <stdio.h>

BOOL (*system_services_get_user_lang)(const char*, char*);
BOOL (*system_services_set_user_lang)(const char*, const char*);
BOOL (*system_services_get_maildir)(const char*, char*);
BOOL (*system_services_get_homedir)(const char*, char*);
BOOL (*system_services_get_timezone)(const char*, char *);
BOOL (*system_services_set_timezone)(const char*, const char *);
BOOL (*system_services_get_username_from_id)(int, char*);
BOOL (*system_services_get_id_from_username)(const char*, int*);
BOOL (*system_services_get_domain_ids)(const char *, int*, int*);
BOOL (*system_services_get_user_ids)(const char*, int*, int*, int*);
BOOL (*system_services_lang_to_charset)(const char*, char*);
const char* (*system_services_cpid_to_charset)(uint32_t);
uint32_t (*system_services_charset_to_cpid)(const char*);
const char* (*system_services_lcid_to_ltag)(uint32_t);
uint32_t (*system_services_ltag_to_lcid)(const char*);
const char* (*system_services_mime_to_extension)(const char*);
const char* (*system_services_extension_to_mime)(const char*);
BOOL (*system_services_auth_login)(const char*,
	const char*, char*, char*, char*, int);
BOOL (*system_services_set_password)(
	const char*, const char*, const char*);
BOOL (*system_services_get_user_displayname)(const char*, char*);
BOOL (*system_services_get_user_privilege_bits)(const char*, uint32_t*);
BOOL (*system_services_get_org_domains)(int, MEM_FILE*);
BOOL (*system_services_get_domain_info)(int, char*, char*, char*);
BOOL (*system_services_get_domain_groups)(int, MEM_FILE*);
BOOL (*system_services_get_group_classes)(int, MEM_FILE*);
BOOL (*system_services_get_sub_classes)(int, MEM_FILE*);
int (*system_services_get_class_users)(int, MEM_FILE*);
int (*system_services_get_group_users)(int, MEM_FILE*);
int (*system_services_get_domain_users)(int, MEM_FILE*);
BOOL (*system_services_get_mlist_ids)(int, int*, int*);
BOOL (*system_services_get_lang)(uint32_t, const char*, char*, int);
BOOL (*system_services_check_same_org)(int, int);
int (*system_services_add_timer)(const char *, int);
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
	system_services_get_user_lang = service_query(
						"get_user_lang", "system");
	if (NULL == system_services_get_user_lang) {
		printf("[system_services]: fail to "
			"get \"get_user_lang\" service\n");
		return -1;
	}
	system_services_set_user_lang = service_query(
						"set_user_lang", "system");
	if (NULL == system_services_set_user_lang) {
		printf("[system_services]: fail to "
			"get \"set_user_lang\" service\n");
		return -2;
	}
	system_services_get_maildir = service_query(
						"get_maildir", "system");
	if (NULL == system_services_get_maildir) {
		printf("[system_services]: fail to "
			"get \"get_maildir\" service\n");
		return -3;
	}
	system_services_get_homedir = service_query(
						"get_homedir", "system");
	if (NULL == system_services_get_homedir) {
		printf("[system_services]: fail to "
			"get \"get_homedir\" service\n");
		return -4;
	}
	system_services_get_timezone = service_query(
						"get_timezone", "system");
	if (NULL == system_services_get_timezone) {
		printf("[system_services]: fail to "
			"get \"get_timezone\" service\n");
		return -5;
	}
	system_services_set_timezone = service_query(
						"set_timezone", "system");
	if (NULL == system_services_set_timezone) {
		printf("[system_services]: fail to "
			"set \"set_timezone\" service\n");
		return -6;
	}
	system_services_get_username_from_id = service_query(
						"get_username_from_id", "system");
	if (NULL == system_services_get_username_from_id) {
		printf("[system_services]: fail to get "
			"\"get_username_from_id\" service\n");
		return -7;
	}
	system_services_get_id_from_username = service_query(
						"get_id_from_username", "system");
	if (NULL == system_services_get_id_from_username) {
		printf("[system_services]: fail to get "
			"\"get_id_from_username\" service\n");
		return -8;
	}
	system_services_get_domain_ids = service_query(
						"get_domain_ids", "system");
	if (NULL == system_services_get_domain_ids) {
		printf("[system_services]: fail to get "
				"\"get_domain_ids\" service\n");
		return -9;
	}
	system_services_get_user_ids = service_query(
						"get_user_ids", "system");
	if (NULL == system_services_get_user_ids) {
		printf("[system_services]: fail to "
			"get \"get_user_ids\" service\n");
		return -10;
	}
	system_services_lang_to_charset = service_query(
						"lang_to_charset", "system");
	if (NULL == system_services_lang_to_charset) {
		printf("[system_services]: fail to get "
				"\"lang_to_charset\" service\n");
		return -11;
	}
	system_services_cpid_to_charset = service_query(
						"cpid_to_charset", "system");
	if (NULL == system_services_cpid_to_charset) {
		printf("[system_services]: fail to get "
				"\"cpid_to_charset\" service\n");
		return -12;
	}
	system_services_charset_to_cpid = service_query(
						"charset_to_cpid", "system");
	if (NULL == system_services_charset_to_cpid) {
		printf("[system_services]: fail to get "
				"\"charset_to_cpid\" service\n");
		return -13;
	}
	system_services_lcid_to_ltag = service_query(
						"lcid_to_ltag", "system");
	if (NULL == system_services_lcid_to_ltag) {
		printf("[system_services]: fail to "
			"get \"lcid_to_ltag\" service\n");
		return -14;
	}
	system_services_ltag_to_lcid = service_query(
						"ltag_to_lcid", "system");
	if (NULL == system_services_ltag_to_lcid) {
		printf("[system_services]: fail to "
			"get \"ltag_to_lcid\" service\n");
		return -15;
	}
	system_services_mime_to_extension = service_query(
						"mime_to_extension", "system");
	if (NULL == system_services_mime_to_extension) {
		printf("[system_services]: fail to get"
			" \"mime_to_extension\" service\n");
		return -16;
	}
	system_services_extension_to_mime = service_query(
						"extension_to_mime", "system");
	if (NULL == system_services_extension_to_mime) {
		printf("[system_services]: fail to get"
			" \"extension_to_mime\" service\n");
		return -17;
	}
	system_services_auth_login = service_query(
						"auth_login", "system");
	if (NULL == system_services_auth_login) {
		printf("[system_services]: fail to "
			"get \"auth_login\" service\n");
		return -18;
	}
	system_services_get_user_displayname = service_query(
						"get_user_displayname", "system");
	if (NULL == system_services_get_user_displayname) {
		printf("[system_services]: fail to get "
			"\"get_user_displayname\" service\n");
		return -19;
	}
	system_services_get_org_domains = service_query(
						"get_org_domains", "system");
	if (NULL == system_services_get_org_domains) {
		printf("[system_services]: fail to get"
			" \"get_org_domains\" service\n");
		return -20;
	}
	system_services_get_domain_info = service_query(
						"get_domain_info", "system");
	if (NULL == system_services_get_domain_info) {
		printf("[system_services]: fail to get"
			" \"get_domain_info\" service\n");
		return -21;
	}
	system_services_get_domain_groups = service_query(
						"get_domain_groups", "system");
	if (NULL == system_services_get_domain_groups) {
		printf("[system_services]: fail to get"
			" \"get_domain_groups\" service\n");
		return -22;
	}
	system_services_get_group_classes = service_query(
						"get_group_classes", "system");
	if (NULL == system_services_get_group_classes) {
		printf("[system_services]: fail to get"
			" \"get_group_classes\" service\n");
		return -23;
	}
	system_services_get_sub_classes = service_query(
						"get_sub_classes", "system");
	if (NULL == system_services_get_sub_classes) {
		printf("[system_services]: fail to get"
			" \"get_sub_classes\" service\n");
		return -24;
	}
	system_services_get_class_users = service_query(
						"get_class_users", "system");
	if (NULL == system_services_get_class_users) {
		printf("[system_services]: fail to get"
			" \"get_class_users\" service\n");
		return -25;
	}
	system_services_get_group_users = service_query(
						"get_group_users", "system");
	if (NULL == system_services_get_group_users) {
		printf("[system_services]: fail to get"
			" \"get_group_users\" service\n");
		return -26;
	}
	system_services_get_domain_users = service_query(
						"get_domain_users", "system");
	if (NULL == system_services_get_domain_users) {
		printf("[system_services]: fail to get"
			" \"get_domain_users\" service\n");
		return -27;
	}
	system_services_get_mlist_ids = service_query(
						"get_mlist_ids", "system");
	if (NULL == system_services_get_mlist_ids) {
		printf("system_services]: fail to get"
			" \" get_mlist_ids\" service\n");
		return -28;
	}
	system_services_get_lang = service_query(
						"get_lang", "system");
	if (NULL == system_services_get_lang) {
		printf("[system_services]: fail to"
			" get \"get_lang\" service\n");
		return -29;
	}
	system_services_check_same_org = service_query(
						"check_same_org", "system");
	if (NULL == system_services_check_same_org) {
		printf("[system_services]: fail to query"
				" \"check_same_org\" service\n");
		return -30;
	}
	system_services_log_info = service_query(
						"log_info", "system");
	if (NULL == system_services_log_info) {
		printf("[system_services]: fail to"
			" get \"log_info\" service\n");
		return -31;
	}
	system_services_set_password = service_query(
						"set_password", "system");
	if (NULL == system_services_set_password) {
		printf("[system_service]: fail to get"
				" \"set_password\" service\n");
		return -32;
	}
	system_services_get_user_privilege_bits =
		service_query("get_user_privilege_bits", "system");
	if (NULL == system_services_get_user_privilege_bits) {
		printf("[system_service]: fail to get "
			"\"get_user_privilege_bits\" service\n");
		return -33;
	}
	system_services_add_timer =
		service_query("add_timer", "system");
	if (NULL == system_services_add_timer) {
		printf("[system_service]: fail to "
			"get \"add_timer\" service\n");
		return -34;
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
	return 0;
}

/*
 *	module's destruct function
 */
void system_services_free()
{
	/* do nothing */

}
