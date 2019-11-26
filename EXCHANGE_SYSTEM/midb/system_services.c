#include "system_services.h"
#include "service.h"
#include <stdio.h>

BOOL (*system_services_get_user_lang)(const char*, char*);
BOOL (*system_services_get_timezone)(const char*, char *);
BOOL (*system_services_get_username_from_id)(int, char*);
BOOL (*system_services_get_id_from_username)(const char*, int*);
BOOL (*system_services_get_user_ids)(const char*, int*, int*, int*);
BOOL (*system_services_lang_to_charset)(const char*, char*);
const char* (*system_services_cpid_to_charset)(uint32_t);
uint32_t (*system_services_charset_to_cpid)(const char*);
const char* (*system_services_lcid_to_ltag)(uint32_t);
uint32_t (*system_services_ltag_to_lcid)(const char*);
const char* (*system_services_mime_to_extension)(const char*);
const char* (*system_services_extension_to_mime)(const char*);
void (*system_services_broadcast_event)(const char*);

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
	system_services_get_user_lang = service_query("get_user_lang", "system");
	if (NULL == system_services_get_user_lang) {
		printf("[system_services]: fail to get \"get_user_lang\" service\n");
		return -1;
	}
	system_services_get_timezone = service_query("get_timezone", "system");
	if (NULL == system_services_get_timezone) {
		printf("[system_services]: fail to get \"get_timezone\" service\n");
		return -2;
	}
	system_services_get_username_from_id = service_query("get_username_from_id", "system");
	if (NULL == system_services_get_username_from_id) {
		printf("[system_services]: fail to get \"get_username_from_id\" service\n");
		return -3;
	}
	system_services_get_id_from_username = service_query("get_id_from_username", "system");
	if (NULL == system_services_get_id_from_username) {
		printf("[system_services]: fail to get \"get_id_from_username\" service\n");
		return -4;
	}
	system_services_get_user_ids = service_query("get_user_ids", "system");
	if (NULL == system_services_get_user_ids) {
		printf("[system_services]: fail to get \"get_user_ids\" service\n");
		return -5;
	}
	system_services_lang_to_charset = service_query("lang_to_charset", "system");
	if (NULL == system_services_lang_to_charset) {
		printf("[system_services]: fail to get \"lang_to_charset\" service\n");
		return -6;
	}
	system_services_cpid_to_charset = service_query("cpid_to_charset", "system");
	if (NULL == system_services_cpid_to_charset) {
		printf("[system_services]: fail to get \"cpid_to_charset\" service\n");
		return -7;
	}
	system_services_charset_to_cpid = service_query("charset_to_cpid", "system");
	if (NULL == system_services_charset_to_cpid) {
		printf("[system_services]: fail to get \"charset_to_cpid\" service\n");
		return -8;
	}
	system_services_lcid_to_ltag = service_query("lcid_to_ltag", "system");
	if (NULL == system_services_lcid_to_ltag) {
		printf("[system_services]: fail to get \"lcid_to_ltag\" service\n");
		return -9;
	}
	system_services_ltag_to_lcid = service_query("ltag_to_lcid", "system");
	if (NULL == system_services_ltag_to_lcid) {
		printf("[system_services]: fail to get \"ltag_to_lcid\" service\n");
		return -10;
	}
	system_services_mime_to_extension = service_query("mime_to_extension", "system");
	if (NULL == system_services_mime_to_extension) {
		printf("[system_services]: fail to get \"mime_to_extension\" service\n");
		return -11;
	}
	system_services_extension_to_mime = service_query("extension_to_mime", "system");
	if (NULL == system_services_extension_to_mime) {
		printf("[system_services]: fail to get \"extension_to_mime\" service\n");
		return -12;
	}
	system_services_broadcast_event = service_query("broadcast_event", "system");
	if (NULL == system_services_broadcast_event) {
		printf("[system_services]: fail to get \"broadcast_event\" service\n");
		return -13;
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
	service_release("get_user_lang", "system");
	service_release("get_timezone", "system");
	service_release("get_username_from_id", "system");
	service_release("get_id_from_username", "system");
	service_release("get_user_ids", "system");
	service_release("lang_to_charset", "system");
	service_release("cpid_to_charset", "system");
	service_release("charset_to_cpid", "system");
	service_release("lcid_to_ltag", "system");
	service_release("ltag_to_lcid", "system");
	service_release("mime_to_extension", "system");
	service_release("extension_to_mime", "system");
	service_release("broadcast_event", "system");
	return 0;
}

/*
 *	module's destruct function
 */
void system_services_free()
{
	/* do nothing */

}
