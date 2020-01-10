#include "system_services.h"
#include "service.h"
#include <stdio.h>

BOOL (*system_services_judge_ip)(const char*);
BOOL (*system_services_judge_user)(const char*);
BOOL (*system_services_container_add_ip)(const char*);
BOOL (*system_services_container_remove_ip)(const char*);
int (*system_services_add_user_into_temp_list)(const char*, int);
BOOL (*system_services_auth_login)(const char*, const char*, char*, char*, char*, int);
const char* (*system_services_extension_to_mime)(const char*);
void (*system_services_log_info)(int, const char *, ...);

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
		printf("[system_services]: failed to get service \"ip_filter_judge\"\n");
		return -1;
	}
	system_services_container_add_ip = service_query("ip_container_add",
												"system");
	if (NULL == system_services_container_add_ip) {
		printf("[system_services]: failed to get service \"ip_container_add\"\n");
		return -2;
	}
	system_services_container_remove_ip = service_query("ip_container_remove",
												"system");
	if (NULL == system_services_container_remove_ip) {
		printf("[system_services]: failed to get service \"ip_container_remove\"\n");
		return -3;
	}
	system_services_log_info = service_query("log_info", "system");
	if (NULL == system_services_log_info) {
		printf("[system_services]: failed to get service \"log_info\"\n");
		return -4;
	}
	system_services_judge_user = service_query("user_filter_judge", "system");
	if (NULL == system_services_judge_user) {
		printf("[system_services]: failed to get service \"user_filter_judge\"\n");
		return -5;
	}
	system_services_add_user_into_temp_list = service_query("user_filter_add", 
												"system");
	if (NULL == system_services_add_user_into_temp_list) {
		printf("[system_services]: failed to get service \"user_filter_add\"\n");
		return -6;
	}
	system_services_auth_login = service_query("auth_login", "system");
	if (NULL == system_services_auth_login) {
		printf("[system_services]: failed to get service \"auth_login\"\n");
		return -7;
	}
	system_services_extension_to_mime = service_query("extension_to_mime", "system");
	if (NULL == system_services_extension_to_mime) {
		printf("[system_services]: failed to get service \"extension_to_mime\"\n");
		return -8;
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
	service_release("ip_container_add", "system");
	service_release("ip_container_remove", "system");
	service_release("log_info", "system");
	service_release("user_filter_judge", "system");
	service_release("user_filer_add", "system");
	service_release("auth_login", "system");
	service_release("extension_to_mime", "system");
	return 0;
}

/*
 *	module's destruct function
 */
void system_services_free()
{
	/* do nothing */

}


