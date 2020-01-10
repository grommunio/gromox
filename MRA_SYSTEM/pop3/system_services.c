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
	system_services_auth_login = service_query("auth_login_pop3", "system");
	if (NULL == system_services_auth_login) {
		printf("[system_services]: failed to get service \"auth_login_pop3\"\n");
		return -7;
	}
	system_services_list_mail = service_query("list_mail", "system");
	if (NULL == system_services_list_mail) {
		printf("[system_services]: failed to get service \"list_mail\"\n");
		return -8;
	}
	system_services_delete_mail = service_query("delete_mail", "system");
	if (NULL == system_services_delete_mail) {
		printf("[system_services]: failed to get service \"delete_mail\"\n");
		return -9;
	}
	system_services_list_cdn_mail = service_query("cdn_uidl", "system");
	system_services_delete_cdn_mail = service_query("cdn_remove", "system");
	system_services_check_cdn_user = service_query("cdn_check", "system");
	system_services_auth_cdn_user = service_query("cdn_auth", "system");
	system_services_create_cdn_user = service_query("cdn_create", "system");
	system_services_broadcast_event = service_query("broadcast_event", "system");
	if (NULL == system_services_broadcast_event) {
		printf("[system_services]: failed to get service \"broadcast_event\"\n");
		return -10;
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

/*
 *	module's destruct function
 */
void system_services_free()
{
	/* do nothing */

}


