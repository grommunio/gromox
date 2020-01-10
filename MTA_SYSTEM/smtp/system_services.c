#include "system_services.h"
#include "service.h"
#include <stdio.h>

BOOL (*system_services_judge_ip)(const char*);
BOOL (*system_services_judge_user)(const char*);
BOOL (*system_services_container_add_ip)(const char*);
BOOL (*system_services_container_remove_ip)(const char*);
int (*system_services_add_ip_into_temp_list)(const char*, int);
int (*system_services_add_user_into_temp_list)(const char*, int);
BOOL (*system_services_check_relay)(const char*);
BOOL (*system_services_check_domain)(const char*);
BOOL (*system_services_check_user)(const char*, char*);
BOOL (*system_services_check_full)(const char*);
void (*system_services_log_info)(int, const char *, ...);
const char* (*system_services_auth_ehlo)();
int (*system_services_auth_process)(int,const char*, int, char*, int);
BOOL (*system_services_auth_retrieve)(int, char*, int);
void (*system_services_auth_clear)(int);
void (*system_services_etrn_process)(const char*, int, char*, int);
void (*system_services_vrfy_process)(const char*, int, char*, int);

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
	system_services_add_ip_into_temp_list = service_query("ip_filter_add", 
												"system");
	if (NULL == system_services_add_ip_into_temp_list) {
		printf("[system_services]: failed to get service \"ip_filter_add\"\n");
		return -2;
	}
	system_services_container_add_ip = service_query("ip_container_add",
												"system");
	if (NULL == system_services_container_add_ip) {
		printf("[system_services]: failed to get service \"ip_container_add\"\n");
		return -3;
	}
	system_services_container_remove_ip = service_query("ip_container_remove",
												"system");
	if (NULL == system_services_container_remove_ip) {
		printf("[system_services]: failed to get service \"ip_container_remove\"\n");
		return -4;
	}
	system_services_check_relay = service_query("check_relay", "system");
	if (NULL == system_services_check_relay) {
		printf("[system_services]: failed to get service \"check_relay\"\n");
		return -5;
	}
	system_services_log_info = service_query("log_info", "system");
	if (NULL == system_services_log_info) {
		printf("[system_services]: failed to get service \"log_info\"\n");
		return -6;
	}
	system_services_judge_user = service_query("user_filter_judge", "system");
	if (NULL == system_services_judge_user) {
		printf("[system_services]: failed to get service \"user_filter_judge\"\n");
		return -7;
	}
	system_services_add_user_into_temp_list = service_query("user_filter_add", 
												"system");
	if (NULL == system_services_add_user_into_temp_list) {
		printf("[system_services]: failed to get service \"user_filter_add\"\n");
		return -8;
	}
	system_services_auth_ehlo = service_query("auth_ehlo","system");
	if (NULL != system_services_auth_ehlo) {
		system_services_auth_process = service_query("auth_process","system");
		if (NULL == system_services_auth_process) {
			printf("[system_services]: failed to get service \"auth_process\"\n");
			return -9;
		}
		system_services_auth_retrieve = service_query("auth_retrieve","system");
		if (NULL == system_services_auth_retrieve) {
			printf("[system_services]: failed to get service \"auth_retrieve\"\n");
			return -9;
		}
		system_services_auth_clear = service_query("auth_clear","system");
		if (NULL == system_services_auth_clear) {
			printf("[system_services]: failed to get service \"auth_clear\"\n");
			return -9;
		}
	}
	system_services_check_domain = service_query("check_domain", "system");
	if (NULL == system_services_check_domain) {
		printf("[system_services]: failed to get service \"check_domain\"\n");
		return -10;
	}
	system_services_check_user = service_query("check_user", "system");
	system_services_check_full = service_query("check_full", "system");
	system_services_etrn_process = service_query("etrn_process", "system");
	system_services_vrfy_process = service_query("vrfy_process", "system");
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
	service_release("check_relay", "system");
	service_release("check_domain", "system");
	if (NULL != system_services_check_user) {
		service_release("check_user", "system");
	}
	if (NULL != system_services_etrn_process) {
		service_release("etrn_process", "system");
	}
	if (NULL != system_services_vrfy_process) {
		service_release("vrfy_process", "system");
	}
	service_release("log_info", "system");
	if (NULL != system_services_auth_ehlo) {
		service_release("auth_ehlo", "system");
		service_release("auth_process", "system");
		service_release("auth_retrieve", "system");
		service_release("auth_clear", "system");
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


