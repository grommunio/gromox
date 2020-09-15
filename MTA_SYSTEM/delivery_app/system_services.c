#include "system_services.h"
#include "service.h"
#include <stdio.h>

void (*system_services_log_info)(int, const char *, ...);
BOOL (*system_services_check_domain)(const char*);

/*
 *	run system services module
 *	@return
 *		0		OK
 *		<>0		fail
 */
int system_services_run()
{
	system_services_log_info = service_query("log_info", "system");
	if (NULL == system_services_log_info) {
		printf("[system_services]: failed to get service \"log_info\"\n");
		return -1;
	}
	system_services_check_domain = service_query("check_domain", "system");
	if (NULL == system_services_check_domain) {
		printf("[system_services]: failed to get service \"check_domain\"\n");
		return -2;
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
	service_release("log_info", "system");
	service_release("check_domain", "system");
	return 0;
}
