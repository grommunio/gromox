#include "system_services.h"
#include "service.h"
#include <stdio.h>

void (*system_services_log_info)(int, char*, ...);
BOOL (*system_services_check_domain)(const char*);

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
	system_services_log_info = service_query("log_info", "system");
	if (NULL == system_services_log_info) {
		printf("[system_services]: fail to get \"log_info\" service\n");
		return -1;
	}
	system_services_check_domain = service_query("check_domain", "system");
	if (NULL == system_services_check_domain) {
		printf("[system_services]: fail to get \"check_domain\" service\n");
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

/*
 *	module's destruct function
 */
void system_services_free()
{
	/* do nothing */

}


