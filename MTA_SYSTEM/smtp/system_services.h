#ifndef _H_SYSTEM_SERVICES_
#define _H_SYSTEM_SERVICES_

#include "common_types.h"

enum{
    SERVICE_AUTH_ERROR,       /* auth session fail  */
	SERVICE_AUTH_CONTINUE,    /* auth session processed OK, continue */
    SERVICE_AUTH_FINISH       /* auth session processed OK, finished */

};

void system_services_init();

int system_services_run();

int system_services_stop();

void system_services_free();

extern BOOL (*system_services_judge_ip)(const char*);
extern int (*system_services_add_ip_into_temp_list)(const char*, int);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern int (*system_services_add_user_into_temp_list)(const char*, int);
extern BOOL (*system_services_check_relay)(const char*);
extern BOOL (*system_services_check_domain)(const char*);
extern BOOL (*system_services_check_user)(const char*, char*);
extern BOOL (*system_services_check_full)(const char*);
extern void (*system_services_log_info)(int, char*, ...);
extern const char* (*system_services_auth_ehlo)();
extern int (*system_services_auth_process)(int, const char*, int, char*, int);
extern BOOL (*system_services_auth_retrieve)(int, char*, int);
extern void (*system_services_auth_clear)(int);
extern void (*system_services_etrn_process)(const char*, int, char*, int);
extern void (*system_services_vrfy_process)(const char*, int, char*, int);

#endif /* _H_SYSTEM_SERVICES_ */
