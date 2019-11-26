#ifndef _H_SYSTEM_SERVICES_
#define _H_SYSTEM_SERVICES_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "common_types.h"
#include "array.h"
#include "single_list.h"

extern void system_services_init(void);
extern int system_services_run(void);
extern int system_services_stop(void);
extern void system_services_free(void);

extern BOOL (*system_services_judge_ip)(const char*);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern int (*system_services_add_user_into_temp_list)(const char*, int);
extern BOOL (*system_services_auth_login)(const char*, const char*, char*, char*, char*, int);
extern int (*system_services_list_mail)(char*, char*, ARRAY*, int *pnum, uint64_t *psize);
extern int (*system_services_delete_mail)(char*, char*, SINGLE_LIST*);
extern int (*system_services_list_cdn_mail)(char*, ARRAY*);
extern int (*system_services_delete_cdn_mail)(char*, SINGLE_LIST*);
extern BOOL (*system_services_auth_cdn_user)(const char*, const char*);
extern int (*system_services_check_cdn_user)(const char*);
extern int (*system_services_create_cdn_user)(const char*);
extern void (*system_services_broadcast_event)(const char*);
extern void (*system_services_log_info)(int, char*, ...);

#endif /* _H_SYSTEM_SERVICES_ */
