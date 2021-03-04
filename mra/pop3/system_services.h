#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/array.hpp>
#include <gromox/single_list.hpp>

extern int system_services_run();
extern int system_services_stop();

extern BOOL (*system_services_judge_ip)(const char*);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern BOOL (*system_services_auth_login)(const char*, const char*, char*, char*, char*, int);
extern int (*system_services_list_mail)(const char *, const char *, ARRAY *, int *pnum, uint64_t *psize);
extern int (*system_services_delete_mail)(const char *, const char *, SINGLE_LIST *);
extern void (*system_services_broadcast_event)(const char*);
extern void (*system_services_log_info)(int, const char *, ...);
