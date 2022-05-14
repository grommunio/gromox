#pragma once
#include <cstdint>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/msg_unit.hpp>
#include "../../exch/authmgr.hpp"

extern int system_services_run();
extern void system_services_stop();

extern BOOL (*system_services_judge_ip)(const char*);
extern BOOL (*system_services_container_add_ip)(const char*);
extern BOOL (*system_services_container_remove_ip)(const char*);
extern BOOL (*system_services_judge_user)(const char*);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern int (*system_services_list_mail)(const char *, const char *, std::vector<gromox::MSG_UNIT> &, int *pnum, uint64_t *psize);
extern int (*system_services_delete_mail)(const char *, const char *, const std::vector<gromox::MSG_UNIT *> &);
extern void (*system_services_broadcast_event)(const char*);
extern void (*system_services_log_info)(unsigned int, const char *, ...);
