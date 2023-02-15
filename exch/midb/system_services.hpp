#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>

extern int system_services_run();
extern void system_services_stop();

#define E(s) extern decltype(mysql_adaptor_ ## s) *system_services_ ## s;
E(get_id_from_username)
E(get_timezone)
E(get_user_ids)
E(get_user_lang)
E(get_username_from_id)
E(get_id_from_maildir)
#undef E
extern void (*system_services_broadcast_event)(const char*);
