#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>
#include "../mysql_adaptor/mysql_adaptor.h"

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
extern BOOL (*system_services_lang_to_charset)(const char*, char*);
extern uint32_t (*system_services_charset_to_cpid)(const char*);
extern const char* (*system_services_lcid_to_ltag)(uint32_t);
extern uint32_t (*system_services_ltag_to_lcid)(const char*);
extern const char* (*system_services_mime_to_extension)(const char*);
extern const char* (*system_services_extension_to_mime)(const char*);
extern void (*system_services_broadcast_event)(const char*);
