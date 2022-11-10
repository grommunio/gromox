// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdio>
#include <gromox/defs.h>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#include "system_services.hpp"

using namespace gromox;
bool (*system_services_get_user_lang)(const char *, char *, size_t);
bool (*system_services_get_timezone)(const char *, char *, size_t);
decltype(system_services_get_username_from_id) system_services_get_username_from_id;
BOOL (*system_services_get_id_from_username)(const char*, int*);
decltype(system_services_get_id_from_maildir) system_services_get_id_from_maildir;
BOOL (*system_services_get_user_ids)(const char *, int *, int *, enum display_type *);
void (*system_services_broadcast_event)(const char*);

int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "system_services: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_get_user_lang, "get_user_lang");
	E(system_services_get_timezone, "get_timezone");
	E(system_services_get_username_from_id, "get_username_from_id");
	E(system_services_get_id_from_username, "get_id_from_username");
	E(system_services_get_id_from_maildir, "get_id_from_maildir");
	E(system_services_get_user_ids, "get_user_ids");
	E(system_services_broadcast_event, "broadcast_event");
	return 0;
#undef E
}

void system_services_stop()
{
	service_release("get_user_lang", "system");
	service_release("get_timezone", "system");
	service_release("get_username_from_id", "system");
	service_release("get_id_from_username", "system");
	service_release("get_id_from_maildir", "system");
	service_release("get_user_ids", "system");
	service_release("broadcast_event", "system");
}
