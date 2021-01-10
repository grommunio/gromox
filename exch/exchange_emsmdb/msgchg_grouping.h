#pragma once
#include <cstdint>
#include <gromox/element_data.hpp>
#include "logon_object.h"
#include <gromox/mapi_types.hpp>

void msgchg_grouping_init(const char *path);
extern int msgchg_grouping_run(void);
extern uint32_t msgchg_grouping_get_last_group_id(void);
PROPERTY_GROUPINFO* msgchg_grouping_get_groupinfo(
	LOGON_OBJECT *plogon, uint32_t group_id);
extern int msgchg_grouping_stop(void);
extern void msgchg_grouping_free(void);
