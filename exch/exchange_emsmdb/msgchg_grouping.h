#pragma once
#include <cstdint>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>

void msgchg_grouping_init(const char *path);
extern int msgchg_grouping_run();
extern uint32_t msgchg_grouping_get_last_group_id();
extern PROPERTY_GROUPINFO *msgchg_grouping_get_groupinfo(BOOL (*)(void *, BOOL, const PROPERTY_NAME *, uint16_t *), void *, uint32_t group_id);
extern int msgchg_grouping_stop();
extern void msgchg_grouping_free();
