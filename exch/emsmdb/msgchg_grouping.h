#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct property_groupinfo;
struct PROPERTY_NAME;

void msgchg_grouping_init(const char *path);
extern int msgchg_grouping_run();
extern uint32_t msgchg_grouping_get_last_group_id();
using get_named_propid_t = BOOL (*)(void *, BOOL, const PROPERTY_NAME *, uint16_t *);
extern std::unique_ptr<property_groupinfo> msgchg_grouping_get_groupinfo(get_named_propid_t, void *, uint32_t group_id);
extern void msgchg_grouping_stop();
extern void msgchg_grouping_free();
