#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct property_groupinfo;
struct PROPERTY_NAME;

extern GX_EXPORT gromox::errno_t msgchg_grouping_run(const char *path);
extern GX_EXPORT uint32_t msgchg_grouping_get_last_map_id();
using get_named_propid_t = BOOL (*)(void *, BOOL, const PROPERTY_NAME *, uint16_t *);
extern GX_EXPORT std::unique_ptr<property_groupinfo> msgchg_grouping_get_groupinfo(get_named_propid_t, void *, uint32_t map_id);
