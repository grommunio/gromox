#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

extern GX_EXPORT RULE_ACTIONS *rule_actions_dup(const RULE_ACTIONS *);
extern GX_EXPORT void rule_actions_free(RULE_ACTIONS *);
extern GX_EXPORT uint32_t rule_actions_size(const RULE_ACTIONS *);
