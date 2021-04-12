#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

RULE_ACTIONS* rule_actions_dup(const RULE_ACTIONS *prule);
void rule_actions_free(RULE_ACTIONS *prule);
uint32_t rule_actions_size(const RULE_ACTIONS *r);
