#pragma once
#include <gromox/mapi_types.hpp>

#ifdef __cplusplus
extern "C" {
#endif

RULE_ACTIONS* rule_actions_dup(const RULE_ACTIONS *prule);

void rule_actions_free(RULE_ACTIONS *prule);

uint32_t rule_actions_size(const RULE_ACTIONS *r);

#ifdef __cplusplus
}
#endif
