#ifndef _H_RULE_ACTIONS_
#define _H_RULE_ACTIONS_
#include "mapi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

RULE_ACTIONS* rule_actions_dup(const RULE_ACTIONS *prule);

void rule_actions_free(RULE_ACTIONS *prule);

uint32_t rule_actions_size(const RULE_ACTIONS *r);

#ifdef __cplusplus
}
#endif

#endif /* _H_RULE_ACTIONS_ */
