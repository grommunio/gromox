#ifndef _H_RESTRICTION_
#define _H_RESTRICTION_
#include "mapi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void restriction_free(RESTRICTION *prestriction);

RESTRICTION* restriction_dup(const RESTRICTION *prestriction);

uint32_t restriction_size(const RESTRICTION *r);

#ifdef __cplusplus
}
#endif

#endif /* _H_RESTRICTION_ */
