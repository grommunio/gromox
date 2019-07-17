#ifndef _H_SORTORDER_SET_
#define _H_SORTORDER_SET_
#include "mapi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void sortorder_set_free(SORTORDER_SET *pset);

SORTORDER_SET* sortorder_set_dup(const SORTORDER_SET *pset);

#ifdef __cplusplus
}
#endif

#endif /* _H_SORTORDER_SET_ */
