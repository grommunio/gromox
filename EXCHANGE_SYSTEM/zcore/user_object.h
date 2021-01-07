#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "mail_func.h"
#include "mapi_types.h"

struct USER_OBJECT {
	int base_id;
	uint32_t minid;
};

#ifdef __cplusplus
extern "C" {
#endif

USER_OBJECT* user_object_create(int base_id, uint32_t minid);

void user_object_free(USER_OBJECT *puser);

BOOL user_object_check_valid(USER_OBJECT *puser);

BOOL user_object_get_properties(USER_OBJECT *puser,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

#ifdef __cplusplus
} /* extern "C" */
#endif
