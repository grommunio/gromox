#ifndef _H_USER_OBJECT_
#define _H_USER_OBJECT_
#include <stdint.h>
#include "mail_func.h"
#include "mapi_types.h"

typedef struct _USER_OBJECT {
	int base_id;
	uint32_t minid;
} USER_OBJECT;

USER_OBJECT* user_object_create(int base_id, uint32_t minid);

void user_object_free(USER_OBJECT *puser);

BOOL user_object_check_valid(USER_OBJECT *puser);

BOOL user_object_get_properties(USER_OBJECT *puser,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

#endif /* _H_USER_OBJECT_ */
