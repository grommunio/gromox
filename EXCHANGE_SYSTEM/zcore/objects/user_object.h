#ifndef _H_USER_OBJECT_
#define _H_USER_OBJECT_
#include <stdint.h>
#include "mail_func.h"
#include "mapi_types.h"

typedef struct _USER_OBJECT {
	EMAIL_ADDR *pemail_addr;
	int base_id;
	uint32_t minid;
} USER_OBJECT;

USER_OBJECT* user_object_create(int base_id, uint32_t minid);

BOOL user_object_set_oneoff(USER_OBJECT *puser, const char *oneoff_string);

void user_object_free(USER_OBJECT *puser);

BOOL user_object_get_properties(USER_OBJECT *puser,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

#endif /* _H_USER_OBJECT_ */
