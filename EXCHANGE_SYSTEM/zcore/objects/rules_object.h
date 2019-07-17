#ifndef _H_RULES_OBJECT_
#define _H_RULES_OBJECT_
#include "store_object.h"
#include "common_util.h"

#define ROWLIST_REPLACE							1

typedef struct _RULES_OBJECT {
	uint64_t folder_id;
	STORE_OBJECT *pstore;
} RULES_OBJECT;

RULES_OBJECT* rules_object_create(
	STORE_OBJECT *pstore, uint64_t folder_id);

STORE_OBJECT* rules_object_get_store(RULES_OBJECT *prules);

uint64_t rules_object_get_folder_id(RULES_OBJECT *prules);

void rules_object_free(RULES_OBJECT *prules);

BOOL rules_object_update(RULES_OBJECT *prules,
	uint32_t flags, const RULE_LIST *plist);

#endif /* _H_RULES_OBJECT_ */
