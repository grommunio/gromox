#include "rules_object.h"
#include <stdlib.h>

RULES_OBJECT* rules_object_create(
	STORE_OBJECT *pstore, uint64_t folder_id)
{
	RULES_OBJECT *prules;
	
	prules = malloc(sizeof(RULES_OBJECT));
	if (NULL == prules) {
		return NULL;
	}
	prules->pstore = pstore;
	prules->folder_id = folder_id;
	return prules;
}

STORE_OBJECT* rules_object_get_store(RULES_OBJECT *prules)
{
	return prules->pstore;
}

uint64_t rules_object_get_folder_id(RULES_OBJECT *prules)
{
	return prules->folder_id;
}

void rules_object_free(RULES_OBJECT *prules)
{
	free(prules);
}

BOOL rules_object_update(RULES_OBJECT *prules,
	uint32_t flags, const RULE_LIST *plist)
{
	int i;
	BOOL b_exceed;
	
	if (flags & MODIFY_RULES_FLAG_REPLACE) {
		if (FALSE == exmdb_client_empty_folder_rule(
			store_object_get_dir(prules->pstore),
			prules->folder_id)) {
			return FALSE;	
		}
	}
	for (i=0; i<plist->count; i++) {
		if (FALSE == common_util_convert_from_zrule(
			&plist->prule[i].propvals)) {
			return FALSE;	
		}
	}
	return exmdb_client_update_folder_rule(
		store_object_get_dir(prules->pstore),
		prules->folder_id, plist->count,
		plist->prule, &b_exceed);
}