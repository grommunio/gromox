#ifndef _H_CONTAINER_OBJECT_
#define _H_CONTAINER_OBJECT_
#include <stdint.h>
#include "mapi_types.h"

#define SPECIAL_CONTAINER_GAL					0
#define SPECIAL_CONTAINER_PROVIDER				1

#define CONTAINER_TYPE_FOLDER					1
#define CONTAINER_TYPE_ABTREE					2

typedef union _CONTAINER_ID {
	struct {
		BOOL b_private;
		uint64_t folder_id;
	} exmdb_id;
	struct {
		int base_id;
		uint32_t minid;
	} abtree_id;
} CONTAINER_ID;

typedef struct _CONTAINER_OBJECT {
	uint8_t type;
	CONTAINER_ID id;
	union {
		TARRAY_SET *prow_set;
		LONG_ARRAY *pminid_array;
	} contents;
} CONTAINER_OBJECT;

BOOL container_object_fetch_special_property(
	uint8_t special_type, uint32_t proptag, void **ppvalue);

CONTAINER_OBJECT* container_object_create(
	uint8_t type, CONTAINER_ID id);

void container_object_free(CONTAINER_OBJECT *pcontainer);

void container_object_clear(CONTAINER_OBJECT *pcontainer);

BOOL container_object_get_properties(CONTAINER_OBJECT *pcontainer,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);
	
BOOL container_object_load_user_table(
	CONTAINER_OBJECT *pcontainer,
	const RESTRICTION *prestriction);

BOOL container_object_get_container_table_num(
	CONTAINER_OBJECT *pcontainer, BOOL b_depth,
	uint32_t *pnum);

void container_object_get_container_table_all_proptags(
	PROPTAG_ARRAY *pproptags);

BOOL container_object_query_container_table(
	CONTAINER_OBJECT *pcontainer, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, uint32_t start_pos, int32_t row_needed,
	TARRAY_SET *pset);

BOOL container_object_get_user_table_num(
	CONTAINER_OBJECT *pcontainer, uint32_t *pnum);

void container_object_get_user_table_all_proptags(
	PROPTAG_ARRAY *pproptags);

BOOL container_object_query_user_table(
	CONTAINER_OBJECT *pcontainer, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset);

#endif /* _H_CONTAINER_OBJECT_ */
