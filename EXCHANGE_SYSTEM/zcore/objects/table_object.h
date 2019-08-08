#ifndef _H_TABLE_OBJECT_
#define _H_TABLE_OBJECT_
#include "store_object.h"
#include "mapi_types.h"

#define STORE_TABLE									1
#define HIERARCHY_TABLE								2
#define CONTENT_TABLE								3
#define RULE_TABLE									4
#define ATTACHMENT_TABLE							5
#define RECIPIENT_TABLE								6
#define CONTAINER_TABLE								7
#define USER_TABLE									8


typedef struct _TABLE_OBJECT {
	STORE_OBJECT *pstore;
	uint32_t handle;
	void *pparent_obj;
	uint8_t table_type;
	uint32_t table_flags;
	PROPTAG_ARRAY *pcolumns;
	SORTORDER_SET *psorts;
	RESTRICTION *prestriction;
	uint32_t position;
	uint32_t table_id;
	uint32_t bookmark_index;
	DOUBLE_LIST bookmark_list;
} TABLE_OBJECT;


TABLE_OBJECT* table_object_create(STORE_OBJECT *pstore,
	void *pparent_obj, uint8_t table_type, uint32_t table_flags);

void table_object_free(TABLE_OBJECT *ptable);

const PROPTAG_ARRAY* table_object_get_columns(TABLE_OBJECT *ptable);

BOOL table_object_set_columns(TABLE_OBJECT *ptable,
	const PROPTAG_ARRAY *pcolumns);

BOOL table_object_set_sorts(TABLE_OBJECT *ptable,
	const SORTORDER_SET *psorts);

BOOL table_object_check_loaded(TABLE_OBJECT *ptable);

BOOL table_object_check_to_load(TABLE_OBJECT *ptable);

void table_object_unload(TABLE_OBJECT *ptable);

BOOL table_object_query_rows(TABLE_OBJECT *ptable, BOOL b_forward,
	const PROPTAG_ARRAY *pcolumns, uint16_t row_count, TARRAY_SET *pset);

BOOL table_object_set_restriction(TABLE_OBJECT *ptable,
	const RESTRICTION *prestriction);

void table_object_seek_current(TABLE_OBJECT *ptable,
	BOOL b_forward, uint32_t row_count);

uint8_t table_object_get_table_type(TABLE_OBJECT *ptable);

uint32_t table_object_get_table_id(TABLE_OBJECT *ptable);

uint32_t table_object_get_position(TABLE_OBJECT *ptable);

void table_object_set_position(TABLE_OBJECT *ptable, uint32_t position);

void table_object_clear_position(TABLE_OBJECT *ptable);

uint32_t table_object_get_total(TABLE_OBJECT *ptable);

BOOL table_object_create_bookmark(TABLE_OBJECT *ptable, uint32_t *pindex);

void table_object_remove_bookmark(TABLE_OBJECT *ptable, uint32_t index);

void table_object_clear_bookmarks(TABLE_OBJECT *ptable);

BOOL table_object_retrieve_bookmark(TABLE_OBJECT *ptable,
	uint32_t index, BOOL *pb_exist);

void table_object_reset(TABLE_OBJECT *ptable);

BOOL table_object_match_row(TABLE_OBJECT *ptable,
	BOOL b_forward, const RESTRICTION *pres,
	int32_t *pposition);

BOOL table_object_read_row(TABLE_OBJECT *ptable,
	uint64_t inst_id, uint32_t inst_num,
	TPROPVAL_ARRAY *ppropvals);

BOOL table_object_expand(TABLE_OBJECT *ptable, uint64_t inst_id,
	BOOL *pb_found, int32_t *pposition, uint32_t *prow_count);

BOOL table_object_collapse(TABLE_OBJECT *ptable, uint64_t inst_id,
	BOOL *pb_found, int32_t *pposition, uint32_t *prow_count);

BOOL table_object_store_state(TABLE_OBJECT *ptable,
	uint64_t inst_id, uint32_t inst_num, uint32_t *pstate_id);

BOOL table_object_restore_state(TABLE_OBJECT *ptable,
	uint32_t state_id, uint32_t *pindex);

#endif /* _H_TABLE_OBJECT_ */
