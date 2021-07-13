#pragma once
#include <cstdint>
#include <memory>
#include "store_object.h"
#include <gromox/mapi_types.hpp>

enum zcore_table_type {
	STORE_TABLE = 1,
	HIERARCHY_TABLE = 2,
	CONTENT_TABLE = 3,
	RULE_TABLE = 4,
	ATTACHMENT_TABLE = 5,
	RECIPIENT_TABLE = 6,
	CONTAINER_TABLE = 7,
	USER_TABLE = 8,
};

struct TABLE_OBJECT {
	~TABLE_OBJECT();

	STORE_OBJECT *pstore = nullptr;
	uint32_t handle = 0;
	void *pparent_obj = nullptr;
	enum zcore_table_type table_type{};
	uint32_t table_flags = 0;
	PROPTAG_ARRAY *pcolumns = nullptr;
	SORTORDER_SET *psorts = nullptr;
	RESTRICTION *prestriction = nullptr;
	uint32_t position = 0, table_id = 0, bookmark_index = 0;
	DOUBLE_LIST bookmark_list{};
};

extern std::unique_ptr<TABLE_OBJECT> table_object_create(STORE_OBJECT *, void *parent, uint8_t table_type, uint32_t table_flags);
const PROPTAG_ARRAY* table_object_get_columns(TABLE_OBJECT *ptable);
BOOL table_object_set_columns(TABLE_OBJECT *ptable,
	const PROPTAG_ARRAY *pcolumns);
BOOL table_object_set_sorts(TABLE_OBJECT *ptable,
	const SORTORDER_SET *psorts);
BOOL table_object_check_to_load(TABLE_OBJECT *ptable);
void table_object_unload(TABLE_OBJECT *ptable);
extern BOOL table_object_query_rows(TABLE_OBJECT *, const PROPTAG_ARRAY *cols, uint32_t row_count, TARRAY_SET *);
BOOL table_object_set_restriction(TABLE_OBJECT *ptable,
	const RESTRICTION *prestriction);
void table_object_seek_current(TABLE_OBJECT *ptable,
	BOOL b_forward, uint32_t row_count);
uint8_t table_object_get_table_type(TABLE_OBJECT *ptable);
uint32_t table_object_get_position(TABLE_OBJECT *ptable);
void table_object_set_position(TABLE_OBJECT *ptable, uint32_t position);
void table_object_clear_position(TABLE_OBJECT *ptable);
uint32_t table_object_get_total(TABLE_OBJECT *ptable);
BOOL table_object_create_bookmark(TABLE_OBJECT *ptable, uint32_t *pindex);
void table_object_remove_bookmark(TABLE_OBJECT *ptable, uint32_t index);
void table_object_clear_bookmarks(TABLE_OBJECT *ptable);
BOOL table_object_retrieve_bookmark(TABLE_OBJECT *ptable,
	uint32_t index, BOOL *pb_exist);
BOOL table_object_filter_rows(TABLE_OBJECT *ptable,
	uint32_t count, const RESTRICTION *pres,
	const PROPTAG_ARRAY *pcolumns, TARRAY_SET *pset);
BOOL table_object_match_row(TABLE_OBJECT *ptable,
	BOOL b_forward, const RESTRICTION *pres,
	int32_t *pposition);
