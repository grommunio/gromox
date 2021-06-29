#pragma once
#include <cstdint>
#include <memory>
#include "emsmdb_interface.h"
#include "logon_object.h"
#include <gromox/mapi_types.hpp>

struct TABLE_OBJECT {
	~TABLE_OBJECT();
	const PROPTAG_ARRAY *get_columns() const { return pcolumns; }
	BOOL set_columns(const PROPTAG_ARRAY *);
	const SORTORDER_SET *get_sorts() const { return psorts; }
	BOOL set_sorts(const SORTORDER_SET *);
	BOOL check_loaded();
	BOOL check_to_load();
	void unload();
	BOOL query_rows(BOOL forward, uint16_t row_count, TARRAY_SET *);
	BOOL set_restriction(const RESTRICTION *);
	void seek_current(BOOL forward, uint16_t row_count);

	LOGON_OBJECT *plogon = nullptr;
	CXH cxh{};
	void *plogmap = nullptr;
	uint8_t logon_id = 0;
	uint32_t handle = 0;
	void *pparent_obj = nullptr;
	uint8_t rop_id = 0, table_flags = 0;
	PROPTAG_ARRAY *pcolumns = nullptr;
	SORTORDER_SET *psorts = nullptr;
	RESTRICTION *prestriction = nullptr;
	uint32_t position = 0, table_id = 0, bookmark_index = 0;
	DOUBLE_LIST bookmark_list{};
};

extern std::unique_ptr<TABLE_OBJECT> table_object_create(LOGON_OBJECT *, void *parent, uint8_t table_flags, uint8_t rop_id, uint8_t logon_id);
uint8_t table_object_get_rop_id(TABLE_OBJECT *ptable);
uint32_t table_object_get_table_id(TABLE_OBJECT *ptable);
void table_object_set_handle(TABLE_OBJECT *ptable, uint32_t handle);
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
BOOL table_object_get_all_columns(TABLE_OBJECT *ptable,
	PROPTAG_ARRAY *pcolumns);
BOOL table_object_match_row(TABLE_OBJECT *ptable,
	BOOL b_forward, const RESTRICTION *pres,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals);
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
