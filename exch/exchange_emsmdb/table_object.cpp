// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/restriction.hpp>
#include <gromox/proc_common.h>
#include "exmdb_client.h"
#include "table_object.h"
#include <gromox/sortorder_set.hpp>
#include "folder_object.h"
#include <gromox/proptag_array.hpp>
#include "rop_processor.h"
#include "message_object.h"
#include "processor_types.h"
#include "emsmdb_interface.h"
#include <cstdlib>
#include <cstring>
#include "common_util.h"

namespace {

struct BOOKMARK_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t index;
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	uint32_t position;
};

}

static void table_object_set_table_id(
	TABLE_OBJECT *ptable, uint32_t table_id)
{
	auto dir = ptable->plogon->get_dir();
	if (0 != ptable->table_id) {
		exmdb_client_unload_table(dir, ptable->table_id);
		if (ptable->rop_id == ropGetContentsTable ||
		    ptable->rop_id == ropGetHierarchyTable)
			emsmdb_interface_remove_table_notify(
							dir, ptable->table_id);
	}
	if (0 != table_id) {
		if (ptable->rop_id == ropGetContentsTable ||
		    ptable->rop_id == ropGetHierarchyTable)
			emsmdb_interface_add_table_notify(
				dir, table_id, ptable->handle,
				ptable->logon_id, &ptable->cxh.guid);
	}
	ptable->table_id = table_id;
}

BOOL table_object_check_loaded(TABLE_OBJECT *ptable)
{
	if (ptable->rop_id == ropGetAttachmentTable)
		return TRUE;
	return ptable->table_id == 0 ? false : TRUE;
}

BOOL table_object_check_to_load(TABLE_OBJECT *ptable)
{
	uint32_t row_num;
	uint32_t table_id;
	uint32_t permission;
	
	if (ptable->rop_id == ropGetAttachmentTable)
		return TRUE;
	if (0 != ptable->table_id) {
		return TRUE;
	}
	switch (ptable->rop_id) {
	case ropGetHierarchyTable: {
		auto rpc_info = get_rpc_info();
		auto username = ptable->plogon->logon_mode == LOGON_MODE_OWNER ?
		                nullptr : rpc_info.username;
		if (!exmdb_client_load_hierarchy_table(ptable->plogon->get_dir(),
		    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
		    username, ptable->table_flags, ptable->prestriction,
		    &table_id, &row_num))
			return FALSE;
		break;
	}
	case ropGetContentsTable: {
		auto rpc_info = get_rpc_info();
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (NULL == pinfo) {
			return FALSE;
		}
		const char *username = nullptr;
		if (ptable->plogon != LOGON_MODE_OWNER) {
			if (!ptable->plogon->check_private()) {
				username = rpc_info.username;
			} else {
				if (!exmdb_client_check_folder_permission(
				    ptable->plogon->get_dir(),
				    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
				    rpc_info.username, &permission))
					return FALSE;	
				if (0 == (permission & PERMISSION_READANY) &&
					0 == (permission & PERMISSION_FOLDEROWNER)) {
					username = rpc_info.username;
				}
			}
		}
		if (!exmdb_client_load_content_table(ptable->plogon->get_dir(),
		    pinfo->cpid, folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
		    username, ptable->table_flags, ptable->prestriction,
		    ptable->psorts, &table_id, &row_num))
			return FALSE;
		break;
	}
	case ropGetPermissionsTable:
		if (!exmdb_client_load_permission_table(ptable->plogon->get_dir(),
		    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
		    ptable->table_flags, &table_id, &row_num))
			return FALSE;
		break;
	case ropGetRulesTable:
		if (!exmdb_client_load_rule_table(ptable->plogon->get_dir(),
		    folder_object_get_id(static_cast<FOLDER_OBJECT *>(ptable->pparent_obj)),
		    ptable->table_flags, ptable->prestriction, &table_id, &row_num))
			return FALSE;
		break;
	default:
		fprintf(stderr, "%s - not calling table_object_set_table_id\n", __func__);
		return TRUE;
	}
	table_object_set_table_id(ptable, table_id);
	return TRUE;
}

void table_object_unload(TABLE_OBJECT *ptable)
{
	table_object_set_table_id(ptable, 0);
}

BOOL table_object_query_rows(TABLE_OBJECT *ptable,
	BOOL b_forward, uint16_t row_count, TARRAY_SET *pset)
{
	DCERPC_INFO rpc_info;
	const char *username;
	
	if (NULL == ptable->pcolumns) {
		return FALSE;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return FALSE;
	}
	if (0 == ptable->position && FALSE == b_forward) {
		pset->count = 0;
		return TRUE;
	}
	if (ptable->position >= table_object_get_total(ptable) &&
		TRUE == b_forward) {
		pset->count = 0;
		return TRUE;
	}
	int32_t row_needed = b_forward ? row_count : -row_count; /* XXX */
	if (ptable->rop_id == ropGetAttachmentTable) {
		return message_object_query_attachment_table(
		       static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj),
		       ptable->pcolumns, ptable->position, row_needed, pset);
	}
	if (!ptable->plogon->check_private()) {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	} else {
		username = NULL;
	}
	return exmdb_client_query_table(ptable->plogon->get_dir(), username,
	       pinfo->cpid, ptable->table_id, ptable->pcolumns,
	       ptable->position, row_needed, pset);
}

void table_object_seek_current(TABLE_OBJECT *ptable,
	BOOL b_forward, uint16_t row_count)
{
	uint32_t total_rows;
	
	if (TRUE == b_forward) {
		ptable->position += row_count;
		total_rows = table_object_get_total(ptable);
		if (ptable->position > total_rows) {
			ptable->position = total_rows;
		}
	} else {
		if (ptable->position < row_count) {
			ptable->position = 0;
			return;
		}
		ptable->position -= row_count;
	}
}

uint8_t table_object_get_rop_id(TABLE_OBJECT *ptable)
{
	return ptable->rop_id;
}

uint32_t table_object_get_table_id(TABLE_OBJECT *ptable)
{
	return ptable->table_id;
}

void table_object_set_handle(TABLE_OBJECT *ptable, uint32_t handle)
{
	ptable->handle = handle;
}

const PROPTAG_ARRAY* table_object_get_columns(TABLE_OBJECT *ptable)
{
	return ptable->pcolumns;
}

BOOL table_object_set_columns(TABLE_OBJECT *ptable,
	const PROPTAG_ARRAY *pcolumns)
{
	if (NULL != ptable->pcolumns) {
		proptag_array_free(ptable->pcolumns);
	}
	if (NULL == pcolumns) {
		ptable->pcolumns = NULL;
		return TRUE;
	}
	ptable->pcolumns = proptag_array_dup(pcolumns);
	if (NULL == ptable->pcolumns) {
		return FALSE;
	}
	return TRUE;
}

const SORTORDER_SET* table_object_get_sorts(TABLE_OBJECT *ptable)
{
	return ptable->psorts;
}

BOOL table_object_set_sorts(TABLE_OBJECT *ptable,
	const SORTORDER_SET *psorts)
{
	if (NULL != ptable->psorts) {
		sortorder_set_free(ptable->psorts);
	}
	if (NULL == psorts) {
		ptable->psorts = NULL;
		return TRUE;
	}
	ptable->psorts = sortorder_set_dup(psorts);
	if (NULL == ptable->psorts) {
		return FALSE;
	}
	return TRUE;
}

BOOL table_object_set_restriction(TABLE_OBJECT *ptable,
	const RESTRICTION *prestriction)
{
	if (NULL != ptable->prestriction) {
		restriction_free(ptable->prestriction);
	}
	if (NULL == prestriction) {
		ptable->prestriction = NULL;
		return TRUE;
	}
	ptable->prestriction = restriction_dup(prestriction);
	if (NULL == ptable->prestriction) {
		return FALSE;
	}
	return TRUE;
}

uint32_t table_object_get_position(TABLE_OBJECT *ptable)
{
	return ptable->position;
}

void table_object_set_position(TABLE_OBJECT *ptable, uint32_t position)
{
	uint32_t total_rows;
	
	total_rows = table_object_get_total(ptable);
	if (position > total_rows) {
		position = total_rows;
	}
	ptable->position = position;
}

void table_object_clear_position(TABLE_OBJECT *ptable)
{
	ptable->position = 0;
}

uint32_t table_object_get_total(TABLE_OBJECT *ptable)
{
	uint16_t num;
	uint32_t total_rows;
	
	if (ptable->rop_id == ropGetAttachmentTable) {
		num = 0;
		message_object_get_attachments_num(static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), &num);
		return num;
	}
	exmdb_client_sum_table(ptable->plogon->get_dir(),
		ptable->table_id, &total_rows);
	return total_rows;
}

std::unique_ptr<TABLE_OBJECT> table_object_create(LOGON_OBJECT *plogon,
	void *pparent_obj, uint8_t table_flags,
	uint8_t rop_id, uint8_t logon_id)
{
	std::unique_ptr<TABLE_OBJECT> ptable;
	try {
		ptable = std::make_unique<TABLE_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	if (FALSE == emsmdb_interface_get_cxh(&ptable->cxh)) {
		return NULL;
	}
	ptable->plogon = plogon;
	ptable->pparent_obj = pparent_obj;
	ptable->handle = 0;
	ptable->rop_id = rop_id;
	ptable->table_flags = table_flags;
	ptable->logon_id = logon_id;
	ptable->pcolumns = NULL;
	ptable->psorts = NULL;
	ptable->prestriction = NULL;
	ptable->position = 0;
	ptable->table_id = 0;
	ptable->bookmark_index = 0;
	double_list_init(&ptable->bookmark_list);
	return ptable;
}

TABLE_OBJECT::~TABLE_OBJECT()
{
	auto ptable = this;
	table_object_reset(ptable);
	double_list_free(&ptable->bookmark_list);
}

BOOL table_object_create_bookmark(TABLE_OBJECT *ptable, uint32_t *pindex)
{
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	
	if (!exmdb_client_mark_table(ptable->plogon->get_dir(), ptable->table_id,
	    ptable->position, &inst_id, &inst_num, &row_type))
		return FALSE;
	auto pbookmark = me_alloc<BOOKMARK_NODE>();
	if (NULL == pbookmark) {
		return FALSE;
	}
	pbookmark->node.pdata = pbookmark;
	pbookmark->index = ptable->bookmark_index;
	ptable->bookmark_index ++;
	pbookmark->inst_id = inst_id;
	pbookmark->row_type = row_type;
	pbookmark->inst_num = inst_num;
	pbookmark->position = ptable->position;
	double_list_append_as_tail(&ptable->bookmark_list, &pbookmark->node);
	*pindex = pbookmark->index;
	return TRUE;
}

BOOL table_object_retrieve_bookmark(TABLE_OBJECT *ptable,
	uint32_t index, BOOL *pb_exist)
{
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	uint32_t position;
	uint32_t tmp_type;
	uint32_t total_rows;
	int32_t tmp_position;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&ptable->bookmark_list); NULL!=pnode;
		pnode=double_list_get_after(&ptable->bookmark_list, pnode)) {
		if (index == ((BOOKMARK_NODE*)pnode->pdata)->index) {
			inst_id = ((BOOKMARK_NODE*)pnode->pdata)->inst_id;
			row_type = ((BOOKMARK_NODE*)pnode->pdata)->row_type;
			inst_num = ((BOOKMARK_NODE*)pnode->pdata)->inst_num;
			position = ((BOOKMARK_NODE*)pnode->pdata)->position;
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	if (!exmdb_client_locate_table(ptable->plogon->get_dir(),
	    ptable->table_id, inst_id, inst_num, &tmp_position, &tmp_type))
		return FALSE;
	*pb_exist = FALSE;
	if (tmp_position >= 0) {
		if (tmp_type == row_type) {
			*pb_exist = TRUE;
		}
		ptable->position = tmp_position;
	} else {
		ptable->position = position;
	}
	total_rows = table_object_get_total(ptable);
	if (ptable->position > total_rows) {
		ptable->position = total_rows;
	}
	return TRUE;
}

void table_object_remove_bookmark(TABLE_OBJECT *ptable, uint32_t index)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&ptable->bookmark_list); NULL!=pnode;
		pnode=double_list_get_after(&ptable->bookmark_list, pnode)) {
		if (index == ((BOOKMARK_NODE*)pnode->pdata)->index) {
			double_list_remove(&ptable->bookmark_list, pnode);
			free(pnode->pdata);
			break;
		}
	}
}

void table_object_clear_bookmarks(TABLE_OBJECT *ptable)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&ptable->bookmark_list)) != nullptr)
		free(pnode->pdata);
}

void table_object_reset(TABLE_OBJECT *ptable)
{
	if (NULL != ptable->pcolumns) {
		proptag_array_free(ptable->pcolumns);
		ptable->pcolumns = NULL;
	}
	if (NULL != ptable->psorts) {
		sortorder_set_free(ptable->psorts);
		ptable->psorts = NULL;
	}
	if (NULL != ptable->prestriction) {
		restriction_free(ptable->prestriction);
		ptable->prestriction = NULL;
	}
	ptable->position = 0;
	table_object_set_table_id(ptable, 0);
	table_object_clear_bookmarks(ptable);
}

BOOL table_object_get_all_columns(TABLE_OBJECT *ptable,
	PROPTAG_ARRAY *pcolumns)
{
	if (ptable->rop_id == ropGetAttachmentTable)
		return message_object_get_attachment_table_all_proptags(
		       static_cast<MESSAGE_OBJECT *>(ptable->pparent_obj), pcolumns);
	return exmdb_client_get_table_all_proptags(ptable->plogon->get_dir(),
	       ptable->table_id, pcolumns);
}

BOOL table_object_match_row(TABLE_OBJECT *ptable,
	BOOL b_forward, const RESTRICTION *pres,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals)
{
	DCERPC_INFO rpc_info;
	const char *username;
	
	if (NULL == ptable->pcolumns) {
		return FALSE;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!ptable->plogon->check_private()) {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	} else {
		username = NULL;
	}
	return exmdb_client_match_table(ptable->plogon->get_dir(), username,
	       pinfo->cpid, ptable->table_id, b_forward, ptable->position,
	       pres, ptable->pcolumns, pposition, ppropvals);
}

BOOL table_object_read_row(TABLE_OBJECT *ptable,
	uint64_t inst_id, uint32_t inst_num,
	TPROPVAL_ARRAY *ppropvals)
{
	DCERPC_INFO rpc_info;
	const char *username;
	
	if (NULL == ptable->pcolumns) {
		return FALSE;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!ptable->plogon->check_private()) {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	} else {
		username = NULL;
	}
	return exmdb_client_read_table_row(ptable->plogon->get_dir(), username,
	       pinfo->cpid, ptable->table_id, ptable->pcolumns,
	       inst_id, inst_num, ppropvals);
}

BOOL table_object_expand(TABLE_OBJECT *ptable, uint64_t inst_id,
	BOOL *pb_found, int32_t *pposition, uint32_t *prow_count)
{
	return exmdb_client_expand_table(ptable->plogon->get_dir(),
	       ptable->table_id, inst_id, pb_found, pposition, prow_count);
}

BOOL table_object_collapse(TABLE_OBJECT *ptable, uint64_t inst_id,
	BOOL *pb_found, int32_t *pposition, uint32_t *prow_count)
{
	return exmdb_client_collapse_table(ptable->plogon->get_dir(),
	       ptable->table_id, inst_id, pb_found, pposition, prow_count);
}

BOOL table_object_store_state(TABLE_OBJECT *ptable,
	uint64_t inst_id, uint32_t inst_num, uint32_t *pstate_id)
{
	return exmdb_client_store_table_state(ptable->plogon->get_dir(),
	       ptable->table_id, inst_id, inst_num, pstate_id);
}

BOOL table_object_restore_state(TABLE_OBJECT *ptable,
	uint32_t state_id, uint32_t *pindex)
{
	int32_t position;
	uint64_t inst_id;
	uint32_t inst_num;
	uint32_t tmp_type;
	uint32_t new_position;
	
	if (!exmdb_client_mark_table(ptable->plogon->get_dir(),
	    ptable->table_id, ptable->position, &inst_id, &inst_num, &tmp_type))
		return FALSE;
	if (!exmdb_client_restore_table_state(ptable->plogon->get_dir(),
	    ptable->table_id, state_id, &position))
		return FALSE;	
	if (!exmdb_client_locate_table(ptable->plogon->get_dir(),
	    ptable->table_id, inst_id, inst_num,
	    reinterpret_cast<int32_t *>(&new_position), &tmp_type))
		return FALSE;
	if (position < 0) {
		/* assign an invalid bookmark index */
		*pindex = ptable->bookmark_index;
		ptable->bookmark_index ++;
		return TRUE;
	}
	ptable->position = position;
	if (FALSE == table_object_create_bookmark(ptable, pindex)) {
		ptable->position = new_position;
		return FALSE;
	}
	ptable->position = new_position;
	return TRUE;
}
