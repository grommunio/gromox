// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <gromox/mapidefs.h>
#include <gromox/tarray_set.hpp>
#include "object_tree.h"
#include <gromox/restriction.hpp>
#include "exmdb_client.h"
#include "table_object.h"
#include <gromox/sortorder_set.hpp>
#include "folder_object.h"
#include <gromox/proptag_array.hpp>
#include "zarafa_server.h"
#include "message_object.h"
#include "container_object.h"
#include "store_object.h"
#include <gromox/propval.hpp>
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

static void table_object_reset(table_object *);

static void table_object_set_table_id(table_object *ptable, uint32_t table_id)
{
	if (0 != ptable->table_id) {
		exmdb_client::unload_table(ptable->pstore->get_dir(), ptable->table_id);
	}
	ptable->table_id = table_id;
}

BOOL table_object::check_to_load()
{
	auto ptable = this;
	uint32_t row_num, permission, new_table_id, new_table_flags;
	
	if (ATTACHMENT_TABLE == ptable->table_type ||
		RECIPIENT_TABLE == ptable->table_type ||
		CONTAINER_TABLE == ptable->table_type ||
		STORE_TABLE == ptable->table_type) {
		return TRUE;
	} else if (USER_TABLE == ptable->table_type) {
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		return ct->load_user_table(ptable->prestriction);
	}
	if (0 != ptable->table_id) {
		return TRUE;
	}
	switch (ptable->table_type) {
	case HIERARCHY_TABLE: {
		auto pinfo = zarafa_server_get_info();
		auto username = ptable->pstore->check_owner_mode() ?
		                nullptr : pinfo->get_username();
		new_table_flags = TABLE_FLAG_NONOTIFICATIONS;
		if (ptable->table_flags & FLAG_SOFT_DELETE) {
			new_table_flags |= TABLE_FLAG_SOFTDELETES;
		}
		if (ptable->table_flags & FLAG_CONVENIENT_DEPTH) {
			new_table_flags |= TABLE_FLAG_DEPTH;
		}
		if (!exmdb_client::load_hierarchy_table(ptable->pstore->get_dir(),
		    static_cast<folder_object *>(ptable->pparent_obj)->folder_id,
		    username, new_table_flags, ptable->prestriction,
		    &new_table_id, &row_num))
			return FALSE;
		break;
	}
	case CONTENT_TABLE: {
		auto pinfo = zarafa_server_get_info();
		const char *username = nullptr;
		if (!ptable->pstore->check_owner_mode()) {
			if (!ptable->pstore->b_private) {
				username = pinfo->get_username();
			} else {
				if (!exmdb_client::check_folder_permission(ptable->pstore->get_dir(),
				    static_cast<folder_object *>(ptable->pparent_obj)->folder_id,
				    pinfo->get_username(), &permission))
					return FALSE;	
				if (!(permission & (frightsReadAny | frightsOwner)))
					username = pinfo->get_username();
			}
		}
		new_table_flags = TABLE_FLAG_NONOTIFICATIONS;
		if (ptable->table_flags & FLAG_SOFT_DELETE) {
			new_table_flags |= TABLE_FLAG_SOFTDELETES;
		}
		if (ptable->table_flags & FLAG_ASSOCIATED) {
			new_table_flags |= TABLE_FLAG_ASSOCIATED;
		}
		if (!exmdb_client::load_content_table(ptable->pstore->get_dir(), pinfo->cpid,
		    static_cast<folder_object *>(ptable->pparent_obj)->folder_id,
		    username, new_table_flags, ptable->prestriction,
		    ptable->psorts, &new_table_id, &row_num))
			return FALSE;
		break;
	}
	case RULE_TABLE:
		if (!exmdb_client::load_rule_table(ptable->pstore->get_dir(),
		    *static_cast<uint64_t *>(ptable->pparent_obj), 0,
		    ptable->prestriction, &new_table_id, &row_num))
			return FALSE;
		break;
	default:
		fprintf(stderr, "%s - not calling table_object_set_table_id\n", __func__);
		return TRUE;
	}
	table_object_set_table_id(ptable, new_table_id);
	return TRUE;
}

void table_object::unload()
{
	auto ptable = this;
	if (USER_TABLE == ptable->table_type) {
		static_cast<container_object *>(ptable->pparent_obj)->clear();
	} else {
		table_object_set_table_id(ptable, 0);
	}
}

static BOOL table_object_get_store_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	PROPTAG_ARRAY tmp_proptags1;
	PROPTAG_ARRAY tmp_proptags2;
	static constexpr uint32_t proptag_buff[] = {
		PR_MDB_PROVIDER, PR_MESSAGE_SIZE, PR_ASSOC_MESSAGE_SIZE,
		PR_NORMAL_MESSAGE_SIZE, PR_EMS_AB_DISPLAY_NAME_PRINTABLE,
		PROP_TAG_DEFAULTSTORE, PR_DISPLAY_NAME, PR_EMAIL_ADDRESS,
		PROP_TAG_EXTENDEDRULESIZELIMIT, PR_MAILBOX_OWNER_ENTRYID,
		PR_MAILBOX_OWNER_NAME, PR_MAX_SUBMIT_MESSAGE_SIZE,
		PR_OBJECT_TYPE, PR_PROVIDER_DISPLAY, PR_RESOURCE_FLAGS,
		PR_RESOURCE_TYPE, PR_RECORD_KEY, PR_INSTANCE_KEY, PR_ENTRYID,
		PR_STORE_ENTRYID, PR_USER_ENTRYID,
	};
	
	auto pinfo = zarafa_server_get_info();
	if (!exmdb_client::get_store_all_proptags(pinfo->get_maildir(), &tmp_proptags1) ||
	    !exmdb_client::get_store_all_proptags(pinfo->get_homedir(), &tmp_proptags2))
		return FALSE;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags1.count + tmp_proptags2.count + 25);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags1.pproptag,
				sizeof(uint32_t)*tmp_proptags1.count);
	pproptags->count = tmp_proptags1.count;
	for (size_t i = 0; i < tmp_proptags2.count; ++i) {
		if (tmp_proptags1.has(tmp_proptags2.pproptag[i]))
			continue;	
		pproptags->pproptag[pproptags->count] =
					tmp_proptags2.pproptag[i];
		pproptags->count ++;
	}
	for (size_t i = 0; i < gromox::arsizeof(proptag_buff); ++i) {
		if (tmp_proptags1.has(proptag_buff[i]) ||
		    tmp_proptags2.has(proptag_buff[i]))
			continue;	
		pproptags->pproptag[pproptags->count] = proptag_buff[i];
		pproptags->count ++;
	}
	return TRUE;
}

static BOOL table_object_get_all_columns(table_object *ptable,
	PROPTAG_ARRAY *pcolumns)
{
	if (ATTACHMENT_TABLE == ptable->table_type) {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		return msg->get_attachment_table_all_proptags(pcolumns);
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		return msg->get_recipient_all_proptags(pcolumns);
	} else if (CONTAINER_TABLE == ptable->table_type) {
		container_object_get_container_table_all_proptags(pcolumns);
		return TRUE;
	} else if (USER_TABLE == ptable->table_type) {
		container_object_get_user_table_all_proptags(pcolumns);
		return TRUE;
	} else if (STORE_TABLE == ptable->table_type) {
		return table_object_get_store_table_all_proptags(pcolumns);
	}
	return exmdb_client::get_table_all_proptags(ptable->pstore->get_dir(),
	       ptable->table_id, pcolumns);
}

static uint32_t table_object_get_folder_tag_access(store_object *pstore,
    uint64_t folder_id, const char *username)
{
	uint32_t permission;
	
	if (pstore->check_owner_mode()) {
		return MAPI_ACCESS_AllSix;
	}
	if (!exmdb_client::check_folder_permission(pstore->get_dir(),
	    folder_id, username, &permission))
		return 0;
	if (permission & frightsOwner) {
		return MAPI_ACCESS_AllSix;
	}
	uint32_t tag_access = MAPI_ACCESS_READ;
	if (permission & frightsCreate)
		tag_access |= MAPI_ACCESS_CREATE_CONTENTS | MAPI_ACCESS_CREATE_ASSOCIATED;
	if (permission & frightsCreateSubfolder)
		tag_access |= MAPI_ACCESS_CREATE_HIERARCHY;
	return tag_access;
}

static uint32_t table_object_get_folder_permission_rights(store_object *pstore,
    uint64_t folder_id, const char *username)
{
	uint32_t permission;
	
	if (pstore->check_owner_mode()) {
		return rightsAll | frightsContact;
	}
	if (!exmdb_client::check_folder_permission(pstore->get_dir(),
	    folder_id, username, &permission))
		return 0;
	return permission;
}

static BOOL rcpttable_query_rows(const table_object *ptable,
    const PROPTAG_ARRAY *pcolumns, TARRAY_SET *pset, uint32_t row_needed)
{
	TARRAY_SET rcpt_set;

	if (!static_cast<message_object *>(ptable->pparent_obj)->
	    read_recipients(0, 0xFFFF, &rcpt_set))
		return FALSE;
	uint32_t end_pos = ptable->position + row_needed > rcpt_set.count ?
	                   rcpt_set.count : ptable->position + row_needed;
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - ptable->position);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	for (size_t i = ptable->position; i < end_pos; ++i) {
		pset->pparray[pset->count] = rcpt_set.pparray[i];
		pset->count++;
	}
	if (!pcolumns->has(PR_ENTRYID))
		return TRUE;
	for (size_t i = 0; i < pset->count; ++i) {
		if (pset->pparray[i]->has(PR_ENTRYID))
			continue;
		auto pvalue = pset->pparray[i]->getval(PR_ADDRTYPE);
		if (pvalue == nullptr ||
		    strcasecmp(static_cast<char *>(pvalue), "EX") != 0)
			continue;
		pvalue = pset->pparray[i]->getval(PR_EMAIL_ADDRESS);
		if (NULL == pvalue) {
			continue;
		}
		auto pentryid = cu_alloc<BINARY>();
		if (NULL == pentryid) {
			return FALSE;
		}
		if (!common_util_essdn_to_entryid(static_cast<char *>(pvalue), pentryid))
			return FALSE;
		pvalue = cu_alloc<TAGGED_PROPVAL>(pset->pparray[i]->count + 1);
		if (NULL == pvalue) {
			return FALSE;
		}
		memcpy(pvalue, pset->pparray[i]->ppropval,
			sizeof(TAGGED_PROPVAL)*pset->pparray[i]->count);
		pset->pparray[i]->ppropval = static_cast<TAGGED_PROPVAL *>(pvalue);
		pset->pparray[i]->ppropval[pset->pparray[i]->count].proptag = PR_ENTRYID;
		pset->pparray[i]->ppropval[pset->pparray[i]->count].pvalue =
			pentryid;
		pset->pparray[i]->count ++;
	}
	return TRUE;
}

static BOOL storetbl_query_rows(const table_object *ptable,
    const PROPTAG_ARRAY *pcolumns, TARRAY_SET *pset, const USER_INFO *pinfo,
    uint32_t row_needed)
{
	uint32_t end_pos = ptable->position + row_needed;
	if (end_pos >= 2) {
		end_pos = 1;
	}
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - ptable->position + 1);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	for (size_t i = ptable->position; i <= end_pos; ++i) {
		pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == pset->pparray[pset->count]) {
			return FALSE;
		}
		uint32_t handle = i == 0 ?
			pinfo->ptree->get_store_handle(TRUE, pinfo->user_id) :
			pinfo->ptree->get_store_handle(false, pinfo->domain_id);
		uint8_t mapi_type = 0;
		auto pstore = pinfo->ptree->get_object<store_object>(handle, &mapi_type);
		if (pstore == nullptr || mapi_type != ZMG_STORE)
			return FALSE;
		if (!pstore->get_properties(pcolumns, pset->pparray[pset->count]))
			return FALSE;
		pset->count ++;
	}
	return TRUE;
}

static bool conttbl_srckey(const table_object *ptable, TARRAY_SET &temp_set)
{
	for (size_t i = 0; i < temp_set.count; ++i) {
		for (size_t j = 0; j < temp_set.pparray[i]->count; ++j) {
			auto &r = temp_set.pparray[i]->ppropval[j];
			if (r.proptag != PidTagMid)
				continue;
			auto tmp_eid = *static_cast<uint64_t *>(r.pvalue);
			r.pvalue = common_util_calculate_message_sourcekey(ptable->pstore, tmp_eid);
			if (r.pvalue == nullptr)
				return FALSE;
			r.proptag = PR_SOURCE_KEY;
			/* Replace just one column of PidTagMid per row with PR_.. */
			break;
		}
	}
	return true;
}

static bool hiertbl_srckey(const table_object *ptable, TARRAY_SET &temp_set)
{
	for (size_t i = 0; i < temp_set.count; ++i) {
		for (size_t j = 0; j < temp_set.pparray[i]->count; ++j) {
			auto &r = temp_set.pparray[i]->ppropval[j];
			if (r.proptag != PidTagFolderId)
				continue;
			auto tmp_eid = *static_cast<uint64_t *>(r.pvalue);
			r.pvalue = common_util_calculate_folder_sourcekey(ptable->pstore, tmp_eid);
			if (r.pvalue == nullptr)
				return false;
			r.proptag = PR_SOURCE_KEY;
			/* Replace just one column of PidTagFolderId per row with PR_.. */
			break;
		}
	}
	return true;
}

static bool hiertbl_access(const table_object *ptable,
    const char *username, TARRAY_SET &temp_set)
{
	for (size_t i = 0; i < temp_set.count; ++i) {
		for (size_t j = 0; j < temp_set.pparray[i]->count; ++j) {
			auto &r = temp_set.pparray[i]->ppropval[j];
			if (r.proptag != PidTagFolderId)
				continue;
			auto tmp_eid = *static_cast<uint64_t *>(r.pvalue);
			auto ptag_access = cu_alloc<uint32_t>();
			if (ptag_access == nullptr)
				return false;
			*ptag_access = table_object_get_folder_tag_access(ptable->pstore,
			               tmp_eid, username);
			r.proptag = PR_ACCESS;
			r.pvalue = ptag_access;
			break;
		}
	}
	return true;
}

static bool hiertbl_rights(const table_object *ptable,
    const char *username, TARRAY_SET &temp_set)
{
	for (size_t i = 0; i < temp_set.count; ++i) {
		for (size_t j = 0; j < temp_set.pparray[i]->count; ++j) {
			auto &r = temp_set.pparray[i]->ppropval[j];
			if (r.proptag != PidTagFolderId)
				continue;
			auto tmp_eid = *static_cast<uint64_t *>(r.pvalue);
			auto perm = cu_alloc<uint32_t>();
			if (perm == nullptr)
				return false;
			*perm = table_object_get_folder_permission_rights(ptable->pstore,
			        tmp_eid, username);
			r.proptag = PR_RIGHTS;
			r.pvalue = perm;
			break;
		}
	}
	return true;
}

static BOOL hierconttbl_query_rows(const table_object *ptable,
    const PROPTAG_ARRAY *pcolumns, PROPTAG_ARRAY &tmp_columns,
    const USER_INFO *pinfo, uint32_t row_needed, TARRAY_SET *pset)
{
	auto username = ptable->pstore->b_private ? nullptr : pinfo->get_username();
	size_t idx_sk = pcolumns->indexof(PR_SOURCE_KEY);
	size_t idx_acc = pcolumns->npos, idx_rig = pcolumns->npos;
	TARRAY_SET temp_set;

	if (HIERARCHY_TABLE == ptable->table_type) {
		idx_acc = pcolumns->indexof(PR_ACCESS);
		idx_rig = pcolumns->indexof(PR_RIGHTS);
	}
	if (idx_sk != pcolumns->npos || idx_acc != pcolumns->npos ||
	    idx_rig != pcolumns->npos) {
		tmp_columns.pproptag = cu_alloc<uint32_t>(pcolumns->count);
		if (NULL == tmp_columns.pproptag) {
			return FALSE;
		}
		tmp_columns.count = pcolumns->count;
		memcpy(tmp_columns.pproptag, pcolumns->pproptag,
			sizeof(uint32_t)*pcolumns->count);
		/*
		 * For source_key/access/rights, we need the MID/FID,
		 * so do some substitution (which will be "undone")
		 * in {hier,cont}tbl_{sourcekey,access,right}.
		 *
		 * We may be requesting PidTagFolderId more than once from
		 * exmdb, which is intentional.
		 */
		if (idx_sk != pcolumns->npos)
			tmp_columns.pproptag[idx_sk] = ptable->table_type == CONTENT_TABLE ?
			                            PidTagMid : PidTagFolderId;
		if (idx_acc != pcolumns->npos)
			tmp_columns.pproptag[idx_acc] = PidTagFolderId;
		if (idx_rig != pcolumns->npos)
			tmp_columns.pproptag[idx_rig] = PidTagFolderId;
		if (!exmdb_client::query_table(ptable->pstore->get_dir(),
		    username, pinfo->cpid, ptable->table_id, &tmp_columns,
		    ptable->position, row_needed, &temp_set))
			return FALSE;
		if (CONTENT_TABLE == ptable->table_type) {
			if (!conttbl_srckey(ptable, temp_set))
				return false;
		} else {
			if (idx_sk != pcolumns->npos &&
			    !hiertbl_srckey(ptable, temp_set))
				return false;
			if (idx_acc != pcolumns->npos &&
			    !hiertbl_access(ptable, pinfo->get_username(), temp_set))
				return false;
			if (idx_rig != pcolumns->npos &&
			    !hiertbl_rights(ptable, pinfo->get_username(), temp_set))
				return false;
		}
	} else {
		if (!exmdb_client::query_table(ptable->pstore->get_dir(),
		    username, pinfo->cpid, ptable->table_id,
		    pcolumns, ptable->position, row_needed, &temp_set))
			return FALSE;
	}
	if (pcolumns->has(PR_STORE_ENTRYID)) {
		auto pentryid = common_util_to_store_entryid(ptable->pstore);
		if (NULL == pentryid) {
			return FALSE;
		}
		for (size_t i = 0; i < temp_set.count; ++i) {
			auto ppropvals = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == ppropvals) {
				return FALSE;
			}
			ppropvals->count = temp_set.pparray[i]->count + 1;
			ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
			if (NULL == ppropvals->ppropval) {
				return FALSE;
			}
			memcpy(ppropvals->ppropval, temp_set.pparray[i]->ppropval,
				sizeof(TAGGED_PROPVAL)*temp_set.pparray[i]->count);
			ppropvals->ppropval[temp_set.pparray[i]->count].proptag = PR_STORE_ENTRYID;
			ppropvals->ppropval[temp_set.pparray[i]->count].pvalue =
				pentryid;
			temp_set.pparray[i] = ppropvals;
		}
	}
	*pset = temp_set;
	return TRUE;
}

BOOL table_object::query_rows(const PROPTAG_ARRAY *cols,
    uint32_t row_count, TARRAY_SET *pset)
{
	auto ptable = this;
	PROPTAG_ARRAY tmp_columns;
	if (cols == nullptr) {
		if (NULL != ptable->pcolumns) {
			cols = ptable->pcolumns;
		} else {
			if (FALSE == table_object_get_all_columns(
			    ptable, &tmp_columns)) {
				return FALSE;
			}
			cols = &tmp_columns;
		}
	}
	auto pinfo = zarafa_server_get_info();
	if (NULL == pinfo) {
		return FALSE;
	}
	auto row_num = get_total();
	if (ptable->position >= row_num) {
		pset->count = 0;
		return TRUE;
	}
	if (row_count > row_num) {
		row_count = row_num;
	}
	if (row_count > INT32_MAX)
		row_count = INT32_MAX;

	if (ATTACHMENT_TABLE == ptable->table_type) {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		return msg->query_attachment_table(cols, ptable->position, row_count, pset);
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		return rcpttable_query_rows(ptable, cols, pset, row_count);
	} else if (CONTAINER_TABLE == ptable->table_type) {
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		return ct->query_container_table(cols,
		       (ptable->table_flags & FLAG_CONVENIENT_DEPTH) ? TRUE : false,
		       ptable->position, row_count, pset);
	} else if (USER_TABLE == ptable->table_type) {
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		return ct->query_user_table(cols, ptable->position, row_count, pset);
	} else if (RULE_TABLE == ptable->table_type) {
		if (!exmdb_client::query_table(ptable->pstore->get_dir(),
		    nullptr, pinfo->cpid, ptable->table_id, cols,
		    ptable->position, row_count, pset))
			return FALSE;
		for (size_t i = 0; i < pset->count; ++i) {
			if (FALSE == common_util_convert_to_zrule_data(
				ptable->pstore, pset->pparray[i])) {
				return FALSE;
			}
		}
		return TRUE;
	} else if (STORE_TABLE == ptable->table_type) {
		return storetbl_query_rows(ptable, cols, pset, pinfo, row_count);
	}
	auto username = ptable->pstore->b_private ? nullptr : pinfo->get_username();
	if ((CONTENT_TABLE == ptable->table_type ||
	    HIERARCHY_TABLE == ptable->table_type)) {
		return hierconttbl_query_rows(ptable, cols, tmp_columns, pinfo, row_count, pset);
	}
	return exmdb_client::query_table(ptable->pstore->get_dir(),
		username, pinfo->cpid, ptable->table_id,
	       cols, ptable->position, row_count, pset);
}

void table_object::seek_current(BOOL b_forward, uint32_t row_count)
{
	auto ptable = this;
	uint32_t total_rows;
	
	if (TRUE == b_forward) {
		ptable->position += row_count;
		total_rows = get_total();
		if (ptable->position > total_rows) {
			ptable->position = total_rows;
		}
		return;
	}
	if (ptable->position < row_count) {
		ptable->position = 0;
		return;
	}
	ptable->position -= row_count;
}

BOOL table_object::set_columns(const PROPTAG_ARRAY *cols)
{
	auto ptable = this;
	if (NULL != ptable->pcolumns) {
		proptag_array_free(ptable->pcolumns);
	}
	if (cols == nullptr) {
		ptable->pcolumns = NULL;
		return TRUE;
	}
	ptable->pcolumns = proptag_array_dup(cols);
	if (NULL == ptable->pcolumns) {
		return FALSE;
	}
	return TRUE;
}

BOOL table_object::set_sorts(const SORTORDER_SET *so)
{
	auto ptable = this;
	if (NULL != ptable->psorts) {
		sortorder_set_free(ptable->psorts);
	}
	if (so == nullptr) {
		ptable->psorts = NULL;
		return TRUE;
	}
	ptable->psorts = sortorder_set_dup(so);
	if (NULL == ptable->psorts) {
		return FALSE;
	}
	return TRUE;
}

BOOL table_object::set_restriction(const RESTRICTION *res)
{
	auto ptable = this;
	if (NULL != ptable->prestriction) {
		restriction_free(ptable->prestriction);
	}
	if (res == nullptr) {
		ptable->prestriction = NULL;
		return TRUE;
	}
	ptable->prestriction = restriction_dup(res);
	if (NULL == ptable->prestriction) {
		return FALSE;
	}
	return TRUE;
}

void table_object::set_position(uint32_t pos)
{
	auto ptable = this;
	auto total_rows = get_total();
	if (pos > total_rows)
		pos = total_rows;
	ptable->position = pos;
}

uint32_t table_object::get_total()
{
	auto ptable = this;
	uint16_t num;
	uint32_t num1;
	uint32_t total_rows;
	
	if (ATTACHMENT_TABLE == ptable->table_type) {
		num = 0;
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		msg->get_attachments_num(&num);
		return num;
	} else if (RECIPIENT_TABLE == ptable->table_type) {
		num = 0;
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		msg->get_recipient_num(&num);
		return num;
	} else if (CONTAINER_TABLE == ptable->table_type) {
		num1 = 0;
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		ct->get_container_table_num((ptable->table_flags & FLAG_CONVENIENT_DEPTH) ? TRUE : false, &num1);
		return num1;
	} else if (USER_TABLE == ptable->table_type) {
		num1 = 0;
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		ct->get_user_table_num(&num1);
		return num1;
	} else if (STORE_TABLE == ptable->table_type) {
		return 2;
	}
	exmdb_client::sum_table(ptable->pstore->get_dir(),
		ptable->table_id, &total_rows);
	return total_rows;
}

std::unique_ptr<table_object> table_object::create(store_object *pstore,
	void *pparent_obj, uint8_t table_type, uint32_t table_flags)
{
	std::unique_ptr<table_object> ptable;
	try {
		ptable.reset(new table_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	ptable->pstore = pstore;
	if (RULE_TABLE == table_type) {
		ptable->pparent_obj = me_alloc<uint64_t>();
		if (NULL == ptable->pparent_obj) {
			return NULL;
		}
		*(uint64_t*)ptable->pparent_obj = *(uint64_t*)pparent_obj;
	} else {
		ptable->pparent_obj = pparent_obj;
	}
	ptable->table_type = static_cast<zcore_table_type>(table_type);
	ptable->table_flags = table_flags;
	ptable->pcolumns = NULL;
	ptable->psorts = NULL;
	ptable->prestriction = NULL;
	ptable->position = 0;
	ptable->table_id = 0;
	ptable->bookmark_index = 0x100;
	double_list_init(&ptable->bookmark_list);
	return ptable;
}

table_object::~table_object()
{
	auto ptable = this;
	table_object_reset(ptable);
	double_list_free(&ptable->bookmark_list);
	if (RULE_TABLE == ptable->table_type) {
		free(ptable->pparent_obj);
	}
}

BOOL table_object::create_bookmark(uint32_t *pindex)
{
	auto ptable = this;
	uint64_t inst_id;
	uint32_t row_type;
	uint32_t inst_num;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	if (!exmdb_client::mark_table(ptable->pstore->get_dir(),
	    ptable->table_id, ptable->position, &inst_id, &inst_num, &row_type))
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

BOOL table_object::retrieve_bookmark(uint32_t index, BOOL *pb_exist)
{
	auto ptable = this;
	uint64_t inst_id;
	uint32_t inst_num, row_type, tmp_type, saved_position;
	int32_t tmp_position;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	for (pnode=double_list_get_head(&ptable->bookmark_list); NULL!=pnode;
		pnode=double_list_get_after(&ptable->bookmark_list, pnode)) {
		auto bn = static_cast<BOOKMARK_NODE *>(pnode->pdata);
		if (index == bn->index) {
			inst_id = bn->inst_id;
			row_type = bn->row_type;
			inst_num = bn->inst_num;
			saved_position = bn->position;
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	if (!exmdb_client::locate_table(ptable->pstore->get_dir(),
	    ptable->table_id, inst_id, inst_num, &tmp_position, &tmp_type))
		return FALSE;
	*pb_exist = FALSE;
	if (tmp_position >= 0) {
		if (tmp_type == row_type) {
			*pb_exist = TRUE;
		}
		ptable->position = tmp_position;
	} else {
		ptable->position = saved_position;
	}
	auto total_rows = get_total();
	if (ptable->position > total_rows) {
		ptable->position = total_rows;
	}
	return TRUE;
}

void table_object::remove_bookmark(uint32_t index)
{
	auto ptable = this;
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

void table_object::clear_bookmarks()
{
	auto ptable = this;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&ptable->bookmark_list)) != nullptr)
		free(pnode->pdata);
}

static void table_object_reset(table_object *ptable)
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
	ptable->clear_bookmarks();
}

static BOOL table_object_evaluate_restriction(
	const TPROPVAL_ARRAY *ppropvals, const RESTRICTION *pres)
{
	uint32_t val_size;
	
	switch (pres->rt) {
	case RES_OR:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (table_object_evaluate_restriction(ppropvals,
			    &pres->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_AND:
		for (size_t i = 0; i < pres->andor->count; ++i)
			if (!table_object_evaluate_restriction(ppropvals,
			    &pres->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_NOT:
		if (table_object_evaluate_restriction(ppropvals, &pres->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pres->cont;
		if (PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		auto pvalue = ppropvals->getval(rcon->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
				return FALSE;
			}
			if (strcmp(static_cast<char *>(rcon->propval.pvalue),
			    static_cast<char *>(pvalue)) == 0)
				return TRUE;
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
				return FALSE;
			}
			if (strstr(static_cast<char *>(pvalue),
			    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
				return TRUE;
			return FALSE;
		case FL_PREFIX: {
			auto len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue),
				    len) == 0)
					return TRUE;
				return FALSE;
			}
			if (strncmp(static_cast<char *>(pvalue),
			    static_cast<char *>(rcon->propval.pvalue),
			    len) == 0)
				return TRUE;
			return FALSE;
		}
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		auto pvalue = ppropvals->getval(rprop->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		if (rprop->proptag == PROP_TAG_ANR) {
			if (PROP_TYPE(rprop->propval.proptag) != PT_UNICODE)
				return FALSE;
			if (strcasestr(static_cast<char *>(rprop->propval.pvalue),
			    static_cast<char *>(pvalue)) != nullptr)
				return TRUE;
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (PROP_TYPE(rprop->proptag1) != PROP_TYPE(rprop->proptag2))
			return FALSE;
		auto pvalue = ppropvals->getval(rprop->proptag1);
		if (NULL == pvalue) {
			return FALSE;
		}
		auto pvalue1 = ppropvals->getval(rprop->proptag2);
		if (NULL == pvalue1) {
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag1), pvalue, pvalue1);
	}
	case RES_BITMASK: {
		auto rbm = pres->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		auto pvalue = ppropvals->get<uint32_t>(rbm->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if (!(*pvalue & rbm->mask))
				return TRUE;
			break;
		case BMR_NEZ:
			if (*pvalue & rbm->mask)
				return TRUE;
			break;
		}	
		return FALSE;
	}
	case RES_SIZE: {
		auto rsize = pres->size;
		auto pvalue = ppropvals->getval(rsize->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		val_size = propval_size(rsize->proptag, pvalue);
		return propval_compare_relop(rsize->relop, PT_LONG,
		       &val_size, &rsize->size);
	}
	case RES_EXIST:
		return ppropvals->has(pres->exist->proptag) ? TRUE : false;
	case RES_COMMENT:
		if (pres->comment->pres == nullptr)
			return TRUE;
		return table_object_evaluate_restriction(ppropvals, pres->comment->pres);
	default:
		return FALSE;
	}	
	return FALSE;
}

BOOL table_object::filter_rows(uint32_t count, const RESTRICTION *pres,
	const PROPTAG_ARRAY *cols, TARRAY_SET *pset)
{
	auto ptable = this;
	TARRAY_SET tmp_set;
	uint32_t tmp_proptag;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY tmp_proptags;
	
	switch (ptable->table_type) {
	case ATTACHMENT_TABLE: {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		if (!msg->get_attachment_table_all_proptags(&proptags))
			return FALSE;	
		tmp_proptag = PR_ATTACH_DATA_BIN;
		tmp_proptags.count = 1;
		tmp_proptags.pproptag = &tmp_proptag;
		common_util_reduce_proptags(&proptags, &tmp_proptags);
		if (!msg->query_attachment_table(&proptags, ptable->position, 0x7FFFFFFF, &tmp_set))
			return FALSE;	
		break;
	}
	case RECIPIENT_TABLE:
		if (!static_cast<message_object *>(ptable->pparent_obj)->
		    read_recipients(0, 0xFFFF, &tmp_set))
			return FALSE;	
		break;
	case USER_TABLE:
		container_object_get_user_table_all_proptags(&proptags);
		if (!static_cast<container_object *>(ptable->pparent_obj)->
		    query_user_table(&proptags, ptable->position, 0x7FFFFFFF, &tmp_set))
			return FALSE;	
		break;
	default:
		return FALSE;	
	}
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(tmp_set.count);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	for (size_t i = 0; i < tmp_set.count && pset->count < count; ++i) {
		if (FALSE == table_object_evaluate_restriction(
			tmp_set.pparray[i], pres)) {
			continue;	
		}
		pset->pparray[pset->count] = tmp_set.pparray[i];
		pset->count ++;
	}
	return TRUE;
}

BOOL table_object::match_row(BOOL b_forward, const RESTRICTION *pres,
	int32_t *pposition)
{
	auto ptable = this;
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[2];
	TPROPVAL_ARRAY tmp_propvals;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	auto pinfo = zarafa_server_get_info();
	auto username = ptable->pstore->b_private ? nullptr : pinfo->get_username();
	proptags.count = 2;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PROP_TAG_INSTID;
	proptag_buff[1] = PROP_TAG_INSTANCENUM;
	return exmdb_client::match_table(ptable->pstore->get_dir(), username,
		pinfo->cpid, ptable->table_id, b_forward,
		ptable->position, pres, &proptags, pposition,
		&tmp_propvals);
}
