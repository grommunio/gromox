// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>
#include <gromox/sortorder_set.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "exmdb_client.h"
#include "object_tree.h"
#include "objects.hpp"
#include "store_object.h"
#include "system_services.hpp"
#include "table_object.h"
#include "zserver.hpp"

using namespace gromox;

static void table_object_reset(table_object *);
static BOOL table_object_get_store_table_all_proptags(PROPTAG_ARRAY *);

static void table_object_set_table_id(table_object *ptable, uint32_t table_id)
{
	if (0 != ptable->table_id) {
		exmdb_client::unload_table(ptable->pstore->get_dir(), ptable->table_id);
	}
	ptable->table_id = table_id;
}

static errno_t storetbl_add_row(table_object *tbl, const USER_INFO &info,
    const PROPTAG_ARRAY &tags, bool is_private, unsigned int user_id)
{
	uint32_t handle = info.ptree->get_store_handle(is_private ? TRUE : false, user_id);
	zs_objtype mapi_type = zs_objtype::invalid;
	auto store = info.ptree->get_object<store_object>(handle, &mapi_type);
	if (store == nullptr || mapi_type != zs_objtype::store)
		return ENOENT;
	auto props = cu_alloc<TPROPVAL_ARRAY>();
	if (props == nullptr)
		return ENOMEM;
	if (!store->get_properties(&tags, props))
		return 0;
	/* props is from the cu_alloc allocator; by duplication, we make one with me_alloc */
	tpropval_array_ptr pdup(props->dup());
	if (pdup == nullptr)
		return ENOMEM;
	return tbl->fixed_data->append_move(std::move(pdup));
}

static errno_t storetbl_refresh(table_object *tbl)
{
	auto info = zs_get_info();
	if (info == nullptr)
		return EIO;
	if (tbl->fixed_data != nullptr)
		tarray_set_free(tbl->fixed_data);
	tbl->fixed_data = tarray_set_init();
	if (tbl->fixed_data == nullptr)
		return ENOMEM;

	PROPTAG_ARRAY tags{};
	if (!table_object_get_store_table_all_proptags(&tags))
		return EIO;
	storetbl_add_row(tbl, *info, tags, true, info->user_id);
	storetbl_add_row(tbl, *info, tags, false, info->domain_id);
	std::vector<sql_user> hints;
	if (system_services_scndstore_hints(info->user_id, hints) == 0)
		for (const auto &user : hints)
			storetbl_add_row(tbl, *info, tags, true, user.id);
	/* Table now contains _validated_ entries. */
	return 0;
}

BOOL table_object::load()
{
	auto ptable = this;
	uint32_t row_num, permission, new_table_id, new_table_flags;
	
	if (ptable->table_type == zcore_tbltype::attachment ||
		ptable->table_type == zcore_tbltype::recipient ||
	    ptable->table_type == zcore_tbltype::container) {
		return TRUE;
	} else if (ptable->table_type == zcore_tbltype::store) {
		return storetbl_refresh(this) == 0 ? TRUE : false;
	} else if (ptable->table_type == zcore_tbltype::abcontusr) {
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		return ct->load_user_table(ptable->prestriction);
	} else if (ptable->table_type == zcore_tbltype::distlist) {
		auto u = static_cast<user_object *>(ptable->pparent_obj);
		return u->load_list_members(ptable->prestriction) == ecSuccess ? TRUE : false;
	}
	if (0 != ptable->table_id) {
		return TRUE;
	}
	switch (ptable->table_type) {
	case zcore_tbltype::hierarchy: {
		auto pinfo = zs_get_info();
		auto username = ptable->pstore->owner_mode() ?
		                nullptr : pinfo->get_username();
		new_table_flags = TABLE_FLAG_NONOTIFICATIONS;
		if (ptable->table_flags & SHOW_SOFT_DELETES)
			new_table_flags |= TABLE_FLAG_SOFTDELETES;
		if (ptable->table_flags & CONVENIENT_DEPTH)
			new_table_flags |= TABLE_FLAG_DEPTH;
		if (!exmdb_client::load_hierarchy_table(ptable->pstore->get_dir(),
		    static_cast<folder_object *>(ptable->pparent_obj)->folder_id,
		    username, new_table_flags, ptable->prestriction,
		    &new_table_id, &row_num))
			return FALSE;
		break;
	}
	case zcore_tbltype::content: {
		auto pinfo = zs_get_info();
		const char *username = nullptr;
		if (!ptable->pstore->owner_mode()) {
			if (!ptable->pstore->b_private) {
				username = pinfo->get_username();
			} else {
				if (!exmdb_client::get_folder_perm(ptable->pstore->get_dir(),
				    static_cast<folder_object *>(ptable->pparent_obj)->folder_id,
				    pinfo->get_username(), &permission))
					return FALSE;	
				if (!(permission & (frightsReadAny | frightsOwner)))
					username = pinfo->get_username();
			}
		}
		new_table_flags = TABLE_FLAG_NONOTIFICATIONS;
		if (ptable->table_flags & SHOW_SOFT_DELETES)
			new_table_flags |= TABLE_FLAG_SOFTDELETES;
		if (ptable->table_flags & MAPI_ASSOCIATED)
			new_table_flags |= TABLE_FLAG_ASSOCIATED;
		if (!exmdb_client::load_content_table(ptable->pstore->get_dir(), pinfo->cpid,
		    static_cast<folder_object *>(ptable->pparent_obj)->folder_id,
		    username, new_table_flags, ptable->prestriction,
		    ptable->psorts, &new_table_id, &row_num))
			return FALSE;
		break;
	}
	case zcore_tbltype::rule:
		if (!exmdb_client::load_rule_table(ptable->pstore->get_dir(),
		    *static_cast<uint64_t *>(ptable->pparent_obj), 0,
		    ptable->prestriction, &new_table_id, &row_num))
			return FALSE;
		break;
	default:
		mlog(LV_WARN, "%s - not calling table_object_set_table_id", __PRETTY_FUNCTION__);
		return TRUE;
	}
	table_object_set_table_id(ptable, new_table_id);
	return TRUE;
}

void table_object::unload()
{
	auto ptable = this;
	if (ptable->table_type == zcore_tbltype::abcontusr) {
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
		PR_DEFAULT_STORE, PR_DISPLAY_NAME, PR_EMAIL_ADDRESS,
		PR_EXTENDED_RULE_SIZE_LIMIT, PR_MAILBOX_OWNER_ENTRYID,
		PR_MAILBOX_OWNER_NAME, PR_MAX_SUBMIT_MESSAGE_SIZE,
		PR_OBJECT_TYPE, PR_PROVIDER_DISPLAY, PR_RESOURCE_FLAGS,
		PR_RESOURCE_TYPE, PR_RECORD_KEY, PR_INSTANCE_KEY, PR_ENTRYID,
		PR_STORE_ENTRYID, PR_USER_ENTRYID,
	};
	
	auto pinfo = zs_get_info();
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
		pproptags->pproptag[pproptags->count++] = tmp_proptags2.pproptag[i];
	}
	for (size_t i = 0; i < arsizeof(proptag_buff); ++i) {
		if (tmp_proptags1.has(proptag_buff[i]) ||
		    tmp_proptags2.has(proptag_buff[i]))
			continue;	
		pproptags->pproptag[pproptags->count++] = proptag_buff[i];
	}
	return TRUE;
}

static BOOL table_object_get_all_columns(table_object *ptable,
	PROPTAG_ARRAY *pcolumns)
{
	if (ptable->table_type == zcore_tbltype::attachment) {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		return msg->get_attachment_table_all_proptags(pcolumns);
	} else if (ptable->table_type == zcore_tbltype::recipient) {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		return msg->get_recipient_all_proptags(pcolumns);
	} else if (ptable->table_type == zcore_tbltype::container) {
		container_object_get_container_table_all_proptags(pcolumns);
		return TRUE;
	} else if (ptable->table_type == zcore_tbltype::abcontusr) {
		container_object_get_user_table_all_proptags(pcolumns);
		return TRUE;
	} else if (ptable->table_type == zcore_tbltype::store) {
		return table_object_get_store_table_all_proptags(pcolumns);
	}
	return exmdb_client::get_table_all_proptags(ptable->pstore->get_dir(),
	       ptable->table_id, pcolumns);
}

static uint32_t table_object_get_folder_tag_access(store_object *pstore,
    uint64_t folder_id, const char *username)
{
	uint32_t permission;
	
	if (pstore->owner_mode()) {
		return MAPI_ACCESS_AllSix;
	}
	if (!exmdb_client::get_folder_perm(pstore->get_dir(),
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
	
	if (pstore->owner_mode()) {
		return rightsAll | frightsContact;
	}
	if (!exmdb_client::get_folder_perm(pstore->get_dir(),
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
		pset->pparray[pset->count++] = rcpt_set.pparray[i];
	}
	if (!pcolumns->has(PR_ENTRYID))
		return TRUE;
	for (size_t i = 0; i < pset->count; ++i) {
		if (pset->pparray[i]->has(PR_ENTRYID))
			continue;
		auto addrtype = pset->pparray[i]->get<const char>(PR_ADDRTYPE);
		if (addrtype == nullptr || strcasecmp(addrtype, "EX") != 0)
			continue;
		auto emaddr = pset->pparray[i]->get<const char>(PR_EMAIL_ADDRESS);
		if (emaddr == nullptr)
			continue;
		auto pentryid = cu_alloc<BINARY>();
		if (NULL == pentryid) {
			return FALSE;
		}
		if (!common_util_essdn_to_entryid(emaddr, pentryid))
			return FALSE;
		auto pvalue = cu_alloc<TAGGED_PROPVAL>(pset->pparray[i]->count + 1);
		if (NULL == pvalue) {
			return FALSE;
		}
		memcpy(pvalue, pset->pparray[i]->ppropval,
			sizeof(TAGGED_PROPVAL)*pset->pparray[i]->count);
		pset->pparray[i]->ppropval = pvalue;
		pset->pparray[i]->ppropval[pset->pparray[i]->count].proptag = PR_ENTRYID;
		pset->pparray[i]->ppropval[pset->pparray[i]->count++].pvalue = pentryid;
	}
	return TRUE;
}

static BOOL storetbl_query_rows(const table_object *ptable,
    const PROPTAG_ARRAY *pcolumns, TARRAY_SET *pset, const USER_INFO *pinfo,
    uint32_t row_needed)
{
	uint32_t end_pos = ptable->position + row_needed;
	if (ptable->fixed_data == nullptr)
		end_pos = 0;
	else if (end_pos >= ptable->fixed_data->count)
		end_pos = ptable->fixed_data->count;
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(end_pos - ptable->position + 1);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	for (size_t i = ptable->position; i < end_pos; ++i) {
		pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == pset->pparray[pset->count]) {
			return FALSE;
		}
		pset->pparray[pset->count++] = ptable->fixed_data->pparray[i];;
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
			r.pvalue = cu_mid_to_sk(ptable->pstore, tmp_eid);
			if (r.pvalue == nullptr)
				return FALSE;
			r.proptag = PR_SOURCE_KEY;
			/* Replace just one column of PidTagMid per row with PR_.. */
			break;
		}
	}
	return true;
}

static bool conttbl_access(const table_object *table,
    const char *username, TARRAY_SET &out_set)
{
	auto fid = static_cast<folder_object *>(table->pparent_obj)->folder_id;
	for (size_t i = 0; i < out_set.count; ++i) {
		for (size_t j = 0; j < out_set.pparray[i]->count; ++j) {
			auto &r = out_set.pparray[i]->ppropval[j];
			if (r.proptag != PidTagMid)
				continue;
			auto mid = *static_cast<uint64_t *>(r.pvalue);
			auto acval = cu_alloc<uint32_t>();
			if (acval == nullptr)
				return false;
			auto err = cu_calc_msg_access(table->pstore, username,
			           fid, mid, *acval);
			if (err != ecSuccess)
				return false;
			r.proptag = PR_ACCESS;
			r.pvalue = acval;
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
			r.pvalue = cu_fid_to_sk(ptable->pstore, tmp_eid);
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
	size_t idx_acc = pcolumns->indexof(PR_ACCESS);
	size_t idx_rig = ptable->table_type == zcore_tbltype::hierarchy ?
	                 pcolumns->indexof(PR_RIGHTS) : pcolumns->npos;
	TARRAY_SET temp_set;

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
			tmp_columns.pproptag[idx_sk] = ptable->table_type == zcore_tbltype::content ?
			                            PidTagMid : PidTagFolderId;
		if (idx_acc != pcolumns->npos)
			tmp_columns.pproptag[idx_acc] = ptable->table_type == zcore_tbltype::content ?
			                                PidTagMid : PidTagFolderId;
		if (idx_rig != pcolumns->npos)
			tmp_columns.pproptag[idx_rig] = PidTagFolderId;
		if (!exmdb_client::query_table(ptable->pstore->get_dir(),
		    username, pinfo->cpid, ptable->table_id, &tmp_columns,
		    ptable->position, row_needed, &temp_set))
			return FALSE;
		if (ptable->table_type == zcore_tbltype::content) {
			if (idx_sk != pcolumns->npos &&
			    !conttbl_srckey(ptable, temp_set))
				return false;
			if (idx_acc != pcolumns->npos &&
			    !conttbl_access(ptable, pinfo->get_username(), temp_set))
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
			if (!table_object_get_all_columns(ptable, &tmp_columns))
				return FALSE;
			cols = &tmp_columns;
		}
	}
	auto pinfo = zs_get_info();
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

	if (ptable->table_type == zcore_tbltype::attachment) {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		return msg->query_attachment_table(cols, ptable->position, row_count, pset);
	} else if (ptable->table_type == zcore_tbltype::recipient) {
		return rcpttable_query_rows(ptable, cols, pset, row_count);
	} else if (ptable->table_type == zcore_tbltype::container) {
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		return ct->query_container_table(cols,
		       (ptable->table_flags & CONVENIENT_DEPTH) ? TRUE : false,
		       ptable->position, row_count, pset);
	} else if (ptable->table_type == zcore_tbltype::abcontusr) {
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		return ct->query_user_table(cols, ptable->position, row_count, pset);
	} else if (ptable->table_type == zcore_tbltype::distlist) {
		auto u = static_cast<user_object *>(ptable->pparent_obj);
		return u->query_member_table(cols, ptable->position, row_count, pset) == ecSuccess ? TRUE : false;
	} else if (ptable->table_type == zcore_tbltype::rule) {
		if (!exmdb_client::query_table(ptable->pstore->get_dir(),
		    nullptr, pinfo->cpid, ptable->table_id, cols,
		    ptable->position, row_count, pset))
			return FALSE;
		for (size_t i = 0; i < pset->count; ++i) {
			if (!common_util_convert_to_zrule_data(
			    ptable->pstore, pset->pparray[i]))
				return FALSE;
		}
		return TRUE;
	} else if (ptable->table_type == zcore_tbltype::store) {
		return storetbl_query_rows(ptable, cols, pset, pinfo, row_count);
	}
	auto username = ptable->pstore->b_private ? nullptr : pinfo->get_username();
	if ((ptable->table_type == zcore_tbltype::content ||
	    ptable->table_type == zcore_tbltype::hierarchy)) {
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
	
	if (b_forward) {
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
	
	if (ptable->table_type == zcore_tbltype::attachment) {
		num = 0;
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		msg->get_attachments_num(&num);
		return num;
	} else if (ptable->table_type == zcore_tbltype::recipient) {
		num = 0;
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		msg->get_recipient_num(&num);
		return num;
	} else if (ptable->table_type == zcore_tbltype::container) {
		num1 = 0;
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		ct->get_container_table_num((ptable->table_flags & CONVENIENT_DEPTH) ? TRUE : false, &num1);
		return num1;
	} else if (ptable->table_type == zcore_tbltype::abcontusr) {
		num1 = 0;
		auto ct = static_cast<container_object *>(ptable->pparent_obj);
		ct->get_user_table_num(&num1);
		return num1;
	} else if (ptable->table_type == zcore_tbltype::distlist) {
		return static_cast<user_object *>(ptable->pparent_obj)->m_members.size();
	} else if (ptable->table_type == zcore_tbltype::store) {
		return fixed_data != nullptr ? fixed_data->count : 0;
	}
	exmdb_client::sum_table(ptable->pstore->get_dir(),
		ptable->table_id, &total_rows);
	return total_rows;
}

std::unique_ptr<table_object> table_object::create(store_object *pstore,
	void *pparent_obj, zcore_tbltype table_type, uint32_t table_flags)
{
	std::unique_ptr<table_object> ptable;
	try {
		ptable.reset(new table_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	ptable->pstore = pstore;
	if (table_type == zcore_tbltype::rule) {
		auto v = me_alloc<uint64_t>();
		ptable->pparent_obj = v;
		if (NULL == ptable->pparent_obj) {
			return NULL;
		}
		*v = *static_cast<uint64_t *>(pparent_obj);
	} else {
		ptable->pparent_obj = pparent_obj;
	}
	ptable->table_type = table_type;
	ptable->table_flags = table_flags;
	ptable->pcolumns = NULL;
	ptable->psorts = NULL;
	ptable->prestriction = NULL;
	ptable->position = 0;
	ptable->table_id = 0;
	ptable->bookmark_index = 0x100;
	return ptable;
}

table_object::~table_object()
{
	auto ptable = this;
	table_object_reset(ptable);
	if (fixed_data != nullptr)
		tarray_set_free(fixed_data);
	if (ptable->table_type == zcore_tbltype::rule) {
		free(ptable->pparent_obj);
	}
}

BOOL table_object::create_bookmark(uint32_t *pindex) try
{
	auto ptable = this;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	bookmark_node bn;
	if (!exmdb_client::mark_table(ptable->pstore->get_dir(),
	    ptable->table_id, ptable->position,
	    &bn.inst_id, &bn.inst_num, &bn.row_type))
		return FALSE;
	bn.index = ptable->bookmark_index++;
	bn.position = ptable->position;
	bookmark_list.push_back(std::move(bn));
	*pindex = bookmark_list.back().index;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1635: ENOMEM");
	return false;
}

BOOL table_object::retrieve_bookmark(uint32_t index, BOOL *pb_exist)
{
	auto ptable = this;
	uint32_t tmp_type;
	int32_t tmp_position;
	
	if (0 == ptable->table_id) {
		return FALSE;
	}
	auto bn = std::find_if(bookmark_list.cbegin(), bookmark_list.cend(),
	          [&](const bookmark_node &b) { return b.index == index; });
	if (bn == bookmark_list.cend())
		return FALSE;
	if (!exmdb_client::locate_table(ptable->pstore->get_dir(),
	    ptable->table_id, bn->inst_id, bn->inst_num, &tmp_position, &tmp_type))
		return FALSE;
	*pb_exist = FALSE;
	if (tmp_position >= 0) {
		if (tmp_type == bn->row_type)
			*pb_exist = TRUE;
		ptable->position = tmp_position;
	} else {
		ptable->position = bn->position;
	}
	auto total_rows = get_total();
	if (ptable->position > total_rows) {
		ptable->position = total_rows;
	}
	return TRUE;
}

void table_object::remove_bookmark(uint32_t index)
{
	gromox::erase_first_if(bookmark_list,
		[index](const bookmark_node &b) { return b.index == index; });
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

static bool table_object_evaluate_restriction(const TPROPVAL_ARRAY *ppropvals,
    const RESTRICTION *pres)
{
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
		return rcon->comparable() &&
		       rcon->eval(ppropvals->getval(rcon->proptag));
	}
	case RES_PROPERTY: {
		auto rprop = pres->prop;
		if (!rprop->comparable())
			return false;
		auto pvalue = ppropvals->getval(rprop->proptag);
		if (pvalue == nullptr || rprop->proptag != PR_ANR)
			return rprop->eval(pvalue);
		return strcasestr(static_cast<char *>(rprop->propval.pvalue),
		       static_cast<char *>(pvalue)) != nullptr;
	}
	case RES_PROPCOMPARE: {
		auto rprop = pres->pcmp;
		if (!rprop->comparable())
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
		return rbm->comparable() &&
		       rbm->eval(ppropvals->getval(rbm->proptag));
	}
	case RES_SIZE:
		return pres->size->eval(ppropvals->getval(pres->size->proptag));
	case RES_EXIST:
		return ppropvals->has(pres->exist->proptag);
	case RES_COMMENT:
	case RES_ANNOTATION:
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
	TARRAY_SET tmp_set{};
	uint32_t tmp_proptag;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY tmp_proptags;
	
	switch (ptable->table_type) {
	case zcore_tbltype::attachment: {
		auto msg = static_cast<message_object *>(ptable->pparent_obj);
		if (!msg->get_attachment_table_all_proptags(&proptags))
			return FALSE;	
		tmp_proptag = PR_ATTACH_DATA_BIN;
		tmp_proptags.count = 1;
		tmp_proptags.pproptag = &tmp_proptag;
		common_util_reduce_proptags(&proptags, &tmp_proptags);
		if (!msg->query_attachment_table(&proptags, ptable->position, INT32_MAX, &tmp_set))
			return FALSE;	
		break;
	}
	case zcore_tbltype::recipient:
		if (!static_cast<message_object *>(ptable->pparent_obj)->
		    read_recipients(0, 0xFFFF, &tmp_set))
			return FALSE;	
		break;
	case zcore_tbltype::store:
		if (storetbl_refresh(this) != 0)
			return false;
		break;
	case zcore_tbltype::abcontusr:
		container_object_get_user_table_all_proptags(&proptags);
		if (!static_cast<container_object *>(ptable->pparent_obj)->
		    query_user_table(&proptags, ptable->position, INT32_MAX, &tmp_set))
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
		if (!table_object_evaluate_restriction(tmp_set.pparray[i], pres))
			continue;	
		pset->pparray[pset->count++] = tmp_set.pparray[i];
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
	auto pinfo = zs_get_info();
	auto username = ptable->pstore->b_private ? nullptr : pinfo->get_username();
	proptags.count = 2;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PidTagInstID;
	proptag_buff[1] = PidTagInstanceNum;
	return exmdb_client::match_table(ptable->pstore->get_dir(), username,
		pinfo->cpid, ptable->table_id, b_forward,
		ptable->position, pres, &proptags, pposition,
		&tmp_propvals);
}
