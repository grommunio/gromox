// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "folder_object.hpp"
#include "logon_object.hpp"
#include "processor_types.hpp"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"
#include "rop_processor.hpp"
#include "table_object.hpp"

using namespace gromox;

ec_error_t rop_openfolder(uint64_t folder_id, uint8_t open_flags,
    uint8_t *phas_rules, GHOST_SERVER **ppghost, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_del;
	BOOL b_exist;
	void *pvalue;
	uint16_t replid;
	ems_objtype object_type;
	uint64_t fid_val;
	uint32_t tag_access;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::logon && object_type != ems_objtype::folder)
		return ecNotSupported;
	replid = rop_util_get_replid(folder_id);
	if (plogon->is_private()) {
		if (replid != 1)
			return ecInvalidParam;
	} else {
		if (1 != replid) {
			*phas_rules = 0;
			*ppghost = cu_alloc<GHOST_SERVER>();
			if (*ppghost == nullptr)
				return ecServerOOM;
			return rop_getowningservers(folder_id,
					*ppghost, plogmap, logon_id, hin);
		}
	}
	auto dir = plogon->get_dir();
	if (!exmdb_client->is_folder_present(dir, folder_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotFound;
	if (!plogon->is_private()) {
		if (!exmdb_client->is_folder_deleted(dir, folder_id, &b_del))
			return ecError;
		if (b_del && !(open_flags & OPEN_MODE_FLAG_OPENSOFTDELETE))
			return ecNotFound;
	}
	if (!exmdb_client->get_folder_property(dir, CP_ACP, folder_id,
	    PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
		return ecError;
	uint8_t type = *static_cast<uint32_t *>(pvalue);
	auto username = plogon->eff_user();
	if (username == STORE_OWNER_GRANTED) {
		tag_access = MAPI_ACCESS_AllSix;
	} else {
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, username, &permission))
			return ecError;
		if (permission == rightsNone) {
			fid_val = rop_util_get_gc_value(folder_id);
			if (plogon->is_private()) {
				if (fid_val == PRIVATE_FID_ROOT ||
				    fid_val == PRIVATE_FID_IPMSUBTREE)
					permission = frightsVisible;
			} else {
				if (fid_val == PUBLIC_FID_ROOT)
					permission = frightsVisible;
			}
		}
		if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
			/* same as Exchange 2013, not ecAccessDenied */
			return ecNotFound;
		if (permission & frightsOwner) {
			tag_access = MAPI_ACCESS_AllSix;
		} else {
			tag_access = MAPI_ACCESS_READ;
			if (permission & frightsCreate)
				tag_access |= MAPI_ACCESS_CREATE_CONTENTS | MAPI_ACCESS_CREATE_ASSOCIATED;
			if (permission & frightsCreateSubfolder)
				tag_access |= MAPI_ACCESS_CREATE_HIERARCHY;
		}
	}
	if (!exmdb_client->get_folder_property(dir, CP_ACP, folder_id,
	    PR_HAS_RULES, &pvalue))
		return ecError;
	*phas_rules = pvb_enabled(pvalue);
	auto pfolder = folder_object::create(plogon, folder_id, type, tag_access);
	if (pfolder == nullptr)
		return ecServerOOM;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::folder, std::move(pfolder)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	*ppghost = NULL;
	return ecSuccess;
}

ec_error_t rop_createfolder(uint8_t folder_type, uint8_t use_unicode,
    uint8_t open_existing, uint8_t reserved, const char *pfolder_name,
    const char *pfolder_comment, uint64_t *pfolder_id, uint8_t *pis_existing,
    uint8_t *phas_rules, GHOST_SERVER **ppghost, LOGMAP *plogmap,
    uint8_t logon_id,  uint32_t hin, uint32_t *phout)
{
	void *pvalue;
	ems_objtype object_type;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	char folder_name[256];
	char folder_comment[1024];
	
	switch (folder_type) {
	case FOLDER_GENERIC:
	case FOLDER_SEARCH:
		break;
	default:
		return ecInvalidParam;
	}
	auto pparent = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pparent == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	if (rop_util_get_replid(pparent->folder_id) != 1)
		return ecAccessDenied;
	if (pparent->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private() && folder_type == FOLDER_SEARCH)
		return ecNotSupported;
	if (0 == use_unicode) {
		if (common_util_convert_string(true, pfolder_name,
		    folder_name, sizeof(folder_name)) < 0)
			return ecInvalidParam;
		if (common_util_convert_string(true, pfolder_comment,
		    folder_comment, sizeof(folder_comment)) < 0)
			return ecInvalidParam;
	} else {
		if (strlen(pfolder_name) >= sizeof(folder_name))
			return ecInvalidParam;
		strcpy(folder_name, pfolder_name);
		gx_strlcpy(folder_comment, pfolder_comment, std::size(folder_comment));
	}
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    pparent->folder_id, username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
	}
	if (!exmdb_client->get_folder_by_name(plogon->get_dir(),
	    pparent->folder_id, folder_name, &folder_id))
		return ecError;
	if (0 != folder_id) {
		if (!exmdb_client->get_folder_property(plogon->get_dir(), CP_ACP,
		    folder_id, PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
			return ecError;
		if (open_existing == 0 ||
		    *static_cast<uint32_t *>(pvalue) != folder_type)
			return ecDuplicateName;
	} else {
		parent_id = pparent->folder_id;
		if (!exmdb_client->allocate_cn(plogon->get_dir(), &change_num))
			return ecError;
		uint32_t tmp_type = folder_type;
		auto last_time = rop_util_current_nttime();
		TAGGED_PROPVAL propval_buff[] = {
			{PidTagParentFolderId, &parent_id},
			{PR_FOLDER_TYPE, &tmp_type},
			{PR_DISPLAY_NAME, folder_name},
			{PR_COMMENT, folder_comment},
			{PR_CREATION_TIME, &last_time},
			{PR_LAST_MODIFICATION_TIME, &last_time},
			{PidTagChangeNumber, &change_num},
			{PR_CHANGE_KEY, nullptr},
			{PR_PREDECESSOR_CHANGE_LIST, nullptr},
		};
		const TPROPVAL_ARRAY tmp_propvals =
			{std::size(propval_buff), deconst(propval_buff)};
		/* PR_CHANGE_KEY */
		propval_buff[7].pvalue = cu_xid_to_bin({plogon->guid(), change_num});
		if (propval_buff[7].pvalue == nullptr)
			return ecServerOOM;
		propval_buff[8].pvalue = common_util_pcl_append(
		                         NULL, static_cast<BINARY *>(propval_buff[7].pvalue));
		if (propval_buff[8].pvalue == nullptr)
			return ecServerOOM;
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		ec_error_t err = ecSuccess;
		if (!exmdb_client->create_folder(plogon->get_dir(), pinfo->cpid,
		    &tmp_propvals, &folder_id, &err))
			return ecError;
		if (err != ecSuccess)
			return err;
		if (folder_id == 0)
			return ecError;
		if (username != STORE_OWNER_GRANTED) {
			auto pentryid = common_util_username_to_addressbook_entryid(username);
			if (pentryid == nullptr)
				return ecServerOOM;
			uint64_t tmp_id = 1;
			uint32_t permission = rightsGromox7;
			const TAGGED_PROPVAL propval_buff2[] = {
				{PR_ENTRYID, pentryid},
				{PR_MEMBER_ID, &tmp_id},
				{PR_MEMBER_RIGHTS, &permission},
			};
			const PERMISSION_DATA permission_row =
				{ROW_ADD, {std::size(propval_buff2), deconst(propval_buff2)}};
			if (!exmdb_client->update_folder_permission(plogon->get_dir(),
			    folder_id, false, 1, &permission_row))
				return ecError;
		}
	}
	uint32_t tag_access = MAPI_ACCESS_AllSix;
	auto pfolder = folder_object::create(plogon, folder_id, folder_type, tag_access);
	if (pfolder == nullptr)
		return ecServerOOM;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::folder, std::move(pfolder)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	*phout = hnd;
	*pfolder_id = folder_id;
	*pis_existing = 0; /* just like exchange 2010 or later */
	/* no need to set value for "phas_rules" */
	*ppghost = NULL;
	return ecSuccess;
}

ec_error_t rop_deletefolder(uint8_t flags, uint64_t folder_id,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_done;
	void *pvalue;
	BOOL b_exist;
	BOOL b_partial;
	ems_objtype object_type;
	uint32_t permission;
	
	*ppartial_completion = 1;
	flags &= ~GX_DELMSG_NOTIFY_UNREAD;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	 if (plogon->is_private()) {
		if (rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
			return ecAccessDenied;
	} else {
		if (rop_util_get_replid(folder_id) == 1 &&
		    rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
			return ecAccessDenied;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED) {
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    folder_id, username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (!exmdb_client->is_folder_present(plogon->get_dir(), folder_id, &b_exist))
		return ecError;
	if (!b_exist) {
		*ppartial_completion = 0;
		return ecSuccess;
	}
	if (flags & DEL_MESSAGES)
		/*
		 * MAPI has the %DEL_ASSOCIATED associated flag, but its use is
		 * not specified for IMAPIFolder::DeleteFolder. Consequently,
		 * %DEL_ASSOCIATED is not specified in OXCROPS either.
		 * Deletion of FAI is implicit in the specs' wording though.
		 */
		flags |= DEL_ASSOCIATED;
	if (plogon->is_private()) {
		if (!emsmdb_pvt_folder_softdel)
			flags |= DELETE_HARD_DELETE;
		if (!exmdb_client->get_folder_property(plogon->get_dir(),
		    CP_ACP, folder_id, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (NULL == pvalue) {
			*ppartial_completion = 0;
			return ecSuccess;
		}
		if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
			goto DELETE_FOLDER;
	}
	if (flags & (DEL_FOLDERS | DEL_MESSAGES | DEL_ASSOCIATED)) {
		if (!exmdb_client->empty_folder(plogon->get_dir(), pinfo->cpid,
		    username, folder_id, flags, &b_partial))
			return ecError;
		if (b_partial) {
			/* failure occurs, stop deleting folder */
			*ppartial_completion = 1;
			return ecSuccess;
		}
	}
 DELETE_FOLDER:
	if (!exmdb_client->delete_folder(plogon->get_dir(), pinfo->cpid,
	    folder_id, (flags & DELETE_HARD_DELETE) ? TRUE : false, &b_done))
		return ecError;
	*ppartial_completion = !b_done;
	return ecSuccess;
}

ec_error_t rop_setsearchcriteria(RESTRICTION *pres,
    const LONGLONG_ARRAY *pfolder_ids, uint32_t search_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	BOOL b_result;
	ems_objtype object_type;
	uint32_t permission;
	uint32_t search_status;
	
	if (!(search_flags & (RESTART_SEARCH | STOP_SEARCH)))
		/* make the default search_flags */
		search_flags |= STOP_SEARCH;
	if (!(search_flags & (RECURSIVE_SEARCH | SHALLOW_SEARCH)))
		/* make the default search_flags */
		search_flags |= SHALLOW_SEARCH;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	if (pfolder->type != FOLDER_SEARCH)
		return ecNotSearchFolder;
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED) {
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    pfolder->folder_id, username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (NULL == pres || 0 == pfolder_ids->count) {
		if (!exmdb_client->get_search_criteria(plogon->get_dir(),
		    pfolder->folder_id, &search_status, nullptr, nullptr))
			return ecError;
		if (search_status == SEARCH_STATUS_NOT_INITIALIZED)
			return ecNotInitialized;
		if (!(search_flags & RESTART_SEARCH) && pres == nullptr &&
		    pfolder_ids->count == 0)
			/* stop static search folder has no meaning,
				status of dynamic running search folder
				cannot be changed */
			return ecSuccess;
	}
	for (size_t i = 0; i < pfolder_ids->count; ++i) {
		if (rop_util_get_replid(pfolder_ids->pll[i]) != 1)
			return ecSearchFolderScopeViolation;
		if (username != STORE_OWNER_GRANTED) {
			if (!exmdb_client->get_folder_perm(plogon->get_dir(),
			    pfolder_ids->pll[i], username, &permission))
				return ecError;
			if (!(permission & (frightsOwner | frightsReadAny)))
				return ecAccessDenied;
		}
	}
	if (pres != nullptr && !common_util_convert_restriction(TRUE, pres))
		return ecError;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client->set_search_criteria(plogon->get_dir(), pinfo->cpid,
	    pfolder->folder_id, search_flags, pres, pfolder_ids, &b_result))
		return ecError;
	if (!b_result)
		return ecSearchFolderScopeViolation;
	return ecSuccess;
}

ec_error_t rop_getsearchcriteria(uint8_t use_unicode, uint8_t include_restriction,
    uint8_t include_folders, RESTRICTION **ppres, LONGLONG_ARRAY *pfolder_ids,
    uint32_t *psearch_flags, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	if (pfolder->type != FOLDER_SEARCH)
		return ecNotSearchFolder;
	if (0 == include_restriction) {
		*ppres = NULL;
		ppres = NULL;
	}
	if (0 == include_folders) {
		pfolder_ids->count = 0;
		pfolder_ids = NULL;
	}
	if (!exmdb_client->get_search_criteria(plogon->get_dir(),
	    pfolder->folder_id, psearch_flags, ppres, pfolder_ids))
		return ecError;
	if (use_unicode == 0 && ppres != nullptr && *ppres != nullptr &&
	    !common_util_convert_restriction(false, *ppres))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_movecopymessages(const LONGLONG_ARRAY *pmessage_ids,
    uint8_t want_asynchronous, uint8_t want_copy, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	BOOL b_partial;
	ems_objtype object_type;
	uint32_t permission;
	
	if (0 == pmessage_ids->count) {
		*ppartial_completion = 0;
		return ecSuccess;
	}
	*ppartial_completion = 1;
	auto psrc_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_folder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto pdst_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	if (pdst_folder->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	BOOL b_copy = want_copy == 0 ? false : TRUE;
	auto rpc_user = znul(get_rpc_info().username);
	auto eff_user = plogon->eff_user();
	BOOL b_guest  = eff_user != STORE_OWNER_GRANTED ? TRUE : false;
	if (b_guest) {
		if (!exmdb_client->get_folder_perm(plogon->get_dir(),
		    pdst_folder->folder_id, eff_user, &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	const EID_ARRAY ids = {pmessage_ids->count, pmessage_ids->pll};
	if (!exmdb_client->movecopy_messages(plogon->get_dir(), pinfo->cpid,
	    b_guest, rpc_user, psrc_folder->folder_id, pdst_folder->folder_id,
	    b_copy, &ids, &b_partial))
		return ecError;
	*ppartial_completion = !!b_partial;
	return ecSuccess;
}

ec_error_t rop_movefolder(uint8_t want_asynchronous, uint8_t use_unicode,
    uint64_t folder_id, const char *pnew_name, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	ems_objtype object_type;
	char new_name[128];
	
	*ppartial_completion = 1;
	auto psrc_parent = rop_proc_get_obj<folder_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_parent == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto pdst_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (0 == use_unicode) {
		if (common_util_convert_string(true, pnew_name,
		    new_name, sizeof(new_name)) < 0)
			return ecInvalidParam;
	} else {
		if (strlen(pnew_name) >= sizeof(new_name))
			return ecInvalidParam;
		strcpy(new_name, pnew_name);
	}
	if (rop_util_get_gc_value(folder_id) < CUSTOM_EID_BEGIN)
		return ecAccessDenied;
	auto dir = plogon->get_dir();
	auto rpc_user = znul(get_rpc_info().username);
	auto eff_user = plogon->eff_user();
	BOOL b_guest  = eff_user != STORE_OWNER_GRANTED ? TRUE : false;
	if (b_guest) {
		uint32_t permission = 0;
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, eff_user, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
		if (!exmdb_client->get_folder_perm(dir,
		    pdst_folder->folder_id, eff_user, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
	}

	BOOL b_cycle = false;
	uint64_t change_num;
	BINARY *pbin_pcl;
	if (!exmdb_client->is_descendant_folder(dir, folder_id,
	    pdst_folder->folder_id, &b_cycle))
		return ecError;
	if (b_cycle)
		return ecRootFolder;
	if (!exmdb_client->allocate_cn(dir, &change_num))
		return ecError;
	if (!exmdb_client->get_folder_property(dir, CP_ACP,
	    folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)))
		return ecError;
	auto pbin_changekey = cu_xid_to_bin({plogon->guid(), change_num});
	if (pbin_changekey == nullptr)
		return ecError;
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (pbin_pcl == nullptr)
		return ecError;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	ec_error_t err = ecSuccess;
	if (!exmdb_client->movecopy_folder(dir, pinfo->cpid, b_guest, rpc_user,
	    psrc_parent->folder_id, folder_id, pdst_folder->folder_id, new_name,
	    false, &err))
		return ecError;
	if (err == ecDuplicateName)
		return err;

	*ppartial_completion = err != ecSuccess;
	auto nt_time = rop_util_current_nttime();
	const TAGGED_PROPVAL propval_buff[] = {
		{PidTagChangeNumber, &change_num},
		{PR_CHANGE_KEY, pbin_changekey},
		{PR_PREDECESSOR_CHANGE_LIST, pbin_pcl},
		{PR_LAST_MODIFICATION_TIME, &nt_time},
	};
	const TPROPVAL_ARRAY propvals = {std::size(propval_buff), deconst(propval_buff)};
	PROBLEM_ARRAY problems;
	if (!exmdb_client->set_folder_properties(dir, CP_ACP,
	    folder_id, &propvals, &problems))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_copyfolder(uint8_t want_asynchronous, uint8_t want_recursive,
    uint8_t use_unicode, uint64_t folder_id, const char *pnew_name,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hsrc, uint32_t hdst)
{
	BOOL b_cycle;
	ems_objtype object_type;
	char new_name[128];
	uint32_t permission;
	
	*ppartial_completion = 1;
	auto psrc_parent = rop_proc_get_obj<folder_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_parent == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto pdst_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (0 == use_unicode) {
		if (common_util_convert_string(true, pnew_name,
		    new_name, sizeof(new_name)) < 0)
			return ecInvalidParam;
	} else {
		if (strlen(pnew_name) >= sizeof(new_name))
			return ecInvalidParam;
		strcpy(new_name, pnew_name);
	}
	if (rop_util_get_gc_value(folder_id) ==
	    (plogon->is_private() ? PRIVATE_FID_ROOT : PUBLIC_FID_ROOT))
		return ecAccessDenied;
	auto dir = plogon->get_dir();
	auto rpc_user = znul(get_rpc_info().username);
	auto eff_user = plogon->eff_user();
	BOOL b_guest  = eff_user != STORE_OWNER_GRANTED ? TRUE : false;
	if (b_guest) {
		if (!exmdb_client->get_folder_perm(dir,
		    folder_id, eff_user, &permission))
			return ecError;
		if (!(permission & frightsReadAny))
			return ecAccessDenied;
		if (!exmdb_client->get_folder_perm(dir,
		    pdst_folder->folder_id, eff_user, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
	}
	if (!exmdb_client->is_descendant_folder(dir, folder_id,
	    pdst_folder->folder_id, &b_cycle))
		return ecError;
	if (b_cycle)
		return ecRootFolder;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	ec_error_t err = ecSuccess;
	if (!exmdb_client->movecopy_folder(dir, pinfo->cpid, b_guest, rpc_user,
	    psrc_parent->folder_id, folder_id, pdst_folder->folder_id, new_name,
	    TRUE, &err))
		return ecError;
	if (err == ecDuplicateName)
		return err;
	*ppartial_completion = err != ecSuccess;
	return ecSuccess;
}

static ec_error_t oxcfold_emptyfolder(unsigned int flags,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_partial;
	ems_objtype object_type;
	uint32_t permission;
	
	*ppartial_completion = 1;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto dir = plogon->get_dir();
	auto username = plogon->eff_user();
	if (username != STORE_OWNER_GRANTED) {
		if (!exmdb_client->get_folder_perm(dir,
		    pfolder->folder_id, username, &permission))
			return ecError;
		if (!(permission & (frightsDeleteAny | frightsDeleteOwned)))
			return ecAccessDenied;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client->empty_folder(dir, pinfo->cpid, username,
	    pfolder->folder_id, flags | DEL_MESSAGES | DEL_FOLDERS, &b_partial))
		return ecError;
	*ppartial_completion = !!b_partial;
	return ecSuccess;
}

ec_error_t rop_emptyfolder(uint8_t want_asynchronous,
    uint8_t want_delete_associated, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_emptyfolder(want_delete_associated ? DEL_ASSOCIATED : 0,
			ppartial_completion, plogmap, logon_id, hin);	
}

ec_error_t rop_harddeletemessagesandsubfolders(uint8_t want_asynchronous,
    uint8_t want_delete_associated, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_emptyfolder(DELETE_HARD_DELETE | (want_delete_associated ? DEL_ASSOCIATED : 0),
			ppartial_completion, plogmap, logon_id, hin);
}

static ec_error_t oxcfold_deletemessages(BOOL b_hard, uint8_t want_asynchronous,
    uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_owner;
	BOOL b_partial;
	BOOL b_partial1;
	ems_objtype object_type;
	uint32_t permission;
	MESSAGE_CONTENT *pbrief;
	
	*ppartial_completion = 1;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto dir = plogon->get_dir();
	auto username = plogon->eff_user();
	if (username == STORE_OWNER_GRANTED)
		/* nothing */;
	else if (!exmdb_client->get_folder_perm(dir,
	    pfolder->folder_id, username, &permission))
		return ecError;
	else if (permission & (frightsDeleteAny | frightsOwner))
		username = STORE_OWNER_GRANTED;
	else if (permission & frightsDeleteOwned)
		/* nothing */;
	else
		return ecAccessDenied;
	if (0 == notify_non_read) {
		const EID_ARRAY ids = {pmessage_ids->count, pmessage_ids->pll};
		if (!exmdb_client->delete_messages(dir, pinfo->cpid,
		    username, pfolder->folder_id, &ids, b_hard, &b_partial))
			return ecError;
		*ppartial_completion = !!b_partial;
		return ecSuccess;
	}
	b_partial = FALSE;
	EID_ARRAY ids = {0, cu_alloc<uint64_t>(pmessage_ids->count)};
	if (ids.pids == nullptr)
		return ecError;
	for (size_t i = 0; i < pmessage_ids->count; ++i) {
		if (username != STORE_OWNER_GRANTED) {
			if (!exmdb_client->is_message_owner(dir,
			    pmessage_ids->pll[i], username, &b_owner))
				return ecError;
			if (!b_owner) {
				b_partial = TRUE;
				continue;
			}
		}
		static constexpr proptag_t proptag_buff[] = {PR_NON_RECEIPT_NOTIFICATION_REQUESTED, PR_READ};
		static constexpr PROPTAG_ARRAY tmp_proptags = {std::size(proptag_buff), deconst(proptag_buff)};
		TPROPVAL_ARRAY tmp_propvals;
		if (!exmdb_client->get_message_properties(dir, nullptr, CP_ACP,
		    pmessage_ids->pll[i], &tmp_proptags, &tmp_propvals))
			return ecError;
		pbrief = NULL;
		auto pvalue = tmp_propvals.get<uint8_t>(PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
		if (pvalue != nullptr && *pvalue != 0) {
			pvalue = tmp_propvals.get<uint8_t>(PR_READ);
			if ((pvalue == nullptr || *pvalue == 0) &&
			    !exmdb_client->get_message_brief(dir,
			     pinfo->cpid, pmessage_ids->pll[i], &pbrief))
				return ecError;
		}
		ids.pids[ids.count++] = pmessage_ids->pll[i];
		if (pbrief != nullptr)
			common_util_notify_receipt(dir,
				NOTIFY_RECEIPT_NON_READ, pbrief);
	}
	if (!exmdb_client->delete_messages(dir, pinfo->cpid, username,
	    pfolder->folder_id, &ids, b_hard, &b_partial1))
		return ecError;
	*ppartial_completion = b_partial || b_partial1;
	return ecSuccess;
}

ec_error_t rop_deletemessages(uint8_t want_asynchronous, uint8_t notify_non_read,
    const LONGLONG_ARRAY *pmessage_ids, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_deletemessages(FALSE, want_asynchronous,
			notify_non_read, pmessage_ids, ppartial_completion,
			plogmap, logon_id, hin);
}

ec_error_t rop_harddeletemessages(uint8_t want_asynchronous,
    uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_deletemessages(TRUE, want_asynchronous,
			notify_non_read, pmessage_ids, ppartial_completion,
			plogmap, logon_id, hin);
}

ec_error_t rop_gethierarchytable(uint8_t table_flags, uint32_t *prow_count,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	
	if (table_flags & (~(TABLE_FLAG_DEPTH | MAPI_DEFERRED_ERRORS |
	    TABLE_FLAG_NONOTIFICATIONS | TABLE_FLAG_SOFTDELETES |
	    TABLE_FLAG_USEUNICODE | TABLE_FLAG_SUPPRESSNOTIFICATIONS)))
		return ecInvalidParam;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	BOOL b_depth = (table_flags & TABLE_FLAG_DEPTH) ? TRUE : false;
	if (!exmdb_client->sum_hierarchy(plogon->get_dir(), pfolder->folder_id,
	    plogon->eff_user(), b_depth, prow_count))
		return ecError;
	auto ptable = table_object::create(plogon, pfolder, table_flags,
	              ropGetHierarchyTable, logon_id);
	if (ptable == nullptr)
		return ecServerOOM;
	auto rtable = ptable.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::table, std::move(ptable)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	rtable->set_handle(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_getcontentstable(uint8_t table_flags, uint32_t *prow_count,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_fai;
	ems_objtype object_type;
	uint32_t permission;
	BOOL b_conversation;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::folder)
		return ecNotSupported;
	b_conversation = FALSE;
	if (plogon->is_private()) {
		if (pfolder->folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
		    (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS))
			b_conversation = TRUE;
	} else {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS)
			b_conversation = TRUE;
	}
	if (!b_conversation && (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS))
		return ecInvalidParam;
	if (table_flags & TABLE_FLAG_ASSOCIATED) {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS)
			return ecInvalidParam;
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	BOOL b_deleted = (table_flags & TABLE_FLAG_SOFTDELETES) ? TRUE : false;
	if (!b_conversation) {
		auto username = plogon->eff_user();
		if (username != STORE_OWNER_GRANTED) {
			if (!exmdb_client->get_folder_perm(plogon->get_dir(),
			    pfolder->folder_id, username, &permission))
				return ecError;
			if (!(permission & (frightsReadAny | frightsOwner)))
				return ecAccessDenied;
		}
		if (!exmdb_client->sum_content(plogon->get_dir(),
		    pfolder->folder_id, b_fai, b_deleted, prow_count))
			return ecError;
	} else {
		*prow_count = 1; /* arbitrary value */
	}
	auto ptable = table_object::create(plogon, pfolder, table_flags,
	              ropGetContentsTable, logon_id);
	if (ptable == nullptr)
		return ecServerOOM;
	auto rtable = ptable.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::table, std::move(ptable)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	rtable->set_handle(hnd);
	*phout = hnd;
	if (table_flags & MAPI_DEFERRED_ERRORS)
		/* Inaccurate rowcount permissible under OXCFOLD v23.2 §2.2.1.14.1 */
		return ecSuccess;
	/*
	 * Inaccurate rowcounts crash OL's "Recover Deleted Items" dialog.
	 * Perform the hard work early on, then.
	 */
	if (!rtable->load())
		return ecError;
	*prow_count = rtable->get_total();
	return ecSuccess;
}
