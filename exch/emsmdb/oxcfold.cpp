// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "logon_object.h"
#include "processor_types.h"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"
#include "rop_processor.h"
#include "table_object.h"

using namespace gromox;

uint32_t rop_openfolder(uint64_t folder_id, uint8_t open_flags,
    uint8_t *phas_rules, GHOST_SERVER **ppghost, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_del;
	BOOL b_exist;
	void *pvalue;
	uint16_t replid;
	int object_type;
	uint64_t fid_val;
	uint32_t tag_access;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_LOGON && object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	replid = rop_util_get_replid(folder_id);
	if (plogon->is_private()) {
		if (1 != replid) {
			return ecInvalidParam;
		}
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
	if (!exmdb_client::check_folder_id(plogon->get_dir(), folder_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotFound;
	if (!plogon->is_private()) {
		if (!exmdb_client::check_folder_deleted(plogon->get_dir(),
		    folder_id, &b_del))
			return ecError;
		if (b_del && !(open_flags & OPEN_FOLDER_FLAG_OPENSOFTDELETED))
			return ecNotFound;
	}
	if (!exmdb_client::get_folder_property(plogon->get_dir(), 0, folder_id,
	    PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
		return ecError;
	uint8_t type = *static_cast<uint32_t *>(pvalue);
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode == logon_mode::owner) {
		tag_access = MAPI_ACCESS_AllSix;
	} else {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    folder_id, rpc_info.username, &permission))
			return ecError;
		if (permission == rightsNone) {
			fid_val = rop_util_get_gc_value(folder_id);
			if (plogon->is_private()) {
				if (PRIVATE_FID_ROOT == fid_val ||
					PRIVATE_FID_IPMSUBTREE == fid_val) {
					permission = frightsVisible;
				}
			} else {
				if (PUBLIC_FID_ROOT == fid_val) {
					permission = frightsVisible;
				}
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
	if (!exmdb_client::get_folder_property(plogon->get_dir(), 0, folder_id,
	    PR_HAS_RULES, &pvalue))
		return ecError;
	*phas_rules = pvb_enabled(pvalue);
	auto pfolder = folder_object::create(plogon, folder_id, type, tag_access);
	if (pfolder == nullptr)
		return ecServerOOM;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_FOLDER, std::move(pfolder)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	*ppghost = NULL;
	return ecSuccess;
}

uint32_t rop_createfolder(uint8_t folder_type, uint8_t use_unicode,
    uint8_t open_existing, uint8_t reserved, const char *pfolder_name,
    const char *pfolder_comment, uint64_t *pfolder_id, uint8_t *pis_existing,
    uint8_t *phas_rules, GHOST_SERVER **ppghost, LOGMAP *plogmap,
    uint8_t logon_id,  uint32_t hin, uint32_t *phout)
{
	void *pvalue;
	uint64_t tmp_id;
	int object_type;
	BINARY *pentryid;
	uint32_t tmp_type;
	uint64_t last_time;
	uint64_t parent_id;
	uint64_t folder_id;
	uint64_t change_num;
	uint32_t permission;
	char folder_name[256];
	char folder_comment[1024];
	TPROPVAL_ARRAY tmp_propvals;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	
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
	if (object_type != OBJECT_TYPE_FOLDER)
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
			folder_name, sizeof(folder_name)) < 0) {
			return ecInvalidParam;
		}
		if (common_util_convert_string(true, pfolder_comment,
			folder_comment, sizeof(folder_comment)) < 0) {
			return ecInvalidParam;
		}
	} else {
		if (strlen(pfolder_name) >= sizeof(folder_name)) {
			return ecInvalidParam;
		}
		strcpy(folder_name, pfolder_name);
		gx_strlcpy(folder_comment, pfolder_comment, gromox::arsizeof(folder_comment));
	}
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    pparent->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
	}
	if (!exmdb_client::get_folder_by_name(plogon->get_dir(),
	    pparent->folder_id, folder_name, &folder_id))
		return ecError;
	if (0 != folder_id) {
		if (!exmdb_client::get_folder_property(plogon->get_dir(), 0,
		    folder_id, PR_FOLDER_TYPE, &pvalue) || pvalue == nullptr)
			return ecError;
		if (open_existing == 0 ||
		    *static_cast<uint32_t *>(pvalue) != folder_type)
			return ecDuplicateName;
	} else {
		parent_id = pparent->folder_id;
		if (!exmdb_client::allocate_cn(plogon->get_dir(), &change_num))
			return ecError;
		tmp_type = folder_type;
		last_time = rop_util_current_nttime();
		tmp_propvals.count = 9;
		tmp_propvals.ppropval = propval_buff;
		propval_buff[0].proptag = PidTagParentFolderId;
		propval_buff[0].pvalue = &parent_id;
		propval_buff[1].proptag = PR_FOLDER_TYPE;
		propval_buff[1].pvalue = &tmp_type;
		propval_buff[2].proptag = PR_DISPLAY_NAME;
		propval_buff[2].pvalue = folder_name;
		propval_buff[3].proptag = PR_COMMENT;
		propval_buff[3].pvalue = folder_comment;
		propval_buff[4].proptag = PR_CREATION_TIME;
		propval_buff[4].pvalue = &last_time;
		propval_buff[5].proptag = PR_LAST_MODIFICATION_TIME;
		propval_buff[5].pvalue = &last_time;
		propval_buff[6].proptag = PidTagChangeNumber;
		propval_buff[6].pvalue = &change_num;
		propval_buff[7].proptag = PR_CHANGE_KEY;
		propval_buff[7].pvalue = cu_xid_to_bin({plogon->guid(), change_num});
		if (NULL == propval_buff[7].pvalue) {
			return ecServerOOM;
		}
		propval_buff[8].proptag = PR_PREDECESSOR_CHANGE_LIST;
		propval_buff[8].pvalue = common_util_pcl_append(
		                         NULL, static_cast<BINARY *>(propval_buff[7].pvalue));
		if (NULL == propval_buff[8].pvalue) {
			return ecServerOOM;
		}
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (!exmdb_client::create_folder_by_properties(plogon->get_dir(),
		    pinfo->cpid, &tmp_propvals, &folder_id))
			return ecError;
		if (0 == folder_id) {
			return ecError;
		}
		if (plogon->logon_mode != logon_mode::owner) {
			pentryid = common_util_username_to_addressbook_entryid(
												rpc_info.username);
			if (NULL == pentryid) {
				return ecServerOOM;
			}
			tmp_id = 1;
			permission = rightsGromox7;
			permission_row.flags = ROW_ADD;
			permission_row.propvals.count = 3;
			permission_row.propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PR_ENTRYID;
			propval_buff[0].pvalue = pentryid;
			propval_buff[1].proptag = PR_MEMBER_ID;
			propval_buff[1].pvalue = &tmp_id;
			propval_buff[2].proptag = PR_MEMBER_RIGHTS;
			propval_buff[2].pvalue = &permission;
			if (!exmdb_client::update_folder_permission(plogon->get_dir(),
			    folder_id, false, 1, &permission_row))
				return ecError;
		}
	}
	uint32_t tag_access = MAPI_ACCESS_AllSix;
	auto pfolder = folder_object::create(plogon, folder_id, folder_type, tag_access);
	if (pfolder == nullptr)
		return ecServerOOM;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_FOLDER, std::move(pfolder)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	*pfolder_id = folder_id;
	*pis_existing = 0; /* just like exchange 2010 or later */
	/* no need to set value for "phas_rules" */
	*ppghost = NULL;
	return ecSuccess;
}

uint32_t rop_deletefolder(uint8_t flags, uint64_t folder_id,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_done;
	void *pvalue;
	BOOL b_exist;
	BOOL b_partial;
	int object_type;
	uint32_t permission;
	const char *username;
	
	*ppartial_completion = 1;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	 if (plogon->is_private()) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return ecAccessDenied;
		}
	} else {
		if (1 == rop_util_get_replid(folder_id) &&
			rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			return ecAccessDenied;
		}
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto rpc_info = get_rpc_info();
	username = NULL;
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
		username = rpc_info.username;
	}
	if (!exmdb_client::check_folder_id(plogon->get_dir(), folder_id, &b_exist))
		return ecError;
	if (!b_exist) {
		*ppartial_completion = 0;
		return ecSuccess;
	}
	BOOL b_normal = (flags & DEL_MESSAGES) ? TRUE : false;
	BOOL b_fai    = b_normal;
	BOOL b_sub    = (flags & DEL_FOLDERS) ? TRUE : false;
	BOOL b_hard   = (flags & DELETE_HARD_DELETE) ? TRUE : false;
	if (plogon->is_private()) {
		if (!exmdb_client::get_folder_property(plogon->get_dir(), 0,
		    folder_id, PR_FOLDER_TYPE, &pvalue))
			return ecError;
		if (NULL == pvalue) {
			*ppartial_completion = 0;
			return ecSuccess;
		}
		if (*static_cast<uint32_t *>(pvalue) == FOLDER_SEARCH)
			goto DELETE_FOLDER;
	}
	if (b_sub || b_normal || b_fai) {
		if (!exmdb_client::empty_folder(plogon->get_dir(), pinfo->cpid,
		    username, folder_id, b_hard, b_normal, b_fai,
		    b_sub, &b_partial))
			return ecError;
		if (b_partial) {
			/* failure occurs, stop deleting folder */
			*ppartial_completion = 1;
			return ecSuccess;
		}
	}
 DELETE_FOLDER:
	if (!exmdb_client::delete_folder(plogon->get_dir(), pinfo->cpid,
	    folder_id, b_hard, &b_done))
		return ecError;
	*ppartial_completion = !b_done;
	return ecSuccess;
}

uint32_t rop_setsearchcriteria(RESTRICTION *pres,
    const LONGLONG_ARRAY *pfolder_ids, uint32_t search_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	BOOL b_result;
	int object_type;
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
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	if (pfolder->type != FOLDER_SEARCH)
		return ecNotSearchFolder;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    pfolder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (NULL == pres || 0 == pfolder_ids->count) {
		if (!exmdb_client::get_search_criteria(plogon->get_dir(),
		    pfolder->folder_id, &search_status, nullptr, nullptr))
			return ecError;
		if (SEARCH_STATUS_NOT_INITIALIZED == search_status) {
			return ecNotInitialized;
		}
		if (!(search_flags & RESTART_SEARCH) && pres == nullptr &&
		    pfolder_ids->count == 0)
			/* stop static search folder has no meaning,
				status of dynamic running search folder
				cannot be changed */
			return ecSuccess;
	}
	for (size_t i = 0; i < pfolder_ids->count; ++i) {
		if (1 != rop_util_get_replid(pfolder_ids->pll[i])) {
			return ecSearchFolderScopeViolation;
		}
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client::check_folder_permission(plogon->get_dir(),
			    pfolder_ids->pll[i], rpc_info.username, &permission))
				return ecError;
			if (!(permission & (frightsOwner | frightsReadAny)))
				return ecAccessDenied;
		}
	}
	if (pres != nullptr && !common_util_convert_restriction(TRUE, pres))
		return ecError;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::set_search_criteria(plogon->get_dir(), pinfo->cpid,
	    pfolder->folder_id, search_flags, pres, pfolder_ids, &b_result))
		return ecError;
	if (!b_result)
		return ecSearchFolderScopeViolation;
	return ecSuccess;
}

uint32_t rop_getsearchcriteria(uint8_t use_unicode, uint8_t include_restriction,
    uint8_t include_folders, RESTRICTION **ppres, LONGLONG_ARRAY *pfolder_ids,
    uint32_t *psearch_flags, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (!plogon->is_private())
		return ecNotSupported;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
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
	if (!exmdb_client::get_search_criteria(plogon->get_dir(),
	    pfolder->folder_id, psearch_flags, ppres, pfolder_ids))
		return ecError;
	if (use_unicode == 0 && ppres != nullptr && *ppres != nullptr &&
	    !common_util_convert_restriction(false, *ppres))
		return ecError;
	return ecSuccess;
}

uint32_t rop_movecopymessages(const LONGLONG_ARRAY *pmessage_ids,
    uint8_t want_asynchronous, uint8_t want_copy, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	BOOL b_guest;
	EID_ARRAY ids;
	BOOL b_partial;
	int object_type;
	uint32_t permission;
	
	if (0 == pmessage_ids->count) {
		*ppartial_completion = 0;
		return ecSuccess;
	}
	*ppartial_completion = 1;
	auto psrc_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_folder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto pdst_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	if (pdst_folder->type == FOLDER_SEARCH)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	ids.count = pmessage_ids->count;
	ids.pids = pmessage_ids->pll;
	BOOL b_copy = want_copy == 0 ? false : TRUE;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    pdst_folder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsCreate))
			return ecAccessDenied;
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::movecopy_messages(plogon->get_dir(),
	    plogon->account_id, pinfo->cpid, b_guest, rpc_info.username,
	    psrc_folder->folder_id, pdst_folder->folder_id,
	    b_copy, &ids, &b_partial))
		return ecError;
	*ppartial_completion = !!b_partial;
	return ecSuccess;
}

uint32_t rop_movefolder(uint8_t want_asynchronous, uint8_t use_unicode,
    uint64_t folder_id, const char *pnew_name, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_guest;
	BOOL b_partial;
	int object_type;
	BINARY *pbin_pcl;
	uint64_t nt_time;
	char new_name[128];
	uint32_t permission;
	uint64_t change_num;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL propval_buff[4];
	
	*ppartial_completion = 1;
	auto psrc_parent = rop_proc_get_obj<folder_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_parent == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto pdst_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (0 == use_unicode) {
		if (common_util_convert_string(true, pnew_name,
			new_name, sizeof(new_name)) < 0) {
			return ecInvalidParam;
		}
	} else {
		if (strlen(pnew_name) >= sizeof(new_name)) {
			return ecInvalidParam;
		}
		strcpy(new_name, pnew_name);
	}
	auto rpc_info = get_rpc_info();
	if (plogon->is_private()) {
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return ecAccessDenied;
		}
	} else {
		if (rop_util_get_gc_value(folder_id) < PUBLIC_FID_CUSTOM) {
			return ecAccessDenied;
		}
	}
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    pdst_folder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	if (!exmdb_client::check_folder_cycle(plogon->get_dir(), folder_id,
	    pdst_folder->folder_id, &b_cycle))
		return ecError;
	if (b_cycle)
		return ecRootFolder;
	if (!exmdb_client::allocate_cn(plogon->get_dir(), &change_num))
		return ecError;
	if (!exmdb_client::get_folder_property(plogon->get_dir(), 0,
	    folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return ecError;
	auto pbin_changekey = cu_xid_to_bin({plogon->guid(), change_num});
	if (NULL == pbin_changekey) {
		return ecError;
	}
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (NULL == pbin_pcl) {
		return ecError;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::movecopy_folder(plogon->get_dir(),
	    plogon->account_id, pinfo->cpid, b_guest, rpc_info.username,
	    psrc_parent->folder_id, folder_id, pdst_folder->folder_id,
	    new_name, FALSE, &b_exist, &b_partial))
		return ecError;
	if (b_exist)
		return ecDuplicateName;
	*ppartial_completion = !!b_partial;
	nt_time = rop_util_current_nttime();
	propvals.count = 4;
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PidTagChangeNumber;
	propval_buff[0].pvalue = &change_num;
	propval_buff[1].proptag = PR_CHANGE_KEY;
	propval_buff[1].pvalue = pbin_changekey;
	propval_buff[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval_buff[2].pvalue = pbin_pcl;
	propval_buff[3].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[3].pvalue = &nt_time;
	if (!exmdb_client::set_folder_properties(plogon->get_dir(), 0,
	    folder_id, &propvals, &problems))
		return ecError;
	return ecSuccess;
}

uint32_t rop_copyfolder(uint8_t want_asynchronous, uint8_t want_recursive,
    uint8_t use_unicode, uint64_t folder_id, const char *pnew_name,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hsrc, uint32_t hdst)
{
	BOOL b_exist;
	BOOL b_cycle;
	BOOL b_guest;
	BOOL b_partial;
	int object_type;
	char new_name[128];
	uint32_t permission;
	
	*ppartial_completion = 1;
	auto psrc_parent = rop_proc_get_obj<folder_object>(plogmap, logon_id, hsrc, &object_type);
	if (psrc_parent == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto pdst_folder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hdst, &object_type);
	if (pdst_folder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (0 == use_unicode) {
		if (common_util_convert_string(true, pnew_name,
			new_name, sizeof(new_name)) < 0) {
			return ecInvalidParam;
		}
	} else {
		if (strlen(pnew_name) >= sizeof(new_name)) {
			return ecInvalidParam;
		}
		strcpy(new_name, pnew_name);
	}
	auto rpc_info = get_rpc_info();
	if (plogon->is_private()) {
		if (PRIVATE_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			return ecAccessDenied;
		}
	} else {
		if (PUBLIC_FID_ROOT == rop_util_get_gc_value(folder_id)) {
			return ecAccessDenied;
		}
	}
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsReadAny))
			return ecAccessDenied;
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    pdst_folder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreateSubfolder)))
			return ecAccessDenied;
		b_guest = TRUE;
	} else {
		b_guest = FALSE;
	}
	if (!exmdb_client::check_folder_cycle(plogon->get_dir(), folder_id,
	    pdst_folder->folder_id, &b_cycle))
		return ecError;
	if (b_cycle)
		return ecRootFolder;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::movecopy_folder(plogon->get_dir(),
	    plogon->account_id, pinfo->cpid, b_guest, rpc_info.username,
	    psrc_parent->folder_id, folder_id, pdst_folder->folder_id, new_name,
	    TRUE, &b_exist, &b_partial))
		return ecError;
	if (b_exist)
		return ecDuplicateName;
	*ppartial_completion = !!b_partial;
	return ecSuccess;
}

static uint32_t oxcfold_emptyfolder(BOOL b_hard, uint8_t want_delete_associated,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_partial;
	int object_type;
	uint32_t permission;
	const char *username;
	
	*ppartial_completion = 1;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	BOOL b_fai = want_delete_associated == 0 ? false : TRUE;
	auto rpc_info = get_rpc_info();
	if (!plogon->is_private())
		/* just like Exchange 2013 or later */
		return ecNotSupported;
	auto fid_val = rop_util_get_gc_value(pfolder->folder_id);
	if (PRIVATE_FID_ROOT == fid_val ||
		PRIVATE_FID_IPMSUBTREE == fid_val) {
		return ecAccessDenied;
	}
	username = NULL;
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::check_folder_permission(plogon->get_dir(),
		    pfolder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & (frightsDeleteAny | frightsDeleteOwned)))
			return ecAccessDenied;
		username = rpc_info.username;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::empty_folder(plogon->get_dir(), pinfo->cpid,
	    username, pfolder->folder_id,
	    b_hard, TRUE, b_fai, TRUE, &b_partial))
		return ecError;
	*ppartial_completion = !!b_partial;
	return ecSuccess;
}

uint32_t rop_emptyfolder(uint8_t want_asynchronous,
    uint8_t want_delete_associated, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_emptyfolder(FALSE, want_delete_associated,
			ppartial_completion, plogmap, logon_id, hin);	
}

uint32_t rop_harddeletemessagesandsubfolders(uint8_t want_asynchronous,
    uint8_t want_delete_associated, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_emptyfolder(TRUE, want_delete_associated,
			ppartial_completion, plogmap, logon_id, hin);
}

static uint32_t oxcfold_deletemessages(BOOL b_hard, uint8_t want_asynchronous,
    uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_owner;
	EID_ARRAY ids;
	BOOL b_partial;
	BOOL b_partial1;
	int object_type;
	uint32_t permission;
	const char *username;
	MESSAGE_CONTENT *pbrief;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	*ppartial_completion = 1;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode == logon_mode::owner)
		username = NULL;
	else if (!exmdb_client::check_folder_permission(plogon->get_dir(),
	    pfolder->folder_id, rpc_info.username, &permission))
		return ecError;
	else if (permission & (frightsDeleteAny | frightsOwner))
		username = NULL;
	else if (permission & frightsDeleteOwned)
		username = rpc_info.username;
	else
		return ecAccessDenied;
	if (0 == notify_non_read) {
		ids.count = pmessage_ids->count;
		ids.pids = pmessage_ids->pll;
		if (!exmdb_client::delete_messages(plogon->get_dir(),
		    plogon->account_id, pinfo->cpid, username,
		    pfolder->folder_id, &ids, b_hard, &b_partial))
			return ecError;
		*ppartial_completion = !!b_partial;
		return ecSuccess;
	}
	b_partial = FALSE;
	ids.count = 0;
	ids.pids = cu_alloc<uint64_t>(pmessage_ids->count);
	if (NULL == ids.pids) {
		return ecError;
	}
	for (size_t i = 0; i < pmessage_ids->count; ++i) {
		if (NULL != username) {
			if (!exmdb_client::check_message_owner(plogon->get_dir(),
			    pmessage_ids->pll[i], username, &b_owner))
				return ecError;
			if (!b_owner) {
				b_partial = TRUE;
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
		proptag_buff[1] = PR_READ;
		if (!exmdb_client::get_message_properties(plogon->get_dir(),
		    nullptr, 0, pmessage_ids->pll[i], &tmp_proptags, &tmp_propvals))
			return ecError;
		pbrief = NULL;
		auto pvalue = tmp_propvals.get<uint8_t>(PR_NON_RECEIPT_NOTIFICATION_REQUESTED);
		if (pvalue != nullptr && *pvalue != 0) {
			pvalue = tmp_propvals.get<uint8_t>(PR_READ);
			if ((pvalue == nullptr || *pvalue == 0) &&
			    !exmdb_client::get_message_brief(plogon->get_dir(),
			     pinfo->cpid, pmessage_ids->pll[i], &pbrief))
				return ecError;
		}
		ids.pids[ids.count++] = pmessage_ids->pll[i];
		if (NULL != pbrief) {
			common_util_notify_receipt(plogon->get_dir(),
				NOTIFY_RECEIPT_NON_READ, pbrief);
		}
	}
	if (!exmdb_client::delete_messages(plogon->get_dir(), plogon->account_id,
	    pinfo->cpid, username, pfolder->folder_id, &ids, b_hard, &b_partial1))
		return ecError;
	*ppartial_completion = b_partial || b_partial1;
	return ecSuccess;
}

uint32_t rop_deletemessages(uint8_t want_asynchronous, uint8_t notify_non_read,
    const LONGLONG_ARRAY *pmessage_ids, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_deletemessages(FALSE, want_asynchronous,
			notify_non_read, pmessage_ids, ppartial_completion,
			plogmap, logon_id, hin);
}

uint32_t rop_harddeletemessages(uint8_t want_asynchronous,
    uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
    uint8_t *ppartial_completion, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	return oxcfold_deletemessages(TRUE, want_asynchronous,
			notify_non_read, pmessage_ids, ppartial_completion,
			plogmap, logon_id, hin);
}

uint32_t rop_gethierarchytable(uint8_t table_flags, uint32_t *prow_count,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int object_type;
	
	if (table_flags & (~(TABLE_FLAG_DEPTH | TABLE_FLAG_DEFERREDERRORS |
		TABLE_FLAG_NONOTIFICATIONS | TABLE_FLAG_SOFTDELETES |
		TABLE_FLAG_USEUNICODE | TABLE_FLAG_SUPPRESSNOTIFICATIONS))) {
		return ecInvalidParam;
	}
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	BOOL b_depth = (table_flags & TABLE_FLAG_DEPTH) ? TRUE : false;
	auto rpc_info = get_rpc_info();
	auto username = plogon->logon_mode == logon_mode::owner ? nullptr : rpc_info.username;
	if (!exmdb_client::sum_hierarchy(plogon->get_dir(), pfolder->folder_id,
	    username, b_depth, prow_count))
		return ecError;
	auto ptable = table_object::create(plogon, pfolder, table_flags,
	              ropGetHierarchyTable, logon_id);
	if (ptable == nullptr)
		return ecServerOOM;
	auto rtable = ptable.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_TABLE, std::move(ptable)});
	if (hnd < 0)
		return ecError;
	rtable->set_handle(hnd);
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_getcontentstable(uint8_t table_flags, uint32_t *prow_count,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_fai;
	int object_type;
	uint32_t permission;
	BOOL b_conversation;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	b_conversation = FALSE;
	if (plogon->is_private()) {
		if (pfolder->folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
		    (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS))
			b_conversation = TRUE;
	} else {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
			b_conversation = TRUE;
		}
	}
	if (!b_conversation && (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS))
		return ecInvalidParam;
	if (table_flags & TABLE_FLAG_ASSOCIATED) {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
			return ecInvalidParam;
		}
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	BOOL b_deleted = (table_flags & TABLE_FLAG_SOFTDELETES) ? TRUE : false;
	if (!b_conversation) {
		auto rpc_info = get_rpc_info();
		if (plogon->logon_mode != logon_mode::owner) {
			if (!exmdb_client::check_folder_permission(plogon->get_dir(),
			    pfolder->folder_id, rpc_info.username, &permission))
				return ecError;
			if (!(permission & (frightsReadAny | frightsOwner)))
				return ecAccessDenied;
		}
		if (!exmdb_client::sum_content(plogon->get_dir(),
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
	           logon_id, hin, {OBJECT_TYPE_TABLE, std::move(ptable)});
	if (hnd < 0)
		return ecError;
	rtable->set_handle(hnd);
	*phout = hnd;
	return ecSuccess;
}
