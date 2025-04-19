// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
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
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "folder_object.hpp"
#include "logon_object.hpp"

using namespace gromox;

std::unique_ptr<folder_object> folder_object::create(logon_object *plogon,
	uint64_t folder_id, uint8_t type, uint32_t tag_access)
{
	std::unique_ptr<folder_object> pfolder;
	try {
		pfolder.reset(new folder_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pfolder->plogon = plogon;
	pfolder->folder_id = folder_id;
	pfolder->type = type;
	pfolder->tag_access = tag_access;
	return pfolder;
}

static bool toplevel(uint64_t f)
{
	return f == rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) ||
	       f == rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);
}

BOOL folder_object::get_all_proptags(PROPTAG_ARRAY *pproptags) const
{
	auto pfolder = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client->get_folder_all_proptags(pfolder->plogon->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;		
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 15);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	/* Folders are not supposed to have namedprops */
	auto eop = std::copy_if(tmp_proptags.begin(), tmp_proptags.end(),
	           pproptags->pproptag, [](uint32_t x) { return x < 0x80000000; });
	pproptags->count = eop - pproptags->pproptag;
	memcpy(pproptags->pproptag, tmp_proptags.pproptag, sizeof(proptag_t) * tmp_proptags.count);
	static constexpr proptag_t tags1[] = {
		PR_ACCESS, PR_RIGHTS, PR_PARENT_ENTRYID, PR_PARENT_SOURCE_KEY,
		PR_SOURCE_KEY,
	};
	for (auto t : tags1)
		pproptags->emplace_back(t);
	static constexpr proptag_t tags2[] = {
		PR_IPM_DRAFTS_ENTRYID, PR_IPM_CONTACT_ENTRYID,
		PR_IPM_APPOINTMENT_ENTRYID, PR_IPM_JOURNAL_ENTRYID,
		PR_IPM_NOTE_ENTRYID, PR_IPM_TASK_ENTRYID, PR_FREEBUSY_ENTRYIDS,
		PR_ADDITIONAL_REN_ENTRYIDS, PR_ADDITIONAL_REN_ENTRYIDS_EX,
	};
	if (pfolder->plogon->is_private() && toplevel(pfolder->folder_id))
		for (auto t : tags2)
			pproptags->emplace_back(t);
	std::sort(pproptags->begin(), pproptags->end());
	pproptags->count = std::unique(pproptags->begin(), pproptags->end()) - pproptags->begin();
	return TRUE;
}

bool folder_object::is_readonly_prop(proptag_t proptag) const
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return true;
	switch (proptag) {
	case PR_ACCESS:
	case PR_ADDRESS_BOOK_ENTRYID:
	case PR_INTERNET_ARTICLE_NUMBER_NEXT:
	case PR_ASSOC_CONTENT_COUNT:
	case PR_ATTR_READONLY:
	case PidTagChangeNumber:
	case PR_CONTENT_COUNT:
	case PR_CONTENT_UNREAD:
	case PR_CREATION_TIME:
	case PR_DELETED_COUNT_TOTAL:
	case PR_DELETED_FOLDER_COUNT:
	case PR_DELETED_ON:
	case PR_ENTRYID:
	case PR_FOLDER_CHILD_COUNT:
	case PR_FOLDER_FLAGS:
	case PidTagFolderId:
	case PR_FOLDER_TYPE:
	case PR_HAS_RULES:
	case PR_HIERARCHY_CHANGE_NUM:
	case PR_HIER_REV:
	case PR_INTERNET_ARTICLE_NUMBER:
	case PR_LOCAL_COMMIT_TIME:
	case PR_LOCAL_COMMIT_TIME_MAX:
	case PR_MESSAGE_SIZE:
	case PR_MESSAGE_SIZE_EXTENDED:
	case PR_ASSOC_MESSAGE_SIZE:
	case PR_ASSOC_MESSAGE_SIZE_EXTENDED:
	case PR_NORMAL_MESSAGE_SIZE:
	case PR_NORMAL_MESSAGE_SIZE_EXTENDED:
	case PR_PARENT_ENTRYID:
	case PidTagParentFolderId:
	case PR_STORE_RECORD_KEY:
	case PR_CHANGE_KEY:
	case PR_SOURCE_KEY:
	case PR_PARENT_SOURCE_KEY:
	case PR_PREDECESSOR_CHANGE_LIST:
	case PR_LAST_MODIFICATION_TIME:
		return true;
	case PR_IPM_DRAFTS_ENTRYID:
	case PR_IPM_CONTACT_ENTRYID:
	case PR_IPM_APPOINTMENT_ENTRYID:
	case PR_IPM_JOURNAL_ENTRYID:
	case PR_IPM_NOTE_ENTRYID:
	case PR_IPM_TASK_ENTRYID: {
		auto pfolder = this;
		return pfolder->plogon->is_private() && toplevel(pfolder->folder_id);
	}
	}
	return FALSE;
}

static BOOL folder_object_get_calculated_property(const folder_object *pfolder,
    proptag_t proptag, void **outvalue)
{
	BINARY *pbin;
	void *pvalue;
	EXT_PUSH ext_push;
	char temp_buff[1024];
	static constexpr uint8_t bin_buff[22]{};
	static constexpr uint32_t fake_del = 0;
	static constexpr BINARY fake_bin = {std::size(bin_buff), {deconst(bin_buff)}};
	auto dir = pfolder->plogon->get_dir();
	
	switch (proptag) {
	case PR_CONTENT_UNREAD: {
		if (pfolder->plogon->is_private())
			return false;
		/*
		 * N.B.: msmapi32 suppresses PR_CONTENT_UNREAD from being
		 * passed to rop_gethierarchytable/setcolumns, which means we
		 * won't deliver even if we could.
		 */
		auto v = cu_alloc<uint32_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		auto rpc_info = get_rpc_info();
		return exmdb_client->get_public_folder_unread_count(dir,
		       rpc_info.username, pfolder->folder_id, v);
	}
	case PR_ACCESS:
		*outvalue = deconst(&pfolder->tag_access);
		return TRUE;
	case PidTagFolderId: {
		auto v = cu_alloc<uint64_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		*v = pfolder->folder_id;
		return TRUE;
	}
	case PR_RIGHTS: {
		auto v = cu_alloc<uint32_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		auto eff_user = pfolder->plogon->eff_user();
		if (eff_user == STORE_OWNER_GRANTED) {
			*v = rightsAll | frightsContact;
			return TRUE;
		}
		if (!exmdb_client->get_folder_perm(dir,
		    pfolder->folder_id, eff_user, v))
			return FALSE;
		return TRUE;
	}
	case PR_ENTRYID:
		*outvalue = cu_fid_to_entryid(*pfolder->plogon, pfolder->folder_id);
		return TRUE;
	case PR_PARENT_ENTRYID:
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, pfolder->folder_id, PidTagParentFolderId,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
		            *static_cast<uint64_t *>(pvalue));
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		if (pfolder->folder_id == rop_util_make_eid_ex(1,
		    pfolder->plogon->is_private() ? PRIVATE_FID_ROOT : PUBLIC_FID_ROOT)) {
			*outvalue = deconst(&fake_bin);
			return TRUE;
		}
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, pfolder->folder_id, PidTagParentFolderId,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, *static_cast<uint64_t *>(pvalue), PR_SOURCE_KEY,
		    outvalue))
			return FALSE;
		if (*outvalue == nullptr) {
			*outvalue = cu_fid_to_sk(*pfolder->plogon,
			            *static_cast<uint64_t *>(pvalue));
			if (*outvalue == nullptr)
				return FALSE;
		}
		return TRUE;
	case PR_STORE_RECORD_KEY:
	case PR_MAPPING_SIGNATURE:
		*outvalue = common_util_guid_to_binary(pfolder->plogon->mailbox_guid);
		return TRUE;
	case PR_DELETED_FOLDER_COUNT:
		/* just like Exchange 2013, always return 0 */
		*outvalue = deconst(&fake_del);
		return TRUE;
	case PR_IPM_DRAFTS_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PR_IPM_CONTACT_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PR_IPM_APPOINTMENT_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PR_IPM_JOURNAL_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PR_IPM_NOTE_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PR_IPM_TASK_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(*pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		return TRUE;
	case PR_REM_ONLINE_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_REM_ONLINE_ENTRYID, &pvalue) || pvalue == nullptr)
			return FALSE;
		*outvalue = pvalue;
		return TRUE;
	case PR_ADDITIONAL_REN_ENTRYIDS: {
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_ADDITIONAL_REN_ENTRYIDS, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*outvalue = pvalue;
			return TRUE;
		}
		auto ba = cu_alloc<BINARY_ARRAY>();
		*outvalue = ba;
		if (*outvalue == nullptr)
			return FALSE;
		ba->count = 5;
		ba->pbin = cu_alloc<BINARY>(ba->count);
		if (ba->pbin == nullptr) {
			ba->count = 0;
			return FALSE;
		}
		pbin = cu_fid_to_entryid(*pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[0] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[1] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[2] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[3] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[4] = *pbin;
		return TRUE;
	}
	case PR_ADDITIONAL_REN_ENTRYIDS_EX: {
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_ADDITIONAL_REN_ENTRYIDS_EX, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*outvalue = pvalue;
			return TRUE;
		}
		auto bv = cu_alloc<BINARY>();
		*outvalue = bv;
		if (*outvalue == nullptr)
			return FALSE;
		const PERSISTDATA pd[] = {
			{RSF_PID_CONV_ACTIONS, RSF_ELID_ENTRYID, cu_fid_to_entryid_s(*pfolder->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS))},
			{RSF_PID_BUDDYLIST_PDLS, RSF_ELID_ENTRYID, cu_fid_to_entryid_s(*pfolder->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST))},
			{RSF_PID_BUDDYLIST_CONTACTS, RSF_ELID_ENTRYID, cu_fid_to_entryid_s(*pfolder->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_QUICKCONTACTS))},
		};
		if (!ext_push.init(temp_buff, sizeof(temp_buff), 0) ||
		    ext_push.p_persistdata_a(pd) != pack_result::ok)
			return false;
		bv->cb = ext_push.m_offset;
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr)
			return FALSE;
		memcpy(bv->pv, ext_push.m_udata, bv->cb);
		return TRUE;
	}
	case PR_FREEBUSY_ENTRYIDS: {
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client->get_folder_property(dir,
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_FREEBUSY_ENTRYIDS, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*outvalue = pvalue;
			return TRUE;
		}
		auto ba = cu_alloc<BINARY_ARRAY>();
		*outvalue = ba;
		if (*outvalue == nullptr)
			return FALSE;
		ba->count = 4;
		ba->pbin = cu_alloc<BINARY>(ba->count);
		if (ba->pbin == nullptr) {
			ba->count = 0;
			return FALSE;
		}
		ba->pbin[0].cb = 0;
		ba->pbin[0].pb = nullptr;
		ba->pbin[1].cb = 0;
		ba->pbin[1].pb = nullptr;
		ba->pbin[2].cb = 0;
		ba->pbin[2].pb = nullptr;
		pbin = cu_fid_to_entryid(*pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[3] = *pbin;
		return TRUE;
	}
	}
	return FALSE;
}

BOOL folder_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals) const
{
	static const uint32_t err_code = ecError;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	PROPTAG_ARRAY tmp_proptags = {0, cu_alloc<uint32_t>(pproptags->count)};
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	auto pfolder = this;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (!folder_object_get_calculated_property(pfolder, tag, &pvalue))
			tmp_proptags.emplace_back(tag);
		else if (pvalue != nullptr)
			ppropvals->emplace_back(tag, pvalue);
		else
			ppropvals->emplace_back(CHANGE_PROP_TYPE(tag, PT_ERROR), &err_code);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client->get_folder_properties(pfolder->plogon->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval + ppropvals->count,
			tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (pproptags->has(PR_SOURCE_KEY) && !ppropvals->has(PR_SOURCE_KEY)) {
		auto v = cu_fid_to_sk(*pfolder->plogon, pfolder->folder_id);
		if (v == nullptr)
			return FALSE;
		ppropvals->emplace_back(PR_SOURCE_KEY, v);
	}
	return TRUE;	
}

BOOL folder_object::set_properties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems) try
{
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	TPROPVAL_ARRAY tmp_propvals = {0, cu_alloc<TAGGED_PROPVAL>(ppropvals->count + 4)};
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	std::vector<uint16_t> poriginal_indices;
	auto pfolder = this;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		const auto &pv = ppropvals->ppropval[i];
		if (pfolder->is_readonly_prop(pv.proptag)) {
			pproblems->emplace_back(i, pv.proptag, ecAccessDenied);
		} else {
			tmp_propvals.ppropval[tmp_propvals.count++] = pv;
			poriginal_indices.push_back(i);
		}
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	auto dir = plogon->get_dir();
	if (!exmdb_client->allocate_cn(dir, &change_num))
		return FALSE;
	tmp_propvals.emplace_back(PidTagChangeNumber, &change_num);
	
	if (!exmdb_client->get_folder_property(dir,
	    CP_ACP, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)))
		return FALSE;
	auto pbin_changekey = cu_xid_to_bin({pfolder->plogon->guid(), change_num});
	if (pbin_changekey == nullptr)
		return FALSE;
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (pbin_pcl == nullptr)
		return FALSE;
	last_time = rop_util_current_nttime();
	tmp_propvals.emplace_back(PR_CHANGE_KEY, pbin_changekey);
	tmp_propvals.emplace_back(PR_PREDECESSOR_CHANGE_LIST, pbin_pcl);
	tmp_propvals.emplace_back(PR_LAST_MODIFICATION_TIME, &last_time);
	
	PROBLEM_ARRAY tmp_problems;
	if (!exmdb_client->set_folder_properties(pfolder->plogon->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count == 0)
		return TRUE;
	tmp_problems.transform(poriginal_indices);
	*pproblems += std::move(tmp_problems);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1743: ENOMEM");
	return false;
}

BOOL folder_object::remove_properties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems)
{
	uint64_t change_num;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	PROPTAG_ARRAY tmp_proptags = {0, cu_alloc<uint32_t>(pproptags->count)};
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	auto pfolder = this;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (pfolder->is_readonly_prop(tag))
			pproblems->emplace_back(i, tag, ecAccessDenied);
		else
			tmp_proptags.emplace_back(tag);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	auto dir = plogon->get_dir();
	if (!exmdb_client->remove_folder_properties(dir,
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;	

	BINARY *pbin_pcl = nullptr;
	if (!exmdb_client->allocate_cn(dir, &change_num))
		return TRUE;
	if (!exmdb_client->get_folder_property(dir,
	    CP_ACP, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)))
		return FALSE;
	auto pbin_changekey = cu_xid_to_bin({pfolder->plogon->guid(), change_num});
	if (pbin_changekey == nullptr)
		return FALSE;
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (pbin_pcl == nullptr)
		return FALSE;
	auto last_time = rop_util_current_nttime();
	const TAGGED_PROPVAL propval_buff[] = {
		{PidTagChangeNumber, &change_num},
		{PR_CHANGE_KEY, pbin_changekey},
		{PR_PREDECESSOR_CHANGE_LIST, pbin_pcl},
		{PR_LAST_MODIFICATION_TIME, &last_time},
	};
	const TPROPVAL_ARRAY tmp_propvals = {std::size(propval_buff), deconst(propval_buff)};
	PROBLEM_ARRAY tmp_problems;
	exmdb_client->set_folder_properties(dir, CP_ACP,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}
