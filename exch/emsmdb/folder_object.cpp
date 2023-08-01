// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "logon_object.h"

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

BOOL folder_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pfolder = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_folder_all_proptags(pfolder->plogon->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;		
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 15);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	auto eop = std::copy_if(&tmp_proptags.pproptag[0],
	           &tmp_proptags.pproptag[tmp_proptags.count],
	           pproptags->pproptag, [](uint32_t x) { return x < 0x80000000; });
	pproptags->count = eop - pproptags->pproptag;
	pproptags->pproptag[pproptags->count++] = PR_ACCESS;
	pproptags->pproptag[pproptags->count++] = PR_RIGHTS;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_SOURCE_KEY;
	if (!tmp_proptags.has(PR_SOURCE_KEY))
		pproptags->pproptag[pproptags->count++] = PR_SOURCE_KEY;
	if (!pfolder->plogon->is_private())
		return TRUE;
	if (!toplevel(pfolder->folder_id))
		return TRUE;
	if (!tmp_proptags.has(PR_IPM_DRAFTS_ENTRYID))
		pproptags->pproptag[pproptags->count++] = PR_IPM_DRAFTS_ENTRYID;
	if (!tmp_proptags.has(PR_IPM_CONTACT_ENTRYID))
		pproptags->pproptag[pproptags->count++] = PR_IPM_CONTACT_ENTRYID;
	if (!tmp_proptags.has(PR_IPM_APPOINTMENT_ENTRYID))
		pproptags->pproptag[pproptags->count++] = PR_IPM_APPOINTMENT_ENTRYID;
	if (!tmp_proptags.has(PR_IPM_JOURNAL_ENTRYID))
		pproptags->pproptag[pproptags->count++] = PR_IPM_JOURNAL_ENTRYID;
	if (!tmp_proptags.has(PR_IPM_NOTE_ENTRYID))
		pproptags->pproptag[pproptags->count++] = PR_IPM_NOTE_ENTRYID;
	if (!tmp_proptags.has(PR_IPM_TASK_ENTRYID))
		pproptags->pproptag[pproptags->count++] = PR_IPM_TASK_ENTRYID;
	if (!tmp_proptags.has(PR_FREEBUSY_ENTRYIDS))
		pproptags->pproptag[pproptags->count++] = PR_FREEBUSY_ENTRYIDS;
	if (!tmp_proptags.has(PR_ADDITIONAL_REN_ENTRYIDS))
		pproptags->pproptag[pproptags->count++] = PR_ADDITIONAL_REN_ENTRYIDS;
	if (!tmp_proptags.has(PR_ADDITIONAL_REN_ENTRYIDS_EX))
		pproptags->pproptag[pproptags->count++] = PR_ADDITIONAL_REN_ENTRYIDS_EX;
	return TRUE;
}

bool folder_object::is_readonly_prop(uint32_t proptag)
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
		if (!pfolder->plogon->is_private())
			return FALSE;
		return !toplevel(pfolder->folder_id);
	}
	}
	return FALSE;
}

static BOOL folder_object_get_calculated_property(folder_object *pfolder,
    uint32_t proptag, void **outvalue)
{
	BINARY *pbin;
	void *pvalue;
	EXT_PUSH ext_push;
	char temp_buff[1024];
	static constexpr uint8_t bin_buff[22]{};
	static constexpr uint32_t fake_del = 0;
	PERSISTDATA_ARRAY persistdatas;
	static constexpr BINARY fake_bin = {std::size(bin_buff), {deconst(bin_buff)}};
	auto dir = pfolder->plogon->get_dir();
	
	switch (proptag) {
	case PR_CONTENT_UNREAD: {
		if (pfolder->plogon->is_private())
			return false;
		auto v = cu_alloc<uint32_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		auto rpc_info = get_rpc_info();
		return exmdb_client::get_public_folder_unread_count(dir,
		       rpc_info.username, pfolder->folder_id, v);
	}
	case PR_ACCESS:
		*outvalue = &pfolder->tag_access;
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
		if (pfolder->plogon->logon_mode == logon_mode::owner) {
			*v = rightsAll | frightsContact;
			return TRUE;
		}
		auto rpc_info = get_rpc_info();
		if (!exmdb_client::get_folder_perm(dir,
		    pfolder->folder_id, rpc_info.username, v))
			return FALSE;
		return TRUE;
	}
	case PR_ENTRYID:
		*outvalue = cu_fid_to_entryid(pfolder->plogon, pfolder->folder_id);
		return TRUE;
	case PR_PARENT_ENTRYID:
		if (!exmdb_client::get_folder_property(dir,
		    CP_ACP, pfolder->folder_id, PidTagParentFolderId,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
		            *static_cast<uint64_t *>(pvalue));
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		if (pfolder->folder_id == rop_util_make_eid_ex(1,
		    pfolder->plogon->is_private() ? PRIVATE_FID_ROOT : PUBLIC_FID_ROOT)) {
			*outvalue = deconst(&fake_bin);
			return TRUE;
		}
		if (!exmdb_client::get_folder_property(dir,
		    CP_ACP, pfolder->folder_id, PidTagParentFolderId,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		if (!exmdb_client::get_folder_property(dir,
		    CP_ACP, *static_cast<uint64_t *>(pvalue), PR_SOURCE_KEY,
		    outvalue))
			return FALSE;
		if (*outvalue == nullptr) {
			*outvalue = cu_fid_to_sk(pfolder->plogon,
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
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PR_IPM_CONTACT_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PR_IPM_APPOINTMENT_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PR_IPM_JOURNAL_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PR_IPM_NOTE_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PR_IPM_TASK_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		*outvalue = cu_fid_to_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		return TRUE;
	case PR_REM_ONLINE_ENTRYID:
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client::get_folder_property(dir,
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_REM_ONLINE_ENTRYID, &pvalue) || pvalue == nullptr)
			return FALSE;
		*outvalue = pvalue;
		return TRUE;
	case PR_ADDITIONAL_REN_ENTRYIDS: {
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;	
		if (!exmdb_client::get_folder_property(dir,
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
		pbin = cu_fid_to_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[0] = *pbin;
		pbin = cu_fid_to_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[1] = *pbin;
		pbin = cu_fid_to_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[2] = *pbin;
		pbin = cu_fid_to_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[3] = *pbin;
		pbin = cu_fid_to_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[4] = *pbin;
		return TRUE;
	}
	case PR_ADDITIONAL_REN_ENTRYIDS_EX: {
		if (!pfolder->plogon->is_private() || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client::get_folder_property(dir,
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
		persistdatas.count = 3;
		persistdatas.ppitems = cu_alloc<PERSISTDATA *>(persistdatas.count);
		if (persistdatas.ppitems == nullptr)
			return FALSE;
		auto ppersistdata = cu_alloc<PERSISTDATA>(persistdatas.count);
		if (ppersistdata == nullptr)
			return FALSE;
		persistdatas.ppitems[0] = ppersistdata;
		persistdatas.ppitems[0]->persist_id = RSF_PID_CONV_ACTIONS;
		persistdatas.ppitems[0]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[0]->element.pentry_id =
			cu_fid_to_entryid(pfolder->plogon,
			rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS));
		persistdatas.ppitems[1] = ppersistdata + 1;
		persistdatas.ppitems[1]->persist_id = RSF_PID_BUDDYLIST_PDLS;
		persistdatas.ppitems[1]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[1]->element.pentry_id =
			cu_fid_to_entryid(pfolder->plogon,
			rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST));
		persistdatas.ppitems[2] = ppersistdata + 2;
		persistdatas.ppitems[2]->persist_id = RSF_PID_BUDDYLIST_CONTACTS;
		persistdatas.ppitems[2]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[2]->element.pentry_id =
			cu_fid_to_entryid(pfolder->plogon,
			rop_util_make_eid_ex(1, PRIVATE_FID_QUICKCONTACTS));
		if (!ext_push.init(temp_buff, sizeof(temp_buff), 0) ||
		    ext_push.p_persistdata_a(persistdatas) != EXT_ERR_SUCCESS)
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
		if (!exmdb_client::get_folder_property(dir,
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
		pbin = cu_fid_to_entryid(pfolder->plogon,
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
    TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t err_code = ecError;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	auto pfolder = this;
	for (i=0; i<pproptags->count; i++) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		if (!folder_object_get_calculated_property(pfolder, pproptags->pproptag[i], &pvalue)) {
			tmp_proptags.pproptag[tmp_proptags.count++] = pproptags->pproptag[i];
			continue;
		}
		if (NULL != pvalue) {
			pv.proptag = pproptags->pproptag[i];
			pv.pvalue = pvalue;
		} else {
			pv.proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_ERROR);
			pv.pvalue = deconst(&err_code);
		}
		ppropvals->count++;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client::get_folder_properties(pfolder->plogon->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval + ppropvals->count,
			tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (pproptags->has(PR_SOURCE_KEY) && !ppropvals->has(PR_SOURCE_KEY)) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		pv.proptag = PR_SOURCE_KEY;
		pv.pvalue = cu_fid_to_sk(pfolder->plogon, pfolder->folder_id);
		if (pv.pvalue == nullptr)
			return FALSE;
		ppropvals->count ++;
	}
	return TRUE;	
}

BOOL folder_object::set_properties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems)
{
	int i;
	uint16_t count;
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return FALSE;
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	tmp_propvals.count = 0;
	count = ppropvals->count + 4;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(count);
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	auto poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
	if (poriginal_indices == nullptr)
		return FALSE;
	auto pfolder = this;
	for (i=0; i<ppropvals->count; i++) {
		if (pfolder->is_readonly_prop(ppropvals->ppropval[i].proptag)) {
			pproblems->emplace_back(i, ppropvals->ppropval[i].proptag, ecAccessDenied);
		} else {
			tmp_propvals.ppropval[tmp_propvals.count] =
								ppropvals->ppropval[i];
			poriginal_indices[tmp_propvals.count++] = i;
		}
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	auto dir = plogon->get_dir();
	if (!exmdb_client::allocate_cn(dir, &change_num))
		return FALSE;
	tmp_propvals.emplace_back(PidTagChangeNumber, &change_num);
	
	if (!exmdb_client::get_folder_property(dir,
	    CP_ACP, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
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
	
	if (!exmdb_client::set_folder_properties(pfolder->plogon->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count == 0)
		return TRUE;
	tmp_problems.transform(poriginal_indices);
	*pproblems += std::move(tmp_problems);
	return TRUE;
}

BOOL folder_object::remove_properties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems)
{
	int i;
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[4];
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	auto pfolder = this;
	for (i=0; i<pproptags->count; i++) {
		if (pfolder->is_readonly_prop(pproptags->pproptag[i]))
			pproblems->emplace_back(i, pproptags->pproptag[i], ecAccessDenied);
		else
			tmp_proptags.pproptag[tmp_proptags.count++] = pproptags->pproptag[i];
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	auto dir = plogon->get_dir();
	if (!exmdb_client::remove_folder_properties(dir,
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;	
	tmp_propvals.count = 4;
	tmp_propvals.ppropval = propval_buff;
	if (!exmdb_client::allocate_cn(dir, &change_num))
		return TRUE;
	if (!exmdb_client::get_folder_property(dir,
	    CP_ACP, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return FALSE;
	propval_buff[0].proptag = PidTagChangeNumber;
	propval_buff[0].pvalue = &change_num;
	auto pbin_changekey = cu_xid_to_bin({pfolder->plogon->guid(), change_num});
	if (pbin_changekey == nullptr)
		return FALSE;
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (pbin_pcl == nullptr)
		return FALSE;
	last_time = rop_util_current_nttime();
	propval_buff[1].proptag = PR_CHANGE_KEY;
	propval_buff[1].pvalue = pbin_changekey;
	propval_buff[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval_buff[2].pvalue = pbin_pcl;
	propval_buff[3].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[3].pvalue = &last_time;
	exmdb_client::set_folder_properties(dir, CP_ACP,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}
