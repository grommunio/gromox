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

BOOL folder_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pfolder = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client_get_folder_all_proptags(pfolder->plogon->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;		
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 15);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
		sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag[pproptags->count++] = PR_ACCESS;
	pproptags->pproptag[pproptags->count++] = PR_RIGHTS;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_SOURCE_KEY;
	if (!tmp_proptags.has(PR_SOURCE_KEY))
		pproptags->pproptag[pproptags->count++] = PR_SOURCE_KEY;
	if (!pfolder->plogon->check_private())
		return TRUE;
	auto basic_fld = pfolder->folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) ||
	                 pfolder->folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_INBOX);
	if (!basic_fld)
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

BOOL folder_object::check_readonly_property(uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
	switch (proptag) {
	case PR_ACCESS:
	case PR_ADDRESS_BOOK_ENTRYID:
	case PROP_TAG_ARTICLENUMBERNEXT:
	case PR_ASSOC_CONTENT_COUNT:
	case PROP_TAG_ATTRIBUTEREADONLY:
	case PidTagChangeNumber:
	case PR_CONTENT_COUNT:
	case PR_CONTENT_UNREAD:
	case PR_CREATION_TIME:
	case PR_DELETED_COUNT_TOTAL:
	case PR_DELETED_FOLDER_COUNT:
	case PR_DELETED_ON:
	case PR_ENTRYID:
	case PROP_TAG_FOLDERCHILDCOUNT:
	case PROP_TAG_FOLDERFLAGS:
	case PidTagFolderId:
	case PR_FOLDER_TYPE:
	case PROP_TAG_HASRULES:
	case PR_HIERARCHY_CHANGE_NUM:
	case PROP_TAG_HIERREV:
	case PR_INTERNET_ARTICLE_NUMBER:
	case PROP_TAG_LOCALCOMMITTIME:
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
		return TRUE;
	case PR_IPM_DRAFTS_ENTRYID:
	case PR_IPM_CONTACT_ENTRYID:
	case PR_IPM_APPOINTMENT_ENTRYID:
	case PR_IPM_JOURNAL_ENTRYID:
	case PR_IPM_NOTE_ENTRYID:
	case PR_IPM_TASK_ENTRYID: {
		auto pfolder = this;
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		return TRUE;
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
	static constexpr BINARY fake_bin = {gromox::arsizeof(bin_buff), {deconst(bin_buff)}};
	
	switch (proptag) {
	case PR_CONTENT_UNREAD:
		if (!pfolder->plogon->check_private()) {
			auto v = cu_alloc<uint32_t>();
			*outvalue = v;
			if (*outvalue == nullptr)
				return FALSE;
			auto rpc_info = get_rpc_info();
			return exmdb_client_get_public_folder_unread_count(
			       pfolder->plogon->get_dir(),
			       rpc_info.username, pfolder->folder_id, v);
		}
		return FALSE;
	case PR_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, pfolder->folder_id, PR_MESSAGE_SIZE_EXTENDED, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_ASSOC_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, pfolder->folder_id, PR_ASSOC_MESSAGE_SIZE_EXTENDED,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
	}
	case PR_NORMAL_MESSAGE_SIZE: {
		auto v = cu_alloc<uint32_t>();
		*outvalue = v;
		if (*outvalue == nullptr)
			return FALSE;
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, pfolder->folder_id, PR_NORMAL_MESSAGE_SIZE_EXTENDED,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		*v = std::min(*static_cast<uint64_t *>(pvalue), static_cast<uint64_t>(INT32_MAX));
		return TRUE;
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
		if (pfolder->plogon->logon_mode == LOGON_MODE_OWNER) {
			*v = rightsAll | frightsContact;
		} else {
			auto rpc_info = get_rpc_info();
			if (!exmdb_client_check_folder_permission(
			    pfolder->plogon->get_dir(),
			    pfolder->folder_id, rpc_info.username, v))
				return FALSE;
		}
		return TRUE;
	}
	case PR_ENTRYID:
		*outvalue = common_util_to_folder_entryid(
			pfolder->plogon, pfolder->folder_id);
		return TRUE;
	case PR_PARENT_ENTRYID:
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, pfolder->folder_id, PidTagParentFolderId,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		*outvalue = common_util_to_folder_entryid(
			pfolder->plogon, *(uint64_t*)pvalue);
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		if (pfolder->plogon->check_private()) {
			if (pfolder->folder_id == rop_util_make_eid_ex(
				1, PRIVATE_FID_ROOT)) {
				*outvalue = deconst(&fake_bin);
				return TRUE;
			}
		} else {
			if (pfolder->folder_id == rop_util_make_eid_ex(
				1, PUBLIC_FID_ROOT)) {
				*outvalue = deconst(&fake_bin);
				return TRUE;
			}
		}
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, pfolder->folder_id, PidTagParentFolderId,
		    &pvalue) || pvalue == nullptr)
			return FALSE;	
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, *static_cast<uint64_t *>(pvalue), PR_SOURCE_KEY,
		    outvalue))
			return FALSE;
		if (*outvalue == nullptr) {
			*outvalue = common_util_calculate_folder_sourcekey(
						pfolder->plogon, *(uint64_t*)pvalue);
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
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*outvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PR_IPM_CONTACT_ENTRYID:
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*outvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PR_IPM_APPOINTMENT_ENTRYID:
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*outvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PR_IPM_JOURNAL_ENTRYID:
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*outvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PR_IPM_NOTE_ENTRYID:
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*outvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PR_IPM_TASK_ENTRYID:
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*outvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		return TRUE;
	case PR_REM_ONLINE_ENTRYID:
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT)) {
			return FALSE;
		}
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_REM_ONLINE_ENTRYID, &pvalue) || pvalue == nullptr)
			return FALSE;
		*outvalue = pvalue;
		return TRUE;
	case PR_ADDITIONAL_REN_ENTRYIDS: {
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
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
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[0] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[1] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[2] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[3] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[4] = *pbin;
		return TRUE;
	}
	case PR_ADDITIONAL_REN_ENTRYIDS_EX: {
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
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
		if (NULL == persistdatas.ppitems) {
			return FALSE;
		}
		auto ppersistdata = cu_alloc<PERSISTDATA>(persistdatas.count);
		if (NULL == ppersistdata) {
			return FALSE;
		}
		persistdatas.ppitems[0] = ppersistdata;
		persistdatas.ppitems[0]->persist_id = RSF_PID_CONV_ACTIONS;
		persistdatas.ppitems[0]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[0]->element.pentry_id =
			common_util_to_folder_entryid(pfolder->plogon,
			rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS));
		persistdatas.ppitems[1] = ppersistdata + 1;
		persistdatas.ppitems[1]->persist_id = RSF_PID_BUDDYLIST_PDLS;
		persistdatas.ppitems[1]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[1]->element.pentry_id =
			common_util_to_folder_entryid(pfolder->plogon,
			rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST));
		persistdatas.ppitems[2] = ppersistdata + 2;
		persistdatas.ppitems[2]->persist_id = RSF_PID_BUDDYLIST_CONTACTS;
		persistdatas.ppitems[2]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[2]->element.pentry_id =
			common_util_to_folder_entryid(pfolder->plogon,
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
		if (!pfolder->plogon->check_private())
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
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
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
		if (NULL == pbin) {
			return FALSE;
		}
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
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
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
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_get_folder_properties(pfolder->plogon->get_dir(),
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
		pv.pvalue = common_util_calculate_folder_sourcekey(pfolder->plogon, pfolder->folder_id);
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
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_propvals.count = 0;
	count = ppropvals->count + 4;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	auto poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	auto pfolder = this;
	for (i=0; i<ppropvals->count; i++) {
		if (pfolder->check_readonly_property(ppropvals->ppropval[i].proptag)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
		} else {
			tmp_propvals.ppropval[tmp_propvals.count] =
								ppropvals->ppropval[i];
			poriginal_indices[tmp_propvals.count++] = i;
		}
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (!exmdb_client_allocate_cn(pfolder->plogon->get_dir(), &change_num))
		return FALSE;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PidTagChangeNumber;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = &change_num;
	
	if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
	    0, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return FALSE;
	auto pbin_changekey = cu_xid_to_bin({pfolder->plogon->guid(), change_num});
	if (NULL == pbin_changekey) {
		return FALSE;
	}
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (NULL == pbin_pcl) {
		return FALSE;
	}
	last_time = rop_util_current_nttime();
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_CHANGE_KEY;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pbin_changekey;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pbin_pcl;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = &last_time;
	
	if (!exmdb_client_set_folder_properties(pfolder->plogon->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (0 == tmp_problems.count) {
		return TRUE;
	}
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
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	auto pfolder = this;
	for (i=0; i<pproptags->count; i++) {
		if (pfolder->check_readonly_property(pproptags->pproptag[i])) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
									pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count++].err = ecAccessDenied;
		} else {
			tmp_proptags.pproptag[tmp_proptags.count++] = pproptags->pproptag[i];
		}
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_remove_folder_properties(pfolder->plogon->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;	
	tmp_propvals.count = 4;
	tmp_propvals.ppropval = propval_buff;
	if (!exmdb_client_allocate_cn(pfolder->plogon->get_dir(), &change_num))
		return TRUE;
	if (!exmdb_client_get_folder_property(pfolder->plogon->get_dir(),
	    0, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return FALSE;
	propval_buff[0].proptag = PidTagChangeNumber;
	propval_buff[0].pvalue = &change_num;
	auto pbin_changekey = cu_xid_to_bin({pfolder->plogon->guid(), change_num});
	if (NULL == pbin_changekey) {
		return FALSE;
	}
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (NULL == pbin_pcl) {
		return FALSE;
	}
	last_time = rop_util_current_nttime();
	propval_buff[1].proptag = PR_CHANGE_KEY;
	propval_buff[1].pvalue = pbin_changekey;
	propval_buff[2].proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval_buff[2].pvalue = pbin_pcl;
	propval_buff[3].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[3].pvalue = &last_time;
	exmdb_client_set_folder_properties(pfolder->plogon->get_dir(), 0,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}
