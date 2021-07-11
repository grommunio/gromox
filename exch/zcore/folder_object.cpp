// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
#include <memory>
#include <unistd.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/tpropval_array.hpp>
#include "folder_object.h"
#include "zarafa_server.h"
#include "common_util.h"
#include "exmdb_client.h"
#include <gromox/ext_buffer.hpp>
#include <gromox/rop_util.hpp>
#include <cstdio>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>

using namespace gromox;

std::unique_ptr<FOLDER_OBJECT> folder_object_create(STORE_OBJECT *pstore,
	uint64_t folder_id, uint8_t type, uint32_t tag_access)
{
	std::unique_ptr<FOLDER_OBJECT> pfolder;
	try {
		pfolder = std::make_unique<FOLDER_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pfolder->pstore = pstore;
	pfolder->folder_id = folder_id;
	pfolder->type = type;
	pfolder->tag_access = tag_access;
	return pfolder;
}

BOOL FOLDER_OBJECT::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pfolder = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_folder_all_proptags(pfolder->pstore->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;		
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 30);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
		sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag[pproptags->count++] = PR_ACCESS;
	pproptags->pproptag[pproptags->count] = PR_ENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PR_OBJECT_TYPE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count++] = PR_MAPPING_SIGNATURE;
	pproptags->pproptag[pproptags->count++] = PR_RIGHTS;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_SOURCE_KEY;
	pproptags->pproptag[pproptags->count++] = PR_STORE_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_STORE_RECORD_KEY;
	if (common_util_index_proptags(&tmp_proptags, PR_SOURCE_KEY) < 0) {
		pproptags->pproptag[pproptags->count] = PR_SOURCE_KEY;
		pproptags->count ++;
	}
	if (!pfolder->pstore->b_private)
		return TRUE;
	if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
	    pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX))
		return TRUE;
	if (common_util_index_proptags(&tmp_proptags, PR_IPM_DRAFTS_ENTRYID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_IPM_DRAFTS_ENTRYID;
	if (common_util_index_proptags(&tmp_proptags, PR_IPM_CONTACT_ENTRYID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_IPM_CONTACT_ENTRYID;
	if (common_util_index_proptags(&tmp_proptags, PR_IPM_APPOINTMENT_ENTRYID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_IPM_APPOINTMENT_ENTRYID;
	if (common_util_index_proptags(&tmp_proptags, PR_IPM_JOURNAL_ENTRYID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_IPM_JOURNAL_ENTRYID;
	if (common_util_index_proptags(&tmp_proptags, PR_IPM_NOTE_ENTRYID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_IPM_NOTE_ENTRYID;
	if (common_util_index_proptags(&tmp_proptags, PR_IPM_TASK_ENTRYID) < 0)
		pproptags->pproptag[pproptags->count++] = PR_IPM_TASK_ENTRYID;
	if (common_util_index_proptags(&tmp_proptags, PR_FREEBUSY_ENTRYIDS) < 0)
		pproptags->pproptag[pproptags->count++] = PR_FREEBUSY_ENTRYIDS;
	if (common_util_index_proptags(&tmp_proptags, PR_ADDITIONAL_REN_ENTRYIDS) < 0)
		pproptags->pproptag[pproptags->count++] = PR_ADDITIONAL_REN_ENTRYIDS;
	if (common_util_index_proptags(&tmp_proptags, PR_ADDITIONAL_REN_ENTRYIDS_EX) < 0)
		pproptags->pproptag[pproptags->count++] = PR_ADDITIONAL_REN_ENTRYIDS_EX;
	return TRUE;
}

BOOL FOLDER_OBJECT::check_readonly_property(uint32_t proptag) const
{
	auto pfolder = this;
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
	switch (proptag) {
	case PR_ACCESS:
	case PR_ADDRESS_BOOK_ENTRYID:
	case PROP_TAG_ARTICLENUMBERNEXT:
	case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
	case PROP_TAG_ATTRIBUTEREADONLY:
	case PROP_TAG_CHANGENUMBER:
	case PROP_TAG_CONTENTCOUNT:
	case PROP_TAG_CONTENTUNREADCOUNT:
	case PR_CREATION_TIME:
	case PR_DELETED_COUNT_TOTAL:
	case PR_DELETED_FOLDER_COUNT:
	case PR_DELETED_ON:
	case PR_ENTRYID:
	case PROP_TAG_FOLDERCHILDCOUNT:
	case PROP_TAG_FOLDERFLAGS:
	case PROP_TAG_FOLDERID:
	case PROP_TAG_FOLDERTYPE:
	case PROP_TAG_HASRULES:
	case PROP_TAG_HIERARCHYCHANGENUMBER:
	case PROP_TAG_HIERREV:
	case PROP_TAG_INTERNETARTICLENUMBER:
	case PROP_TAG_LOCALCOMMITTIME:
	case PROP_TAG_LOCALCOMMITTIMEMAX:
	case PR_MESSAGE_SIZE:
	case PR_MESSAGE_SIZE_EXTENDED:
	case PROP_TAG_ASSOCMESSAGESIZE:
	case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
	case PR_NORMAL_MESSAGE_SIZE:
	case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
	case PR_PARENT_ENTRYID:
	case PROP_TAG_PARENTFOLDERID:
	case PR_STORE_RECORD_KEY:
	case PR_STORE_ENTRYID:
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
	case PR_IPM_TASK_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		return TRUE;
	}
	return FALSE;
}

static BOOL folder_object_get_calculated_property(
	FOLDER_OBJECT *pfolder, uint32_t proptag, void **ppvalue)
{
	BINARY *pbin;
	void *pvalue;
	EXT_PUSH ext_push;
	char temp_buff[1024];
	PERSISTDATA *ppersistdata;
	static constexpr uint8_t bin_buff[22]{};
	static constexpr uint32_t fake_del = 0;
	PERSISTDATA_ARRAY persistdatas;
	static constexpr BINARY fake_bin = {sizeof(bin_buff), const_cast<uint8_t *>(bin_buff)};
	
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = &pfolder->tag_access;
		return TRUE;
	case PROP_TAG_CONTENTUNREADCOUNT: {
		if (pfolder->pstore->b_private)
			return false;
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		auto pinfo = zarafa_server_get_info();
		return exmdb_client::get_public_folder_unread_count(pfolder->pstore->get_dir(),
		       pinfo->get_username(), pfolder->folder_id,
		       static_cast<uint32_t *>(*ppvalue));
	}
	case PROP_TAG_FOLDERID:
		*ppvalue = cu_alloc<uint64_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint64_t*)(*ppvalue) = pfolder->folder_id;
		return TRUE;
	case PR_RIGHTS: {
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (pfolder->pstore->check_owner_mode()) {
			*static_cast<uint32_t *>(*ppvalue) = rightsAll | frightsContact;
			return TRUE;
		}
		auto pinfo = zarafa_server_get_info();
		return exmdb_client::check_folder_permission(pfolder->pstore->get_dir(),
		       pfolder->folder_id, pinfo->get_username(),
		       static_cast<uint32_t *>(*ppvalue));
	}
	case PR_ENTRYID:
	case PR_RECORD_KEY:
		*ppvalue = common_util_to_folder_entryid(
			pfolder->pstore, pfolder->folder_id);
		return TRUE;
	case PR_PARENT_ENTRYID:
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    0, pfolder->folder_id, PROP_TAG_PARENTFOLDERID, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*ppvalue = common_util_to_folder_entryid(
			pfolder->pstore, *(uint64_t*)pvalue);
		return TRUE;
	case PR_SOURCE_KEY:
		*ppvalue = common_util_calculate_folder_sourcekey(
					pfolder->pstore, pfolder->folder_id);
		return TRUE;
	case PR_PARENT_SOURCE_KEY:
		if (pfolder->pstore->b_private) {
			if (pfolder->folder_id == rop_util_make_eid_ex(
				1, PRIVATE_FID_ROOT)) {
				*ppvalue = deconst(&fake_bin);
				return TRUE;
			}
		} else {
			if (pfolder->folder_id == rop_util_make_eid_ex(
				1, PUBLIC_FID_ROOT)) {
				*ppvalue = deconst(&fake_bin);
				return TRUE;
			}
		}
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    0, pfolder->folder_id, PROP_TAG_PARENTFOLDERID, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*ppvalue = common_util_calculate_folder_sourcekey(
					pfolder->pstore, *(uint64_t*)pvalue);
		return TRUE;
	case PR_STORE_RECORD_KEY:
	case PR_MAPPING_SIGNATURE:
		*ppvalue = common_util_guid_to_binary(pfolder->pstore->mailbox_guid);
		return TRUE;
	case PR_STORE_ENTRYID:
		*ppvalue = common_util_to_store_entryid(pfolder->pstore);
		return *ppvalue != nullptr ? TRUE : false;
	case PR_DELETED_FOLDER_COUNT:
		/* just like exchange 2013, alway return 0 */
		*ppvalue = deconst(&fake_del);
		return TRUE;
	case PR_IPM_DRAFTS_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PR_IPM_CONTACT_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PR_IPM_APPOINTMENT_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PR_IPM_JOURNAL_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PR_IPM_NOTE_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PR_IPM_TASK_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		return TRUE;
	case PROP_TAG_REMINDERSONLINEENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PROP_TAG_REMINDERSONLINEENTRYID, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	case PR_ADDITIONAL_REN_ENTRYIDS: {
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_ADDITIONAL_REN_ENTRYIDS, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = cu_alloc<BINARY_ARRAY>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		auto ba = static_cast<BINARY_ARRAY *>(*ppvalue);
		ba->count = 5;
		ba->pbin = cu_alloc<BINARY>(ba->count);
		if (ba->pbin == nullptr) {
			ba->count = 0;
			return FALSE;
		}
		pbin = common_util_to_folder_entryid(pfolder->pstore,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[0] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[1] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[2] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[3] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->pstore,
				rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[4] = *pbin;
		return TRUE;
	}
	case PR_ADDITIONAL_REN_ENTRYIDS_EX: {
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_ADDITIONAL_REN_ENTRYIDS_EX, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = cu_alloc<BINARY>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(*ppvalue);
		persistdatas.count = 3;
		persistdatas.ppitems = cu_alloc<PERSISTDATA *>(persistdatas.count);
		if (NULL == persistdatas.ppitems) {
			return FALSE;
		}
		ppersistdata = cu_alloc<PERSISTDATA>(persistdatas.count);
		if (NULL == ppersistdata) {
			return FALSE;
		}
		persistdatas.ppitems[0] = ppersistdata;
		persistdatas.ppitems[0]->persist_id = RSF_PID_CONV_ACTIONS;
		persistdatas.ppitems[0]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[0]->element.pentry_id =
			common_util_to_folder_entryid(pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS));
		persistdatas.ppitems[1] = ppersistdata + 1;
		persistdatas.ppitems[1]->persist_id = RSF_PID_BUDDYLIST_PDLS;
		persistdatas.ppitems[1]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[1]->element.pentry_id =
			common_util_to_folder_entryid(pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST));
		persistdatas.ppitems[2] = ppersistdata + 2;
		persistdatas.ppitems[2]->persist_id = RSF_PID_BUDDYLIST_CONTACTS;
		persistdatas.ppitems[2]->element.element_id = RSF_ELID_ENTRYID;
		persistdatas.ppitems[2]->element.pentry_id =
			common_util_to_folder_entryid(pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_QUICKCONTACTS));
		if (!ext_push.init(temp_buff, sizeof(temp_buff), 0) ||
		    ext_push.p_persistdata_a(&persistdatas) != EXT_ERR_SUCCESS)
			return FALSE;	
		bv->cb = ext_push.offset;
		bv->pv = common_util_alloc(ext_push.offset);
		if (bv->pv == nullptr) {
			bv->cb = 0;
			return FALSE;
		}
		memcpy(bv->pv, ext_push.data, ext_push.offset);
		return TRUE;
	}
	case PR_FREEBUSY_ENTRYIDS: {
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    0, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_FREEBUSY_ENTRYIDS, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = cu_alloc<BINARY_ARRAY>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		auto ba = static_cast<BINARY_ARRAY *>(*ppvalue);
		ba->count = 4;
		ba->pbin = cu_alloc<BINARY>(ba->count);
		if (ba->pbin == nullptr) {
			ba->count = 0;
			return FALSE;
		}
		ba->pbin[0].cb = 0;
		ba->pbin[0].pb = NULL;
		ba->pbin[1].cb = 0;
		ba->pbin[1].pb = NULL;
		ba->pbin[2].cb = 0;
		ba->pbin[2].pb = NULL;
		pbin = common_util_to_folder_entryid(pfolder->pstore,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
		if (NULL == pbin) {
			return FALSE;
		}
		ba->pbin[3] = *pbin;
		return TRUE;
	}
	case PR_OBJECT_TYPE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = OBJECT_FOLDER;
		return TRUE;
	}
	return FALSE;
}

BOOL FOLDER_OBJECT::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
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
		if (TRUE == folder_object_get_calculated_property(
			pfolder, pproptags->pproptag[i], &pvalue)) {
			if (NULL == pvalue) {
				return FALSE;
			}
			ppropvals->ppropval[ppropvals->count].proptag =
										pproptags->pproptag[i];
			ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
			ppropvals->count ++;
		} else {
			tmp_proptags.pproptag[tmp_proptags.count] =
								pproptags->pproptag[i];
			tmp_proptags.count ++;
		}
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	auto pinfo = zarafa_server_get_info();
	if (!exmdb_client::get_folder_properties(pfolder->pstore->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_proptags, &tmp_propvals))
		return FALSE;
	if (tmp_propvals.count == 0)
		return TRUE;
	memcpy(ppropvals->ppropval + ppropvals->count,
	       tmp_propvals.ppropval,
	       sizeof(TAGGED_PROPVAL) * tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

BOOL FOLDER_OBJECT::set_properties(const TPROPVAL_ARRAY *ppropvals)
{
	XID tmp_xid;
	uint16_t count;
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	BINARY *pbin_changekey;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (ppropvals->count == 0)
		return TRUE;
	count = ppropvals->count + 4;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	memcpy(tmp_propvals.ppropval, ppropvals->ppropval,
			sizeof(TAGGED_PROPVAL)*ppropvals->count);
	tmp_propvals.count = ppropvals->count;
	auto pfolder = this;
	if (!exmdb_client::allocate_cn(pfolder->pstore->get_dir(), &change_num))
		return FALSE;
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_CHANGENUMBER;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue =
											&change_num;
	tmp_propvals.count ++;
	if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
	    0, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return FALSE;
	tmp_xid.guid = pfolder->pstore->guid();
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin_changekey = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin_changekey) {
		return FALSE;
	}
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (NULL == pbin_pcl) {
		return FALSE;
	}
	last_time = rop_util_current_nttime();
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_CHANGE_KEY;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = 
										pbin_changekey;
	tmp_propvals.count ++;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue =
												pbin_pcl;
	tmp_propvals.count ++;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue =
											&last_time;
	tmp_propvals.count ++;
	auto pinfo = zarafa_server_get_info();
	if (!exmdb_client::set_folder_properties(pfolder->pstore->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	return TRUE;
}

BOOL FOLDER_OBJECT::remove_properties(const PROPTAG_ARRAY *pproptags)
{
	int i;
	XID tmp_xid;
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	BINARY *pbin_changekey;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[4];
	
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	auto pfolder = this;
	for (i=0; i<pproptags->count; i++) {
		if (pfolder->check_readonly_property(pproptags->pproptag[i]))
			continue;
		tmp_proptags.pproptag[tmp_proptags.count] =
							pproptags->pproptag[i];
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client::remove_folder_properties(pfolder->pstore->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;	
	tmp_propvals.count = 4;
	tmp_propvals.ppropval = propval_buff;
	if (!exmdb_client::allocate_cn(pfolder->pstore->get_dir(), &change_num))
		return TRUE;
	if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
	    0, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)) ||
	    pbin_pcl == nullptr)
		return FALSE;
	propval_buff[0].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[0].pvalue = &change_num;
	tmp_xid.guid = pfolder->pstore->guid();
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin_changekey = common_util_xid_to_binary(22, &tmp_xid);
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
	exmdb_client::set_folder_properties(pfolder->pstore->get_dir(), 0,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}

BOOL FOLDER_OBJECT::get_permissions(PERMISSION_SET *pperm_set)
{
	uint32_t row_num;
	uint32_t *prights;
	uint32_t table_id;
	BINARY *pentry_id;
	PROPTAG_ARRAY proptags;
	TARRAY_SET permission_set;
	static const uint32_t proptag_buff[] = {
		PR_ENTRYID,
		PROP_TAG_MEMBERRIGHTS
	};
	
	auto pfolder = this;
	auto dir = pfolder->pstore->get_dir();
	uint32_t flags = !pfolder->pstore->b_private &&
	                 rop_util_get_gc_value(pfolder->folder_id) == PRIVATE_FID_CALENDAR ?
		         PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY : 0;
	if (!exmdb_client::load_permission_table(dir,
		pfolder->folder_id, flags, &table_id, &row_num)) {
		return FALSE;
	}
	proptags.count = 2;
	proptags.pproptag = deconst(proptag_buff);
	if (!exmdb_client::query_table(dir, NULL, 0,
		table_id, &proptags, 0, row_num, &permission_set)) {
		exmdb_client::unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client::unload_table(dir, table_id);
	pperm_set->count = 0;
	pperm_set->prows = cu_alloc<PERMISSION_ROW>(permission_set.count);
	if (NULL == pperm_set->prows) {
		return FALSE;
	}
	for (size_t i = 0; i < permission_set.count; ++i) {
		pperm_set->prows[pperm_set->count].flags = RIGHT_NORMAL;
		pentry_id = static_cast<BINARY *>(common_util_get_propvals(
		            permission_set.pparray[i], PR_ENTRYID));
		/* ignore the default and anonymous user */
		if (NULL == pentry_id || 0 == pentry_id->cb) {
			continue;
		}
		prights = static_cast<uint32_t *>(common_util_get_propvals(
		          permission_set.pparray[i], PROP_TAG_MEMBERRIGHTS));
		if (NULL == prights) {
			continue;
		}
		pperm_set->prows[pperm_set->count].flags = RIGHT_NORMAL;
		pperm_set->prows[pperm_set->count].entryid = *pentry_id;
		pperm_set->prows[pperm_set->count].member_rights = *prights;
		pperm_set->count ++;
	}
	return TRUE;
}

BOOL FOLDER_OBJECT::set_permissions(const PERMISSION_SET *pperm_set)
{
	BINARY *pentryid;
	uint32_t row_num;
	uint32_t table_id;
	uint64_t *pmember_id;
	PROPTAG_ARRAY proptags;
	TARRAY_SET permission_set;
	PERMISSION_DATA *pperm_data;
	static const uint32_t proptag_buff[] = {
		PR_ENTRYID,
		PROP_TAG_MEMBERID
	};
	
	auto pfolder = this;
	auto dir = pfolder->pstore->get_dir();
	if (!exmdb_client::load_permission_table(dir,
		pfolder->folder_id, 0, &table_id, &row_num)) {
		return FALSE;
	}
	proptags.count = 2;
	proptags.pproptag = deconst(proptag_buff);
	if (!exmdb_client::query_table(dir, NULL, 0,
		table_id, &proptags, 0, row_num, &permission_set)) {
		exmdb_client::unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client::unload_table(dir, table_id);
	pperm_data = cu_alloc<PERMISSION_DATA>(pperm_set->count);
	if (NULL == pperm_data) {
		return FALSE;
	}
	uint16_t count = 0;
	for (size_t i = 0; i < pperm_set->count; ++i) {
		if (pperm_set->prows[i].flags & (RIGHT_NEW | RIGHT_MODIFY)) {
			size_t j;
			for (j=0; j<permission_set.count; j++) {
				pentryid = static_cast<BINARY *>(common_util_get_propvals(
				           permission_set.pparray[j], PR_ENTRYID));
				if (NULL != pentryid && pentryid->cb ==
					pperm_set->prows[i].entryid.cb && 0 ==
					memcmp(pperm_set->prows[i].entryid.pb,
					pentryid->pb, pentryid->cb)) {
					break;	
				}
			}
			if (j < permission_set.count) {
				pmember_id = static_cast<uint64_t *>(common_util_get_propvals(
							permission_set.pparray[j],
				             PROP_TAG_MEMBERID));
				if (NULL == pmember_id) {
					continue;
				}
				pperm_data[count].flags = PERMISSION_DATA_FLAG_MODIFY_ROW;
				pperm_data[count].propvals.count = 2;
				pperm_data[count].propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(2);
				if (NULL == pperm_data[i].propvals.ppropval) {
					return FALSE;
				}
				pperm_data[count].propvals.ppropval[0].proptag =
												PROP_TAG_MEMBERID;
				pperm_data[count].propvals.ppropval[0].pvalue =
													pmember_id;
				pperm_data[count].propvals.ppropval[1].proptag =
											PROP_TAG_MEMBERRIGHTS;
				pperm_data[count].propvals.ppropval[1].pvalue =
							&pperm_set->prows[i].member_rights;
				count ++;
				continue;
			}
		}
		if (pperm_set->prows[i].flags & RIGHT_NEW) {
			pperm_data[count].flags = PERMISSION_DATA_FLAG_ADD_ROW;
			pperm_data[count].propvals.count = 2;
			pperm_data[count].propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(2);
			if (NULL == pperm_data[i].propvals.ppropval) {
				return FALSE;
			}
			pperm_data[count].propvals.ppropval[0].proptag = PR_ENTRYID;
			pperm_data[count].propvals.ppropval[0].pvalue =
								&pperm_set->prows[i].entryid;
			pperm_data[count].propvals.ppropval[1].proptag =
										PROP_TAG_MEMBERRIGHTS;
			pperm_data[count].propvals.ppropval[1].pvalue =
						&pperm_set->prows[i].member_rights;
		} else if (pperm_set->prows[i].flags & RIGHT_DELETED) {
			size_t j;
			for (j=0; j<permission_set.count; j++) {
				pentryid = static_cast<BINARY *>(common_util_get_propvals(
				           permission_set.pparray[j], PR_ENTRYID));
				if (NULL != pentryid && pentryid->cb ==
					pperm_set->prows[i].entryid.cb && 0 ==
					memcmp(pperm_set->prows[i].entryid.pb,
					pentryid->pb, pentryid->cb)) {
					break;	
				}
			}
			if (j >= permission_set.count) {
				continue;
			}
			pmember_id = static_cast<uint64_t *>(common_util_get_propvals(
						permission_set.pparray[j],
			             PROP_TAG_MEMBERID));
			if (NULL == pmember_id) {
				continue;
			}
			pperm_data[count].flags = PERMISSION_DATA_FLAG_REMOVE_ROW;
			pperm_data[count].propvals.count = 1;
			pperm_data[count].propvals.ppropval = cu_alloc<TAGGED_PROPVAL>();
			if (NULL == pperm_data[i].propvals.ppropval) {
				return FALSE;
			}
			pperm_data[count].propvals.ppropval[0].proptag =
										PROP_TAG_MEMBERID;
			pperm_data[count].propvals.ppropval[0].pvalue =
												pmember_id;
		} else {
			continue;
		}
		count ++;
	}
	BOOL b_freebusy = !pfolder->pstore->b_private &&
	                  rop_util_get_gc_value(pfolder->folder_id) == PRIVATE_FID_CALENDAR ?
	                  TRUE : false;
	return exmdb_client::update_folder_permission(dir,
		pfolder->folder_id, b_freebusy, count, pperm_data);
}

static BOOL folder_object_flush_delegates(int fd,
	FORWARDDELEGATE_ACTION *paction)
{
	int i, j;
	int tmp_len;
	char *ptype;
	char *paddress;
	BINARY *pentryid;
	char address_buff[UADDR_SIZE];

	for (i=0; i<paction->count; i++) {
		ptype = NULL;
		paddress = NULL;
		pentryid = NULL;
		for (j=0; j<paction->pblock[i].count; j++) {
			switch (paction->pblock[i].ppropval[j].proptag) {
			case PROP_TAG_ADDRESSTYPE:
				ptype = static_cast<char *>(paction->pblock[i].ppropval[j].pvalue);
				break;
			case PR_ENTRYID:
				pentryid = static_cast<BINARY *>(paction->pblock[i].ppropval[j].pvalue);
				break;
			case PR_EMAIL_ADDRESS:
				paddress = static_cast<char *>(paction->pblock[i].ppropval[j].pvalue);
				break;
			}
		}
		address_buff[0] = '\0';
		if (NULL != ptype && NULL != paddress) {
			if (0 == strcasecmp(ptype, "SMTP")) {
				gx_strlcpy(address_buff, paddress, GX_ARRAY_SIZE(address_buff));
			} else if (0 == strcasecmp(ptype, "EX")) {
				common_util_essdn_to_username(paddress,
					address_buff, GX_ARRAY_SIZE(address_buff));
			}
		}
		if (address_buff[0] == '\0' && pentryid != nullptr &&
		    !common_util_entryid_to_username(pentryid,
		    address_buff, GX_ARRAY_SIZE(address_buff)))
			return FALSE;	
		if ('\0' != address_buff[0]) {
			tmp_len = strlen(address_buff);
			address_buff[tmp_len] = '\n';
			tmp_len ++;
			write(fd, address_buff, tmp_len);
		}
	}
	return TRUE;
}


BOOL FOLDER_OBJECT::updaterules(uint32_t flags, const RULE_LIST *plist)
{
	int i, fd;
	BOOL b_exceed;
	BOOL b_delegate;
	char *pprovider;
	char temp_path[256];
	RULE_ACTIONS *pactions = nullptr;
	auto pfolder = this;
	
	if (flags & MODIFY_RULES_FLAG_REPLACE &&
	    !exmdb_client::empty_folder_rule(pfolder->pstore->get_dir(), pfolder->folder_id))
		return FALSE;	
	b_delegate = FALSE;
	for (i=0; i<plist->count; i++) {
		if (FALSE == common_util_convert_from_zrule(
			&plist->prule[i].propvals)) {
			return FALSE;	
		}
		pprovider = static_cast<char *>(common_util_get_propvals(
				&plist->prule[i].propvals,
		            PROP_TAG_RULEPROVIDER));
		if (NULL == pprovider || 0 != strcasecmp(
			pprovider, "Schedule+ EMS Interface")) {
			continue;	
		}
		auto act = static_cast<RULE_ACTIONS *>(common_util_get_propvals(
					&plist->prule[i].propvals,
		           PROP_TAG_RULEACTIONS));
		if (NULL != pactions) {
			b_delegate = TRUE;
			pactions = act;
		}
	}
	if (pfolder->pstore->b_private &&
		PRIVATE_FID_INBOX == rop_util_get_gc_value(pfolder->folder_id)
		&& ((flags & MODIFY_RULES_FLAG_REPLACE) || TRUE == b_delegate)) {
		snprintf(temp_path, arsizeof(temp_path), "%s/config/delegates.txt",
		         pfolder->pstore->get_dir());
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			if (TRUE == b_delegate) {
				for (i=0; i<pactions->count; i++) {
					if (pactions->pblock[i].type == OP_DELEGATE &&
					    !folder_object_flush_delegates(fd, static_cast<FORWARDDELEGATE_ACTION *>(pactions->pblock[i].pdata))) {
						close(fd);
						return FALSE;
					}
				}
			}
			close(fd);
		}
	}
	return exmdb_client::update_folder_rule(pfolder->pstore->get_dir(),
		pfolder->folder_id, plist->count,
		plist->prule, &b_exceed);
}
