// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "objects.hpp"
#include "store_object.hpp"
#include "zserver.hpp"

using namespace std::string_literals;
using namespace gromox;

std::unique_ptr<folder_object> folder_object::create(store_object *pstore,
	uint64_t folder_id, uint8_t type, uint32_t tag_access)
{
	std::unique_ptr<folder_object> pfolder;
	try {
		pfolder.reset(new folder_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pfolder->pstore = pstore;
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
	
	if (!exmdb_client->get_folder_all_proptags(pfolder->pstore->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;		
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 30);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
		sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag[pproptags->count++] = PR_ACCESS;
	pproptags->pproptag[pproptags->count++] = PR_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_OBJECT_TYPE;
	pproptags->pproptag[pproptags->count++] = PR_MAPPING_SIGNATURE;
	pproptags->pproptag[pproptags->count++] = PR_RIGHTS;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_PARENT_SOURCE_KEY;
	pproptags->pproptag[pproptags->count++] = PR_STORE_ENTRYID;
	pproptags->pproptag[pproptags->count++] = PR_STORE_RECORD_KEY;
	if (!tmp_proptags.has(PR_SOURCE_KEY))
		pproptags->pproptag[pproptags->count++] = PR_SOURCE_KEY;
	if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
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

bool folder_object::is_readonly_prop(proptag_t proptag) const
{
	auto pfolder = this;
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
	case PR_STORE_ENTRYID:
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
	case PR_IPM_TASK_ENTRYID:
		return pfolder->pstore->b_private && toplevel(pfolder->folder_id);
	}
	return FALSE;
}

static BOOL folder_object_get_calculated_property(folder_object *pfolder,
    proptag_t proptag, void **ppvalue)
{
	BINARY *pbin;
	void *pvalue;
	EXT_PUSH ext_push;
	char temp_buff[1024];
	static constexpr uint8_t bin_buff[22]{};
	static constexpr uint32_t fake_del = 0;
	static constexpr BINARY fake_bin = {std::size(bin_buff), {deconst(bin_buff)}};
	
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = &pfolder->tag_access;
		return TRUE;
	case PR_CONTENT_UNREAD: {
		if (pfolder->pstore->b_private)
			return false;
		*ppvalue = cu_alloc<uint32_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		auto pinfo = zs_get_info();
		return exmdb_client->get_public_folder_unread_count(pfolder->pstore->get_dir(),
		       pinfo->get_username(), pfolder->folder_id,
		       static_cast<uint32_t *>(*ppvalue));
	}
	case PidTagFolderId:
		*ppvalue = cu_alloc<uint64_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		*static_cast<uint64_t *>(*ppvalue) = pfolder->folder_id;
		return TRUE;
	case PR_RIGHTS: {
		*ppvalue = cu_alloc<uint32_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		if (pfolder->pstore->owner_mode()) {
			*static_cast<uint32_t *>(*ppvalue) = rightsAll | frightsContact;
			return TRUE;
		}
		auto pinfo = zs_get_info();
		return exmdb_client->get_folder_perm(pfolder->pstore->get_dir(),
		       pfolder->folder_id, pinfo->get_username(),
		       static_cast<uint32_t *>(*ppvalue));
	}
	case PR_ENTRYID:
	case PR_RECORD_KEY:
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore, pfolder->folder_id);
		return TRUE;
	case PR_PARENT_ENTRYID:
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    CP_ACP, pfolder->folder_id, PidTagParentFolderId, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
		           *static_cast<uint64_t *>(pvalue));
		return TRUE;
	case PR_SOURCE_KEY:
		*ppvalue = cu_fid_to_sk(*pfolder->pstore, pfolder->folder_id);
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
		    CP_ACP, pfolder->folder_id, PidTagParentFolderId, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;	
		*ppvalue = cu_fid_to_sk(*pfolder->pstore,
		           *static_cast<uint64_t *>(pvalue));
		return TRUE;
	case PR_STORE_RECORD_KEY:
	case PR_MAPPING_SIGNATURE:
		*ppvalue = common_util_guid_to_binary(pfolder->pstore->mailbox_guid);
		return TRUE;
	case PR_STORE_ENTRYID:
		*ppvalue = cu_to_store_entryid(*pfolder->pstore);
		return *ppvalue != nullptr ? TRUE : false;
	case PR_DELETED_FOLDER_COUNT:
		/* just like Exchange 2013, always return 0 */
		*ppvalue = deconst(&fake_del);
		return TRUE;
	case PR_IPM_DRAFTS_ENTRYID:
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;	
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PR_IPM_CONTACT_ENTRYID:
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PR_IPM_APPOINTMENT_ENTRYID:
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PR_IPM_JOURNAL_ENTRYID:
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PR_IPM_NOTE_ENTRYID:
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PR_IPM_TASK_ENTRYID:
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		*ppvalue = cu_fid_to_entryid(*pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		return TRUE;
	case PR_REM_ONLINE_ENTRYID:
		if (!pfolder->pstore->b_private)
			return FALSE;
		if (pfolder->folder_id != rop_util_make_eid_ex(
		    1, PRIVATE_FID_ROOT))
			return FALSE;	
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_REM_ONLINE_ENTRYID, &pvalue) ||
		    pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	case PR_ADDITIONAL_REN_ENTRYIDS: {
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_ADDITIONAL_REN_ENTRYIDS, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = cu_alloc<BINARY_ARRAY>();
		if (*ppvalue == nullptr)
			return FALSE;
		auto ba = static_cast<BINARY_ARRAY *>(*ppvalue);
		ba->count = 5;
		ba->pbin = cu_alloc<BINARY>(ba->count);
		if (ba->pbin == nullptr) {
			ba->count = 0;
			return FALSE;
		}
		pbin = cu_fid_to_entryid(*pfolder->pstore,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[0] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[1] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[2] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->pstore,
			rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[3] = *pbin;
		pbin = cu_fid_to_entryid(*pfolder->pstore,
				rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[4] = *pbin;
		return TRUE;
	}
	case PR_ADDITIONAL_REN_ENTRYIDS_EX: {
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_ADDITIONAL_REN_ENTRYIDS_EX, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		const PERSISTDATA pd[] = {
			{RSF_PID_CONV_ACTIONS, RSF_ELID_ENTRYID, cu_fid_to_entryid_s(*pfolder->pstore, rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS))},
			{RSF_PID_BUDDYLIST_PDLS, RSF_ELID_ENTRYID, cu_fid_to_entryid_s(*pfolder->pstore, rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST))},
			{RSF_PID_BUDDYLIST_CONTACTS, RSF_ELID_ENTRYID, cu_fid_to_entryid_s(*pfolder->pstore, rop_util_make_eid_ex(1, PRIVATE_FID_QUICKCONTACTS))},
		};
		if (!ext_push.init(temp_buff, sizeof(temp_buff), 0) ||
		    ext_push.p_persistdata_a(pd) != pack_result::ok)
			return FALSE;	
		*ppvalue = cu_alloc<BINARY>();
		if (*ppvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(*ppvalue);
		bv->cb = ext_push.m_offset;
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr) {
			bv->cb = 0;
			return FALSE;
		}
		memcpy(bv->pv, ext_push.m_udata, bv->cb);
		return TRUE;
	}
	case PR_FREEBUSY_ENTRYIDS: {
		if (!pfolder->pstore->b_private || !toplevel(pfolder->folder_id))
			return FALSE;
		if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
		    CP_ACP, rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
		    PR_FREEBUSY_ENTRYIDS, &pvalue))
			return FALSE;
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = cu_alloc<BINARY_ARRAY>();
		if (*ppvalue == nullptr)
			return FALSE;
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
		pbin = cu_fid_to_entryid(*pfolder->pstore,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
		if (pbin == nullptr)
			return FALSE;
		ba->pbin[3] = *pbin;
		return TRUE;
	}
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = static_cast<uint32_t>(MAPI_FOLDER);
		return TRUE;
	}
	}
	return FALSE;
}

BOOL folder_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
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
			return false;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	auto pinfo = zs_get_info();
	if (!exmdb_client->get_folder_properties(pfolder->pstore->get_dir(),
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

BOOL folder_object::set_properties(const TPROPVAL_ARRAY *ppropvals)
{
	uint16_t count;
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (ppropvals->count == 0)
		return TRUE;
	count = ppropvals->count + 4;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(count);
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	memcpy(tmp_propvals.ppropval, ppropvals->ppropval,
			sizeof(TAGGED_PROPVAL)*ppropvals->count);
	tmp_propvals.count = ppropvals->count;
	auto pfolder = this;
	if (!exmdb_client->allocate_cn(pfolder->pstore->get_dir(), &change_num))
		return FALSE;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PidTagChangeNumber;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = &change_num;
	if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
	    CP_ACP, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)))
		return FALSE;
	auto pbin_changekey = cu_xid_to_bin({pfolder->pstore->guid(), change_num});
	if (pbin_changekey == nullptr)
		return FALSE;
	pbin_pcl = common_util_pcl_append(pbin_pcl, pbin_changekey);
	if (pbin_pcl == nullptr)
		return FALSE;
	last_time = rop_util_current_nttime();
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_CHANGE_KEY;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pbin_changekey;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_PREDECESSOR_CHANGE_LIST;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = pbin_pcl;
	tmp_propvals.ppropval[tmp_propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
	tmp_propvals.ppropval[tmp_propvals.count++].pvalue = &last_time;
	auto pinfo = zs_get_info();
	if (!exmdb_client->set_folder_properties(pfolder->pstore->get_dir(),
	    pinfo->cpid, pfolder->folder_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	return TRUE;
}

BOOL folder_object::remove_properties(const PROPTAG_ARRAY *pproptags)
{
	BINARY *pbin_pcl;
	uint64_t last_time;
	uint64_t change_num;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[4];
	
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	auto pfolder = this;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (pfolder->is_readonly_prop(tag))
			continue;
		tmp_proptags.pproptag[tmp_proptags.count++] = tag;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client->remove_folder_properties(pfolder->pstore->get_dir(),
	    pfolder->folder_id, &tmp_proptags))
		return FALSE;	
	tmp_propvals.count = 4;
	tmp_propvals.ppropval = propval_buff;
	if (!exmdb_client->allocate_cn(pfolder->pstore->get_dir(), &change_num))
		return TRUE;
	if (!exmdb_client_get_folder_property(pfolder->pstore->get_dir(),
	    CP_ACP, pfolder->folder_id, PR_PREDECESSOR_CHANGE_LIST,
	    reinterpret_cast<void **>(&pbin_pcl)))
		return FALSE;
	propval_buff[0].proptag = PidTagChangeNumber;
	propval_buff[0].pvalue = &change_num;
	auto pbin_changekey = cu_xid_to_bin({pfolder->pstore->guid(), change_num});
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
	exmdb_client->set_folder_properties(pfolder->pstore->get_dir(), CP_ACP,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}

BOOL folder_object::get_permissions(PERMISSION_SET *pperm_set)
{
	uint32_t row_num;
	uint32_t table_id;
	TARRAY_SET permission_set;
	static constexpr proptag_t proptag_buff[] = {PR_ENTRYID, PR_MEMBER_RIGHTS, PR_MEMBER_ID};
	static constexpr PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	
	auto pfolder = this;
	auto dir = pfolder->pstore->get_dir();
	uint32_t flags = pfolder->pstore->b_private &&
	                 rop_util_get_gc_value(pfolder->folder_id) == PRIVATE_FID_CALENDAR ?
		         PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY : 0;
	if (!exmdb_client->load_permission_table(dir,
		pfolder->folder_id, flags, &table_id, &row_num)) {
		return FALSE;
	}
	if (!exmdb_client->query_table(dir, nullptr, CP_ACP,
		table_id, &proptags, 0, row_num, &permission_set)) {
		exmdb_client->unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client->unload_table(dir, table_id);
	pperm_set->count = 0;
	pperm_set->prows = cu_alloc<PERMISSION_ROW>(permission_set.count);
	if (pperm_set->prows == nullptr)
		return FALSE;
	for (size_t i = 0; i < permission_set.count; ++i) {
		auto pentry_id = permission_set.pparray[i]->get<BINARY>(PR_ENTRYID);
		auto &cur = pperm_set->prows[pperm_set->count];
		cur.flags = RIGHT_NORMAL;
		auto v = permission_set.pparray[i]->get<uint32_t>(PR_MEMBER_RIGHTS);
		if (v == nullptr)
			continue;
		cur.member_rights = *v;
		v = permission_set.pparray[i]->get<uint32_t>(PR_MEMBER_ID);
		cur.member_id = v != nullptr ? *v : 0xdeadbeefU;
		cur.entryid = pentry_id != nullptr ? *pentry_id : BINARY{};
		++pperm_set->count;
	}
	return TRUE;
}

BOOL folder_object::set_permissions(const PERMISSION_SET *pperm_set)
{
	uint32_t row_num;
	uint32_t table_id;
	TARRAY_SET permission_set;
	PERMISSION_DATA *pperm_data;
	
	auto pfolder = this;
	auto dir = pfolder->pstore->get_dir();
	if (!exmdb_client->load_permission_table(dir,
	    pfolder->folder_id, 0, &table_id, &row_num))
		return FALSE;
	static constexpr proptag_t proptag_buff[] = {PR_ENTRYID, PR_MEMBER_ID};
	static constexpr PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	if (!exmdb_client->query_table(dir, nullptr, CP_ACP,
		table_id, &proptags, 0, row_num, &permission_set)) {
		exmdb_client->unload_table(dir, table_id);
		return FALSE;
	}
	exmdb_client->unload_table(dir, table_id);
	pperm_data = cu_alloc<PERMISSION_DATA>(pperm_set->count);
	if (pperm_data == nullptr)
		return FALSE;
	uint16_t count = 0;
	/* For each row in the new set... */
	for (size_t i = 0; i < pperm_set->count; ++i) {
		if (pperm_set->prows[i].flags & (RIGHT_NEW | RIGHT_MODIFY)) {
			size_t j;
			/* ... check against the old set rows. */
			for (j = 0; j < permission_set.count; ++j)
				if (permrow_entryids_equal(pperm_set->prows[i],
				    permission_set.pparray[j]->get<uint32_t>(PR_MEMBER_ID),
				    permission_set.pparray[j]->get<BINARY>(PR_ENTRYID)))
					break;
			if (j < permission_set.count) {
				auto pmember_id = permission_set.pparray[j]->get<uint64_t>(PR_MEMBER_ID);
				if (pmember_id == nullptr)
					continue;
				pperm_data[count].flags = ROW_MODIFY;
				pperm_data[count].propvals.count = 2;
				pperm_data[count].propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(2);
				if (pperm_data[count].propvals.ppropval == nullptr)
					return FALSE;
				pperm_data[count].propvals.ppropval[0].proptag = PR_MEMBER_ID;
				pperm_data[count].propvals.ppropval[0].pvalue = pmember_id;
				pperm_data[count].propvals.ppropval[1].proptag = PR_MEMBER_RIGHTS;
				pperm_data[count].propvals.ppropval[1].pvalue =
							&pperm_set->prows[i].member_rights;
				count ++;
				continue;
			}
		}
		if (pperm_set->prows[i].flags & RIGHT_NEW) {
			pperm_data[count].flags = ROW_ADD;
			pperm_data[count].propvals.count = 2;
			pperm_data[count].propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(2);
			if (pperm_data[count].propvals.ppropval == nullptr)
				return FALSE;
			pperm_data[count].propvals.ppropval[0].proptag = PR_ENTRYID;
			pperm_data[count].propvals.ppropval[0].pvalue =
								&pperm_set->prows[i].entryid;
			pperm_data[count].propvals.ppropval[1].proptag = PR_MEMBER_RIGHTS;
			pperm_data[count].propvals.ppropval[1].pvalue =
						&pperm_set->prows[i].member_rights;
		} else if (pperm_set->prows[i].flags & RIGHT_DELETED) {
			size_t j;
			for (j = 0; j < permission_set.count; ++j)
				if (permrow_entryids_equal(pperm_set->prows[i],
				    permission_set.pparray[j]->get<uint32_t>(PR_MEMBER_ID),
				    permission_set.pparray[j]->get<BINARY>(PR_ENTRYID)))
					break;	
			if (j >= permission_set.count)
				continue;
			auto pmember_id = permission_set.pparray[j]->get<uint64_t>(PR_MEMBER_ID);
			if (pmember_id == nullptr)
				continue;
			pperm_data[count].flags = ROW_REMOVE;
			pperm_data[count].propvals.count = 1;
			pperm_data[count].propvals.ppropval = cu_alloc<TAGGED_PROPVAL>();
			if (pperm_data[count].propvals.ppropval == nullptr)
				return FALSE;
			pperm_data[count].propvals.ppropval[0].proptag = PR_MEMBER_ID;
			pperm_data[count].propvals.ppropval[0].pvalue = pmember_id;
		} else {
			continue;
		}
		count ++;
	}
	BOOL b_freebusy = pfolder->pstore->b_private &&
	                  rop_util_get_gc_value(pfolder->folder_id) == PRIVATE_FID_CALENDAR ?
	                  TRUE : false;
	return exmdb_client->update_folder_permission(dir,
		pfolder->folder_id, b_freebusy, count, pperm_data);
}

static int folder_object_flush_delegates(int fd,
    const FORWARDDELEGATE_ACTION &action)
{
	for (const auto &dlgt : action) {
		const char *ptype = nullptr, *paddress = nullptr;
		const BINARY *pentryid = nullptr;
		for (const auto &p : dlgt) {
			switch (p.proptag) {
			case PR_ADDRTYPE:
				ptype = static_cast<const char *>(p.pvalue);
				break;
			case PR_ENTRYID:
				pentryid = static_cast<const BINARY *>(p.pvalue);
				break;
			case PR_EMAIL_ADDRESS:
				paddress = static_cast<const char *>(p.pvalue);
				break;
			}
		}
		std::string address_buff;
		if (ptype != nullptr) {
			auto ret = cvt_genaddr_to_smtpaddr(ptype, paddress,
			           g_org_name, cu_id2user, address_buff);
			if (ret == ecSuccess)
				/* ok */;
			else if (ret != ecNullObject)
				return -1;
		}
		if (address_buff.empty() && pentryid != nullptr) {
			auto ret = cvt_entryid_to_smtpaddr(pentryid, g_org_name,
			           cu_id2user, address_buff);
			if (ret == ecSuccess)
				/* ok */;
			else if (ret != ecNullObject)
				return -1;
		}
		if (address_buff.size() > 0) {
			address_buff += '\n';
			auto ret = HXio_fullwrite(fd, address_buff.c_str(), address_buff.size());
			if (ret < 0 || static_cast<size_t>(ret) != address_buff.size())
				return -2;
		}
	}
	return 0;
}

BOOL folder_object::updaterules(uint32_t flags, RULE_LIST *plist) try
{
	BOOL b_exceed;
	BOOL b_delegate;
	const RULE_ACTIONS *pactions = nullptr;
	auto pfolder = this;
	
	if (flags & MODIFY_RULES_FLAG_REPLACE &&
	    !exmdb_client->empty_folder_rule(pfolder->pstore->get_dir(), pfolder->folder_id))
		return FALSE;	
	b_delegate = FALSE;
	for (auto &rule : *plist) {
		if (!common_util_convert_from_zrule(&rule.propvals))
			return FALSE;	
		auto pprovider = rule.propvals.get<char>(PR_RULE_PROVIDER);
		if (pprovider == nullptr ||
		    strcasecmp(pprovider, "Schedule+ EMS Interface") != 0)
			continue;	
		auto act = rule.propvals.get<RULE_ACTIONS>(PR_RULE_ACTIONS);
		if (act != nullptr) {
			b_delegate = TRUE;
			pactions = act;
		}
	}
	if (pfolder->pstore->b_private &&
	    rop_util_get_gc_value(pfolder->folder_id) == PRIVATE_FID_INBOX &&
	    ((flags & MODIFY_RULES_FLAG_REPLACE) || b_delegate)) {
		auto dlg_dir  = pfolder->pstore->get_dir() + "/config"s;
		auto dlg_path = dlg_dir + "/delegates.txt";
		gromox::tmpfile fd;
		if (fd.open_linkable(dlg_dir.c_str(), O_CREAT | O_TRUNC | O_WRONLY, FMODE_PUBLIC) >= 0 &&
		    b_delegate)
			for (const auto &a : *pactions) {
				if (a.type != OP_DELEGATE)
					continue;
				auto ret = folder_object_flush_delegates(fd,
				           *static_cast<const FORWARDDELEGATE_ACTION *>(a.pdata));
				if (ret == -2)
					mlog(LV_ERR, "E-2330: write %s: %s",
						fd.m_path.c_str(), strerror(errno));
				if (ret < 0)
					return false;
			}
		if (fd.link_to(dlg_path.c_str()) != 0)
			mlog(LV_ERR, "E-2350: link %s %s: %s", fd.m_path.c_str(),
				dlg_path.c_str(), strerror(errno));
	}
	return exmdb_client->update_folder_rule(pfolder->pstore->get_dir(),
		pfolder->folder_id, plist->count,
		plist->prule, &b_exceed);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1491: ENOMEM");
	return false;
}
