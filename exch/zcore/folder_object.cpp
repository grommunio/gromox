// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
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


FOLDER_OBJECT* folder_object_create(STORE_OBJECT *pstore,
	uint64_t folder_id, uint8_t type, uint32_t tag_access)
{
	auto pfolder = me_alloc<FOLDER_OBJECT>();
	if (NULL == pfolder) {
		return NULL;
	}
	pfolder->pstore = pstore;
	pfolder->folder_id = folder_id;
	pfolder->type = type;
	pfolder->tag_access = tag_access;
	return pfolder;
}

void folder_object_free(FOLDER_OBJECT *pfolder)
{
	free(pfolder);
}

uint64_t folder_object_get_id(FOLDER_OBJECT *pfolder)
{
	return pfolder->folder_id;
}

uint8_t folder_object_get_type(FOLDER_OBJECT *pfolder)
{
	return pfolder->type;
}

STORE_OBJECT* folder_object_get_store(FOLDER_OBJECT *pfolder)
{
	return pfolder->pstore;
}

BOOL folder_object_get_all_proptags(FOLDER_OBJECT *pfolder,
	PROPTAG_ARRAY *pproptags)
{
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_folder_all_proptags(
		store_object_get_dir(pfolder->pstore),
		pfolder->folder_id, &tmp_proptags)) {
		return FALSE;		
	}
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 30);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
		sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag[pproptags->count] = PROP_TAG_ACCESS;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_ENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_OBJECTTYPE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_MAPPINGSIGNATURE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_RIGHTS;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_PARENTENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_PARENTSOURCEKEY;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_STOREENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_STORERECORDKEY;
	pproptags->count ++;
	if (common_util_index_proptags(&tmp_proptags,
		PROP_TAG_SOURCEKEY) < 0) {
		pproptags->pproptag[pproptags->count] = PROP_TAG_SOURCEKEY;
		pproptags->count ++;
	}
	if (TRUE == store_object_check_private(pfolder->pstore)) {
		if (pfolder->folder_id == rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) || pfolder->folder_id ==
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_IPMDRAFTSENTRYID) < 0) {
				pproptags->pproptag[pproptags->count] =
							PROP_TAG_IPMDRAFTSENTRYID;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_IPMCONTACTENTRYID) < 0) {
				pproptags->pproptag[pproptags->count] =
							PROP_TAG_IPMCONTACTENTRYID;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_IPMAPPOINTMENTENTRYID) < 0) {
				pproptags->pproptag[pproptags->count] =
						PROP_TAG_IPMAPPOINTMENTENTRYID;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_IPMJOURNALENTRYID) < 0) {
				pproptags->pproptag[pproptags->count] =
							PROP_TAG_IPMJOURNALENTRYID;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_IPMNOTEENTRYID) < 0) {
				pproptags->pproptag[pproptags->count] =
								PROP_TAG_IPMNOTEENTRYID;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_IPMTASKENTRYID) < 0) {
				pproptags->pproptag[pproptags->count] =
								PROP_TAG_IPMTASKENTRYID;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_FREEBUSYENTRYIDS) < 0) {
				pproptags->pproptag[pproptags->count] =
							PROP_TAG_FREEBUSYENTRYIDS;
				pproptags->count ++;
				
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_ADDITIONALRENENTRYIDS) < 0) {
				pproptags->pproptag[pproptags->count] =
					PROP_TAG_ADDITIONALRENENTRYIDS;
				pproptags->count ++;
			}
			if (common_util_index_proptags(&tmp_proptags,
				PROP_TAG_ADDITIONALRENENTRYIDSEX) < 0) {
				pproptags->pproptag[pproptags->count] =
						PROP_TAG_ADDITIONALRENENTRYIDSEX;
				pproptags->count ++;
			}
		}
	}
	return TRUE;
}

BOOL folder_object_check_readonly_property(
	FOLDER_OBJECT *pfolder, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT)
		return TRUE;
	switch (proptag) {
	case PROP_TAG_ACCESS:
	case PROP_TAG_ADDRESSBOOKENTRYID:
	case PROP_TAG_ARTICLENUMBERNEXT:
	case PROP_TAG_ASSOCIATEDCONTENTCOUNT:
	case PROP_TAG_ATTRIBUTEREADONLY:
	case PROP_TAG_CHANGENUMBER:
	case PROP_TAG_CONTENTCOUNT:
	case PROP_TAG_CONTENTUNREADCOUNT:
	case PROP_TAG_CREATIONTIME:
	case PROP_TAG_DELETEDCOUNTTOTAL:
	case PROP_TAG_DELETEDFOLDERTOTAL:
	case PROP_TAG_DELETEDON:
	case PROP_TAG_ENTRYID:
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
	case PROP_TAG_MESSAGESIZE:
	case PROP_TAG_MESSAGESIZEEXTENDED:
	case PROP_TAG_ASSOCMESSAGESIZE:
	case PROP_TAG_ASSOCMESSAGESIZEEXTENDED:
	case PROP_TAG_NORMALMESSAGESIZE:
	case PROP_TAG_NORMALMESSAGESIZEEXTENDED:
	case PROP_TAG_PARENTENTRYID:
	case PROP_TAG_PARENTFOLDERID:
	case PROP_TAG_STORERECORDKEY:
	case PROP_TAG_STOREENTRYID:
	case PROP_TAG_CHANGEKEY:
	case PROP_TAG_SOURCEKEY:
	case PROP_TAG_PARENTSOURCEKEY:
	case PROP_TAG_PREDECESSORCHANGELIST:
	case PROP_TAG_LASTMODIFICATIONTIME:
		return TRUE;
	case PROP_TAG_IPMDRAFTSENTRYID:
	case PROP_TAG_IPMCONTACTENTRYID:
	case PROP_TAG_IPMAPPOINTMENTENTRYID:
	case PROP_TAG_IPMJOURNALENTRYID:
	case PROP_TAG_IPMNOTEENTRYID:
	case PROP_TAG_IPMTASKENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
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
	USER_INFO *pinfo;
	EXT_PUSH ext_push;
	char temp_buff[1024];
	PERSISTDATA *ppersistdata;
	static constexpr uint8_t bin_buff[22]{};
	static constexpr uint32_t fake_del = 0;
	PERSISTDATA_ARRAY persistdatas;
	static constexpr BINARY fake_bin = {sizeof(bin_buff), const_cast<uint8_t *>(bin_buff)};
	
	switch (proptag) {
	case PROP_TAG_ACCESS:
		*ppvalue = &pfolder->tag_access;
		return TRUE;
	case PROP_TAG_CONTENTUNREADCOUNT:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			*ppvalue = cu_alloc<uint32_t>();
			if (NULL == *ppvalue) {
				return FALSE;
			}
			pinfo = zarafa_server_get_info();
			return exmdb_client::get_public_folder_unread_count(
						store_object_get_dir(pfolder->pstore),
						pinfo->username, pfolder->folder_id,
			       static_cast<uint32_t *>(*ppvalue));
		}
		return FALSE;
	case PROP_TAG_FOLDERID:
		*ppvalue = cu_alloc<uint64_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint64_t*)(*ppvalue) = pfolder->folder_id;
		return TRUE;
	case PROP_TAG_RIGHTS:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (TRUE == store_object_check_owner_mode(pfolder->pstore)) {
			*(uint32_t*)(*ppvalue) =
				PERMISSION_READANY|PERMISSION_CREATE|
				PERMISSION_EDITOWNED|PERMISSION_DELETEOWNED|
				PERMISSION_EDITANY|PERMISSION_DELETEANY|
				PERMISSION_CREATESUBFOLDER|PERMISSION_FOLDEROWNER|
				PERMISSION_FOLDERCONTACT|PERMISSION_FOLDERVISIBLE;
		} else {
			pinfo = zarafa_server_get_info();
			if (!exmdb_client::check_folder_permission(
				store_object_get_dir(pfolder->pstore),
			    pfolder->folder_id, pinfo->username,
			    static_cast<uint32_t *>(*ppvalue))) {
				return FALSE;
			}
		}
		return TRUE;
	case PROP_TAG_ENTRYID:
	case PROP_TAG_RECORDKEY:
		*ppvalue = common_util_to_folder_entryid(
			pfolder->pstore, pfolder->folder_id);
		return TRUE;
	case PROP_TAG_PARENTENTRYID:
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pfolder->pstore), 0,
			pfolder->folder_id, PROP_TAG_PARENTFOLDERID,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(
			pfolder->pstore, *(uint64_t*)pvalue);
		return TRUE;
	case PROP_TAG_SOURCEKEY:
		*ppvalue = common_util_calculate_folder_sourcekey(
					pfolder->pstore, pfolder->folder_id);
		return TRUE;
	case PROP_TAG_PARENTSOURCEKEY:
		if (TRUE == store_object_check_private(pfolder->pstore)) {
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
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pfolder->pstore), 0,
			pfolder->folder_id, PROP_TAG_PARENTFOLDERID,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		*ppvalue = common_util_calculate_folder_sourcekey(
					pfolder->pstore, *(uint64_t*)pvalue);
		return TRUE;
	case PROP_TAG_STORERECORDKEY:
	case PROP_TAG_MAPPINGSIGNATURE:
		*ppvalue = common_util_guid_to_binary(
				store_object_get_mailbox_guid(
				pfolder->pstore));
		return TRUE;
	case PROP_TAG_STOREENTRYID:
		*ppvalue = common_util_to_store_entryid(pfolder->pstore);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	case PROP_TAG_DELETEDFOLDERTOTAL:
		/* just like exchange 2013, alway return 0 */
		*ppvalue = deconst(&fake_del);
		return TRUE;
	case PROP_TAG_IPMDRAFTSENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PROP_TAG_IPMCONTACTENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PROP_TAG_IPMAPPOINTMENTENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PROP_TAG_IPMJOURNALENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PROP_TAG_IPMNOTEENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->pstore,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PROP_TAG_IPMTASKENTRYID:
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
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
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pfolder->pstore), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_REMINDERSONLINEENTRYID, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDITIONALRENENTRYIDS: {
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pfolder->pstore), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_ADDITIONALRENENTRYIDS, &pvalue)) {
			return FALSE;
		}
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
	case PROP_TAG_ADDITIONALRENENTRYIDSEX: {
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pfolder->pstore), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_ADDITIONALRENENTRYIDSEX, &pvalue)) {
			return FALSE;
		}
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
		ext_buffer_push_init(&ext_push, temp_buff, sizeof(temp_buff), 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_persistdata_array(
			&ext_push, &persistdatas)) {
			return FALSE;	
		}
		bv->cb = ext_push.offset;
		bv->pv = common_util_alloc(ext_push.offset);
		if (bv->pv == nullptr) {
			bv->cb = 0;
			return FALSE;
		}
		memcpy(bv->pv, ext_push.data, ext_push.offset);
		return TRUE;
	}
	case PROP_TAG_FREEBUSYENTRYIDS: {
		if (FALSE == store_object_check_private(pfolder->pstore)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(
			1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			store_object_get_dir(pfolder->pstore), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_FREEBUSYENTRYIDS, &pvalue)) {
			return FALSE;
		}
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
	case PROP_TAG_OBJECTTYPE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = OBJECT_FOLDER;
		return TRUE;
	}
	return FALSE;
}

BOOL folder_object_get_properties(FOLDER_OBJECT *pfolder,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	USER_INFO *pinfo;
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
	pinfo = zarafa_server_get_info();
	if (!exmdb_client::get_folder_properties(
		store_object_get_dir(pfolder->pstore), pinfo->cpid,
		pfolder->folder_id, &tmp_proptags, &tmp_propvals)) {
		return FALSE;
	}
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval + ppropvals->count,
			tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	return TRUE;	
}

BOOL folder_object_set_properties(FOLDER_OBJECT *pfolder,
	const TPROPVAL_ARRAY *ppropvals)
{
	XID tmp_xid;
	uint16_t count;
	BINARY *pbin_pcl;
	USER_INFO *pinfo;
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
	if (!exmdb_client::allocate_cn(
		store_object_get_dir(pfolder->pstore),
		&change_num)) {
		return FALSE;
	}
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_CHANGENUMBER;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue =
											&change_num;
	tmp_propvals.count ++;
	if (FALSE == exmdb_client_get_folder_property(
		store_object_get_dir(pfolder->pstore), 0,
		pfolder->folder_id, PROP_TAG_PREDECESSORCHANGELIST,
		(void**)&pbin_pcl) || NULL == pbin_pcl) {
		return FALSE;
	}
	tmp_xid.guid = store_object_guid(pfolder->pstore);
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
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_CHANGEKEY;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = 
										pbin_changekey;
	tmp_propvals.count ++;
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
						PROP_TAG_PREDECESSORCHANGELIST;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue =
												pbin_pcl;
	tmp_propvals.count ++;
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
							PROP_TAG_LASTMODIFICATIONTIME;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue =
											&last_time;
	tmp_propvals.count ++;
	pinfo = zarafa_server_get_info();
	if (!exmdb_client::set_folder_properties(
		store_object_get_dir(pfolder->pstore), pinfo->cpid,
		pfolder->folder_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	return TRUE;
}

BOOL folder_object_remove_properties(FOLDER_OBJECT *pfolder,
	const PROPTAG_ARRAY *pproptags)
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
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == folder_object_check_readonly_property(
			pfolder, pproptags->pproptag[i])) {
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] =
							pproptags->pproptag[i];
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client::remove_folder_properties(
		store_object_get_dir(pfolder->pstore),
		pfolder->folder_id, &tmp_proptags)) {
		return FALSE;	
	}
	tmp_propvals.count = 4;
	tmp_propvals.ppropval = propval_buff;
	if (!exmdb_client::allocate_cn(
		store_object_get_dir(pfolder->pstore), &change_num)) {
		return TRUE;
	}
	if (FALSE == exmdb_client_get_folder_property(
		store_object_get_dir(pfolder->pstore), 0,
		pfolder->folder_id, PROP_TAG_PREDECESSORCHANGELIST,
		(void**)&pbin_pcl) || NULL == pbin_pcl) {
		return FALSE;
	}
	propval_buff[0].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[0].pvalue = &change_num;
	tmp_xid.guid = store_object_guid(pfolder->pstore);
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
	propval_buff[1].proptag = PROP_TAG_CHANGEKEY;
	propval_buff[1].pvalue = pbin_changekey;
	propval_buff[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval_buff[2].pvalue = pbin_pcl;
	propval_buff[3].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval_buff[3].pvalue = &last_time;
	exmdb_client::set_folder_properties(
		store_object_get_dir(pfolder->pstore), 0,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}

BOOL folder_object_get_permissions(FOLDER_OBJECT *pfolder,
	PERMISSION_SET *pperm_set)
{
	const char *dir;
	uint32_t row_num;
	uint32_t *prights;
	uint32_t table_id;
	BINARY *pentry_id;
	PROPTAG_ARRAY proptags;
	TARRAY_SET permission_set;
	static const uint32_t proptag_buff[] = {
		PROP_TAG_ENTRYID,
		PROP_TAG_MEMBERRIGHTS
	};
	
	dir = store_object_get_dir(pfolder->pstore);
	uint32_t flags = !store_object_check_private(pfolder->pstore) &&
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
		            permission_set.pparray[i], PROP_TAG_ENTRYID));
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

BOOL folder_object_set_permissions(FOLDER_OBJECT *pfolder,
	const PERMISSION_SET *pperm_set)
{
	const char *dir;
	BINARY *pentryid;
	uint32_t row_num;
	uint32_t table_id;
	uint64_t *pmember_id;
	PROPTAG_ARRAY proptags;
	TARRAY_SET permission_set;
	PERMISSION_DATA *pperm_data;
	static const uint32_t proptag_buff[] = {
		PROP_TAG_ENTRYID,
		PROP_TAG_MEMBERID
	};
	
	dir = store_object_get_dir(pfolder->pstore);
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
							permission_set.pparray[j],
				           PROP_TAG_ENTRYID));
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
			pperm_data[count].propvals.ppropval[0].proptag =
											PROP_TAG_ENTRYID;
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
							permission_set.pparray[j],
				           PROP_TAG_ENTRYID));
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
	BOOL b_freebusy = !store_object_check_private(pfolder->pstore) &&
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
	char address_buff[324];

	for (i=0; i<paction->count; i++) {
		ptype = NULL;
		paddress = NULL;
		pentryid = NULL;
		for (j=0; j<paction->pblock[i].count; j++) {
			switch (paction->pblock[i].ppropval[j].proptag) {
			case PROP_TAG_ADDRESSTYPE:
				ptype = static_cast<char *>(paction->pblock[i].ppropval[j].pvalue);
				break;
			case PROP_TAG_ENTRYID:
				pentryid = static_cast<BINARY *>(paction->pblock[i].ppropval[j].pvalue);
				break;
			case PROP_TAG_EMAILADDRESS:
				paddress = static_cast<char *>(paction->pblock[i].ppropval[j].pvalue);
				break;
			}
		}
		address_buff[0] = '\0';
		if (NULL != ptype && NULL != paddress) {
			if (0 == strcasecmp(ptype, "SMTP")) {
				HX_strlcpy(address_buff, paddress, GX_ARRAY_SIZE(address_buff));
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


BOOL folder_object_updaterules(FOLDER_OBJECT *pfolder,
	uint32_t flags, const RULE_LIST *plist)
{
	int i, fd;
	BOOL b_exceed;
	BOOL b_delegate;
	char *pprovider;
	char temp_path[256];
	RULE_ACTIONS *pactions = nullptr;
	
	if (flags & MODIFY_RULES_FLAG_REPLACE) {
		if (!exmdb_client::empty_folder_rule(
			store_object_get_dir(pfolder->pstore),
			pfolder->folder_id)) {
			return FALSE;	
		}
	}
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
		pactions = static_cast<RULE_ACTIONS *>(common_util_get_propvals(
					&plist->prule[i].propvals,
		           PROP_TAG_RULEACTIONS));
		if (NULL != pactions) {
			b_delegate = TRUE;
		}
	}
	if (TRUE == store_object_check_private(pfolder->pstore) &&
		PRIVATE_FID_INBOX == rop_util_get_gc_value(pfolder->folder_id)
		&& ((flags & MODIFY_RULES_FLAG_REPLACE) || TRUE == b_delegate)) {
		sprintf(temp_path, "%s/config/delegates.txt",
				store_object_get_dir(pfolder->pstore));
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			if (TRUE == b_delegate) {
				for (i=0; i<pactions->count; i++) {
					if (pactions->pblock[i].type == OP_DELEGATE) {
						if (!folder_object_flush_delegates(
						    fd, static_cast<FORWARDDELEGATE_ACTION *>(pactions->pblock[i].pdata))) {
							close(fd);
							return FALSE;
						}
					}
				}
			}
			close(fd);
		}
	}
	return exmdb_client::update_folder_rule(
		store_object_get_dir(pfolder->pstore),
		pfolder->folder_id, plist->count,
		plist->prule, &b_exceed);
}
