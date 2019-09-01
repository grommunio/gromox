#include "emsmdb_interface.h"
#include "tpropval_array.h"
#include "folder_object.h"
#include "exmdb_client.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "rop_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


FOLDER_OBJECT* folder_object_create(LOGON_OBJECT *plogon,
	uint64_t folder_id, uint8_t type, uint32_t tag_access)
{
	FOLDER_OBJECT *pfolder;
	
	pfolder = malloc(sizeof(FOLDER_OBJECT));
	if (NULL == pfolder) {
		return NULL;
	}
	pfolder->plogon = plogon;
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

uint32_t folder_object_get_tag_access(FOLDER_OBJECT *pfolder)
{
	return pfolder->tag_access;
}

BOOL folder_object_get_all_proptags(FOLDER_OBJECT *pfolder,
	PROPTAG_ARRAY *pproptags)
{
	int i;
	PROPTAG_ARRAY tmp_proptags;
	
	if (FALSE == exmdb_client_get_folder_all_proptags(
		logon_object_get_dir(pfolder->plogon),
		pfolder->folder_id, &tmp_proptags)) {
		return FALSE;		
	}
	pproptags->pproptag = common_util_alloc(sizeof(
		uint32_t)*(tmp_proptags.count + 15));
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
		sizeof(uint32_t)*tmp_proptags.count);
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag[pproptags->count] = PROP_TAG_ACCESS;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_RIGHTS;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_PARENTENTRYID;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_PARENTSOURCEKEY;
	pproptags->count ++;
	if (common_util_index_proptags(&tmp_proptags,
		PROP_TAG_SOURCEKEY) < 0) {
		pproptags->pproptag[pproptags->count] = PROP_TAG_SOURCEKEY;
		pproptags->count ++;
	}
	if (TRUE == logon_object_check_private(pfolder->plogon)) {
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
	if (PROPVAL_TYPE_OBJECT == (proptag & 0xFFFF)) {
		return TRUE;
	}
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
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
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
	DCERPC_INFO rpc_info;
	char temp_buff[1024];
	PERSISTDATA *ppersistdata;
	static uint8_t bin_buff[22];
	static uint32_t fake_del = 0;
	PERSISTDATA_ARRAY persistdatas;
	static BINARY fake_bin = {22, bin_buff};
	
	switch (proptag) {
	case PROP_TAG_CONTENTUNREADCOUNT:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			*ppvalue = common_util_alloc(sizeof(uint32_t));
			if (NULL == *ppvalue) {
				return FALSE;
			}
			rpc_info = get_rpc_info();
			return exmdb_client_get_public_folder_unread_count(
						logon_object_get_dir(pfolder->plogon),
						rpc_info.username, pfolder->folder_id,
						*ppvalue);
		}
		return FALSE;
	case PROP_TAG_MESSAGESIZE:
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			pfolder->folder_id, PROP_TAG_MESSAGESIZEEXTENDED,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		if (*(uint64_t*)pvalue > 0x7FFFFFFF) {
			**(uint32_t**)ppvalue = 0x7FFFFFFF;
		} else {
			**(uint32_t**)ppvalue = *(uint64_t*)pvalue;
		}
		return TRUE;
	case PROP_TAG_ASSOCMESSAGESIZE:
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			pfolder->folder_id, PROP_TAG_ASSOCMESSAGESIZEEXTENDED,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		if (*(uint64_t*)pvalue > 0x7FFFFFFF) {
			**(uint32_t**)ppvalue = 0x7FFFFFFF;
		} else {
			**(uint32_t**)ppvalue = *(uint64_t*)pvalue;
		}
		return TRUE;
	case PROP_TAG_NORMALMESSAGESIZE:
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			pfolder->folder_id, PROP_TAG_NORMALMESSAGESIZEEXTENDED,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		if (*(uint64_t*)pvalue > 0x7FFFFFFF) {
			**(uint32_t**)ppvalue = 0x7FFFFFFF;
		} else {
			**(uint32_t**)ppvalue = *(uint64_t*)pvalue;
		}
		return TRUE;
	case PROP_TAG_ACCESS:
		*ppvalue = &pfolder->tag_access;
		return TRUE;
	case PROP_TAG_FOLDERID:
		*ppvalue = common_util_alloc(sizeof(uint64_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint64_t*)(*ppvalue) = pfolder->folder_id;
		return TRUE;
	case PROP_TAG_RIGHTS:
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		if (LOGON_MODE_OWNER == logon_object_get_mode(pfolder->plogon)) {
			*(uint32_t*)(*ppvalue) = PERMISSION_READANY|PERMISSION_CREATE|
									PERMISSION_EDITOWNED|PERMISSION_DELETEOWNED|
									PERMISSION_EDITANY|PERMISSION_DELETEANY|
									PERMISSION_CREATESUBFOLDER|PERMISSION_FOLDEROWNER|
									PERMISSION_FOLDERCONTACT|PERMISSION_FOLDERVISIBLE;
		} else {
			rpc_info = get_rpc_info();
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(pfolder->plogon),
				pfolder->folder_id, rpc_info.username, *ppvalue)) {
				return FALSE;
			}
		}
		return TRUE;
	case PROP_TAG_ENTRYID:
		*ppvalue = common_util_to_folder_entryid(
			pfolder->plogon, pfolder->folder_id);
		return TRUE;
	case PROP_TAG_PARENTENTRYID:
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			pfolder->folder_id, PROP_TAG_PARENTFOLDERID,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(
			pfolder->plogon, *(uint64_t*)pvalue);
		return TRUE;
	case PROP_TAG_PARENTSOURCEKEY:
		if (TRUE == logon_object_check_private(pfolder->plogon)) {
			if (pfolder->folder_id == rop_util_make_eid_ex(
				1, PRIVATE_FID_ROOT)) {
				*ppvalue = &fake_bin;
				return TRUE;
			}
		} else {
			if (pfolder->folder_id == rop_util_make_eid_ex(
				1, PUBLIC_FID_ROOT)) {
				*ppvalue = &fake_bin;
				return TRUE;
			}
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			pfolder->folder_id, PROP_TAG_PARENTFOLDERID,
			&pvalue) || NULL == pvalue) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			*(uint64_t*)pvalue, PROP_TAG_SOURCEKEY,
			ppvalue)) {
			return FALSE;
		}
		if (NULL == *ppvalue) {
			*ppvalue = common_util_calculate_folder_sourcekey(
						pfolder->plogon, *(uint64_t*)pvalue);
			if (NULL == *ppvalue) {
				return FALSE;
			}
		}
		return TRUE;
	case PROP_TAG_STORERECORDKEY:
	case PROP_TAG_MAPPINGSIGNATURE:
		*ppvalue = common_util_guid_to_binary(
					logon_object_get_mailbox_guid(
					pfolder->plogon));
		return TRUE;
	case PROP_TAG_DELETEDFOLDERTOTAL:
		/* just like exchange 2013, alway return 0 */
		*ppvalue = &fake_del;
		return TRUE;
	case PROP_TAG_IPMDRAFTSENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		return TRUE;
	case PROP_TAG_IPMCONTACTENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		return TRUE;
	case PROP_TAG_IPMAPPOINTMENTENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		return TRUE;
	case PROP_TAG_IPMJOURNALENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		return TRUE;
	case PROP_TAG_IPMNOTEENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		return TRUE;
	case PROP_TAG_IPMTASKENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		*ppvalue = common_util_to_folder_entryid(pfolder->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		return TRUE;
	case PROP_TAG_REMINDERSONLINEENTRYID:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT)) {
			return FALSE;
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_REMINDERSONLINEENTRYID, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDITIONALRENENTRYIDS:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_ADDITIONALRENENTRYIDS, &pvalue)) {
			return FALSE;
		}
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = common_util_alloc(sizeof(BINARY_ARRAY));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->count = 5;
		((BINARY_ARRAY*)*ppvalue)->pbin = common_util_alloc(
			sizeof(BINARY)*((BINARY_ARRAY*)*ppvalue)->count);
		if (NULL == ((BINARY_ARRAY*)*ppvalue)->pbin) {
			return FALSE;
		}
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
		if (NULL == pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[0] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
		if (NULL == pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[1] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
		if (NULL == pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[2] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
		if (NULL == pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[3] = *pbin;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
		if (NULL == pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[4] = *pbin;
		return TRUE;
	case PROP_TAG_ADDITIONALRENENTRYIDSEX:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_ADDITIONALRENENTRYIDSEX, &pvalue)) {
			return FALSE;
		}
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		persistdatas.count = 3;
		persistdatas.ppitems = common_util_alloc(
				sizeof(void*)*persistdatas.count);
		if (NULL == persistdatas.ppitems) {
			return FALSE;
		}
		ppersistdata = common_util_alloc(
			sizeof(PERSISTDATA)*persistdatas.count);
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
		ext_buffer_push_init(&ext_push, temp_buff, sizeof(temp_buff), 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_persistdata_array(
			&ext_push, &persistdatas)) {
			return FALSE;	
		}
		((BINARY*)(*ppvalue))->cb = ext_push.offset;
		((BINARY*)(*ppvalue))->pb = common_util_alloc(ext_push.offset);
		if (NULL == ((BINARY*)(*ppvalue))->pb) {
			return FALSE;
		}
		memcpy(((BINARY*)(*ppvalue))->pb, ext_push.data, ext_push.offset);
		return TRUE;
	case PROP_TAG_FREEBUSYENTRYIDS:
		if (FALSE == logon_object_check_private(pfolder->plogon)) {
			return FALSE;
		}
		if (pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) &&
			pfolder->folder_id != rop_util_make_eid_ex(1, PRIVATE_FID_INBOX)) {
			return FALSE;	
		}
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(pfolder->plogon), 0,
			rop_util_make_eid_ex(1, PRIVATE_FID_INBOX),
			PROP_TAG_FREEBUSYENTRYIDS, &pvalue)) {
			return FALSE;
		}
		if (NULL != pvalue) {
			*ppvalue = pvalue;
			return TRUE;
		}
		*ppvalue = common_util_alloc(sizeof(BINARY_ARRAY));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->count = 4;
		((BINARY_ARRAY*)*ppvalue)->pbin = common_util_alloc(
			sizeof(BINARY)*((BINARY_ARRAY*)*ppvalue)->count);
		if (NULL == ((BINARY_ARRAY*)*ppvalue)->pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[0].cb = 0;
		((BINARY_ARRAY*)*ppvalue)->pbin[0].pb = NULL;
		((BINARY_ARRAY*)*ppvalue)->pbin[1].cb = 0;
		((BINARY_ARRAY*)*ppvalue)->pbin[1].pb = NULL;
		((BINARY_ARRAY*)*ppvalue)->pbin[2].cb = 0;
		((BINARY_ARRAY*)*ppvalue)->pbin[2].pb = NULL;
		pbin = common_util_to_folder_entryid(pfolder->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
		if (NULL == pbin) {
			return FALSE;
		}
		((BINARY_ARRAY*)*ppvalue)->pbin[3] = *pbin;
		return TRUE;
	}
	return FALSE;
}

BOOL folder_object_get_properties(FOLDER_OBJECT *pfolder,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	EMSMDB_INFO *pinfo;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static uint32_t err_code = EC_ERROR;
	
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return FALSE;
	}
	ppropvals->ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = common_util_alloc(
			sizeof(uint32_t)*pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == folder_object_get_calculated_property(
			pfolder, pproptags->pproptag[i], &pvalue)) {
			if (NULL != pvalue) {
				ppropvals->ppropval[ppropvals->count].proptag =
											pproptags->pproptag[i];
				ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
			} else {
				ppropvals->ppropval[ppropvals->count].proptag =
					(pproptags->pproptag[i]&0xFFFF0000)|PROPVAL_TYPE_ERROR;
				ppropvals->ppropval[ppropvals->count].pvalue = &err_code;
			}
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
	if (FALSE == exmdb_client_get_folder_properties(
		logon_object_get_dir(pfolder->plogon), pinfo->cpid,
		pfolder->folder_id, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	if (tmp_propvals.count > 0) {
		memcpy(ppropvals->ppropval + ppropvals->count,
			tmp_propvals.ppropval,
			sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
		ppropvals->count += tmp_propvals.count;
	}
	if (common_util_index_proptags(pproptags,
		PROP_TAG_SOURCEKEY) >= 0 && NULL ==
		common_util_get_propvals(ppropvals,
		PROP_TAG_SOURCEKEY)) {
		ppropvals->ppropval[ppropvals->count].proptag =
									PROP_TAG_SOURCEKEY;
		ppropvals->ppropval[ppropvals->count].pvalue =
			common_util_calculate_folder_sourcekey(
			pfolder->plogon, pfolder->folder_id);
		if (NULL == ppropvals->ppropval[ppropvals->count].pvalue) {
			return FALSE;
		}
		ppropvals->count ++;
	}
	return TRUE;	
}

BOOL folder_object_set_properties(FOLDER_OBJECT *pfolder,
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	int i;
	XID tmp_xid;
	uint16_t count;
	BINARY *pbin_pcl;
	EMSMDB_INFO *pinfo;
	uint64_t last_time;
	uint64_t change_num;
	BINARY *pbin_changekey;
	PROBLEM_ARRAY tmp_problems;
	PROPERTY_PROBLEM *pproblem;
	TPROPVAL_ARRAY tmp_propvals;
	uint16_t *poriginal_indices;
	
	
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (NULL == pinfo) {
		return FALSE;
	}
	pproblems->count = 0;
	pproblems->pproblem = common_util_alloc(
		sizeof(PROPERTY_PROBLEM)*ppropvals->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_propvals.count = 0;
	count = ppropvals->count + 4;
	tmp_propvals.ppropval = common_util_alloc(
				sizeof(TAGGED_PROPVAL)*count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	poriginal_indices = common_util_alloc(
		sizeof(uint16_t)*ppropvals->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	for (i=0; i<ppropvals->count; i++) {
		if (TRUE == folder_object_check_readonly_property(
			pfolder, ppropvals->ppropval[i].proptag)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
								ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count].err = 
											EC_ACCESS_DENIED;
			pproblems->count ++;
		} else {
			tmp_propvals.ppropval[tmp_propvals.count] =
								ppropvals->ppropval[i];
			poriginal_indices[tmp_propvals.count] = i;
			tmp_propvals.count ++;
		}
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(pfolder->plogon), &change_num)) {
		return FALSE;
	}
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
											PROP_TAG_CHANGENUMBER;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = &change_num;
	tmp_propvals.count ++;
	
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(pfolder->plogon), 0,
		pfolder->folder_id, PROP_TAG_PREDECESSORCHANGELIST,
		(void**)&pbin_pcl) || NULL == pbin_pcl) {
		return FALSE;
	}
	if (TRUE == logon_object_check_private(pfolder->plogon)) {
		tmp_xid.guid = rop_util_make_user_guid(
			logon_object_get_account_id(pfolder->plogon));
	} else {
		tmp_xid.guid = rop_util_make_domain_guid(
			logon_object_get_account_id(pfolder->plogon));
	}
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
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = pbin_changekey;
	tmp_propvals.count ++;
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_PREDECESSORCHANGELIST;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = pbin_pcl;
	tmp_propvals.count ++;
	tmp_propvals.ppropval[tmp_propvals.count].proptag =
									PROP_TAG_LASTMODIFICATIONTIME;
	tmp_propvals.ppropval[tmp_propvals.count].pvalue = &last_time;
	tmp_propvals.count ++;
	
	if (FALSE == exmdb_client_set_folder_properties(
		logon_object_get_dir(pfolder->plogon), pinfo->cpid,
		pfolder->folder_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	if (0 == tmp_problems.count) {
		return TRUE;
	}
	for (i=0; i<tmp_problems.count; i++) {
		tmp_problems.pproblem[i].index =
			poriginal_indices[tmp_problems.pproblem[i].index];
	}
	memcpy(pproblems->pproblem + pproblems->count, tmp_problems.pproblem,
		tmp_problems.count*sizeof(PROPERTY_PROBLEM));
	pproblems->count += tmp_problems.count;
	qsort(pproblems->pproblem, pproblems->count,
		sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
	return TRUE;
}

BOOL folder_object_remove_properties(FOLDER_OBJECT *pfolder,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
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
	
	pproblems->count = 0;
	pproblems->pproblem = common_util_alloc(
		sizeof(PROPERTY_PROBLEM)*pproptags->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = common_util_alloc(
		sizeof(uint32_t)*pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == folder_object_check_readonly_property(
			pfolder, pproptags->pproptag[i])) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
									pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count].err = 
										EC_ACCESS_DENIED;
			pproblems->count ++;
		} else {
			tmp_proptags.pproptag[tmp_proptags.count] =
									pproptags->pproptag[i];
			tmp_proptags.count ++;
		}
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (FALSE == exmdb_client_remove_folder_properties(
		logon_object_get_dir(pfolder->plogon),
		pfolder->folder_id, &tmp_proptags)) {
		return FALSE;	
	}
	tmp_propvals.count = 4;
	tmp_propvals.ppropval = propval_buff;
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(pfolder->plogon), &change_num)) {
		return TRUE;
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(pfolder->plogon), 0,
		pfolder->folder_id, PROP_TAG_PREDECESSORCHANGELIST,
		(void**)&pbin_pcl) || NULL == pbin_pcl) {
		return FALSE;
	}
	propval_buff[0].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[0].pvalue = &change_num;
	
	if (TRUE == logon_object_check_private(pfolder->plogon)) {
		tmp_xid.guid = rop_util_make_user_guid(
			logon_object_get_account_id(pfolder->plogon));
	} else {
		tmp_xid.guid = rop_util_make_domain_guid(
			logon_object_get_account_id(pfolder->plogon));
	}
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
	exmdb_client_set_folder_properties(
		logon_object_get_dir(pfolder->plogon), 0,
		pfolder->folder_id, &tmp_propvals, &tmp_problems);
	return TRUE;
}
