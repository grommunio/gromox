#include "rpc_ext.h"

static zend_bool rpc_ext_push_logon_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_string(pctx, ppayload->logon.username)) {
		return 0;
	}
	if (NULL == ppayload->logon.password) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_string(pctx, ppayload->logon.password)) {
			return 0;
		}
	}
	return ext_pack_push_uint32(pctx, ppayload->logon.flags);
}

static zend_bool rpc_ext_pull_logon_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_guid(pctx, &ppayload->logon.hsession);
}

static zend_bool rpc_ext_push_checksession_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	return ext_pack_push_guid(pctx, &ppayload->unloadobject.hsession);
}

static zend_bool rpc_ext_push_uinfo_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	return ext_pack_push_string(pctx, ppayload->uinfo.username);
}

static zend_bool rpc_ext_pull_uinfo_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	if (!ext_pack_pull_binary(pctx, &ppayload->uinfo.entryid)) {
		return 0;
	}
	if (!ext_pack_pull_string(pctx, &ppayload->uinfo.pdisplay_name)) {
		return 0;
	}
	if (!ext_pack_pull_string(pctx, &ppayload->uinfo.px500dn)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &ppayload->uinfo.privilege_bits);
}

static zend_bool rpc_ext_push_unloadobject_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->unloadobject.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->unloadobject.hobject);
}

static zend_bool rpc_ext_push_openentry_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->openentry.hsession)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &ppayload->openentry.entryid)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->openentry.flags);
}

static zend_bool rpc_ext_pull_openentry_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	if (!ext_pack_pull_uint8(pctx, &ppayload->openentry.mapi_type)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &ppayload->openentry.hobject);
}

static zend_bool rpc_ext_push_openstoreentry_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->openstoreentry.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->openstoreentry.hobject)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &ppayload->openstoreentry.entryid)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->openstoreentry.flags);
}

static zend_bool rpc_ext_pull_openstoreentry_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	if (!ext_pack_pull_uint8(pctx, &ppayload->openstoreentry.mapi_type)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &ppayload->openstoreentry.hobject);
}

static zend_bool rpc_ext_push_openabentry_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->openabentry.hsession)) {
		return 0;
	}
	return ext_pack_push_binary(pctx, &ppayload->openabentry.entryid);
}

static zend_bool rpc_ext_pull_openabentry_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	if (!ext_pack_pull_uint8(pctx, &ppayload->openabentry.mapi_type)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx, &ppayload->openabentry.hobject);
}

static zend_bool rpc_ext_push_resolvename_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->resolvename.hsession)) {
		return 0;
	}
	return ext_pack_push_tarray_set(pctx,
		ppayload->resolvename.pcond_set);
}

static zend_bool rpc_ext_pull_resolvename_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_tarray_set(pctx,
		&ppayload->resolvename.result_set);
}

static zend_bool rpc_ext_push_getpermissions_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->getpermissions.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->getpermissions.hobject); 
}

static zend_bool rpc_ext_pull_getpermissions_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_permission_set(pctx,
		&ppayload->getpermissions.perm_set);
}

static zend_bool rpc_ext_push_modifypermissions_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->modifypermissions.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->modifypermissions.hfolder)) {
		return 0;
	}
	return ext_pack_push_permission_set(pctx,
			ppayload->modifypermissions.pset);
}

static zend_bool rpc_ext_push_modifyrules_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->modifyrules.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->modifyrules.hfolder)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->modifyrules.flags)) {
		return 0;
	}
	return ext_pack_push_rule_list(pctx, ppayload->modifyrules.plist);
}

static zend_bool rpc_ext_push_getabgal_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	return ext_pack_push_guid(pctx, &ppayload->getabgal.hsession);
}

static zend_bool rpc_ext_pull_getabgal_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx, &ppayload->getabgal.entryid);
}

static zend_bool rpc_ext_push_loadstoretable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{	
	return ext_pack_push_guid(pctx,
		&ppayload->loadstoretable.hsession);
}

static zend_bool rpc_ext_pull_loadstoretable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->loadstoretable.hobject);
}

static zend_bool rpc_ext_push_openstore_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->openstore.hsession)) {
		return 0;
	}
	return ext_pack_push_binary(pctx, &ppayload->openstore.entryid);
}

static zend_bool rpc_ext_pull_openstore_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->openstore.hobject);
}

static zend_bool rpc_ext_push_openpropfilesec_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->openpropfilesec.hsession)) {
		return 0;
	}
	if (NULL == ppayload->openpropfilesec.puid) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_bytes(pctx,
			(void*)ppayload->openpropfilesec.puid,
			sizeof(FLATUID));
	}
}

static zend_bool rpc_ext_pull_openpropfilesec_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->openpropfilesec.hobject);
}

static zend_bool rpc_ext_push_loadhierarchytable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->loadhierarchytable.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->loadhierarchytable.hfolder)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->loadhierarchytable.flags);
}

static zend_bool rpc_ext_pull_loadhierarchytable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->loadhierarchytable.hobject);
}

static zend_bool rpc_ext_push_loadcontenttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->loadcontenttable.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->loadcontenttable.hfolder)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->loadcontenttable.flags);
}

static zend_bool rpc_ext_pull_loadcontenttable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->loadcontenttable.hobject);
}

static zend_bool rpc_ext_push_loadrecipienttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->loadrecipienttable.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->loadrecipienttable.hmessage);
}

static zend_bool rpc_ext_pull_loadrecipienttable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->loadrecipienttable.hobject);
}

static zend_bool rpc_ext_push_loadruletable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->loadruletable.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->loadruletable.hfolder);
}

static zend_bool rpc_ext_pull_loadruletable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->loadruletable.hobject);
}

static zend_bool rpc_ext_push_createmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->createmessage.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->createmessage.hfolder)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->createmessage.flags);
}

static zend_bool rpc_ext_pull_createmessage_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->createmessage.hobject);
}

static zend_bool rpc_ext_push_deletemessages_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->deletemessages.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->deletemessages.hfolder)) {
		return 0;
	}
	if (!ext_pack_push_binary_array(pctx,
		ppayload->deletemessages.pentryids)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx, ppayload->deletemessages.flags);
}

static zend_bool rpc_ext_push_copymessages_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->copymessages.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->copymessages.hsrcfolder)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->copymessages.hdstfolder)) {
		return 0;
	}
	if (!ext_pack_push_binary_array(pctx,
		ppayload->copymessages.pentryids)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->copymessages.flags);
}

static zend_bool rpc_ext_push_setreadflags_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->setreadflags.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->setreadflags.hfolder)) {
		return 0;
	}
	if (!ext_pack_push_binary_array(pctx,
		ppayload->setreadflags.pentryids)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx, ppayload->setreadflags.flags);
}

static zend_bool rpc_ext_push_createfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->createfolder.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->createfolder.hparent_folder)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->createfolder.folder_type)) {
		return 0;
	}
	if (!ext_pack_push_string(pctx, ppayload->createfolder.folder_name)) {
		return 0;
	}
	if (!ext_pack_push_string(pctx,
		ppayload->createfolder.folder_comment)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->createfolder.flags);
}

static zend_bool rpc_ext_pull_createfolder_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->createfolder.hobject);
}

static zend_bool rpc_ext_push_deletefolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->deletefolder.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->deletefolder.hparent_folder)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &ppayload->deletefolder.entryid)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->deletefolder.flags);
}

static zend_bool rpc_ext_push_emptyfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->emptyfolder.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->emptyfolder.hfolder)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->emptyfolder.flags);
}

static zend_bool rpc_ext_push_copyfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->copyfolder.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->copyfolder.hsrc_folder)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &ppayload->copyfolder.entryid)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->copyfolder.hdst_folder)) {
		return 0;
	}
	if (NULL == ppayload->copyfolder.new_name) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_string(pctx, ppayload->copyfolder.new_name)) {
			return 0;
		}
	}
	return ext_pack_push_uint32(pctx, ppayload->copyfolder.flags);
}

static zend_bool rpc_ext_push_getstoreentryid_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	return ext_pack_push_string(pctx,
		ppayload->getstoreentryid.mailbox_dn);
}

static zend_bool rpc_ext_pull_getstoreentryid_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx,
		&ppayload->getstoreentryid.entryid);	
}

static zend_bool rpc_ext_push_entryidfromsourcekey_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->entryidfromsourcekey.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->entryidfromsourcekey.hstore)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx,
		&ppayload->entryidfromsourcekey.folder_key)) {
		return 0;
	}
	if (NULL == ppayload->entryidfromsourcekey.pmessage_key) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_binary(pctx,
			ppayload->entryidfromsourcekey.pmessage_key);
	}
}

static zend_bool rpc_ext_pull_entryidfromsourcekey_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx,
		&ppayload->entryidfromsourcekey.entryid);	
}

static zend_bool rpc_ext_push_storeadvise_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->storeadvise.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx, ppayload->storeadvise.hstore)) {
		return 0;
	}
	if (NULL == ppayload->storeadvise.pentryid) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_binary(pctx,
			ppayload->storeadvise.pentryid)) {
			return 0;	
		}
	}
	return ext_pack_push_uint32(pctx,
		ppayload->storeadvise.event_mask);
}

static zend_bool rpc_ext_pull_storeadvise_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->storeadvise.sub_id);
}

static zend_bool rpc_ext_push_unadvise_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->unadvise.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->unadvise.hstore)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx, ppayload->unadvise.sub_id);
}

static zend_bool rpc_ext_push_notifdequeue_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	if (!ext_pack_push_guid(pctx,
		&ppayload->notifdequeue.psink->hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint16(pctx,
		ppayload->notifdequeue.psink->count)) {
		return 0;
	}
	for (i=0; i<ppayload->notifdequeue.psink->count; i++) {
		if (!ext_pack_push_uint32(pctx,
			ppayload->notifdequeue.psink->padvise[i].hstore)) {
			return 0;	
		}
		if (!ext_pack_push_uint32(pctx,
			ppayload->notifdequeue.psink->padvise[i].sub_id)) {
			return 0;	
		}
	}
	return ext_pack_push_uint32(pctx, ppayload->notifdequeue.timeval);
}

static zend_bool rpc_ext_pull_notifdequeue_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_znotification_array(pctx,
			&ppayload->notifdequeue.notifications);
}

static zend_bool rpc_ext_push_queryrows_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->queryrows.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->queryrows.htable)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->queryrows.start)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->queryrows.count)) {
		return 0;
	}
	if (NULL == ppayload->queryrows.prestriction) {
		if (!ext_pack_push_uint8(pctx, 0)) {
			return 0;
		}
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		if (!ext_pack_push_restriction(pctx,
			ppayload->queryrows.prestriction)) {
			return 0;
		}
	}
	if (NULL == ppayload->queryrows.pproptags) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_proptag_array(pctx,
				ppayload->queryrows.pproptags);
	}
}

static zend_bool rpc_ext_pull_queryrows_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_tarray_set(pctx, &ppayload->queryrows.rowset);
}

static zend_bool rpc_ext_push_setcolumns_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->setcolumns.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->setcolumns.htable)) {
		return 0;
	}
	if (!ext_pack_push_proptag_array(pctx,
		ppayload->setcolumns.pproptags)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->setcolumns.flags);
}

static zend_bool rpc_ext_push_seekrow_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->seekrow.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->seekrow.htable)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->seekrow.bookmark)) {
		return 0;
	}
	return ext_pack_push_int32(pctx, ppayload->seekrow.seek_rows);
}

static zend_bool rpc_ext_pull_seekrow_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_int32(pctx, &ppayload->seekrow.sought_rows);
}

static zend_bool rpc_ext_push_sorttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->sorttable.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->sorttable.htable)) {
		return 0;
	}
	return ext_pack_push_sortorder_set(
		pctx, ppayload->sorttable.psortset);
}

static zend_bool rpc_ext_push_getrowcount_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->getrowcount.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->getrowcount.htable);
}

static zend_bool rpc_ext_pull_getrowcount_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->getrowcount.count);
}

static zend_bool rpc_ext_push_restricttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->restricttable.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->restricttable.htable)) {
		return 0;
	}
	if (!ext_pack_push_restriction(pctx,
		ppayload->restricttable.prestriction)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx, ppayload->restricttable.flags);
}

static zend_bool rpc_ext_push_findrow_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->findrow.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->findrow.htable)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->findrow.bookmark)) {
		return 0;
	}
	if (!ext_pack_push_restriction(pctx,
		ppayload->findrow.prestriction)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->findrow.flags);
}

static zend_bool rpc_ext_pull_findrow_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->findrow.row_idx);
}

static zend_bool rpc_ext_push_createbookmark_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	
	if (!ext_pack_push_guid(pctx,
		&ppayload->createbookmark.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx,
		ppayload->createbookmark.htable);
}

static zend_bool rpc_ext_pull_createbookmark_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->createbookmark.bookmark);
}

static zend_bool rpc_ext_push_freebookmark_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->freebookmark.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->freebookmark.htable)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx,
		ppayload->freebookmark.bookmark);
}

static zend_bool rpc_ext_push_getreceivefolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->getreceivefolder.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->getreceivefolder.hstore)) {
		return 0;	
	}
	if (NULL == ppayload->getreceivefolder.pstrclass) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_string(pctx,
			ppayload->getreceivefolder.pstrclass);
	}
}

static zend_bool rpc_ext_pull_getreceivefolder_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx,
		&ppayload->getreceivefolder.entryid);	
}

static zend_bool rpc_ext_push_modifyrecipients_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->modifyrecipients.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->modifyrecipients.hmessage)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->modifyrecipients.flags)) {
		return 0;
	}
	return ext_pack_push_tarray_set(pctx,
		ppayload->modifyrecipients.prcpt_list);
}

static zend_bool rpc_ext_push_submitmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->submitmessage.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->submitmessage.hmessage);
}

static zend_bool rpc_ext_push_loadattachmenttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->loadattachmenttable.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx,
		ppayload->loadattachmenttable.hmessage);
}

static zend_bool rpc_ext_pull_loadattachmenttable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->loadattachmenttable.hobject);
}

static zend_bool rpc_ext_push_openattachment_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->openattachment.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx, ppayload->openattachment.hmessage)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->openattachment.attach_id);
}

static zend_bool rpc_ext_pull_openattachment_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->openattachment.hobject);
}

static zend_bool rpc_ext_push_createattachment_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->createattachment.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx,
		ppayload->createattachment.hmessage);
}

static zend_bool rpc_ext_pull_createattachment_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->createattachment.hobject);
}

static zend_bool rpc_ext_push_deleteattachment_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->deleteattachment.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->deleteattachment.hmessage)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx,
		ppayload->deleteattachment.attach_id);
}

static zend_bool rpc_ext_push_setpropvals_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->setpropvals.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->setpropvals.hobject)) {
		return 0;
	}
	return ext_pack_push_tpropval_array(pctx,
			ppayload->setpropvals.ppropvals);
}

static zend_bool rpc_ext_push_getpropvals_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{	
	if (!ext_pack_push_guid(pctx, &ppayload->getpropvals.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->getpropvals.hobject)) {
		return 0;
	}
	if (NULL == ppayload->getpropvals.pproptags) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_proptag_array(pctx,
				ppayload->getpropvals.pproptags);
	}
}

static zend_bool rpc_ext_pull_getpropvals_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_tpropval_array(pctx,
			&ppayload->getpropvals.propvals);
}

static zend_bool rpc_ext_push_deletepropvals_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->deletepropvals.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->deletepropvals.hobject)) {
		return 0;
	}
	return ext_pack_push_proptag_array(pctx,
		ppayload->deletepropvals.pproptags);
}

static zend_bool rpc_ext_push_setmessagereadflag_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->setmessagereadflag.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->setmessagereadflag.hmessage)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->setmessagereadflag.flags);
}

static zend_bool rpc_ext_push_openembedded_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->openembedded.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->openembedded.hattachment)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->openembedded.flags);
}

static zend_bool rpc_ext_pull_openembedded_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->openembedded.hobject);
}

static zend_bool rpc_ext_push_getnamedpropids_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->getnamedpropids.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->getnamedpropids.hstore)) {
		return 0;
	}
	return ext_pack_push_propname_array(pctx,
		ppayload->getnamedpropids.ppropnames);
}

static zend_bool rpc_ext_pull_getnamedpropids_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_propid_array(pctx,
		&ppayload->getnamedpropids.propids);
}

static zend_bool rpc_ext_push_getpropnames_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->getpropnames.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->getpropnames.hstore)) {
		return 0;	
	}
	return ext_pack_push_propid_array(pctx,
			ppayload->getpropnames.ppropids);
}

static zend_bool rpc_ext_pull_getpropnames_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_propname_array(pctx,
			&ppayload->getpropnames.propnames);
}

static zend_bool rpc_ext_push_copyto_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->copyto.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->copyto.hsrcobject)) {
		return 0;
	}
	if (!ext_pack_push_proptag_array(pctx,
		ppayload->copyto.pexclude_proptags)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->copyto.hdstobject)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->copyto.flags);
}

static zend_bool rpc_ext_push_savechanges_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->savechanges.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->savechanges.hobject);
}

static zend_bool rpc_ext_push_hierarchysync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->hierarchysync.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->hierarchysync.hfolder);
}

static zend_bool rpc_ext_pull_hierarchysync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->hierarchysync.hobject);
}

static zend_bool rpc_ext_push_contentsync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->contentsync.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->contentsync.hfolder);
}

static zend_bool rpc_ext_pull_contentsync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx,
		&ppayload->contentsync.hobject);
}

static zend_bool rpc_ext_push_configsync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->configsync.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->configsync.hctx)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->configsync.flags)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, ppayload->configsync.pstate)) {
		return 0;
	}
	if (NULL == ppayload->configsync.prestriction) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_restriction(pctx,
			ppayload->configsync.prestriction);
	}
}

static zend_bool rpc_ext_pull_configsync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	if (!ext_pack_pull_bool(pctx, &ppayload->configsync.b_changed)) {
		return 0;
	}
	return ext_pack_pull_uint32(pctx,
		&ppayload->configsync.count);
}

static zend_bool rpc_ext_push_statesync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->statesync.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->configsync.hctx);
}

static zend_bool rpc_ext_pull_statesync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx, &ppayload->statesync.state);	
}

static zend_bool rpc_ext_push_syncmessagechange_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->syncmessagechange.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->syncmessagechange.hctx);
}

static zend_bool rpc_ext_pull_syncmessagechange_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	if (!ext_pack_pull_bool(pctx, &ppayload->syncmessagechange.b_new)) {
		return 0;
	}
	return ext_pack_pull_tpropval_array(pctx,
		&ppayload->syncmessagechange.proplist);
}

static zend_bool rpc_ext_push_syncfolderchange_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->syncfolderchange.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->syncfolderchange.hctx);
}

static zend_bool rpc_ext_pull_syncfolderchange_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_tpropval_array(pctx,
		&ppayload->syncfolderchange.proplist);
}

static zend_bool rpc_ext_push_syncreadstatechanges_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->syncreadstatechanges.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx,
		ppayload->syncreadstatechanges.hctx);
}

static zend_bool rpc_ext_pull_syncreadstatechanges_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_state_array(pctx,
		&ppayload->syncreadstatechanges.states);
}

static zend_bool rpc_ext_push_syncdeletions_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->syncdeletions.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->syncdeletions.hctx)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx,
		ppayload->syncdeletions.flags);
}

static zend_bool rpc_ext_pull_syncdeletions_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary_array(pctx,
			&ppayload->syncdeletions.bins);	
}

static zend_bool rpc_ext_push_hierarchyimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->hierarchyimport.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->hierarchyimport.hfolder);
}

static zend_bool rpc_ext_pull_hierarchyimport_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->hierarchyimport.hobject);
}

static zend_bool rpc_ext_push_contentimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->contentimport.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->contentimport.hfolder);
}

static zend_bool rpc_ext_pull_contentimport_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->contentimport.hobject);
}

static zend_bool rpc_ext_push_configimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->configimport.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->configimport.hctx)) {
		return 0;
	}
	if (!ext_pack_push_uint8(pctx, ppayload->configimport.sync_type)) {
		return 0;
	}
	return ext_pack_push_binary(pctx, ppayload->configimport.pstate);
}

static zend_bool rpc_ext_push_stateimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->stateimport.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->stateimport.hctx);
}

static zend_bool rpc_ext_pull_stateimport_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx, &ppayload->stateimport.state);
}

static zend_bool rpc_ext_push_importmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->importmessage.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->importmessage.hctx)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->importmessage.flags)) {
		return 0;
	}
	return ext_pack_push_tpropval_array(pctx,
		ppayload->importmessage.pproplist);
}

static zend_bool rpc_ext_pull_importmessage_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_uint32(pctx, &ppayload->importmessage.hobject);
}

static zend_bool rpc_ext_push_importfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->importfolder.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->importfolder.hctx)) {
		return 0;
	}
	return ext_pack_push_tpropval_array(pctx,
		ppayload->importfolder.pproplist);
}

static zend_bool rpc_ext_push_importdeletion_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->importdeletion.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->importdeletion.hctx)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->importdeletion.flags)) {
		return 0;
	}
	return ext_pack_push_binary_array(pctx,
			ppayload->importdeletion.pbins);
}

static zend_bool rpc_ext_push_importreadstates_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->importreadstates.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->importreadstates.hctx)) {
		return 0;
	}
	return ext_pack_push_state_array(pctx,
		ppayload->importreadstates.pstates);
}

static zend_bool rpc_ext_push_getsearchcriteria_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->getsearchcriteria.hsession)) {
		return 0;
	}
	return ext_pack_push_uint32(pctx, ppayload->getsearchcriteria.hfolder);
}

static zend_bool rpc_ext_pull_getsearchcriteria_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (!ext_pack_pull_binary_array(pctx,
		&ppayload->getsearchcriteria.folder_array)) {
		return 0;	
	}
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		ppayload->getsearchcriteria.prestriction = NULL;
	} else {
		ppayload->getsearchcriteria.prestriction =
						emalloc(sizeof(RESTRICTION));
		if (NULL == ppayload->getsearchcriteria.prestriction) {
			return 0;
		}
		if (!ext_pack_pull_restriction(pctx,
			ppayload->getsearchcriteria.prestriction)) {
			return 0;	
		}
	}
	return ext_pack_pull_uint32(pctx,
		&ppayload->getsearchcriteria.search_stat);
}

static zend_bool rpc_ext_push_setsearchcriteria_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->setsearchcriteria.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->setsearchcriteria.hfolder)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx, ppayload->setsearchcriteria.flags)) {
		return 0;
	}
	if (!ext_pack_push_binary_array(pctx,
		ppayload->setsearchcriteria.pfolder_array)) {
		return 0;	
	}
	if (NULL == ppayload->setsearchcriteria.prestriction) {
		return ext_pack_push_uint8(pctx, 0);
	} else {
		if (!ext_pack_push_uint8(pctx, 1)) {
			return 0;
		}
		return ext_pack_push_restriction(pctx,
			ppayload->setsearchcriteria.prestriction);
	}
}

static zend_bool rpc_ext_push_messagetorfc822_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->messagetorfc822.hsession)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx,
		ppayload->messagetorfc822.hmessage);
}

static zend_bool rpc_ext_pull_messagetorfc822_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx,
		&ppayload->messagetorfc822.eml_bin);
}

static zend_bool rpc_ext_push_rfc822tomessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->rfc822tomessage.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->rfc822tomessage.hmessage)) {
		return 0;
	}
	return ext_pack_push_binary(pctx,
		ppayload->rfc822tomessage.peml_bin);
}

static zend_bool rpc_ext_push_messagetoical_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->messagetoical.hsession)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx,
		ppayload->messagetoical.hmessage);
}

static zend_bool rpc_ext_pull_messagetoical_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx,
		&ppayload->messagetoical.ical_bin);
}

static zend_bool rpc_ext_push_icaltomessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->icaltomessage.hsession)) {
		return 0;	
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->icaltomessage.hmessage)) {
		return 0;
	}
	return ext_pack_push_binary(pctx,
		ppayload->icaltomessage.pical_bin);
}

static zend_bool rpc_ext_push_messagetovcf_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->messagetovcf.hsession)) {
		return 0;	
	}
	return ext_pack_push_uint32(pctx,
		ppayload->messagetovcf.hmessage);
}

static zend_bool rpc_ext_pull_messagetovcf_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	return ext_pack_pull_binary(pctx,
		&ppayload->messagetovcf.vcf_bin);
}

static zend_bool rpc_ext_push_vcftomessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->vcftomessage.hsession)) {
		return 0;
	}
	if (!ext_pack_push_uint32(pctx,
		ppayload->vcftomessage.hmessage)) {
		return 0;
	}
	return ext_pack_push_binary(pctx,
		ppayload->vcftomessage.pvcf_bin);
}

static zend_bool rpc_ext_push_getuseravailability_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx,
		&ppayload->vcftomessage.hsession)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx,
		&ppayload->getuseravailability.entryid)) {
		return 0;
	}
	if (!ext_pack_push_uint64(pctx,
		ppayload->getuseravailability.starttime)) {
		return 0;	
	}
	return ext_pack_push_uint64(pctx,
		ppayload->getuseravailability.endtime);
}

static zend_bool rpc_ext_pull_getuseravailability_reponse(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (!ext_pack_pull_uint8(pctx, &tmp_byte)) {
		return 0;
	}
	if (0 == tmp_byte) {
		ppayload->getuseravailability.result_string = NULL;
		return 1;
	}
	return ext_pack_pull_string(pctx,
		&ppayload->getuseravailability.result_string);
}

static zend_bool rpc_ext_push_setpasswd_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_string(pctx, ppayload->setpasswd.username)) {
		return 0;	
	}
	if (!ext_pack_push_string(pctx, ppayload->setpasswd.passwd)) {
		return 0;	
	}
	return ext_pack_push_string(pctx, ppayload->setpasswd.new_passwd);
}

static zend_bool rpc_ext_push_linkmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	if (!ext_pack_push_guid(pctx, &ppayload->linkmessage.hsession)) {
		return 0;
	}
	if (!ext_pack_push_binary(pctx, &ppayload->linkmessage.search_entryid)) {
		return 0;
	}
	return ext_pack_push_binary(pctx, &ppayload->linkmessage.message_entryid);
}

zend_bool rpc_ext_push_request(const RPC_REQUEST *prequest,
	BINARY *pbin_out)
{
	PUSH_CTX push_ctx;
	zend_bool b_result;

	if (!ext_pack_push_init(&push_ctx)) {
		return 0;
	}
	if (!ext_pack_push_advance(&push_ctx, sizeof(uint32_t))) {
		ext_pack_push_free(&push_ctx);
		return 0;
	}
	if (!ext_pack_push_uint8(&push_ctx, prequest->call_id)) {
		ext_pack_push_free(&push_ctx);
		return 0;
	}
	switch (prequest->call_id) {
	case CALL_ID_LOGON:
		b_result = rpc_ext_push_logon_request(
				&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CHECKSESSION:
		b_result = rpc_ext_push_checksession_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_UINFO:
		b_result = rpc_ext_push_uinfo_request(
				&push_ctx, &prequest->payload);
		break;
	case CALL_ID_UNLOADOBJECT:
		b_result = rpc_ext_push_unloadobject_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENENTRY:
		b_result = rpc_ext_push_openentry_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENSTOREENTRY:
		b_result = rpc_ext_push_openstoreentry_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENABENTRY:
		b_result = rpc_ext_push_openabentry_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_RESOLVENAME:
		b_result = rpc_ext_push_resolvename_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETPERMISSIONS:
		b_result = rpc_ext_push_getpermissions_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_MODIFYPERMISSIONS:
		b_result = rpc_ext_push_modifypermissions_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_MODIFYRULES:
		b_result = rpc_ext_push_modifyrules_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETABGAL:
		b_result = rpc_ext_push_getabgal_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LOADSTORETABLE:
		b_result = rpc_ext_push_loadstoretable_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENSTORE:
		b_result = rpc_ext_push_openstore_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENPROPFILESEC:
		b_result = rpc_ext_push_openpropfilesec_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LOADHIERARCHYTABLE:
		b_result = rpc_ext_push_loadhierarchytable_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LOADCONTENTTABLE:
		b_result = rpc_ext_push_loadcontenttable_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LOADRECIPIENTTABLE:
		b_result = rpc_ext_push_loadrecipienttable_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LOADRULETABLE:
		b_result = rpc_ext_push_loadruletable_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CREATEMESSAGE:
		b_result = rpc_ext_push_createmessage_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_DELETEMESSAGES:
		b_result = rpc_ext_push_deletemessages_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_COPYMESSAGES:
		b_result = rpc_ext_push_copymessages_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SETREADFLAGS:
		b_result = rpc_ext_push_setreadflags_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CREATEFOLDER:
		b_result = rpc_ext_push_createfolder_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_DELETEFOLDER:
		b_result = rpc_ext_push_deletefolder_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_EMPTYFOLDER:
		b_result = rpc_ext_push_emptyfolder_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_COPYFOLDER:
		b_result = rpc_ext_push_copyfolder_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETSTOREENTRYID:
		b_result = rpc_ext_push_getstoreentryid_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_ENTRYIDFROMSOURCEKEY:
		b_result = rpc_ext_push_entryidfromsourcekey_request(
								&push_ctx, &prequest->payload);
		break;
	case CALL_ID_STOREADVISE:
		b_result = rpc_ext_push_storeadvise_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_UNADVISE:
		b_result = rpc_ext_push_unadvise_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_NOTIFDEQUEUE:
		b_result = rpc_ext_push_notifdequeue_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_QUERYROWS:
		b_result = rpc_ext_push_queryrows_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SETCOLUMNS:
		b_result = rpc_ext_push_setcolumns_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SEEKROW:
		b_result = rpc_ext_push_seekrow_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SORTTABLE:
		b_result = rpc_ext_push_sorttable_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETROWCOUNT:
		b_result = rpc_ext_push_getrowcount_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_RESTRICTTABLE:
		b_result = rpc_ext_push_restricttable_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_FINDROW:
		b_result = rpc_ext_push_findrow_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CREATEBOOKMARK:
		b_result = rpc_ext_push_createbookmark_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_FREEBOOKMARK:
		b_result = rpc_ext_push_freebookmark_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETRECEIVEFOLDER:
		b_result = rpc_ext_push_getreceivefolder_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_MODIFYRECIPIENTS:
		b_result = rpc_ext_push_modifyrecipients_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SUBMITMESSAGE:
		b_result = rpc_ext_push_submitmessage_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LOADATTACHMENTTABLE:
		b_result = rpc_ext_push_loadattachmenttable_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENATTACHMENT:
		b_result = rpc_ext_push_openattachment_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CREATEATTACHMENT:
		b_result = rpc_ext_push_createattachment_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_DELETEATTACHMENT:
		b_result = rpc_ext_push_deleteattachment_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SETPROPVALS:
		b_result = rpc_ext_push_setpropvals_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETPROPVALS:
		b_result = rpc_ext_push_getpropvals_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_DELETEPROPVALS:
		b_result = rpc_ext_push_deletepropvals_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SETMESSAGEREADFLAG:
		b_result = rpc_ext_push_setmessagereadflag_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_OPENEMBEDDED:
		b_result = rpc_ext_push_openembedded_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETNAMEDPROPIDS:
		b_result = rpc_ext_push_getnamedpropids_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETPROPNAMES:
		b_result = rpc_ext_push_getpropnames_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_COPYTO:
		b_result = rpc_ext_push_copyto_request(
				&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SAVECHANGES:
		b_result = rpc_ext_push_savechanges_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_HIERARCHYSYNC:
		b_result = rpc_ext_push_hierarchysync_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CONTENTSYNC:
		b_result = rpc_ext_push_contentsync_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CONFIGSYNC:
		b_result = rpc_ext_push_configsync_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_STATESYNC:
		b_result = rpc_ext_push_statesync_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SYNCMESSAGECHANGE:
		b_result = rpc_ext_push_syncmessagechange_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SYNCFOLDERCHANGE:
		b_result = rpc_ext_push_syncfolderchange_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SYNCREADSTATECHANGES:
		b_result = rpc_ext_push_syncreadstatechanges_request(
								&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SYNCDELETIONS:
		b_result = rpc_ext_push_syncdeletions_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_HIERARCHYIMPORT:
		b_result = rpc_ext_push_hierarchyimport_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CONTENTIMPORT:
		b_result = rpc_ext_push_contentimport_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_CONFIGIMPORT:
		b_result = rpc_ext_push_configimport_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_STATEIMPORT:
		b_result = rpc_ext_push_stateimport_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_IMPORTMESSAGE:
		b_result = rpc_ext_push_importmessage_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_IMPORTFOLDER:
		b_result = rpc_ext_push_importfolder_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_IMPORTDELETION:
		b_result = rpc_ext_push_importdeletion_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_IMPORTREADSTATES:
		b_result = rpc_ext_push_importreadstates_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETSEARCHCRITERIA:
		b_result = rpc_ext_push_getsearchcriteria_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SETSEARCHCRITERIA:
		b_result = rpc_ext_push_setsearchcriteria_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_MESSAGETORFC822:
		b_result = rpc_ext_push_messagetorfc822_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_RFC822TOMESSAGE:
		b_result = rpc_ext_push_rfc822tomessage_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_MESSAGETOICAL:
		b_result = rpc_ext_push_messagetoical_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_ICALTOMESSAGE:
		b_result = rpc_ext_push_icaltomessage_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_MESSAGETOVCF:
		b_result = rpc_ext_push_messagetovcf_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_VCFTOMESSAGE:
		b_result = rpc_ext_push_vcftomessage_request(
						&push_ctx, &prequest->payload);
		break;
	case CALL_ID_GETUSERAVAILABILITY:
		b_result = rpc_ext_push_getuseravailability_request(
							&push_ctx, &prequest->payload);
		break;
	case CALL_ID_SETPASSWD:
		b_result = rpc_ext_push_setpasswd_request(
					&push_ctx, &prequest->payload);
		break;
	case CALL_ID_LINKMESSAGE:
		b_result = rpc_ext_push_linkmessage_request(
					&push_ctx, &prequest->payload);
		break;
	default:
		return 0;
	}
	if (!b_result) {
		ext_pack_push_free(&push_ctx);
		return 0;
	}
	pbin_out->cb = push_ctx.offset;
	push_ctx.offset = 0;
	ext_pack_push_uint32(&push_ctx, pbin_out->cb - sizeof(uint32_t));
	pbin_out->pb = push_ctx.data;
	return 1;
}

zend_bool rpc_ext_pull_response(const BINARY *pbin_in,
	RPC_RESPONSE *presponse)
{
	PULL_CTX pull_ctx;
	
	ext_pack_pull_init(&pull_ctx, pbin_in->pb, pbin_in->cb);
	if (!ext_pack_pull_uint32(&pull_ctx, &presponse->result)) {
		return 0;
	}
	if (EC_SUCCESS != presponse->result) {
		return 1;
	}
	switch (presponse->call_id) {
	case CALL_ID_LOGON:
		return rpc_ext_pull_logon_response(
			&pull_ctx, &presponse->payload);
	case CALL_ID_CHECKSESSION:
		return 1;
	case CALL_ID_UINFO:
		return rpc_ext_pull_uinfo_response(
			&pull_ctx, &presponse->payload);
	case CALL_ID_UNLOADOBJECT:
		return 1;
	case CALL_ID_OPENENTRY:
		return rpc_ext_pull_openentry_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_OPENSTOREENTRY:
		return rpc_ext_pull_openstoreentry_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_OPENABENTRY:
		return rpc_ext_pull_openabentry_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_RESOLVENAME:
		return rpc_ext_pull_resolvename_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_GETPERMISSIONS:
		return rpc_ext_pull_getpermissions_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_MODIFYPERMISSIONS:
	case CALL_ID_MODIFYRULES:
		return 1;
	case CALL_ID_GETABGAL:
		return rpc_ext_pull_getabgal_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_LOADSTORETABLE:
		return rpc_ext_pull_loadstoretable_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_OPENSTORE:
		return rpc_ext_pull_openstore_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_OPENPROPFILESEC:
		return rpc_ext_pull_openpropfilesec_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_LOADHIERARCHYTABLE:
		return rpc_ext_pull_loadhierarchytable_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_LOADCONTENTTABLE:
		return rpc_ext_pull_loadcontenttable_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_LOADRECIPIENTTABLE:
		return rpc_ext_pull_loadrecipienttable_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_LOADRULETABLE:
		return rpc_ext_pull_loadruletable_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_CREATEMESSAGE:
		return rpc_ext_pull_createmessage_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_DELETEMESSAGES:
	case CALL_ID_COPYMESSAGES:
	case CALL_ID_SETREADFLAGS:
		return 1;
	case CALL_ID_CREATEFOLDER:
		return rpc_ext_pull_createfolder_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_DELETEFOLDER:
	case CALL_ID_EMPTYFOLDER:
	case CALL_ID_COPYFOLDER:
		return 1;
	case CALL_ID_GETSTOREENTRYID:
		return rpc_ext_pull_getstoreentryid_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_ENTRYIDFROMSOURCEKEY:
		return rpc_ext_pull_entryidfromsourcekey_response(
							&pull_ctx, &presponse->payload);
	case CALL_ID_STOREADVISE:
		return rpc_ext_pull_storeadvise_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_UNADVISE:
		return 1;
	case CALL_ID_NOTIFDEQUEUE:
		return rpc_ext_pull_notifdequeue_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_QUERYROWS:
		return rpc_ext_pull_queryrows_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_SETCOLUMNS:
	case CALL_ID_SEEKROW:
	case CALL_ID_SORTTABLE:
		return 1;
	case CALL_ID_GETROWCOUNT:
		return rpc_ext_pull_getrowcount_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_RESTRICTTABLE:
		return 1;
	case CALL_ID_FINDROW:
		return rpc_ext_pull_findrow_response(
			&pull_ctx, &presponse->payload);
	case CALL_ID_CREATEBOOKMARK:
		return rpc_ext_pull_createbookmark_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_FREEBOOKMARK:
		return 1;
	case CALL_ID_GETRECEIVEFOLDER:
		return rpc_ext_pull_getreceivefolder_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_MODIFYRECIPIENTS:
	case CALL_ID_SUBMITMESSAGE:
		return 1;
	case CALL_ID_LOADATTACHMENTTABLE:
		return rpc_ext_pull_loadattachmenttable_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_OPENATTACHMENT:
		return rpc_ext_pull_openattachment_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_CREATEATTACHMENT:
		return rpc_ext_pull_createattachment_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_DELETEATTACHMENT:
	case CALL_ID_SETPROPVALS:
		return 1;
	case CALL_ID_GETPROPVALS:
		return rpc_ext_pull_getpropvals_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_DELETEPROPVALS:
	case CALL_ID_SETMESSAGEREADFLAG:
		return 1;
	case CALL_ID_OPENEMBEDDED:
		return rpc_ext_pull_openembedded_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_GETNAMEDPROPIDS:
		return rpc_ext_pull_getnamedpropids_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_GETPROPNAMES:
		return rpc_ext_pull_getpropnames_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_COPYTO:
	case CALL_ID_SAVECHANGES:
		return 1;
	case CALL_ID_HIERARCHYSYNC:
		return rpc_ext_pull_hierarchysync_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_CONTENTSYNC:
		return rpc_ext_pull_contentsync_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_CONFIGSYNC:
		return rpc_ext_pull_configsync_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_STATESYNC:
		return rpc_ext_pull_statesync_response(
				&pull_ctx, &presponse->payload);
	case CALL_ID_SYNCMESSAGECHANGE:
		return rpc_ext_pull_syncmessagechange_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_SYNCFOLDERCHANGE:
		return rpc_ext_pull_syncfolderchange_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_SYNCREADSTATECHANGES:
		return rpc_ext_pull_syncreadstatechanges_response(
							&pull_ctx, &presponse->payload);
	case CALL_ID_SYNCDELETIONS:
		return rpc_ext_pull_syncdeletions_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_HIERARCHYIMPORT:
		return rpc_ext_pull_hierarchyimport_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_CONTENTIMPORT:
		return rpc_ext_pull_contentimport_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_CONFIGIMPORT:
		return 1;
	case CALL_ID_STATEIMPORT:
		return rpc_ext_pull_stateimport_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_IMPORTMESSAGE:
		return rpc_ext_pull_importmessage_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_IMPORTFOLDER:
	case CALL_ID_IMPORTDELETION:
	case CALL_ID_IMPORTREADSTATES:
		return 1;
	case CALL_ID_GETSEARCHCRITERIA:
		return rpc_ext_pull_getsearchcriteria_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_SETSEARCHCRITERIA:
		return 1;
	case CALL_ID_MESSAGETORFC822:
		return rpc_ext_pull_messagetorfc822_response(
						&pull_ctx, &presponse->payload);
	case CALL_ID_RFC822TOMESSAGE:
		return 1;
	case CALL_ID_MESSAGETOICAL:
		return rpc_ext_pull_messagetoical_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_ICALTOMESSAGE:
		return 1;
	case CALL_ID_MESSAGETOVCF:
		return rpc_ext_pull_messagetovcf_response(
					&pull_ctx, &presponse->payload);
	case CALL_ID_VCFTOMESSAGE:
		return 1;
	case CALL_ID_GETUSERAVAILABILITY:
		return rpc_ext_pull_getuseravailability_reponse(
						&pull_ctx, &presponse->payload);
	case CALL_ID_SETPASSWD:
		return 1;
	case CALL_ID_LINKMESSAGE:
		return 1;
	default:
		return 0;
	}
}
