// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/zcore_rpc.hpp>
#include "ext.hpp"
#include "rpc_ext.h"
#define TRY(expr) do { if (!(expr)) return 0; } while (false)

using RPC_REQUEST = ZCORE_RPC_REQUEST;
using RPC_RESPONSE = ZCORE_RPC_RESPONSE;
using REQUEST_PAYLOAD = ZCORE_REQUEST_PAYLOAD;
using RESPONSE_PAYLOAD = ZCORE_RESPONSE_PAYLOAD;

static zend_bool rpc_ext_push_logon_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_str(ppayload->logon.username));
	if (NULL == ppayload->logon.password) {
		TRY(pctx->p_uint8(0));
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_str(ppayload->logon.password));
	}
	TRY(pctx->p_uint32(ppayload->logon.flags));
	return true;
}

static zend_bool rpc_ext_pull_logon_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_guid(&ppayload->logon.hsession));
	return true;
}

static zend_bool rpc_ext_push_checksession_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->unloadobject.hsession));
	return true;
}

static zend_bool rpc_ext_push_uinfo_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_str(ppayload->uinfo.username));
	return true;
}

static zend_bool rpc_ext_pull_uinfo_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->uinfo.entryid));
	TRY(pctx->g_str(&ppayload->uinfo.pdisplay_name));
	TRY(pctx->g_str(&ppayload->uinfo.px500dn));
	TRY(pctx->g_uint32(&ppayload->uinfo.privilege_bits));
	return true;
}

static zend_bool rpc_ext_push_unloadobject_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->unloadobject.hsession));
	TRY(pctx->p_uint32(ppayload->unloadobject.hobject));
	return true;
}

static zend_bool rpc_ext_push_openentry_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openentry.hsession));
	TRY(pctx->p_bin(ppayload->openentry.entryid));
	TRY(pctx->p_uint32(ppayload->openentry.flags));
	return true;
}

static zend_bool rpc_ext_pull_openentry_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint8(&ppayload->openentry.mapi_type));
	TRY(pctx->g_uint32(&ppayload->openentry.hobject));
	return true;
}

static zend_bool rpc_ext_push_openstoreentry_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openstoreentry.hsession));
	TRY(pctx->p_uint32(ppayload->openstoreentry.hobject));
	TRY(pctx->p_bin(ppayload->openstoreentry.entryid));
	TRY(pctx->p_uint32(ppayload->openstoreentry.flags));
	return true;
}

static zend_bool rpc_ext_pull_openstoreentry_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint8(&ppayload->openstoreentry.mapi_type));
	TRY(pctx->g_uint32(&ppayload->openstoreentry.hxobject));
	return true;
}

static zend_bool rpc_ext_push_openabentry_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openabentry.hsession));
	TRY(pctx->p_bin(ppayload->openabentry.entryid));
	return true;
}

static zend_bool rpc_ext_pull_openabentry_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint8(&ppayload->openabentry.mapi_type));
	TRY(pctx->g_uint32(&ppayload->openabentry.hobject));
	return true;
}

static zend_bool rpc_ext_push_resolvename_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->resolvename.hsession));
	TRY(pctx->p_tarray_set(*ppayload->resolvename.pcond_set));
	return true;
}

static zend_bool rpc_ext_pull_resolvename_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_tarray_set(&ppayload->resolvename.result_set));
	return true;
}

static zend_bool rpc_ext_push_getpermissions_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getpermissions.hsession));
	TRY(pctx->p_uint32(ppayload->getpermissions.hobject));
	return true; 
}

static zend_bool rpc_ext_pull_getpermissions_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_perm_set(&ppayload->getpermissions.perm_set));
	return true;
}

static zend_bool rpc_ext_push_modifypermissions_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->modifypermissions.hsession));
	TRY(pctx->p_uint32(ppayload->modifypermissions.hfolder));
	TRY(pctx->p_perm_set(ppayload->modifypermissions.pset));
	return true;
}

static zend_bool rpc_ext_push_modifyrules_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->modifyrules.hsession));
	TRY(pctx->p_uint32(ppayload->modifyrules.hfolder));
	TRY(pctx->p_uint32(ppayload->modifyrules.flags));
	TRY(pctx->p_rule_list(ppayload->modifyrules.plist));
	return true;
}

static zend_bool rpc_ext_push_getabgal_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getabgal.hsession));
	return true;
}

static zend_bool rpc_ext_pull_getabgal_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->getabgal.entryid));
	return true;
}

static zend_bool rpc_ext_push_loadstoretable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{	
	TRY(pctx->p_guid(ppayload->loadstoretable.hsession));
	return true;
}

static zend_bool rpc_ext_pull_loadstoretable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->loadstoretable.hobject));
	return true;
}

static zend_bool rpc_ext_push_openstore_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openstore.hsession));
	TRY(pctx->p_bin(ppayload->openstore.entryid));
	return true;
}

static zend_bool rpc_ext_pull_openstore_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->openstore.hobject));
	return true;
}

static zend_bool rpc_ext_push_openprofilesec_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openprofilesec.hsession));
	if (ppayload->openprofilesec.puid == nullptr) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		return pctx->p_bytes(ppayload->openprofilesec.puid, sizeof(FLATUID));
	}
}

static zend_bool rpc_ext_pull_openprofilesec_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->openprofilesec.hobject));
	return true;
}

static zend_bool rpc_ext_push_loadhierarchytable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->loadhierarchytable.hsession));
	TRY(pctx->p_uint32(ppayload->loadhierarchytable.hfolder));
	TRY(pctx->p_uint32(ppayload->loadhierarchytable.flags));
	return true;
}

static zend_bool rpc_ext_pull_loadhierarchytable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->loadhierarchytable.hobject));
	return true;
}

static zend_bool rpc_ext_push_loadcontenttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->loadcontenttable.hsession));
	TRY(pctx->p_uint32(ppayload->loadcontenttable.hfolder));
	TRY(pctx->p_uint32(ppayload->loadcontenttable.flags));
	return true;
}

static zend_bool rpc_ext_pull_loadcontenttable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->loadcontenttable.hobject));
	return true;
}

static zend_bool rpc_ext_push_loadrecipienttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->loadrecipienttable.hsession));
	TRY(pctx->p_uint32(ppayload->loadrecipienttable.hmessage));
	return true;
}

static zend_bool rpc_ext_pull_loadrecipienttable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->loadrecipienttable.hobject));
	return true;
}

static zend_bool rpc_ext_push_loadruletable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->loadruletable.hsession));
	TRY(pctx->p_uint32(ppayload->loadruletable.hfolder));
	return true;
}

static zend_bool rpc_ext_pull_loadruletable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->loadruletable.hobject));
	return true;
}

static zend_bool rpc_ext_push_createmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->createmessage.hsession));
	TRY(pctx->p_uint32(ppayload->createmessage.hfolder));
	TRY(pctx->p_uint32(ppayload->createmessage.flags));
	return true;
}

static zend_bool rpc_ext_pull_createmessage_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->createmessage.hobject));
	return true;
}

static zend_bool rpc_ext_push_deletemessages_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->deletemessages.hsession));
	TRY(pctx->p_uint32(ppayload->deletemessages.hfolder));
	TRY(pctx->p_bin_a(*ppayload->deletemessages.pentryids));
	TRY(pctx->p_uint32(ppayload->deletemessages.flags));
	return true;
}

static zend_bool rpc_ext_push_copymessages_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->copymessages.hsession));
	TRY(pctx->p_uint32(ppayload->copymessages.hsrcfolder));
	TRY(pctx->p_uint32(ppayload->copymessages.hdstfolder));
	TRY(pctx->p_bin_a(*ppayload->copymessages.pentryids));
	TRY(pctx->p_uint32(ppayload->copymessages.flags));
	return true;
}

static zend_bool rpc_ext_push_setreadflags_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->setreadflags.hsession));
	TRY(pctx->p_uint32(ppayload->setreadflags.hfolder));
	TRY(pctx->p_bin_a(*ppayload->setreadflags.pentryids));
	TRY(pctx->p_uint32(ppayload->setreadflags.flags));
	return true;
}

static zend_bool rpc_ext_push_createfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->createfolder.hsession));
	TRY(pctx->p_uint32(ppayload->createfolder.hparent_folder));
	TRY(pctx->p_uint32(ppayload->createfolder.folder_type));
	TRY(pctx->p_str(ppayload->createfolder.folder_name));
	TRY(pctx->p_str(ppayload->createfolder.folder_comment));
	TRY(pctx->p_uint32(ppayload->createfolder.flags));
	return true;
}

static zend_bool rpc_ext_pull_createfolder_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->createfolder.hobject));
	return true;
}

static zend_bool rpc_ext_push_deletefolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->deletefolder.hsession));
	TRY(pctx->p_uint32(ppayload->deletefolder.hparent_folder));
	TRY(pctx->p_bin(ppayload->deletefolder.entryid));
	TRY(pctx->p_uint32(ppayload->deletefolder.flags));
	return true;
}

static zend_bool rpc_ext_push_emptyfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->emptyfolder.hsession));
	TRY(pctx->p_uint32(ppayload->emptyfolder.hfolder));
	TRY(pctx->p_uint32(ppayload->emptyfolder.flags));
	return true;
}

static zend_bool rpc_ext_push_copyfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->copyfolder.hsession));
	TRY(pctx->p_uint32(ppayload->copyfolder.hsrc_folder));
	TRY(pctx->p_bin(ppayload->copyfolder.entryid));
	TRY(pctx->p_uint32(ppayload->copyfolder.hdst_folder));
	if (NULL == ppayload->copyfolder.new_name) {
		TRY(pctx->p_uint8(0));
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_str(ppayload->copyfolder.new_name));
	}
	TRY(pctx->p_uint32(ppayload->copyfolder.flags));
	return true;
}

static zend_bool rpc_ext_push_getstoreentryid_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_str(ppayload->getstoreentryid.mailbox_dn));
	return true;
}

static zend_bool rpc_ext_pull_getstoreentryid_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->getstoreentryid.entryid));
	return true;
}

static zend_bool rpc_ext_push_entryidfromsourcekey_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->entryidfromsourcekey.hsession));
	TRY(pctx->p_uint32(ppayload->entryidfromsourcekey.hstore));
	TRY(pctx->p_bin(ppayload->entryidfromsourcekey.folder_key));
	if (NULL == ppayload->entryidfromsourcekey.pmessage_key) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_bin(*ppayload->entryidfromsourcekey.pmessage_key));
	return true;
	}
}

static zend_bool rpc_ext_pull_entryidfromsourcekey_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->entryidfromsourcekey.entryid));
	return true;
}

static zend_bool rpc_ext_push_storeadvise_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->storeadvise.hsession));
	TRY(pctx->p_uint32(ppayload->storeadvise.hstore));
	if (NULL == ppayload->storeadvise.pentryid) {
		TRY(pctx->p_uint8(0));
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_bin(*ppayload->storeadvise.pentryid));
	}
	TRY(pctx->p_uint32(ppayload->storeadvise.event_mask));
	return true;
}

static zend_bool rpc_ext_pull_storeadvise_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->storeadvise.sub_id));
	return true;
}

static zend_bool rpc_ext_push_unadvise_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->unadvise.hsession));
	TRY(pctx->p_uint32(ppayload->unadvise.hstore));
	TRY(pctx->p_uint32(ppayload->unadvise.sub_id));
	return true;
}

static zend_bool rpc_ext_push_notifdequeue_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	TRY(pctx->p_guid(ppayload->notifdequeue.psink->hsession));
	TRY(pctx->p_uint16(ppayload->notifdequeue.psink->count));
	for (i=0; i<ppayload->notifdequeue.psink->count; i++) {
		TRY(pctx->p_uint32(ppayload->notifdequeue.psink->padvise[i].hstore));
		TRY(pctx->p_uint32(ppayload->notifdequeue.psink->padvise[i].sub_id));
	}
	TRY(pctx->p_uint32(ppayload->notifdequeue.timeval));
	return true;
}

static zend_bool rpc_ext_pull_notifdequeue_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_znotif_a(&ppayload->notifdequeue.notifications));
	return true;
}

static zend_bool rpc_ext_push_queryrows_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->queryrows.hsession));
	TRY(pctx->p_uint32(ppayload->queryrows.htable));
	TRY(pctx->p_uint32(ppayload->queryrows.start));
	TRY(pctx->p_uint32(ppayload->queryrows.count));
	if (NULL == ppayload->queryrows.prestriction) {
		TRY(pctx->p_uint8(0));
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_restriction(*ppayload->queryrows.prestriction));
	}
	if (NULL == ppayload->queryrows.pproptags) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_proptag_a(*ppayload->queryrows.pproptags));
	return true;
	}
}

static zend_bool rpc_ext_pull_queryrows_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_tarray_set(&ppayload->queryrows.rowset));
	return true;
}

static zend_bool rpc_ext_push_setcolumns_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->setcolumns.hsession));
	TRY(pctx->p_uint32(ppayload->setcolumns.htable));
	TRY(pctx->p_proptag_a(*ppayload->setcolumns.pproptags));
	TRY(pctx->p_uint32(ppayload->setcolumns.flags));
	return true;
}

static zend_bool rpc_ext_push_seekrow_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->seekrow.hsession));
	TRY(pctx->p_uint32(ppayload->seekrow.htable));
	TRY(pctx->p_uint32(ppayload->seekrow.bookmark));
	TRY(pctx->p_int32(ppayload->seekrow.seek_rows));
	return true;
}

static zend_bool rpc_ext_push_sorttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->sorttable.hsession));
	TRY(pctx->p_uint32(ppayload->sorttable.htable));
	TRY(pctx->p_sortorder_set(ppayload->sorttable.psortset));
	return true;
}

static zend_bool rpc_ext_push_getrowcount_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getrowcount.hsession));
	TRY(pctx->p_uint32(ppayload->getrowcount.htable));
	return true;
}

static zend_bool rpc_ext_pull_getrowcount_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->getrowcount.count));
	return true;
}

static zend_bool rpc_ext_push_restricttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->restricttable.hsession));
	TRY(pctx->p_uint32(ppayload->restricttable.htable));
	TRY(pctx->p_restriction(*ppayload->restricttable.prestriction));
	TRY(pctx->p_uint32(ppayload->restricttable.flags));
	return true;
}

static zend_bool rpc_ext_push_findrow_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->findrow.hsession));
	TRY(pctx->p_uint32(ppayload->findrow.htable));
	TRY(pctx->p_uint32(ppayload->findrow.bookmark));
	TRY(pctx->p_restriction(*ppayload->findrow.prestriction));
	TRY(pctx->p_uint32(ppayload->findrow.flags));
	return true;
}

static zend_bool rpc_ext_pull_findrow_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->findrow.row_idx));
	return true;
}

static zend_bool rpc_ext_push_createbookmark_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	
	TRY(pctx->p_guid(ppayload->createbookmark.hsession));
	TRY(pctx->p_uint32(ppayload->createbookmark.htable));
	return true;
}

static zend_bool rpc_ext_pull_createbookmark_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->createbookmark.bookmark));
	return true;
}

static zend_bool rpc_ext_push_freebookmark_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->freebookmark.hsession));
	TRY(pctx->p_uint32(ppayload->freebookmark.htable));
	TRY(pctx->p_uint32(ppayload->freebookmark.bookmark));
	return true;
}

static zend_bool rpc_ext_push_getreceivefolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getreceivefolder.hsession));
	TRY(pctx->p_uint32(ppayload->getreceivefolder.hstore));
	if (NULL == ppayload->getreceivefolder.pstrclass) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_str(ppayload->getreceivefolder.pstrclass));
	return true;
	}
}

static zend_bool rpc_ext_pull_getreceivefolder_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->getreceivefolder.entryid));
	return true;
}

static zend_bool rpc_ext_push_modifyrecipients_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->modifyrecipients.hsession));
	TRY(pctx->p_uint32(ppayload->modifyrecipients.hmessage));
	TRY(pctx->p_uint32(ppayload->modifyrecipients.flags));
	TRY(pctx->p_tarray_set(*ppayload->modifyrecipients.prcpt_list));
	return true;
}

static zend_bool rpc_ext_push_submitmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->submitmessage.hsession));
	TRY(pctx->p_uint32(ppayload->submitmessage.hmessage));
	return true;
}

static zend_bool rpc_ext_push_loadattachmenttable_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->loadattachmenttable.hsession));
	TRY(pctx->p_uint32(ppayload->loadattachmenttable.hmessage));
	return true;
}

static zend_bool rpc_ext_pull_loadattachmenttable_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->loadattachmenttable.hobject));
	return true;
}

static zend_bool rpc_ext_push_openattachment_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openattachment.hsession));
	TRY(pctx->p_uint32(ppayload->openattachment.hmessage));
	TRY(pctx->p_uint32(ppayload->openattachment.attach_id));
	return true;
}

static zend_bool rpc_ext_pull_openattachment_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->openattachment.hobject));
	return true;
}

static zend_bool rpc_ext_push_createattachment_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->createattachment.hsession));
	TRY(pctx->p_uint32(ppayload->createattachment.hmessage));
	return true;
}

static zend_bool rpc_ext_pull_createattachment_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->createattachment.hobject));
	return true;
}

static zend_bool rpc_ext_push_deleteattachment_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->deleteattachment.hsession));
	TRY(pctx->p_uint32(ppayload->deleteattachment.hmessage));
	TRY(pctx->p_uint32(ppayload->deleteattachment.attach_id));
	return true;
}

static zend_bool rpc_ext_push_setpropvals_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->setpropvals.hsession));
	TRY(pctx->p_uint32(ppayload->setpropvals.hobject));
	TRY(pctx->p_tpropval_a(*ppayload->setpropvals.ppropvals));
	return true;
}

static zend_bool rpc_ext_push_getpropvals_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{	
	TRY(pctx->p_guid(ppayload->getpropvals.hsession));
	TRY(pctx->p_uint32(ppayload->getpropvals.hobject));
	if (NULL == ppayload->getpropvals.pproptags) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_proptag_a(*ppayload->getpropvals.pproptags));
		return true;
	}
}

static zend_bool rpc_ext_pull_getpropvals_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_tpropval_a(&ppayload->getpropvals.propvals));
	return true;
}

static zend_bool rpc_ext_push_deletepropvals_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->deletepropvals.hsession));
	TRY(pctx->p_uint32(ppayload->deletepropvals.hobject));
	TRY(pctx->p_proptag_a(*ppayload->deletepropvals.pproptags));
	return true;
}

static zend_bool rpc_ext_push_setmessagereadflag_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->setmessagereadflag.hsession));
	TRY(pctx->p_uint32(ppayload->setmessagereadflag.hmessage));
	TRY(pctx->p_uint32(ppayload->setmessagereadflag.flags));
	return true;
}

static zend_bool rpc_ext_push_openembedded_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->openembedded.hsession));
	TRY(pctx->p_uint32(ppayload->openembedded.hattachment));
	TRY(pctx->p_uint32(ppayload->openembedded.flags));
	return true;
}

static zend_bool rpc_ext_pull_openembedded_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->openembedded.hobject));
	return true;
}

static zend_bool rpc_ext_push_getnamedpropids_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getnamedpropids.hsession));
	TRY(pctx->p_uint32(ppayload->getnamedpropids.hstore));
	TRY(pctx->p_propname_a(*ppayload->getnamedpropids.ppropnames));
	return true;
}

static zend_bool rpc_ext_pull_getnamedpropids_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_propid_a(&ppayload->getnamedpropids.propids));
	return true;
}

static zend_bool rpc_ext_push_getpropnames_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getpropnames.hsession));
	TRY(pctx->p_uint32(ppayload->getpropnames.hstore));
	TRY(pctx->p_propid_a(*ppayload->getpropnames.ppropids));
	return true;
}

static zend_bool rpc_ext_pull_getpropnames_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_propname_a(&ppayload->getpropnames.propnames));
	return true;
}

static zend_bool rpc_ext_push_copyto_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->copyto.hsession));
	TRY(pctx->p_uint32(ppayload->copyto.hsrcobject));
	TRY(pctx->p_proptag_a(*ppayload->copyto.pexclude_proptags));
	TRY(pctx->p_uint32(ppayload->copyto.hdstobject));
	TRY(pctx->p_uint32(ppayload->copyto.flags));
	return true;
}

static zend_bool rpc_ext_push_savechanges_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->savechanges.hsession));
	TRY(pctx->p_uint32(ppayload->savechanges.hobject));
	return true;
}

static zend_bool rpc_ext_push_hierarchysync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->hierarchysync.hsession));
	TRY(pctx->p_uint32(ppayload->hierarchysync.hfolder));
	return true;
}

static zend_bool rpc_ext_pull_hierarchysync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->hierarchysync.hobject));
	return true;
}

static zend_bool rpc_ext_push_contentsync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->contentsync.hsession));
	TRY(pctx->p_uint32(ppayload->contentsync.hfolder));
	return true;
}

static zend_bool rpc_ext_pull_contentsync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->contentsync.hobject));
	return true;
}

static zend_bool rpc_ext_push_configsync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->configsync.hsession));
	TRY(pctx->p_uint32(ppayload->configsync.hctx));
	TRY(pctx->p_uint32(ppayload->configsync.flags));
	TRY(pctx->p_bin(*ppayload->configsync.pstate));
	if (NULL == ppayload->configsync.prestriction) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_restriction(*ppayload->configsync.prestriction));
	return true;
	}
}

static zend_bool rpc_ext_pull_configsync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint8(&ppayload->configsync.b_changed));
	TRY(pctx->g_uint32(&ppayload->configsync.count));
	return true;
}

static zend_bool rpc_ext_push_statesync_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->statesync.hsession));
	TRY(pctx->p_uint32(ppayload->configsync.hctx));
	return true;
}

static zend_bool rpc_ext_pull_statesync_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->statesync.state));
	return true;
}

static zend_bool rpc_ext_push_syncmessagechange_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->syncmessagechange.hsession));
	TRY(pctx->p_uint32(ppayload->syncmessagechange.hctx));
	return true;
}

static zend_bool rpc_ext_pull_syncmessagechange_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t v = 0;
	TRY(pctx->g_uint8(&v));
	ppayload->syncmessagechange.b_new = v;
	TRY(pctx->g_tpropval_a(&ppayload->syncmessagechange.proplist));
	return true;
}

static zend_bool rpc_ext_push_syncfolderchange_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->syncfolderchange.hsession));
	TRY(pctx->p_uint32(ppayload->syncfolderchange.hctx));
	return true;
}

static zend_bool rpc_ext_pull_syncfolderchange_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_tpropval_a(&ppayload->syncfolderchange.proplist));
	return true;
}

static zend_bool rpc_ext_push_syncreadstatechanges_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->syncreadstatechanges.hsession));
	TRY(pctx->p_uint32(ppayload->syncreadstatechanges.hctx));
	return true;
}

static zend_bool rpc_ext_pull_syncreadstatechanges_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_state_a(&ppayload->syncreadstatechanges.states));
	return true;
}

static zend_bool rpc_ext_push_syncdeletions_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->syncdeletions.hsession));
	TRY(pctx->p_uint32(ppayload->syncdeletions.hctx));
	TRY(pctx->p_uint32(ppayload->syncdeletions.flags));
	return true;
}

static zend_bool rpc_ext_pull_syncdeletions_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin_a(&ppayload->syncdeletions.bins));
	return true;
}

static zend_bool rpc_ext_push_hierarchyimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->hierarchyimport.hsession));
	TRY(pctx->p_uint32(ppayload->hierarchyimport.hfolder));
	return true;
}

static zend_bool rpc_ext_pull_hierarchyimport_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->hierarchyimport.hobject));
	return true;
}

static zend_bool rpc_ext_push_contentimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->contentimport.hsession));
	TRY(pctx->p_uint32(ppayload->contentimport.hfolder));
	return true;
}

static zend_bool rpc_ext_pull_contentimport_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->contentimport.hobject));
	return true;
}

static zend_bool rpc_ext_push_configimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->configimport.hsession));
	TRY(pctx->p_uint32(ppayload->configimport.hctx));
	TRY(pctx->p_uint8(ppayload->configimport.sync_type));
	TRY(pctx->p_bin(*ppayload->configimport.pstate));
	return true;
}

static zend_bool rpc_ext_push_stateimport_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->stateimport.hsession));
	TRY(pctx->p_uint32(ppayload->stateimport.hctx));
	return true;
}

static zend_bool rpc_ext_pull_stateimport_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->stateimport.state));
	return true;
}

static zend_bool rpc_ext_push_importmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->importmessage.hsession));
	TRY(pctx->p_uint32(ppayload->importmessage.hctx));
	TRY(pctx->p_uint32(ppayload->importmessage.flags));
	TRY(pctx->p_tpropval_a(*ppayload->importmessage.pproplist));
	return true;
}

static zend_bool rpc_ext_pull_importmessage_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_uint32(&ppayload->importmessage.hobject));
	return true;
}

static zend_bool rpc_ext_push_importfolder_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->importfolder.hsession));
	TRY(pctx->p_uint32(ppayload->importfolder.hctx));
	TRY(pctx->p_tpropval_a(*ppayload->importfolder.pproplist));
	return true;
}

static zend_bool rpc_ext_push_importdeletion_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->importdeletion.hsession));
	TRY(pctx->p_uint32(ppayload->importdeletion.hctx));
	TRY(pctx->p_uint32(ppayload->importdeletion.flags));
	TRY(pctx->p_bin_a(*ppayload->importdeletion.pbins));
	return true;
}

static zend_bool rpc_ext_push_importreadstates_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->importreadstates.hsession));
	TRY(pctx->p_uint32(ppayload->importreadstates.hctx));
	TRY(pctx->p_state_a(ppayload->importreadstates.pstates));
	return true;
}

static zend_bool rpc_ext_push_getsearchcriteria_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->getsearchcriteria.hsession));
	TRY(pctx->p_uint32(ppayload->getsearchcriteria.hfolder));
	return true;
}

static zend_bool rpc_ext_pull_getsearchcriteria_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pctx->g_bin_a(&ppayload->getsearchcriteria.folder_array));
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->getsearchcriteria.prestriction = NULL;
	} else {
		ppayload->getsearchcriteria.prestriction = st_malloc<RESTRICTION>();
		if (NULL == ppayload->getsearchcriteria.prestriction) {
			return 0;
		}
		TRY(pctx->g_restriction(ppayload->getsearchcriteria.prestriction));
	}
	TRY(pctx->g_uint32(&ppayload->getsearchcriteria.search_stat));
	return true;
}

static zend_bool rpc_ext_push_setsearchcriteria_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->setsearchcriteria.hsession));
	TRY(pctx->p_uint32(ppayload->setsearchcriteria.hfolder));
	TRY(pctx->p_uint32(ppayload->setsearchcriteria.flags));
	TRY(pctx->p_bin_a(*ppayload->setsearchcriteria.pfolder_array));
	if (NULL == ppayload->setsearchcriteria.prestriction) {
		TRY(pctx->p_uint8(0));
	return true;
	} else {
		TRY(pctx->p_uint8(1));
		TRY(pctx->p_restriction(*ppayload->setsearchcriteria.prestriction));
	return true;
	}
}

static zend_bool rpc_ext_push_messagetorfc822_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->messagetorfc822.hsession));
	TRY(pctx->p_uint32(ppayload->messagetorfc822.hmessage));
	return true;
}

static zend_bool rpc_ext_pull_messagetorfc822_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->messagetorfc822.eml_bin));
	return true;
}

static zend_bool rpc_ext_push_rfc822tomessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->rfc822tomessage.hsession));
	TRY(pctx->p_uint32(ppayload->rfc822tomessage.hmessage));
	TRY(pctx->p_bin(*ppayload->rfc822tomessage.peml_bin));
	return true;
}

static zend_bool rpc_ext_push_messagetoical_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->messagetoical.hsession));
	TRY(pctx->p_uint32(ppayload->messagetoical.hmessage));
	return true;
}

static zend_bool rpc_ext_pull_messagetoical_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->messagetoical.ical_bin));
	return true;
}

static zend_bool rpc_ext_push_icaltomessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->icaltomessage.hsession));
	TRY(pctx->p_uint32(ppayload->icaltomessage.hmessage));
	TRY(pctx->p_bin(*ppayload->icaltomessage.pical_bin));
	return true;
}

static zend_bool rpc_ext_push_messagetovcf_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->messagetovcf.hsession));
	TRY(pctx->p_uint32(ppayload->messagetovcf.hmessage));
	return true;
}

static zend_bool rpc_ext_pull_messagetovcf_response(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	TRY(pctx->g_bin(&ppayload->messagetovcf.vcf_bin));
	return true;
}

static zend_bool rpc_ext_push_vcftomessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->vcftomessage.hsession));
	TRY(pctx->p_uint32(ppayload->vcftomessage.hmessage));
	TRY(pctx->p_bin(*ppayload->vcftomessage.pvcf_bin));
	return true;
}

static zend_bool rpc_ext_push_getuseravailability_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->vcftomessage.hsession));
	TRY(pctx->p_bin(ppayload->getuseravailability.entryid));
	TRY(pctx->p_uint64(ppayload->getuseravailability.starttime));
	TRY(pctx->p_uint64(ppayload->getuseravailability.endtime));
	return true;
}

static zend_bool rpc_ext_pull_getuseravailability_reponse(
	PULL_CTX *pctx, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->getuseravailability.result_string = NULL;
		return 1;
	}
	TRY(pctx->g_str(&ppayload->getuseravailability.result_string));
	return true;
}

static zend_bool rpc_ext_push_setpasswd_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_str(ppayload->setpasswd.username));
	TRY(pctx->p_str(ppayload->setpasswd.passwd));
	TRY(pctx->p_str(ppayload->setpasswd.new_passwd));
	return true;
}

static zend_bool rpc_ext_push_linkmessage_request(
	PUSH_CTX *pctx, const REQUEST_PAYLOAD *ppayload)
{
	TRY(pctx->p_guid(ppayload->linkmessage.hsession));
	TRY(pctx->p_bin(ppayload->linkmessage.search_entryid));
	TRY(pctx->p_bin(ppayload->linkmessage.message_entryid));
	return true;
}

zend_bool rpc_ext_push_request(const RPC_REQUEST *prequest,
	BINARY *pbin_out)
{
	PUSH_CTX push_ctx;
	zend_bool b_result;

	TRY(push_ctx.init());
	TRY(push_ctx.advance(sizeof(uint32_t)));
	TRY(push_ctx.p_uint8(prequest->call_id));
	switch (prequest->call_id) {
	case zcore_callid::LOGON:
		b_result = rpc_ext_push_logon_request(
				&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CHECKSESSION:
		b_result = rpc_ext_push_checksession_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::UINFO:
		b_result = rpc_ext_push_uinfo_request(
				&push_ctx, &prequest->payload);
		break;
	case zcore_callid::UNLOADOBJECT:
		b_result = rpc_ext_push_unloadobject_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENENTRY:
		b_result = rpc_ext_push_openentry_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENSTOREENTRY:
		b_result = rpc_ext_push_openstoreentry_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENABENTRY:
		b_result = rpc_ext_push_openabentry_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::RESOLVENAME:
		b_result = rpc_ext_push_resolvename_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETPERMISSIONS:
		b_result = rpc_ext_push_getpermissions_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::MODIFYPERMISSIONS:
		b_result = rpc_ext_push_modifypermissions_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::MODIFYRULES:
		b_result = rpc_ext_push_modifyrules_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETABGAL:
		b_result = rpc_ext_push_getabgal_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LOADSTORETABLE:
		b_result = rpc_ext_push_loadstoretable_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENSTORE:
		b_result = rpc_ext_push_openstore_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENPROFILESEC:
		b_result = rpc_ext_push_openprofilesec_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LOADHIERARCHYTABLE:
		b_result = rpc_ext_push_loadhierarchytable_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LOADCONTENTTABLE:
		b_result = rpc_ext_push_loadcontenttable_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LOADRECIPIENTTABLE:
		b_result = rpc_ext_push_loadrecipienttable_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LOADRULETABLE:
		b_result = rpc_ext_push_loadruletable_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CREATEMESSAGE:
		b_result = rpc_ext_push_createmessage_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::DELETEMESSAGES:
		b_result = rpc_ext_push_deletemessages_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::COPYMESSAGES:
		b_result = rpc_ext_push_copymessages_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SETREADFLAGS:
		b_result = rpc_ext_push_setreadflags_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CREATEFOLDER:
		b_result = rpc_ext_push_createfolder_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::DELETEFOLDER:
		b_result = rpc_ext_push_deletefolder_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::EMPTYFOLDER:
		b_result = rpc_ext_push_emptyfolder_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::COPYFOLDER:
		b_result = rpc_ext_push_copyfolder_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETSTOREENTRYID:
		b_result = rpc_ext_push_getstoreentryid_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::ENTRYIDFROMSOURCEKEY:
		b_result = rpc_ext_push_entryidfromsourcekey_request(
								&push_ctx, &prequest->payload);
		break;
	case zcore_callid::STOREADVISE:
		b_result = rpc_ext_push_storeadvise_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::UNADVISE:
		b_result = rpc_ext_push_unadvise_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::NOTIFDEQUEUE:
		b_result = rpc_ext_push_notifdequeue_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::QUERYROWS:
		b_result = rpc_ext_push_queryrows_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SETCOLUMNS:
		b_result = rpc_ext_push_setcolumns_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SEEKROW:
		b_result = rpc_ext_push_seekrow_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SORTTABLE:
		b_result = rpc_ext_push_sorttable_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETROWCOUNT:
		b_result = rpc_ext_push_getrowcount_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::RESTRICTTABLE:
		b_result = rpc_ext_push_restricttable_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::FINDROW:
		b_result = rpc_ext_push_findrow_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CREATEBOOKMARK:
		b_result = rpc_ext_push_createbookmark_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::FREEBOOKMARK:
		b_result = rpc_ext_push_freebookmark_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETRECEIVEFOLDER:
		b_result = rpc_ext_push_getreceivefolder_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::MODIFYRECIPIENTS:
		b_result = rpc_ext_push_modifyrecipients_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SUBMITMESSAGE:
		b_result = rpc_ext_push_submitmessage_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LOADATTACHMENTTABLE:
		b_result = rpc_ext_push_loadattachmenttable_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENATTACHMENT:
		b_result = rpc_ext_push_openattachment_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CREATEATTACHMENT:
		b_result = rpc_ext_push_createattachment_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::DELETEATTACHMENT:
		b_result = rpc_ext_push_deleteattachment_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SETPROPVALS:
		b_result = rpc_ext_push_setpropvals_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETPROPVALS:
		b_result = rpc_ext_push_getpropvals_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::DELETEPROPVALS:
		b_result = rpc_ext_push_deletepropvals_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SETMESSAGEREADFLAG:
		b_result = rpc_ext_push_setmessagereadflag_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::OPENEMBEDDED:
		b_result = rpc_ext_push_openembedded_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETNAMEDPROPIDS:
		b_result = rpc_ext_push_getnamedpropids_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETPROPNAMES:
		b_result = rpc_ext_push_getpropnames_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::COPYTO:
		b_result = rpc_ext_push_copyto_request(
				&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SAVECHANGES:
		b_result = rpc_ext_push_savechanges_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::HIERARCHYSYNC:
		b_result = rpc_ext_push_hierarchysync_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CONTENTSYNC:
		b_result = rpc_ext_push_contentsync_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CONFIGSYNC:
		b_result = rpc_ext_push_configsync_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::STATESYNC:
		b_result = rpc_ext_push_statesync_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SYNCMESSAGECHANGE:
		b_result = rpc_ext_push_syncmessagechange_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SYNCFOLDERCHANGE:
		b_result = rpc_ext_push_syncfolderchange_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SYNCREADSTATECHANGES:
		b_result = rpc_ext_push_syncreadstatechanges_request(
								&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SYNCDELETIONS:
		b_result = rpc_ext_push_syncdeletions_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::HIERARCHYIMPORT:
		b_result = rpc_ext_push_hierarchyimport_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CONTENTIMPORT:
		b_result = rpc_ext_push_contentimport_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::CONFIGIMPORT:
		b_result = rpc_ext_push_configimport_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::STATEIMPORT:
		b_result = rpc_ext_push_stateimport_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::IMPORTMESSAGE:
		b_result = rpc_ext_push_importmessage_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::IMPORTFOLDER:
		b_result = rpc_ext_push_importfolder_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::IMPORTDELETION:
		b_result = rpc_ext_push_importdeletion_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::IMPORTREADSTATES:
		b_result = rpc_ext_push_importreadstates_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETSEARCHCRITERIA:
		b_result = rpc_ext_push_getsearchcriteria_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SETSEARCHCRITERIA:
		b_result = rpc_ext_push_setsearchcriteria_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::MESSAGETORFC822:
		b_result = rpc_ext_push_messagetorfc822_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::RFC822TOMESSAGE:
		b_result = rpc_ext_push_rfc822tomessage_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::MESSAGETOICAL:
		b_result = rpc_ext_push_messagetoical_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::ICALTOMESSAGE:
		b_result = rpc_ext_push_icaltomessage_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::MESSAGETOVCF:
		b_result = rpc_ext_push_messagetovcf_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::VCFTOMESSAGE:
		b_result = rpc_ext_push_vcftomessage_request(
						&push_ctx, &prequest->payload);
		break;
	case zcore_callid::GETUSERAVAILABILITY:
		b_result = rpc_ext_push_getuseravailability_request(
							&push_ctx, &prequest->payload);
		break;
	case zcore_callid::SETPASSWD:
		b_result = rpc_ext_push_setpasswd_request(
					&push_ctx, &prequest->payload);
		break;
	case zcore_callid::LINKMESSAGE:
		b_result = rpc_ext_push_linkmessage_request(
					&push_ctx, &prequest->payload);
		break;
	default:
		return 0;
	}
	if (!b_result) {
		return 0;
	}
	pbin_out->cb = push_ctx.m_offset;
	push_ctx.m_offset = 0;
	push_ctx.p_uint32(pbin_out->cb - sizeof(uint32_t));
	pbin_out->pv = push_ctx.release();
	return 1;
}

zend_bool rpc_ext_pull_response(const BINARY *pbin_in,
	RPC_RESPONSE *presponse)
{
	PULL_CTX pull_ctx;
	
	pull_ctx.init(pbin_in->pb, pbin_in->cb);
	TRY(pull_ctx.g_uint32(&presponse->result));
	if (presponse->result != ecSuccess)
		return 1;
	switch (presponse->call_id) {
	case zcore_callid::LOGON:
		return rpc_ext_pull_logon_response(
			&pull_ctx, &presponse->payload);
	case zcore_callid::CHECKSESSION:
		return 1;
	case zcore_callid::UINFO:
		return rpc_ext_pull_uinfo_response(
			&pull_ctx, &presponse->payload);
	case zcore_callid::UNLOADOBJECT:
		return 1;
	case zcore_callid::OPENENTRY:
		return rpc_ext_pull_openentry_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::OPENSTOREENTRY:
		return rpc_ext_pull_openstoreentry_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::OPENABENTRY:
		return rpc_ext_pull_openabentry_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::RESOLVENAME:
		return rpc_ext_pull_resolvename_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::GETPERMISSIONS:
		return rpc_ext_pull_getpermissions_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::MODIFYPERMISSIONS:
	case zcore_callid::MODIFYRULES:
		return 1;
	case zcore_callid::GETABGAL:
		return rpc_ext_pull_getabgal_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::LOADSTORETABLE:
		return rpc_ext_pull_loadstoretable_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::OPENSTORE:
		return rpc_ext_pull_openstore_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::OPENPROFILESEC:
		return rpc_ext_pull_openprofilesec_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::LOADHIERARCHYTABLE:
		return rpc_ext_pull_loadhierarchytable_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::LOADCONTENTTABLE:
		return rpc_ext_pull_loadcontenttable_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::LOADRECIPIENTTABLE:
		return rpc_ext_pull_loadrecipienttable_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::LOADRULETABLE:
		return rpc_ext_pull_loadruletable_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::CREATEMESSAGE:
		return rpc_ext_pull_createmessage_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::DELETEMESSAGES:
	case zcore_callid::COPYMESSAGES:
	case zcore_callid::SETREADFLAGS:
		return 1;
	case zcore_callid::CREATEFOLDER:
		return rpc_ext_pull_createfolder_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::DELETEFOLDER:
	case zcore_callid::EMPTYFOLDER:
	case zcore_callid::COPYFOLDER:
		return 1;
	case zcore_callid::GETSTOREENTRYID:
		return rpc_ext_pull_getstoreentryid_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::ENTRYIDFROMSOURCEKEY:
		return rpc_ext_pull_entryidfromsourcekey_response(
							&pull_ctx, &presponse->payload);
	case zcore_callid::STOREADVISE:
		return rpc_ext_pull_storeadvise_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::UNADVISE:
		return 1;
	case zcore_callid::NOTIFDEQUEUE:
		return rpc_ext_pull_notifdequeue_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::QUERYROWS:
		return rpc_ext_pull_queryrows_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::SETCOLUMNS:
	case zcore_callid::SEEKROW:
	case zcore_callid::SORTTABLE:
		return 1;
	case zcore_callid::GETROWCOUNT:
		return rpc_ext_pull_getrowcount_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::RESTRICTTABLE:
		return 1;
	case zcore_callid::FINDROW:
		return rpc_ext_pull_findrow_response(
			&pull_ctx, &presponse->payload);
	case zcore_callid::CREATEBOOKMARK:
		return rpc_ext_pull_createbookmark_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::FREEBOOKMARK:
		return 1;
	case zcore_callid::GETRECEIVEFOLDER:
		return rpc_ext_pull_getreceivefolder_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::MODIFYRECIPIENTS:
	case zcore_callid::SUBMITMESSAGE:
		return 1;
	case zcore_callid::LOADATTACHMENTTABLE:
		return rpc_ext_pull_loadattachmenttable_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::OPENATTACHMENT:
		return rpc_ext_pull_openattachment_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::CREATEATTACHMENT:
		return rpc_ext_pull_createattachment_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::DELETEATTACHMENT:
	case zcore_callid::SETPROPVALS:
		return 1;
	case zcore_callid::GETPROPVALS:
		return rpc_ext_pull_getpropvals_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::DELETEPROPVALS:
	case zcore_callid::SETMESSAGEREADFLAG:
		return 1;
	case zcore_callid::OPENEMBEDDED:
		return rpc_ext_pull_openembedded_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::GETNAMEDPROPIDS:
		return rpc_ext_pull_getnamedpropids_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::GETPROPNAMES:
		return rpc_ext_pull_getpropnames_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::COPYTO:
	case zcore_callid::SAVECHANGES:
		return 1;
	case zcore_callid::HIERARCHYSYNC:
		return rpc_ext_pull_hierarchysync_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::CONTENTSYNC:
		return rpc_ext_pull_contentsync_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::CONFIGSYNC:
		return rpc_ext_pull_configsync_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::STATESYNC:
		return rpc_ext_pull_statesync_response(
				&pull_ctx, &presponse->payload);
	case zcore_callid::SYNCMESSAGECHANGE:
		return rpc_ext_pull_syncmessagechange_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::SYNCFOLDERCHANGE:
		return rpc_ext_pull_syncfolderchange_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::SYNCREADSTATECHANGES:
		return rpc_ext_pull_syncreadstatechanges_response(
							&pull_ctx, &presponse->payload);
	case zcore_callid::SYNCDELETIONS:
		return rpc_ext_pull_syncdeletions_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::HIERARCHYIMPORT:
		return rpc_ext_pull_hierarchyimport_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::CONTENTIMPORT:
		return rpc_ext_pull_contentimport_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::CONFIGIMPORT:
		return 1;
	case zcore_callid::STATEIMPORT:
		return rpc_ext_pull_stateimport_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::IMPORTMESSAGE:
		return rpc_ext_pull_importmessage_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::IMPORTFOLDER:
	case zcore_callid::IMPORTDELETION:
	case zcore_callid::IMPORTREADSTATES:
		return 1;
	case zcore_callid::GETSEARCHCRITERIA:
		return rpc_ext_pull_getsearchcriteria_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::SETSEARCHCRITERIA:
		return 1;
	case zcore_callid::MESSAGETORFC822:
		return rpc_ext_pull_messagetorfc822_response(
						&pull_ctx, &presponse->payload);
	case zcore_callid::RFC822TOMESSAGE:
		return 1;
	case zcore_callid::MESSAGETOICAL:
		return rpc_ext_pull_messagetoical_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::ICALTOMESSAGE:
		return 1;
	case zcore_callid::MESSAGETOVCF:
		return rpc_ext_pull_messagetovcf_response(
					&pull_ctx, &presponse->payload);
	case zcore_callid::VCFTOMESSAGE:
		return 1;
	case zcore_callid::GETUSERAVAILABILITY:
		return rpc_ext_pull_getuseravailability_reponse(
						&pull_ctx, &presponse->payload);
	case zcore_callid::SETPASSWD:
		return 1;
	case zcore_callid::LINKMESSAGE:
		return 1;
	default:
		return 0;
	}
}
