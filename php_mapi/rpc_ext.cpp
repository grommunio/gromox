// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/zcore_rpc.hpp>
#include "ext.hpp"
#define TRY(expr) do { if ((expr) != EXT_ERR_SUCCESS) return false; } while (false)

using RPC_REQUEST = ZCORE_RPC_REQUEST;
using RPC_RESPONSE = ZCORE_RPC_RESPONSE;
using REQUEST_PAYLOAD = ZCORE_REQUEST_PAYLOAD;
using RESPONSE_PAYLOAD = ZCORE_RESPONSE_PAYLOAD;

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOGON &d)
{
	TRY(x.p_str(d.username));
	if (d.password == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.password));
	}
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOGON &d)
{
	TRY(x.g_guid(&d.hsession));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CHECKSESSION &d)
{
	TRY(x.p_guid(d.hsession));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_UINFO &d)
{
	TRY(x.p_str(d.username));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_UINFO &d)
{
	TRY(x.g_bin(&d.entryid));
	TRY(x.g_str(&d.pdisplay_name));
	TRY(x.g_str(&d.px500dn));
	TRY(x.g_uint32(&d.privilege_bits));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_UNLOADOBJECT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENENTRY &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENENTRY &d)
{
	TRY(x.g_uint8(&d.mapi_type));
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENSTOREENTRY &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENSTOREENTRY &d)
{
	TRY(x.g_uint8(&d.mapi_type));
	TRY(x.g_uint32(&d.hxobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENABENTRY &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENABENTRY &d)
{
	TRY(x.g_uint8(&d.mapi_type));
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_RESOLVENAME &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_tarray_set(*d.pcond_set));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_RESOLVENAME &d)
{
	TRY(x.g_tarray_set(&d.result_set));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETPERMISSIONS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	return true; 
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETPERMISSIONS &d)
{
	TRY(x.g_perm_set(&d.perm_set));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_MODIFYPERMISSIONS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_perm_set(d.pset));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_MODIFYRULES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_rule_list(d.plist));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETABGAL &d)
{
	TRY(x.p_guid(d.hsession));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETABGAL &d)
{
	TRY(x.g_bin(&d.entryid));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOADSTORETABLE &d)
{	
	TRY(x.p_guid(d.hsession));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOADSTORETABLE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENSTORE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENSTORE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENPROFILESEC &d)
{
	TRY(x.p_guid(d.hsession));
	if (d.puid == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_bytes(d.puid, sizeof(FLATUID)));
	}
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENPROFILESEC &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOADHIERARCHYTABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOADHIERARCHYTABLE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOADCONTENTTABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOADCONTENTTABLE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOADRECIPIENTTABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOADRECIPIENTTABLE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOADRULETABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOADRULETABLE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CREATEMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CREATEMESSAGE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_DELETEMESSAGES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_bin_a(*d.pentryids));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_COPYMESSAGES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hsrcfolder));
	TRY(x.p_uint32(d.hdstfolder));
	TRY(x.p_bin_a(*d.pentryids));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SETREADFLAGS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_bin_a(*d.pentryids));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CREATEFOLDER &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hparent_folder));
	TRY(x.p_uint32(d.folder_type));
	TRY(x.p_str(d.folder_name));
	TRY(x.p_str(d.folder_comment));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CREATEFOLDER &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_DELETEFOLDER &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hparent_folder));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_EMPTYFOLDER &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_COPYFOLDER &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hsrc_folder));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.hdst_folder));
	if (d.new_name == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.new_name));
	}
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETSTOREENTRYID &d)
{
	TRY(x.p_str(d.mailbox_dn));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETSTOREENTRYID &d)
{
	TRY(x.g_bin(&d.entryid));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_ENTRYIDFROMSOURCEKEY &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_bin(d.folder_key));
	if (d.pmessage_key == nullptr) {
		TRY(x.p_uint8(0));
	return true;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_bin(*d.pmessage_key));
	return true;
	}
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_ENTRYIDFROMSOURCEKEY &d)
{
	TRY(x.g_bin(&d.entryid));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_STOREADVISE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	if (d.pentryid == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_bin(*d.pentryid));
	}
	TRY(x.p_uint32(d.event_mask));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_STOREADVISE &d)
{
	TRY(x.g_uint32(&d.sub_id));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_UNADVISE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_uint32(d.sub_id));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_NOTIFDEQUEUE &d)
{
	int i;
	
	TRY(x.p_guid(d.psink->hsession));
	TRY(x.p_uint16(d.psink->count));
	for (i=0; i<d.psink->count; i++) {
		TRY(x.p_uint32(d.psink->padvise[i].hstore));
		TRY(x.p_uint32(d.psink->padvise[i].sub_id));
	}
	TRY(x.p_uint32(d.timeval));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_NOTIFDEQUEUE &d)
{
	TRY(x.g_znotif_a(&d.notifications));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_QUERYROWS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.start));
	TRY(x.p_uint32(d.count));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	}
	if (d.pproptags == nullptr) {
		TRY(x.p_uint8(0));
	return true;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_proptag_a(*d.pproptags));
	return true;
	}
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_QUERYROWS &d)
{
	TRY(x.g_tarray_set(&d.rowset));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SETCOLUMNS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_proptag_a(*d.pproptags));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SEEKROW &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.bookmark));
	TRY(x.p_int32(d.seek_rows));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SORTTABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_sortorder_set(*d.psortset));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETROWCOUNT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETROWCOUNT &d)
{
	TRY(x.g_uint32(&d.count));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_RESTRICTTABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_restriction(*d.prestriction));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_FINDROW &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.bookmark));
	TRY(x.p_restriction(*d.prestriction));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_FINDROW &d)
{
	TRY(x.g_uint32(&d.row_idx));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CREATEBOOKMARK &d)
{
	
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CREATEBOOKMARK &d)
{
	TRY(x.g_uint32(&d.bookmark));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_FREEBOOKMARK &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.bookmark));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETRECEIVEFOLDER &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	if (d.pstrclass == nullptr) {
		TRY(x.p_uint8(0));
	return true;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.pstrclass));
	return true;
	}
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETRECEIVEFOLDER &d)
{
	TRY(x.g_bin(&d.entryid));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_MODIFYRECIPIENTS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_tarray_set(*d.prcpt_list));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SUBMITMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LOADATTACHMENTTABLE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_LOADATTACHMENTTABLE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENATTACHMENT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.attach_id));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENATTACHMENT &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CREATEATTACHMENT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CREATEATTACHMENT &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_DELETEATTACHMENT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.attach_id));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SETPROPVALS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	TRY(x.p_tpropval_a(*d.ppropvals));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETPROPVALS &d)
{	
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	if (d.pproptags == nullptr) {
		TRY(x.p_uint8(0));
	return true;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_proptag_a(*d.pproptags));
		return true;
	}
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETPROPVALS &d)
{
	TRY(x.g_tpropval_a(&d.propvals));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_DELETEPROPVALS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	TRY(x.p_proptag_a(*d.pproptags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SETMESSAGEREADFLAG &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_OPENEMBEDDED &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hattachment));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_OPENEMBEDDED &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETNAMEDPROPIDS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_propname_a(*d.ppropnames));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETNAMEDPROPIDS &d)
{
	TRY(x.g_propid_a(&d.propids));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETPROPNAMES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_propid_a(*d.ppropids));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETPROPNAMES &d)
{
	TRY(x.g_propname_a(&d.propnames));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_COPYTO &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hsrcobject));
	TRY(x.p_proptag_a(*d.pexclude_proptags));
	TRY(x.p_uint32(d.hdstobject));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SAVECHANGES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_HIERARCHYSYNC &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_HIERARCHYSYNC &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CONTENTSYNC &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CONTENTSYNC &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CONFIGSYNC &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_bin(*d.pstate));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	return true;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	return true;
	}
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CONFIGSYNC &d)
{
	TRY(x.g_uint8(&d.b_changed));
	TRY(x.g_uint32(&d.count));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_STATESYNC &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_STATESYNC &d)
{
	TRY(x.g_bin(&d.state));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SYNCMESSAGECHANGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_SYNCMESSAGECHANGE &d)
{
	uint8_t v = 0;
	TRY(x.g_uint8(&v));
	d.b_new = v;
	TRY(x.g_tpropval_a(&d.proplist));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SYNCFOLDERCHANGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_SYNCFOLDERCHANGE &d)
{
	TRY(x.g_tpropval_a(&d.proplist));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SYNCREADSTATECHANGES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_SYNCREADSTATECHANGES &d)
{
	TRY(x.g_state_a(&d.states));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SYNCDELETIONS &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_SYNCDELETIONS &d)
{
	TRY(x.g_bin_a(&d.bins));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_HIERARCHYIMPORT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_HIERARCHYIMPORT &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CONTENTIMPORT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_CONTENTIMPORT &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_CONFIGIMPORT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint8(d.sync_type));
	TRY(x.p_bin(*d.pstate));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_STATEIMPORT &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_STATEIMPORT &d)
{
	TRY(x.g_bin(&d.state));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_IMPORTMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_tpropval_a(*d.pproplist));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_IMPORTMESSAGE &d)
{
	TRY(x.g_uint32(&d.hobject));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_IMPORTFOLDER &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_tpropval_a(*d.pproplist));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_IMPORTDELETION &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_bin_a(*d.pbins));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_IMPORTREADSTATES &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_state_a(d.pstates));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETSEARCHCRITERIA &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETSEARCHCRITERIA &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_bin_a(&d.folder_array));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = st_malloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return 0;
		TRY(x.g_restriction(d.prestriction));
	}
	TRY(x.g_uint32(&d.search_stat));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SETSEARCHCRITERIA &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_bin_a(*d.pfolder_array));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	return true;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	return true;
	}
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_MESSAGETORFC822 &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_MESSAGETORFC822 &d)
{
	TRY(x.g_bin(&d.eml_bin));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_RFC822TOMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.mxf_flags));
	TRY(x.p_bin(*d.peml_bin));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_MESSAGETOICAL &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_MESSAGETOICAL &d)
{
	TRY(x.g_bin(&d.ical_bin));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_ICALTOMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_bin(*d.pical_bin));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_ICALTOMESSAGE2 &d)
{
	TRY(x.p_guid(d.session));
	TRY(x.p_uint32(d.folder));
	TRY(x.p_str(d.ical_data));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_MESSAGETOVCF &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_MESSAGETOVCF &d)
{
	TRY(x.g_bin(&d.vcf_bin));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_VCFTOMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_bin(*d.pvcf_bin));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_GETUSERAVAILABILITY &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint64(d.starttime));
	TRY(x.p_uint64(d.endtime));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_GETUSERAVAILABILITY &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.result_string = nullptr;
		return 1;
	}
	TRY(x.g_str(&d.result_string));
	return true;
}

static zend_bool zrpc_pull(PULL_CTX &x, ZCRESP_ICALTOMESSAGE2 &d)
{
	TRY(x.g_uint32_a(&d.msg_handles));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_SETPASSWD &d)
{
	TRY(x.p_str(d.username));
	TRY(x.p_str(d.passwd));
	TRY(x.p_str(d.new_passwd));
	return true;
}

static zend_bool zrpc_push(PUSH_CTX &x, const ZCREQ_LINKMESSAGE &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.search_entryid));
	TRY(x.p_bin(d.message_entryid));
	return true;
}

zend_bool rpc_ext_push_request(const RPC_REQUEST *prequest,
	BINARY *pbin_out)
{
	PUSH_CTX push_ctx;
	zend_bool b_result;

	if (!push_ctx.init())
		return false;
	TRY(push_ctx.advance(sizeof(uint32_t)));
	TRY(push_ctx.p_uint8(static_cast<uint8_t>(prequest->call_id)));
	switch (prequest->call_id) {
#define E(t) case zcore_callid::t: b_result = zrpc_push(push_ctx, prequest->payload.t); break;
	E(logon)
	E(checksession)
	E(uinfo)
	E(unloadobject)
	E(openentry)
	E(openstoreentry)
	E(openabentry)
	E(resolvename)
	E(getpermissions)
	E(modifypermissions)
	E(modifyrules)
	E(getabgal)
	E(loadstoretable)
	E(openstore)
	E(openprofilesec)
	E(loadhierarchytable)
	E(loadcontenttable)
	E(loadrecipienttable)
	E(loadruletable)
	E(createmessage)
	E(deletemessages)
	E(copymessages)
	E(setreadflags)
	E(createfolder)
	E(deletefolder)
	E(emptyfolder)
	E(copyfolder)
	E(getstoreentryid)
	E(entryidfromsourcekey)
	E(storeadvise)
	E(unadvise)
	E(notifdequeue)
	E(queryrows)
	E(setcolumns)
	E(seekrow)
	E(sorttable)
	E(getrowcount)
	E(restricttable)
	E(findrow)
	E(createbookmark)
	E(freebookmark)
	E(getreceivefolder)
	E(modifyrecipients)
	E(submitmessage)
	E(loadattachmenttable)
	E(openattachment)
	E(createattachment)
	E(deleteattachment)
	E(setpropvals)
	E(getpropvals)
	E(deletepropvals)
	E(setmessagereadflag)
	E(openembedded)
	E(getnamedpropids)
	E(getpropnames)
	E(copyto)
	E(savechanges)
	E(hierarchysync)
	E(contentsync)
	E(configsync)
	E(statesync)
	E(syncmessagechange)
	E(syncfolderchange)
	E(syncreadstatechanges)
	E(syncdeletions)
	E(hierarchyimport)
	E(contentimport)
	E(configimport)
	E(stateimport)
	E(importmessage)
	E(importfolder)
	E(importdeletion)
	E(importreadstates)
	E(getsearchcriteria)
	E(setsearchcriteria)
	E(messagetorfc822)
	E(rfc822tomessage)
	E(messagetoical)
	E(icaltomessage)
	E(messagetovcf)
	E(vcftomessage)
	E(getuseravailability)
	E(setpasswd)
	E(linkmessage)
	E(icaltomessage2)
#undef E
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
	case zcore_callid::checksession:
	case zcore_callid::unloadobject:
	case zcore_callid::modifypermissions:
	case zcore_callid::modifyrules:
	case zcore_callid::deletemessages:
	case zcore_callid::copymessages:
	case zcore_callid::setreadflags:
	case zcore_callid::deletefolder:
	case zcore_callid::emptyfolder:
	case zcore_callid::copyfolder:
	case zcore_callid::unadvise:
	case zcore_callid::setcolumns:
	case zcore_callid::seekrow:
	case zcore_callid::sorttable:
	case zcore_callid::restricttable:
	case zcore_callid::freebookmark:
	case zcore_callid::modifyrecipients:
	case zcore_callid::submitmessage:
	case zcore_callid::deleteattachment:
	case zcore_callid::setpropvals:
	case zcore_callid::deletepropvals:
	case zcore_callid::setmessagereadflag:
	case zcore_callid::copyto:
	case zcore_callid::savechanges:
	case zcore_callid::configimport:
	case zcore_callid::importfolder:
	case zcore_callid::importdeletion:
	case zcore_callid::importreadstates:
	case zcore_callid::setsearchcriteria:
	case zcore_callid::rfc822tomessage:
	case zcore_callid::icaltomessage:
	case zcore_callid::vcftomessage:
	case zcore_callid::setpasswd:
	case zcore_callid::linkmessage:
		return 1;
#define E(t) case zcore_callid::t: return zrpc_pull(pull_ctx, presponse->payload.t);
	E(logon)
	E(uinfo)
	E(openentry)
	E(openstoreentry)
	E(openabentry)
	E(resolvename)
	E(getpermissions)
	E(getabgal)
	E(loadstoretable)
	E(openstore)
	E(openprofilesec)
	E(loadhierarchytable)
	E(loadcontenttable)
	E(loadrecipienttable)
	E(loadruletable)
	E(createmessage)
	E(createfolder)
	E(getstoreentryid)
	E(entryidfromsourcekey)
	E(storeadvise)
	E(notifdequeue)
	E(queryrows)
	E(getrowcount)
	E(findrow)
	E(createbookmark)
	E(getreceivefolder)
	E(loadattachmenttable)
	E(openattachment)
	E(createattachment)
	E(getpropvals)
	E(openembedded)
	E(getnamedpropids)
	E(getpropnames)
	E(hierarchysync)
	E(contentsync)
	E(configsync)
	E(statesync)
	E(syncmessagechange)
	E(syncfolderchange)
	E(syncreadstatechanges)
	E(syncdeletions)
	E(hierarchyimport)
	E(contentimport)
	E(stateimport)
	E(importmessage)
	E(getsearchcriteria)
	E(messagetorfc822)
	E(messagetoical)
	E(messagetovcf)
	E(getuseravailability)
	E(icaltomessage2)
#undef E
	default:
		return 0;
	}
}
