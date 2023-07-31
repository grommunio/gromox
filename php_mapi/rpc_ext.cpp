// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/zcore_rpc.hpp>
#include "ext.hpp"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_logon_token &d)
{
	return x.p_str(d.token);
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_logon_token &d)
{
	return x.g_guid(&d.hsession);
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_logon &d)
{
	TRY(x.p_str(d.username));
	if (d.password == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.password));
	}
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_logon &d)
{
	TRY(x.g_guid(&d.hsession));
	return pack_result::ok;
}
static pack_result zrpc_push(PUSH_CTX &x, const zcreq_checksession &d)
{
	TRY(x.p_guid(d.hsession));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_uinfo &d)
{
	TRY(x.p_str(d.username));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_uinfo &d)
{
	TRY(x.g_bin(&d.entryid));
	TRY(x.g_str(&d.pdisplay_name));
	TRY(x.g_str(&d.px500dn));
	TRY(x.g_uint32(&d.privilege_bits));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_unloadobject &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openentry &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openentry &d)
{
	uint8_t v;
	TRY(x.g_uint8(&v));
	d.mapi_type = static_cast<zs_objtype>(v);
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openstoreentry &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openstoreentry &d)
{
	uint8_t v;
	TRY(x.g_uint8(&v));
	d.mapi_type = static_cast<zs_objtype>(v);
	TRY(x.g_uint32(&d.hxobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openabentry &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openabentry &d)
{
	uint8_t v;
	TRY(x.g_uint8(&v));
	d.mapi_type = static_cast<zs_objtype>(v);
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_resolvename &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_tarray_set(*d.pcond_set));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_resolvename &d)
{
	TRY(x.g_tarray_set(&d.result_set));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getpermissions &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	return pack_result::ok; 
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getpermissions &d)
{
	TRY(x.g_perm_set(&d.perm_set));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_modifypermissions &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_perm_set(d.pset));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_modifyrules &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_rule_list(d.plist));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getabgal &d)
{
	TRY(x.p_guid(d.hsession));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getabgal &d)
{
	TRY(x.g_bin(&d.entryid));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_loadstoretable &d)
{	
	TRY(x.p_guid(d.hsession));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_loadstoretable &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openstore &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openstore &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openprofilesec &d)
{
	TRY(x.p_guid(d.hsession));
	if (d.puid == nullptr) {
		TRY(x.p_uint8(0));
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_bytes(d.puid, sizeof(FLATUID)));
	}
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openprofilesec &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_loadhierarchytable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_loadhierarchytable &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_loadcontenttable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_loadcontenttable &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_loadrecipienttable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_loadrecipienttable &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_loadruletable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_loadruletable &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_createmessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_createmessage &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_deletemessages &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_bin_a(*d.pentryids));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_copymessages &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hsrcfolder));
	TRY(x.p_uint32(d.hdstfolder));
	TRY(x.p_bin_a(*d.pentryids));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_setreadflags &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_bin_a(*d.pentryids));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_createfolder &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hparent_folder));
	TRY(x.p_uint32(d.folder_type));
	TRY(x.p_str(d.folder_name));
	TRY(x.p_str(d.folder_comment));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_createfolder &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_deletefolder &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hparent_folder));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_emptyfolder &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_copyfolder &d)
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
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getstoreentryid &d)
{
	TRY(x.p_str(d.mailbox_dn));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getstoreentryid &d)
{
	TRY(x.g_bin(&d.entryid));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_entryidfromsourcekey &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_bin(d.folder_key));
	if (d.pmessage_key == nullptr) {
		TRY(x.p_uint8(0));
	return pack_result::ok;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_bin(*d.pmessage_key));
	return pack_result::ok;
	}
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_entryidfromsourcekey &d)
{
	TRY(x.g_bin(&d.entryid));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_storeadvise &d)
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
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_storeadvise &d)
{
	TRY(x.g_uint32(&d.sub_id));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_unadvise &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_uint32(d.sub_id));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_notifdequeue &d)
{
	int i;
	
	TRY(x.p_guid(d.psink->hsession));
	TRY(x.p_uint16(d.psink->count));
	for (i=0; i<d.psink->count; i++) {
		TRY(x.p_uint32(d.psink->padvise[i].hstore));
		TRY(x.p_uint32(d.psink->padvise[i].sub_id));
	}
	TRY(x.p_uint32(d.timeval));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_notifdequeue &d)
{
	TRY(x.g_znotif_a(&d.notifications));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_queryrows &d)
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
	return pack_result::ok;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_proptag_a(*d.pproptags));
	return pack_result::ok;
	}
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_queryrows &d)
{
	TRY(x.g_tarray_set(&d.rowset));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_setcolumns &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_proptag_a(*d.pproptags));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_seekrow &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.bookmark));
	TRY(x.p_int32(d.seek_rows));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_sorttable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_sortorder_set(*d.psortset));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getrowcount &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getrowcount &d)
{
	TRY(x.g_uint32(&d.count));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_restricttable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_restriction(*d.prestriction));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_findrow &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.bookmark));
	TRY(x.p_restriction(*d.prestriction));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_findrow &d)
{
	TRY(x.g_uint32(&d.row_idx));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_createbookmark &d)
{
	
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_createbookmark &d)
{
	TRY(x.g_uint32(&d.bookmark));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_freebookmark &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.htable));
	TRY(x.p_uint32(d.bookmark));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getreceivefolder &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	if (d.pstrclass == nullptr) {
		TRY(x.p_uint8(0));
	return pack_result::ok;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_str(d.pstrclass));
	return pack_result::ok;
	}
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getreceivefolder &d)
{
	TRY(x.g_bin(&d.entryid));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_modifyrecipients &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_tarray_set(*d.prcpt_list));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_submitmessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_loadattachmenttable &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_loadattachmenttable &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openattachment &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.attach_id));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openattachment &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_createattachment &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_createattachment &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_deleteattachment &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.attach_id));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_setpropvals &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	TRY(x.p_tpropval_a(*d.ppropvals));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getpropvals &d)
{	
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	if (d.pproptags == nullptr) {
		TRY(x.p_uint8(0));
	return pack_result::ok;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_proptag_a(*d.pproptags));
		return pack_result::ok;
	}
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getpropvals &d)
{
	TRY(x.g_tpropval_a(&d.propvals));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_deletepropvals &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	TRY(x.p_proptag_a(*d.pproptags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_setmessagereadflag &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_openembedded &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hattachment));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_openembedded &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getnamedpropids &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_propname_a(*d.ppropnames));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getnamedpropids &d)
{
	TRY(x.g_propid_a(&d.propids));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getpropnames &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hstore));
	TRY(x.p_propid_a(*d.ppropids));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getpropnames &d)
{
	TRY(x.g_propname_a(&d.propnames));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_copyto &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hsrcobject));
	TRY(x.p_proptag_a(*d.pexclude_proptags));
	TRY(x.p_uint32(d.hdstobject));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_savechanges &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_hierarchysync &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_hierarchysync &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_contentsync &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_contentsync &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_configsync &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_bin(*d.pstate));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	return pack_result::ok;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	return pack_result::ok;
	}
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_configsync &d)
{
	TRY(x.g_uint8(&d.b_changed));
	TRY(x.g_uint32(&d.count));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_statesync &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_statesync &d)
{
	TRY(x.g_bin(&d.state));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_syncmessagechange &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_syncmessagechange &d)
{
	uint8_t v = 0;
	TRY(x.g_uint8(&v));
	d.b_new = v;
	TRY(x.g_tpropval_a(&d.proplist));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_syncfolderchange &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_syncfolderchange &d)
{
	TRY(x.g_tpropval_a(&d.proplist));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_syncreadstatechanges &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_syncreadstatechanges &d)
{
	TRY(x.g_state_a(&d.states));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_syncdeletions &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_syncdeletions &d)
{
	TRY(x.g_bin_a(&d.bins));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_hierarchyimport &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_hierarchyimport &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_contentimport &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_contentimport &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_configimport &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint8(d.sync_type));
	TRY(x.p_bin(*d.pstate));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_stateimport &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_stateimport &d)
{
	TRY(x.g_bin(&d.state));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_importmessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_tpropval_a(*d.pproplist));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_importmessage &d)
{
	TRY(x.g_uint32(&d.hobject));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_importfolder &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_tpropval_a(*d.pproplist));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_importdeletion &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_bin_a(*d.pbins));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_importreadstates &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hctx));
	TRY(x.p_state_a(d.pstates));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getsearchcriteria &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getsearchcriteria &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_bin_a(&d.folder_array));
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = st_malloc<RESTRICTION>();
		if (d.prestriction == nullptr)
			return pack_result::alloc;
		TRY(x.g_restriction(d.prestriction));
	}
	TRY(x.g_uint32(&d.search_stat));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_setsearchcriteria &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hfolder));
	TRY(x.p_uint32(d.flags));
	TRY(x.p_bin_a(*d.pfolder_array));
	if (d.prestriction == nullptr) {
		TRY(x.p_uint8(0));
	return pack_result::ok;
	} else {
		TRY(x.p_uint8(1));
		TRY(x.p_restriction(*d.prestriction));
	return pack_result::ok;
	}
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_messagetorfc822 &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_messagetorfc822 &d)
{
	TRY(x.g_bin(&d.eml_bin));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_rfc822tomessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_uint32(d.mxf_flags));
	TRY(x.p_bin(*d.peml_bin));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_messagetoical &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_messagetoical &d)
{
	TRY(x.g_bin(&d.ical_bin));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_icaltomessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_bin(*d.pical_bin));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_imtomessage2 &d)
{
	TRY(x.p_guid(d.session));
	TRY(x.p_uint32(d.folder));
	TRY(x.p_uint32(d.data_type));
	TRY(x.p_str(d.im_data));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_essdn_to_username &d)
{
	TRY(x.p_str(d.essdn));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_messagetovcf &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_messagetovcf &d)
{
	TRY(x.g_bin(&d.vcf_bin));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_vcftomessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_uint32(d.hmessage));
	TRY(x.p_bin(*d.pvcf_bin));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_getuseravailability &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.entryid));
	TRY(x.p_uint64(d.starttime));
	TRY(x.p_uint64(d.endtime));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_getuseravailability &d)
{
	uint8_t tmp_byte;
	
	TRY(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.result_string = nullptr;
		return pack_result::ok;
	}
	TRY(x.g_str(&d.result_string));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_imtomessage2 &d)
{
	TRY(x.g_uint32_a(&d.msg_handles));
	return pack_result::ok;
}

static pack_result zrpc_pull(PULL_CTX &x, zcresp_essdn_to_username &d)
{
	TRY(x.g_str(&d.username));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_setpasswd &d)
{
	TRY(x.p_str(d.username));
	TRY(x.p_str(d.passwd));
	TRY(x.p_str(d.new_passwd));
	return pack_result::ok;
}

static pack_result zrpc_push(PUSH_CTX &x, const zcreq_linkmessage &d)
{
	TRY(x.p_guid(d.hsession));
	TRY(x.p_bin(d.search_entryid));
	TRY(x.p_bin(d.message_entryid));
	return pack_result::ok;
}

pack_result rpc_ext_push_request(const zcreq *prequest, BINARY *pbin_out)
{
	PUSH_CTX push_ctx;
	auto b_result = pack_result::failure;

	if (!push_ctx.init())
		return pack_result::alloc;
	TRY(push_ctx.advance(sizeof(uint32_t)));
	TRY(push_ctx.p_uint8(static_cast<uint8_t>(prequest->call_id)));
	switch (prequest->call_id) {
#define E(t) case zcore_callid::t: b_result = zrpc_push(push_ctx, *static_cast<const zcreq_ ## t *>(prequest)); break;
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
	E(imtomessage2)
	E(essdn_to_username)
	E(logon_token)
#undef E
	default:
		return pack_result::bad_switch;
	}
	if (b_result != pack_result::ok)
		return b_result;
	pbin_out->cb = push_ctx.m_offset;
	push_ctx.m_offset = 0;
	push_ctx.p_uint32(pbin_out->cb - sizeof(uint32_t));
	pbin_out->pv = push_ctx.release();
	return pack_result::ok;
}

pack_result rpc_ext_pull_response(const BINARY *pbin_in, zcresp *presponse)
{
	PULL_CTX pull_ctx;
	
	pull_ctx.init(pbin_in->pb, pbin_in->cb);
	uint32_t v;
	TRY(pull_ctx.g_uint32(&v));
	presponse->result = static_cast<ec_error_t>(v);
	if (presponse->result != ecSuccess)
		return pack_result::ok;
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
		return pack_result::ok;
#define E(t) case zcore_callid::t: return zrpc_pull(pull_ctx, *static_cast<zcresp_ ## t *>(presponse));
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
	E(imtomessage2)
	E(essdn_to_username)
	E(logon_token)
#undef E
	default:
		return pack_result::bad_switch;
	}
}
