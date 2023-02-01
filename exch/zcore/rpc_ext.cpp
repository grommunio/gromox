// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/zcore_rpc.hpp>
#include "common_util.h"
#include "rpc_ext.h"
#define QRF(expr) do { if ((expr) != EXT_ERR_SUCCESS) return false; } while (false)

static BOOL rpc_ext_pull_propval(
	EXT_PULL *pext, uint16_t type, void **ppval)
{
#define CASE(mt, ct, fu) \
	case (mt): \
		*ppval = pext->anew<ct>(); \
		if (*ppval == nullptr) \
			return false; \
		QRF(pext->fu(static_cast<ct *>(*ppval))); \
		return TRUE;

	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	CASE(PT_SHORT, uint16_t, g_uint16);
	case PT_ERROR:
	CASE(PT_LONG, uint32_t, g_uint32);
	CASE(PT_FLOAT, float, g_float);
	case PT_APPTIME:
	CASE(PT_DOUBLE, double, g_double);
	CASE(PT_BOOLEAN, uint8_t, g_uint8);
	case PT_CURRENCY:
	case PT_SYSTIME:
	CASE(PT_I8, uint64_t, g_uint64);
	case PT_STRING8:
		QRF(pext->g_str(reinterpret_cast<char **>(ppval)));
		return TRUE;
	case PT_UNICODE:
		QRF(pext->g_wstr(reinterpret_cast<char **>(ppval)));
		return TRUE;
	CASE(PT_CLSID, GUID, g_guid);
	CASE(PT_SRESTRICTION, RESTRICTION, g_restriction);
	CASE(PT_ACTIONS, RULE_ACTIONS, g_rule_actions);
	CASE(PT_BINARY, BINARY, g_bin);
	CASE(PT_MV_SHORT, SHORT_ARRAY, g_uint16_a);
	CASE(PT_MV_LONG, LONG_ARRAY, g_uint32_a);
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
	CASE(PT_MV_I8, LONGLONG_ARRAY, g_uint64_a);
	CASE(PT_MV_FLOAT, FLOAT_ARRAY, g_float_a);
	case PT_MV_APPTIME:
	CASE(PT_MV_DOUBLE, DOUBLE_ARRAY, g_double_a);
	CASE(PT_MV_STRING8, STRING_ARRAY, g_str_a);
	CASE(PT_MV_UNICODE, STRING_ARRAY, g_wstr_a);
	CASE(PT_MV_CLSID, GUID_ARRAY, g_guid_a);
	CASE(PT_MV_BINARY, BINARY_ARRAY, g_bin_a);
	default:
		return FALSE;
	}
#undef CASE
}

static BOOL rpc_ext_pull_tagged_propval(
	EXT_PULL *pext, TAGGED_PROPVAL *r)
{	
	QRF(pext->g_uint32(&r->proptag));
	return rpc_ext_pull_propval(pext, PROP_TYPE(r->proptag), &r->pvalue);
}

static BOOL rpc_ext_pull_tpropval_array(
	EXT_PULL *pext, TPROPVAL_ARRAY *r)
{
	QRF(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->ppropval = NULL;
		return TRUE;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		r->count = 0;
		return FALSE;
	}
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_pull_tagged_propval(pext, &r->ppropval[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_pull_rule_data(
	EXT_PULL *pext, RULE_DATA *r)
{
	QRF(pext->g_uint8(&r->flags));
	return rpc_ext_pull_tpropval_array(pext, &r->propvals);
}

static BOOL rpc_ext_pull_rule_list(
	EXT_PULL *pext, RULE_LIST *r)
{
	QRF(pext->g_uint16(&r->count));
	if (0 == r->count) {
		r->prule = NULL;
		return TRUE;
	}
	r->prule = pext->anew<RULE_DATA>(r->count);
	if (NULL == r->prule) {
		r->count = 0;
		return FALSE;
	}
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_pull_rule_data(pext, &r->prule[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_pull_permission_row(
	EXT_PULL *pext, PERMISSION_ROW *r)
{
	QRF(pext->g_uint32(&r->flags));
	QRF(pext->g_bin(&r->entryid));
	QRF(pext->g_uint32(&r->member_rights));
	return TRUE;
}

static BOOL rpc_ext_pull_permission_set(
	EXT_PULL *pext, PERMISSION_SET *r)
{
	QRF(pext->g_uint16(&r->count));
	r->prows = pext->anew<PERMISSION_ROW>(r->count);
	if (NULL == r->prows) {
		r->count = 0;
		return FALSE;
	}
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_pull_permission_row(pext, &r->prows[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_pull_message_state(
	EXT_PULL *pext, MESSAGE_STATE *r)
{
	QRF(pext->g_bin(&r->source_key));
	QRF(pext->g_uint32(&r->message_flags));
	return TRUE;
}

static BOOL rpc_ext_pull_state_array(
	EXT_PULL *pext, STATE_ARRAY *r)
{
	QRF(pext->g_uint32(&r->count));
	if (0 == r->count) {
		r->pstate = NULL;
		return TRUE;
	}
	r->pstate = pext->anew<MESSAGE_STATE>(r->count);
	if (NULL == r->pstate) {
		r->count = 0;
		return FALSE;
	}
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_pull_message_state(pext, &r->pstate[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_push_propval(EXT_PUSH *pext,
	uint16_t type, const void *pval)
{
#define CASE(mt, ct, fu) \
	case (mt): \
		QRF(pext->fu(*static_cast<const ct *>(pval))); \
		return TRUE;

	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	CASE(PT_SHORT, uint16_t, p_uint16);
	case PT_ERROR:
	CASE(PT_LONG, uint32_t, p_uint32);
	CASE(PT_FLOAT, float, p_float);
	case PT_APPTIME:
	CASE(PT_DOUBLE, double, p_double);
	CASE(PT_BOOLEAN, uint8_t, p_uint8);
	case PT_CURRENCY:
	case PT_SYSTIME:
	CASE(PT_I8, uint64_t, p_uint64);
	case PT_STRING8:
		QRF(pext->p_str(static_cast<const char *>(pval)));
		return TRUE;
	case PT_UNICODE:
		QRF(pext->p_wstr(static_cast<const char *>(pval)));
		return TRUE;
	CASE(PT_CLSID, GUID, p_guid);
	CASE(PT_SRESTRICTION, RESTRICTION, p_restriction);
	CASE(PT_ACTIONS, RULE_ACTIONS, p_rule_actions);
	CASE(PT_BINARY, BINARY, p_bin);
	CASE(PT_MV_SHORT, SHORT_ARRAY, p_uint16_a);
	CASE(PT_MV_LONG, LONG_ARRAY, p_uint32_a);
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
	CASE(PT_MV_I8, LONGLONG_ARRAY, p_uint64_a);
	CASE(PT_MV_FLOAT, FLOAT_ARRAY, p_float_a);
	case PT_MV_APPTIME:
	CASE(PT_MV_DOUBLE, DOUBLE_ARRAY, p_double_a);
	CASE(PT_MV_STRING8, STRING_ARRAY, p_str_a);
	CASE(PT_MV_UNICODE, STRING_ARRAY, p_wstr_a);
	CASE(PT_MV_CLSID, GUID_ARRAY, p_guid_a);
	CASE(PT_MV_BINARY, BINARY_ARRAY, p_bin_a);
	default:
		return FALSE;
	}
#undef CASE
}

static BOOL rpc_ext_push_tagged_propval(
	EXT_PUSH *pext, const TAGGED_PROPVAL *r)
{
	QRF(pext->p_uint32(r->proptag));
	return rpc_ext_push_propval(pext, PROP_TYPE(r->proptag), r->pvalue);
}

static BOOL rpc_ext_push_tpropval_array(
	EXT_PUSH *pext, const TPROPVAL_ARRAY *r)
{
	QRF(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_push_tagged_propval(pext, &r->ppropval[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_push_tarray_set(
	EXT_PUSH *pext, const TARRAY_SET *r)
{
	QRF(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_push_tpropval_array(pext, r->pparray[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_push_permission_row(
	EXT_PUSH *pext, const PERMISSION_ROW *r)
{
	QRF(pext->p_uint32(r->flags));
	QRF(pext->p_bin(r->entryid));
	QRF(pext->p_uint32(r->member_rights));
	return TRUE;
}

static BOOL rpc_ext_push_permission_set(
	EXT_PUSH *pext, const PERMISSION_SET *r)
{
	QRF(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_push_permission_row(pext, &r->prows[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_push_message_state(
	EXT_PUSH *pext, const MESSAGE_STATE *r)
{
	QRF(pext->p_bin(r->source_key));
	QRF(pext->p_uint32(r->message_flags));
	return TRUE;
}

static BOOL rpc_ext_push_state_array(
	EXT_PUSH *pext, const STATE_ARRAY *r)
{
	QRF(pext->p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_push_message_state(pext, &r->pstate[i]))
			return FALSE;
	return TRUE;
}

static BOOL rpc_ext_push_newmail_znotification(
	EXT_PUSH *pext, const NEWMAIL_ZNOTIFICATION *r)
{
	QRF(pext->p_bin(r->entryid));
	QRF(pext->p_bin(r->parentid));
	QRF(pext->p_uint32(r->flags));
	QRF(pext->p_str(r->message_class));
	QRF(pext->p_uint32(r->message_flags));
	return TRUE;
}

static BOOL rpc_ext_push_object_znotification(
	EXT_PUSH *pext, const OBJECT_ZNOTIFICATION *r)
{	
	QRF(pext->p_uint32(r->object_type));
	if (NULL == r->pentryid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(*r->pentryid));
	}
	if (NULL == r->pparentid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(*r->pparentid));
	}
	if (NULL == r->pold_entryid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(*r->pold_entryid));
	}
	if (NULL == r->pold_parentid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(*r->pold_parentid));
	}
	if (NULL == r->pproptags) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_proptag_a(*r->pproptags));
	}
	return TRUE;
}

static BOOL rpc_ext_push_znotification(
	EXT_PUSH *pext, const ZNOTIFICATION *r)
{
	QRF(pext->p_uint32(r->event_type));
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		return rpc_ext_push_newmail_znotification(pext,
		       static_cast<NEWMAIL_ZNOTIFICATION *>(r->pnotification_data));
	case EVENT_TYPE_OBJECTCREATED:
	case EVENT_TYPE_OBJECTDELETED:
	case EVENT_TYPE_OBJECTMODIFIED:
	case EVENT_TYPE_OBJECTMOVED:
	case EVENT_TYPE_OBJECTCOPIED:
	case EVENT_TYPE_SEARCHCOMPLETE:
		return rpc_ext_push_object_znotification(pext,
		       static_cast<OBJECT_ZNOTIFICATION *>(r->pnotification_data));
	default:
		return TRUE;
	}
}

static BOOL rpc_ext_push_znotification_array(
	EXT_PUSH *pext, const ZNOTIFICATION_ARRAY *r)
{
	QRF(pext->p_uint16(r->count));
	for (size_t i = 0; i < r->count; ++i)
		if (!rpc_ext_push_znotification(pext, r->ppnotification[i]))
			return FALSE;
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_logon &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_str(&d.username));
	QRF(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.password = nullptr;
	else
		QRF(x.g_str(&d.password));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_logon &d)
{
	QRF(x.p_guid(d.hsession));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_checksession &d)
{
	QRF(x.g_guid(&d.hsession));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_uinfo &d)
{
	QRF(x.g_str(&d.username));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_uinfo &d)
{
	QRF(x.p_bin(d.entryid));
	QRF(x.p_str(d.pdisplay_name));
	QRF(x.p_str(d.px500dn));
	QRF(x.p_uint32(d.privilege_bits));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_unloadobject &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openentry &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_bin(&d.entryid));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openentry &d)
{
	QRF(x.p_uint8(d.mapi_type));
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openstoreentry &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	QRF(x.g_bin(&d.entryid));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openstoreentry &d)
{
	QRF(x.p_uint8(d.mapi_type));
	QRF(x.p_uint32(d.hxobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openabentry &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_bin(&d.entryid));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openabentry &d)
{
	QRF(x.p_uint8(d.mapi_type));
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_resolvename &d)
{
	QRF(x.g_guid(&d.hsession));
	d.pcond_set = x.anew<TARRAY_SET>();
	if (d.pcond_set == nullptr)
		return FALSE;
	QRF(x.g_tarray_set(d.pcond_set));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_resolvename &d)
{
	QRF(x.p_tarray_set(d.result_set));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getpermissions &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getpermissions &d)
{
	return rpc_ext_push_permission_set(&x, &d.perm_set);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_modifypermissions &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	d.pset = x.anew<PERMISSION_SET>();
	if (d.pset == nullptr)
		return FALSE;
	return rpc_ext_pull_permission_set(&x, d.pset);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_modifyrules &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	QRF(x.g_uint32(&d.flags));
	d.plist = x.anew<RULE_LIST>();
	if (d.plist == nullptr)
		return FALSE;
	return rpc_ext_pull_rule_list(&x, d.plist);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getabgal &d)
{
	QRF(x.g_guid(&d.hsession));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getabgal &d)
{
	QRF(x.p_bin(d.entryid));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_loadstoretable &d)
{	
	QRF(x.g_guid(&d.hsession));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_loadstoretable &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openstore &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_bin(&d.entryid));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openstore &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openprofilesec &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.puid = nullptr;
	} else {
		d.puid = x.anew<FLATUID>();
		if (d.puid == nullptr)
			return FALSE;
		QRF(x.g_bytes(deconst(d.puid), sizeof(FLATUID)));
	}
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openprofilesec &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_loadhierarchytable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_loadhierarchytable &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_loadcontenttable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_loadcontenttable &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_loadrecipienttable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_loadrecipienttable &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_loadruletable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_loadruletable &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_createmessage &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_createmessage &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_deletemessages &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	d.pentryids = x.anew<BINARY_ARRAY>();
	if (d.pentryids == nullptr)
		return FALSE;
	QRF(x.g_bin_a(d.pentryids));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_copymessages &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hsrcfolder));
	QRF(x.g_uint32(&d.hdstfolder));
	d.pentryids = x.anew<BINARY_ARRAY>();
	if (d.pentryids == nullptr)
		return FALSE;
	QRF(x.g_bin_a(d.pentryids));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_setreadflags &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	d.pentryids = x.anew<BINARY_ARRAY>();
	if (d.pentryids == nullptr)
		return FALSE;
	QRF(x.g_bin_a(d.pentryids));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_createfolder &d)
{	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hparent_folder));
	QRF(x.g_uint32(&d.folder_type));
	QRF(x.g_str(&d.folder_name));
	QRF(x.g_str(&d.folder_comment));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_createfolder &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_deletefolder &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hparent_folder));
	QRF(x.g_bin(&d.entryid));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_emptyfolder &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_copyfolder &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hsrc_folder));
	QRF(x.g_bin(&d.entryid));
	QRF(x.g_uint32(&d.hdst_folder));
	QRF(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.new_name = nullptr;
	else
		QRF(x.g_str(&d.new_name));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getstoreentryid &d)
{
	QRF(x.g_str(&d.mailbox_dn));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getstoreentryid &d)
{
	QRF(x.p_bin(d.entryid));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_entryidfromsourcekey &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hstore));
	QRF(x.g_bin(&d.folder_key));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pmessage_key = nullptr;
	} else {
		d.pmessage_key = x.anew<BINARY>();
		if (d.pmessage_key == nullptr)
			return FALSE;
		QRF(x.g_bin(d.pmessage_key));
	}
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_entryidfromsourcekey &d)
{
	QRF(x.p_bin(d.entryid));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_storeadvise &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hstore));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pentryid = nullptr;
	} else {
		d.pentryid = x.anew<BINARY>();
		if (d.pentryid == nullptr)
			return FALSE;
		QRF(x.g_bin(d.pentryid));
	}
	QRF(x.g_uint32(&d.event_mask));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_storeadvise &d)
{
	QRF(x.p_uint32(d.sub_id));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_unadvise &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hstore));
	QRF(x.g_uint32(&d.sub_id));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_notifdequeue &d)
{
	int i;
	
	d.psink = x.anew<NOTIF_SINK>();
	if (d.psink == nullptr)
		return FALSE;
	QRF(x.g_guid(&d.psink->hsession));
	QRF(x.g_uint16(&d.psink->count));
	d.psink->padvise = x.anew<ADVISE_INFO>(d.psink->count);
	if (d.psink->padvise == nullptr) {
		d.psink->count = 0;
		return FALSE;
	}
	for (i=0; i<d.psink->count; i++) {
		QRF(x.g_uint32(&d.psink->padvise[i].hstore));
		QRF(x.g_uint32(&d.psink->padvise[i].sub_id));
	}
	QRF(x.g_uint32(&d.timeval));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_notifdequeue &d)
{
	return rpc_ext_push_znotification_array(&x, &d.notifications);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_queryrows &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	QRF(x.g_uint32(&d.start));
	QRF(x.g_uint32(&d.count));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = x.anew<RESTRICTION>();
		if (d.prestriction == nullptr)
			return FALSE;
		QRF(x.g_restriction(d.prestriction));
	}
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pproptags = nullptr;
	} else {
		d.pproptags = x.anew<PROPTAG_ARRAY>();
		if (d.pproptags == nullptr)
			return FALSE;
		QRF(x.g_proptag_a(d.pproptags));
	}
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_queryrows &d)
{
	return rpc_ext_push_tarray_set(&x, &d.rowset);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_setcolumns &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	d.pproptags = x.anew<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return FALSE;
	QRF(x.g_proptag_a(d.pproptags));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_seekrow &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	QRF(x.g_uint32(&d.bookmark));
	QRF(x.g_int32(&d.seek_rows));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_seekrow &d)
{
	QRF(x.p_int32(d.sought_rows));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_sorttable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	d.psortset = x.anew<SORTORDER_SET>();
	if (d.psortset == nullptr)
		return FALSE;
	QRF(x.g_sortorder_set(d.psortset));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getrowcount &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getrowcount &d)
{
	QRF(x.p_uint32(d.count));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_restricttable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	d.prestriction = x.anew<RESTRICTION>();
	if (d.prestriction == nullptr)
		return FALSE;
	QRF(x.g_restriction(d.prestriction));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_findrow &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	QRF(x.g_uint32(&d.bookmark));
	d.prestriction = x.anew<RESTRICTION>();
	if (d.prestriction == nullptr)
		return FALSE;
	QRF(x.g_restriction(d.prestriction));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_findrow &d)
{
	QRF(x.p_uint32(d.row_idx));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_createbookmark &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_createbookmark &d)
{
	QRF(x.p_uint32(d.bookmark));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_freebookmark &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.htable));
	QRF(x.g_uint32(&d.bookmark));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getreceivefolder &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hstore));
	QRF(x.g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		d.pstrclass = nullptr;
	else
		QRF(x.g_str(&d.pstrclass));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getreceivefolder &d)
{
	QRF(x.p_bin(d.entryid));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_modifyrecipients &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	QRF(x.g_uint32(&d.flags));
	d.prcpt_list = x.anew<TARRAY_SET>();
	if (d.prcpt_list == nullptr)
		return FALSE;
	QRF(x.g_tarray_set(d.prcpt_list));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_submitmessage &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_loadattachmenttable &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_loadattachmenttable &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openattachment &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	QRF(x.g_uint32(&d.attach_id));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openattachment &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_createattachment &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_createattachment &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_deleteattachment &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	QRF(x.g_uint32(&d.attach_id));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_setpropvals &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	d.ppropvals = x.anew<TPROPVAL_ARRAY>();
	if (d.ppropvals == nullptr)
		return FALSE;
	QRF(x.g_tpropval_a(d.ppropvals));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getpropvals &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.pproptags = nullptr;
	} else {
		d.pproptags = x.anew<PROPTAG_ARRAY>();
		if (d.pproptags == nullptr)
			return FALSE;
		QRF(x.g_proptag_a(d.pproptags));
	}
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getpropvals &d)
{
	QRF(x.p_tpropval_a(d.propvals));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_deletepropvals &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	d.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (d.pproptags == nullptr)
		return FALSE;
	QRF(x.g_proptag_a(d.pproptags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_setmessagereadflag &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_openembedded &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hattachment));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_openembedded &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getnamedpropids &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hstore));
	d.ppropnames = x.anew<PROPNAME_ARRAY>();
	if (d.ppropnames == nullptr)
		return FALSE;
	QRF(x.g_propname_a(d.ppropnames));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getnamedpropids &d)
{
	QRF(x.p_propid_a(d.propids));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getpropnames &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hstore));
	d.ppropids = x.anew<PROPID_ARRAY>();
	if (d.ppropids == nullptr)
		return FALSE;
	QRF(x.g_propid_a(d.ppropids));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getpropnames &d)
{
	QRF(x.p_propname_a(d.propnames));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_copyto &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hsrcobject));
	d.pexclude_proptags = x.anew<PROPTAG_ARRAY>();
	if (d.pexclude_proptags == nullptr)
		return FALSE;
	QRF(x.g_proptag_a(d.pexclude_proptags));
	QRF(x.g_uint32(&d.hdstobject));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_savechanges &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_hierarchysync &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_hierarchysync &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_contentsync &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_contentsync &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_configsync &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	QRF(x.g_uint32(&d.flags));
	d.pstate = x.anew<BINARY>();
	if (d.pstate == nullptr)
		return FALSE;
	QRF(x.g_bin(d.pstate));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = x.anew<RESTRICTION>();
		if (d.prestriction == nullptr)
			return FALSE;
		QRF(x.g_restriction(d.prestriction));
	}
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_configsync &d)
{
	QRF(x.p_uint8(d.b_changed));
	QRF(x.p_uint32(d.count));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_statesync &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_statesync &d)
{
	QRF(x.p_bin(d.state));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_syncmessagechange &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_syncmessagechange &d)
{
	QRF(x.p_uint8(d.b_new));
	QRF(x.p_tpropval_a(d.proplist));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_syncfolderchange &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_syncfolderchange &d)
{
	QRF(x.p_tpropval_a(d.proplist));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_syncreadstatechanges &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_syncreadstatechanges &d)
{
	return rpc_ext_push_state_array(&x, &d.states);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_syncdeletions &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	QRF(x.g_uint32(&d.flags));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_syncdeletions &d)
{
	QRF(x.p_bin_a(d.bins));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_hierarchyimport &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_hierarchyimport &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_contentimport &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_contentimport &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_configimport &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	QRF(x.g_uint8(&d.sync_type));
	d.pstate = x.anew<BINARY>();
	if (d.pstate == nullptr)
		return FALSE;
	QRF(x.g_bin(d.pstate));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_stateimport &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_stateimport &d)
{
	QRF(x.p_bin(d.state));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_importmessage &d)
{
	QRF(x.g_guid(&d.hsession));
	if (x.g_uint32(&d.hctx) != EXT_ERR_SUCCESS)
		return FALSE;
	if (x.g_uint32(&d.flags) != EXT_ERR_SUCCESS)
		return FALSE;
	d.pproplist = x.anew<TPROPVAL_ARRAY>();
	if (d.pproplist == nullptr)
		return FALSE;
	QRF(x.g_tpropval_a(d.pproplist));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_importmessage &d)
{
	QRF(x.p_uint32(d.hobject));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_importfolder &d)
{
	QRF(x.g_guid(&d.hsession));
	if (x.g_uint32(&d.hctx) != EXT_ERR_SUCCESS)
		return FALSE;
	d.pproplist = x.anew<TPROPVAL_ARRAY>();
	if (d.pproplist == nullptr)
		return FALSE;
	QRF(x.g_tpropval_a(d.pproplist));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_importdeletion &d)
{
	QRF(x.g_guid(&d.hsession));
	if (x.g_uint32(&d.hctx) != EXT_ERR_SUCCESS)
		return FALSE;
	if (x.g_uint32(&d.flags) != EXT_ERR_SUCCESS)
		return FALSE;
	d.pbins = x.anew<BINARY_ARRAY>();
	if (d.pbins == nullptr)
		return FALSE;
	QRF(x.g_bin_a(d.pbins));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_importreadstates &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hctx));
	d.pstates = x.anew<STATE_ARRAY>();
	if (d.pstates == nullptr)
		return FALSE;
	return rpc_ext_pull_state_array(&x, d.pstates);
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getsearchcriteria &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getsearchcriteria &d)
{	
	QRF(x.p_bin_a(d.folder_array));
	if (d.prestriction == nullptr) {
		QRF(x.p_uint8(0));
	} else {
		QRF(x.p_uint8(1));
		QRF(x.p_restriction(*d.prestriction));
	}
	QRF(x.p_uint32(d.search_stat));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_setsearchcriteria &d)
{
	uint8_t tmp_byte;
	
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hfolder));
	QRF(x.g_uint32(&d.flags));
	d.pfolder_array = x.anew<BINARY_ARRAY>();
	if (d.pfolder_array == nullptr)
		return FALSE;
	QRF(x.g_bin_a(d.pfolder_array));
	QRF(x.g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		d.prestriction = nullptr;
	} else {
		d.prestriction = x.anew<RESTRICTION>();
		if (d.prestriction == nullptr)
			return FALSE;
		QRF(x.g_restriction(d.prestriction));
	}
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_messagetorfc822 &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_messagetorfc822 &d)
{
	QRF(x.p_bin(d.eml_bin));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_rfc822tomessage &d)
{
	QRF(x.g_guid(&d.hsession));
	if (x.g_uint32(&d.hmessage) != EXT_ERR_SUCCESS ||
	    x.g_uint32(&d.mxf_flags) != EXT_ERR_SUCCESS)
		return FALSE;
	d.peml_bin = x.anew<BINARY>();
	if (d.peml_bin == nullptr)
		return FALSE;
	QRF(x.g_bin(d.peml_bin));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_messagetoical &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_messagetoical &d)
{
	QRF(x.p_bin(d.ical_bin));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_icaltomessage &d)
{
	QRF(x.g_guid(&d.hsession));
	if (x.g_uint32(&d.hmessage) != EXT_ERR_SUCCESS)
		return FALSE;
	d.pical_bin = x.anew<BINARY>();
	if (d.pical_bin == nullptr)
		return FALSE;
	QRF(x.g_bin(d.pical_bin));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_messagetovcf &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_uint32(&d.hmessage));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_messagetovcf &d)
{
	QRF(x.p_bin(d.vcf_bin));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_vcftomessage &d)
{
	QRF(x.g_guid(&d.hsession));
	if (x.g_uint32(&d.hmessage) != EXT_ERR_SUCCESS)
		return FALSE;
	d.pvcf_bin = x.anew<BINARY>();
	if (d.pvcf_bin == nullptr)
		return FALSE;
	QRF(x.g_bin(d.pvcf_bin));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_getuseravailability &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_bin(&d.entryid));
	QRF(x.g_uint64(&d.starttime));
	QRF(x.g_uint64(&d.endtime));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_getuseravailability &d)
{
	if (d.result_string == nullptr) {
		QRF(x.p_uint8(0));
		return TRUE;
	}
	QRF(x.p_uint8(1));
	QRF(x.p_str(d.result_string));
	return TRUE;
}

static BOOL zrpc_push(EXT_PUSH &x, const zcresp_imtomessage2 &d)
{
	QRF(x.p_uint32_a(d.msg_handles));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_setpasswd &d)
{
	QRF(x.g_str(&d.username));
	QRF(x.g_str(&d.passwd));
	QRF(x.g_str(&d.new_passwd));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_linkmessage &d)
{
	QRF(x.g_guid(&d.hsession));
	QRF(x.g_bin(&d.search_entryid));
	QRF(x.g_bin(&d.message_entryid));
	return TRUE;
}

static BOOL zrpc_pull(EXT_PULL &x, zcreq_imtomessage2 &d)
{
	QRF(x.g_guid(&d.session));
	QRF(x.g_uint32(&d.folder));
	QRF(x.g_uint32(&d.data_type));
	QRF(x.g_str(&d.im_data));
	return TRUE;
}

BOOL rpc_ext_pull_request(const BINARY *pbin_in, zcreq *&prequest)
{
	EXT_PULL ext_pull;
	uint8_t call_id;
	BOOL b_ret = false;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE);
	QRF(ext_pull.g_uint8(&call_id));
	switch (static_cast<zcore_callid>(call_id)) {
#define E(t) case zcore_callid::t: { \
		auto r = cu_alloc<zcreq_ ## t>(); \
		prequest = r; \
		if (r == nullptr) \
			return false; \
		b_ret = zrpc_pull(ext_pull, *r); \
		break; \
	}
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
#undef E
	default:
		return FALSE;
	}
	prequest->call_id = static_cast<zcore_callid>(call_id);
	return b_ret;
}

BOOL rpc_ext_push_response(const zcresp *presponse, BINARY *pbin_out)
{
	BOOL b_result;
	EXT_PUSH ext_push;

	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE))
		return FALSE;
	QRF(ext_push.p_uint8(static_cast<uint8_t>(zcore_response::success)));
	if (presponse->result != ecSuccess) {
		if (ext_push.p_uint32(4) != EXT_ERR_SUCCESS ||
		    ext_push.p_uint32(presponse->result) != EXT_ERR_SUCCESS)
			return FALSE;
		pbin_out->cb = ext_push.m_offset;
		pbin_out->pb = ext_push.release();
		return TRUE;
	}
	if (ext_push.advance(sizeof(uint32_t)) != EXT_ERR_SUCCESS ||
	    ext_push.p_uint32(presponse->result) != EXT_ERR_SUCCESS)
		return FALSE;
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
		b_result = TRUE;
		break;
#define E(t) case zcore_callid::t: b_result = zrpc_push(ext_push, *static_cast<const zcresp_ ## t *>(presponse)); break;
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
	E(seekrow)
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
#undef E
	default:
		return FALSE;
	}
	if (!b_result)
		return FALSE;
	pbin_out->cb = ext_push.m_offset;
	ext_push.m_offset = 1;
	if (ext_push.p_uint32(pbin_out->cb - sizeof(uint32_t) - 1) != EXT_ERR_SUCCESS)
		return false;
	pbin_out->pb = ext_push.release();
	return TRUE;
}
