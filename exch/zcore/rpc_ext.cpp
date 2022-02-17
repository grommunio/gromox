// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/mapidefs.h>
#include <gromox/zcore_rpc.hpp>
#include "rpc_ext.h"
#include <gromox/ext_buffer.hpp>
#include "common_util.h"
#define QRF(expr) do { if ((expr) != EXT_ERR_SUCCESS) return false; } while (false)

using RPC_REQUEST = ZCORE_RPC_REQUEST;
using RPC_RESPONSE = ZCORE_RPC_RESPONSE;
using REQUEST_PAYLOAD = ZCORE_REQUEST_PAYLOAD;
using RESPONSE_PAYLOAD = ZCORE_RESPONSE_PAYLOAD;

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

static BOOL rpc_ext_pull_logon_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_str(&ppayload->logon.username));
	QRF(pext->g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		ppayload->logon.password = NULL;
	else
		QRF(pext->g_str(&ppayload->logon.password));
	QRF(pext->g_uint32(&ppayload->logon.flags));
	return TRUE;
}

static BOOL rpc_ext_push_logon_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_guid(ppayload->logon.hsession));
	return TRUE;
}

static BOOL rpc_ext_pull_checksession_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->unloadobject.hsession));
	return TRUE;
}

static BOOL rpc_ext_pull_uinfo_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_str(&ppayload->uinfo.username));
	return TRUE;
}

static BOOL rpc_ext_push_uinfo_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->uinfo.entryid));
	QRF(pext->p_str(ppayload->uinfo.pdisplay_name));
	QRF(pext->p_str(ppayload->uinfo.px500dn));
	QRF(pext->p_uint32(ppayload->uinfo.privilege_bits));
	return TRUE;
}

static BOOL rpc_ext_pull_unloadobject_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->unloadobject.hsession));
	QRF(pext->g_uint32(&ppayload->unloadobject.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->openentry.hsession));
	QRF(pext->g_bin(&ppayload->openentry.entryid));
	QRF(pext->g_uint32(&ppayload->openentry.flags));
	return TRUE;
}

static BOOL rpc_ext_push_openentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint8(ppayload->openentry.mapi_type));
	QRF(pext->p_uint32(ppayload->openentry.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openstoreentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->openstoreentry.hsession));
	QRF(pext->g_uint32(&ppayload->openstoreentry.hobject));
	QRF(pext->g_bin(&ppayload->openstoreentry.entryid));
	QRF(pext->g_uint32(&ppayload->openstoreentry.flags));
	return TRUE;
}

static BOOL rpc_ext_push_openstoreentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint8(ppayload->openstoreentry.mapi_type));
	QRF(pext->p_uint32(ppayload->openstoreentry.hxobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openabentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->openabentry.hsession));
	QRF(pext->g_bin(&ppayload->openabentry.entryid));
	return TRUE;
}

static BOOL rpc_ext_push_openabentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint8(ppayload->openabentry.mapi_type));
	QRF(pext->p_uint32(ppayload->openabentry.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_resolvename_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->resolvename.hsession));
	ppayload->resolvename.pcond_set = pext->anew<TARRAY_SET>();
	if (ppayload->resolvename.pcond_set == nullptr)
		return FALSE;
	QRF(pext->g_tarray_set(ppayload->resolvename.pcond_set));
	return TRUE;
}

static BOOL rpc_ext_push_resolvename_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_tarray_set(ppayload->resolvename.result_set));
	return TRUE;
}

static BOOL rpc_ext_pull_getpermissions_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getpermissions.hsession));
	QRF(pext->g_uint32(&ppayload->getpermissions.hobject));
	return TRUE;
}

static BOOL rpc_ext_push_getpermissions_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return rpc_ext_push_permission_set(pext,
		&ppayload->getpermissions.perm_set);
}

static BOOL rpc_ext_pull_modifypermissions_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->modifypermissions.hsession));
	QRF(pext->g_uint32(&ppayload->modifypermissions.hfolder));
	ppayload->modifypermissions.pset = pext->anew<PERMISSION_SET>();
	if (ppayload->modifypermissions.pset == nullptr)
		return FALSE;
	return rpc_ext_pull_permission_set(pext,
			ppayload->modifypermissions.pset);
}

static BOOL rpc_ext_pull_modifyrules_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->modifyrules.hsession));
	QRF(pext->g_uint32(&ppayload->modifyrules.hfolder));
	QRF(pext->g_uint32(&ppayload->modifyrules.flags));
	ppayload->modifyrules.plist = pext->anew<RULE_LIST>();
	if (ppayload->modifyrules.plist == nullptr)
		return FALSE;
	return rpc_ext_pull_rule_list(pext,
			ppayload->modifyrules.plist);
}

static BOOL rpc_ext_pull_getabgal_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getabgal.hsession));
	return TRUE;
}

static BOOL rpc_ext_push_getabgal_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->getabgal.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_loadstoretable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{	
	QRF(pext->g_guid(&ppayload->loadstoretable.hsession));
	return TRUE;
}

static BOOL rpc_ext_push_loadstoretable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->loadstoretable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openstore_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->openstore.hsession));
	QRF(pext->g_bin(&ppayload->openstore.entryid));
	return TRUE;
}

static BOOL rpc_ext_push_openstore_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->openstore.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openprofilesec_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->openprofilesec.hsession));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->openprofilesec.puid = nullptr;
	} else {
		ppayload->openprofilesec.puid = pext->anew<FLATUID>();
		if (ppayload->openprofilesec.puid == nullptr)
			return FALSE;
		QRF(pext->g_bytes(deconst(ppayload->openprofilesec.puid), sizeof(FLATUID)));
	}
	return TRUE;
}

static BOOL rpc_ext_push_openprofilesec_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->openprofilesec.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadhierarchytable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->loadhierarchytable.hsession));
	QRF(pext->g_uint32(&ppayload->loadhierarchytable.hfolder));
	QRF(pext->g_uint32(&ppayload->loadhierarchytable.flags));
	return TRUE;
}

static BOOL rpc_ext_push_loadhierarchytable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->loadhierarchytable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadcontenttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->loadcontenttable.hsession));
	QRF(pext->g_uint32(&ppayload->loadcontenttable.hfolder));
	QRF(pext->g_uint32(&ppayload->loadcontenttable.flags));
	return TRUE;
}

static BOOL rpc_ext_push_loadcontenttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->loadcontenttable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadrecipienttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->loadrecipienttable.hsession));
	QRF(pext->g_uint32(&ppayload->loadrecipienttable.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_loadrecipienttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->loadrecipienttable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadruletable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->loadruletable.hsession));
	QRF(pext->g_uint32(&ppayload->loadruletable.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_loadruletable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->loadruletable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_createmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->createmessage.hsession));
	QRF(pext->g_uint32(&ppayload->createmessage.hfolder));
	QRF(pext->g_uint32(&ppayload->createmessage.flags));
	return TRUE;
}

static BOOL rpc_ext_push_createmessage_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->createmessage.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_deletemessages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->deletemessages.hsession));
	QRF(pext->g_uint32(&ppayload->deletemessages.hfolder));
	ppayload->deletemessages.pentryids = pext->anew<BINARY_ARRAY>();
	if (ppayload->deletemessages.pentryids == nullptr)
		return FALSE;
	QRF(pext->g_bin_a(ppayload->deletemessages.pentryids));
	QRF(pext->g_uint32(&ppayload->deletemessages.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_copymessages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->copymessages.hsession));
	QRF(pext->g_uint32(&ppayload->copymessages.hsrcfolder));
	QRF(pext->g_uint32(&ppayload->copymessages.hdstfolder));
	ppayload->copymessages.pentryids = pext->anew<BINARY_ARRAY>();
	if (ppayload->copymessages.pentryids == nullptr)
		return FALSE;
	QRF(pext->g_bin_a(ppayload->copymessages.pentryids));
	QRF(pext->g_uint32(&ppayload->copymessages.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_setreadflags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->setreadflags.hsession));
	QRF(pext->g_uint32(&ppayload->setreadflags.hfolder));
	ppayload->setreadflags.pentryids = pext->anew<BINARY_ARRAY>();
	if (ppayload->setreadflags.pentryids == nullptr)
		return FALSE;
	QRF(pext->g_bin_a(ppayload->setreadflags.pentryids));
	QRF(pext->g_uint32(&ppayload->setreadflags.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_createfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{	
	QRF(pext->g_guid(&ppayload->createfolder.hsession));
	QRF(pext->g_uint32(&ppayload->createfolder.hparent_folder));
	QRF(pext->g_uint32(&ppayload->createfolder.folder_type));
	QRF(pext->g_str(&ppayload->createfolder.folder_name));
	QRF(pext->g_str(&ppayload->createfolder.folder_comment));
	QRF(pext->g_uint32(&ppayload->createfolder.flags));
	return TRUE;
}

static BOOL rpc_ext_push_createfolder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->createfolder.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_deletefolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->deletefolder.hsession));
	QRF(pext->g_uint32(&ppayload->deletefolder.hparent_folder));
	QRF(pext->g_bin(&ppayload->deletefolder.entryid));
	QRF(pext->g_uint32(&ppayload->deletefolder.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_emptyfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->emptyfolder.hsession));
	QRF(pext->g_uint32(&ppayload->emptyfolder.hfolder));
	QRF(pext->g_uint32(&ppayload->emptyfolder.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_copyfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->copyfolder.hsession));
	QRF(pext->g_uint32(&ppayload->copyfolder.hsrc_folder));
	QRF(pext->g_bin(&ppayload->copyfolder.entryid));
	QRF(pext->g_uint32(&ppayload->copyfolder.hdst_folder));
	QRF(pext->g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		ppayload->copyfolder.new_name = NULL;
	else
		QRF(pext->g_str(&ppayload->copyfolder.new_name));
	QRF(pext->g_uint32(&ppayload->copyfolder.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_getstoreentryid_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_str(&ppayload->getstoreentryid.mailbox_dn));
	return TRUE;
}

static BOOL rpc_ext_push_getstoreentryid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->getstoreentryid.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_entryidfromsourcekey_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->entryidfromsourcekey.hsession));
	QRF(pext->g_uint32(&ppayload->entryidfromsourcekey.hstore));
	QRF(pext->g_bin(&ppayload->entryidfromsourcekey.folder_key));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->entryidfromsourcekey.pmessage_key = NULL;
	} else {
		ppayload->entryidfromsourcekey.pmessage_key = pext->anew<BINARY>();
		if (ppayload->entryidfromsourcekey.pmessage_key == nullptr)
			return FALSE;
		QRF(pext->g_bin(ppayload->entryidfromsourcekey.pmessage_key));
	}
	return TRUE;
}

static BOOL rpc_ext_push_entryidfromsourcekey_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->entryidfromsourcekey.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_storeadvise_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->storeadvise.hsession));
	QRF(pext->g_uint32(&ppayload->storeadvise.hstore));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->storeadvise.pentryid = NULL;
	} else {
		ppayload->storeadvise.pentryid = pext->anew<BINARY>();
		if (ppayload->storeadvise.pentryid == nullptr)
			return FALSE;
		QRF(pext->g_bin(ppayload->storeadvise.pentryid));
	}
	QRF(pext->g_uint32(&ppayload->storeadvise.event_mask));
	return TRUE;
}

static BOOL rpc_ext_push_storeadvise_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->storeadvise.sub_id));
	return TRUE;
}

static BOOL rpc_ext_pull_unadvise_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->unadvise.hsession));
	QRF(pext->g_uint32(&ppayload->unadvise.hstore));
	QRF(pext->g_uint32(&ppayload->unadvise.sub_id));
	return TRUE;
}

static BOOL rpc_ext_pull_notifdequeue_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	ppayload->notifdequeue.psink = pext->anew<NOTIF_SINK>();
	if (ppayload->notifdequeue.psink == nullptr)
		return FALSE;
	QRF(pext->g_guid(&ppayload->notifdequeue.psink->hsession));
	QRF(pext->g_uint16(&ppayload->notifdequeue.psink->count));
	ppayload->notifdequeue.psink->padvise = pext->anew<ADVISE_INFO>(ppayload->notifdequeue.psink->count);
	if (NULL == ppayload->notifdequeue.psink->padvise) {
		ppayload->notifdequeue.psink->count = 0;
		return FALSE;
	}
	for (i=0; i<ppayload->notifdequeue.psink->count; i++) {
		QRF(pext->g_uint32(&ppayload->notifdequeue.psink->padvise[i].hstore));
		QRF(pext->g_uint32(&ppayload->notifdequeue.psink->padvise[i].sub_id));
	}
	QRF(pext->g_uint32(&ppayload->notifdequeue.timeval));
	return TRUE;
}

static BOOL rpc_ext_push_notifdequeue_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return rpc_ext_push_znotification_array(
		pext, &ppayload->notifdequeue.notifications);
}

static BOOL rpc_ext_pull_queryrows_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->queryrows.hsession));
	QRF(pext->g_uint32(&ppayload->queryrows.htable));
	QRF(pext->g_uint32(&ppayload->queryrows.start));
	QRF(pext->g_uint32(&ppayload->queryrows.count));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->queryrows.prestriction = NULL;
	} else {
		ppayload->queryrows.prestriction = pext->anew<RESTRICTION>();
		if (ppayload->queryrows.prestriction == nullptr)
			return FALSE;
		QRF(pext->g_restriction(ppayload->queryrows.prestriction));
	}
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->queryrows.pproptags = NULL;
	} else {
		ppayload->queryrows.pproptags = pext->anew<PROPTAG_ARRAY>();
		if (ppayload->queryrows.pproptags == nullptr)
			return FALSE;
		QRF(pext->g_proptag_a(ppayload->queryrows.pproptags));
	}
	return TRUE;
}

static BOOL rpc_ext_push_queryrows_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return rpc_ext_push_tarray_set(pext,
			&ppayload->queryrows.rowset);
}

static BOOL rpc_ext_pull_setcolumns_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->setcolumns.hsession));
	QRF(pext->g_uint32(&ppayload->setcolumns.htable));
	ppayload->setcolumns.pproptags = pext->anew<PROPTAG_ARRAY>();
	if (ppayload->setcolumns.pproptags == nullptr)
		return FALSE;
	QRF(pext->g_proptag_a(ppayload->setcolumns.pproptags));
	QRF(pext->g_uint32(&ppayload->setcolumns.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_seekrow_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->seekrow.hsession));
	QRF(pext->g_uint32(&ppayload->seekrow.htable));
	QRF(pext->g_uint32(&ppayload->seekrow.bookmark));
	QRF(pext->g_int32(&ppayload->seekrow.seek_rows));
	return TRUE;
}

static BOOL rpc_ext_push_seekrow_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_int32(ppayload->seekrow.sought_rows));
	return TRUE;
}

static BOOL rpc_ext_pull_sorttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->sorttable.hsession));
	QRF(pext->g_uint32(&ppayload->sorttable.htable));
	ppayload->sorttable.psortset = pext->anew<SORTORDER_SET>();
	if (ppayload->sorttable.psortset == nullptr)
		return FALSE;
	QRF(pext->g_sortorder_set(ppayload->sorttable.psortset));
	return TRUE;
}

static BOOL rpc_ext_pull_getrowcount_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getrowcount.hsession));
	QRF(pext->g_uint32(&ppayload->getrowcount.htable));
	return TRUE;
}

static BOOL rpc_ext_push_getrowcount_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->getrowcount.count));
	return TRUE;
}

static BOOL rpc_ext_pull_restricttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->restricttable.hsession));
	QRF(pext->g_uint32(&ppayload->restricttable.htable));
	ppayload->restricttable.prestriction = pext->anew<RESTRICTION>();
	if (ppayload->restricttable.prestriction == nullptr)
		return FALSE;
	QRF(pext->g_restriction(ppayload->restricttable.prestriction));
	QRF(pext->g_uint32(&ppayload->restricttable.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_findrow_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->findrow.hsession));
	QRF(pext->g_uint32(&ppayload->findrow.htable));
	QRF(pext->g_uint32(&ppayload->findrow.bookmark));
	ppayload->findrow.prestriction = pext->anew<RESTRICTION>();
	if (ppayload->findrow.prestriction == nullptr)
		return FALSE;
	QRF(pext->g_restriction(ppayload->findrow.prestriction));
	QRF(pext->g_uint32(&ppayload->findrow.flags));
	return TRUE;
}

static BOOL rpc_ext_push_findrow_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->findrow.row_idx));
	return TRUE;
}

static BOOL rpc_ext_pull_createbookmark_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->createbookmark.hsession));
	QRF(pext->g_uint32(&ppayload->createbookmark.htable));
	return TRUE;
}

static BOOL rpc_ext_push_createbookmark_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->createbookmark.bookmark));
	return TRUE;
}

static BOOL rpc_ext_pull_freebookmark_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->freebookmark.hsession));
	QRF(pext->g_uint32(&ppayload->freebookmark.htable));
	QRF(pext->g_uint32(&ppayload->freebookmark.bookmark));
	return TRUE;
}

static BOOL rpc_ext_pull_getreceivefolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->getreceivefolder.hsession));
	QRF(pext->g_uint32(&ppayload->getreceivefolder.hstore));
	QRF(pext->g_uint8(&tmp_byte));
	if (tmp_byte == 0)
		ppayload->getreceivefolder.pstrclass = NULL;
	else
		QRF(pext->g_str(&ppayload->getreceivefolder.pstrclass));
	return TRUE;
}

static BOOL rpc_ext_push_getreceivefolder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->getreceivefolder.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_modifyrecipients_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->modifyrecipients.hsession));
	QRF(pext->g_uint32(&ppayload->modifyrecipients.hmessage));
	QRF(pext->g_uint32(&ppayload->modifyrecipients.flags));
	ppayload->modifyrecipients.prcpt_list = pext->anew<TARRAY_SET>();
	if (ppayload->modifyrecipients.prcpt_list == nullptr)
		return FALSE;
	QRF(pext->g_tarray_set(ppayload->modifyrecipients.prcpt_list));
	return TRUE;
}

static BOOL rpc_ext_pull_submitmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->submitmessage.hsession));
	QRF(pext->g_uint32(&ppayload->submitmessage.hmessage));
	return TRUE;
}

static BOOL rpc_ext_pull_loadattachmenttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->loadattachmenttable.hsession));
	QRF(pext->g_uint32(&ppayload->loadattachmenttable.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_loadattachmenttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->loadattachmenttable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->openattachment.hsession));
	QRF(pext->g_uint32(&ppayload->openattachment.hmessage));
	QRF(pext->g_uint32(&ppayload->openattachment.attach_id));
	return TRUE;
}

static BOOL rpc_ext_push_openattachment_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->openattachment.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_createattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->createattachment.hsession));
	QRF(pext->g_uint32(&ppayload->createattachment.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_createattachment_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->createattachment.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_deleteattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->deleteattachment.hsession));
	QRF(pext->g_uint32(&ppayload->deleteattachment.hmessage));
	QRF(pext->g_uint32(&ppayload->deleteattachment.attach_id));
	return TRUE;
}

static BOOL rpc_ext_pull_setpropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->setpropvals.hsession));
	QRF(pext->g_uint32(&ppayload->setpropvals.hobject));
	ppayload->setpropvals.ppropvals = pext->anew<TPROPVAL_ARRAY>();
	if (ppayload->setpropvals.ppropvals == nullptr)
		return FALSE;
	QRF(pext->g_tpropval_a(ppayload->setpropvals.ppropvals));
	return TRUE;
}

static BOOL rpc_ext_pull_getpropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->getpropvals.hsession));
	QRF(pext->g_uint32(&ppayload->getpropvals.hobject));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->getpropvals.pproptags = NULL;
	} else {
		ppayload->getpropvals.pproptags = pext->anew<PROPTAG_ARRAY>();
		if (ppayload->getpropvals.pproptags == nullptr)
			return FALSE;
		QRF(pext->g_proptag_a(ppayload->getpropvals.pproptags));
	}
	return TRUE;
}

static BOOL rpc_ext_push_getpropvals_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_tpropval_a(ppayload->getpropvals.propvals));
	return TRUE;
}

static BOOL rpc_ext_pull_deletepropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->deletepropvals.hsession));
	QRF(pext->g_uint32(&ppayload->deletepropvals.hobject));
	ppayload->deletepropvals.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (ppayload->deletepropvals.pproptags == nullptr)
		return FALSE;
	QRF(pext->g_proptag_a(ppayload->deletepropvals.pproptags));
	return TRUE;
}

static BOOL rpc_ext_pull_setmessagereadflag_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->setmessagereadflag.hsession));
	QRF(pext->g_uint32(&ppayload->setmessagereadflag.hmessage));
	QRF(pext->g_uint32(&ppayload->setmessagereadflag.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_openembedded_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->openembedded.hsession));
	QRF(pext->g_uint32(&ppayload->openembedded.hattachment));
	QRF(pext->g_uint32(&ppayload->openembedded.flags));
	return TRUE;
}

static BOOL rpc_ext_push_openembedded_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->openembedded.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_getnamedpropids_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getnamedpropids.hsession));
	QRF(pext->g_uint32(&ppayload->getnamedpropids.hstore));
	ppayload->getnamedpropids.ppropnames = pext->anew<PROPNAME_ARRAY>();
	if (ppayload->getnamedpropids.ppropnames == nullptr)
		return FALSE;
	QRF(pext->g_propname_a(ppayload->getnamedpropids.ppropnames));
	return TRUE;
}

static BOOL rpc_ext_push_getnamedpropids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_propid_a(ppayload->getnamedpropids.propids));
	return TRUE;
}

static BOOL rpc_ext_pull_getpropnames_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getpropnames.hsession));
	QRF(pext->g_uint32(&ppayload->getpropnames.hstore));
	ppayload->getpropnames.ppropids = pext->anew<PROPID_ARRAY>();
	if (ppayload->getpropnames.ppropids == nullptr)
		return FALSE;
	QRF(pext->g_propid_a(ppayload->getpropnames.ppropids));
	return TRUE;
}

static BOOL rpc_ext_push_getpropnames_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_propname_a(ppayload->getpropnames.propnames));
	return TRUE;
}

static BOOL rpc_ext_pull_copyto_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->copyto.hsession));
	QRF(pext->g_uint32(&ppayload->copyto.hsrcobject));
	ppayload->copyto.pexclude_proptags = pext->anew<PROPTAG_ARRAY>();
	if (ppayload->copyto.pexclude_proptags == nullptr)
		return FALSE;
	QRF(pext->g_proptag_a(ppayload->copyto.pexclude_proptags));
	QRF(pext->g_uint32(&ppayload->copyto.hdstobject));
	QRF(pext->g_uint32(&ppayload->copyto.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_savechanges_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->savechanges.hsession));
	QRF(pext->g_uint32(&ppayload->savechanges.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_hierarchysync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->hierarchysync.hsession));
	QRF(pext->g_uint32(&ppayload->hierarchysync.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_hierarchysync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->hierarchysync.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_contentsync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->contentsync.hsession));
	QRF(pext->g_uint32(&ppayload->contentsync.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_contentsync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->contentsync.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_configsync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->configsync.hsession));
	QRF(pext->g_uint32(&ppayload->configsync.hctx));
	QRF(pext->g_uint32(&ppayload->configsync.flags));
	ppayload->configsync.pstate = pext->anew<BINARY>();
	if (ppayload->configsync.pstate == nullptr)
		return FALSE;
	QRF(pext->g_bin(ppayload->configsync.pstate));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->configsync.prestriction = NULL;
	} else {
		ppayload->configsync.prestriction = pext->anew<RESTRICTION>();
		if (ppayload->configsync.prestriction == nullptr)
			return FALSE;
		QRF(pext->g_restriction(ppayload->configsync.prestriction));
	}
	return TRUE;
}

static BOOL rpc_ext_push_configsync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint8(ppayload->configsync.b_changed));
	QRF(pext->p_uint32(ppayload->configsync.count));
	return TRUE;
}

static BOOL rpc_ext_pull_statesync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->statesync.hsession));
	QRF(pext->g_uint32(&ppayload->configsync.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_statesync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->statesync.state));
	return TRUE;
}

static BOOL rpc_ext_pull_syncmessagechange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->syncmessagechange.hsession));
	QRF(pext->g_uint32(&ppayload->syncmessagechange.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_syncmessagechange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint8(ppayload->syncmessagechange.b_new));
	QRF(pext->p_tpropval_a(ppayload->syncmessagechange.proplist));
	return TRUE;
}

static BOOL rpc_ext_pull_syncfolderchange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->syncfolderchange.hsession));
	QRF(pext->g_uint32(&ppayload->syncfolderchange.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_syncfolderchange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_tpropval_a(ppayload->syncfolderchange.proplist));
	return TRUE;
}

static BOOL rpc_ext_pull_syncreadstatechanges_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->syncreadstatechanges.hsession));
	QRF(pext->g_uint32(&ppayload->syncreadstatechanges.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_syncreadstatechanges_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return rpc_ext_push_state_array(pext,
		&ppayload->syncreadstatechanges.states);
}

static BOOL rpc_ext_pull_syncdeletions_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->syncdeletions.hsession));
	QRF(pext->g_uint32(&ppayload->syncdeletions.hctx));
	QRF(pext->g_uint32(&ppayload->syncdeletions.flags));
	return TRUE;
}

static BOOL rpc_ext_push_syncdeletions_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin_a(ppayload->syncdeletions.bins));
	return TRUE;
}

static BOOL rpc_ext_pull_hierarchyimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->hierarchyimport.hsession));
	QRF(pext->g_uint32(&ppayload->hierarchyimport.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_hierarchyimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->hierarchyimport.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_contentimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->contentimport.hsession));
	QRF(pext->g_uint32(&ppayload->contentimport.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_contentimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->contentimport.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_configimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->configimport.hsession));
	QRF(pext->g_uint32(&ppayload->configimport.hctx));
	QRF(pext->g_uint8(&ppayload->configimport.sync_type));
	ppayload->configimport.pstate = pext->anew<BINARY>();
	if (ppayload->configimport.pstate == nullptr)
		return FALSE;
	QRF(pext->g_bin(ppayload->configimport.pstate));
	return TRUE;
}

static BOOL rpc_ext_pull_stateimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->stateimport.hsession));
	QRF(pext->g_uint32(&ppayload->stateimport.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_stateimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->stateimport.state));
	return TRUE;
}

static BOOL rpc_ext_pull_importmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->importmessage.hsession));
	if (pext->g_uint32(&ppayload->importmessage.hctx) != EXT_ERR_SUCCESS)
		return FALSE;
	if (pext->g_uint32(&ppayload->importmessage.flags) != EXT_ERR_SUCCESS)
		return FALSE;
	ppayload->importmessage.pproplist = pext->anew<TPROPVAL_ARRAY>();
	if (ppayload->importmessage.pproplist == nullptr)
		return FALSE;
	QRF(pext->g_tpropval_a(ppayload->importmessage.pproplist));
	return TRUE;
}

static BOOL rpc_ext_push_importmessage_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->importmessage.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_importfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->importfolder.hsession));
	if (pext->g_uint32(&ppayload->importfolder.hctx) != EXT_ERR_SUCCESS)
		return FALSE;
	ppayload->importfolder.pproplist = pext->anew<TPROPVAL_ARRAY>();
	if (ppayload->importfolder.pproplist == nullptr)
		return FALSE;
	QRF(pext->g_tpropval_a(ppayload->importfolder.pproplist));
	return TRUE;
}

static BOOL rpc_ext_pull_importdeletion_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->importdeletion.hsession));
	if (pext->g_uint32(&ppayload->importdeletion.hctx) != EXT_ERR_SUCCESS)
		return FALSE;
	if (pext->g_uint32(&ppayload->importdeletion.flags) != EXT_ERR_SUCCESS)
		return FALSE;
	ppayload->importdeletion.pbins = pext->anew<BINARY_ARRAY>();
	if (ppayload->importdeletion.pbins == nullptr)
		return FALSE;
	QRF(pext->g_bin_a(ppayload->importdeletion.pbins));
	return TRUE;
}

static BOOL rpc_ext_pull_importreadstates_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->importreadstates.hsession));
	QRF(pext->g_uint32(&ppayload->importreadstates.hctx));
	ppayload->importreadstates.pstates = pext->anew<STATE_ARRAY>();
	if (ppayload->importreadstates.pstates == nullptr)
		return FALSE;
	return rpc_ext_pull_state_array(pext,
		ppayload->importreadstates.pstates);
}

static BOOL rpc_ext_pull_getsearchcriteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getsearchcriteria.hsession));
	QRF(pext->g_uint32(&ppayload->getsearchcriteria.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_getsearchcriteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{	
	QRF(pext->p_bin_a(ppayload->getsearchcriteria.folder_array));
	if (NULL == ppayload->getsearchcriteria.prestriction) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_restriction(*ppayload->getsearchcriteria.prestriction));
	}
	QRF(pext->p_uint32(ppayload->getsearchcriteria.search_stat));
	return TRUE;
}

static BOOL rpc_ext_pull_setsearchcriteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->setsearchcriteria.hsession));
	QRF(pext->g_uint32(&ppayload->setsearchcriteria.hfolder));
	QRF(pext->g_uint32(&ppayload->setsearchcriteria.flags));
	ppayload->setsearchcriteria.pfolder_array = pext->anew<BINARY_ARRAY>();
	if (ppayload->setsearchcriteria.pfolder_array == nullptr)
		return FALSE;
	QRF(pext->g_bin_a(ppayload->setsearchcriteria.pfolder_array));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->setsearchcriteria.prestriction = NULL;
	} else {
		ppayload->setsearchcriteria.prestriction = pext->anew<RESTRICTION>();
		if (ppayload->setsearchcriteria.prestriction == nullptr)
			return FALSE;
		QRF(pext->g_restriction(ppayload->setsearchcriteria.prestriction));
	}
	return TRUE;
}

static BOOL rpc_ext_pull_messagetorfc822_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->messagetorfc822.hsession));
	QRF(pext->g_uint32(&ppayload->messagetorfc822.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_messagetorfc822_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->messagetorfc822.eml_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_rfc822tomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->rfc822tomessage.hsession));
	if (pext->g_uint32(&ppayload->rfc822tomessage.hmessage) != EXT_ERR_SUCCESS)
		return FALSE;
	ppayload->rfc822tomessage.peml_bin = pext->anew<BINARY>();
	if (ppayload->rfc822tomessage.peml_bin == nullptr)
		return FALSE;
	QRF(pext->g_bin(ppayload->rfc822tomessage.peml_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_messagetoical_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->messagetoical.hsession));
	QRF(pext->g_uint32(&ppayload->messagetoical.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_messagetoical_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->messagetoical.ical_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_icaltomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->icaltomessage.hsession));
	if (pext->g_uint32(&ppayload->icaltomessage.hmessage) != EXT_ERR_SUCCESS)
		return FALSE;
	ppayload->icaltomessage.pical_bin = pext->anew<BINARY>();
	if (ppayload->icaltomessage.pical_bin == nullptr)
		return FALSE;
	QRF(pext->g_bin(ppayload->icaltomessage.pical_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_messagetovcf_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->messagetovcf.hsession));
	QRF(pext->g_uint32(&ppayload->messagetovcf.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_messagetovcf_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_bin(ppayload->messagetovcf.vcf_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_vcftomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->vcftomessage.hsession));
	if (pext->g_uint32(&ppayload->vcftomessage.hmessage) != EXT_ERR_SUCCESS)
		return FALSE;
	ppayload->vcftomessage.pvcf_bin = pext->anew<BINARY>();
	if (ppayload->vcftomessage.pvcf_bin == nullptr)
		return FALSE;
	QRF(pext->g_bin(ppayload->vcftomessage.pvcf_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_getuseravailability_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->getuseravailability.hsession));
	QRF(pext->g_bin(&ppayload->getuseravailability.entryid));
	QRF(pext->g_uint64(&ppayload->getuseravailability.starttime));
	QRF(pext->g_uint64(&ppayload->getuseravailability.endtime));
	return TRUE;
}

static BOOL rpc_ext_push_getuseravailability_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (NULL == ppayload->getuseravailability.result_string) {
		QRF(pext->p_uint8(0));
		return TRUE;
	}
	QRF(pext->p_uint8(1));
	QRF(pext->p_str(ppayload->getuseravailability.result_string));
	return TRUE;
}

static BOOL rpc_ext_pull_setpasswd_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_str(&ppayload->setpasswd.username));
	QRF(pext->g_str(&ppayload->setpasswd.passwd));
	QRF(pext->g_str(&ppayload->setpasswd.new_passwd));
	return TRUE;
}

static BOOL rpc_ext_pull_linkmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(pext->g_guid(&ppayload->linkmessage.hsession));
	QRF(pext->g_bin(&ppayload->linkmessage.search_entryid));
	QRF(pext->g_bin(&ppayload->linkmessage.message_entryid));
	return TRUE;
}

BOOL rpc_ext_pull_request(const BINARY *pbin_in,
	RPC_REQUEST *prequest)
{
	EXT_PULL ext_pull;
	uint8_t call_id;
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE);
	QRF(ext_pull.g_uint8(&call_id));
	prequest->call_id = static_cast<zcore_callid>(call_id);
	switch (prequest->call_id) {
#define E(t) case zcore_callid::t: return rpc_ext_pull_ ## t ## _request(&ext_pull, &prequest->payload);
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
#undef E
	default:
		return FALSE;
	}
}

BOOL rpc_ext_push_response(const RPC_RESPONSE *presponse,
	BINARY *pbin_out)
{
	BOOL b_result;
	EXT_PUSH ext_push;

	if (!ext_push.init(nullptr, 0, EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE))
		return FALSE;
	QRF(ext_push.p_uint8(static_cast<uint8_t>(zcore_response::success)));
	if (EXT_ERR_SUCCESS != presponse->result) {
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
#define E(t) case zcore_callid::t: b_result = rpc_ext_push_ ## t ## _response(&ext_push, &presponse->payload); break;
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
