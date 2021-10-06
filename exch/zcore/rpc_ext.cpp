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
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_SHORT:
		*ppval = pext->anew<uint16_t>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint16(static_cast<uint16_t *>(*ppval)));
		return TRUE;
	case PT_LONG:
	case PT_ERROR:
		*ppval = pext->anew<uint32_t>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint32(static_cast<uint32_t *>(*ppval)));
		return TRUE;
	case PT_FLOAT:
		*ppval = pext->anew<float>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_float(static_cast<float *>(*ppval)));
		return TRUE;
	case PT_DOUBLE:
	case PT_APPTIME:
		*ppval = pext->anew<double>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_double(static_cast<double *>(*ppval)));
		return TRUE;
	case PT_BOOLEAN:
		*ppval = pext->anew<uint8_t>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint8(static_cast<uint8_t *>(*ppval)));
		return TRUE;
	case PT_I8:
	case PT_SYSTIME:
		*ppval = pext->anew<uint64_t>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint64(static_cast<uint64_t *>(*ppval)));
		return TRUE;
	case PT_STRING8:
		QRF(pext->g_str(reinterpret_cast<char **>(ppval)));
		return TRUE;
	case PT_UNICODE:
		QRF(pext->g_wstr(reinterpret_cast<char **>(ppval)));
		return TRUE;
	case PT_CLSID:
		*ppval = pext->anew<GUID>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_guid(static_cast<GUID *>(*ppval)));
		return TRUE;
	case PT_SRESTRICTION:
		*ppval = pext->anew<RESTRICTION>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_restriction(static_cast<RESTRICTION *>(*ppval)));
		return TRUE;
	case PT_ACTIONS:
		*ppval = pext->anew<RULE_ACTIONS>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_rule_actions(static_cast<RULE_ACTIONS *>(*ppval)));
		return TRUE;
	case PT_BINARY:
		*ppval = pext->anew<BINARY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_bin(static_cast<BINARY *>(*ppval)));
		return TRUE;
	case PT_MV_SHORT:
		*ppval = pext->anew<SHORT_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint16_a(static_cast<SHORT_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_LONG:
		*ppval = pext->anew<LONG_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint32_a(static_cast<LONG_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_I8:
		*ppval = pext->anew<LONGLONG_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_uint64_a(static_cast<LONGLONG_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_STRING8:
		*ppval = pext->anew<STRING_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_str_a(static_cast<STRING_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_UNICODE:
		*ppval = pext->anew<STRING_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_wstr_a(static_cast<STRING_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_CLSID:
		*ppval = pext->anew<GUID_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_guid_a(static_cast<GUID_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_BINARY:
		*ppval = pext->anew<BINARY_ARRAY>();
		if (*ppval == nullptr)
			return FALSE;
		QRF(pext->g_bin_a(static_cast<BINARY_ARRAY *>(*ppval)));
		return TRUE;
	default:
		return FALSE;
	}
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
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_SHORT:
		QRF(pext->p_uint16(*static_cast<const uint16_t *>(pval)));
		return TRUE;
	case PT_LONG:
	case PT_ERROR:
		QRF(pext->p_uint32(*static_cast<const uint32_t *>(pval)));
		return TRUE;
	case PT_FLOAT:
		QRF(pext->p_float(*static_cast<const float *>(pval)));
		return TRUE;
	case PT_DOUBLE:
	case PT_APPTIME:
		QRF(pext->p_double(*static_cast<const double *>(pval)));
		return TRUE;
	case PT_BOOLEAN:
		QRF(pext->p_uint8(*static_cast<const uint8_t *>(pval)));
		return TRUE;
	case PT_I8:
	case PT_SYSTIME:
		QRF(pext->p_uint64(*static_cast<const uint64_t *>(pval)));
		return TRUE;
	case PT_STRING8:
		QRF(pext->p_str(static_cast<const char *>(pval)));
		return TRUE;
	case PT_UNICODE:
		QRF(pext->p_wstr(static_cast<const char *>(pval)));
		return TRUE;
	case PT_CLSID:
		QRF(pext->p_guid(static_cast<const GUID *>(pval)));
		return TRUE;
	case PT_SRESTRICTION:
		QRF(pext->p_restriction(static_cast<const RESTRICTION *>(pval)));
		return TRUE;
	case PT_ACTIONS:
		QRF(pext->p_rule_actions(static_cast<const RULE_ACTIONS *>(pval)));
		return TRUE;
	case PT_BINARY:
		QRF(pext->p_bin(static_cast<const BINARY *>(pval)));
		return TRUE;
	case PT_MV_SHORT:
		QRF(pext->p_uint16_a(static_cast<const SHORT_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_LONG:
		QRF(pext->p_uint32_a(static_cast<const LONG_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_I8:
		QRF(pext->p_uint64_a(static_cast<const LONGLONG_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_STRING8:
		QRF(pext->p_str_a(static_cast<const STRING_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_UNICODE:
		QRF(pext->p_wstr_a(static_cast<const STRING_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_CLSID:
		QRF(pext->p_guid_a(static_cast<const GUID_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_BINARY:
		QRF(pext->p_bin_a(static_cast<const BINARY_ARRAY *>(pval)));
		return TRUE;
	default:
		return FALSE;
	}
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
	QRF(pext->p_bin(&r->entryid));
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
	QRF(pext->p_bin(&r->source_key));
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
	QRF(pext->p_bin(&r->entryid));
	QRF(pext->p_bin(&r->parentid));
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
		QRF(pext->p_bin(r->pentryid));
	}
	if (NULL == r->pparentid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(r->pparentid));
	}
	if (NULL == r->pold_entryid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(r->pold_entryid));
	}
	if (NULL == r->pold_parentid) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_bin(r->pold_parentid));
	}
	if (NULL == r->pproptags) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_proptag_a(r->pproptags));
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
	QRF(pext->p_guid(&ppayload->logon.hsession));
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
	QRF(pext->p_bin(&ppayload->uinfo.entryid));
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
	QRF(pext->p_tarray_set(&ppayload->resolvename.result_set));
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
	QRF(pext->p_bin(&ppayload->getabgal.entryid));
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

static BOOL rpc_ext_pull_openpropfilesec_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(pext->g_guid(&ppayload->openpropfilesec.hsession));
	QRF(pext->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		ppayload->openpropfilesec.puid = NULL;
	} else {
		ppayload->openpropfilesec.puid = pext->anew<FLATUID>();
		if (ppayload->openpropfilesec.puid == nullptr)
			return FALSE;
		QRF(pext->g_bytes(deconst(ppayload->openpropfilesec.puid), sizeof(FLATUID)));
	}
	return TRUE;
}

static BOOL rpc_ext_push_openpropfilesec_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(pext->p_uint32(ppayload->openpropfilesec.hobject));
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
	QRF(pext->p_bin(&ppayload->getstoreentryid.entryid));
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
	QRF(pext->p_bin(&ppayload->entryidfromsourcekey.entryid));
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
	QRF(pext->p_bin(&ppayload->getreceivefolder.entryid));
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
	QRF(pext->p_tpropval_a(&ppayload->getpropvals.propvals));
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
	QRF(pext->p_propid_a(&ppayload->getnamedpropids.propids));
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
	QRF(pext->p_propname_a(&ppayload->getpropnames.propnames));
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
	QRF(pext->p_bin(&ppayload->statesync.state));
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
	QRF(pext->p_tpropval_a(&ppayload->syncmessagechange.proplist));
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
	QRF(pext->p_tpropval_a(&ppayload->syncfolderchange.proplist));
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
	QRF(pext->p_bin_a(&ppayload->syncdeletions.bins));
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
	QRF(pext->p_bin(&ppayload->stateimport.state));
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
	QRF(pext->p_bin_a(&ppayload->getsearchcriteria.folder_array));
	if (NULL == ppayload->getsearchcriteria.prestriction) {
		QRF(pext->p_uint8(0));
	} else {
		QRF(pext->p_uint8(1));
		QRF(pext->p_restriction(ppayload->getsearchcriteria.prestriction));
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
	QRF(pext->p_bin(&ppayload->messagetorfc822.eml_bin));
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
	QRF(pext->p_bin(&ppayload->messagetoical.ical_bin));
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
	QRF(pext->p_bin(&ppayload->messagetovcf.vcf_bin));
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
	
	ext_pull.init(pbin_in->pb, pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE);
	QRF(ext_pull.g_uint8(&prequest->call_id));
	switch (prequest->call_id) {
	case zcore_callid::LOGON:
		return rpc_ext_pull_logon_request(
			&ext_pull, &prequest->payload);
	case zcore_callid::CHECKSESSION:
		return rpc_ext_pull_checksession_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::UINFO:
		return rpc_ext_pull_uinfo_request(
			&ext_pull, &prequest->payload);
	case zcore_callid::UNLOADOBJECT:
		return rpc_ext_pull_unloadobject_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::OPENENTRY:
		return rpc_ext_pull_openentry_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::OPENSTOREENTRY:
		return rpc_ext_pull_openstoreentry_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::OPENABENTRY:
		return rpc_ext_pull_openabentry_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::RESOLVENAME:
		return rpc_ext_pull_resolvename_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::GETPERMISSIONS:
		return rpc_ext_pull_getpermissions_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::MODIFYPERMISSIONS:
		return rpc_ext_pull_modifypermissions_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::MODIFYRULES:
		return rpc_ext_pull_modifyrules_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::GETABGAL:
		return rpc_ext_pull_getabgal_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::LOADSTORETABLE:
		return rpc_ext_pull_loadstoretable_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::OPENSTORE:
		return rpc_ext_pull_openstore_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::OPENPROPFILESEC:
		return rpc_ext_pull_openpropfilesec_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::LOADHIERARCHYTABLE:
		return rpc_ext_pull_loadhierarchytable_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::LOADCONTENTTABLE:
		return rpc_ext_pull_loadcontenttable_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::LOADRECIPIENTTABLE:
		return rpc_ext_pull_loadrecipienttable_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::LOADRULETABLE:
		return rpc_ext_pull_loadruletable_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CREATEMESSAGE:
		return rpc_ext_pull_createmessage_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::DELETEMESSAGES:
		return rpc_ext_pull_deletemessages_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::COPYMESSAGES:
		return rpc_ext_pull_copymessages_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::SETREADFLAGS:
		return rpc_ext_pull_setreadflags_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CREATEFOLDER:
		return rpc_ext_pull_createfolder_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::DELETEFOLDER:
		return rpc_ext_pull_deletefolder_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::EMPTYFOLDER:
		return rpc_ext_pull_emptyfolder_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::COPYFOLDER:
		return rpc_ext_pull_copyfolder_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::GETSTOREENTRYID:
		return rpc_ext_pull_getstoreentryid_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::ENTRYIDFROMSOURCEKEY:
		return rpc_ext_pull_entryidfromsourcekey_request(
							&ext_pull, &prequest->payload);
	case zcore_callid::STOREADVISE:
		return rpc_ext_pull_storeadvise_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::UNADVISE:
		return rpc_ext_pull_unadvise_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::NOTIFDEQUEUE:
		return rpc_ext_pull_notifdequeue_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::QUERYROWS:
		return rpc_ext_pull_queryrows_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::SETCOLUMNS:
		return rpc_ext_pull_setcolumns_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::SEEKROW:
		return rpc_ext_pull_seekrow_request(
			&ext_pull, &prequest->payload);
	case zcore_callid::SORTTABLE:
		return rpc_ext_pull_sorttable_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::GETROWCOUNT:
		return rpc_ext_pull_getrowcount_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::RESTRICTTABLE:
		return rpc_ext_pull_restricttable_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::FINDROW:
		return rpc_ext_pull_findrow_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::CREATEBOOKMARK:
		return rpc_ext_pull_createbookmark_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::FREEBOOKMARK:
		return rpc_ext_pull_freebookmark_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::GETRECEIVEFOLDER:
		return rpc_ext_pull_getreceivefolder_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::MODIFYRECIPIENTS:
		return rpc_ext_pull_modifyrecipients_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::SUBMITMESSAGE:
		return rpc_ext_pull_submitmessage_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::LOADATTACHMENTTABLE:
		return rpc_ext_pull_loadattachmenttable_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::OPENATTACHMENT:
		return rpc_ext_pull_openattachment_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CREATEATTACHMENT:
		return rpc_ext_pull_createattachment_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::DELETEATTACHMENT:
		return rpc_ext_pull_deleteattachment_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::SETPROPVALS:
		return rpc_ext_pull_setpropvals_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::GETPROPVALS:
		return rpc_ext_pull_getpropvals_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::DELETEPROPVALS:
		return rpc_ext_pull_deletepropvals_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::SETMESSAGEREADFLAG:
		return rpc_ext_pull_setmessagereadflag_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::OPENEMBEDDED:
		return rpc_ext_pull_openembedded_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::GETNAMEDPROPIDS:
		return rpc_ext_pull_getnamedpropids_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::GETPROPNAMES:
		return rpc_ext_pull_getpropnames_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::COPYTO:
		return rpc_ext_pull_copyto_request(
			&ext_pull, &prequest->payload);
	case zcore_callid::SAVECHANGES:
		return rpc_ext_pull_savechanges_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::HIERARCHYSYNC:
		return rpc_ext_pull_hierarchysync_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CONTENTSYNC:
		return rpc_ext_pull_contentsync_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CONFIGSYNC:
		return rpc_ext_pull_configsync_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::STATESYNC:
		return rpc_ext_pull_statesync_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::SYNCMESSAGECHANGE:
		return rpc_ext_pull_syncmessagechange_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::SYNCFOLDERCHANGE:
		return rpc_ext_pull_syncfolderchange_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::SYNCREADSTATECHANGES:
		return rpc_ext_pull_syncreadstatechanges_request(
							&ext_pull, &prequest->payload);
	case zcore_callid::SYNCDELETIONS:
		return rpc_ext_pull_syncdeletions_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::HIERARCHYIMPORT:
		return rpc_ext_pull_hierarchyimport_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CONTENTIMPORT:
		return rpc_ext_pull_contentimport_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::CONFIGIMPORT:
		return rpc_ext_pull_configimport_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::STATEIMPORT:
		return rpc_ext_pull_stateimport_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::IMPORTMESSAGE:
		return rpc_ext_pull_importmessage_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::IMPORTFOLDER:
		return rpc_ext_pull_importfolder_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::IMPORTDELETION:
		return rpc_ext_pull_importdeletion_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::IMPORTREADSTATES:
		return rpc_ext_pull_importreadstates_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::GETSEARCHCRITERIA:
		return rpc_ext_pull_getsearchcriteria_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::SETSEARCHCRITERIA:
		return rpc_ext_pull_setsearchcriteria_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::MESSAGETORFC822:
		return rpc_ext_pull_messagetorfc822_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::RFC822TOMESSAGE:
		return rpc_ext_pull_rfc822tomessage_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::MESSAGETOICAL:
		return rpc_ext_pull_messagetoical_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::ICALTOMESSAGE:
		return rpc_ext_pull_icaltomessage_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::MESSAGETOVCF:
		return rpc_ext_pull_messagetovcf_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::VCFTOMESSAGE:
		return rpc_ext_pull_vcftomessage_request(
					&ext_pull, &prequest->payload);
	case zcore_callid::GETUSERAVAILABILITY:
		return rpc_ext_pull_getuseravailability_request(
						&ext_pull, &prequest->payload);
	case zcore_callid::SETPASSWD:
		return rpc_ext_pull_setpasswd_request(
				&ext_pull, &prequest->payload);
	case zcore_callid::LINKMESSAGE:
		return rpc_ext_pull_linkmessage_request(
				&ext_pull, &prequest->payload);
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
	QRF(ext_push.p_uint8(zcore_response::SUCCESS));
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
	case zcore_callid::LOGON:
		b_result = rpc_ext_push_logon_response(
				&ext_push, &presponse->payload);
		break;
	case zcore_callid::CHECKSESSION:
		b_result = TRUE;
		break;
	case zcore_callid::UINFO:
		b_result = rpc_ext_push_uinfo_response(
				&ext_push, &presponse->payload);
		break;
	case zcore_callid::UNLOADOBJECT:
		b_result = TRUE;
		break;
	case zcore_callid::OPENENTRY:
		b_result = rpc_ext_push_openentry_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::OPENSTOREENTRY:
		b_result = rpc_ext_push_openstoreentry_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::OPENABENTRY:
		b_result = rpc_ext_push_openabentry_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::RESOLVENAME:
		b_result = rpc_ext_push_resolvename_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::GETPERMISSIONS:
		b_result = rpc_ext_push_getpermissions_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::MODIFYPERMISSIONS:
	case zcore_callid::MODIFYRULES:
		b_result = TRUE;
		break;
	case zcore_callid::GETABGAL:
		b_result = rpc_ext_push_getabgal_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::LOADSTORETABLE:
		b_result = rpc_ext_push_loadstoretable_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::OPENSTORE:
		b_result = rpc_ext_push_openstore_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::OPENPROPFILESEC:
		b_result = rpc_ext_push_openpropfilesec_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::LOADHIERARCHYTABLE:
		b_result = rpc_ext_push_loadhierarchytable_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::LOADCONTENTTABLE:
		b_result = rpc_ext_push_loadcontenttable_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::LOADRECIPIENTTABLE:
		b_result = rpc_ext_push_loadrecipienttable_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::LOADRULETABLE:
		b_result = rpc_ext_push_loadruletable_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::CREATEMESSAGE:
		b_result = rpc_ext_push_createmessage_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::DELETEMESSAGES:
	case zcore_callid::COPYMESSAGES:
	case zcore_callid::SETREADFLAGS:
		b_result = TRUE;
		break;
	case zcore_callid::CREATEFOLDER:
		b_result = rpc_ext_push_createfolder_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::DELETEFOLDER:
	case zcore_callid::EMPTYFOLDER:
	case zcore_callid::COPYFOLDER:
		b_result = TRUE;
		break;
	case zcore_callid::GETSTOREENTRYID:
		b_result = rpc_ext_push_getstoreentryid_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::ENTRYIDFROMSOURCEKEY:
		b_result = rpc_ext_push_entryidfromsourcekey_response(
								&ext_push, &presponse->payload);
		break;
	case zcore_callid::STOREADVISE:
		b_result = rpc_ext_push_storeadvise_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::UNADVISE:
		b_result = TRUE;
		break;
	case zcore_callid::NOTIFDEQUEUE:
		b_result = rpc_ext_push_notifdequeue_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::QUERYROWS:
		b_result = rpc_ext_push_queryrows_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::SETCOLUMNS:
		b_result = TRUE;
		break;
	case zcore_callid::SEEKROW:
		b_result = rpc_ext_push_seekrow_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::SORTTABLE:
		b_result = TRUE;
		break;
	case zcore_callid::GETROWCOUNT:
		b_result = rpc_ext_push_getrowcount_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::RESTRICTTABLE:
		b_result = TRUE;
		break;
	case zcore_callid::FINDROW:
		b_result = rpc_ext_push_findrow_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::CREATEBOOKMARK:
		b_result = rpc_ext_push_createbookmark_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::FREEBOOKMARK:
		b_result = TRUE;
		break;
	case zcore_callid::GETRECEIVEFOLDER:
		b_result = rpc_ext_push_getreceivefolder_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::MODIFYRECIPIENTS:
	case zcore_callid::SUBMITMESSAGE:
		b_result = TRUE;
		break;
	case zcore_callid::LOADATTACHMENTTABLE:
		b_result = rpc_ext_push_loadattachmenttable_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::OPENATTACHMENT:
		b_result = rpc_ext_push_openattachment_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::CREATEATTACHMENT:
		b_result = rpc_ext_push_createattachment_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::DELETEATTACHMENT:
		b_result = TRUE;
		break;
	case zcore_callid::SETPROPVALS:
		b_result = TRUE;
		break;
	case zcore_callid::GETPROPVALS:
		b_result = rpc_ext_push_getpropvals_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::DELETEPROPVALS:
	case zcore_callid::SETMESSAGEREADFLAG:
		b_result = TRUE;
		break;
	case zcore_callid::OPENEMBEDDED:
		b_result = rpc_ext_push_openembedded_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::GETNAMEDPROPIDS:
		b_result = rpc_ext_push_getnamedpropids_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::GETPROPNAMES:
		b_result = rpc_ext_push_getpropnames_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::COPYTO:
	case zcore_callid::SAVECHANGES:
		b_result = TRUE;
		break;
	case zcore_callid::HIERARCHYSYNC:
		b_result = rpc_ext_push_hierarchysync_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::CONTENTSYNC:
		b_result = rpc_ext_push_contentsync_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::CONFIGSYNC:
		b_result = rpc_ext_push_configsync_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::STATESYNC:
		b_result = rpc_ext_push_statesync_response(
					&ext_push, &presponse->payload);
		break;
	case zcore_callid::SYNCMESSAGECHANGE:
		b_result = rpc_ext_push_syncmessagechange_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::SYNCFOLDERCHANGE:
		b_result = rpc_ext_push_syncfolderchange_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::SYNCREADSTATECHANGES:
		b_result = rpc_ext_push_syncreadstatechanges_response(
								&ext_push, &presponse->payload);
		break;
	case zcore_callid::SYNCDELETIONS:
		b_result = rpc_ext_push_syncdeletions_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::HIERARCHYIMPORT:
		b_result = rpc_ext_push_hierarchyimport_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::CONTENTIMPORT:
		b_result = rpc_ext_push_contentimport_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::CONFIGIMPORT:
		b_result = TRUE;
		break;
	case zcore_callid::STATEIMPORT:
		b_result = rpc_ext_push_stateimport_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::IMPORTMESSAGE:
		b_result = rpc_ext_push_importmessage_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::IMPORTFOLDER:
		b_result = TRUE;
		break;
	case zcore_callid::IMPORTDELETION:
	case zcore_callid::IMPORTREADSTATES:
		b_result = TRUE;
		break;
	case zcore_callid::GETSEARCHCRITERIA:
		b_result = rpc_ext_push_getsearchcriteria_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::SETSEARCHCRITERIA:
		b_result = TRUE;
		break;
	case zcore_callid::MESSAGETORFC822:
		b_result = rpc_ext_push_messagetorfc822_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::RFC822TOMESSAGE:
		b_result = TRUE;
		break;
	case zcore_callid::MESSAGETOICAL:
		b_result = rpc_ext_push_messagetoical_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::ICALTOMESSAGE:
		b_result = TRUE;
		break;
	case zcore_callid::MESSAGETOVCF:
		b_result = rpc_ext_push_messagetovcf_response(
						&ext_push, &presponse->payload);
		break;
	case zcore_callid::VCFTOMESSAGE:
		b_result = TRUE;
		break;
	case zcore_callid::GETUSERAVAILABILITY:
		b_result = rpc_ext_push_getuseravailability_response(
							&ext_push, &presponse->payload);
		break;
	case zcore_callid::SETPASSWD:
		b_result = TRUE;
		break;
	case zcore_callid::LINKMESSAGE:
		b_result = TRUE;
		break;
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
