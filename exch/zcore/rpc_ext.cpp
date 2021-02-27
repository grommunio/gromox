// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/mapidefs.h>
#include <gromox/zcore_rpc.hpp>
#include "rpc_ext.h"
#include <gromox/ext_buffer.hpp>
#include "common_util.h"
#define QRF(expr) do { if ((expr) != EXT_ERR_SUCCESS) return false; } while (false)

static BOOL rpc_ext_pull_zmovecopy_action(
	EXT_PULL *pext, ZMOVECOPY_ACTION *r)
{
	QRF(ext_buffer_pull_binary(pext, &r->store_eid));
	QRF(ext_buffer_pull_binary(pext, &r->folder_eid));
	return TRUE;
}

static BOOL rpc_ext_pull_zreply_action(
	EXT_PULL *pext, ZREPLY_ACTION *r)
{
	QRF(ext_buffer_pull_binary(pext, &r->message_eid));
	QRF(ext_buffer_pull_guid(pext, &r->template_guid));
	return TRUE;
}

static BOOL rpc_ext_pull_recipient_block(
	EXT_PULL *pext, RECIPIENT_BLOCK *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint8(pext, &r->reserved));
	QRF(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		return FALSE;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		QRF(ext_buffer_pull_tagged_propval(pext, &r->ppropval[i]));
	}
	return TRUE;
}

static BOOL rpc_ext_pull_forwarddelegate_action(
	EXT_PULL *pext, FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		return FALSE;
	}
	r->pblock = pext->anew<RECIPIENT_BLOCK>(r->count);
	if (NULL == r->pblock) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (FALSE == rpc_ext_pull_recipient_block(
			pext, &r->pblock[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_action_block(
	EXT_PULL *pext, ACTION_BLOCK *r)
{
	uint16_t tmp_len;
	
	QRF(ext_buffer_pull_uint16(pext, &r->length));
	QRF(ext_buffer_pull_uint8(pext, &r->type));
	QRF(ext_buffer_pull_uint32(pext, &r->flavor));
	QRF(ext_buffer_pull_uint32(pext, &r->flags));
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = pext->anew<ZMOVECOPY_ACTION>();
		if (NULL == r->pdata) {
			return FALSE;
		}
		return rpc_ext_pull_zmovecopy_action(pext,
		       static_cast<ZMOVECOPY_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = pext->anew<ZREPLY_ACTION>();
		if (NULL == r->pdata) {
			return FALSE;
		}
		return rpc_ext_pull_zreply_action(pext,
		       static_cast<ZREPLY_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = pext->alloc(tmp_len);
		if (NULL == r->pdata) {
			return FALSE;
		}
		QRF(ext_buffer_pull_bytes(pext, r->pdata, tmp_len));
		return TRUE;
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = pext->anew<uint32_t>();
		if (NULL == r->pdata) {
			return FALSE;
		}
		QRF(ext_buffer_pull_uint32(pext, static_cast<uint32_t *>(r->pdata)));
		return TRUE;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = pext->anew<FORWARDDELEGATE_ACTION>();
		if (NULL == r->pdata) {
			return FALSE;
		}
		return rpc_ext_pull_forwarddelegate_action(pext,
		       static_cast<FORWARDDELEGATE_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_TAG:
		r->pdata = pext->anew<TAGGED_PROPVAL>();
		if (NULL == r->pdata) {
			return FALSE;
		}
		QRF(ext_buffer_pull_tagged_propval(pext, static_cast<TAGGED_PROPVAL *>(r->pdata)));
		return TRUE;
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		r->pdata = NULL;
		return TRUE;
	default:
		return FALSE;
	}
}

static BOOL rpc_ext_pull_rule_actions(
	EXT_PULL *pext, RULE_ACTIONS *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		return FALSE;
	}
	r->pblock = pext->anew<ACTION_BLOCK>(r->count);
	if (NULL == r->pblock) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_action_block(
			pext, &r->pblock[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_propval(
	EXT_PULL *pext, uint16_t type, void **ppval)
{
	/* convert multi-value instance into single value */
	if ((type & MVI_FLAG) == MVI_FLAG)
		type &= ~MVI_FLAG;
	switch (type) {
	case PT_SHORT:
		*ppval = pext->anew<uint16_t>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_uint16(pext, static_cast<uint16_t *>(*ppval)));
		return TRUE;
	case PT_LONG:
	case PT_ERROR:
		*ppval = pext->anew<uint32_t>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_uint32(pext, static_cast<uint32_t *>(*ppval)));
		return TRUE;
	case PT_FLOAT:
		*ppval = pext->anew<float>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_float(pext, static_cast<float *>(*ppval)));
		return TRUE;
	case PT_DOUBLE:
	case PT_APPTIME:
		*ppval = pext->anew<double>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_double(pext, static_cast<double *>(*ppval)));
		return TRUE;
	case PT_BOOLEAN:
		*ppval = pext->anew<uint8_t>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_uint8(pext, static_cast<uint8_t *>(*ppval)));
		return TRUE;
	case PT_I8:
	case PT_SYSTIME:
		*ppval = pext->anew<uint64_t>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_uint64(pext, static_cast<uint64_t *>(*ppval)));
		return TRUE;
	case PT_STRING8:
		QRF(ext_buffer_pull_string(pext, reinterpret_cast<char **>(ppval)));
		return TRUE;
	case PT_UNICODE:
		QRF(ext_buffer_pull_wstring(pext, reinterpret_cast<char **>(ppval)));
		return TRUE;
	case PT_CLSID:
		*ppval = pext->anew<GUID>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_guid(pext, static_cast<GUID *>(*ppval)));
		return TRUE;
	case PT_SRESTRICT:
		*ppval = pext->anew<RESTRICTION>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_restriction(pext, static_cast<RESTRICTION *>(*ppval)));
		return TRUE;
	case PT_ACTIONS:
		*ppval = pext->anew<RULE_ACTIONS>();
		if (NULL == *ppval) {
			return FALSE;
		}
		return rpc_ext_pull_rule_actions(pext, static_cast<RULE_ACTIONS *>(*ppval));
	case PT_BINARY:
		*ppval = pext->anew<BINARY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_binary(pext, static_cast<BINARY *>(*ppval)));
		return TRUE;
	case PT_MV_SHORT:
		*ppval = pext->anew<SHORT_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_short_array(pext, static_cast<SHORT_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_LONG:
		*ppval = pext->anew<LONG_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_long_array(pext, static_cast<LONG_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_I8:
		*ppval = pext->anew<LONGLONG_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_longlong_array(pext, static_cast<LONGLONG_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_STRING8:
		*ppval = pext->anew<STRING_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_string_array(pext, static_cast<STRING_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_UNICODE:
		*ppval = pext->anew<STRING_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_wstring_array(pext, static_cast<STRING_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_CLSID:
		*ppval = pext->anew<GUID_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_guid_array(pext, static_cast<GUID_ARRAY *>(*ppval)));
		return TRUE;
	case PT_MV_BINARY:
		*ppval = pext->anew<BINARY_ARRAY>();
		if (NULL == *ppval) {
			return FALSE;
		}
		QRF(ext_buffer_pull_binary_array(pext, static_cast<BINARY_ARRAY *>(*ppval)));
		return TRUE;
	default:
		return FALSE;
	}
}

static BOOL rpc_ext_pull_tagged_propval(
	EXT_PULL *pext, TAGGED_PROPVAL *r)
{	
	QRF(ext_buffer_pull_uint32(pext, &r->proptag));
	return rpc_ext_pull_propval(pext, PROP_TYPE(r->proptag), &r->pvalue);
}

static BOOL rpc_ext_pull_tpropval_array(
	EXT_PULL *pext, TPROPVAL_ARRAY *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->ppropval = NULL;
		return TRUE;
	}
	r->ppropval = pext->anew<TAGGED_PROPVAL>(r->count);
	if (NULL == r->ppropval) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_tagged_propval(
			pext, r->ppropval + i)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_rule_data(
	EXT_PULL *pext, RULE_DATA *r)
{
	QRF(ext_buffer_pull_uint8(pext, &r->flags));
	return rpc_ext_pull_tpropval_array(pext, &r->propvals);
}

static BOOL rpc_ext_pull_rule_list(
	EXT_PULL *pext, RULE_LIST *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint16(pext, &r->count));
	if (0 == r->count) {
		r->prule = NULL;
		return TRUE;
	}
	r->prule = pext->anew<RULE_DATA>(r->count);
	if (NULL == r->prule) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_rule_data(
			pext, &r->prule[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_permission_row(
	EXT_PULL *pext, PERMISSION_ROW *r)
{
	QRF(ext_buffer_pull_uint32(pext, &r->flags));
	QRF(ext_buffer_pull_binary(pext, &r->entryid));
	QRF(ext_buffer_pull_uint32(pext, &r->member_rights));
	return TRUE;
}

static BOOL rpc_ext_pull_permission_set(
	EXT_PULL *pext, PERMISSION_SET *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint16(pext, &r->count));
	r->prows = pext->anew<PERMISSION_ROW>(r->count);
	if (NULL == r->prows) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_permission_row(
			pext, &r->prows[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_message_state(
	EXT_PULL *pext, MESSAGE_STATE *r)
{
	QRF(ext_buffer_pull_binary(pext, &r->source_key));
	QRF(ext_buffer_pull_uint32(pext, &r->message_flags));
	return TRUE;
}

static BOOL rpc_ext_pull_state_array(
	EXT_PULL *pext, STATE_ARRAY *r)
{
	int i;
	
	QRF(ext_buffer_pull_uint32(pext, &r->count));
	if (0 == r->count) {
		r->pstate = NULL;
		return TRUE;
	}
	r->pstate = pext->anew<MESSAGE_STATE>(r->count);
	if (NULL == r->pstate) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_message_state(
			pext, &r->pstate[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_zmovecopy_action(
	EXT_PUSH *pext, const ZMOVECOPY_ACTION *r)
{
	QRF(ext_buffer_push_binary(pext, &r->store_eid));
	QRF(ext_buffer_push_binary(pext, &r->folder_eid));
	return TRUE;
}

static BOOL rpc_ext_push_zreply_action(
	EXT_PUSH *pext, const ZREPLY_ACTION *r)
{	
	QRF(ext_buffer_push_binary(pext, &r->message_eid));
	QRF(ext_buffer_push_guid(pext, &r->template_guid));
	return TRUE;
}

static BOOL rpc_ext_push_recipient_block(
	EXT_PUSH *pext, const RECIPIENT_BLOCK *r)
{
	int i;
	
	if (0 == r->count) {
		return FALSE;
	}
	QRF(ext_buffer_push_uint8(pext, r->reserved));
	QRF(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		QRF(ext_buffer_push_tagged_propval(pext, &r->ppropval[i]));
	}
	return TRUE;
}

static BOOL rpc_ext_push_forwarddelegate_action(
	EXT_PUSH *pext, const FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	if (0 == r->count) {
		return FALSE;
	}
	QRF(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (FALSE == rpc_ext_push_recipient_block(
			pext, &r->pblock[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_action_block(
	EXT_PUSH *pext, const ACTION_BLOCK *r)
{
	uint32_t offset;
	uint32_t offset1;
	uint16_t tmp_len;
	
	offset = pext->offset;
	QRF(ext_buffer_push_advance(pext, sizeof(uint16_t)));
	QRF(ext_buffer_push_uint8(pext, r->type));
	QRF(ext_buffer_push_uint32(pext, r->flavor));
	QRF(ext_buffer_push_uint32(pext, r->flags));
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		if (!rpc_ext_push_zmovecopy_action(pext,
		    static_cast<const ZMOVECOPY_ACTION *>(r->pdata)))
			return FALSE;
		break;
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		if (!rpc_ext_push_zreply_action(pext,
		    static_cast<const ZREPLY_ACTION *>(r->pdata)))
			return FALSE;
		break;
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		QRF(ext_buffer_push_bytes(pext, r->pdata, tmp_len));
		break;
	case ACTION_TYPE_OP_BOUNCE:
		QRF(ext_buffer_push_uint32(pext, *static_cast<uint32_t *>(r->pdata)));
		break;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		return rpc_ext_push_forwarddelegate_action(pext,
		       static_cast<const FORWARDDELEGATE_ACTION *>(r->pdata));
	case ACTION_TYPE_OP_TAG:
		QRF(ext_buffer_push_tagged_propval(pext, static_cast<const TAGGED_PROPVAL *>(r->pdata)));
		break;
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		break;
	default:
		return FALSE;
	}
	tmp_len = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	QRF(ext_buffer_push_uint16(pext, tmp_len));
	pext->offset = offset1;
	return TRUE;
}

static BOOL rpc_ext_push_rule_actions(
	EXT_PUSH *pext, const RULE_ACTIONS *r)
{
	int i;
	
	if (0 == r->count) {
		return FALSE;
	}
	QRF(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_action_block(
			pext, &r->pblock[i])) {
			return FALSE;
		}
	}
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
		QRF(ext_buffer_push_uint16(pext, *static_cast<const uint16_t *>(pval)));
		return TRUE;
	case PT_LONG:
	case PT_ERROR:
		QRF(ext_buffer_push_uint32(pext, *static_cast<const uint32_t *>(pval)));
		return TRUE;
	case PT_FLOAT:
		QRF(ext_buffer_push_float(pext, *static_cast<const float *>(pval)));
		return TRUE;
	case PT_DOUBLE:
	case PT_APPTIME:
		QRF(ext_buffer_push_double(pext, *static_cast<const double *>(pval)));
		return TRUE;
	case PT_BOOLEAN:
		QRF(ext_buffer_push_uint8(pext, *static_cast<const uint8_t *>(pval)));
		return TRUE;
	case PT_I8:
	case PT_SYSTIME:
		QRF(ext_buffer_push_uint64(pext, *static_cast<const uint64_t *>(pval)));
		return TRUE;
	case PT_STRING8:
		QRF(ext_buffer_push_string(pext, static_cast<const char *>(pval)));
		return TRUE;
	case PT_UNICODE:
		QRF(ext_buffer_push_wstring(pext, static_cast<const char *>(pval)));
		return TRUE;
	case PT_CLSID:
		QRF(ext_buffer_push_guid(pext, static_cast<const GUID *>(pval)));
		return TRUE;
	case PT_SRESTRICT:
		QRF(ext_buffer_push_restriction(pext, static_cast<const RESTRICTION *>(pval)));
		return TRUE;
	case PT_ACTIONS:
		return rpc_ext_push_rule_actions(pext, static_cast<const RULE_ACTIONS *>(pval));
	case PT_BINARY:
		QRF(ext_buffer_push_binary(pext, static_cast<const BINARY *>(pval)));
		return TRUE;
	case PT_MV_SHORT:
		QRF(ext_buffer_push_short_array(pext, static_cast<const SHORT_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_LONG:
		QRF(ext_buffer_push_long_array(pext, static_cast<const LONG_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_I8:
		QRF(ext_buffer_push_longlong_array(pext, static_cast<const LONGLONG_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_STRING8:
		QRF(ext_buffer_push_string_array(pext, static_cast<const STRING_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_UNICODE:
		QRF(ext_buffer_push_wstring_array(pext, static_cast<const STRING_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_CLSID:
		QRF(ext_buffer_push_guid_array(pext, static_cast<const GUID_ARRAY *>(pval)));
		return TRUE;
	case PT_MV_BINARY:
		QRF(ext_buffer_push_binary_array(pext, static_cast<const BINARY_ARRAY *>(pval)));
		return TRUE;
	default:
		return FALSE;
	}
}

static BOOL rpc_ext_push_tagged_propval(
	EXT_PUSH *pext, const TAGGED_PROPVAL *r)
{
	QRF(ext_buffer_push_uint32(pext, r->proptag));
	return rpc_ext_push_propval(pext, PROP_TYPE(r->proptag), r->pvalue);
}

static BOOL rpc_ext_push_tpropval_array(
	EXT_PUSH *pext, const TPROPVAL_ARRAY *r)
{
	int i;
	
	QRF(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_tagged_propval(
			pext, r->ppropval + i)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_tarray_set(
	EXT_PUSH *pext, const TARRAY_SET *r)
{
	int i;
	
	QRF(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (FALSE == rpc_ext_push_tpropval_array(
			pext, r->pparray[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_permission_row(
	EXT_PUSH *pext, const PERMISSION_ROW *r)
{
	QRF(ext_buffer_push_uint32(pext, r->flags));
	QRF(ext_buffer_push_binary(pext, &r->entryid));
	QRF(ext_buffer_push_uint32(pext, r->member_rights));
	return TRUE;
}

static BOOL rpc_ext_push_permission_set(
	EXT_PUSH *pext, const PERMISSION_SET *r)
{
	int i;
	
	QRF(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_permission_row(
			pext, &r->prows[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_message_state(
	EXT_PUSH *pext, const MESSAGE_STATE *r)
{
	QRF(ext_buffer_push_binary(pext, &r->source_key));
	QRF(ext_buffer_push_uint32(pext, r->message_flags));
	return TRUE;
}

static BOOL rpc_ext_push_state_array(
	EXT_PUSH *pext, const STATE_ARRAY *r)
{
	int i;
	
	QRF(ext_buffer_push_uint32(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_message_state(
			pext, &r->pstate[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_newmail_znotification(
	EXT_PUSH *pext, const NEWMAIL_ZNOTIFICATION *r)
{
	QRF(ext_buffer_push_binary(pext, &r->entryid));
	QRF(ext_buffer_push_binary(pext, &r->parentid));
	QRF(ext_buffer_push_uint32(pext, r->flags));
	QRF(ext_buffer_push_string(pext, r->message_class));
	QRF(ext_buffer_push_uint32(pext, r->message_flags));
	return TRUE;
}

static BOOL rpc_ext_push_object_znotification(
	EXT_PUSH *pext, const OBJECT_ZNOTIFICATION *r)
{	
	QRF(ext_buffer_push_uint32(pext, r->object_type));
	if (NULL == r->pentryid) {
		QRF(ext_buffer_push_uint8(pext, 0));
	} else {
		QRF(ext_buffer_push_uint8(pext, 1));
		QRF(ext_buffer_push_binary(pext, r->pentryid));
	}
	if (NULL == r->pparentid) {
		QRF(ext_buffer_push_uint8(pext, 0));
	} else {
		QRF(ext_buffer_push_uint8(pext, 1));
		QRF(ext_buffer_push_binary(pext, r->pparentid));
	}
	if (NULL == r->pold_entryid) {
		QRF(ext_buffer_push_uint8(pext, 0));
	} else {
		QRF(ext_buffer_push_uint8(pext, 1));
		QRF(ext_buffer_push_binary(pext, r->pold_entryid));
	}
	if (NULL == r->pold_parentid) {
		QRF(ext_buffer_push_uint8(pext, 0));
	} else {
		QRF(ext_buffer_push_uint8(pext, 1));
		QRF(ext_buffer_push_binary(pext, r->pold_parentid));
	}
	if (NULL == r->pproptags) {
		QRF(ext_buffer_push_uint8(pext, 0));
	} else {
		QRF(ext_buffer_push_uint8(pext, 1));
		QRF(ext_buffer_push_proptag_array(pext, r->pproptags));
	}
	return TRUE;
}

static BOOL rpc_ext_push_znotification(
	EXT_PUSH *pext, const ZNOTIFICATION *r)
{
	QRF(ext_buffer_push_uint32(pext, r->event_type));
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
	int i;
	
	QRF(ext_buffer_push_uint16(pext, r->count));
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_znotification(
			pext, r->ppnotification[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

/*---------------------------------------------------------------------------*/

static BOOL rpc_ext_pull_logon_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_string(pext, &ppayload->logon.username));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->logon.password = NULL;
	} else {
		QRF(ext_buffer_pull_string(pext, &ppayload->logon.password));
	}
	QRF(ext_buffer_pull_uint32(pext, &ppayload->logon.flags));
	return TRUE;
}

static BOOL rpc_ext_push_logon_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_guid(pext, &ppayload->logon.hsession));
	return TRUE;
}

static BOOL rpc_ext_pull_checksession_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->unloadobject.hsession));
	return TRUE;
}

static BOOL rpc_ext_pull_uinfo_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_string(pext, &ppayload->uinfo.username));
	return TRUE;
}

static BOOL rpc_ext_push_uinfo_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->uinfo.entryid));
	QRF(ext_buffer_push_string(pext, ppayload->uinfo.pdisplay_name));
	QRF(ext_buffer_push_string(pext, ppayload->uinfo.px500dn));
	QRF(ext_buffer_push_uint32(pext, ppayload->uinfo.privilege_bits));
	return TRUE;
}

static BOOL rpc_ext_pull_unloadobject_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->unloadobject.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->unloadobject.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->openentry.hsession));
	QRF(ext_buffer_pull_binary(pext, &ppayload->openentry.entryid));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openentry.flags));
	return TRUE;
}

static BOOL rpc_ext_push_openentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint8(pext, ppayload->openentry.mapi_type));
	QRF(ext_buffer_push_uint32(pext, ppayload->openentry.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openstoreentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->openstoreentry.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openstoreentry.hobject));
	QRF(ext_buffer_pull_binary(pext, &ppayload->openstoreentry.entryid));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openstoreentry.flags));
	return TRUE;
}

static BOOL rpc_ext_push_openstoreentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint8(pext, ppayload->openstoreentry.mapi_type));
	QRF(ext_buffer_push_uint32(pext, ppayload->openstoreentry.hxobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openabentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->openabentry.hsession));
	QRF(ext_buffer_pull_binary(pext, &ppayload->openabentry.entryid));
	return TRUE;
}

static BOOL rpc_ext_push_openabentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint8(pext, ppayload->openabentry.mapi_type));
	QRF(ext_buffer_push_uint32(pext, ppayload->openabentry.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_resolvename_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->resolvename.hsession));
	ppayload->resolvename.pcond_set = pext->anew<TARRAY_SET>();
	if (NULL == ppayload->resolvename.pcond_set) {
		return FALSE;
	}
	QRF(ext_buffer_pull_tarray_set(pext, ppayload->resolvename.pcond_set));
	return TRUE;
}

static BOOL rpc_ext_push_resolvename_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_tarray_set(pext, &ppayload->resolvename.result_set));
	return TRUE;
}

static BOOL rpc_ext_pull_getpermissions_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->getpermissions.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getpermissions.hobject));
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
	QRF(ext_buffer_pull_guid(pext, &ppayload->modifypermissions.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->modifypermissions.hfolder));
	ppayload->modifypermissions.pset = pext->anew<PERMISSION_SET>();
	if (NULL == ppayload->modifypermissions.pset) {
		return FALSE;
	}
	return rpc_ext_pull_permission_set(pext,
			ppayload->modifypermissions.pset);
}

static BOOL rpc_ext_pull_modifyrules_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->modifyrules.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->modifyrules.hfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->modifyrules.flags));
	ppayload->modifyrules.plist = pext->anew<RULE_LIST>();
	if (NULL == ppayload->modifyrules.plist) {
		return FALSE;
	}
	return rpc_ext_pull_rule_list(pext,
			ppayload->modifyrules.plist);
}

static BOOL rpc_ext_pull_getabgal_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->getabgal.hsession));
	return TRUE;
}

static BOOL rpc_ext_push_getabgal_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->getabgal.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_loadstoretable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{	
	QRF(ext_buffer_pull_guid(pext, &ppayload->loadstoretable.hsession));
	return TRUE;
}

static BOOL rpc_ext_push_loadstoretable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->loadstoretable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openstore_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->openstore.hsession));
	QRF(ext_buffer_pull_binary(pext, &ppayload->openstore.entryid));
	return TRUE;
}

static BOOL rpc_ext_push_openstore_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->openstore.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openpropfilesec_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->openpropfilesec.hsession));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->openpropfilesec.puid = NULL;
	} else {
		ppayload->openpropfilesec.puid = pext->anew<FLATUID>();
		if (NULL == ppayload->openpropfilesec.puid) {
			return FALSE;
		}
		QRF(ext_buffer_pull_bytes(pext, const_cast<FLATUID *>(ppayload->openpropfilesec.puid), sizeof(FLATUID)));
	}
	return TRUE;
}

static BOOL rpc_ext_push_openpropfilesec_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->openpropfilesec.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadhierarchytable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->loadhierarchytable.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->loadhierarchytable.hfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->loadhierarchytable.flags));
	return TRUE;
}

static BOOL rpc_ext_push_loadhierarchytable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->loadhierarchytable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadcontenttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->loadcontenttable.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->loadcontenttable.hfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->loadcontenttable.flags));
	return TRUE;
}

static BOOL rpc_ext_push_loadcontenttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->loadcontenttable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadrecipienttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->loadrecipienttable.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->loadrecipienttable.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_loadrecipienttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->loadrecipienttable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_loadruletable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->loadruletable.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->loadruletable.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_loadruletable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->loadruletable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_createmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->createmessage.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->createmessage.hfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->createmessage.flags));
	return TRUE;
}

static BOOL rpc_ext_push_createmessage_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->createmessage.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_deletemessages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->deletemessages.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deletemessages.hfolder));
	ppayload->deletemessages.pentryids = pext->anew<BINARY_ARRAY>();
	if (NULL == ppayload->deletemessages.pentryids) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary_array(pext, ppayload->deletemessages.pentryids));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deletemessages.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_copymessages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->copymessages.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copymessages.hsrcfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copymessages.hdstfolder));
	ppayload->copymessages.pentryids = pext->anew<BINARY_ARRAY>();
	if (NULL == ppayload->copymessages.pentryids) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary_array(pext, ppayload->copymessages.pentryids));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copymessages.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_setreadflags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->setreadflags.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setreadflags.hfolder));
	ppayload->setreadflags.pentryids = pext->anew<BINARY_ARRAY>();
	if (NULL == ppayload->setreadflags.pentryids) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary_array(pext, ppayload->setreadflags.pentryids));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setreadflags.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_createfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{	
	QRF(ext_buffer_pull_guid(pext, &ppayload->createfolder.hsession));
	QRF(ext_buffer_pull_uint32(pext,
		&ppayload->createfolder.hparent_folder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->createfolder.folder_type));
	QRF(ext_buffer_pull_string(pext, &ppayload->createfolder.folder_name));
	QRF(ext_buffer_pull_string(pext,
		&ppayload->createfolder.folder_comment));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->createfolder.flags));
	return TRUE;
}

static BOOL rpc_ext_push_createfolder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->createfolder.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_deletefolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->deletefolder.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deletefolder.hparent_folder));
	QRF(ext_buffer_pull_binary(pext, &ppayload->deletefolder.entryid));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deletefolder.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_emptyfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->emptyfolder.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->emptyfolder.hfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->emptyfolder.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_copyfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->copyfolder.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copyfolder.hsrc_folder));
	QRF(ext_buffer_pull_binary(pext, &ppayload->copyfolder.entryid));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copyfolder.hdst_folder));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->copyfolder.new_name = NULL;
	} else {
		QRF(ext_buffer_pull_string(pext, &ppayload->copyfolder.new_name));
	}
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copyfolder.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_getstoreentryid_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_string(pext,
		&ppayload->getstoreentryid.mailbox_dn));
	return TRUE;
}

static BOOL rpc_ext_push_getstoreentryid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->getstoreentryid.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_entryidfromsourcekey_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->entryidfromsourcekey.hsession));
	QRF(ext_buffer_pull_uint32(pext,
		&ppayload->entryidfromsourcekey.hstore));
	QRF(ext_buffer_pull_binary(pext,
		&ppayload->entryidfromsourcekey.folder_key));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->entryidfromsourcekey.pmessage_key = NULL;
	} else {
		ppayload->entryidfromsourcekey.pmessage_key = pext->anew<BINARY>();
		if (NULL == ppayload->entryidfromsourcekey.pmessage_key) {
			return FALSE;
		}
		QRF(ext_buffer_pull_binary(pext,
			ppayload->entryidfromsourcekey.pmessage_key));
	}
	return TRUE;
}

static BOOL rpc_ext_push_entryidfromsourcekey_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext,
		&ppayload->entryidfromsourcekey.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_storeadvise_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->storeadvise.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->storeadvise.hstore));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->storeadvise.pentryid = NULL;
	} else {
		ppayload->storeadvise.pentryid = pext->anew<BINARY>();
		if (NULL == ppayload->storeadvise.pentryid) {
			return FALSE;
		}
		QRF(ext_buffer_pull_binary(pext, ppayload->storeadvise.pentryid));
	}
	QRF(ext_buffer_pull_uint32(pext, &ppayload->storeadvise.event_mask));
	return TRUE;
}

static BOOL rpc_ext_push_storeadvise_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->storeadvise.sub_id));
	return TRUE;
}

static BOOL rpc_ext_pull_unadvise_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->unadvise.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->unadvise.hstore));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->unadvise.sub_id));
	return TRUE;
}

static BOOL rpc_ext_pull_notifdequeue_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	ppayload->notifdequeue.psink = pext->anew<NOTIF_SINK>();
	if (NULL == ppayload->notifdequeue.psink) {
		return FALSE;
	}
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->notifdequeue.psink->hsession));
	QRF(ext_buffer_pull_uint16(pext, &ppayload->notifdequeue.psink->count));
	ppayload->notifdequeue.psink->padvise = pext->anew<ADVISE_INFO>(ppayload->notifdequeue.psink->count);
	if (NULL == ppayload->notifdequeue.psink->padvise) {
		return FALSE;
	}
	for (i=0; i<ppayload->notifdequeue.psink->count; i++) {
		QRF(ext_buffer_pull_uint32(pext,
			&ppayload->notifdequeue.psink->padvise[i].hstore));
		QRF(ext_buffer_pull_uint32(pext,
			&ppayload->notifdequeue.psink->padvise[i].sub_id));
	}
	QRF(ext_buffer_pull_uint32(pext, &ppayload->notifdequeue.timeval));
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
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->queryrows.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->queryrows.htable));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->queryrows.start));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->queryrows.count));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->queryrows.prestriction = NULL;
	} else {
		ppayload->queryrows.prestriction = pext->anew<RESTRICTION>();
		if (NULL == ppayload->queryrows.prestriction) {
			return FALSE;
		}
		QRF(ext_buffer_pull_restriction(pext, ppayload->queryrows.prestriction));
	}
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->queryrows.pproptags = NULL;
	} else {
		ppayload->queryrows.pproptags = pext->anew<PROPTAG_ARRAY>();
		if (NULL == ppayload->queryrows.pproptags) {
			return FALSE;
		}
		QRF(ext_buffer_pull_proptag_array(pext, ppayload->queryrows.pproptags));
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
	QRF(ext_buffer_pull_guid(pext, &ppayload->setcolumns.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setcolumns.htable));
	ppayload->setcolumns.pproptags = pext->anew<PROPTAG_ARRAY>();
	if (NULL == ppayload->setcolumns.pproptags) {
		return FALSE;
	}
	QRF(ext_buffer_pull_proptag_array(pext, ppayload->setcolumns.pproptags));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setcolumns.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_seekrow_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->seekrow.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->seekrow.htable));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->seekrow.bookmark));
	QRF(ext_buffer_pull_int32(pext, &ppayload->seekrow.seek_rows));
	return TRUE;
}

static BOOL rpc_ext_push_seekrow_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_int32(pext, ppayload->seekrow.sought_rows));
	return TRUE;
}

static BOOL rpc_ext_pull_sorttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->sorttable.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->sorttable.htable));
	ppayload->sorttable.psortset = pext->anew<SORTORDER_SET>();
	if (NULL == ppayload->sorttable.psortset) {
		return FALSE;
	}
	QRF(ext_buffer_pull_sortorder_set(pext, ppayload->sorttable.psortset));
	return TRUE;
}

static BOOL rpc_ext_pull_getrowcount_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->getrowcount.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getrowcount.htable));
	return TRUE;
}

static BOOL rpc_ext_push_getrowcount_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->getrowcount.count));
	return TRUE;
}

static BOOL rpc_ext_pull_restricttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->restricttable.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->restricttable.htable));
	ppayload->restricttable.prestriction = pext->anew<RESTRICTION>();
	if (NULL == ppayload->restricttable.prestriction) {
		return FALSE;
	}
	QRF(ext_buffer_pull_restriction(pext, ppayload->restricttable.prestriction));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->restricttable.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_findrow_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->findrow.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->findrow.htable));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->findrow.bookmark));
	ppayload->findrow.prestriction = pext->anew<RESTRICTION>();
	if (NULL == ppayload->findrow.prestriction) {
		return FALSE;
	}
	QRF(ext_buffer_pull_restriction(pext, ppayload->findrow.prestriction));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->findrow.flags));
	return TRUE;
}

static BOOL rpc_ext_push_findrow_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->findrow.row_idx));
	return TRUE;
}

static BOOL rpc_ext_pull_createbookmark_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->createbookmark.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->createbookmark.htable));
	return TRUE;
}

static BOOL rpc_ext_push_createbookmark_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->createbookmark.bookmark));
	return TRUE;
}

static BOOL rpc_ext_pull_freebookmark_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->freebookmark.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->freebookmark.htable));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->freebookmark.bookmark));
	return TRUE;
}

static BOOL rpc_ext_pull_getreceivefolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->getreceivefolder.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getreceivefolder.hstore));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->getreceivefolder.pstrclass = NULL;
	} else {
		QRF(ext_buffer_pull_string(pext, &ppayload->getreceivefolder.pstrclass));
	}
	return TRUE;
}

static BOOL rpc_ext_push_getreceivefolder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->getreceivefolder.entryid));
	return TRUE;
}

static BOOL rpc_ext_pull_modifyrecipients_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->modifyrecipients.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->modifyrecipients.hmessage));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->modifyrecipients.flags));
	ppayload->modifyrecipients.prcpt_list = pext->anew<TARRAY_SET>();
	if (NULL == ppayload->modifyrecipients.prcpt_list) {
		return FALSE;
	}
	QRF(ext_buffer_pull_tarray_set(pext, ppayload->modifyrecipients.prcpt_list));
	return TRUE;
}

static BOOL rpc_ext_pull_submitmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->submitmessage.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->submitmessage.hmessage));
	return TRUE;
}

static BOOL rpc_ext_pull_loadattachmenttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->loadattachmenttable.hsession));
	QRF(ext_buffer_pull_uint32(pext,
		&ppayload->loadattachmenttable.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_loadattachmenttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->loadattachmenttable.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_openattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->openattachment.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openattachment.hmessage));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openattachment.attach_id));
	return TRUE;
}

static BOOL rpc_ext_push_openattachment_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->openattachment.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_createattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->createattachment.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->createattachment.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_createattachment_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->createattachment.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_deleteattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->deleteattachment.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deleteattachment.hmessage));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deleteattachment.attach_id));
	return TRUE;
}

static BOOL rpc_ext_pull_setpropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->setpropvals.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setpropvals.hobject));
	ppayload->setpropvals.ppropvals = pext->anew<TPROPVAL_ARRAY>();
	if (NULL == ppayload->setpropvals.ppropvals) {
		return FALSE;
	}
	QRF(ext_buffer_pull_tpropval_array(pext, ppayload->setpropvals.ppropvals));
	return TRUE;
}

static BOOL rpc_ext_pull_getpropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->getpropvals.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getpropvals.hobject));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->getpropvals.pproptags = NULL;
	} else {
		ppayload->getpropvals.pproptags = pext->anew<PROPTAG_ARRAY>();
		if (NULL == ppayload->getpropvals.pproptags) {
			return FALSE;
		}
		QRF(ext_buffer_pull_proptag_array(pext, ppayload->getpropvals.pproptags));
	}
	return TRUE;
}

static BOOL rpc_ext_push_getpropvals_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_tpropval_array(pext, &ppayload->getpropvals.propvals));
	return TRUE;
}

static BOOL rpc_ext_pull_deletepropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->deletepropvals.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->deletepropvals.hobject));
	ppayload->deletepropvals.pproptags = cu_alloc<PROPTAG_ARRAY>();
	if (NULL == ppayload->deletepropvals.pproptags) {
		return FALSE;
	}
	QRF(ext_buffer_pull_proptag_array(pext, ppayload->deletepropvals.pproptags));
	return TRUE;
}

static BOOL rpc_ext_pull_setmessagereadflag_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->setmessagereadflag.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setmessagereadflag.hmessage));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setmessagereadflag.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_openembedded_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->openembedded.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openembedded.hattachment));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->openembedded.flags));
	return TRUE;
}

static BOOL rpc_ext_push_openembedded_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->openembedded.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_getnamedpropids_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->getnamedpropids.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getnamedpropids.hstore));
	ppayload->getnamedpropids.ppropnames = pext->anew<PROPNAME_ARRAY>();
	if (NULL == ppayload->getnamedpropids.ppropnames) {
		return FALSE;
	}
	QRF(ext_buffer_pull_propname_array(pext, ppayload->getnamedpropids.ppropnames));
	return TRUE;
}

static BOOL rpc_ext_push_getnamedpropids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_propid_array(pext, &ppayload->getnamedpropids.propids));
	return TRUE;
}

static BOOL rpc_ext_pull_getpropnames_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->getpropnames.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getpropnames.hstore));
	ppayload->getpropnames.ppropids = pext->anew<PROPID_ARRAY>();
	if (NULL == ppayload->getpropnames.ppropids) {
		return FALSE;
	}
	QRF(ext_buffer_pull_propid_array(pext, ppayload->getpropnames.ppropids));
	return TRUE;
}

static BOOL rpc_ext_push_getpropnames_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_propname_array(pext, &ppayload->getpropnames.propnames));
	return TRUE;
}

static BOOL rpc_ext_pull_copyto_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->copyto.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copyto.hsrcobject));
	ppayload->copyto.pexclude_proptags = pext->anew<PROPTAG_ARRAY>();
	if (NULL == ppayload->copyto.pexclude_proptags) {
		return FALSE;
	}
	QRF(ext_buffer_pull_proptag_array(pext, ppayload->copyto.pexclude_proptags));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copyto.hdstobject));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->copyto.flags));
	return TRUE;
}

static BOOL rpc_ext_pull_savechanges_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->savechanges.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->savechanges.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_hierarchysync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->hierarchysync.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->hierarchysync.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_hierarchysync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->hierarchysync.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_contentsync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->contentsync.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->contentsync.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_contentsync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->contentsync.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_configsync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->configsync.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->configsync.hctx));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->configsync.flags));
	ppayload->configsync.pstate = pext->anew<BINARY>();
	if (NULL == ppayload->configsync.pstate) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary(pext, ppayload->configsync.pstate));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->configsync.prestriction = NULL;
	} else {
		ppayload->configsync.prestriction = pext->anew<RESTRICTION>();
		if (NULL == ppayload->configsync.prestriction) {
			return FALSE;
		}
		QRF(ext_buffer_pull_restriction(pext, ppayload->configsync.prestriction));
	}
	return TRUE;
}

static BOOL rpc_ext_push_configsync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_bool(pext, ppayload->configsync.b_changed));
	QRF(ext_buffer_push_uint32(pext, ppayload->configsync.count));
	return TRUE;
}

static BOOL rpc_ext_pull_statesync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->statesync.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->configsync.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_statesync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->statesync.state));
	return TRUE;
}

static BOOL rpc_ext_pull_syncmessagechange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->syncmessagechange.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->syncmessagechange.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_syncmessagechange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_bool(pext, ppayload->syncmessagechange.b_new));
	QRF(ext_buffer_push_tpropval_array(pext, &ppayload->syncmessagechange.proplist));
	return TRUE;
}

static BOOL rpc_ext_pull_syncfolderchange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->syncfolderchange.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->syncfolderchange.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_syncfolderchange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_tpropval_array(pext, &ppayload->syncfolderchange.proplist));
	return TRUE;
}

static BOOL rpc_ext_pull_syncreadstatechanges_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->syncreadstatechanges.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->syncreadstatechanges.hctx));
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
	QRF(ext_buffer_pull_guid(pext, &ppayload->syncdeletions.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->syncdeletions.hctx));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->syncdeletions.flags));
	return TRUE;
}

static BOOL rpc_ext_push_syncdeletions_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary_array(pext, &ppayload->syncdeletions.bins));
	return TRUE;
}

static BOOL rpc_ext_pull_hierarchyimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->hierarchyimport.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->hierarchyimport.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_hierarchyimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->hierarchyimport.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_contentimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->contentimport.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->contentimport.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_contentimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->contentimport.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_configimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->configimport.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->configimport.hctx));
	QRF(ext_buffer_pull_uint8(pext, &ppayload->configimport.sync_type));
	ppayload->configimport.pstate = pext->anew<BINARY>();
	if (NULL == ppayload->configimport.pstate) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary(pext, ppayload->configimport.pstate));
	return TRUE;
}

static BOOL rpc_ext_pull_stateimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->stateimport.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->stateimport.hctx));
	return TRUE;
}

static BOOL rpc_ext_push_stateimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->stateimport.state));
	return TRUE;
}

static BOOL rpc_ext_pull_importmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->importmessage.hsession));
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importmessage.hctx)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importmessage.flags)) {
		return FALSE;
	}
	ppayload->importmessage.pproplist = pext->anew<TPROPVAL_ARRAY>();
	if (NULL == ppayload->importmessage.pproplist) {
		return FALSE;
	}
	QRF(ext_buffer_pull_tpropval_array(pext, ppayload->importmessage.pproplist));
	return TRUE;
}

static BOOL rpc_ext_push_importmessage_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_uint32(pext, ppayload->importmessage.hobject));
	return TRUE;
}

static BOOL rpc_ext_pull_importfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->importfolder.hsession));
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importfolder.hctx)) {
		return FALSE;
	}
	ppayload->importfolder.pproplist = pext->anew<TPROPVAL_ARRAY>();
	if (NULL == ppayload->importfolder.pproplist) {
		return FALSE;
	}
	QRF(ext_buffer_pull_tpropval_array(pext, ppayload->importfolder.pproplist));
	return TRUE;
}

static BOOL rpc_ext_pull_importdeletion_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->importdeletion.hsession));
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importdeletion.hctx)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importdeletion.flags)) {
		return FALSE;
	}
	ppayload->importdeletion.pbins = pext->anew<BINARY_ARRAY>();
	if (NULL == ppayload->importdeletion.pbins) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary_array(pext, ppayload->importdeletion.pbins));
	return TRUE;
}

static BOOL rpc_ext_pull_importreadstates_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->importreadstates.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->importreadstates.hctx));
	ppayload->importreadstates.pstates = pext->anew<STATE_ARRAY>();
	if (NULL == ppayload->importreadstates.pstates) {
		return FALSE;
	}
	return rpc_ext_pull_state_array(pext,
		ppayload->importreadstates.pstates);
}

static BOOL rpc_ext_pull_getsearchcriteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->getsearchcriteria.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->getsearchcriteria.hfolder));
	return TRUE;
}

static BOOL rpc_ext_push_getsearchcriteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{	
	QRF(ext_buffer_push_binary_array(pext, &ppayload->getsearchcriteria.folder_array));
	if (NULL == ppayload->getsearchcriteria.prestriction) {
		QRF(ext_buffer_push_uint8(pext, 0));
	} else {
		QRF(ext_buffer_push_uint8(pext, 1));
		QRF(ext_buffer_push_restriction(pext,
			ppayload->getsearchcriteria.prestriction));
	}
	QRF(ext_buffer_push_uint32(pext,
		ppayload->getsearchcriteria.search_stat));
	return TRUE;
}

static BOOL rpc_ext_pull_setsearchcriteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	QRF(ext_buffer_pull_guid(pext, &ppayload->setsearchcriteria.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setsearchcriteria.hfolder));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->setsearchcriteria.flags));
	ppayload->setsearchcriteria.pfolder_array = pext->anew<BINARY_ARRAY>();
	if (NULL == ppayload->setsearchcriteria.pfolder_array) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary_array(pext, ppayload->setsearchcriteria.pfolder_array));
	QRF(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->setsearchcriteria.prestriction = NULL;
	} else {
		ppayload->setsearchcriteria.prestriction = pext->anew<RESTRICTION>();
		if (NULL == ppayload->setsearchcriteria.prestriction) {
			return FALSE;
		}
		QRF(ext_buffer_pull_restriction(pext, ppayload->setsearchcriteria.prestriction));
	}
	return TRUE;
}

static BOOL rpc_ext_pull_messagetorfc822_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->messagetorfc822.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->messagetorfc822.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_messagetorfc822_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->messagetorfc822.eml_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_rfc822tomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext,
		&ppayload->rfc822tomessage.hsession));
	if (ext_buffer_pull_uint32(pext,
		&ppayload->rfc822tomessage.hmessage)) {
		return FALSE;
	}
	ppayload->rfc822tomessage.peml_bin = pext->anew<BINARY>();
	if (NULL == ppayload->rfc822tomessage.peml_bin) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary(pext, ppayload->rfc822tomessage.peml_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_messagetoical_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->messagetoical.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->messagetoical.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_messagetoical_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->messagetoical.ical_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_icaltomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->icaltomessage.hsession));
	if (ext_buffer_pull_uint32(pext,
		&ppayload->icaltomessage.hmessage)) {
		return FALSE;
	}
	ppayload->icaltomessage.pical_bin = pext->anew<BINARY>();
	if (NULL == ppayload->icaltomessage.pical_bin) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary(pext, ppayload->icaltomessage.pical_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_messagetovcf_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->messagetovcf.hsession));
	QRF(ext_buffer_pull_uint32(pext, &ppayload->messagetovcf.hmessage));
	return TRUE;
}

static BOOL rpc_ext_push_messagetovcf_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	QRF(ext_buffer_push_binary(pext, &ppayload->messagetovcf.vcf_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_vcftomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->vcftomessage.hsession));
	if (ext_buffer_pull_uint32(pext,
		&ppayload->vcftomessage.hmessage)) {
		return FALSE;
	}
	ppayload->vcftomessage.pvcf_bin = pext->anew<BINARY>();
	if (NULL == ppayload->vcftomessage.pvcf_bin) {
		return FALSE;
	}
	QRF(ext_buffer_pull_binary(pext, ppayload->vcftomessage.pvcf_bin));
	return TRUE;
}

static BOOL rpc_ext_pull_getuseravailability_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->getuseravailability.hsession));
	QRF(ext_buffer_pull_binary(pext, &ppayload->getuseravailability.entryid));
	QRF(ext_buffer_pull_uint64(pext, &ppayload->getuseravailability.starttime));
	QRF(ext_buffer_pull_uint64(pext, &ppayload->getuseravailability.endtime));
	return TRUE;
}

static BOOL rpc_ext_push_getuseravailability_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (NULL == ppayload->getuseravailability.result_string) {
		QRF(ext_buffer_push_uint8(pext, 0));
		return TRUE;
	}
	QRF(ext_buffer_push_uint8(pext, 1));
	QRF(ext_buffer_push_string(pext,
		ppayload->getuseravailability.result_string));
	return TRUE;
}

static BOOL rpc_ext_pull_setpasswd_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_string(pext, &ppayload->setpasswd.username));
	QRF(ext_buffer_pull_string(pext, &ppayload->setpasswd.passwd));
	QRF(ext_buffer_pull_string(pext, &ppayload->setpasswd.new_passwd));
	return TRUE;
}

static BOOL rpc_ext_pull_linkmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	QRF(ext_buffer_pull_guid(pext, &ppayload->linkmessage.hsession));
	QRF(ext_buffer_pull_binary(pext, &ppayload->linkmessage.search_entryid));
	QRF(ext_buffer_pull_binary(pext, &ppayload->linkmessage.message_entryid));
	return TRUE;
}

BOOL rpc_ext_pull_request(const BINARY *pbin_in,
	RPC_REQUEST *prequest)
{
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
	QRF(ext_buffer_pull_uint8(&ext_pull, &prequest->call_id));
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

	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_WCOUNT)) {
		return FALSE;
	}
	QRF(ext_buffer_push_uint8(&ext_push, zcore_response::SUCCESS));
	if (EXT_ERR_SUCCESS != presponse->result) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
			&ext_push, 4)) {
			ext_buffer_push_free(&ext_push);
			return FALSE;	
		}
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
			&ext_push, presponse->result)) {
			ext_buffer_push_free(&ext_push);
			return FALSE;
		}
		pbin_out->cb = ext_push.offset;
		pbin_out->pb = ext_buffer_push_release(&ext_push);
		return TRUE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
		&ext_push, sizeof(uint32_t))) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		&ext_push, presponse->result)) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
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
	if (FALSE == b_result) {
		ext_buffer_push_free(&ext_push);
		return FALSE;
	}
	pbin_out->cb = ext_push.offset;
	ext_push.offset = 1;
	ext_buffer_push_uint32(&ext_push,
		pbin_out->cb - sizeof(uint32_t) - 1);
	pbin_out->pb = ext_buffer_push_release(&ext_push);
	return TRUE;
}
