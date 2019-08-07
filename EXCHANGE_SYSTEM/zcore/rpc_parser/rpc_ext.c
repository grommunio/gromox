#include "rpc_ext.h"
#include "ext_buffer.h"
#include "common_util.h"

static BOOL rpc_ext_pull_zmovecopy_action(
	EXT_PULL *pext, ZMOVECOPY_ACTION *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->store_eid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->folder_eid)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_pull_zreply_action(
	EXT_PULL *pext, ZREPLY_ACTION *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->message_eid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &r->template_guid)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_pull_recipient_block(
	EXT_PULL *pext, RECIPIENT_BLOCK *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(pext, &r->reserved)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		return FALSE;
	}
	r->ppropval = pext->alloc(sizeof(TAGGED_PROPVAL)*r->count);
	if (NULL == r->ppropval) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_tagged_propval(
			pext, &r->ppropval[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_forwarddelegate_action(
	EXT_PULL *pext, FORWARDDELEGATE_ACTION *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		return FALSE;
	}
	r->pblock = pext->alloc(sizeof(RECIPIENT_BLOCK)*r->count);
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
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &r->length)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &r->type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->flavor)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->flags)) {
		return FALSE;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		r->pdata = pext->alloc(sizeof(ZMOVECOPY_ACTION));
		if (NULL == r->pdata) {
			return FALSE;
		}
		return rpc_ext_pull_zmovecopy_action(pext, r->pdata);
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		r->pdata = pext->alloc(sizeof(ZREPLY_ACTION));
		if (NULL == r->pdata) {
			return FALSE;
		}
		return rpc_ext_pull_zreply_action(pext, r->pdata);
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		r->pdata = pext->alloc(tmp_len);
		if (NULL == r->pdata) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_bytes(
			pext, r->pdata, tmp_len)) {
			return FALSE;	
		}
		return TRUE;
	case ACTION_TYPE_OP_BOUNCE:
		r->pdata = pext->alloc(sizeof(uint32_t));
		if (NULL == r->pdata) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
			pext, r->pdata)) {
			return FALSE;	
		}
		return TRUE;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		r->pdata = pext->alloc(sizeof(FORWARDDELEGATE_ACTION));
		if (NULL == r->pdata) {
			return FALSE;
		}
		return rpc_ext_pull_forwarddelegate_action(pext, r->pdata);
	case ACTION_TYPE_OP_TAG:
		r->pdata = pext->alloc(sizeof(TAGGED_PROPVAL));
		if (NULL == r->pdata) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_tagged_propval(
			pext, r->pdata)) {
			return FALSE;	
		}
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
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		return FALSE;
	}
	r->pblock = pext->alloc(sizeof(ACTION_BLOCK)*r->count);
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
	if (0x3000 == (type & 0x3000)) {
		type &= ~0x3000;
	}
	switch (type) {
	case PROPVAL_TYPE_SHORT:
		*ppval = pext->alloc(sizeof(uint16_t));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
			pext, *ppval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_LONG:
	case PROPVAL_TYPE_ERROR:
		*ppval = pext->alloc(sizeof(uint32_t));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_FLOAT:
		*ppval = pext->alloc(sizeof(float));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_float(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		*ppval = pext->alloc(sizeof(double));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_double(
			pext, *ppval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_BYTE:
		*ppval = pext->alloc(sizeof(uint8_t));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		*ppval = pext->alloc(sizeof(uint64_t));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(
			pext, *ppval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_STRING:
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
			pext, (char**)ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_WSTRING:
		if (EXT_ERR_SUCCESS != ext_buffer_pull_wstring(
			pext, (char**)ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_GUID:
		*ppval = pext->alloc(sizeof(GUID));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_RESTRICTION:
		*ppval = pext->alloc(sizeof(RESTRICTION));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			pext, *ppval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_RULE:
		*ppval = pext->alloc(sizeof(RULE_ACTIONS));
		if (NULL == *ppval) {
			return FALSE;
		}
		return rpc_ext_pull_rule_actions(pext, *ppval);
	case PROPVAL_TYPE_BINARY:
		*ppval = pext->alloc(sizeof(BINARY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
			pext, *ppval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_SHORT_ARRAY:
		*ppval = pext->alloc(sizeof(SHORT_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_short_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONG_ARRAY:
		*ppval = pext->alloc(sizeof(LONG_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_long_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		*ppval = pext->alloc(sizeof(LONGLONG_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_longlong_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_STRING_ARRAY:
		*ppval = pext->alloc(sizeof(STRING_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_WSTRING_ARRAY:
		*ppval = pext->alloc(sizeof(STRING_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_wstring_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_GUID_ARRAY:
		*ppval = pext->alloc(sizeof(GUID_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_guid_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_BINARY_ARRAY:
		*ppval = pext->alloc(sizeof(BINARY_ARRAY));
		if (NULL == *ppval) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
			pext, *ppval)) {
			return FALSE;	
		}
		return TRUE;
	default:
		return FALSE;
	}
}

static BOOL rpc_ext_pull_tagged_propval(
	EXT_PULL *pext, TAGGED_PROPVAL *r)
{	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->proptag)) {
		return FALSE;
	}
	return rpc_ext_pull_propval(pext,
		r->proptag&0xFFFF, &r->pvalue);
}

static BOOL rpc_ext_pull_tpropval_array(
	EXT_PULL *pext, TPROPVAL_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		r->ppropval = NULL;
		return TRUE;
	}
	r->ppropval = pext->alloc(sizeof(TAGGED_PROPVAL)*r->count);
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

static BOOL rpc_ext_pull_tarray_set(EXT_PULL *pext, TARRAY_SET *r)
{
	int i;

	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		r->pparray = NULL;
		return TRUE;
	}
	r->pparray = pext->alloc(sizeof(TPROPVAL_ARRAY*)*r->count);
	if (NULL == r->pparray) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		r->pparray[i] = pext->alloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == r->pparray[i]) {
			return FALSE;
		}
		if (FALSE == rpc_ext_pull_tpropval_array(
			pext, r->pparray[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_rule_data(
	EXT_PULL *pext, RULE_DATA *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &r->flags)) {
		return FALSE;
	}
	return rpc_ext_pull_tpropval_array(pext, &r->propvals);
}

static BOOL rpc_ext_pull_rule_list(
	EXT_PULL *pext, RULE_LIST *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		r->prule = NULL;
		return TRUE;
	}
	r->prule = pext->alloc(sizeof(RULE_DATA)*r->count);
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
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->flags)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->member_rights)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_permission_set(
	EXT_PULL *pext, PERMISSION_SET *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &r->count)) {
		return FALSE;
	}
	r->prows = pext->alloc(sizeof(PERMISSION_ROW)*r->count);
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
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->source_key)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->message_flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_state_array(
	EXT_PULL *pext, STATE_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		r->pstate = NULL;
		return TRUE;
	}
	r->pstate = pext->alloc(sizeof(MESSAGE_STATE)*r->count);
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

static BOOL rpc_ext_pull_newmail_znotification(
	EXT_PULL *pext, NEWMAIL_ZNOTIFICATION *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &r->parentid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->flags)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
		pext, &r->message_class)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->message_flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_object_znotification(
	EXT_PULL *pext, OBJECT_ZNOTIFICATION *r)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->object_type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		r->pentryid = NULL;
	} else {
		r->pentryid = pext->alloc(sizeof(BINARY));
		if (NULL == r->pentryid) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
			pext, r->pentryid)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		r->pparentid = NULL;
	} else {
		r->pparentid = pext->alloc(sizeof(BINARY));
		if (NULL == r->pparentid) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
			pext, r->pparentid)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		r->pold_entryid = NULL;
	} else {
		r->pold_entryid = pext->alloc(sizeof(BINARY));
		if (NULL == r->pold_entryid) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
			pext, r->pold_entryid)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		r->pold_parentid = NULL;
	} else {
		r->pold_parentid = pext->alloc(sizeof(BINARY));
		if (NULL == r->pold_parentid) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
			pext, r->pold_parentid)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		r->pproptags = NULL;
	} else {
		r->pproptags = pext->alloc(sizeof(PROPTAG_ARRAY));
		if (NULL == r->pproptags) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
			pext, r->pproptags)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_znotification(
	EXT_PULL *pext, ZNOTIFICATION *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->event_type)) {
		return FALSE;
	}
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		r->pnotification_data =
			pext->alloc(sizeof(NEWMAIL_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return FALSE;
		}
		return rpc_ext_pull_newmail_znotification(
					pext, r->pnotification_data);
	case EVENT_TYPE_OBJECTCREATED:
	case EVENT_TYPE_OBJECTDELETED:
	case EVENT_TYPE_OBJECTMODIFIED:
	case EVENT_TYPE_OBJECTMOVED:
	case EVENT_TYPE_OBJECTCOPIED:
	case EVENT_TYPE_SEARCHCOMPLETE:
		r->pnotification_data =
			pext->alloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return FALSE;
		}
		return rpc_ext_pull_object_znotification(
					pext, r->pnotification_data);
	default:
		r->pnotification_data = NULL;
		return TRUE;
	}
}

static BOOL rpc_ext_pull_znotification_array(
	EXT_PULL *pext, ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	if (TRUE != ext_buffer_pull_uint16(pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		r->ppnotification = NULL;
		return TRUE;
	}
	r->ppnotification = pext->alloc(sizeof(ZNOTIFICATION*)*r->count);
	if (NULL == r->ppnotification) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_znotification(
			pext, r->ppnotification[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_freebusy_block(
	EXT_PULL *pext, FREEBUSY_BLOCK *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(
		pext, &r->nttime_start)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(
		pext, &r->nttime_end)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &r->status)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_fbblock_array(
	EXT_PULL *pext, FBBLOCK_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &r->count)) {
		return FALSE;
	}
	if (0 == r->count) {
		r->pblocks = NULL;
		return TRUE;
	}
	r->pblocks = pext->alloc(sizeof(FREEBUSY_BLOCK)*r->count);
	if (NULL == r->pblocks) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_pull_freebusy_block(
			pext, &r->pblocks[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

/*---------------------------------------------------------------------------*/

static BOOL rpc_ext_push_zmovecopy_action(
	EXT_PUSH *pext, const ZMOVECOPY_ACTION *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->store_eid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->folder_eid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_zreply_action(
	EXT_PUSH *pext, const ZREPLY_ACTION *r)
{	
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->message_eid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_guid(
		pext, &r->template_guid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_recipient_block(
	EXT_PUSH *pext, const RECIPIENT_BLOCK *r)
{
	int i;
	
	if (0 == r->count) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(pext, r->reserved)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(pext, r->count)) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_tagged_propval(
			pext, &r->ppropval[i])) {
			return FALSE;
		}
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
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(pext, r->count)) {
		return FALSE;
	}
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
	if (EXT_ERR_SUCCESS != ext_buffer_push_advance(
		pext, sizeof(uint16_t))) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		pext, r->type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->flavor)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->flags)) {
		return FALSE;
	}
	switch (r->type) {
	case ACTION_TYPE_OP_MOVE:
	case ACTION_TYPE_OP_COPY:
		if (TRUE != rpc_ext_push_zmovecopy_action(
			pext, r->pdata)) {
			return FALSE;
		}
		break;
	case ACTION_TYPE_OP_REPLY:
	case ACTION_TYPE_OP_OOF_REPLY:
		if (TRUE != rpc_ext_push_zreply_action(
			pext, r->pdata)) {
			return FALSE;
		}
		break;
	case ACTION_TYPE_OP_DEFER_ACTION:
		tmp_len = r->length - sizeof(uint8_t) - 2*sizeof(uint32_t);
		if (EXT_ERR_SUCCESS != ext_buffer_push_bytes(
			pext, r->pdata, tmp_len)) {
			return FALSE;
		}
		break;
	case ACTION_TYPE_OP_BOUNCE:
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
			pext, *(uint32_t*)r->pdata)) {
			return FALSE;
		}
		break;
	case ACTION_TYPE_OP_FORWARD:
	case ACTION_TYPE_OP_DELEGATE:
		return rpc_ext_push_forwarddelegate_action(pext, r->pdata);
	case ACTION_TYPE_OP_TAG:
		if (EXT_ERR_SUCCESS != ext_buffer_push_tagged_propval(
			pext, r->pdata)) {
			return FALSE;
		}
	case ACTION_TYPE_OP_DELETE:
	case ACTION_TYPE_OP_MARK_AS_READ:
		break;
	default:
		return FALSE;
	}
	tmp_len = pext->offset - (offset + sizeof(uint16_t));
	offset1 = pext->offset;
	pext->offset = offset;
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		pext, tmp_len)) {
		return FALSE;
	}
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
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		pext, r->count)) {
		return FALSE;
	}
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
	if (0x3000 == (type & 0x3000)) {
		type &= ~0x3000;
	}
	switch (type) {
	case PROPVAL_TYPE_SHORT:
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
			pext, *(uint16_t*)pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONG:
	case PROPVAL_TYPE_ERROR:
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
			pext, *(uint32_t*)pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_FLOAT:
		if (EXT_ERR_SUCCESS != ext_buffer_push_float(
			pext, *(float*)pval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		if (EXT_ERR_SUCCESS != ext_buffer_push_double(
			pext, *(double*)pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_BYTE:
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, *(uint8_t*)pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(
			pext, *(uint64_t*)pval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_STRING:
		if (EXT_ERR_SUCCESS != ext_buffer_push_string(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_WSTRING:
		if (EXT_ERR_SUCCESS != ext_buffer_push_wstring(
			pext, pval)) {
			return FALSE;
		}
		return TRUE;
	case PROPVAL_TYPE_GUID:
		if (EXT_ERR_SUCCESS != ext_buffer_push_guid(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_RESTRICTION:
		if (EXT_ERR_SUCCESS != ext_buffer_push_restriction(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_RULE:
		return rpc_ext_push_rule_actions(pext, pval);
	case PROPVAL_TYPE_BINARY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_SHORT_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_short_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONG_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_long_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_longlong_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_STRING_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_string_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_WSTRING_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_wstring_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_GUID_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_guid_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	case PROPVAL_TYPE_BINARY_ARRAY:
		if (EXT_ERR_SUCCESS != ext_buffer_push_binary_array(
			pext, pval)) {
			return FALSE;	
		}
		return TRUE;
	default:
		return FALSE;
	}
}

static BOOL rpc_ext_push_tagged_propval(
	EXT_PUSH *pext, const TAGGED_PROPVAL *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->proptag)) {
		return FALSE;
	}
	return rpc_ext_push_propval(pext,
		r->proptag&0xFFFF, r->pvalue);
}

static BOOL rpc_ext_push_tpropval_array(
	EXT_PUSH *pext, const TPROPVAL_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		pext, r->count)) {
		return FALSE;
	}
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
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->count)) {
		return FALSE;
	}
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
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->flags)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->member_rights)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_permission_set(
	EXT_PUSH *pext, const PERMISSION_SET *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		pext, r->count)) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_permission_row(
			pext, &r->prows[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_rule_data(
	EXT_PUSH *pext, const RULE_DATA *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		pext, r->flags)) {
		return FALSE;
	}
	return rpc_ext_push_tpropval_array(
					pext, &r->propvals);
}

static BOOL rpc_ext_push_rule_list(
	EXT_PUSH *pext, const RULE_LIST *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		pext, r->count)) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_rule_data(
			pext, &r->prule[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_message_state(
	EXT_PUSH *pext, const MESSAGE_STATE *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->source_key)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->message_flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_state_array(
	EXT_PUSH *pext, const STATE_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->count)) {
		return FALSE;
	}
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
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &r->parentid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->flags)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_string(
		pext, r->message_class)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->message_flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_object_znotification(
	EXT_PUSH *pext, const OBJECT_ZNOTIFICATION *r)
{	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->object_type)) {
		return FALSE;
	}
	if (NULL == r->pentryid) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 0)) {
			return FALSE;
		}
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 1)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS!= ext_buffer_push_binary(
			pext, r->pentryid)) {
			return FALSE;
		}
	}
	if (NULL == r->pparentid) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 0)) {
			return FALSE;
		}
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 1)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS!= ext_buffer_push_binary(
			pext, r->pparentid)) {
			return FALSE;
		}
	}
	if (NULL == r->pold_entryid) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 0)) {
			return FALSE;
		}
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 1)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS!= ext_buffer_push_binary(
			pext, r->pold_entryid)) {
			return FALSE;
		}
	}
	if (NULL == r->pold_parentid) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 0)) {
			return FALSE;
		}
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 1)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS!= ext_buffer_push_binary(
			pext, r->pold_parentid)) {
			return FALSE;
		}
	}
	if (NULL == r->pproptags) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(pext, 0)) {
			return FALSE;
		}
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
			pext, 1)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_push_proptag_array(
			pext, r->pproptags)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_znotification(
	EXT_PUSH *pext, const ZNOTIFICATION *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->event_type)) {
		return FALSE;
	}
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		return rpc_ext_push_newmail_znotification(
					pext, r->pnotification_data);
	case EVENT_TYPE_OBJECTCREATED:
	case EVENT_TYPE_OBJECTDELETED:
	case EVENT_TYPE_OBJECTMODIFIED:
	case EVENT_TYPE_OBJECTMOVED:
	case EVENT_TYPE_OBJECTCOPIED:
	case EVENT_TYPE_SEARCHCOMPLETE:
		return rpc_ext_push_object_znotification(
					pext, r->pnotification_data);
	default:
		return TRUE;
	}
}

static BOOL rpc_ext_push_znotification_array(
	EXT_PUSH *pext, const ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint16(
		pext, r->count)) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_znotification(
			pext, r->ppnotification[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_freebusy_block(
	EXT_PUSH *pext, const FREEBUSY_BLOCK *r)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(
		pext, r->nttime_start)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(
		pext, r->nttime_end)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		pext, r->status)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_fbblock_array(
	EXT_PUSH *pext, const FBBLOCK_ARRAY *r)
{
	int i;
	
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, r->count)) {
		return FALSE;
	}
	for (i=0; i<r->count; i++) {
		if (TRUE != rpc_ext_push_freebusy_block(
			pext, &r->pblocks[i])) {
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
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
		pext, &ppayload->logon.username)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->logon.password = NULL;
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
			pext, &ppayload->logon.password)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->logon.flags)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_push_logon_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_guid(
		pext, &ppayload->logon.hsession)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_checksession_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->unloadobject.hsession)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_pull_uinfo_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
		pext, &ppayload->uinfo.username)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_uinfo_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->uinfo.entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_string(
		pext, ppayload->uinfo.pdisplay_name)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_string(
		pext, ppayload->uinfo.px500dn)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_pull_unloadobject_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->unloadobject.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->unloadobject.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openentry.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &ppayload->openentry.entryid)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openentry.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		pext, ppayload->openentry.mapi_type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openentry.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openstoreentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openstoreentry.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openstoreentry.hobject)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &ppayload->openstoreentry.entryid)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openstoreentry.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openstoreentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		pext, ppayload->openstoreentry.mapi_type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openstoreentry.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openabentry_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openabentry.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &ppayload->openabentry.entryid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openabentry_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		pext, ppayload->openabentry.mapi_type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openabentry.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_resolvename_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->resolvename.hsession)) {
		return FALSE;
	}
	ppayload->resolvename.pcond_set =
		pext->alloc(sizeof(TARRAY_SET));
	if (NULL == ppayload->resolvename.pcond_set) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tarray_set(
		pext, ppayload->resolvename.pcond_set)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_resolvename_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_tarray_set(
		pext, &ppayload->resolvename.result_set)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openrules_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openrules.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openrules.hfolder)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openrules_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openrules.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getpermissions_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->getpermissions.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getpermissions.hobject)) {
		return FALSE;	
	}
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
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->modifypermissions.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->modifypermissions.hfolder)) {
		return FALSE;
	}
	ppayload->modifypermissions.pset =
		pext->alloc(sizeof(PERMISSION_SET));
	if (NULL == ppayload->modifypermissions.pset) {
		return FALSE;
	}
	return rpc_ext_pull_permission_set(pext,
			ppayload->modifypermissions.pset);
}

static BOOL rpc_ext_pull_modifyrules_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->modifyrules.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->modifyrules.hrules)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->modifyrules.flags)) {
		return FALSE;
	}
	ppayload->modifyrules.plist =
		pext->alloc(sizeof(RULE_LIST));
	if (NULL == ppayload->modifyrules.plist) {
		return FALSE;
	}
	return rpc_ext_pull_rule_list(pext,
			ppayload->modifyrules.plist);
}

static BOOL rpc_ext_pull_getabgal_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->getabgal.hsession)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getabgal_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->getabgal.entryid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_loadstoretable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->loadstoretable.hsession)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_push_loadstoretable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->loadstoretable.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openstore_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openstore.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &ppayload->openstore.entryid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openstore_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openstore.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openpropfilesec_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openpropfilesec.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->openpropfilesec.puid = NULL;
	} else {
		ppayload->openpropfilesec.puid =
			pext->alloc(sizeof(FLATUID));
		if (NULL == ppayload->openpropfilesec.puid) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_bytes(
			pext, (void*)ppayload->openpropfilesec.puid,
			sizeof(FLATUID))) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_openpropfilesec_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openpropfilesec.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_loadhierarchytable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->loadhierarchytable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->loadhierarchytable.hfolder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->loadhierarchytable.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_loadhierarchytable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->loadhierarchytable.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_loadcontenttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->loadcontenttable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->loadcontenttable.hfolder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->loadcontenttable.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_loadcontenttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->loadcontenttable.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_loadrecipienttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->loadrecipienttable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->loadrecipienttable.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_loadrecipienttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->loadrecipienttable.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_loadruletable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->loadruletable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->loadruletable.hrules)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_push_loadruletable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->loadruletable.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_createmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->createmessage.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->createmessage.hfolder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->createmessage.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_createmessage_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->createmessage.hobject)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_pull_deletemessages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->deletemessages.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deletemessages.hfolder)) {
		return FALSE;
	}
	ppayload->deletemessages.pentryids =
		pext->alloc(sizeof(BINARY_ARRAY));
	if (NULL == ppayload->deletemessages.pentryids) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
		pext, ppayload->deletemessages.pentryids)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deletemessages.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_copymessages_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->copymessages.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copymessages.hsrcfolder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copymessages.hdstfolder)) {
		return FALSE;	
	}
	ppayload->copymessages.pentryids =
		pext->alloc(sizeof(BINARY_ARRAY));
	if (NULL == ppayload->copymessages.pentryids) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
		pext, ppayload->copymessages.pentryids)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copymessages.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_setreadflags_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->setreadflags.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setreadflags.hfolder)) {
		return FALSE;
	}
	ppayload->setreadflags.pentryids =
		pext->alloc(sizeof(BINARY_ARRAY));
	if (NULL == ppayload->setreadflags.pentryids) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
		pext, ppayload->setreadflags.pentryids)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setreadflags.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_createfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->createfolder.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
		&ppayload->createfolder.hparent_folder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->createfolder.folder_type)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
		pext, &ppayload->createfolder.folder_name)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_string(pext,
		&ppayload->createfolder.folder_comment)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->createfolder.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_createfolder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->createfolder.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_deletefolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->deletefolder.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deletefolder.hparent_folder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &ppayload->deletefolder.entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deletefolder.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_emptyfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->emptyfolder.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->emptyfolder.hfolder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->emptyfolder.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_copyfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->copyfolder.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copyfolder.hsrc_folder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, &ppayload->copyfolder.entryid)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copyfolder.hdst_folder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->copyfolder.new_name = NULL;
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
			pext, &ppayload->copyfolder.new_name)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copyfolder.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getstoreentryid_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_string(pext,
		&ppayload->getstoreentryid.mailbox_dn)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getstoreentryid_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->getstoreentryid.entryid)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_pull_entryidfromsourcekey_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->entryidfromsourcekey.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
		&ppayload->entryidfromsourcekey.hstore)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(pext,
		&ppayload->entryidfromsourcekey.folder_key)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->entryidfromsourcekey.pmessage_key = NULL;
	} else {
		ppayload->entryidfromsourcekey.pmessage_key =
						pext->alloc(sizeof(BINARY));
		if (NULL == ppayload->entryidfromsourcekey.pmessage_key) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(pext,
			ppayload->entryidfromsourcekey.pmessage_key)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_entryidfromsourcekey_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(pext,
		&ppayload->entryidfromsourcekey.entryid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_storeadvise_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->storeadvise.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->storeadvise.hstore)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->storeadvise.pentryid = NULL;
	} else {
		ppayload->storeadvise.pentryid =
			pext->alloc(sizeof(BINARY));
		if (NULL == ppayload->storeadvise.pentryid) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
			pext, ppayload->storeadvise.pentryid)) {
			return FALSE;	
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->storeadvise.event_mask)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_storeadvise_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->storeadvise.sub_id)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_unadvise_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->unadvise.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->unadvise.hstore)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->unadvise.sub_id)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_notifdequeue_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	ppayload->notifdequeue.psink =
		pext->alloc(sizeof(NOTIF_SINK));
	if (NULL == ppayload->notifdequeue.psink) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->notifdequeue.psink->hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint16(
		pext, &ppayload->notifdequeue.psink->count)) {
		return FALSE;
	}
	ppayload->notifdequeue.psink->padvise
		= pext->alloc(sizeof(ADVISE_INFO)*
		ppayload->notifdequeue.psink->count);
	if (NULL == ppayload->notifdequeue.psink->padvise) {
		return FALSE;
	}
	for (i=0; i<ppayload->notifdequeue.psink->count; i++) {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
			&ppayload->notifdequeue.psink->padvise[i].hstore)) {
			return FALSE;	
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
			&ppayload->notifdequeue.psink->padvise[i].sub_id)) {
			return FALSE;	
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->notifdequeue.timeval)) {
		return FALSE;	
	}
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
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->queryrows.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->queryrows.htable)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->queryrows.start)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->queryrows.count)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->queryrows.prestriction = NULL;
	} else {
		ppayload->queryrows.prestriction =
			pext->alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->queryrows.prestriction) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			pext, ppayload->queryrows.prestriction)) {
			return FALSE;
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->queryrows.pproptags = NULL;
	} else {
		ppayload->queryrows.pproptags =
			pext->alloc(sizeof(PROPTAG_ARRAY));
		if (NULL == ppayload->queryrows.pproptags) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
			pext, ppayload->queryrows.pproptags)) {
			return FALSE;	
		}
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
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->setcolumns.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setcolumns.htable)) {
		return FALSE;
	}
	ppayload->setcolumns.pproptags =
		pext->alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->setcolumns.pproptags) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
		pext, ppayload->setcolumns.pproptags)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setcolumns.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_seekrow_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->seekrow.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->seekrow.htable)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->seekrow.bookmark)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_int32(
		pext, &ppayload->seekrow.seek_rows)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_seekrow_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_int32(
		pext, ppayload->seekrow.sought_rows)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_sorttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->sorttable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->sorttable.htable)) {
		return FALSE;
	}
	ppayload->sorttable.psortset =
		pext->alloc(sizeof(SORTORDER_SET));
	if (NULL == ppayload->sorttable.psortset) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_sortorder_set(
		pext, ppayload->sorttable.psortset)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getrowcount_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->getrowcount.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getrowcount.htable)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getrowcount_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->getrowcount.count)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_restricttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->restricttable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->restricttable.htable)) {
		return FALSE;
	}
	ppayload->restricttable.prestriction =
		pext->alloc(sizeof(RESTRICTION));
	if (NULL == ppayload->restricttable.prestriction) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
		pext, ppayload->restricttable.prestriction)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->restricttable.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_findrow_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->findrow.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->findrow.htable)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->findrow.bookmark)) {
		return FALSE;
	}
	ppayload->findrow.prestriction =
		pext->alloc(sizeof(RESTRICTION));
	if (NULL == ppayload->findrow.prestriction) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
		pext, ppayload->findrow.prestriction)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->findrow.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_findrow_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->findrow.row_idx)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_createbookmark_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->createbookmark.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->createbookmark.htable)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL rpc_ext_push_createbookmark_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->createbookmark.bookmark)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_freebookmark_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->freebookmark.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->freebookmark.htable)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->freebookmark.bookmark)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getreceivefolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->getreceivefolder.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getreceivefolder.hstore)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->getreceivefolder.pstrclass = NULL;
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
			pext, &ppayload->getreceivefolder.pstrclass)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_getreceivefolder_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->getreceivefolder.entryid)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_modifyrecipients_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->modifyrecipients.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->modifyrecipients.hmessage)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->modifyrecipients.flags)) {
		return FALSE;
	}
	ppayload->modifyrecipients.prcpt_list =
			pext->alloc(sizeof(TARRAY_SET));
	if (NULL == ppayload->modifyrecipients.prcpt_list) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tarray_set(
		pext, ppayload->modifyrecipients.prcpt_list)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_submitmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->submitmessage.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->submitmessage.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_loadattachmenttable_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->loadattachmenttable.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
		&ppayload->loadattachmenttable.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_loadattachmenttable_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->loadattachmenttable.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openattachment.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openattachment.hmessage)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openattachment.attach_id)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openattachment_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openattachment.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_createattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->createattachment.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->createattachment.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_createattachment_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->createattachment.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_deleteattachment_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->deleteattachment.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deleteattachment.hmessage)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deleteattachment.attach_id)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_setpropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->setpropvals.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setpropvals.hobject)) {
		return FALSE;
	}
	ppayload->setpropvals.ppropvals =
		pext->alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->setpropvals.ppropvals) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tpropval_array(
		pext, ppayload->setpropvals.ppropvals)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getpropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->getpropvals.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getpropvals.hobject)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->getpropvals.pproptags = NULL;
	} else {
		ppayload->getpropvals.pproptags =
			pext->alloc(sizeof(PROPTAG_ARRAY));
		if (NULL == ppayload->getpropvals.pproptags) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
			pext, ppayload->getpropvals.pproptags)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_getpropvals_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_tpropval_array(
		pext, &ppayload->getpropvals.propvals)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_deletepropvals_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->deletepropvals.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->deletepropvals.hobject)) {
		return FALSE;
	}
	ppayload->deletepropvals.pproptags =
		common_util_alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->deletepropvals.pproptags) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
		pext, ppayload->deletepropvals.pproptags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_setmessagereadflag_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->setmessagereadflag.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setmessagereadflag.hmessage)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setmessagereadflag.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openembedded_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openembedded.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openembedded.hattachment)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openembedded.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openembedded_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->openembedded.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getnamedpropids_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->getnamedpropids.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getnamedpropids.hstore)) {
		return FALSE;	
	}
	ppayload->getnamedpropids.ppropnames =
		pext->alloc(sizeof(PROPNAME_ARRAY));
	if (NULL == ppayload->getnamedpropids.ppropnames) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_propname_array(
		pext, ppayload->getnamedpropids.ppropnames)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getnamedpropids_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_propid_array(
		pext, &ppayload->getnamedpropids.propids)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_getpropnames_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->getpropnames.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getpropnames.hstore)) {
		return FALSE;	
	}
	ppayload->getpropnames.ppropids =
		pext->alloc(sizeof(PROPID_ARRAY));
	if (NULL == ppayload->getpropnames.ppropids) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_propid_array(
		pext, ppayload->getpropnames.ppropids)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getpropnames_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_propname_array(
		pext, &ppayload->getpropnames.propnames)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_copyto_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->copyto.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copyto.hsrcobject)) {
		return FALSE;
	}
	ppayload->copyto.pexclude_proptags =
		pext->alloc(sizeof(PROPTAG_ARRAY));
	if (NULL == ppayload->copyto.pexclude_proptags) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_proptag_array(
		pext, ppayload->copyto.pexclude_proptags)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copyto.hdstobject)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->copyto.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_savechanges_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->savechanges.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->savechanges.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_hierarchysync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->hierarchysync.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->hierarchysync.hfolder)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_hierarchysync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->hierarchysync.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_contentsync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->contentsync.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->contentsync.hfolder)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_contentsync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->contentsync.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_configsync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->configsync.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->configsync.hctx)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->configsync.flags)) {
		return FALSE;
	}
	ppayload->configsync.pstate =
		pext->alloc(sizeof(BINARY));
	if (NULL == ppayload->configsync.pstate) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, ppayload->configsync.pstate)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;	
	}
	if (0 == tmp_byte) {
		ppayload->configsync.prestriction = NULL;
	} else {
		ppayload->configsync.prestriction =
			pext->alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->configsync.prestriction) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			pext, ppayload->configsync.prestriction)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_configsync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_bool(
		pext, ppayload->configsync.b_changed)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->configsync.count)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_statesync_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->statesync.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->configsync.hctx)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_statesync_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->statesync.state)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_syncmessagechange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->syncmessagechange.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->syncmessagechange.hctx)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_syncmessagechange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_bool(
		pext, ppayload->syncmessagechange.b_new)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_tpropval_array(
		pext, &ppayload->syncmessagechange.proplist)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_syncfolderchange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->syncfolderchange.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->syncfolderchange.hctx)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_syncfolderchange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_tpropval_array(
		pext, &ppayload->syncfolderchange.proplist)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_syncreadstatechanges_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->syncreadstatechanges.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->syncreadstatechanges.hctx)) {
		return FALSE;	
	}
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
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->syncdeletions.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->syncdeletions.hctx)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->syncdeletions.flags)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_syncdeletions_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary_array(
		pext, &ppayload->syncdeletions.bins)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_hierarchyimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->hierarchyimport.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->hierarchyimport.hfolder)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_hierarchyimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->hierarchyimport.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_contentimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->contentimport.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->contentimport.hfolder)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_contentimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->contentimport.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_configimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->configimport.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->configimport.hctx)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &ppayload->configimport.sync_type)) {
		return FALSE;
	}
	ppayload->configimport.pstate =
		pext->alloc(sizeof(BINARY));
	if (NULL == ppayload->configimport.pstate) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, ppayload->configimport.pstate)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_stateimport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->stateimport.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->stateimport.hctx)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_stateimport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->stateimport.state)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_importmessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->importmessage.hsession)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importmessage.hctx)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importmessage.flags)) {
		return FALSE;
	}
	ppayload->importmessage.pproplist =
		pext->alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->importmessage.pproplist) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tpropval_array(
		pext, ppayload->importmessage.pproplist)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_importmessage_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->importmessage.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_importfolder_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->importfolder.hsession)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importfolder.hctx)) {
		return FALSE;
	}
	ppayload->importfolder.pproplist =
		pext->alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == ppayload->importfolder.pproplist) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_tpropval_array(
		pext, ppayload->importfolder.pproplist)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_importdeletion_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->importdeletion.hsession)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importdeletion.hctx)) {
		return FALSE;
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->importdeletion.flags)) {
		return FALSE;
	}
	ppayload->importdeletion.pbins =
		pext->alloc(sizeof(BINARY_ARRAY));
	if (NULL == ppayload->importdeletion.pbins) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
		pext, ppayload->importdeletion.pbins)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_importreadstates_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->importreadstates.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->importreadstates.hctx)) {
		return FALSE;
	}
	ppayload->importreadstates.pstates =
		pext->alloc(sizeof(STATE_ARRAY));
	if (NULL == ppayload->importreadstates.pstates) {
		return FALSE;
	}
	return rpc_ext_pull_state_array(pext,
		ppayload->importreadstates.pstates);
}

static BOOL rpc_ext_pull_getsearchcriteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->getsearchcriteria.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getsearchcriteria.hfolder)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getsearchcriteria_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{	
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary_array(
		pext, &ppayload->getsearchcriteria.folder_array)) {
		return FALSE;	
	}
	if (NULL == ppayload->getsearchcriteria.prestriction) {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(pext, 0)) {
			return FALSE;
		}
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(pext, 1)) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_push_restriction(pext,
			ppayload->getsearchcriteria.prestriction)) {
			return FALSE;	
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(pext,
		ppayload->getsearchcriteria.search_stat)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_setsearchcriteria_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->setsearchcriteria.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setsearchcriteria.hfolder)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->setsearchcriteria.flags)) {
		return FALSE;
	}
	ppayload->setsearchcriteria.pfolder_array =
			pext->alloc(sizeof(BINARY_ARRAY));
	if (NULL == ppayload->setsearchcriteria.pfolder_array) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
		pext, ppayload->setsearchcriteria.pfolder_array)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->setsearchcriteria.prestriction = NULL;
	} else {
		ppayload->setsearchcriteria.prestriction =
				pext->alloc(sizeof(RESTRICTION));
		if (NULL == ppayload->setsearchcriteria.prestriction) {
			return FALSE;
		}
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			pext, ppayload->setsearchcriteria.prestriction)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_pull_openfreebusydata_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->openfreebusydata.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->openfreebusydata.hsupport)) {
		return FALSE;
	}
	ppayload->openfreebusydata.pentryids =
		pext->alloc(sizeof(BINARY_ARRAY));
	if (NULL == ppayload->openfreebusydata.pentryids) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary_array(
		pext, ppayload->openfreebusydata.pentryids)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_openfreebusydata_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_long_array(
		pext, &ppayload->openfreebusydata.hobject_array)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_enumfreebusyblocks_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->enumfreebusyblocks.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
		&ppayload->enumfreebusyblocks.hfbdata)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(pext,
		&ppayload->enumfreebusyblocks.nttime_start)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(pext,
		&ppayload->enumfreebusyblocks.nttime_end)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_enumfreebusyblocks_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint32(
		pext, ppayload->enumfreebusyblocks.hobject)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_fbenumreset_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->fbenumreset.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fbenumreset.hfbenum)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_fbenumskip_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->fbenumskip.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fbenumskip.hfbenum)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fbenumskip.num)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_fbenumrestrict_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->fbenumrestrict.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fbenumrestrict.hfbenum)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(pext,
		&ppayload->fbenumrestrict.nttime_start)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(
		pext, &ppayload->fbenumrestrict.nttime_end)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_fbenumexport_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->fbenumexport.hsession)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fbenumexport.hfbenum)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fbenumexport.count)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(
		pext, &ppayload->fbenumexport.nttime_start)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint64(
		pext, &ppayload->fbenumexport.nttime_end)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->fbenumexport.organizer_name = NULL;
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(pext,
			&ppayload->fbenumexport.organizer_name)) {
			return FALSE;	
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->fbenumexport.username = NULL;
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
			pext, &ppayload->fbenumexport.username)) {
			return FALSE;	
		}
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		pext, &tmp_byte)) {
		return FALSE;
	}
	if (0 == tmp_byte) {
		ppayload->fbenumexport.uid_string = NULL;
	} else {
		if (EXT_ERR_SUCCESS != ext_buffer_pull_string(
			pext, &ppayload->fbenumexport.uid_string)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL rpc_ext_push_fbenumexport_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->fbenumexport.bin_ical)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_fetchfreebusyblocks_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->fetchfreebusyblocks.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(pext,
		&ppayload->fetchfreebusyblocks.hfbenum)) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->fetchfreebusyblocks.celt)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_fetchfreebusyblocks_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	return rpc_ext_push_fbblock_array(pext,
		&ppayload->fetchfreebusyblocks.blocks);
}

static BOOL rpc_ext_pull_getfreebusyrange_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->getfreebusyrange.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->getfreebusyrange.hfbdata)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_getfreebusyrange_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(pext,
		ppayload->getfreebusyrange.nttime_start)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint64(
		pext, ppayload->getfreebusyrange.nttime_end)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_messagetorfc822_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->messagetorfc822.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->messagetorfc822.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_messagetorfc822_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->messagetorfc822.eml_bin)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_rfc822tomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(pext,
		&ppayload->rfc822tomessage.hsession)) {
		return FALSE;	
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->rfc822tomessage.hmessage)) {
		return FALSE;
	}
	ppayload->rfc822tomessage.peml_bin =
			pext->alloc(sizeof(BINARY));
	if (NULL == ppayload->rfc822tomessage.peml_bin) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, ppayload->rfc822tomessage.peml_bin)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_messagetoical_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->messagetoical.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->messagetoical.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_messagetoical_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->messagetoical.ical_bin)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_icaltomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->icaltomessage.hsession)) {
		return FALSE;	
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->icaltomessage.hmessage)) {
		return FALSE;
	}
	ppayload->icaltomessage.pical_bin =
			pext->alloc(sizeof(BINARY));
	if (NULL == ppayload->icaltomessage.pical_bin) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, ppayload->icaltomessage.pical_bin)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_messagetovcf_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->messagetovcf.hsession)) {
		return FALSE;	
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint32(
		pext, &ppayload->messagetovcf.hmessage)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_push_messagetovcf_response(
	EXT_PUSH *pext, const RESPONSE_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_push_binary(
		pext, &ppayload->messagetovcf.vcf_bin)) {
		return FALSE;	
	}
	return TRUE;
}

static BOOL rpc_ext_pull_vcftomessage_request(
	EXT_PULL *pext, REQUEST_PAYLOAD *ppayload)
{
	if (EXT_ERR_SUCCESS != ext_buffer_pull_guid(
		pext, &ppayload->vcftomessage.hsession)) {
		return FALSE;	
	}
	if (ext_buffer_pull_uint32(pext,
		&ppayload->vcftomessage.hmessage)) {
		return FALSE;
	}
	ppayload->vcftomessage.pvcf_bin =
		pext->alloc(sizeof(BINARY));
	if (NULL == ppayload->vcftomessage.pvcf_bin) {
		return FALSE;
	}
	if (EXT_ERR_SUCCESS != ext_buffer_pull_binary(
		pext, ppayload->vcftomessage.pvcf_bin)) {
		return FALSE;	
	}
	return TRUE;
}

BOOL rpc_ext_pull_request(const BINARY *pbin_in,
	RPC_REQUEST *prequest)
{
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_uint8(
		&ext_pull, &prequest->call_id)) {
		return FALSE;	
	}
	switch (prequest->call_id) {
	case CALL_ID_LOGON:
		return rpc_ext_pull_logon_request(
			&ext_pull, &prequest->payload);
	case CALL_ID_CHECKSESSION:
		return rpc_ext_pull_checksession_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_UINFO:
		return rpc_ext_pull_uinfo_request(
			&ext_pull, &prequest->payload);
	case CALL_ID_UNLOADOBJECT:
		return rpc_ext_pull_unloadobject_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_OPENENTRY:
		return rpc_ext_pull_openentry_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_OPENSTOREENTRY:
		return rpc_ext_pull_openstoreentry_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_OPENABENTRY:
		return rpc_ext_pull_openabentry_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_RESOLVENAME:
		return rpc_ext_pull_resolvename_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_OPENRULES:
		return rpc_ext_pull_openrules_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_GETPERMISSIONS:
		return rpc_ext_pull_getpermissions_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_MODIFYPERMISSIONS:
		return rpc_ext_pull_modifypermissions_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_MODIFYRULES:
		return rpc_ext_pull_modifyrules_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GETABGAL:
		return rpc_ext_pull_getabgal_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_LOADSTORETABLE:
		return rpc_ext_pull_loadstoretable_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_OPENSTORE:
		return rpc_ext_pull_openstore_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_OPENPROPFILESEC:
		return rpc_ext_pull_openpropfilesec_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_LOADHIERARCHYTABLE:
		return rpc_ext_pull_loadhierarchytable_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_LOADCONTENTTABLE:
		return rpc_ext_pull_loadcontenttable_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_LOADRECIPIENTTABLE:
		return rpc_ext_pull_loadrecipienttable_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_LOADRULETABLE:
		return rpc_ext_pull_loadruletable_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CREATEMESSAGE:
		return rpc_ext_pull_createmessage_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_DELETEMESSAGES:
		return rpc_ext_pull_deletemessages_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_COPYMESSAGES:
		return rpc_ext_pull_copymessages_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_SETREADFLAGS:
		return rpc_ext_pull_setreadflags_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CREATEFOLDER:
		return rpc_ext_pull_createfolder_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_DELETEFOLDER:
		return rpc_ext_pull_deletefolder_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_EMPTYFOLDER:
		return rpc_ext_pull_emptyfolder_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_COPYFOLDER:
		return rpc_ext_pull_copyfolder_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_GETSTOREENTRYID:
		return rpc_ext_pull_getstoreentryid_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_ENTRYIDFROMSOURCEKEY:
		return rpc_ext_pull_entryidfromsourcekey_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_STOREADVISE:
		return rpc_ext_pull_storeadvise_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_UNADVISE:
		return rpc_ext_pull_unadvise_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_NOTIFDEQUEUE:
		return rpc_ext_pull_notifdequeue_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_QUERYROWS:
		return rpc_ext_pull_queryrows_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_SETCOLUMNS:
		return rpc_ext_pull_setcolumns_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_SEEKROW:
		return rpc_ext_pull_seekrow_request(
			&ext_pull, &prequest->payload);
	case CALL_ID_SORTTABLE:
		return rpc_ext_pull_sorttable_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_GETROWCOUNT:
		return rpc_ext_pull_getrowcount_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_RESTRICTTABLE:
		return rpc_ext_pull_restricttable_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_FINDROW:
		return rpc_ext_pull_findrow_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_CREATEBOOKMARK:
		return rpc_ext_pull_createbookmark_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_FREEBOOKMARK:
		return rpc_ext_pull_freebookmark_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GETRECEIVEFOLDER:
		return rpc_ext_pull_getreceivefolder_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_MODIFYRECIPIENTS:
		return rpc_ext_pull_modifyrecipients_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_SUBMITMESSAGE:
		return rpc_ext_pull_submitmessage_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_LOADATTACHMENTTABLE:
		return rpc_ext_pull_loadattachmenttable_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_OPENATTACHMENT:
		return rpc_ext_pull_openattachment_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CREATEATTACHMENT:
		return rpc_ext_pull_createattachment_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_DELETEATTACHMENT:
		return rpc_ext_pull_deleteattachment_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_SETPROPVALS:
		return rpc_ext_pull_setpropvals_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GETPROPVALS:
		return rpc_ext_pull_getpropvals_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_DELETEPROPVALS:
		return rpc_ext_pull_deletepropvals_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_SETMESSAGEREADFLAG:
		return rpc_ext_pull_setmessagereadflag_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_OPENEMBEDDED:
		return rpc_ext_pull_openembedded_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GETNAMEDPROPIDS:
		return rpc_ext_pull_getnamedpropids_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_GETPROPNAMES:
		return rpc_ext_pull_getpropnames_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_COPYTO:
		return rpc_ext_pull_copyto_request(
			&ext_pull, &prequest->payload);
	case CALL_ID_SAVECHANGES:
		return rpc_ext_pull_savechanges_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_HIERARCHYSYNC:
		return rpc_ext_pull_hierarchysync_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CONTENTSYNC:
		return rpc_ext_pull_contentsync_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CONFIGSYNC:
		return rpc_ext_pull_configsync_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_STATESYNC:
		return rpc_ext_pull_statesync_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_SYNCMESSAGECHANGE:
		return rpc_ext_pull_syncmessagechange_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_SYNCFOLDERCHANGE:
		return rpc_ext_pull_syncfolderchange_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_SYNCREADSTATECHANGES:
		return rpc_ext_pull_syncreadstatechanges_request(
							&ext_pull, &prequest->payload);
	case CALL_ID_SYNCDELETIONS:
		return rpc_ext_pull_syncdeletions_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_HIERARCHYIMPORT:
		return rpc_ext_pull_hierarchyimport_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CONTENTIMPORT:
		return rpc_ext_pull_contentimport_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_CONFIGIMPORT:
		return rpc_ext_pull_configimport_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_STATEIMPORT:
		return rpc_ext_pull_stateimport_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_IMPORTMESSAGE:
		return rpc_ext_pull_importmessage_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_IMPORTFOLDER:
		return rpc_ext_pull_importfolder_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_IMPORTDELETION:
		return rpc_ext_pull_importdeletion_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_IMPORTREADSTATES:
		return rpc_ext_pull_importreadstates_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GETSEARCHCRITERIA:
		return rpc_ext_pull_getsearchcriteria_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_SETSEARCHCRITERIA:
		return rpc_ext_pull_setsearchcriteria_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_OPENFREEBUSYDATA:
		return rpc_ext_pull_openfreebusydata_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_ENUMFREEBUSYBLOCKS:
		return rpc_ext_pull_enumfreebusyblocks_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_FBENUMRESET:
		return rpc_ext_pull_fbenumreset_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_FBENUMSKIP:
		return rpc_ext_pull_fbenumskip_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_FBENUMRESTRICT:
		return rpc_ext_pull_fbenumreset_request(
				&ext_pull, &prequest->payload);
	case CALL_ID_FBENUMEXPORT:
		return rpc_ext_pull_fbenumexport_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_FETCHFREEBUSYBLOCKS:
		return rpc_ext_pull_fetchfreebusyblocks_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_GETFREEBUSYRANGE:
		return rpc_ext_pull_getfreebusyrange_request(
						&ext_pull, &prequest->payload);
	case CALL_ID_MESSAGETORFC822:
		return rpc_ext_pull_messagetorfc822_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_RFC822TOMESSAGE:
		return rpc_ext_pull_rfc822tomessage_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_MESSAGETOICAL:
		return rpc_ext_pull_messagetoical_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_ICALTOMESSAGE:
		return rpc_ext_pull_icaltomessage_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_MESSAGETOVCF:
		return rpc_ext_pull_messagetovcf_request(
					&ext_pull, &prequest->payload);
	case CALL_ID_VCFTOMESSAGE:
		return rpc_ext_pull_vcftomessage_request(
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
	if (EXT_ERR_SUCCESS != ext_buffer_push_uint8(
		&ext_push, RESPONSE_CODE_SUCCESS)) {
		return FALSE;	
	}
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
		pbin_out->pb = ext_push.data;
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
	case CALL_ID_LOGON:
		b_result = rpc_ext_push_logon_response(
				&ext_push, &presponse->payload);
		break;
	case CALL_ID_CHECKSESSION:
		b_result = TRUE;
		break;
	case CALL_ID_UINFO:
		b_result = rpc_ext_push_uinfo_response(
				&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNLOADOBJECT:
		b_result = TRUE;
		break;
	case CALL_ID_OPENENTRY:
		b_result = rpc_ext_push_openentry_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_OPENSTOREENTRY:
		b_result = rpc_ext_push_openstoreentry_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_OPENABENTRY:
		b_result = rpc_ext_push_openabentry_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_RESOLVENAME:
		b_result = rpc_ext_push_resolvename_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_OPENRULES:
		b_result = rpc_ext_push_openrules_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_GETPERMISSIONS:
		b_result = rpc_ext_push_getpermissions_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_MODIFYPERMISSIONS:
	case CALL_ID_MODIFYRULES:
		b_result = TRUE;
		break;
	case CALL_ID_GETABGAL:
		b_result = rpc_ext_push_getabgal_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOADSTORETABLE:
		b_result = rpc_ext_push_loadstoretable_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_OPENSTORE:
		b_result = rpc_ext_push_openstore_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_OPENPROPFILESEC:
		b_result = rpc_ext_push_openpropfilesec_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOADHIERARCHYTABLE:
		b_result = rpc_ext_push_loadhierarchytable_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOADCONTENTTABLE:
		b_result = rpc_ext_push_loadcontenttable_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOADRECIPIENTTABLE:
		b_result = rpc_ext_push_loadrecipienttable_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_LOADRULETABLE:
		b_result = rpc_ext_push_loadruletable_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CREATEMESSAGE:
		b_result = rpc_ext_push_createmessage_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_DELETEMESSAGES:
	case CALL_ID_COPYMESSAGES:
	case CALL_ID_SETREADFLAGS:
		b_result = TRUE;
		break;
	case CALL_ID_CREATEFOLDER:
		b_result = rpc_ext_push_createfolder_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_DELETEFOLDER:
	case CALL_ID_EMPTYFOLDER:
	case CALL_ID_COPYFOLDER:
		b_result = TRUE;
		break;
	case CALL_ID_GETSTOREENTRYID:
		b_result = rpc_ext_push_getstoreentryid_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_ENTRYIDFROMSOURCEKEY:
		b_result = rpc_ext_push_entryidfromsourcekey_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_STOREADVISE:
		b_result = rpc_ext_push_storeadvise_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_UNADVISE:
		b_result = TRUE;
		break;
	case CALL_ID_NOTIFDEQUEUE:
		b_result = rpc_ext_push_notifdequeue_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_QUERYROWS:
		b_result = rpc_ext_push_queryrows_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_SETCOLUMNS:
		b_result = TRUE;
		break;
	case CALL_ID_SEEKROW:
		b_result = rpc_ext_push_seekrow_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_SORTTABLE:
		b_result = TRUE;
		break;
	case CALL_ID_GETROWCOUNT:
		b_result = rpc_ext_push_getrowcount_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_RESTRICTTABLE:
		b_result = TRUE;
		break;
	case CALL_ID_FINDROW:
		b_result = rpc_ext_push_findrow_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_CREATEBOOKMARK:
		b_result = rpc_ext_push_createbookmark_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_FREEBOOKMARK:
		b_result = TRUE;
		break;
	case CALL_ID_GETRECEIVEFOLDER:
		b_result = rpc_ext_push_getreceivefolder_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_MODIFYRECIPIENTS:
	case CALL_ID_SUBMITMESSAGE:
		b_result = TRUE;
		break;
	case CALL_ID_LOADATTACHMENTTABLE:
		b_result = rpc_ext_push_loadattachmenttable_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_OPENATTACHMENT:
		b_result = rpc_ext_push_openattachment_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CREATEATTACHMENT:
		b_result = rpc_ext_push_createattachment_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_DELETEATTACHMENT:
		b_result = TRUE;
		break;
	case CALL_ID_SETPROPVALS:
		b_result = TRUE;
		break;
	case CALL_ID_GETPROPVALS:
		b_result = rpc_ext_push_getpropvals_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_DELETEPROPVALS:
	case CALL_ID_SETMESSAGEREADFLAG:
		b_result = TRUE;
		break;
	case CALL_ID_OPENEMBEDDED:
		b_result = rpc_ext_push_openembedded_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_GETNAMEDPROPIDS:
		b_result = rpc_ext_push_getnamedpropids_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_GETPROPNAMES:
		b_result = rpc_ext_push_getpropnames_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_COPYTO:
	case CALL_ID_SAVECHANGES:
		b_result = TRUE;
		break;
	case CALL_ID_HIERARCHYSYNC:
		b_result = rpc_ext_push_hierarchysync_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CONTENTSYNC:
		b_result = rpc_ext_push_contentsync_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_CONFIGSYNC:
		b_result = rpc_ext_push_configsync_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_STATESYNC:
		b_result = rpc_ext_push_statesync_response(
					&ext_push, &presponse->payload);
		break;
	case CALL_ID_SYNCMESSAGECHANGE:
		b_result = rpc_ext_push_syncmessagechange_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_SYNCFOLDERCHANGE:
		b_result = rpc_ext_push_syncfolderchange_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_SYNCREADSTATECHANGES:
		b_result = rpc_ext_push_syncreadstatechanges_response(
								&ext_push, &presponse->payload);
		break;
	case CALL_ID_SYNCDELETIONS:
		b_result = rpc_ext_push_syncdeletions_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_HIERARCHYIMPORT:
		b_result = rpc_ext_push_hierarchyimport_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CONTENTIMPORT:
		b_result = rpc_ext_push_contentimport_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_CONFIGIMPORT:
		b_result = TRUE;
		break;
	case CALL_ID_STATEIMPORT:
		b_result = rpc_ext_push_stateimport_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_IMPORTMESSAGE:
		b_result = rpc_ext_push_importmessage_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_IMPORTFOLDER:
		b_result = TRUE;
		break;
	case CALL_ID_IMPORTDELETION:
	case CALL_ID_IMPORTREADSTATES:
		b_result = TRUE;
		break;
	case CALL_ID_GETSEARCHCRITERIA:
		b_result = rpc_ext_push_getsearchcriteria_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_SETSEARCHCRITERIA:
		b_result = TRUE;
		break;
	case CALL_ID_OPENFREEBUSYDATA:
		b_result = rpc_ext_push_openfreebusydata_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_ENUMFREEBUSYBLOCKS:
		b_result = rpc_ext_push_enumfreebusyblocks_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_FBENUMRESET:
	case CALL_ID_FBENUMSKIP:
	case CALL_ID_FBENUMRESTRICT:
		b_result = TRUE;
		break;
	case CALL_ID_FBENUMEXPORT:
		b_result = rpc_ext_push_fbenumexport_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_FETCHFREEBUSYBLOCKS:
		b_result = rpc_ext_push_fetchfreebusyblocks_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_GETFREEBUSYRANGE:
		b_result = rpc_ext_push_getfreebusyrange_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_MESSAGETORFC822:
		b_result = rpc_ext_push_messagetorfc822_response(
							&ext_push, &presponse->payload);
		break;
	case CALL_ID_RFC822TOMESSAGE:
		b_result = TRUE;
		break;
	case CALL_ID_MESSAGETOICAL:
		b_result = rpc_ext_push_messagetoical_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_ICALTOMESSAGE:
		b_result = TRUE;
		break;
	case CALL_ID_MESSAGETOVCF:
		b_result = rpc_ext_push_messagetovcf_response(
						&ext_push, &presponse->payload);
		break;
	case CALL_ID_VCFTOMESSAGE:
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
	pbin_out->pb = ext_push.data;
	return TRUE;
}
