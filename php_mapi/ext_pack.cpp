// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/mapidefs.h>
#include "ext_pack.h"
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <cstdint>
#include <gromox/defs.h>
#include "ext.hpp"
#define BTRY(expr) do { if (!(expr)) return 0; } while (false)
#define GROWING_BLOCK_SIZE				0x1000

/* emalloc is a macro and cannot be used like a function */
void *ext_pack_alloc(size_t z) { return emalloc(z); }
static void *ext_pack_realloc(void *p, size_t z) { return erealloc(p, z); }
static void ext_pack_free(void *p) { efree(p); }

const EXT_BUFFER_MGT ext_buffer_mgt = {ext_pack_alloc, ext_pack_realloc, ext_pack_free};

static zend_bool ext_pack_pull_permission_row(
	PULL_CTX *pctx, PERMISSION_ROW *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->flags));
	BTRY(ext_pack_pull_binary(pctx, &r->entryid));
	return ext_pack_pull_uint32(pctx, &r->member_rights);
}

zend_bool ext_pack_pull_permission_set(PULL_CTX *pctx, PERMISSION_SET *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	r->prows = sta_malloc<PERMISSION_ROW>(r->count);
	if (NULL == r->prows) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_pull_permission_row(pctx, &r->prows[i]));
	}
	return 1;
}

static zend_bool ext_pack_pull_message_state(PULL_CTX *pctx, MESSAGE_STATE *r)
{
	BTRY(ext_pack_pull_binary(pctx, &r->source_key));
	return ext_pack_pull_uint32(pctx, &r->message_flags);
}

zend_bool ext_pack_pull_state_array(PULL_CTX *pctx, STATE_ARRAY *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->count));
	if (0 == r->count) {
		r->pstate = NULL;
		return 1;
	}
	r->pstate = sta_malloc<MESSAGE_STATE>(r->count);
	if (NULL == r->pstate) {
		r->count = 0;
		return 0;
	}
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_pull_message_state(pctx, &r->pstate[i]));
	return 1;
}

static zend_bool ext_pack_pull_newmail_znotification(
	PULL_CTX *pctx, NEWMAIL_ZNOTIFICATION *r)
{
	BTRY(ext_pack_pull_binary(pctx, &r->entryid));
	BTRY(ext_pack_pull_binary(pctx, &r->parentid));
	BTRY(ext_pack_pull_uint32(pctx, &r->flags));
	BTRY(ext_pack_pull_string(pctx, &r->message_class));
	return ext_pack_pull_uint32(pctx, &r->message_flags);
}

static zend_bool ext_pack_pull_object_znotification(
	PULL_CTX *pctx, OBJECT_ZNOTIFICATION *r)
{
	uint8_t tmp_byte;
	
	BTRY(ext_pack_pull_uint32(pctx, &r->object_type));
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pentryid = NULL;
	} else {
		r->pentryid = st_malloc<BINARY>();
		if (NULL == r->pentryid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pentryid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pparentid = NULL;
	} else {
		r->pparentid = st_malloc<BINARY>();
		if (NULL == r->pparentid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pparentid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pold_entryid = NULL;
	} else {
		r->pold_entryid = st_malloc<BINARY>();
		if (NULL == r->pold_entryid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pold_entryid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pold_parentid = NULL;
	} else {
		r->pold_parentid = st_malloc<BINARY>();
		if (NULL == r->pold_parentid) {
			return 0;
		}
		BTRY(ext_pack_pull_binary(pctx, r->pold_parentid));
	}
	BTRY(ext_pack_pull_uint8(pctx, &tmp_byte));
	if (0 == tmp_byte) {
		r->pproptags = NULL;
		return 1;
	} else {
		r->pproptags = st_malloc<PROPTAG_ARRAY>();
		if (NULL == r->pproptags) {
			return 0;
		}
		return ext_pack_pull_proptag_array(pctx, r->pproptags);
	}
}

static zend_bool ext_pack_pull_znotification(
	PULL_CTX *pctx, ZNOTIFICATION *r)
{
	BTRY(ext_pack_pull_uint32(pctx, &r->event_type));
	switch (r->event_type) {
	case EVENT_TYPE_NEWMAIL:
		r->pnotification_data = emalloc(sizeof(NEWMAIL_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return 0;
		}
		return ext_pack_pull_newmail_znotification(pctx,
		       static_cast<NEWMAIL_ZNOTIFICATION *>(r->pnotification_data));
	case EVENT_TYPE_OBJECTCREATED:
	case EVENT_TYPE_OBJECTDELETED:
	case EVENT_TYPE_OBJECTMODIFIED:
	case EVENT_TYPE_OBJECTMOVED:
	case EVENT_TYPE_OBJECTCOPIED:
	case EVENT_TYPE_SEARCHCOMPLETE:
		r->pnotification_data = emalloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return 0;
		}
		return ext_pack_pull_object_znotification(pctx,
		       static_cast<OBJECT_ZNOTIFICATION *>(r->pnotification_data));
	default:
		r->pnotification_data = NULL;
		return 1;
	}
}

zend_bool ext_pack_pull_znotification_array(
	PULL_CTX *pctx, ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	BTRY(ext_pack_pull_uint16(pctx, &r->count));
	if (0 == r->count) {
		r->ppnotification = NULL;
		return 1;
	}
	r->ppnotification = sta_malloc<ZNOTIFICATION *>(r->count);
	if (NULL == r->ppnotification) {
		r->count = 0;
		return 0;
	}
	for (i=0; i<r->count; i++) {
		r->ppnotification[i] = st_malloc<ZNOTIFICATION>();
		if (NULL == r->ppnotification[i]) {
			return 0;
		}
		BTRY(ext_pack_pull_znotification(pctx, r->ppnotification[i]));
	}
	return 1;
}

static zend_bool ext_pack_push_permission_row(
	PUSH_CTX *pctx, const PERMISSION_ROW *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->flags));
	BTRY(ext_pack_push_binary(pctx, &r->entryid));
	return ext_pack_push_uint32(pctx, r->member_rights);
}

zend_bool ext_pack_push_permission_set(
	PUSH_CTX *pctx, const PERMISSION_SET *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_permission_row(pctx, &r->prows[i]));
	}
	return 1;
}

zend_bool ext_pack_push_rule_data(
	PUSH_CTX *pctx, const RULE_DATA *r)
{
	BTRY(ext_pack_push_uint8(pctx, r->flags));
	return ext_pack_push_tpropval_array(pctx, &r->propvals);
}

zend_bool ext_pack_push_rule_list(
	PUSH_CTX *pctx, const RULE_LIST *r)
{
	int i;
	
	BTRY(ext_pack_push_uint16(pctx, r->count));
	for (i=0; i<r->count; i++) {
		BTRY(ext_pack_push_rule_data(pctx, &r->prule[i]));
	}
	return 1;
}

static zend_bool ext_pack_push_message_state(
	PUSH_CTX *pctx, const MESSAGE_STATE *r)
{
	BTRY(ext_pack_push_binary(pctx, &r->source_key));
	return ext_pack_push_uint32(pctx, r->message_flags);
}

zend_bool ext_pack_push_state_array(
	PUSH_CTX *pctx, const STATE_ARRAY *r)
{
	BTRY(ext_pack_push_uint32(pctx, r->count));
	for (size_t i = 0; i < r->count; ++i)
		BTRY(ext_pack_push_message_state(pctx, &r->pstate[i]));
	return 1;
}
