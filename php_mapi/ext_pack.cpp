// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iconv.h>
#include <utility>
#include <vector>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/util.hpp>
#include "ext.hpp"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)
#define GROWING_BLOCK_SIZE				0x1000

static thread_local std::vector<void *> g_allocs;
static thread_local unsigned int g_amgr_refcount;

void palloc_tls_init()
{
	++g_amgr_refcount;
}

void palloc_tls_free()
{
	if (--g_amgr_refcount != 0)
		return;
	for (auto p : g_allocs)
		efree(p);
	g_allocs.clear();
}

/*
 * emalloc is a macro and it cannot be used where a function pointer is
 * expected
 */
void *ext_pack_alloc(size_t z) try
{
	g_allocs.push_back(nullptr);
	auto p = ecalloc(1, z);
	if (p != nullptr)
		g_allocs.back() = p;
	return p;
} catch (const std::bad_alloc &) {
	return nullptr;
}

static void *ext_pack_realloc(void *p, size_t z)
{
	auto i = std::find(g_allocs.begin(), g_allocs.end(), p);
	if (i != g_allocs.end())
		g_allocs.erase(i);
	auto q = erealloc(p, z);
	if (q == nullptr)
		return nullptr;
	g_allocs.push_back(q);
	return q;
}

void ext_pack_free(void *p)
{
	auto i = std::find(g_allocs.begin(), g_allocs.end(), p);
	if (i != g_allocs.end())
		g_allocs.erase(i);
	efree(p);
}

const EXT_BUFFER_MGT ext_buffer_mgt = {ext_pack_alloc, ext_pack_realloc, ext_pack_free};

static pack_result ext_pack_pull_permission_row(PULL_CTX *pctx, PERMISSION_ROW *r)
{
	TRY(pctx->g_uint32(&r->flags));
	TRY(pctx->g_bin(&r->entryid));
	return pctx->g_uint32(&r->member_rights);
}

pack_result PULL_CTX::g_perm_set(PERMISSION_SET *r)
{
	int i;
	
	TRY(g_uint16(&r->count));
	r->prows = sta_malloc<PERMISSION_ROW>(r->count);
	if (NULL == r->prows) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_pack_pull_permission_row(this, &r->prows[i]));
	}
	return EXT_ERR_SUCCESS;
}

static pack_result ext_pack_pull_message_state(PULL_CTX *pctx, MESSAGE_STATE *r)
{
	TRY(pctx->g_bin(&r->source_key));
	return pctx->g_uint32(&r->message_flags);
}

pack_result PULL_CTX::g_state_a(STATE_ARRAY *r)
{
	TRY(g_uint32(&r->count));
	if (0 == r->count) {
		r->pstate = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->pstate = sta_malloc<MESSAGE_STATE>(r->count);
	if (NULL == r->pstate) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_pack_pull_message_state(this, &r->pstate[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result ext_pack_pull_newmail_znotification(PULL_CTX *pctx,
    NEWMAIL_ZNOTIFICATION *r)
{
	TRY(pctx->g_bin(&r->entryid));
	TRY(pctx->g_bin(&r->parentid));
	TRY(pctx->g_uint32(&r->flags));
	TRY(pctx->g_str(&r->message_class));
	return pctx->g_uint32(&r->message_flags);
}

static pack_result ext_pack_pull_object_znotification(PULL_CTX *pctx,
    OBJECT_ZNOTIFICATION *r)
{
	uint8_t tmp_byte;
	uint32_t ot;
	
	TRY(pctx->g_uint32(&ot));
	r->object_type = static_cast<mapi_object_type>(ot);
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pentryid = NULL;
	} else {
		r->pentryid = st_malloc<BINARY>();
		if (NULL == r->pentryid) {
			return EXT_ERR_ALLOC;
		}
		TRY(pctx->g_bin(r->pentryid));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pparentid = NULL;
	} else {
		r->pparentid = st_malloc<BINARY>();
		if (NULL == r->pparentid) {
			return EXT_ERR_ALLOC;
		}
		TRY(pctx->g_bin(r->pparentid));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pold_entryid = NULL;
	} else {
		r->pold_entryid = st_malloc<BINARY>();
		if (NULL == r->pold_entryid) {
			return EXT_ERR_ALLOC;
		}
		TRY(pctx->g_bin(r->pold_entryid));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pold_parentid = NULL;
	} else {
		r->pold_parentid = st_malloc<BINARY>();
		if (NULL == r->pold_parentid) {
			return EXT_ERR_ALLOC;
		}
		TRY(pctx->g_bin(r->pold_parentid));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pproptags = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		r->pproptags = st_malloc<PROPTAG_ARRAY>();
		if (NULL == r->pproptags) {
			return EXT_ERR_ALLOC;
		}
		return pctx->g_proptag_a(r->pproptags);
	}
}

static pack_result ext_pack_pull_znotification(PULL_CTX *pctx, ZNOTIFICATION *r)
{
	TRY(pctx->g_uint32(&r->event_type));
	switch (r->event_type) {
	case NF_NEW_MAIL:
		r->pnotification_data = emalloc(sizeof(NEWMAIL_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return EXT_ERR_ALLOC;
		}
		return ext_pack_pull_newmail_znotification(pctx,
		       static_cast<NEWMAIL_ZNOTIFICATION *>(r->pnotification_data));
	case NF_OBJECT_CREATED:
	case NF_OBJECT_DELETED:
	case NF_OBJECT_MODIFIED:
	case NF_OBJECT_MOVED:
	case NF_OBJECT_COPIED:
	case NF_SEARCH_COMPLETE:
		r->pnotification_data = emalloc(sizeof(OBJECT_ZNOTIFICATION));
		if (NULL == r->pnotification_data) {
			return EXT_ERR_ALLOC;
		}
		return ext_pack_pull_object_znotification(pctx,
		       static_cast<OBJECT_ZNOTIFICATION *>(r->pnotification_data));
	default:
		r->pnotification_data = NULL;
		return EXT_ERR_SUCCESS;
	}
}

pack_result PULL_CTX::g_znotif_a(ZNOTIFICATION_ARRAY *r)
{
	int i;
	
	TRY(g_uint16(&r->count));
	if (0 == r->count) {
		r->ppnotification = NULL;
		return EXT_ERR_SUCCESS;
	}
	r->ppnotification = sta_malloc<ZNOTIFICATION *>(r->count);
	if (NULL == r->ppnotification) {
		r->count = 0;
		return EXT_ERR_ALLOC;
	}
	for (i=0; i<r->count; i++) {
		r->ppnotification[i] = st_malloc<ZNOTIFICATION>();
		if (NULL == r->ppnotification[i]) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_pack_pull_znotification(this, r->ppnotification[i]));
	}
	return EXT_ERR_SUCCESS;
}

static pack_result ext_pack_push_permission_row(PUSH_CTX *pctx, const PERMISSION_ROW *r)
{
	TRY(pctx->p_uint32(r->flags));
	TRY(pctx->p_bin(r->entryid));
	return pctx->p_uint32(r->member_rights);
}

pack_result PUSH_CTX::p_perm_set(const PERMISSION_SET *r)
{
	int i;
	
	TRY(p_uint16(r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_pack_push_permission_row(this, &r->prows[i]));
	}
	return EXT_ERR_SUCCESS;
}

pack_result PUSH_CTX::p_rule_data(const RULE_DATA *r)
{
	TRY(p_uint8(r->flags));
	return p_tpropval_a(r->propvals);
}

pack_result PUSH_CTX::p_rule_list(const RULE_LIST *r)
{
	TRY(p_uint16(r->count));
	for (const auto &rule : *r)
		TRY(p_rule_data(&rule));
	return EXT_ERR_SUCCESS;
}

static pack_result ext_pack_push_message_state(PUSH_CTX *pctx, const MESSAGE_STATE *r)
{
	TRY(pctx->p_bin(r->source_key));
	return pctx->p_uint32(r->message_flags);
}

pack_result PUSH_CTX::p_state_a(const STATE_ARRAY *r)
{
	TRY(p_uint32(r->count));
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_pack_push_message_state(this, &r->pstate[i]));
	return EXT_ERR_SUCCESS;
}
