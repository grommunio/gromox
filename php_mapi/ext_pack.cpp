// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
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
#include <gromox/zcore_types.hpp>
#include "ext.hpp"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::ok) return klfdv; } while (false)
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

static pack_result ext_pack_pull_permission_row(PULL_CTX *x, PERMISSION_ROW *r)
{
	TRY(x->g_uint32(&r->flags));
	TRY(x->g_uint32(&r->member_id));
	TRY(x->g_uint32(&r->member_rights));
	return x->g_bin(&r->entryid);
}

pack_result PULL_CTX::g_perm_set(PERMISSION_SET *r)
{
	int i;
	
	TRY(g_uint16(&r->count));
	r->count = std::min(r->count, static_cast<uint16_t>(UINT16_MAX));
	r->prows = sta_malloc<PERMISSION_ROW>(r->count);
	if (NULL == r->prows) {
		r->count = 0;
		return pack_result::alloc;
	}
	for (i=0; i<r->count; i++) {
		TRY(ext_pack_pull_permission_row(this, &r->prows[i]));
	}
	return pack_result::ok;
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
		return pack_result::ok;
	}
	r->count = std::min(r->count, static_cast<uint32_t>(UINT32_MAX));
	r->pstate = sta_malloc<MESSAGE_STATE>(r->count);
	if (NULL == r->pstate) {
		r->count = 0;
		return pack_result::alloc;
	}
	for (size_t i = 0; i < r->count; ++i)
		TRY(ext_pack_pull_message_state(this, &r->pstate[i]));
	return pack_result::ok;
}

static pack_result ext_pack_pull_newmail_znotification(PULL_CTX *pctx,
    ZNOTIFICATION *r) try
{
	std::string s;
	TRY(pctx->g_bin(&s));
	r->pentryid = std::move(s);
	TRY(pctx->g_bin(&s));
	r->pparentid = std::move(s);
	TRY(pctx->g_uint32(&r->flags));
	TRY(pctx->g_str(&r->message_class));
	return pctx->g_uint32(&r->message_flags);
} catch (const std::bad_alloc &) {
	return pack_result::alloc;
}

static pack_result ext_pack_pull_object_znotification(PULL_CTX *pctx,
    ZNOTIFICATION *r)
{
	uint8_t tmp_byte;
	uint32_t ot;
	
	TRY(pctx->g_uint32(&ot));
	r->object_type = static_cast<mapi_object_type>(ot);
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pentryid.reset();
	} else {
		std::string bin;
		TRY(pctx->g_bin(&bin));
		r->pentryid.emplace(std::move(bin));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pparentid.reset();
	} else {
		std::string bin;
		TRY(pctx->g_bin(&bin));
		r->pparentid.emplace(std::move(bin));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pold_entryid.reset();
	} else {
		std::string bin;
		TRY(pctx->g_bin(&bin));
		r->pold_entryid.emplace(std::move(bin));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pold_parentid.reset();
	} else {
		std::string bin;
		TRY(pctx->g_bin(&bin));
		r->pold_parentid.emplace(std::move(bin));
	}
	TRY(pctx->g_uint8(&tmp_byte));
	if (0 == tmp_byte) {
		r->pproptags.reset();
	} else {
		std::vector<gromox::proptag_t> tags;
		TRY(pctx->g_proptag_a(&tags));
		r->pproptags.emplace(std::move(tags));
	}
	return pack_result::ok;
}

static pack_result ext_pack_pull_znotification(PULL_CTX *pctx, ZNOTIFICATION *r) try
{
	TRY(pctx->g_uint32(&r->event_type));
	switch (r->event_type) {
	case fnevNewMail:
		return ext_pack_pull_newmail_znotification(pctx, r);
	case fnevObjectCreated:
	case fnevObjectDeleted:
	case fnevObjectModified:
	case fnevObjectMoved:
	case fnevObjectCopied:
	case fnevSearchComplete:
		return ext_pack_pull_object_znotification(pctx, r);
	default:
		return pack_result::ok;
	}
} catch (const std::bad_alloc &) {
	return pack_result::alloc;
}

pack_result PULL_CTX::g_znotif_a(std::vector<ZNOTIFICATION> *r) try
{
	uint16_t count = 0;
	TRY(g_uint16(&count));
	r->resize(count);
	if (count == 0)
		return pack_result::ok;
	for (unsigned int i = 0; i < count; ++i)
		TRY(ext_pack_pull_znotification(this, &(*r)[i]));
	return pack_result::ok;
} catch (const std::bad_alloc &) {
	return pack_result::alloc;
}

static pack_result ext_pack_push_permission_row(PUSH_CTX *x, const PERMISSION_ROW *r)
{
	TRY(x->p_uint32(r->flags));
	TRY(x->p_uint32(r->member_id));
	TRY(x->p_uint32(r->member_rights));
	return x->p_bin(r->entryid);
}

pack_result PUSH_CTX::p_perm_set(const PERMISSION_SET *r)
{
	int i;
	
	TRY(p_uint16(r->count));
	for (i=0; i<r->count; i++) {
		TRY(ext_pack_push_permission_row(this, &r->prows[i]));
	}
	return pack_result::ok;
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
	return pack_result::ok;
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
	return pack_result::ok;
}
