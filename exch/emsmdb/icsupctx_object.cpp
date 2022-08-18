// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <gromox/mapi_types.hpp>
#include "common_util.h"
#include "ics_state.h"
#include "icsupctx_object.h"

std::unique_ptr<icsupctx_object> icsupctx_object::create(logon_object *plogon,
    folder_object *pfolder, uint8_t sync_type)
{
	int state_type = sync_type == SYNC_TYPE_CONTENTS ? ICS_STATE_CONTENTS_UP : ICS_STATE_HIERARCHY_UP;
	std::unique_ptr<icsupctx_object> pctx;
	try {
		pctx.reset(new icsupctx_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pctx->pstate = ics_state::create_shared(plogon, state_type);
	if (pctx->pstate == nullptr)
		return NULL;
	pctx->plogon = plogon;
	pctx->pfolder = pfolder;
	pctx->sync_type = sync_type;
	return pctx;
}

icsupctx_object::~icsupctx_object()
{
	auto pctx = this;
	if (0 != pctx->state_property) {
		mem_file_free(&pctx->f_state_stream);
	}
}

BOOL icsupctx_object::begin_state_stream(uint32_t new_state_prop)
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (0 != pctx->state_property) {
		return FALSE;
	}
	switch (new_state_prop) {
	case MetaTagIdsetGiven:
	case MetaTagIdsetGiven1:
	case MetaTagCnsetSeen:
		break;
	case MetaTagCnsetSeenFAI:
	case MetaTagCnsetRead:
		if (SYNC_TYPE_CONTENTS != pctx->sync_type) {
			return FALSE;
		}
		break;
	default:
		return FALSE;
	}
	pctx->state_property = new_state_prop;
	mem_file_init(&pctx->f_state_stream, common_util_get_allocator());
	return TRUE;
}

BOOL icsupctx_object::continue_state_stream(const BINARY *pstream_data)
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (0 == pctx->state_property) {
		return FALSE;
	}
	if (pctx->state_property == MetaTagIdsetGiven ||
	    pctx->state_property == MetaTagIdsetGiven1)
		return TRUE;
	return f_state_stream.write(pstream_data->pb, pstream_data->cb) ==
	       pstream_data->cb ? TRUE : false;
}

BOOL icsupctx_object::end_state_stream()
{
	auto pctx = this;
	BINARY tmp_bin;
	
	if (pctx->b_started)
		return FALSE;
	if (0 == pctx->state_property) {
		return FALSE;
	}
	if (pctx->state_property == MetaTagIdsetGiven ||
	    pctx->state_property == MetaTagIdsetGiven1) {
		pctx->state_property = 0;
		mem_file_free(&pctx->f_state_stream);
		return TRUE;
	}
	auto pset = idset::create(false, REPL_TYPE_GUID);
	if (NULL == pset) {
		return FALSE;
	}
	tmp_bin.cb = pctx->f_state_stream.get_total_length();
	tmp_bin.pv = common_util_alloc(tmp_bin.cb);
	if (tmp_bin.pv == nullptr) {
		return FALSE;
	}
	pctx->f_state_stream.read(tmp_bin.pv, tmp_bin.cb);
	mem_file_free(&pctx->f_state_stream);
	auto saved_state_prop = pctx->state_property;
	pctx->state_property = 0;
	if (!pset->deserialize(&tmp_bin)) {
		return FALSE;
	}
	if (!pset->register_mapping(pctx->plogon, common_util_mapping_replica))
		return FALSE;
	if (!pset->convert()) {
		return FALSE;
	}
	if (!pctx->pstate->append_idset(saved_state_prop, std::move(pset)))
		return FALSE;
	return TRUE;
}
