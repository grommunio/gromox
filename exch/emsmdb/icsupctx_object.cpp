// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <utility>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "ics_state.h"
#include "icsupctx_object.h"

using namespace gromox;

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

BOOL icsupctx_object::begin_state_stream(uint32_t new_state_prop)
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (pctx->state_property != 0)
		return FALSE;
	switch (new_state_prop) {
	case MetaTagIdsetGiven:
	case MetaTagIdsetGiven1:
	case MetaTagCnsetSeen:
		break;
	case MetaTagCnsetSeenFAI:
	case MetaTagCnsetRead:
		if (pctx->sync_type != SYNC_TYPE_CONTENTS)
			return FALSE;
		break;
	default:
		return FALSE;
	}
	pctx->state_property = new_state_prop;
	f_state_stream.clear();
	return TRUE;
}

BOOL icsupctx_object::continue_state_stream(const BINARY *pstream_data) try
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (pctx->state_property == 0)
		return FALSE;
	if (pctx->state_property == MetaTagIdsetGiven ||
	    pctx->state_property == MetaTagIdsetGiven1)
		return TRUE;
	f_state_stream += std::string_view(pstream_data->pc, pstream_data->cb);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1089: ENOMEM");
	return false;
}

BOOL icsupctx_object::end_state_stream()
{
	auto pctx = this;
	BINARY tmp_bin;
	
	if (pctx->b_started)
		return FALSE;
	if (pctx->state_property == 0)
		return FALSE;
	if (pctx->state_property == MetaTagIdsetGiven ||
	    pctx->state_property == MetaTagIdsetGiven1) {
		pctx->state_property = 0;
		return TRUE;
	}
	auto pset = idset::create(false, REPL_TYPE_GUID);
	if (pset == nullptr)
		return FALSE;
	tmp_bin.pv = f_state_stream.data();
	tmp_bin.cb = f_state_stream.size();
	auto saved_state_prop = pctx->state_property;
	pctx->state_property = 0;
	if (!pset->deserialize(std::move(tmp_bin)))
		return FALSE;
	if (!pset->register_mapping(pctx->plogon, common_util_mapping_replica))
		return FALSE;
	if (!pset->convert())
		return FALSE;
	if (!pctx->pstate->append_idset(saved_state_prop, std::move(pset)))
		return FALSE;
	return TRUE;
}
