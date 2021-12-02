// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "icsupctx_object.h"
#include "ics_state.h"
#include "common_util.h"
#include <gromox/idset.hpp>
#include <cstdlib>

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
	pctx->pstate = ics_state::create(plogon, state_type);
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
	if (TRUE == pctx->b_started) {
		return FALSE;
	}
	if (0 != pctx->state_property) {
		return FALSE;
	}
	switch (new_state_prop) {
	case META_TAG_IDSETGIVEN:
	case META_TAG_IDSETGIVEN1:
	case META_TAG_CNSETSEEN:
		break;
	case META_TAG_CNSETSEENFAI:
	case META_TAG_CNSETREAD:
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
	if (TRUE == pctx->b_started) {
		return FALSE;
	}
	if (0 == pctx->state_property) {
		return FALSE;
	}
	if (META_TAG_IDSETGIVEN == pctx->state_property ||
		META_TAG_IDSETGIVEN1 == pctx->state_property) {
		return TRUE;
	}
	return f_state_stream.write(pstream_data->pb, pstream_data->cb) ==
	       pstream_data->cb ? TRUE : false;
}

BOOL icsupctx_object::end_state_stream()
{
	auto pctx = this;
	IDSET *pset;
	BINARY tmp_bin;
	
	if (TRUE == pctx->b_started) {
		return FALSE;
	}
	if (0 == pctx->state_property) {
		return FALSE;
	}
	if (META_TAG_IDSETGIVEN == pctx->state_property ||
		META_TAG_IDSETGIVEN1 == pctx->state_property) {
		pctx->state_property = 0;
		mem_file_free(&pctx->f_state_stream);
		return TRUE;
	}
	pset = idset_init(FALSE, REPL_TYPE_GUID);
	if (NULL == pset) {
		return FALSE;
	}
	tmp_bin.cb = mem_file_get_total_length(&pctx->f_state_stream);
	tmp_bin.pv = common_util_alloc(tmp_bin.cb);
	if (tmp_bin.pv == nullptr) {
		idset_free(pset);
		return FALSE;
	}
	pctx->f_state_stream.read(tmp_bin.pv, tmp_bin.cb);
	mem_file_free(&pctx->f_state_stream);
	auto saved_state_prop = pctx->state_property;
	pctx->state_property = 0;
	if (!pset->deserialize(&tmp_bin)) {
		idset_free(pset);
		return FALSE;
	}
	tmp_bin.cb = sizeof(void*);
	tmp_bin.pv = &pctx->plogon;
	if (!pset->register_mapping(&tmp_bin, common_util_mapping_replica)) {
		idset_free(pset);
		return FALSE;
	}
	if (!pset->convert()) {
		idset_free(pset);
		return FALSE;
	}
	if (!pctx->pstate->append_idset(saved_state_prop, pset)) {
		idset_free(pset);
		return FALSE;
	}
	return TRUE;
}

void icsupctx_object::mark_started()
{
	b_started = TRUE;
}
