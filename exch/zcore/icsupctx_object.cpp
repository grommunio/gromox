// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "folder_object.h"
#include "icsupctx_object.h"
#include "ics_state.h"
#include "common_util.h"
#include <gromox/idset.hpp>
#include <cstdlib>

std::unique_ptr<ICSUPCTX_OBJECT> icsupctx_object_create(
	FOLDER_OBJECT *pfolder, uint8_t sync_type)
{
	std::unique_ptr<ICSUPCTX_OBJECT> pctx;
	try {
		pctx = std::make_unique<ICSUPCTX_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pctx->pstate = ics_state_create(sync_type);
	if (NULL == pctx->pstate) {
		return NULL;
	}
	pctx->pstore = pfolder->pstore;
	pctx->folder_id = pfolder->folder_id;
	pctx->sync_type = sync_type;
	return pctx;
}

BOOL ICSUPCTX_OBJECT::upload_state(const BINARY *out)
{
	return ics_state_deserialize(pstate, out);
}

BINARY *ICSUPCTX_OBJECT::get_state()
{
	return ics_state_serialize(pstate);
}
