// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "folder_object.h"
#include "icsupctx_object.h"
#include "ics_state.h"
#include "common_util.h"
#include <gromox/idset.hpp>
#include <cstdlib>

std::unique_ptr<icsupctx_object>
icsupctx_object::create(folder_object *pfolder, uint8_t sync_type)
{
	std::unique_ptr<icsupctx_object> pctx;
	try {
		pctx.reset(new icsupctx_object);
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

BOOL icsupctx_object::upload_state(const BINARY *out)
{
	return ics_state_deserialize(pstate, out);
}

BINARY *icsupctx_object::get_state()
{
	return ics_state_serialize(pstate);
}
