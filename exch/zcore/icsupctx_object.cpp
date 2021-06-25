// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "icsupctx_object.h"
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
	pctx->pstore = folder_object_get_store(pfolder);
	pctx->folder_id = pfolder->folder_id;
	pctx->sync_type = sync_type;
	return pctx;
}

BOOL icsupctx_object_upload_state(
	ICSUPCTX_OBJECT *pctx, const BINARY *pstate)
{
	return ics_state_deserialize(pctx->pstate, pstate);
}

BINARY* icsupctx_object_get_state(ICSUPCTX_OBJECT *pctx)
{
	return ics_state_serialize(pctx->pstate);
}

STORE_OBJECT* icsupctx_object_get_store(ICSUPCTX_OBJECT *pctx)
{
	return pctx->pstore;
}

uint8_t icsupctx_object_get_type(ICSUPCTX_OBJECT *pctx)
{
	return pctx->sync_type;
}

uint64_t icsupctx_object_get_parent_folder_id(ICSUPCTX_OBJECT *pctx)
{
	return pctx->folder_id;
}
