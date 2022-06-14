// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <gromox/mapi_types.hpp>
#include "common_util.h"
#include "ics_state.h"
#include "objects.hpp"

std::unique_ptr<icsupctx_object>
icsupctx_object::create(folder_object *pfolder, uint8_t sync_type)
{
	std::unique_ptr<icsupctx_object> pctx;
	try {
		pctx.reset(new icsupctx_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pctx->pstate = ics_state::create_shared(sync_type);
	if (NULL == pctx->pstate) {
		return NULL;
	}
	pctx->pstore = pfolder->pstore;
	pctx->folder_id = pfolder->folder_id;
	pctx->sync_type = sync_type;
	return pctx;
}
