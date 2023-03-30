// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include "common_util.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "rop_funcs.hpp"
#include "rop_processor.h"
#include "subscription_object.h"

ec_error_t rop_registernotification(uint8_t notification_types, uint8_t reserved,
    uint8_t want_whole_store, const uint64_t *pfolder_id,
    const uint64_t *pmessage_id, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin, uint32_t *phout)
{
	BOOL b_whole;
	ems_objtype object_type;
	uint64_t folder_id;
	uint64_t message_id;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecNullObject;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (0 == want_whole_store) {
		b_whole = FALSE;
		folder_id = *pfolder_id;
		message_id = *pmessage_id;
	} else {
		b_whole = TRUE;
		folder_id = 0;
		message_id = 0;
	}
	auto psub = subscription_object::create(plogon, logon_id,
	            notification_types, b_whole, folder_id, message_id);
	if (psub == nullptr)
		return ecServerOOM;
	auto rsub = psub.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {ems_objtype::subscription, std::move(psub)});
	if (hnd < 0)
		return aoh_to_error(hnd);
	rsub->set_handle(hnd);
	*phout = hnd;
	return ecSuccess;
}

void rop_release(LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	rop_processor_release_object_handle(plogmap, logon_id, hin);
}
