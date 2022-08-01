// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "logon_object.h"
#include "processor_types.h"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"
#include "rop_processor.h"
#include "table_object.h"

uint32_t rop_modifypermissions(uint8_t flags, uint16_t count,
    const PERMISSION_DATA *prow, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	BOOL b_freebusy;
	int object_type;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	b_freebusy = FALSE;
	auto folder_id = pfolder->folder_id;
	if (flags & MODIFY_PERMISSIONS_FLAG_INCLUDEFREEBUSY) {
		if (!plogon->is_private())
			return ecNotSupported;
		if (folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR)) {
			b_freebusy = TRUE;
		}
	}
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client_check_folder_permission(plogon->get_dir(),
		    pfolder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & frightsOwner))
			return ecAccessDenied;
	}
	if (MODIFY_PERMISSIONS_FLAG_REPLACEROWS & flags) {
		if (!exmdb_client_empty_folder_permission(plogon->get_dir(),
		    pfolder->folder_id))
			return ecError;
	}
	if (0 == count) {
		return ecSuccess;
	}
	if (!exmdb_client_update_folder_permission(plogon->get_dir(),
	    folder_id, b_freebusy, count, prow))
		return ecError;
	return ecSuccess;
}

uint32_t rop_getpermissionstable(uint8_t flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int object_type;
	uint32_t permission;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pfolder = rop_proc_get_obj<folder_object>(plogmap, logon_id, hin, &object_type);
	if (pfolder == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client_check_folder_permission(plogon->get_dir(),
		    pfolder->folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsVisible)))
			return ecAccessDenied;
	}
	auto ptable = table_object::create(plogon, pfolder, flags,
	              ropGetPermissionsTable, logon_id);
	if (ptable == nullptr)
		return ecServerOOM;
	auto rtable = ptable.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_TABLE, std::move(ptable)});
	if (hnd < 0)
		return ecError;
	rtable->set_handle(hnd);
	*phout = hnd;
	return ecSuccess;
}
