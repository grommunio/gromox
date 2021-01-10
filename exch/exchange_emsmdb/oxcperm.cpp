// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/defs.h>
#include "rops.h"
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include <gromox/proc_common.h>
#include "exmdb_client.h"
#include "logon_object.h"
#include "table_object.h"
#include "folder_object.h"
#include "rop_processor.h"
#include "processor_types.h"


uint32_t rop_modifypermissions(uint8_t flags,
	uint16_t count, const PERMISSION_DATA *prow,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_freebusy;
	int object_type;
	uint64_t folder_id;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pfolder = static_cast<FOLDER_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return ecNotSupported;
	}
	b_freebusy = FALSE;
	folder_id = folder_object_get_id(pfolder);
	if (flags & MODIFY_PERMISSIONS_FLAG_INCLUDEFREEBUSY) {
		if (FALSE == logon_object_check_private(plogon)) {
			return ecNotSupported;
		}
		if (folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR)) {
			b_freebusy = TRUE;
		}
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return ecAccessDenied;
		}
	}
	if (MODIFY_PERMISSIONS_FLAG_REPLACEROWS & flags) {
		if (FALSE == exmdb_client_empty_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder))) {
			return ecError;
		}
	}
	if (0 == count) {
		return ecSuccess;
	}
	if (FALSE == exmdb_client_update_folder_permission(
		logon_object_get_dir(plogon), folder_id,
		b_freebusy, count, prow)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_getpermissionstable(uint8_t flags,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int object_type;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	TABLE_OBJECT *ptable;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pfolder = static_cast<FOLDER_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return ecNotSupported;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER) &&
			0 == (permission & PERMISSION_FOLDERVISIBLE)) {
			return ecAccessDenied;
		}
	}
	ptable = table_object_create(plogon, pfolder, flags,
	         ropGetPermissionsTable, logon_id);
	if (NULL == ptable) {
		return ecMAPIOOM;
	}
	*phout = rop_processor_add_object_handle(plogmap,
			logon_id, hin, OBJECT_TYPE_TABLE, ptable);
	if (*phout < 0) {
		table_object_free(ptable);
		return ecError;
	}
	table_object_set_handle(ptable, *phout);
	return ecSuccess;
}
