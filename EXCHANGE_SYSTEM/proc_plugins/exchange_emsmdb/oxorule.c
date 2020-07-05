#include <gromox/defs.h>
#include "rops.h"
#include "rop_util.h"
#include "ext_buffer.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include "exmdb_client.h"
#include "logon_object.h"
#include "table_object.h"
#include "folder_object.h"
#include "rop_processor.h"
#include "processor_types.h"


uint32_t rop_modifyrules(uint8_t flags,
	uint16_t count, const RULE_DATA *prow,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i, j;
	BOOL b_exceed;
	int object_type;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	
	/* MS-OXORULE 3.2.5.2 */
	if (flags & ~MODIFY_RULES_FLAG_REPLACE) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
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
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (MODIFY_RULES_FLAG_REPLACE & flags) {
		for (i=0; i<count; i++) {
			if (prow[i].flags != RULE_DATA_FLAG_ADD_ROW) {
				return ecInvalidParam;
			}
		}
		if (FALSE == exmdb_client_empty_folder_rule(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder))) {
			return ecError;
		}
	}
	for (i=0; i<count; i++) {
		for (j=0; j<prow[i].propvals.count; j++) {
			if (FALSE == common_util_convert_tagged_propval(
				TRUE, prow[i].propvals.ppropval + j)) {
				return ecError;
			}
		}
	}
	if (FALSE == exmdb_client_update_folder_rule(
		logon_object_get_dir(plogon),
		folder_object_get_id(pfolder),
		count, prow, &b_exceed)) {
		return ecError;
	}
	if (TRUE == b_exceed) {
		return ecMAPIOOM;
	}
	return ecSuccess;
}

uint32_t rop_getrulestable(uint8_t flags,
	void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	int object_type;
	TABLE_OBJECT *ptable;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return ecNotSupported;
	}
	ptable = table_object_create(plogon, pfolder,
	         flags, ropGetRulesTable, logon_id);
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

uint32_t rop_updatedeferredactionmessages(
	const BINARY *pserver_entry_id,
	const BINARY *pclient_entry_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	uint64_t *pmid;
	uint8_t tmp_byte;
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	uint32_t tmp_proptag;
	uint64_t fid_deferred;
	PROBLEM_ARRAY problems;
	PROPTAG_ARRAY proptags;
	RESTRICTION restriction;
	TPROPVAL_ARRAY propvals;
	TAGGED_PROPVAL propval_buff[2];
	RESTRICTION_PROPERTY res_property;
	
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (FALSE == logon_object_check_private(plogon)) {
		return ecNotSupported;
	}
	fid_deferred = rop_util_make_eid_ex(1, PRIVATE_FID_DEFERRED_ACTION);
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), fid_deferred,
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_EDITANY)) {
			return EC_ACCESS_DENIED;
		}
	}
	
	restriction.rt = RESTRICTION_TYPE_PROPERTY;
	restriction.pres = &res_property;
	res_property.relop = RELOP_EQ;
	res_property.proptag =
		PROP_TAG_DEFERREDACTIONMESSAGEORIGINALENTRYID;
	res_property.propval.proptag = res_property.proptag;
	res_property.propval.pvalue = (void*)pserver_entry_id;
	if (FALSE == exmdb_client_load_content_table(
		logon_object_get_dir(plogon), 0, fid_deferred,
		NULL, TABLE_FLAG_NONOTIFICATIONS, &restriction,
		NULL, &table_id, &row_count)) {
		return ecError;
	}
	
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PROP_TAG_MID;
	
	if (FALSE == exmdb_client_query_table(
		logon_object_get_dir(plogon), NULL,
		0, table_id, &proptags, 0, row_count,
		&tmp_set)) {
		return ecError;
	}
	exmdb_client_unload_table(
		logon_object_get_dir(plogon), table_id);
	
	propvals.count = 2;
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag =
		PROP_TAG_DEFERREDACTIONMESSAGEORIGINALENTRYID;
	propval_buff[0].pvalue = (void*)pclient_entry_id;
	propval_buff[1].proptag = PROP_TAG_DAMBACKPATCHED;
	propval_buff[1].pvalue = &tmp_byte;
	tmp_byte = 1;
	
	for (i=0; i<tmp_set.count; i++) {
		pmid = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_MID);
		if (NULL == pmid) {
			continue;
		}
		exmdb_client_set_message_properties(
			logon_object_get_dir(plogon), NULL,
			0, *pmid, &propvals, &problems);
	}
	return ecSuccess;
}
