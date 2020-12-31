#include <stdbool.h>
#include <libHX/defs.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "rops.h"
#include "propval.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include "exmdb_client.h"
#include "logon_object.h"
#include "folder_object.h"
#include "stream_object.h"
#include "rop_processor.h"
#include "message_object.h"
#include "processor_types.h"
#include "emsmdb_interface.h"
#include "attachment_object.h"


uint32_t rop_getpropertyidsfromnames(uint8_t flags,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_create;
	int object_type;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (NULL == rop_processor_get_object(
		plogmap, logon_id, hin, &object_type)) {
		return ecNullObject;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
	case OBJECT_TYPE_FOLDER:
	case OBJECT_TYPE_MESSAGE:
	case OBJECT_TYPE_ATTACHMENT:
		break;
	default:
		return ecNotSupported;
	}
	if (PROPIDS_FROM_NAMES_FLAG_GETORCREATE == flags) {
		if (TRUE == logon_object_check_private(plogon) &&
			LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
			b_create = FALSE;
		} else {
			b_create = TRUE;
		}
	} else if (PROPIDS_FROM_NAMES_FLAG_GETONLY == flags) {
		b_create = FALSE;
	} else {
		return ecInvalidParam;
	}
	if (0 == ppropnames->count &&
		OBJECT_TYPE_LOGON == object_type) {
		if (FALSE == exmdb_client_get_all_named_propids(
			logon_object_get_dir(plogon), ppropids)) {
			return ecError;
		}
		return ecSuccess;
	}
	if (FALSE == logon_object_get_named_propids(
		plogon, b_create, ppropnames, ppropids)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_getnamesfrompropertyids(
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	if (NULL == rop_processor_get_object(
		plogmap, logon_id, hin, &object_type)) {
		return ecNullObject;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
	case OBJECT_TYPE_FOLDER:
	case OBJECT_TYPE_MESSAGE:
	case OBJECT_TYPE_ATTACHMENT:
		if (FALSE == logon_object_get_named_propnames(
			plogon, ppropids, ppropnames)) {
			return ecError;
		}
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t rop_getpropertiesspecific(uint16_t size_limit,
	uint16_t want_unicode, const PROPTAG_ARRAY *pproptags,
	PROPERTY_ROW *prow, void *plogmap, uint8_t logon_id,
	uint32_t hin)
{
	int i;
	uint32_t cpid;
	void *pobject;
	BOOL b_unicode;
	int object_type;
	uint32_t tmp_size;
	uint16_t proptype;
	EMSMDB_INFO *pinfo;
	uint32_t total_size;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY *ptmp_proptags;
	
	/* we ignore the size_limit as
		mentioned in MS-OXCPRPT 3.2.5.1 */
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if (0 == want_unicode) {
		b_unicode = FALSE;
	} else {
		b_unicode = TRUE;
	}
	ptmp_proptags = common_util_trim_proptags(pproptags);
	if (NULL == ptmp_proptags) {
		return ecMAPIOOM;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
		if (!logon_object_get_properties(static_cast<LOGON_OBJECT *>(pobject),
		    ptmp_proptags, &propvals))
			return ecError;
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (NULL == pinfo) {
			return ecError;
		}
		cpid = pinfo->cpid;
		break;
	case OBJECT_TYPE_FOLDER:
		if (folder_object_get_properties(static_cast<FOLDER_OBJECT *>(pobject),
		    ptmp_proptags, &propvals))
			return ecError;
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (NULL == pinfo) {
			return ecError;
		}
		cpid = pinfo->cpid;
		break;
	case OBJECT_TYPE_MESSAGE: {
		auto msg = static_cast<MESSAGE_OBJECT *>(pobject);
		if (!message_object_get_properties(msg, 0, ptmp_proptags, &propvals))
			return ecError;
		cpid = message_object_get_cpid(msg);
		break;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		auto atx = static_cast<ATTACHMENT_OBJECT *>(pobject);
		if (!attachment_object_get_properties(atx, 0, ptmp_proptags, &propvals))
			return ecError;
		cpid = attachment_object_get_cpid(atx);
		break;
	}
	default:
		return ecNotSupported;
	}
	total_size = 0;
	for (i=0; i<propvals.count; i++) {
		tmp_size = propval_size(PROP_TYPE(propvals.ppropval[i].proptag),
			propvals.ppropval[i].pvalue);
		if (tmp_size > 0x8000) {
			propvals.ppropval[i].proptag = CHANGE_PROP_TYPE(propvals.ppropval[i].proptag, PT_ERROR);
			propvals.ppropval[i].pvalue =
				common_util_alloc(sizeof(uint32_t));
			if (NULL == propvals.ppropval[i].pvalue) {
				return ecMAPIOOM;
			}
			*static_cast<uint32_t *>(propvals.ppropval[i].pvalue) = ecMAPIOOM;
			continue;
		}
		total_size += tmp_size;
	}
	if (total_size > 0x7000) {
		for (i=0; i<propvals.count; i++) {
			proptype = PROP_TYPE(propvals.ppropval[i].proptag);
			switch (proptype) {
			case PT_BINARY:
			case PT_OBJECT:
			case PT_STRING8:
			case PT_UNICODE:
				if (0x1000 < propval_size(proptype,
					propvals.ppropval[i].pvalue)) {
					propvals.ppropval[i].proptag = CHANGE_PROP_TYPE(propvals.ppropval[i].proptag, PT_ERROR);
					propvals.ppropval[i].pvalue =
						common_util_alloc(sizeof(uint32_t));
					if (NULL == propvals.ppropval[i].pvalue) {
						return ecMAPIOOM;
					}
					*static_cast<uint32_t *>(propvals.ppropval[i].pvalue) = ecMAPIOOM;
				}
				break;
			}
		}
	}
	if (FALSE == common_util_propvals_to_row_ex(
		cpid, b_unicode, &propvals, pproptags, prow)) {
		return ecMAPIOOM;
	}
	return ecSuccess;
}

uint32_t rop_getpropertiesall(uint16_t size_limit,
	uint16_t want_unicode, TPROPVAL_ARRAY *ppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	uint32_t cpid;
	void *pobject;
	BOOL b_unicode = false;
	int object_type;
	EMSMDB_INFO *pinfo;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY *ptmp_proptags;
	
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON: {
		auto xlog = static_cast<LOGON_OBJECT *>(pobject);
		if (!logon_object_get_all_proptags(xlog, &proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecMAPIOOM;
		}
		if (!logon_object_get_properties(xlog, ptmp_proptags, ppropvals))
			return ecError;
		for (i=0; i<ppropvals->count; i++) {
			if (propval_size(PROP_TYPE(ppropvals->ppropval[i].proptag),
				ppropvals->ppropval[i].pvalue) > size_limit) {
				ppropvals->ppropval[i].proptag = CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_ERROR);
				ppropvals->ppropval[i].pvalue =
					common_util_alloc(sizeof(uint32_t));
				if (NULL == ppropvals->ppropval[i].pvalue) {
					return ecMAPIOOM;
				}
				*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) = ecMAPIOOM;
			}
		}
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (NULL == pinfo) {
			return ecError;
		}
		cpid = pinfo->cpid;
		break;
	}
	case OBJECT_TYPE_FOLDER: {
		auto fld = static_cast<FOLDER_OBJECT *>(pobject);
		if (!folder_object_get_all_proptags(fld, &proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecMAPIOOM;
		}
		if (!folder_object_get_properties(fld, ptmp_proptags, ppropvals))
			return ecError;
		for (i=0; i<ppropvals->count; i++) {
			if (propval_size(PROP_TYPE(ppropvals->ppropval[i].proptag),
				ppropvals->ppropval[i].pvalue) > size_limit) {
				ppropvals->ppropval[i].proptag = CHANGE_PROP_TYPE(ppropvals->ppropval[i].proptag, PT_ERROR);
				ppropvals->ppropval[i].pvalue =
								common_util_alloc(sizeof(uint32_t));
				if (NULL == ppropvals->ppropval[i].pvalue) {
					return ecMAPIOOM;
				}
				*static_cast<uint32_t *>(ppropvals->ppropval[i].pvalue) = ecMAPIOOM;
			}
		}
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (NULL == pinfo) {
			return ecError;
		}
		cpid = pinfo->cpid;
		break;
	}
	case OBJECT_TYPE_MESSAGE: {
		auto msg = static_cast<MESSAGE_OBJECT *>(pobject);
		if (!message_object_get_all_proptags(msg, &proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecMAPIOOM;
		}
		if (!message_object_get_properties(msg, size_limit,
		    ptmp_proptags, ppropvals))
			return ecError;
		cpid = attachment_object_get_cpid(static_cast<ATTACHMENT_OBJECT *>(pobject));
		break;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		auto atx = static_cast<ATTACHMENT_OBJECT *>(pobject);
		if (!attachment_object_get_all_proptags(atx, &proptags))
			return ecError;
		ptmp_proptags = common_util_trim_proptags(&proptags);
		if (NULL == ptmp_proptags) {
			return ecMAPIOOM;
		}
		if (!attachment_object_get_properties(atx, size_limit,
		    ptmp_proptags, ppropvals))
			return ecError;
		cpid = attachment_object_get_cpid(atx);
		break;
	}
	default:
		return ecNotSupported;
	}
	for (i=0; i<ppropvals->count; i++) {
		if (PROP_TYPE(ppropvals->ppropval[i].proptag) != PT_UNSPECIFIED)
			continue;	
		if (!common_util_convert_unspecified(cpid, b_unicode,
		    static_cast<TYPED_PROPVAL *>(ppropvals->ppropval[i].pvalue)))
			return ecMAPIOOM;
	}
	return ecSuccess;
}

uint32_t rop_getpropertieslist(PROPTAG_ARRAY *pproptags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pobject;
	int object_type;
	
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
		if (!logon_object_get_all_proptags(static_cast<LOGON_OBJECT *>(pobject), pproptags))
			return ecError;
		return ecSuccess;
	case OBJECT_TYPE_FOLDER:
		if (!folder_object_get_all_proptags(static_cast<FOLDER_OBJECT *>(pobject), pproptags))
			return ecError;
		return ecSuccess;
	case OBJECT_TYPE_MESSAGE:
		if (!message_object_get_all_proptags(static_cast<MESSAGE_OBJECT *>(pobject), pproptags))
			return ecError;
		return ecSuccess;
	case OBJECT_TYPE_ATTACHMENT:
		if (!attachment_object_get_all_proptags(static_cast<ATTACHMENT_OBJECT *>(pobject), pproptags))
			return ecError;
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t rop_setproperties(const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	void *pobject;
	int object_type;
	uint32_t tag_access;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
		if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
			return ecAccessDenied;
		}
		if (!logon_object_set_properties(static_cast<LOGON_OBJECT *>(pobject), ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	case OBJECT_TYPE_FOLDER: {
		auto fld = static_cast<FOLDER_OBJECT *>(pobject);
		rpc_info = get_rpc_info();
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (!exmdb_client_check_folder_permission(logon_object_get_dir(plogon),
			    folder_object_get_id(fld), rpc_info.username, &permission))
				return ecError;
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
		}
		if (!folder_object_set_properties(fld, ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	case OBJECT_TYPE_MESSAGE: {
		auto msg = static_cast<MESSAGE_OBJECT *>(pobject);
		tag_access = message_object_get_tag_access(msg);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (!message_object_set_properties(msg, ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		auto atx = static_cast<ATTACHMENT_OBJECT *>(pobject);
		tag_access = attachment_object_get_tag_access(atx);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (!attachment_object_set_properties(atx, ppropvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

uint32_t rop_setpropertiesnoreplicate(
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	return rop_setproperties(ppropvals,
		pproblems, plogmap, logon_id, hin);
}

uint32_t rop_deleteproperties(
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pobject;
	int object_type;
	uint32_t tag_access;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
		if (LOGON_MODE_GUEST == logon_object_get_mode(plogon)) {
			return ecAccessDenied;
		}
		if (!logon_object_remove_properties(static_cast<LOGON_OBJECT *>(pobject),
		    pproptags, pproblems))
			return ecError;
		return ecSuccess;
	case OBJECT_TYPE_FOLDER: {
		auto fld = static_cast<FOLDER_OBJECT *>(pobject);
		rpc_info = get_rpc_info();
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (!exmdb_client_check_folder_permission(logon_object_get_dir(plogon),
			    folder_object_get_id(fld), rpc_info.username, &permission))
				return ecError;
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
		}
		if (!folder_object_remove_properties(fld, pproptags, pproblems))
			return ecError;
		return ecSuccess;
	}
	case OBJECT_TYPE_MESSAGE: {
		auto msg = static_cast<MESSAGE_OBJECT *>(pobject);
		tag_access = message_object_get_tag_access(msg);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (!message_object_remove_properties(msg, pproptags, pproblems))
			return ecError;
		return ecSuccess;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		auto atx = static_cast<ATTACHMENT_OBJECT *>(pobject);
		tag_access = attachment_object_get_tag_access(atx);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (!attachment_object_remove_properties(static_cast<ATTACHMENT_OBJECT *>(atx),
		    pproptags, pproblems))
			return ecError;
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

uint32_t rop_deletepropertiesnoreplicate(
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	return rop_deleteproperties(pproptags,
		pproblems, plogmap, logon_id, hin);
}

uint32_t rop_querynamedproperties(uint8_t query_flags,
	const GUID *pguid, PROPIDNAME_ARRAY *ppropidnames,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	void *pobject;
	int object_type;
	uint16_t propid;
	LOGON_OBJECT *plogon;
	PROPID_ARRAY propids;
	PROPTAG_ARRAY proptags;
	PROPNAME_ARRAY propnames;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if ((query_flags & QUERY_FLAG_NOIDS) &&
		(query_flags & QUERY_FLAG_NOSTRINGS)) {
		ppropidnames->count = 0;
		ppropidnames->ppropid = NULL;
		ppropidnames->ppropname = NULL;
		return ecSuccess;
	}
	switch (object_type) {
	case OBJECT_TYPE_LOGON:
		if (!logon_object_get_all_proptags(static_cast<LOGON_OBJECT *>(pobject), &proptags))
			return ecError;
		break;
	case OBJECT_TYPE_FOLDER:
		if (!folder_object_get_all_proptags(static_cast<FOLDER_OBJECT *>(pobject), &proptags))
			return ecError;
		break;
	case OBJECT_TYPE_MESSAGE:
		if (!message_object_get_all_proptags(static_cast<MESSAGE_OBJECT *>(pobject), &proptags))
			return ecError;
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (!attachment_object_get_all_proptags(static_cast<ATTACHMENT_OBJECT *>(pobject), &proptags))
			return ecError;
		break;
	default:
		return ecNotSupported;
	}
	propids.count = 0;
	propids.ppropid = static_cast<uint16_t *>(common_util_alloc(
	                  sizeof(uint16_t) * proptags.count));
	if (NULL == propids.ppropid) {
		return ecMAPIOOM;
	}
	for (i=0; i<proptags.count; i++) {
		propid = PROP_ID(proptags.pproptag[i]);
		if (propid & 0x8000) {
			propids.ppropid[propids.count] = propid;
			propids.count ++;
		}
	}
	if (0 == propids.count) {
		ppropidnames->count = 0;
		ppropidnames->ppropid = NULL;
		ppropidnames->ppropname = NULL;
		return ecSuccess;
	}
	ppropidnames->count = 0;
	ppropidnames->ppropid = static_cast<uint16_t *>(common_util_alloc(
	                        sizeof(uint16_t) * propids.count));
	if (NULL == ppropidnames->ppropid) {
		return ecMAPIOOM;
	}
	ppropidnames->ppropname = static_cast<PROPERTY_NAME *>(common_util_alloc(
	                          sizeof(PROPERTY_NAME) * propids.count));
	if (NULL == ppropidnames->ppropid) {
		return ecMAPIOOM;
	}
	if (FALSE == logon_object_get_named_propnames(
		plogon, &propids, &propnames)) {
		return ecError;
	}
	for (i=0; i<propids.count; i++) {
		if (KIND_NONE == propnames.ppropname[i].kind) {
			continue;
		}
		if (NULL != pguid && 0 != memcmp(pguid,
			&propnames.ppropname[i].guid, sizeof(GUID))) {
			continue;
		}
		if ((query_flags & QUERY_FLAG_NOSTRINGS) &&
		    propnames.ppropname[i].kind == MNID_STRING)
			continue;
		if ((query_flags & QUERY_FLAG_NOIDS) &&
		    ppropidnames->ppropname[i].kind == MNID_ID)
			continue;
		ppropidnames->ppropid[ppropidnames->count] =
										propids.ppropid[i];
		ppropidnames->ppropname[ppropidnames->count] =
								ppropidnames->ppropname[i];
		ppropidnames->count ++;
	}
	return ecSuccess;
}

uint32_t rop_copyproperties(uint8_t want_asynchronous,
	uint8_t copy_flags, const PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	int i;
	BOOL b_force;
	int dst_type;
	BOOL b_result;
	void *pobject;
	int object_type;
	void *pobject_dst;
	uint32_t permission;
	uint32_t tag_access;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROBLEM_ARRAY tmp_problems;
	
	/* we don't support COPY_FLAG_MOVE, just
		like exchange 2010 or later */
	if (copy_flags & ~(COPY_FLAG_MOVE|COPY_FLAG_NOOVERWRITE)) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hsrc, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	pobject_dst = rop_processor_get_object(
		plogmap, logon_id, hdst, &dst_type);
	if (NULL == pobject_dst) {
		return ecDstNullObject;
	}
	if (dst_type != object_type) {
		return MAPI_E_DECLINE_COPY;
	}
	if (OBJECT_TYPE_FOLDER == object_type &&
		(COPY_FLAG_MOVE & copy_flags)) {
		return ecNotSupported;
	}
	proptags.count = 0;
	proptags.pproptag = static_cast<uint32_t *>(common_util_alloc(
	                    sizeof(uint32_t) * pproptags->count));
	if (NULL == proptags.pproptag) {
		return ecMAPIOOM;
	}
	pproblems->count = 0;
	pproblems->pproblem = static_cast<PROPERTY_PROBLEM *>(common_util_alloc(
	                      sizeof(PROPERTY_PROBLEM) * pproptags->count));
	if (NULL == pproblems->pproblem) {
		return ecMAPIOOM;
	}
	auto poriginal_indices = static_cast<uint16_t *>(common_util_alloc(
	                         sizeof(uint16_t)*pproptags->count));
	if (NULL == poriginal_indices) {
		return ecError;
	}
	switch (object_type) {
	case OBJECT_TYPE_FOLDER: {
		auto fldsrc = static_cast<FOLDER_OBJECT *>(pobject);
		auto flddst = static_cast<FOLDER_OBJECT *>(pobject_dst);
		rpc_info = get_rpc_info();
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (!exmdb_client_check_folder_permission(logon_object_get_dir(plogon),
			    folder_object_get_id(flddst), rpc_info.username, &permission))
				return ecError;
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
		}
		if (copy_flags & COPY_FLAG_NOOVERWRITE) {
			if (!folder_object_get_all_proptags(flddst, &proptags1))
				return ecError;
		}
		for (i=0; i<pproptags->count; i++) {
			if (folder_object_check_readonly_property(flddst, pproptags->pproptag[i])) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count].err = ecAccessDenied;
				pproblems->count ++;
				continue;
			}
			if ((copy_flags & COPY_FLAG_NOOVERWRITE) &&
				common_util_index_proptags(&proptags1,
				pproptags->pproptag[i]) >= 0) {
				continue;
			}
			proptags.pproptag[proptags.count] = 
							pproptags->pproptag[i];
			poriginal_indices[proptags.count] = i;
			proptags.count ++;
		}
		if (!folder_object_get_properties(fldsrc, &proptags, &propvals))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (NULL == common_util_get_propvals(
				&propvals, proptags.pproptag[i])) {
				pproblems->pproblem[pproblems->count].index =
										poriginal_indices[i];
				pproblems->pproblem[pproblems->count].proptag = 
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count].err = ecNotFound;
				pproblems->count ++;
			}
		}
		if (!folder_object_set_properties(flddst, &propvals, &tmp_problems))
			return ecError;
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index = common_util_index_proptags(
							pproptags, tmp_problems.pproblem[i].proptag);
		}
		memcpy(pproblems->pproblem + pproblems->count,
			tmp_problems.pproblem, tmp_problems.count*
			sizeof(PROPERTY_PROBLEM));
		pproblems->count += tmp_problems.count;
		qsort(pproblems->pproblem, pproblems->count,
			sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
		return ecSuccess;
	}
	case OBJECT_TYPE_MESSAGE: {
		auto msgsrc = static_cast<MESSAGE_OBJECT *>(pobject);
		auto msgdst = static_cast<MESSAGE_OBJECT* >(pobject_dst);
		tag_access = message_object_get_tag_access(msgdst);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		b_force = TRUE;
		if (copy_flags & COPY_FLAG_NOOVERWRITE) {
			b_force = FALSE;
			if (!message_object_get_all_proptags(msgdst, &proptags1))
				return ecError;
		}
		for (i=0; i<pproptags->count; i++) {
			if (PROP_TAG_MESSAGEATTACHMENTS == pproptags->pproptag[i]) {
				if (!message_object_copy_attachments(msgdst,
				    msgsrc, b_force, &b_result))
					return ecError;
				if (FALSE == b_result) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
										PROP_TAG_MESSAGEATTACHMENTS;
					pproblems->pproblem[pproblems->count].err = ecAccessDenied;
					pproblems->count ++;
				}
				continue;
			} else if (PROP_TAG_MESSAGERECIPIENTS == pproptags->pproptag[i]) {
				if (!message_object_copy_rcpts(msgdst, msgsrc,
				    b_force, &b_result))
					return ecError;
				if (FALSE == b_result) {
					pproblems->pproblem[pproblems->count].index = i;
					pproblems->pproblem[pproblems->count].proptag =
										PROP_TAG_MESSAGERECIPIENTS;
					pproblems->pproblem[pproblems->count].err = ecAccessDenied;
					pproblems->count ++;
				}
				continue;
			}
			if (message_object_check_readonly_property(msgdst, pproptags->pproptag[i])) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count].err = ecAccessDenied;
				pproblems->count ++;
				continue;
			}
			if ((copy_flags & COPY_FLAG_NOOVERWRITE) &&
				common_util_index_proptags(&proptags1,
				pproptags->pproptag[i]) >= 0) {
				continue;
			}
			proptags.pproptag[proptags.count] = 
							pproptags->pproptag[i];
			poriginal_indices[proptags.count] = i;
			proptags.count ++;
		}
		if (!message_object_get_properties(msgsrc, 0, &proptags, &propvals))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (NULL == common_util_get_propvals(
				&propvals, proptags.pproptag[i])) {
				pproblems->pproblem[pproblems->count].index =
										poriginal_indices[i];
				pproblems->pproblem[pproblems->count].proptag = 
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count].err = ecNotFound;
				pproblems->count ++;
			}
		}
		if (!message_object_set_properties(msgdst, &propvals, &tmp_problems))
			return ecError;
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index = common_util_index_proptags(
							pproptags, tmp_problems.pproblem[i].proptag);
		}
		memcpy(pproblems->pproblem + pproblems->count,
			tmp_problems.pproblem, tmp_problems.count*
			sizeof(PROPERTY_PROBLEM));
		pproblems->count += tmp_problems.count;
		qsort(pproblems->pproblem, pproblems->count,
			sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
		return ecSuccess;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		auto atsrc = static_cast<ATTACHMENT_OBJECT *>(pobject);
		auto atdst = static_cast<ATTACHMENT_OBJECT *>(pobject_dst);
		tag_access = attachment_object_get_tag_access(atdst);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (copy_flags & COPY_FLAG_NOOVERWRITE) {
			if (!attachment_object_get_all_proptags(atdst, &proptags1))
				return ecError;
		}
		for (i=0; i<pproptags->count; i++) {
			if (attachment_object_check_readonly_property(atdst, pproptags->pproptag[i])) {
				pproblems->pproblem[pproblems->count].index = i;
				pproblems->pproblem[pproblems->count].proptag =
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count].err = ecAccessDenied;
				pproblems->count ++;
				continue;
			}
			if ((copy_flags & COPY_FLAG_NOOVERWRITE) &&
				common_util_index_proptags(&proptags1,
				pproptags->pproptag[i]) >= 0) {
				continue;
			}
			proptags.pproptag[proptags.count] = 
							pproptags->pproptag[i];
			poriginal_indices[proptags.count] = i;
			proptags.count ++;
		}
		if (!attachment_object_get_properties(atsrc, 0, &proptags, &propvals))
			return ecError;
		for (i=0; i<proptags.count; i++) {
			if (NULL == common_util_get_propvals(
				&propvals, proptags.pproptag[i])) {
				pproblems->pproblem[pproblems->count].index =
										poriginal_indices[i];
				pproblems->pproblem[pproblems->count].proptag = 
										pproptags->pproptag[i];
				pproblems->pproblem[pproblems->count].err = ecNotFound;
				pproblems->count ++;
			}
		}
		if (!attachment_object_set_properties(atdst, &propvals, &tmp_problems))
			return ecError;
		for (i=0; i<tmp_problems.count; i++) {
			tmp_problems.pproblem[i].index = common_util_index_proptags(
							pproptags, tmp_problems.pproblem[i].proptag);
		}
		memcpy(pproblems->pproblem + pproblems->count,
			tmp_problems.pproblem, tmp_problems.count*
			sizeof(PROPERTY_PROBLEM));
		pproblems->count += tmp_problems.count;
		qsort(pproblems->pproblem, pproblems->count,
			sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

uint32_t rop_copyto(uint8_t want_asynchronous,
	uint8_t want_subobjects, uint8_t copy_flags,
	const PROPTAG_ARRAY *pexcluded_proptags,
	PROBLEM_ARRAY *pproblems, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst)
{
	int i;
	BOOL b_fai;
	BOOL b_sub;
	BOOL b_guest;
	BOOL b_force;
	BOOL b_cycle;
	int dst_type;
	BOOL b_normal;
	BOOL b_collid;
	void *pobject;
	BOOL b_partial;
	int object_type;
	void *pobject_dst;
	EMSMDB_INFO *pinfo;
	uint32_t tag_access;
	uint32_t permission;
	const char *username;
	LOGON_OBJECT *plogon;
	DCERPC_INFO rpc_info;
	PROPTAG_ARRAY proptags;
	PROPTAG_ARRAY proptags1;
	TPROPVAL_ARRAY propvals;
	PROPTAG_ARRAY tmp_proptags;
	
	/* we don't support COPY_FLAG_MOVE, just
		like exchange 2010 or later */
	if (copy_flags & ~(COPY_FLAG_MOVE|COPY_FLAG_NOOVERWRITE)) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hsrc, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	pobject_dst = rop_processor_get_object(
		plogmap, logon_id, hdst, &dst_type);
	if (NULL == pobject_dst) {
		return ecDstNullObject;
	}
	if (dst_type != object_type) {
		return MAPI_E_DECLINE_COPY;
	}
	if (OBJECT_TYPE_FOLDER == object_type &&
		(COPY_FLAG_MOVE & copy_flags)) {
		return ecNotSupported;
	}
	if (copy_flags & COPY_FLAG_NOOVERWRITE) {
		b_force = FALSE;
	} else {
		b_force = TRUE;
	}
	switch (object_type) {
	case OBJECT_TYPE_FOLDER: {
		auto fldsrc = static_cast<FOLDER_OBJECT *>(pobject);
		auto flddst = static_cast<FOLDER_OBJECT *>(pobject_dst);
		/* MS-OXCPRPT 3.2.5.8, public folder not supported */
		if (FALSE == logon_object_check_private(plogon)) {
			return ecNotSupported;
		}
		rpc_info = get_rpc_info();
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (!exmdb_client_check_folder_permission(logon_object_get_dir(plogon),
			    folder_object_get_id(fldsrc), rpc_info.username, &permission))
				return ecError;
			if (permission & PERMISSION_FOLDEROWNER) {
				username = NULL;
			} else {
				if (0 == (permission & PERMISSION_READANY)) {
					return ecAccessDenied;
				}
				username = rpc_info.username;
			}
			if (!exmdb_client_check_folder_permission(logon_object_get_dir(plogon),
			    folder_object_get_id(flddst), rpc_info.username, &permission))
				return ecError;
			if (0 == (permission & PERMISSION_FOLDEROWNER)) {
				return ecAccessDenied;
			}
			
		} else {
			username = NULL;
		}
		if (common_util_index_proptags(pexcluded_proptags,
			PROP_TAG_CONTAINERHIERARCHY) < 0) {
			if (FALSE == exmdb_client_check_folder_cycle(
				logon_object_get_dir(plogon),
			    folder_object_get_id(fldsrc),
			    folder_object_get_id(flddst), &b_cycle))
				return ecError;
			if (TRUE == b_cycle) {
				return MAPI_E_FOLDER_CYCLE;
			}
			b_sub = TRUE;
		} else {
			b_sub = FALSE;
		}
		if (common_util_index_proptags(pexcluded_proptags,
			PROP_TAG_CONTAINERCONTENTS) < 0) {
			b_normal = TRUE;
		} else {
			b_normal = FALSE;
		}
		if (common_util_index_proptags(pexcluded_proptags,
			PROP_TAG_FOLDERASSOCIATEDCONTENTS) < 0) {
			b_fai = TRUE;	
		} else {
			b_fai = FALSE;
		}
		if (!folder_object_get_all_proptags(fldsrc, &proptags))
			return ecError;
		common_util_reduce_proptags(&proptags, pexcluded_proptags);
		tmp_proptags.count = 0;
		tmp_proptags.pproptag = static_cast<uint32_t *>(common_util_alloc(
		                        sizeof(uint32_t) * proptags.count));
		if (NULL == tmp_proptags.pproptag) {
			return ecMAPIOOM;
		}
		if (FALSE == b_force) {
			if (!folder_object_get_all_proptags(flddst, &proptags1))
				return ecError;
		}
		for (i=0; i<proptags.count; i++) {
			if (folder_object_check_readonly_property(flddst, proptags.pproptag[i]))
				continue;
			if (FALSE == b_force && common_util_index_proptags(
				&proptags1, proptags.pproptag[i]) >= 0) {
				continue;
			}
			tmp_proptags.pproptag[tmp_proptags.count] = 
									proptags.pproptag[i];
			tmp_proptags.count ++;
		}
		if (!folder_object_get_properties(fldsrc, &tmp_proptags, &propvals))
			return ecError;
		if (TRUE == b_sub || TRUE == b_normal || TRUE == b_fai) {
			pinfo = emsmdb_interface_get_emsmdb_info();
			if (NULL == username) {
				b_guest = FALSE;
			} else {
				b_guest = TRUE;
			}
			if (!exmdb_client_copy_folder_internal(logon_object_get_dir(plogon),
			    logon_object_get_account_id(plogon), pinfo->cpid,
			    b_guest, rpc_info.username, folder_object_get_id(fldsrc),
			    b_normal, b_fai, b_sub, folder_object_get_id(flddst),
			    &b_collid, &b_partial))
				return ecError;
			if (TRUE == b_collid) {
				return ecDuplicateName;
			}
			if (!folder_object_set_properties(flddst, &propvals, pproblems))
				return ecError;
			return ecSuccess;
		}
		if (!folder_object_set_properties(flddst, &propvals, pproblems))
			return ecError;
		return ecSuccess;
	}
	case OBJECT_TYPE_MESSAGE: {
		auto msgdst = static_cast<MESSAGE_OBJECT *>(pobject_dst);
		tag_access = message_object_get_tag_access(msgdst);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (!message_object_copy_to(msgdst, static_cast<MESSAGE_OBJECT *>(pobject),
		    pexcluded_proptags, b_force, &b_cycle, pproblems))
			return ecError;
		if (TRUE == b_cycle) {
			return ecMsgCycle;
		}
		return ecSuccess;
	}
	case OBJECT_TYPE_ATTACHMENT: {
		auto atdst = static_cast<ATTACHMENT_OBJECT *>(pobject_dst);
		tag_access = attachment_object_get_tag_access(atdst);
		if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
			return ecAccessDenied;
		}
		if (!attachment_object_copy_properties(atdst,
		    static_cast<ATTACHMENT_OBJECT *>(pobject), pexcluded_proptags,
		    b_force, &b_cycle, pproblems))
			return ecError;
		if (TRUE == b_cycle) {
			return ecMsgCycle;
		}
		return ecSuccess;
	}
	default:
		return ecNotSupported;
	}
}

uint32_t rop_progress(uint8_t want_cancel,
	uint32_t *pcompleted_count, uint32_t *ptotal_count,
	uint8_t *prop_id, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	return ecNotSupported;
}

uint32_t rop_openstream(uint32_t proptag, uint8_t flags,
	uint32_t *pstream_size, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_write;
	void *pobject;
	int object_type;
	uint32_t max_length;
	uint32_t tag_access;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	STREAM_OBJECT *pstream;
	
	/* MS-OXCPERM 3.1.4.1 */
	if (PROP_TAG_SECURITYDESCRIPTORASXML == proptag) {
		return ecNotSupported;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if (OPENSTREAM_FLAG_CREATE == flags ||
		OPENSTREAM_FLAG_READWRITE == flags) {
		b_write = TRUE;
	} else {
		b_write = FALSE;
	}
	switch (object_type) {
	case OBJECT_TYPE_FOLDER:
		if (FALSE == logon_object_check_private(plogon) &&
			OPENSTREAM_FLAG_READONLY != flags) {
			return ecNotSupported;
		}
		if (PROP_TYPE(proptag) != PT_BINARY)
			return ecNotSupported;
		if (TRUE == b_write) {
			rpc_info = get_rpc_info();
			if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
				if (!exmdb_client_check_folder_permission(logon_object_get_dir(plogon),
				    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
				    rpc_info.username, &permission))
					return ecError;
				if (0 == (permission & PERMISSION_FOLDEROWNER)) {
					return ecAccessDenied;
				}
			}
		}
		max_length = MAX_LENGTH_FOR_FOLDER;
		break;
	case OBJECT_TYPE_MESSAGE:
	case OBJECT_TYPE_ATTACHMENT:
		switch (PROP_TYPE(proptag)) {
		case PT_BINARY:
		case PT_STRING8:
		case PT_UNICODE:
			break;
		case PT_OBJECT:
			if (PROP_TAG_ATTACHDATAOBJECT == proptag) {
				break;
			}
			return ecNotFound;
		default:
			return ecNotSupported;
		}
		if (TRUE == b_write) {
			if (OBJECT_TYPE_MESSAGE == object_type) {
				tag_access = message_object_get_tag_access(static_cast<MESSAGE_OBJECT *>(pobject));
			} else {
				tag_access = attachment_object_get_tag_access(static_cast<ATTACHMENT_OBJECT *>(pobject));
			}
			if (0 == (tag_access & TAG_ACCESS_MODIFY)) {
				return ecAccessDenied;
			}
		}
		max_length = common_util_get_param(COMMON_UTIL_MAX_MAIL_LENGTH);
		break;
	default:
		return ecNotSupported;
	}
	pstream = stream_object_create(pobject,
		object_type, flags, proptag, max_length);
	if (NULL == pstream) {
		return ecError;
	}
	if (FALSE == stream_object_check(pstream)) {
		stream_object_free(pstream);
		return ecNotFound;
	}
	*phout = rop_processor_add_object_handle(plogmap,
			logon_id, hin, OBJECT_TYPE_STREAM, pstream);
	if (*phout < 0) {
		stream_object_free(pstream);
		return ecError;
	}
	*pstream_size = stream_object_get_length(pstream);
	return ecSuccess;
}

uint32_t rop_readstream(uint16_t byte_count,
	uint32_t max_byte_count, BINARY *pdata_bin,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	uint16_t max_rop;
	uint16_t read_len;
	uint32_t buffer_size;
	int32_t object_type;
	
	auto pstream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pstream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	if (0xBABE == byte_count) {
		buffer_size = max_byte_count;
	} else {
		buffer_size = byte_count;
	}
	emsmdb_interface_get_rop_left(&max_rop);
	max_rop -= 16;
	if (buffer_size > max_rop) {
		buffer_size = max_rop;
	}
	if (0 == buffer_size) {
		pdata_bin->cb = 0;
		pdata_bin->pb = NULL;
		return ecSuccess;
	}
	pdata_bin->pv = common_util_alloc(buffer_size);
	if (pdata_bin->pv == nullptr)
		return ecMAPIOOM;
	read_len = stream_object_read(pstream, pdata_bin->pv, buffer_size);
	pdata_bin->cb = read_len;
	return ecSuccess;
}

uint32_t rop_writestream(const BINARY *pdata_bin,
	uint16_t *pwritten_size, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	int32_t object_type;
	
	auto pstream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pstream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	if (stream_object_get_open_flags(pstream) ==
		OPENSTREAM_FLAG_READONLY) {
		return STG_E_ACCESSDENIED;	
	}
	if (0 == pdata_bin->cb) {
		*pwritten_size = 0;
		return ecSuccess;
	}
	if (stream_object_get_seek_position(pstream) >=
		stream_object_get_max_length(pstream)) {
		return ecTooBig;
	}
	*pwritten_size = stream_object_write(
			pstream, pdata_bin->pb, pdata_bin->cb);
	if (0 == *pwritten_size) {
		return ecError;
	}
	if (*pwritten_size < pdata_bin->cb) {
		return ecTooBig;
	}
	return ecSuccess;
}

uint32_t rop_commitstream(void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	int object_type;
	
	auto pstream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pstream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	switch (stream_object_get_parent_type(pstream)) {
	case OBJECT_TYPE_FOLDER:
		if (FALSE == stream_object_commit(pstream)) {
			return ecError;
		}
		return ecSuccess;
	case OBJECT_TYPE_MESSAGE:
	case OBJECT_TYPE_ATTACHMENT:
		return ecSuccess;
	default:
		return ecNotSupported;
	}
}

uint32_t rop_getstreamsize(uint32_t *pstream_size,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	
	auto pstream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pstream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	*pstream_size = stream_object_get_length(pstream);
	return ecSuccess;
}

uint32_t rop_setstreamsize(uint64_t stream_size,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	
	if (stream_size > 0x80000000) {
		return ecInvalidParam;
	}
	auto pstream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pstream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	if (stream_size > stream_object_get_max_length(pstream)) {
		return ecTooBig;
	}
	if (FALSE == stream_object_set_length(pstream, stream_size)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_seekstream(uint8_t seek_pos,
	int64_t offset, uint64_t *pnew_pos,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	
	switch (seek_pos) {
	case SEEK_POS_BEGIN:
	case SEEK_POS_CURRENT:
	case SEEK_POS_END:
		break;
	default:
		return ecInvalidParam;
	}
	if (offset > 0x7FFFFFFF || offset < -0x7FFFFFFF) {
		return StreamSeekError;
	}
	auto pstream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pstream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	if (FALSE == stream_object_seek(pstream, seek_pos, offset)) {
		return StreamSeekError;
	}
	*pnew_pos = stream_object_get_seek_position(pstream);
	return ecSuccess;
}

uint32_t rop_copytostream(uint64_t byte_count,
	uint64_t *pread_bytes, uint64_t *pwritten_bytes,
	void *plogmap, uint8_t logon_id, uint32_t hsrc,
	uint32_t hdst)
{
	int object_type;
	uint32_t length;
	
	auto psrc_stream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	                   logon_id, hsrc, &object_type));
	if (NULL == psrc_stream) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_STREAM != object_type) {
		return ecNotSupported;
	}
	auto pdst_stream = static_cast<STREAM_OBJECT *>(rop_processor_get_object(plogmap,
	                   logon_id, hdst, &object_type));
	if (NULL == psrc_stream) {
		return ecDstNullObject;
	}
	if (stream_object_get_open_flags(pdst_stream)
		== OPENSTREAM_FLAG_READONLY) {
		return ecAccessDenied;
	}
	if (0 == byte_count) {
		*pread_bytes = 0;
		*pwritten_bytes = 0;
		return ecSuccess;
	}
	length = byte_count;
	if (FALSE == stream_object_copy(
		pdst_stream, psrc_stream, &length)) {
		return ecError;
	}
	*pread_bytes = length;
	*pwritten_bytes = length;
	return ecSuccess;
}

uint32_t rop_lockregionstream(uint64_t region_offset,
	uint64_t region_size, uint32_t lock_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	 /* just like exchange 2010 or later */
	 return NotImplemented;
}

uint32_t rop_unlockregionstream(uint64_t region_offset,
	uint64_t region_size, uint32_t lock_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	 /* just like exchange 2010 or later */
	return NotImplemented;
}

uint32_t rop_writeandcommitstream(
	const BINARY *pdata, uint16_t *pwritten_size,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	 /* just like exchange 2010 or later */
	return NotImplemented;
}

uint32_t rop_clonestream(void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	 /* just like exchange 2010 or later */
	return NotImplemented;
}
