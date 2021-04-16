// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <climits>
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "rops.h"
#include <gromox/guid.hpp>
#include <gromox/idset.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/eid_array.hpp>
#include "common_util.h"
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include "exmdb_client.h"
#include "folder_object.h"
#include "rop_processor.h"
#include <gromox/tpropval_array.hpp>
#include "message_object.h"
#include "icsupctx_object.h"
#include "emsmdb_interface.h"
#include "fastupctx_object.h"
#include "icsdownctx_object.h"
#include "attachment_object.h"
#include "fastdownctx_object.h"


static EID_ARRAY* oxcfxics_load_folder_messages(
	LOGON_OBJECT *plogon, uint64_t folder_id,
	const char *username, BOOL b_fai)
{
	uint64_t *pmid;
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	uint32_t tmp_proptag;
	PROPTAG_ARRAY proptags;
	RESTRICTION restriction;
	EID_ARRAY *pmessage_ids;
	RESTRICTION_PROPERTY res_prop;
	uint8_t tmp_associated = !!b_fai;
	
	restriction.rt = RES_PROPERTY;
	restriction.pres = &res_prop;
	res_prop.relop = RELOP_EQ;
	res_prop.proptag = PROP_TAG_ASSOCIATED;
	res_prop.propval.proptag = res_prop.proptag;
	res_prop.propval.pvalue = &tmp_associated;
	if (FALSE == exmdb_client_load_content_table(
		logon_object_get_dir(plogon), 0, folder_id,
		username, TABLE_FLAG_NONOTIFICATIONS,
		&restriction, NULL, &table_id, &row_count)) {
		return NULL;	
	}
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	tmp_proptag = PROP_TAG_MID;
	if (FALSE == exmdb_client_query_table(
		logon_object_get_dir(plogon), NULL,
		0, table_id, &proptags, 0, row_count,
		&tmp_set)) {
		return NULL;	
	}
	exmdb_client_unload_table(
		logon_object_get_dir(plogon), table_id);
	pmessage_ids = eid_array_init();
	if (NULL == pmessage_ids) {
		return NULL;
	}
	for (size_t i = 0; i < tmp_set.count; ++i) {
		pmid = static_cast<uint64_t *>(common_util_get_propvals(
		       tmp_set.pparray[i], PROP_TAG_MID));
		if (NULL == pmid) {
			eid_array_free(pmessage_ids);
			return NULL;
		}
		if (!eid_array_append(pmessage_ids, *pmid)) {
			eid_array_free(pmessage_ids);
			return NULL;
		}
	}
	return pmessage_ids;
}

static FOLDER_CONTENT* oxcfxics_load_folder_content(
	LOGON_OBJECT *plogon, uint64_t folder_id,
	BOOL b_fai, BOOL b_normal, BOOL b_sub)
{
	BOOL b_found;
	BINARY *pbin;
	uint16_t replid;
	uint32_t table_id;
	uint32_t row_count;
	EMSMDB_INFO *pinfo;
	TARRAY_SET tmp_set;
	char tmp_essdn[256];
	uint32_t permission;
	const char *username;
	DCERPC_INFO rpc_info;
	uint64_t *pfolder_id;
	uint32_t tmp_proptag;
	EID_ARRAY *pmessage_ids;
	FOLDER_CONTENT *pfldctnt;
	TPROPVAL_ARRAY *pproplist;
	LONG_TERM_ID long_term_id;
	TAGGED_PROPVAL tmp_propval;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	FOLDER_CONTENT *psubfldctnt;
	
	
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			username, &permission)) {
			return NULL;	
		}
		if (0 == (permission & PERMISSION_READANY) &&
			0 == (permission & PERMISSION_FOLDEROWNER)) {
			return NULL;
		}
	} else {
		username = NULL;
	}
	pfldctnt = folder_content_init();
	if (NULL == pfldctnt) {
		return NULL;
	}
	if (FALSE == exmdb_client_get_folder_all_proptags(
		logon_object_get_dir(plogon), folder_id,
		&tmp_proptags)) {
		folder_content_free(pfldctnt);
		return NULL;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_get_folder_properties(
		logon_object_get_dir(plogon), pinfo->cpid,
		folder_id, &tmp_proptags, &tmp_propvals)) {
		folder_content_free(pfldctnt);
		return NULL;
	}
	pproplist = folder_content_get_proplist(pfldctnt);
	for (size_t i = 0; i < tmp_propvals.count; ++i) {
		if (!tpropval_array_set_propval(pproplist,
		    tmp_propvals.ppropval + i)) {
			folder_content_free(pfldctnt);
			return NULL;
		}
	}
	replid = rop_util_get_replid(folder_id);
	if (1 != replid) {
		if (FALSE == exmdb_client_get_mapping_guid(
			logon_object_get_dir(plogon), replid,
			&b_found, &long_term_id.guid) ||
			FALSE == b_found) {
			folder_content_free(pfldctnt);
			return NULL;
		}
		rop_util_get_gc_array(folder_id,
			long_term_id.global_counter);
		common_util_domain_to_essdn(logon_object_get_account(plogon),
			tmp_essdn, GX_ARRAY_SIZE(tmp_essdn));
		pbin = common_util_to_folder_replica(
				&long_term_id, tmp_essdn);
		if (NULL == pbin) {
			folder_content_free(pfldctnt);
			return NULL;
		}
		tmp_propval.proptag = META_TAG_NEWFXFOLDER;
		tmp_propval.pvalue = pbin;
		if (!tpropval_array_set_propval(pproplist,
		    &tmp_propval)) {
			folder_content_free(pfldctnt);
			return NULL;
		}
		return pfldctnt;
	}
	if (TRUE == b_fai) {
		pmessage_ids = oxcfxics_load_folder_messages(
					plogon, folder_id, username, TRUE);
		if (NULL == pmessage_ids) {
			folder_content_free(pfldctnt);
			return NULL;
		}
		folder_content_append_failist_internal(
						pfldctnt, pmessage_ids);
	}
	if (TRUE == b_normal) {
		pmessage_ids = oxcfxics_load_folder_messages(
					plogon, folder_id, username, FALSE);
		if (NULL == pmessage_ids) {
			folder_content_free(pfldctnt);
			return NULL;
		}
		folder_content_append_normallist_internal(
							pfldctnt, pmessage_ids);
	}
	if (TRUE == b_sub) {
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			rpc_info = get_rpc_info();
			username = rpc_info.username;
		} else {
			username = NULL;
		}
		if (FALSE == exmdb_client_load_hierarchy_table(
			logon_object_get_dir(plogon), folder_id,
			username, TABLE_FLAG_NONOTIFICATIONS, NULL,
			&table_id, &row_count)) {
			folder_content_free(pfldctnt);
			return NULL;	
		}
		tmp_proptags.count = 1;
		tmp_proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_FOLDERID;
		if (FALSE == exmdb_client_query_table(
			logon_object_get_dir(plogon), NULL, 0,
			table_id, &tmp_proptags, 0, row_count,
			&tmp_set)) {
			folder_content_free(pfldctnt);
			return NULL;	
		}
		exmdb_client_unload_table(
			logon_object_get_dir(plogon), table_id);
		for (size_t i = 0; i < tmp_set.count; ++i) {
			pfolder_id = static_cast<uint64_t *>(common_util_get_propvals(
			             tmp_set.pparray[i], PROP_TAG_FOLDERID));
			if (NULL == pfolder_id) {
				folder_content_free(pfldctnt);
				return NULL;
			}
			psubfldctnt = oxcfxics_load_folder_content(
				plogon, *pfolder_id, TRUE, TRUE, TRUE);
			if (NULL == psubfldctnt) {
				folder_content_free(pfldctnt);
				return NULL;
			}
			if (FALSE == folder_content_append_subfolder_internal(
				pfldctnt, psubfldctnt)) {
				folder_content_free(psubfldctnt);
				folder_content_free(pfldctnt);
				return NULL;
			}
		}
	}
	return pfldctnt;
}

uint32_t rop_fasttransferdestconfigure(
	uint8_t source_operation, uint8_t flags,
	void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	void *pvalue;
	void *pobject;
	int object_type;
	int root_element;
	LOGON_OBJECT *plogon;
	FASTUPCTX_OBJECT *pctx;
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (flags & ~FAST_DEST_CONFIG_FLAG_MOVE) {
		return ecInvalidParam;
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
	switch (source_operation) {
	case FAST_SOURCE_OPERATION_COPYTO:
	case FAST_SOURCE_OPERATION_COPYPROPERTIES:
		switch (object_type) {
		case OBJECT_TYPE_FOLDER:
			root_element = ROOT_ELEMENT_FOLDERCONTENT;
			break;
		case OBJECT_TYPE_MESSAGE:
			root_element = ROOT_ELEMENT_MESSAGECONTENT;
			break;
		case OBJECT_TYPE_ATTACHMENT:
			root_element = ROOT_ELEMENT_ATTACHMENTCONTENT;
			break;
		default:
			return ecNotSupported;
		}
		break;
	case FAST_SOURCE_OPERATION_COPYMESSAGES:
		if (OBJECT_TYPE_FOLDER != object_type) {
			return ecNotSupported;
		}
		root_element = ROOT_ELEMENT_MESSAGELIST;
		break;
	case FAST_SOURCE_OPERATION_COPYFOLDER:
		if (OBJECT_TYPE_FOLDER != object_type) {
			return ecNotSupported;
		}
		root_element = ROOT_ELEMENT_TOPFOLDER;
		break;
	default:
		return ecInvalidParam;
	}
	if (ROOT_ELEMENT_TOPFOLDER == root_element ||
		ROOT_ELEMENT_MESSAGELIST == root_element ||
		ROOT_ELEMENT_FOLDERCONTENT == root_element) {
		tmp_proptags.count = 4;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_MESSAGESIZEEXTENDED;
		proptag_buff[1] = PROP_TAG_STORAGEQUOTALIMIT;
		proptag_buff[2] = PROP_TAG_ASSOCIATEDCONTENTCOUNT;
		proptag_buff[3] = PROP_TAG_CONTENTCOUNT;
		if (FALSE == logon_object_get_properties(
			plogon, &tmp_proptags, &tmp_propvals)) {
			return ecError;
		}
		pvalue = common_util_get_propvals(&tmp_propvals, PROP_TAG_STORAGEQUOTALIMIT);
		uint64_t max_quota = ULLONG_MAX;
		if (pvalue != nullptr) {
			max_quota = *static_cast<uint32_t *>(pvalue);
			max_quota = max_quota >= ULLONG_MAX / 1024 ? ULLONG_MAX : max_quota * 1024ULL;
		}
		pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_MESSAGESIZEEXTENDED);
		uint64_t total_size = pvalue == nullptr ? 0 : *static_cast<uint64_t *>(pvalue);
		if (total_size > max_quota)
			return ecQuotaExceeded;
		pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_ASSOCIATEDCONTENTCOUNT);
		uint32_t total_mail = pvalue != nullptr ? *static_cast<uint32_t *>(pvalue) : 0;
		pvalue = common_util_get_propvals(&tmp_propvals,
								PROP_TAG_CONTENTCOUNT);
		if (NULL != pvalue) {
			total_mail += *(uint32_t*)pvalue;
		}
		if (total_mail > common_util_get_param(
			COMMON_UTIL_MAX_MESSAGE)) {
			return ecQuotaExceeded;
		}
	}
	pctx = fastupctx_object_create(plogon, pobject, root_element);
	if (NULL == pctx) {
		return ecError;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_FASTUPCTX, pctx);
	if (hnd < 0) {
		fastupctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_fasttransferdestputbuffer(
	const BINARY *ptransfer_data, uint16_t *ptransfer_status,
	uint16_t *pin_progress_count, uint16_t *ptotal_step_count,
	uint8_t *preserved, uint16_t *pused_size, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	void *pobject;
	int object_type;
	
	*ptransfer_status = 0;
	*pin_progress_count = 0;
	*ptotal_step_count = 1;
	*preserved = 0;
	*pused_size = 0;
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_FASTUPCTX != object_type) {
		return ecNotSupported;
	}
	auto err = fastupctx_object_write_buffer(static_cast<FASTUPCTX_OBJECT *>(pobject), ptransfer_data);
	if (err != GXERR_SUCCESS)
		return gxerr_to_hresult(err);
	*pused_size = ptransfer_data->cb;
	return ecSuccess;
}

uint32_t rop_fasttransfersourcegetbuffer(uint16_t buffer_size,
	uint16_t max_buffer_size, uint16_t *ptransfer_status,
	uint16_t *pin_progress_count, uint16_t *ptotal_step_count,
	uint8_t *preserved, BINARY *ptransfer_data,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_last;
	void *pobject;
	int object_type;
	uint16_t max_rop;
	
	*ptransfer_status = TRANSFER_STATUS_ERROR;
	*pin_progress_count = 0;
	*ptotal_step_count = 1;
	*preserved = 0;
	ptransfer_data->cb = 0;
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSDOWNCTX != object_type &&
		OBJECT_TYPE_FASTDOWNCTX != object_type) {
		return ecNotSupported;
	}
	emsmdb_interface_get_rop_left(&max_rop);
	max_rop -= 32;
	if (max_rop > 0x7b00) {
		max_rop = 0x7b00;
	}
	uint16_t len = buffer_size == 0xBABE ? max_buffer_size : buffer_size;
	if (len > max_rop) {
		len = max_rop;
	}
	ptransfer_data->pv = common_util_alloc(len);
	if (ptransfer_data->pv == nullptr)
		return ecMAPIOOM;
	if (OBJECT_TYPE_FASTDOWNCTX == object_type) {
		if (!fastdownctx_object_get_buffer(static_cast<FASTDOWNCTX_OBJECT *>(pobject),
		    ptransfer_data->pv, &len, &b_last, pin_progress_count, ptotal_step_count))
			return ecError;
	} else if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		auto dobj = static_cast<ICSDOWNCTX_OBJECT *>(pobject);
		if (!icsdownctx_object_check_started(dobj))
			if (!icsdownctx_object_make_sync(dobj))
				return ecError;
		if (!icsdownctx_object_get_buffer(dobj, ptransfer_data->pv,
		    &len, &b_last, pin_progress_count, ptotal_step_count))
			return ecError;
	}
	if (0xBABE != buffer_size && len > max_rop) {
		return ecBufferTooSmall;
	}
	*ptransfer_status = !b_last ? TRANSFER_STATUS_PARTIAL : TRANSFER_STATUS_DONE;
	ptransfer_data->cb = len;
	return ecSuccess;
}

uint32_t rop_fasttransfersourcecopyfolder(uint8_t flags,
	uint8_t send_options, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	BOOL b_sub;
	int object_type;
	LOGON_OBJECT *plogon;
	FASTDOWNCTX_OBJECT *pctx;
	FOLDER_CONTENT *pfldctnt;
	
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return ecInvalidParam;
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return ecInvalidParam;
	}
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
	b_sub = FALSE;
	if (flags & FAST_COPY_FOLDER_FLAG_MOVE ||
		flags & FAST_COPY_FOLDER_FLAG_COPYSUBFOLDERS) {
		b_sub = TRUE;
	}
	pfldctnt = oxcfxics_load_folder_content(plogon,
				folder_object_get_id(pfolder),
				TRUE, TRUE, b_sub);
	if (NULL == pfldctnt) {
		return ecError;
	}
	pctx = fastdownctx_object_create(
			plogon, send_options & 0x0F);
	if (NULL == pctx) {
		folder_content_free(pfldctnt);
		return ecError;
	}
	if (FALSE == fastdownctx_object_make_topfolder(
		pctx, pfldctnt)) {
		fastdownctx_object_free(pctx);
		folder_content_free(pfldctnt);
		return ecError;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (hnd < 0) {
		fastdownctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_fasttransfersourcecopymessages(
	const LONGLONG_ARRAY *pmessage_ids, uint8_t flags,
	uint8_t send_options, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	BOOL b_owner;
	int object_type;
	EID_ARRAY *pmids;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FASTDOWNCTX_OBJECT *pctx;
	
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return ecInvalidParam;
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return ecInvalidParam;
	}
	/* we ignore the FAST_COPY_MESSAGE_FLAG_MOVE
	   in flags just like exchange 2010 or later */
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
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		rpc_info = get_rpc_info();
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (PERMISSION_READANY & permission) &&
			0 == (PERMISSION_FOLDEROWNER & permission)) {
			for (size_t i = 0; i < pmessage_ids->count; ++i) {
				if (FALSE == exmdb_client_check_message_owner(
					logon_object_get_dir(plogon), pmessage_ids->pll[i],
					rpc_info.username, &b_owner)) {
					return ecError;
				}
				if (FALSE == b_owner) {
					return ecAccessDenied;
				}
			}
		}
	}
	pmids = eid_array_init();
	if (NULL == pmids) {
		return ecMAPIOOM;
	}
	if (!eid_array_batch_append(pmids, pmessage_ids->count,
	    pmessage_ids->pll)) {
		eid_array_free(pmids);
		return ecMAPIOOM;
	}
	BOOL b_chginfo = (flags & FAST_COPY_MESSAGE_FLAG_SENDENTRYID) ? TRUE : false;
	pctx = fastdownctx_object_create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		eid_array_free(pmids);
		return ecError;
	}
	if (FALSE == fastdownctx_object_make_messagelist(
		pctx, b_chginfo, pmids)) {
		fastdownctx_object_free(pctx);
		eid_array_free(pmids);
		return ecError;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (hnd < 0) {
		fastdownctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_fasttransfersourcecopyto(uint8_t level, uint32_t flags,
	uint8_t send_options, const PROPTAG_ARRAY *pproptags,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int i;
	BOOL b_sub;
	BOOL b_fai;
	BOOL b_normal;
	void *pobject;
	int object_type;
	LOGON_OBJECT *plogon;
	MESSAGE_CONTENT msgctnt;
	FOLDER_CONTENT *pfldctnt;
	FASTDOWNCTX_OBJECT *pctx;
	TPROPVAL_ARRAY *pproplist;
	ATTACHMENT_CONTENT attctnt;
	
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return ecInvalidParam;
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return ecInvalidParam;
	}
	/* just like exchange 2010 or later */
	if (flags & FAST_COPY_TO_FLAG_MOVE) {
		return ecInvalidParam;
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
	if (OBJECT_TYPE_FOLDER != object_type &&
		OBJECT_TYPE_MESSAGE != object_type &&
		OBJECT_TYPE_ATTACHMENT != object_type) {
		return ecNotSupported;
	}
	pctx = fastdownctx_object_create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		return ecError;
	}
	switch (object_type) {
	case OBJECT_TYPE_FOLDER:
		if (0 == level) {
			b_sub = TRUE;
			b_fai = TRUE;
			b_normal = TRUE;
			for (i=0; i<pproptags->count; i++) {
				switch (pproptags->pproptag[i]) {
				case PROP_TAG_CONTAINERHIERARCHY:
					b_sub = FALSE;
					break;
				case PROP_TAG_CONTAINERCONTENTS:
					b_normal = FALSE;
					break;
				case PROP_TAG_FOLDERASSOCIATEDCONTENTS:
					b_fai = FALSE;
					break;
				}
			}
		} else {
			b_sub = FALSE;
			b_fai = FALSE;
			b_normal = FALSE;
		}
		pfldctnt = oxcfxics_load_folder_content(plogon,
		           folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
					b_fai, b_normal, b_sub);
		if (NULL == pfldctnt) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		pproplist = folder_content_get_proplist(pfldctnt);
		for (i=0; i<pproptags->count; i++) {
			tpropval_array_remove_propval(
				pproplist, pproptags->pproptag[i]);
		}
		if (FALSE == fastdownctx_object_make_foldercontent(
			pctx, b_sub, pfldctnt)) {
			folder_content_free(pfldctnt);
			fastdownctx_object_free(pctx);
			return ecError;
		}
		break;
	case OBJECT_TYPE_MESSAGE:
		if (!message_object_flush_streams(static_cast<MESSAGE_OBJECT *>(pobject)))
			return ecError;
		if (FALSE == exmdb_client_read_message_instance(
			logon_object_get_dir(plogon),
		    message_object_get_instance_id(static_cast<MESSAGE_OBJECT *>(pobject)), &msgctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		for (i=0; i<pproptags->count; i++) {
			switch (pproptags->pproptag[i]) {
			case PROP_TAG_MESSAGERECIPIENTS:	
				msgctnt.children.prcpts = NULL;
				break;
			case PROP_TAG_MESSAGEATTACHMENTS:
				msgctnt.children.pattachments = NULL;
				break;
			default:
				common_util_remove_propvals(&msgctnt.proplist,
										pproptags->pproptag[i]);
				break;
			}
		}
		if (0 != level) {
			msgctnt.children.prcpts = NULL;
			msgctnt.children.pattachments = NULL;
		}
		if (FALSE == fastdownctx_object_make_messagecontent(
			pctx, &msgctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (!attachment_object_flush_streams(static_cast<ATTACHMENT_OBJECT *>(pobject)))
			return ecError;
		if (FALSE == exmdb_client_read_attachment_instance(
			logon_object_get_dir(plogon),
		    attachment_object_get_instance_id(static_cast<ATTACHMENT_OBJECT *>(pobject)), &attctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		for (i=0; i<pproptags->count; i++) {
			switch (pproptags->pproptag[i]) {
			case PROP_TAG_ATTACHDATAOBJECT:
				attctnt.pembedded = NULL;
				break;
			default:
				common_util_remove_propvals(&attctnt.proplist,
										pproptags->pproptag[i]);
				break;
			}
		}
		if (FALSE == fastdownctx_object_make_attachmentcontent(
			pctx, &attctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		break;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (hnd < 0) {
		fastdownctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_fasttransfersourcecopyproperties(uint8_t level, uint8_t flags,
	uint8_t send_options, const PROPTAG_ARRAY *pproptags, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int i;
	BOOL b_sub;
	BOOL b_fai;
	BOOL b_normal;
	void *pobject;
	int object_type;
	LOGON_OBJECT *plogon;
	MESSAGE_CONTENT msgctnt;
	FOLDER_CONTENT *pfldctnt;
	FASTDOWNCTX_OBJECT *pctx;
	TPROPVAL_ARRAY *pproplist;
	ATTACHMENT_CONTENT attctnt;
	
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return ecInvalidParam;
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return ecInvalidParam;
	}
	/* just like exchange 2010 or later */
	if (flags & FAST_COPY_PROPERTIES_FLAG_MOVE) {
		return ecInvalidParam;
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
	if (OBJECT_TYPE_FOLDER != object_type &&
		OBJECT_TYPE_MESSAGE != object_type &&
		OBJECT_TYPE_ATTACHMENT != object_type) {
		return ecNotSupported;
	}
	pctx = fastdownctx_object_create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		return ecError;
	}
	switch (object_type) {
	case OBJECT_TYPE_FOLDER:
		if (0 == level) {
			b_sub = FALSE;
			b_fai = FALSE;
			b_normal = FALSE;
			for (i=0; i<pproptags->count; i++) {
				switch (pproptags->pproptag[i]) {
				case PROP_TAG_CONTAINERHIERARCHY:
					b_sub = TRUE;
					break;
				case PROP_TAG_CONTAINERCONTENTS:
					b_normal = TRUE;
					break;
				case PROP_TAG_FOLDERASSOCIATEDCONTENTS:
					b_fai = TRUE;
					break;
				}
			}
		} else {
			b_sub = FALSE;
			b_fai = FALSE;
			b_normal = FALSE;
		}
		pfldctnt = oxcfxics_load_folder_content(plogon,
		           folder_object_get_id(static_cast<FOLDER_OBJECT *>(pobject)),
					b_fai, b_normal, b_sub);
		if (NULL == pfldctnt) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		pproplist = folder_content_get_proplist(pfldctnt);
		i = 0;
		while (i < pproplist->count) {
			if (META_TAG_NEWFXFOLDER != pproplist->ppropval[i].proptag) {
				if (-1 == common_util_index_proptags(pproptags,
					pproplist->ppropval[i].proptag)) {
					tpropval_array_remove_propval(pproplist,
							pproplist->ppropval[i].proptag);
					continue;
				}
			}
			i ++;
		}
		if (FALSE == fastdownctx_object_make_foldercontent(
			pctx, b_sub, pfldctnt)) {
			folder_content_free(pfldctnt);
			fastdownctx_object_free(pctx);
			return ecError;
		}
		break;
	case OBJECT_TYPE_MESSAGE:
		if (!message_object_flush_streams(static_cast<MESSAGE_OBJECT *>(pobject)))
			return ecError;
		if (FALSE == exmdb_client_read_message_instance(
			logon_object_get_dir(plogon),
		    message_object_get_instance_id(static_cast<MESSAGE_OBJECT *>(pobject)), &msgctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		i = 0;
		while (i < msgctnt.proplist.count) {
			if (-1 == common_util_index_proptags(pproptags,
				msgctnt.proplist.ppropval[i].proptag)) {
				common_util_remove_propvals(&msgctnt.proplist,
						msgctnt.proplist.ppropval[i].proptag);
				continue;
			}
			i ++;
		}
		if (-1 == common_util_index_proptags(
			pproptags, PROP_TAG_MESSAGERECIPIENTS)) {				
			msgctnt.children.prcpts = NULL;
		}
		if (-1 == common_util_index_proptags(
			pproptags, PROP_TAG_MESSAGEATTACHMENTS)) {
			msgctnt.children.pattachments = NULL;
		}
		if (0 != level) {
			msgctnt.children.prcpts = NULL;
			msgctnt.children.pattachments = NULL;
		}
		if (FALSE == fastdownctx_object_make_messagecontent(
			pctx, &msgctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (!attachment_object_flush_streams(static_cast<ATTACHMENT_OBJECT *>(pobject)))
			return ecError;
		if (FALSE == exmdb_client_read_attachment_instance(
			logon_object_get_dir(plogon),
		    attachment_object_get_instance_id(static_cast<ATTACHMENT_OBJECT *>(pobject)), &attctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		i = 0;
		while (i < attctnt.proplist.count) {
			if (-1 == common_util_index_proptags(pproptags,
				attctnt.proplist.ppropval[i].proptag)) {
				common_util_remove_propvals(&attctnt.proplist,
						attctnt.proplist.ppropval[i].proptag);
				continue;
			}
			i ++;
		}
		if (-1 == common_util_index_proptags(
			pproptags, PROP_TAG_ATTACHDATAOBJECT)) {
			attctnt.pembedded = NULL;
		}
		if (FALSE == fastdownctx_object_make_attachmentcontent(
			pctx, &attctnt)) {
			fastdownctx_object_free(pctx);
			return ecError;
		}
		break;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (hnd < 0) {
		fastdownctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_tellversion(const uint16_t *pversion,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	return ecSuccess;
}

uint32_t rop_syncconfigure(uint8_t sync_type, uint8_t send_options,
	uint16_t sync_flags, const RESTRICTION *pres, uint32_t extra_flags,
	const PROPTAG_ARRAY *pproptags, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	int object_type;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	ICSDOWNCTX_OBJECT *pctx;
	
	if (SYNC_TYPE_CONTENTS != sync_type &&
		SYNC_TYPE_HIERARCHY != sync_type) {
		return ecInvalidParam;
	}
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return ecInvalidParam;
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return ecInvalidParam;
	}
	if (SYNC_TYPE_HIERARCHY == sync_type && NULL != pres) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pfolder = static_cast<FOLDER_OBJECT *>(rop_processor_get_object(plogmap,
	               logon_id, hin, &object_type));
	if (NULL == pfolder) {
		return ecNullObject;
	}
	if (SYNC_TYPE_CONTENTS == SYNC_TYPE_CONTENTS) {
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			rpc_info = get_rpc_info();
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon),
				folder_object_get_id(pfolder),
				rpc_info.username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER) &&
				0 == (permission & PERMISSION_READANY)) {
				return ecAccessDenied;
			}
		}
	}
	if (NULL != pres) {
		if (FALSE == common_util_convert_restriction(
			TRUE, (RESTRICTION*)pres)) {
			return ecError;
		}
	}
	pctx = icsdownctx_object_create(plogon, pfolder,
			sync_type, send_options, sync_flags,
			pres, extra_flags, pproptags);
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_ICSDOWNCTX, pctx);
	if (hnd < 0) {
		icsdownctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_syncimportmessagechange(uint8_t import_flags,
	const TPROPVAL_ARRAY *ppropvals, uint64_t *pmessage_id,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_new;
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_owner;
	void *pvalue;
	GUID tmp_guid;
	uint32_t result;
	int object_type;
	EMSMDB_INFO *pinfo;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission, tag_access = 0;
	DCERPC_INFO rpc_info = {};
	LOGON_OBJECT *plogon;
	uint32_t tmp_proptag;
	FOLDER_OBJECT *pfolder;
	PROPTAG_ARRAY proptags;
	MESSAGE_OBJECT *pmessage;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (import_flags & (~(IMPORT_FLAG_ASSOCIATED|
		IMPORT_FLAG_FAILONCONFLICT))) {
		return ecInvalidParam;
	}
	if (4 != ppropvals->count ||
		PROP_TAG_SOURCEKEY != ppropvals->ppropval[0].proptag ||
		PROP_TAG_LASTMODIFICATIONTIME != ppropvals->ppropval[1].proptag ||
		PROP_TAG_CHANGEKEY != ppropvals->ppropval[2].proptag ||
		PROP_TAG_PREDECESSORCHANGELIST != ppropvals->ppropval[3].proptag) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pctx = static_cast<ICSUPCTX_OBJECT *>(rop_processor_get_object(plogmap,
	            logon_id, hin, &object_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return ecNotSupported;
	}
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_sync_type(pctx)) {
		return ecNotSupported;
	}
	icsupctx_object_mark_started(pctx);
	pfolder = icsupctx_object_get_parent_object(pctx);
	folder_id = folder_object_get_id(pfolder);
	auto pbin = static_cast<BINARY *>(ppropvals->ppropval[0].pvalue);
	if (pbin == nullptr || pbin->cb != 22)
		return ecInvalidParam;
	if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
		return ecError;
	}
	tmp_guid = logon_object_guid(plogon);
	if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
		return ecInvalidParam;
	}
	message_id = rop_util_make_eid(1, tmp_xid.local_id);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon), folder_id,
		message_id, &b_exist)) {
		return ecError;
	}
	*pmessage_id = message_id;
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		rpc_info = get_rpc_info();
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (FALSE == b_exist) {
			if (0 == (permission & PERMISSION_CREATE)) {
				return ecAccessDenied;
			}
			tag_access = TAG_ACCESS_READ;
			if ((permission & PERMISSION_EDITANY) ||
				(permission & PERMISSION_EDITOWNED)) {
				tag_access |= TAG_ACCESS_MODIFY;	
			}
			if ((permission & PERMISSION_DELETEANY) ||
				(permission & PERMISSION_DELETEOWNED)) {
				tag_access |= TAG_ACCESS_DELETE;	
			}
		} else {
			if (permission & PERMISSION_FOLDEROWNER) {
				tag_access = TAG_ACCESS_MODIFY|
					TAG_ACCESS_READ|TAG_ACCESS_DELETE;
			} else {
				if (FALSE == exmdb_client_check_message_owner(
					logon_object_get_dir(plogon), message_id,
					rpc_info.username, &b_owner)) {
					return ecError;
				}
				if (TRUE == b_owner || (permission & PERMISSION_READANY)) {
					tag_access |= TAG_ACCESS_READ;
				}
				if ((permission & PERMISSION_EDITANY) || (TRUE ==
					b_owner && (permission & PERMISSION_EDITOWNED))) {
					tag_access |= TAG_ACCESS_MODIFY;	
				}
				if ((permission & PERMISSION_DELETEANY) || (TRUE ==
					b_owner && (permission & PERMISSION_DELETEOWNED))) {
					tag_access |= TAG_ACCESS_DELETE;	
				}
			}
		}
	} else {
		tag_access = TAG_ACCESS_MODIFY|TAG_ACCESS_READ|TAG_ACCESS_DELETE;
	}
	if (TRUE == b_exist) {
		if (FALSE == exmdb_client_get_message_property(
			logon_object_get_dir(plogon), NULL, 0,
			message_id, PROP_TAG_ASSOCIATED, &pvalue)) {
			return ecError;
		}
		if (IMPORT_FLAG_ASSOCIATED & import_flags) {
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				return ecInvalidParam;
			}
		} else {
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				return ecInvalidParam;
			}
		}
		b_new = FALSE;
	} else {
		b_new = TRUE;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	pmessage = message_object_create(plogon, b_new,
		pinfo->cpid, message_id, &folder_id, tag_access,
		OPEN_MODE_FLAG_READWRITE, pctx->pstate);
	if (NULL == pmessage) {
		return ecError;
	}
	if (TRUE == b_exist) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_PREDECESSORCHANGELIST;
		if (FALSE == message_object_get_properties(
			pmessage, 0, &proptags, &tmp_propvals)) {
			message_object_free(pmessage);
			return ecError;
		}
		pvalue = common_util_get_propvals(&tmp_propvals, 
						PROP_TAG_PREDECESSORCHANGELIST);
		if (NULL == pvalue) {
			message_object_free(pmessage);
			return ecError;
		}
		if (!common_util_pcl_compare(static_cast<BINARY *>(pvalue),
		    static_cast<BINARY *>(ppropvals->ppropval[3].pvalue), &result)) {
			message_object_free(pmessage);
			return ecError;
		}
		if (PCL_INCLUDE & result) {
			return SYNC_E_IGNORE;
		} else if (PCL_CONFLICT == result) {
			if (IMPORT_FLAG_FAILONCONFLICT & import_flags) {
				message_object_free(pmessage);
				return SYNC_E_CONFLICT;
			}
		}
	}
	if (FALSE == b_new) {
		if (FALSE == exmdb_client_clear_message_instance(
			logon_object_get_dir(plogon),
			message_object_get_instance_id(pmessage))) {
			message_object_free(pmessage);
			return ecError;
		}
	} else {
		BOOL b_fai = (import_flags & IMPORT_FLAG_ASSOCIATED) ? TRUE : false;
		if (FALSE == message_object_init_message(
			pmessage, b_fai, pinfo->cpid)) {
			return ecError;
		}
	}
	tmp_propvals.count = 3;
	tmp_propvals.ppropval = ppropvals->ppropval + 1;
	if (FALSE == exmdb_client_set_instance_properties(
		logon_object_get_dir(plogon),
		message_object_get_instance_id(pmessage),
		&tmp_propvals, &tmp_problems)) {
		message_object_free(pmessage);
		return ecError;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_MESSAGE, pmessage);
	if (hnd < 0) {
		message_object_free(pmessage);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_syncimportreadstatechanges(uint16_t count,
	const MESSAGE_READ_STAT *pread_stat,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	XID tmp_xid;
	BOOL b_owner;
	void *pvalue;
	GUID tmp_guid;
	int object_type;
	uint64_t read_cn;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t permission;
	const char *username;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pctx = static_cast<ICSUPCTX_OBJECT *>(rop_processor_get_object(plogmap,
	            logon_id, hin, &object_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return ecNotSupported;
	}
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_sync_type(pctx)) {
		return ecNotSupported;
	}
	icsupctx_object_mark_started(pctx);
	username = NULL;
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		pfolder = icsupctx_object_get_parent_object(pctx);
		folder_id = folder_object_get_id(pfolder);
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_READANY)) {
			username = rpc_info.username;
		}
	}
	for (i=0; i<count; i++) {
		if (FALSE == common_util_binary_to_xid(
			&pread_stat[i].message_xid, &tmp_xid)) {
			return ecError;
		}
		tmp_guid = logon_object_guid(plogon);
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			continue;
		}
		message_id = rop_util_make_eid(1, tmp_xid.local_id);
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				logon_object_get_dir(plogon), message_id,
				username, &b_owner)) {
				return ecError;
			}
			if (FALSE == b_owner) {
				continue;
			}
		}
		tmp_proptags.count = 2;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_ASSOCIATED;
		proptag_buff[1] = PROP_TAG_READ;
		if (FALSE == exmdb_client_get_message_properties(
			logon_object_get_dir(plogon), NULL, 0,
			message_id, &tmp_proptags, &tmp_propvals)) {
			return ecError;
		}
		pvalue = common_util_get_propvals(
			&tmp_propvals, PROP_TAG_ASSOCIATED);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			continue;
		}
		pvalue = common_util_get_propvals(
			&tmp_propvals, PROP_TAG_READ);
		if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
			if (0 == pread_stat[i].mark_as_read) {
				continue;
			}
		} else {
			if (0 != pread_stat[i].mark_as_read) {
				continue;
			}
		}
		if (TRUE == logon_object_check_private(plogon)) {
			if (FALSE == exmdb_client_set_message_read_state(
				logon_object_get_dir(plogon), NULL, message_id,
				pread_stat[i].mark_as_read, &read_cn)) {
				return ecError;
			}
		} else {
			if (FALSE == exmdb_client_set_message_read_state(
				logon_object_get_dir(plogon), rpc_info.username,
				message_id, pread_stat[i].mark_as_read, &read_cn)) {
				return ecError;
			}
		}
		idset_append(pctx->pstate->pread, read_cn);
	}
	return ecSuccess;
}

uint32_t rop_syncimporthierarchychange(const TPROPVAL_ARRAY *phichyvals,
	const TPROPVAL_ARRAY *ppropvals, uint64_t *pfolder_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	XID tmp_xid;
	BOOL b_exist;
	BINARY *pbin;
	BOOL b_guest;
	BOOL b_found;
	void *pvalue;
	GUID tmp_guid;
	int domain_id;
	BOOL b_partial;
	uint32_t result;
	int object_type;
	uint16_t replid;
	uint64_t tmp_fid;
	uint32_t tmp_type;
	EMSMDB_INFO *pinfo;
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t parent_id1;
	uint64_t change_num;
	uint32_t permission;
	uint32_t parent_type;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (6 != phichyvals->count ||
		PROP_TAG_PARENTSOURCEKEY != phichyvals->ppropval[0].proptag ||
		PROP_TAG_SOURCEKEY != phichyvals->ppropval[1].proptag ||
		PROP_TAG_LASTMODIFICATIONTIME != phichyvals->ppropval[2].proptag ||
		PROP_TAG_CHANGEKEY != phichyvals->ppropval[3].proptag ||
		PROP_TAG_PREDECESSORCHANGELIST != phichyvals->ppropval[4].proptag ||
		PROP_TAG_DISPLAYNAME != phichyvals->ppropval[5].proptag) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pctx = static_cast<ICSUPCTX_OBJECT *>(rop_processor_get_object(plogmap,
	            logon_id, hin, &object_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return ecNotSupported;
	}
	if (SYNC_TYPE_HIERARCHY != icsupctx_object_get_sync_type(pctx)) {
		return ecNotSupported;
	}
	icsupctx_object_mark_started(pctx);
	pfolder = icsupctx_object_get_parent_object(pctx);
	rpc_info = get_rpc_info();
	if (0 == ((BINARY*)phichyvals->ppropval[0].pvalue)->cb) {
		parent_type = folder_object_get_type(pfolder);
		parent_id1 = folder_object_get_id(pfolder);
		if (FALSE == exmdb_client_check_folder_id(
			logon_object_get_dir(plogon), parent_id1, &b_exist)) {
			return ecError;
		}
		if (FALSE == b_exist) {
			return SYNC_E_NO_PARENT;
		}
	} else {
		pbin = static_cast<BINARY *>(phichyvals->ppropval[0].pvalue);
		if (pbin == nullptr || pbin->cb != 22)
			return ecInvalidParam;
		if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
			return ecError;
		}
		if (TRUE == logon_object_check_private(plogon)) {
			tmp_guid = rop_util_make_user_guid(
				logon_object_get_account_id(plogon));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return ecInvalidParam;
			}
		} else {
			tmp_guid = rop_util_make_domain_guid(
				logon_object_get_account_id(plogon));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return ecAccessDenied;
			}
		}
		parent_id1 = rop_util_make_eid(1, tmp_xid.local_id);
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(plogon), 0, parent_id1,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			return ecError;
		}
		if (NULL == pvalue) {
			return SYNC_E_NO_PARENT;
		}
		parent_type = *(uint32_t*)pvalue;
	}
	if (FOLDER_TYPE_SEARCH == parent_type) {
		return ecNotSupported;
	}
	pbin = static_cast<BINARY *>(phichyvals->ppropval[1].pvalue);
	if (pbin == nullptr || pbin->cb != 22)
		return ecInvalidParam;
	if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
		return ecError;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		tmp_guid = rop_util_make_user_guid(
			logon_object_get_account_id(plogon));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			return ecInvalidParam;
		}
		folder_id = rop_util_make_eid(1, tmp_xid.local_id);
	} else {
		tmp_guid = rop_util_make_domain_guid(
			logon_object_get_account_id(plogon));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			domain_id = rop_util_make_domain_id(tmp_xid.guid);
			if (-1 == domain_id) {
				return ecInvalidParam;
			}
			if (FALSE == common_util_check_same_org(
				domain_id, logon_object_get_account_id(plogon))) {
				return ecInvalidParam;
			}
			if (FALSE == exmdb_client_get_mapping_replid(
				logon_object_get_dir(plogon),
				tmp_xid.guid, &b_found, &replid)) {
				return ecError;
			}
			if (FALSE == b_found) {
				return ecInvalidParam;
			}
			folder_id = rop_util_make_eid(replid, tmp_xid.local_id);
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_id);
		}
	}
	if (FALSE == exmdb_client_check_folder_id(
		logon_object_get_dir(plogon), folder_id, &b_exist)) {
		return ecError;
	}
	*pfolder_id = 0;
	if (FALSE == b_exist) {
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon), parent_id1,
				rpc_info.username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				return ecAccessDenied;
			}
		}
		if (FALSE == exmdb_client_get_folder_by_name(
			logon_object_get_dir(plogon), parent_id1,
		    static_cast<char *>(phichyvals->ppropval[5].pvalue), &tmp_fid))
			return ecError;
		if (0 != tmp_fid) {
			return ecDuplicateName;
		}
		if (FALSE == exmdb_client_allocate_cn(
			logon_object_get_dir(plogon), &change_num)) {
			return ecError;
		}
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(8 + ppropvals->count);
		if (NULL == tmp_propvals.ppropval) {
			return ecMAPIOOM;
		}
		tmp_propvals.ppropval[0].proptag = PROP_TAG_FOLDERID;
		tmp_propvals.ppropval[0].pvalue = &folder_id;
		tmp_propvals.ppropval[1].proptag = PROP_TAG_PARENTFOLDERID;
		tmp_propvals.ppropval[1].pvalue = &parent_id1;
		tmp_propvals.ppropval[2].proptag = PROP_TAG_LASTMODIFICATIONTIME;
		tmp_propvals.ppropval[2].pvalue = phichyvals->ppropval[2].pvalue;
		tmp_propvals.ppropval[3].proptag = PROP_TAG_CHANGEKEY;
		tmp_propvals.ppropval[3].pvalue = phichyvals->ppropval[3].pvalue;
		tmp_propvals.ppropval[4].proptag = PROP_TAG_PREDECESSORCHANGELIST;
		tmp_propvals.ppropval[4].pvalue = phichyvals->ppropval[4].pvalue;
		tmp_propvals.ppropval[5].proptag = PROP_TAG_DISPLAYNAME;
		tmp_propvals.ppropval[5].pvalue = phichyvals->ppropval[5].pvalue;
		tmp_propvals.ppropval[6].proptag = PROP_TAG_CHANGENUMBER;
		tmp_propvals.ppropval[6].pvalue = &change_num;
		tmp_propvals.count = 7;
		for (i=0; i<ppropvals->count; i++) {
			tmp_propvals.ppropval[tmp_propvals.count] =
								ppropvals->ppropval[i];
			tmp_propvals.count ++;
		}
		if (NULL == common_util_get_propvals(
			&tmp_propvals, PROP_TAG_FOLDERTYPE)) {
			tmp_type = FOLDER_TYPE_GENERIC;
			tmp_propvals.ppropval[tmp_propvals.count].proptag =
											PROP_TAG_FOLDERTYPE;
			tmp_propvals.ppropval[tmp_propvals.count].pvalue =
													&tmp_type;
			tmp_propvals.count ++;
		}
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (FALSE == exmdb_client_create_folder_by_properties(
			logon_object_get_dir(plogon), pinfo->cpid,
			&tmp_propvals, &tmp_fid) || folder_id != tmp_fid) {
			return ecError;
		}
		idset_append(pctx->pstate->pseen, change_num);
		return ecSuccess;
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0, folder_id,
		PROP_TAG_PREDECESSORCHANGELIST, &pvalue) ||
		NULL == pvalue) {
		return ecError;
	}
	if (!common_util_pcl_compare(static_cast<BINARY *>(pvalue),
	    static_cast<BINARY *>(phichyvals->ppropval[4].pvalue), &result))
		return ecError;
	if (PCL_INCLUDE & result) {
		return SYNC_E_IGNORE;
	}
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return ecAccessDenied;
		}
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0, folder_id,
		PROP_TAG_PARENTFOLDERID, &pvalue) || NULL == pvalue) {
		return ecError;
	}
	parent_id = *(uint64_t*)pvalue;
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (FALSE == logon_object_check_private(plogon)) {
			return ecNotSupported;
		}
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return ecAccessDenied;
		}
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon), parent_id1,
				rpc_info.username, &permission)) {
				return ecError;
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				return ecAccessDenied;
			}
			b_guest = TRUE;
		} else {
			b_guest = FALSE;
		}
		pinfo = emsmdb_interface_get_emsmdb_info();
		if (FALSE == exmdb_client_movecopy_folder(
			logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon),
			pinfo->cpid, b_guest, rpc_info.username,
			parent_id, folder_id, parent_id1,
		    static_cast<char *>(phichyvals->ppropval[5].pvalue), false,
			&b_exist, &b_partial)) {
			return ecError;
		}
		if (TRUE == b_exist) {
			return ecDuplicateName;
		}
		if (TRUE == b_partial) {
			return ecError;
		}
	}
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(plogon), &change_num)) {
		return ecError;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5 + ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return ecMAPIOOM;
	}
	tmp_propvals.ppropval[0].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	tmp_propvals.ppropval[0].pvalue = phichyvals->ppropval[2].pvalue;
	tmp_propvals.ppropval[1].proptag = PROP_TAG_CHANGEKEY;
	tmp_propvals.ppropval[1].pvalue = phichyvals->ppropval[3].pvalue;
	tmp_propvals.ppropval[2].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	tmp_propvals.ppropval[2].pvalue = phichyvals->ppropval[4].pvalue;
	tmp_propvals.ppropval[3].proptag = PROP_TAG_DISPLAYNAME;
	tmp_propvals.ppropval[3].pvalue = phichyvals->ppropval[5].pvalue;
	tmp_propvals.ppropval[4].proptag = PROP_TAG_CHANGENUMBER;
	tmp_propvals.ppropval[4].pvalue = &change_num;
	tmp_propvals.count = 5;
	for (i=0; i<ppropvals->count; i++) {
		tmp_propvals.ppropval[tmp_propvals.count] =
							ppropvals->ppropval[i];
		tmp_propvals.count ++;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_set_folder_properties(
		logon_object_get_dir(plogon), pinfo->cpid,
		folder_id, &tmp_propvals, &tmp_problems)) {
		return ecError;
	}
	idset_append(pctx->pstate->pseen, change_num);
	return ecSuccess;
}

uint32_t rop_syncimportdeletes(
	uint8_t flags, const TPROPVAL_ARRAY *ppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	XID tmp_xid;
	void *pvalue;
	BOOL b_exist;
	BOOL b_found;
	uint64_t eid;
	BOOL b_owner;
	int domain_id;
	GUID tmp_guid;
	BOOL b_result;
	BOOL b_partial;
	int object_type;
	uint16_t replid;
	uint8_t sync_type;
	uint64_t folder_id;
	EMSMDB_INFO *pinfo;
	uint32_t permission;
	const char *username;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	EID_ARRAY message_ids;
	FOLDER_OBJECT *pfolder;
	
	if (ppropvals->count != 1 ||
	    PROP_TYPE(ppropvals->ppropval[0].proptag) != PT_MV_BINARY)
		return ecInvalidParam;
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pctx = static_cast<ICSUPCTX_OBJECT *>(rop_processor_get_object(plogmap,
	            logon_id, hin, &object_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return ecNotSupported;
	}
	sync_type = icsupctx_object_get_sync_type(pctx);
	BOOL b_hard = (flags & SYNC_DELETES_FLAG_HARDDELETE) ? TRUE : false;
	if (SYNC_DELETES_FLAG_HIERARCHY & flags) {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			return ecNotSupported;
		}
	}
	icsupctx_object_mark_started(pctx);
	pfolder = icsupctx_object_get_parent_object(pctx);
	folder_id = folder_object_get_id(pfolder);
	rpc_info = get_rpc_info();
	username = rpc_info.username;
	if (LOGON_MODE_OWNER == logon_object_get_mode(plogon)) {
		username = NULL;
	} else {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon), folder_id,
				rpc_info.username, &permission)) {
				if ((permission & PERMISSION_FOLDEROWNER) ||
					(permission & PERMISSION_DELETEANY)) {
					username = NULL;	
				} else if (0 == (permission & PERMISSION_DELETEOWNED)) {
					return ecAccessDenied;
				}
			}
		}
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	auto pbins = static_cast<BINARY_ARRAY *>(ppropvals->ppropval[0].pvalue);
	if (SYNC_TYPE_CONTENTS == sync_type) {
		message_ids.count = 0;
		message_ids.pids = cu_alloc<uint64_t>(pbins->count);
		if (NULL == message_ids.pids) {
			return ecMAPIOOM;
		}
	}
	for (size_t i = 0; i < pbins->count; ++i) {
		if (22 != pbins->pbin[i].cb) {
			return ecInvalidParam;
		}
		if (FALSE == common_util_binary_to_xid(
			pbins->pbin + i, &tmp_xid)) {
			return ecError;
		}
		if (TRUE == logon_object_check_private(plogon)) {
			tmp_guid = rop_util_make_user_guid(
				logon_object_get_account_id(plogon));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return ecInvalidParam;
			}
			eid = rop_util_make_eid(1, tmp_xid.local_id);
		} else {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				tmp_guid = rop_util_make_domain_guid(
					logon_object_get_account_id(plogon));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					return ecInvalidParam;
				}
				eid = rop_util_make_eid(1, tmp_xid.local_id);
			} else {
				tmp_guid = rop_util_make_domain_guid(
					logon_object_get_account_id(plogon));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					domain_id = rop_util_make_domain_id(tmp_xid.guid);
					if (-1 == domain_id) {
						return ecInvalidParam;
					}
					if (FALSE == common_util_check_same_org(
						domain_id, logon_object_get_account_id(plogon))) {
						return ecInvalidParam;
					}
					if (FALSE == exmdb_client_get_mapping_replid(
						logon_object_get_dir(plogon),
						tmp_xid.guid, &b_found, &replid)) {
						return ecError;
					}
					if (FALSE == b_found) {
						return ecInvalidParam;
					}
					eid = rop_util_make_eid(replid, tmp_xid.local_id);
				} else {
					eid = rop_util_make_eid(1, tmp_xid.local_id);
				}
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			if (FALSE == exmdb_client_check_message(
				logon_object_get_dir(plogon), folder_id,
				eid, &b_exist)) {
				return ecError;
			}
		} else {
			if (FALSE == exmdb_client_check_folder_id(
				logon_object_get_dir(plogon), eid, &b_exist)) {
				return ecError;
			}
		}
		if (FALSE == b_exist) {
			continue;
		}
		if (NULL != username) {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				if (FALSE == exmdb_client_check_message_owner(
					logon_object_get_dir(plogon),
					eid, username, &b_owner)) {
					return ecError;
				}
				if (FALSE == b_owner) {
					return ecAccessDenied;
				}
			} else {
				if (FALSE == exmdb_client_check_folder_permission(
					logon_object_get_dir(plogon),
					eid, username, &permission)) {
					if (0 == (PERMISSION_FOLDEROWNER & permission))	{
						return ecAccessDenied;
					}
				}
			}
		}
		if (SYNC_TYPE_CONTENTS == sync_type) {
			message_ids.pids[message_ids.count] = eid;
			message_ids.count ++;
		} else {
			if (TRUE == logon_object_check_private(plogon)) {
				if (FALSE == exmdb_client_get_folder_property(
					logon_object_get_dir(plogon), 0, eid,
					PROP_TAG_FOLDERTYPE, &pvalue)) {
					return ecError;
				}
				if (NULL == pvalue) {
					return ecSuccess;
				}
				if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
					goto DELETE_FOLDER;
				}
			}
			if (FALSE == exmdb_client_empty_folder(
				logon_object_get_dir(plogon), pinfo->cpid,
				username, eid, b_hard, TRUE, TRUE, TRUE,
				&b_partial) || TRUE == b_partial) {
				return ecError;
			}
 DELETE_FOLDER:
			if (FALSE == exmdb_client_delete_folder(
				logon_object_get_dir(plogon), pinfo->cpid,
				eid, b_hard, &b_result) || FALSE == b_result) {
				return ecError;
			}
		}
	}
	if (SYNC_TYPE_CONTENTS == sync_type && message_ids.count > 0) {
		if (FALSE == exmdb_client_delete_messages(
			logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon),
			pinfo->cpid, NULL, folder_id, &message_ids,
			b_hard, &b_partial) || TRUE == b_partial) {
			return ecError;
		}
	}
	return ecSuccess;
}

uint32_t rop_syncimportmessagemove(
	const BINARY *psrc_folder_id, const BINARY *psrc_message_id,
	const BINARY *pchange_list, const BINARY *pdst_message_id,
	const BINARY *pchange_number, uint64_t *pmessage_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	XID xid_src;
	XID xid_dst;
	XID xid_fsrc;
	void *pvalue;
	BOOL b_exist;
	BOOL b_owner;
	BOOL b_result;
	GUID tmp_guid;
	uint32_t result;
	int object_type;
	uint64_t src_fid;
	uint64_t src_mid;
	uint64_t dst_mid;
	EMSMDB_INFO *pinfo;
	uint64_t folder_id;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	TAGGED_PROPVAL tmp_propval;
	
	if (22 != psrc_folder_id->cb ||
		22 != psrc_message_id->cb ||
		22 != pdst_message_id->cb) {
		return ecInvalidParam;
	}
	if (pchange_number->cb < 17 || pchange_number->cb > 24) {
		return ecInvalidParam;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	auto pctx = static_cast<ICSUPCTX_OBJECT *>(rop_processor_get_object(plogmap,
	            logon_id, hin, &object_type));
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return ecNotSupported;
	}
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_sync_type(pctx)) {
		return ecNotSupported;
	}
	icsupctx_object_mark_started(pctx);
	pfolder = icsupctx_object_get_parent_object(pctx);
	folder_id = folder_object_get_id(pfolder);
	if (FALSE == common_util_binary_to_xid(
		psrc_folder_id, &xid_fsrc) ||
		FALSE == common_util_binary_to_xid(
		psrc_message_id, &xid_src) ||
		FALSE == common_util_binary_to_xid(
		pdst_message_id, &xid_dst)) {
		return ecError;
	}
	tmp_guid = logon_object_guid(plogon);
	if (0 != guid_compare(&tmp_guid, &xid_fsrc.guid) ||
		0 != guid_compare(&tmp_guid, &xid_src.guid) ||
		0 != guid_compare(&tmp_guid, &xid_dst.guid)) {
		return ecInvalidParam;
	}
	src_fid = rop_util_make_eid(1, xid_fsrc.local_id);
	src_mid = rop_util_make_eid(1, xid_src.local_id);
	dst_mid = rop_util_make_eid(1, xid_dst.local_id);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		src_fid, src_mid, &b_exist)) {
		return ecError;
	}
	if (FALSE == b_exist) {
		return ecNotFound;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), src_fid,
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (PERMISSION_DELETEANY & permission) {
			/* do nothing */
		} else if (PERMISSION_DELETEOWNED & permission) {
			if (FALSE == exmdb_client_check_message_owner(
				logon_object_get_dir(plogon), src_mid,
				rpc_info.username, &b_owner)) {
				return ecError;
			}
			if (FALSE == b_owner) {
				return ecAccessDenied;
			}
		} else {
			return ecAccessDenied;
		}
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return ecError;
		}
		if (0 == (permission & PERMISSION_CREATE)) {
			return ecAccessDenied;
		}
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0,
		src_mid, PROP_TAG_ASSOCIATED, &pvalue)) {
		return ecError;
	}
	if (NULL == pvalue) {
		return ecNotFound;
	}
	BOOL b_fai = *static_cast<uint8_t *>(pvalue) != 0 ? TRUE : false;
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0, src_mid,
		PROP_TAG_PREDECESSORCHANGELIST, &pvalue)) {
		return ecError;
	}
	if (NULL == pvalue) {
		return ecError;
	}
	if (!common_util_pcl_compare(static_cast<BINARY *>(pvalue), pchange_list, &result))
		return ecError;
	BOOL b_newer = result == PCL_INCLUDED ? TRUE : false;
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_movecopy_message(
		logon_object_get_dir(plogon),
		logon_object_get_account_id(plogon),
		pinfo->cpid, src_mid, folder_id, dst_mid,
		TRUE, &b_result) || FALSE == b_result) {
		return ecError;
	}
	if (TRUE == b_newer) {
		tmp_propval.proptag = PROP_TAG_PREDECESSORCHANGELIST;
		tmp_propval.pvalue = pvalue;
		exmdb_client_set_message_property(
			logon_object_get_dir(plogon), NULL,
			0, dst_mid, &tmp_propval, reinterpret_cast<uint32_t *>(&b_result));
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0, dst_mid,
		PROP_TAG_CHANGENUMBER, &pvalue) || NULL == pvalue) {
		return ecError;
	}
	idset_append(b_fai ? pctx->pstate->pseen_fai : pctx->pstate->pseen,
	             *static_cast<uint64_t *>(pvalue));
	idset_append(pctx->pstate->pgiven, dst_mid);
	*pmessage_id = 0;
	if (TRUE == b_newer) {
		return SYNC_W_CLIENT_CHANGE_NEWER;
	}
	return ecSuccess;
}

uint32_t rop_syncopencollector(uint8_t is_content_collector,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int object_type;
	LOGON_OBJECT *plogon;
	ICSUPCTX_OBJECT *pctx;
	
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
	uint8_t sync_type = is_content_collector == 0 ? SYNC_TYPE_HIERARCHY : SYNC_TYPE_CONTENTS;
	pctx = icsupctx_object_create(plogon, pfolder, sync_type);
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_ICSUPCTX, pctx);
	if (hnd < 0) {
		icsupctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_syncgettransferstate(void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	void *pobject;
	int object_type;
	ICS_STATE *pstate;
	LOGON_OBJECT *plogon;
	FASTDOWNCTX_OBJECT *pctx;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return ecError;
	}
	pobject = rop_processor_get_object(plogmap,
					logon_id, hin, &object_type);
	if (NULL == pobject) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		pstate = icsdownctx_object_get_state(static_cast<ICSDOWNCTX_OBJECT *>(pobject));
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		pstate = icsupctx_object_get_state(static_cast<ICSUPCTX_OBJECT *>(pobject));
	} else {
		return ecNotSupported;
	}
	if (NULL == pstate) {
		return ecError;
	}
	pctx = fastdownctx_object_create(plogon, 0);
	if (NULL == pctx) {
		return ecError;
	}
	if (FALSE == fastdownctx_object_make_state(pctx, pstate)) {
		fastdownctx_object_free(pctx);
		return ecError;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (hnd < 0) {
		fastdownctx_object_free(pctx);
		return ecError;
	}
	*phout = hnd;
	return ecSuccess;
}

uint32_t rop_syncuploadstatestreambegin(uint32_t proptag_state,
	uint32_t buffer_size, void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pctx;
	int object_type;
	
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (!icsdownctx_object_begin_state_stream(static_cast<ICSDOWNCTX_OBJECT *>(pctx), proptag_state))
			return ecError;
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		if (!icsupctx_object_begin_state_stream(static_cast<ICSUPCTX_OBJECT *>(pctx), proptag_state))
			return ecError;
	} else {
		return ecNotSupported;
	}
	return ecSuccess;
}

uint32_t rop_syncuploadstatestreamcontinue(const BINARY *pstream_data,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pctx;
	int object_type;
	
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (!icsdownctx_object_continue_state_stream(static_cast<ICSDOWNCTX_OBJECT *>(pctx), pstream_data))
			return ecError;
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		if (!icsupctx_object_continue_state_stream(static_cast<ICSUPCTX_OBJECT *>(pctx), pstream_data))
			return ecError;
	} else {
		return ecNotSupported;
	}
	return ecSuccess;
}

uint32_t rop_syncuploadstatestreamend(void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	void *pctx;
	int object_type;
	
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (!icsdownctx_object_end_state_stream(static_cast<ICSDOWNCTX_OBJECT *>(pctx)))
			return ecError;
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		if (!icsupctx_object_end_state_stream(static_cast<ICSUPCTX_OBJECT *>(pctx)))
			return ecError;
	} else {
		return ecNotSupported;
	}
	return ecSuccess;
}

uint32_t rop_setlocalreplicamidsetdeleted(uint32_t count,
	const LONG_TERM_ID_RANGE *prange, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	return ecSuccess;
}

uint32_t rop_getlocalreplicaids(uint32_t count,
	GUID *pguid, uint8_t *pglobal_count,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	uint64_t begin_eid;
	
	auto plogon = static_cast<LOGON_OBJECT *>(rop_processor_get_object(plogmap,
	              logon_id, hin, &object_type));
	if (NULL == plogon) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_LOGON != object_type) {
		return ecError;
	}
	if (FALSE == exmdb_client_allocate_ids(
		logon_object_get_dir(plogon), count, &begin_eid)) {
		return ecError;
	}
	/* allocate too many eids within an interval */
	if (0 == begin_eid) {
		return ecError;
	}
	*pguid = logon_object_guid(plogon);
	rop_util_get_gc_array(begin_eid, pglobal_count);
	return ecSuccess;
}
