#include "rops.h"
#include "guid.h"
#include "idset.h"
#include "rop_util.h"
#include "eid_array.h"
#include "common_util.h"
#include "proc_common.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "rop_processor.h"
#include "tpropval_array.h"
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
	int i;
	uint64_t *pmid;
	uint32_t table_id;
	RESTRICTION *pres;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	uint32_t tmp_proptag;
	uint8_t tmp_associated;
	PROPTAG_ARRAY proptags;
	RESTRICTION restriction;
	EID_ARRAY *pmessage_ids;
	RESTRICTION_PROPERTY res_prop;
	
	pres = &restriction;
	if (TRUE == b_fai) {
		tmp_associated = 1;
	} else {
		tmp_associated = 0;
	}
	restriction.rt = RESTRICTION_TYPE_PROPERTY;
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
	for (i=0; i<tmp_set.count; i++) {
		pmid = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_MID);
		if (NULL == pmid) {
			eid_array_free(pmessage_ids);
			return NULL;
		}
		if (FALSE == eid_array_append(pmessage_ids, *pmid)) {
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
	int i;
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
	for (i=0; i<tmp_propvals.count; i++) {
		if (FALSE == tpropval_array_set_propval(
			pproplist, tmp_propvals.ppropval + i)) {
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
		common_util_domain_to_essdn(
			logon_object_get_account(plogon),
			tmp_essdn);
		pbin = common_util_to_folder_replica(
				&long_term_id, tmp_essdn);
		if (NULL == pbin) {
			folder_content_free(pfldctnt);
			return NULL;
		}
		tmp_propval.proptag = META_TAG_NEWFXFOLDER;
		tmp_propval.pvalue = pbin;
		if (FALSE == tpropval_array_set_propval(
			pproplist, &tmp_propval)) {
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
		for (i=0; i<tmp_set.count; i++) {
			pfolder_id = common_util_get_propvals(
				tmp_set.pparray[i], PROP_TAG_FOLDERID);
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
	int64_t max_quota;
	uint32_t total_mail;
	uint64_t total_size;
	LOGON_OBJECT *plogon;
	FASTUPCTX_OBJECT *pctx;
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (flags & ~FAST_DEST_CONFIG_FLAG_MOVE) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return EC_NULL_OBJECT;
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
			return EC_NOT_SUPPORTED;
		}
		break;
	case FAST_SOURCE_OPERATION_COPYMESSAGES:
		if (OBJECT_TYPE_FOLDER != object_type) {
			return EC_NOT_SUPPORTED;
		}
		root_element = ROOT_ELEMENT_MESSAGELIST;
		break;
	case FAST_SOURCE_OPERATION_COPYFOLDER:
		if (OBJECT_TYPE_FOLDER != object_type) {
			return EC_NOT_SUPPORTED;
		}
		root_element = ROOT_ELEMENT_TOPFOLDER;
		break;
	default:
		return EC_INVALID_PARAMETER;
	}
	if (ROOT_ELEMENT_TOPFOLDER == root_element ||
		ROOT_ELEMENT_MESSAGELIST == root_element ||
		ROOT_ELEMENT_FOLDERCONTENT == root_element) {
		tmp_proptags.count = 4;
		tmp_proptags.pproptag = proptag_buff;
		proptag_buff[0] = PROP_TAG_MESSAGESIZEEXTENDED;
		proptag_buff[1] = PROP_TAG_PROHIBITSENDQUOTA;
		proptag_buff[2] = PROP_TAG_ASSOCIATEDCONTENTCOUNT;
		proptag_buff[3] = PROP_TAG_CONTENTCOUNT;
		if (FALSE == logon_object_get_properties(
			plogon, &tmp_proptags, &tmp_propvals)) {
			return EC_ERROR;	
		}
		pvalue = common_util_get_propvals(&tmp_propvals,
							PROP_TAG_PROHIBITSENDQUOTA);
		if (NULL == pvalue) {
			max_quota = -1;
		} else {
			max_quota = *(uint32_t*)pvalue;
			max_quota *= 1024;
		}
		pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_MESSAGESIZEEXTENDED);
		if (NULL == pvalue) {
			total_size = 0;
		} else {
			total_size = *(uint64_t*)pvalue;
		}
		if (max_quota > 0 && total_size > max_quota) {
			return EC_QUOTA_EXCEEDED;
		}
		total_mail = 0;
		pvalue = common_util_get_propvals(&tmp_propvals,
						PROP_TAG_ASSOCIATEDCONTENTCOUNT);
		if (NULL != pvalue) {
			total_mail += *(uint32_t*)pvalue;
		}
		pvalue = common_util_get_propvals(&tmp_propvals,
								PROP_TAG_CONTENTCOUNT);
		if (NULL != pvalue) {
			total_mail += *(uint32_t*)pvalue;
		}
		if (total_mail > common_util_get_param(
			COMMON_UTIL_MAX_MESSAGE)) {
			return EC_QUOTA_EXCEEDED;
		}
	}
	pctx = fastupctx_object_create(plogon, pobject, root_element);
	if (NULL == pctx) {
		return EC_ERROR;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FASTUPCTX, pctx);
	if (*phout < 0) {
		fastupctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
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
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FASTUPCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (FALSE == fastupctx_object_write_buffer(
		pobject, ptransfer_data)) {
		return EC_ERROR;
	}
	*pused_size = ptransfer_data->cb;
	return EC_SUCCESS;
}

uint32_t rop_fasttransfersourcegetbuffer(uint16_t buffer_size,
	uint16_t max_buffer_size, uint16_t *ptransfer_status,
	uint16_t *pin_progress_count, uint16_t *ptotal_step_count,
	uint8_t *preserved, BINARY *ptransfer_data,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_last;
	uint16_t len;
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
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSDOWNCTX != object_type &&
		OBJECT_TYPE_FASTDOWNCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	emsmdb_interface_get_rop_left(&max_rop);
	max_rop -= 32;
	if (max_rop > 0x7b00) {
		max_rop = 0x7b00;
	}
	if (0xBABE == buffer_size) {
		len = max_buffer_size;
	} else {
		len = buffer_size;
	}
	if (len > max_rop) {
		len = max_rop;
	}
	ptransfer_data->pb = common_util_alloc(len);
	if (NULL == ptransfer_data->pb) {
		return EC_OUT_OF_MEMORY;
	}
	if (OBJECT_TYPE_FASTDOWNCTX == object_type) {
		if (FALSE == fastdownctx_object_get_buffer(
			pobject, ptransfer_data->pb, &len, &b_last,
			pin_progress_count, ptotal_step_count)) {
			return EC_ERROR;	
		}
	} else if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (FALSE == icsdownctx_object_check_started(pobject)) {
			if (FALSE == icsdownctx_object_make_sync(pobject)) {
				return EC_ERROR;
			}
		}
		if (FALSE == icsdownctx_object_get_buffer(
			pobject, ptransfer_data->pb, &len, &b_last,
			pin_progress_count, ptotal_step_count)) {
			return EC_ERROR;	
		}
	}
	if (0xBABE != buffer_size && len > max_rop) {
		return EC_BUFFER_TOO_SMALL;
	}
	if (FALSE == b_last) {
		*ptransfer_status = TRANSFER_STATUS_PARTIAL;
	} else {
		*ptransfer_status = TRANSFER_STATUS_DONE;
	}
	ptransfer_data->cb = len;
	return EC_SUCCESS;
}

uint32_t rop_fasttransfersourcecopyfolder(uint8_t flags,
	uint8_t send_options, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	BOOL b_sub;
	int object_type;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	FASTDOWNCTX_OBJECT *pctx;
	FOLDER_CONTENT *pfldctnt;
	
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return EC_INVALID_PARAMETER;
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
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
		return EC_ERROR;
	}
	pctx = fastdownctx_object_create(
			plogon, send_options & 0x0F);
	if (NULL == pctx) {
		folder_content_free(pfldctnt);
		return EC_ERROR;
	}
	if (FALSE == fastdownctx_object_make_topfolder(
		pctx, pfldctnt)) {
		fastdownctx_object_free(pctx);
		folder_content_free(pfldctnt);
		return EC_ERROR;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (*phout < 0) {
		fastdownctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t rop_fasttransfersourcecopymessages(
	const LONGLONG_ARRAY *pmessage_ids, uint8_t flags,
	uint8_t send_options, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout)
{
	int i;
	BOOL b_owner;
	BOOL b_chginfo;
	int object_type;
	EID_ARRAY *pmids;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	FOLDER_OBJECT *pfolder;
	FASTDOWNCTX_OBJECT *pctx;
	
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return EC_INVALID_PARAMETER;	
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return EC_INVALID_PARAMETER;
	}
	/* we ignore the FAST_COPY_MESSAGE_FLAG_MOVE
	   in flags just like exchange 2010 or later */
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		rpc_info = get_rpc_info();
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon),
			folder_object_get_id(pfolder),
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (PERMISSION_READANY & permission) &&
			0 == (PERMISSION_FOLDEROWNER & permission)) {
			for (i=0; i<pmessage_ids->count; i++) {
				if (FALSE == exmdb_client_check_message_owner(
					logon_object_get_dir(plogon), pmessage_ids->pll[i],
					rpc_info.username, &b_owner)) {
					return EC_ERROR;	
				}
				if (FALSE == b_owner) {
					return EC_ACCESS_DENIED;
				}
			}
		}
	}
	pmids = eid_array_init();
	if (NULL == pmids) {
		return EC_OUT_OF_MEMORY;
	}
	if (FALSE == eid_array_batch_append(pmids,
		pmessage_ids->count, pmessage_ids->pll)) {
		eid_array_free(pmids);
		return EC_OUT_OF_MEMORY;
	}
	if (flags & FAST_COPY_MESSAGE_FLAG_SENDENTRYID) {
		b_chginfo = TRUE;
	} else {
		b_chginfo = FALSE;
	}
	pctx = fastdownctx_object_create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		eid_array_free(pmids);
		return EC_ERROR;
	}
	if (FALSE == fastdownctx_object_make_messagelist(
		pctx, b_chginfo, pmids)) {
		fastdownctx_object_free(pctx);
		eid_array_free(pmids);
		return EC_ERROR;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (*phout < 0) {
		fastdownctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
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
		return EC_INVALID_PARAMETER;	
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return EC_INVALID_PARAMETER;
	}
	/* just like exchange 2010 or later */
	if (flags & FAST_COPY_TO_FLAG_MOVE) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type &&
		OBJECT_TYPE_MESSAGE != object_type &&
		OBJECT_TYPE_ATTACHMENT != object_type) {
		return EC_NOT_SUPPORTED;
	}
	pctx = fastdownctx_object_create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		return EC_ERROR;
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
					folder_object_get_id(pobject),
					b_fai, b_normal, b_sub);
		if (NULL == pfldctnt) {
			fastdownctx_object_free(pctx);
			return EC_ERROR;
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
			return EC_ERROR;
		}
		break;
	case OBJECT_TYPE_MESSAGE:
		if (FALSE == message_object_flush_streams(pobject)) {
			return EC_ERROR;
		}
		if (FALSE == exmdb_client_read_message_instance(
			logon_object_get_dir(plogon),
			message_object_get_instance_id(pobject), &msgctnt)) {
			fastdownctx_object_free(pctx);
			return EC_ERROR;
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
			return EC_ERROR;
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (FALSE == attachment_object_flush_streams(pobject)) {
			return EC_ERROR;
		}
		if (FALSE == exmdb_client_read_attachment_instance(
			logon_object_get_dir(plogon),
			attachment_object_get_instance_id(pobject), &attctnt)) {
			fastdownctx_object_free(pctx);
			return EC_ERROR;
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
			return EC_ERROR;
		}
		break;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (*phout < 0) {
		fastdownctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
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
		return EC_INVALID_PARAMETER;	
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return EC_INVALID_PARAMETER;
	}
	/* just like exchange 2010 or later */
	if (flags & FAST_COPY_PROPERTIES_FLAG_MOVE) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pobject = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pobject) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type &&
		OBJECT_TYPE_MESSAGE != object_type &&
		OBJECT_TYPE_ATTACHMENT != object_type) {
		return EC_NOT_SUPPORTED;
	}
	pctx = fastdownctx_object_create(plogon, send_options & 0x0F);
	if (NULL == pctx) {
		return EC_ERROR;
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
					folder_object_get_id(pobject),
					b_fai, b_normal, b_sub);
		if (NULL == pfldctnt) {
			fastdownctx_object_free(pctx);
			return EC_ERROR;
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
			return EC_ERROR;
		}
		break;
	case OBJECT_TYPE_MESSAGE:
		if (FALSE == message_object_flush_streams(pobject)) {
			return EC_ERROR;
		}
		if (FALSE == exmdb_client_read_message_instance(
			logon_object_get_dir(plogon),
			message_object_get_instance_id(pobject), &msgctnt)) {
			fastdownctx_object_free(pctx);
			return EC_ERROR;
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
			return EC_ERROR;	
		}
		break;
	case OBJECT_TYPE_ATTACHMENT:
		if (FALSE == attachment_object_flush_streams(pobject)) {
			return EC_ERROR;
		}
		if (FALSE == exmdb_client_read_attachment_instance(
			logon_object_get_dir(plogon),
			attachment_object_get_instance_id(pobject), &attctnt)) {
			fastdownctx_object_free(pctx);
			return EC_ERROR;
		}
		i = 0;
		while (i < msgctnt.proplist.count) {
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
			return EC_ERROR;
		}
		break;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (*phout < 0) {
		fastdownctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t rop_tellversion(const uint16_t *pversion,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	return EC_SUCCESS;
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
	FOLDER_OBJECT *pfolder;
	ICSDOWNCTX_OBJECT *pctx;
	
	if (SYNC_TYPE_CONTENTS != sync_type &&
		SYNC_TYPE_HIERARCHY != sync_type) {
		return EC_INVALID_PARAMETER;
	}
	if (send_options & ~(SEND_OPTIONS_UNICODE|
		SEND_OPTIONS_USECPID|SEND_OPTIONS_RECOVERMODE|
		SEND_OPTIONS_FORCEUNICODE|SEND_OPTIONS_PARTIAL|
		SEND_OPTIONS_RESERVED1|SEND_OPTIONS_RESERVED2)) {
		return EC_INVALID_PARAMETER;	
	}
	if ((send_options & SEND_OPTIONS_UNICODE) &&
		(send_options & SEND_OPTIONS_USECPID) &&
		(send_options & SEND_OPTIONS_RECOVERMODE)) {
		return EC_INVALID_PARAMETER;
	}
	if (SYNC_TYPE_HIERARCHY == sync_type && NULL != pres) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pfolder = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (SYNC_TYPE_CONTENTS == SYNC_TYPE_CONTENTS) {
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			rpc_info = get_rpc_info();
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon),
				folder_object_get_id(pfolder),
				rpc_info.username, &permission)) {
				return FALSE;	
			}
			if (0 == (permission & PERMISSION_FOLDEROWNER) &&
				0 == (permission & PERMISSION_READANY)) {
				return EC_ACCESS_DENIED;
			}
		}
	}
	if (NULL != pres) {
		if (FALSE == common_util_convert_restriction(
			TRUE, (RESTRICTION*)pres)) {
			return EC_ERROR;
		}
	}
	pctx = icsdownctx_object_create(plogon, pfolder,
			sync_type, send_options, sync_flags,
			pres, extra_flags, pproptags);
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_ICSDOWNCTX, pctx);
	if (*phout < 0) {
		icsdownctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t rop_syncimportmessagechange(uint8_t import_flags,
	const TPROPVAL_ARRAY *ppropvals, uint64_t *pmessage_id,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	BOOL b_new;
	BOOL b_fai;
	XID tmp_xid;
	BOOL b_exist;
	BOOL b_owner;
	BINARY *pbin;
	void *pvalue;
	GUID tmp_guid;
	uint32_t result;
	int object_type;
	EMSMDB_INFO *pinfo;
	uint64_t folder_id;
	uint32_t tag_access;
	uint64_t message_id;
	uint32_t permission;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	uint32_t tmp_proptag;
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	PROPTAG_ARRAY proptags;
	MESSAGE_OBJECT *pmessage;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (import_flags & (~(IMPORT_FLAG_ASSOCIATED|
		IMPORT_FLAG_FAILONCONFLICT))) {
		return EC_INVALID_PARAMETER;	
	}
	if (4 != ppropvals->count ||
		PROP_TAG_SOURCEKEY != ppropvals->ppropval[0].proptag ||
		PROP_TAG_LASTMODIFICATIONTIME != ppropvals->ppropval[1].proptag ||
		PROP_TAG_CHANGEKEY != ppropvals->ppropval[2].proptag ||
		PROP_TAG_PREDECESSORCHANGELIST != ppropvals->ppropval[3].proptag) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_sync_type(pctx)) {
		return EC_NOT_SUPPORTED;
	}
	icsupctx_object_mark_started(pctx);
	pfolder = icsupctx_object_get_parent_object(pctx);
	folder_id = folder_object_get_id(pfolder);
	pbin = ppropvals->ppropval[0].pvalue;
	if (22 != pbin->cb) {
		return EC_INVALID_PARAMETER;
	}
	if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
		return EC_ERROR;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		tmp_guid = rop_util_make_user_guid(
			logon_object_get_account_id(plogon));
	} else {
		tmp_guid = rop_util_make_domain_guid(
			logon_object_get_account_id(plogon));
	}
	if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
		return EC_INVALID_PARAMETER;
	}
	message_id = rop_util_make_eid(1, tmp_xid.local_id);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon), folder_id,
		message_id, &b_exist)) {
		return EC_ERROR;
	}
	*pmessage_id = message_id;
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (FALSE == b_exist) {
			if (0 == (permission & PERMISSION_CREATE)) {
				return EC_ACCESS_DENIED;
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
					return EC_ERROR;	
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
			return EC_ERROR;	
		}
		if (IMPORT_FLAG_ASSOCIATED & import_flags) {
			if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
				return EC_INVALID_PARAMETER;
			}
		} else {
			if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
				return EC_INVALID_PARAMETER;
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
		return EC_ERROR;
	}
	if (TRUE == b_exist) {
		proptags.count = 1;
		proptags.pproptag = &tmp_proptag;
		tmp_proptag = PROP_TAG_PREDECESSORCHANGELIST;
		if (FALSE == message_object_get_properties(
			pmessage, 0, &proptags, &tmp_propvals)) {
			message_object_free(pmessage);
			return EC_ERROR;
		}
		pvalue = common_util_get_propvals(&tmp_propvals, 
						PROP_TAG_PREDECESSORCHANGELIST);
		if (NULL == pvalue) {
			message_object_free(pmessage);
			return EC_ERROR;
		}
		if (FALSE == common_util_pcl_compare(pvalue,
			ppropvals->ppropval[3].pvalue, &result)) {
			message_object_free(pmessage);
			return EC_ERROR;
		}
		if (PCL_INCLUDE & result) {
			return EC_IGNORE_FAILURE;
		} else if (PCL_CONFLICT == result) {
			if (IMPORT_FLAG_FAILONCONFLICT & import_flags) {
				message_object_free(pmessage);
				return EC_SYNC_CONFLICT;
			}
		}
	}
	if (FALSE == b_new) {
		if (FALSE == exmdb_client_clear_message_instance(
			logon_object_get_dir(plogon),
			message_object_get_instance_id(pmessage))) {
			message_object_free(pmessage);
			return EC_ERROR;
		}
	} else {
		if (IMPORT_FLAG_ASSOCIATED & import_flags) {
			b_fai = TRUE;
		} else {
			b_fai = FALSE;
		}
		if (FALSE == message_object_init_message(
			pmessage, b_fai, pinfo->cpid)) {
			return EC_ERROR;	
		}
	}
	tmp_propvals.count = 3;
	tmp_propvals.ppropval = ppropvals->ppropval + 1;
	if (FALSE == exmdb_client_set_instance_properties(
		logon_object_get_dir(plogon),
		message_object_get_instance_id(pmessage),
		&tmp_propvals, &tmp_problems)) {
		message_object_free(pmessage);
		return EC_ERROR;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_MESSAGE, pmessage);
	if (*phout < 0) {
		message_object_free(pmessage);
		return EC_ERROR;
	}
	return EC_SUCCESS;
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
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	uint32_t proptag_buff[2];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pctx = rop_processor_get_object(plogmap,
			logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_sync_type(pctx)) {
		return EC_NOT_SUPPORTED;
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
			return EC_ERROR;
		}
		if (0 == (permission & PERMISSION_READANY)) {
			username = rpc_info.username;
		}
	}
	for (i=0; i<count; i++) {
		if (FALSE == common_util_binary_to_xid(
			&pread_stat[i].message_xid, &tmp_xid)) {
			return EC_ERROR;	
		}
		if (TRUE == logon_object_check_private(plogon)) {
			tmp_guid = rop_util_make_user_guid(
				logon_object_get_account_id(plogon));
		} else {
			tmp_guid = rop_util_make_domain_guid(
				logon_object_get_account_id(plogon));
		}
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			continue;
		}
		message_id = rop_util_make_eid(1, tmp_xid.local_id);
		if (NULL != username) {
			if (FALSE == exmdb_client_check_message_owner(
				logon_object_get_dir(plogon), message_id,
				username, &b_owner)) {
				return EC_ERROR;
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
			return EC_ERROR;
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
				return EC_ERROR;	
			}
		} else {
			if (FALSE == exmdb_client_set_message_read_state(
				logon_object_get_dir(plogon), rpc_info.username,
				message_id, pread_stat[i].mark_as_read, &read_cn)) {
				return EC_ERROR;	
			}
		}
		idset_append(pctx->pstate->pread, read_cn);
	}
	return EC_SUCCESS;
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
	const char *username;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	ICSUPCTX_OBJECT *pctx;
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
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (SYNC_TYPE_HIERARCHY != icsupctx_object_get_sync_type(pctx)) {
		return EC_NOT_SUPPORTED;
	}
	icsupctx_object_mark_started(pctx);
	pfolder = icsupctx_object_get_parent_object(pctx);
	rpc_info = get_rpc_info();
	if (0 == ((BINARY*)phichyvals->ppropval[0].pvalue)->cb) {
		parent_type = folder_object_get_type(pfolder);
		parent_id1 = folder_object_get_id(pfolder);
		if (FALSE == exmdb_client_check_folder_id(
			logon_object_get_dir(plogon), parent_id1, &b_exist)) {
			return EC_ERROR;	
		}
		if (FALSE == b_exist) {
			return EC_NO_PARENT_FOLDER;
		}
	} else {
		pbin = phichyvals->ppropval[0].pvalue;
		if (22 != pbin->cb) {
			return EC_INVALID_PARAMETER;
		}
		if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
			return EC_ERROR;
		}
		if (TRUE == logon_object_check_private(plogon)) {
			tmp_guid = rop_util_make_user_guid(
				logon_object_get_account_id(plogon));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return EC_INVALID_PARAMETER;
			}
		} else {
			tmp_guid = rop_util_make_domain_guid(
				logon_object_get_account_id(plogon));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return EC_ACCESS_DENIED;
			}
		}
		parent_id1 = rop_util_make_eid(1, tmp_xid.local_id);
		if (FALSE == exmdb_client_get_folder_property(
			logon_object_get_dir(plogon), 0, parent_id1,
			PROP_TAG_FOLDERTYPE, &pvalue)) {
			return EC_ERROR;	
		}
		if (NULL == pvalue) {
			return EC_NO_PARENT_FOLDER;
		}
		parent_type = *(uint32_t*)pvalue;
	}
	if (FOLDER_TYPE_SEARCH == parent_type) {
		return EC_NOT_SUPPORTED;
	}
	pbin = phichyvals->ppropval[1].pvalue;
	if (22 != pbin->cb) {
		return EC_INVALID_PARAMETER;
	}
	if (FALSE == common_util_binary_to_xid(pbin, &tmp_xid)) {
		return EC_ERROR;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		tmp_guid = rop_util_make_user_guid(
			logon_object_get_account_id(plogon));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			return EC_INVALID_PARAMETER;
		}
		folder_id = rop_util_make_eid(1, tmp_xid.local_id);
	} else {
		tmp_guid = rop_util_make_domain_guid(
			logon_object_get_account_id(plogon));
		if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
			domain_id = rop_util_make_domain_id(tmp_xid.guid);
			if (-1 == domain_id) {
				return EC_INVALID_PARAMETER;
			}
			if (FALSE == common_util_check_same_org(
				domain_id, logon_object_get_account_id(plogon))) {
				return EC_INVALID_PARAMETER;
			}
			if (FALSE == exmdb_client_get_mapping_replid(
				logon_object_get_dir(plogon),
				tmp_xid.guid, &b_found, &replid)) {
				return EC_ERROR;
			}
			if (FALSE == b_found) {
				return EC_INVALID_PARAMETER;
			}
			folder_id = rop_util_make_eid(replid, tmp_xid.local_id);
		} else {
			folder_id = rop_util_make_eid(1, tmp_xid.local_id);
		}
	}
	if (FALSE == exmdb_client_check_folder_id(
		logon_object_get_dir(plogon), folder_id, &b_exist)) {
		return EC_ERROR;	
	}
	*pfolder_id = 0;
	if (FALSE == b_exist) {
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon), parent_id1,
				rpc_info.username, &permission)) {
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				return EC_ACCESS_DENIED;
			}
		}
		if (FALSE == exmdb_client_get_folder_by_name(
			logon_object_get_dir(plogon), parent_id1,
			phichyvals->ppropval[5].pvalue, &tmp_fid)) {
			return EC_ERROR;	
		}
		if (0 != tmp_fid) {
			return EC_DUPLICATE_NAME;
		}
		if (FALSE == exmdb_client_allocate_cn(
			logon_object_get_dir(plogon), &change_num)) {
			return EC_ERROR;	
		}
		tmp_propvals.count = 0;
		tmp_propvals.ppropval = common_util_alloc(
			(8 + ppropvals->count)*sizeof(TAGGED_PROPVAL));
		if (NULL == tmp_propvals.ppropval) {
			return EC_OUT_OF_MEMORY;
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
			return EC_ERROR;
		}
		idset_append(pctx->pstate->pseen, change_num);
		return EC_SUCCESS;
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0, folder_id,
		PROP_TAG_PREDECESSORCHANGELIST, &pvalue) ||
		NULL == pvalue) {
		return EC_ERROR;
	}
	if (FALSE == common_util_pcl_compare(pvalue,
		phichyvals->ppropval[4].pvalue, &result)) {
		return EC_ERROR;
	}
	if (PCL_INCLUDE & result) {
		return EC_IGNORE_FAILURE;
	}
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_FOLDEROWNER)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == exmdb_client_get_folder_property(
		logon_object_get_dir(plogon), 0, folder_id,
		PROP_TAG_PARENTFOLDERID, &pvalue) || NULL == pvalue) {
		return EC_ERROR;	
	}
	parent_id = *(uint64_t*)pvalue;
	if (parent_id != parent_id1) {
		/* MS-OXCFXICS 3.3.5.8.8 move folders
		within public mailbox is not supported */
		if (FALSE == logon_object_check_private(plogon)) {
			return EC_NOT_SUPPORTED;
		}
		if (rop_util_get_gc_value(folder_id) < PRIVATE_FID_CUSTOM) {
			return EC_ACCESS_DENIED;
		}
		if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
			if (FALSE == exmdb_client_check_folder_permission(
				logon_object_get_dir(plogon), parent_id1,
				rpc_info.username, &permission)) {
				return EC_ERROR;	
			}
			if (0 == (permission & PERMISSION_CREATESUBFOLDER)) {
				return EC_ACCESS_DENIED;
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
			phichyvals->ppropval[5].pvalue, FALSE,
			&b_exist, &b_partial)) {
			return EC_ERROR;
		}
		if (TRUE == b_exist) {
			return EC_DUPLICATE_NAME;
		}
		if (TRUE == b_partial) {
			return EC_ERROR;
		}
	}
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(plogon), &change_num)) {
		return EC_ERROR;	
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = common_util_alloc(
		(5 + ppropvals->count)*sizeof(TAGGED_PROPVAL));
	if (NULL == tmp_propvals.ppropval) {
		return EC_OUT_OF_MEMORY;
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
		return EC_ERROR;
	}
	idset_append(pctx->pstate->pseen, change_num);
	return EC_SUCCESS;
}

uint32_t rop_syncimportdeletes(
	uint8_t flags, const TPROPVAL_ARRAY *ppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	XID tmp_xid;
	BOOL b_hard;
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
	BINARY_ARRAY *pbins;
	const char *username;
	DCERPC_INFO rpc_info;
	LOGON_OBJECT *plogon;
	EID_ARRAY message_ids;
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	
	if (1 != ppropvals->count || PROPVAL_TYPE_BINARY_ARRAY
		!= (ppropvals->ppropval[0].proptag & 0xFFFF)) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pctx = rop_processor_get_object(plogmap,
			logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	sync_type = icsupctx_object_get_sync_type(pctx);
	if (SYNC_DELETES_FLAG_HARDDELETE & flags) {
		b_hard = TRUE;
	} else {
		b_hard = FALSE;
	}
	if (SYNC_DELETES_FLAG_HIERARCHY & flags) {
		if (SYNC_TYPE_CONTENTS == sync_type) {
			return EC_NOT_SUPPORTED;
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
					return EC_ACCESS_DENIED;
				}
			}
		}
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	pbins = ppropvals->ppropval[0].pvalue;
	if (SYNC_TYPE_CONTENTS == sync_type) {
		message_ids.count = 0;
		message_ids.pids = common_util_alloc(
				sizeof(uint64_t)*pbins->count);
		if (NULL == message_ids.pids) {
			return EC_OUT_OF_MEMORY;
		}
	}
	for (i=0; i<pbins->count; i++) {
		if (22 != pbins->pbin[i].cb) {
			return EC_INVALID_PARAMETER;
		}
		if (FALSE == common_util_binary_to_xid(
			pbins->pbin + i, &tmp_xid)) {
			return EC_ERROR;
		}
		if (TRUE == logon_object_check_private(plogon)) {
			tmp_guid = rop_util_make_user_guid(
				logon_object_get_account_id(plogon));
			if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
				return EC_INVALID_PARAMETER;
			}
			eid = rop_util_make_eid(1, tmp_xid.local_id);
		} else {
			if (SYNC_TYPE_CONTENTS == sync_type) {
				tmp_guid = rop_util_make_domain_guid(
					logon_object_get_account_id(plogon));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					return EC_INVALID_PARAMETER;
				}
				eid = rop_util_make_eid(1, tmp_xid.local_id);
			} else {
				tmp_guid = rop_util_make_domain_guid(
					logon_object_get_account_id(plogon));
				if (0 != guid_compare(&tmp_guid, &tmp_xid.guid)) {
					domain_id = rop_util_make_domain_id(tmp_xid.guid);
					if (-1 == domain_id) {
						return EC_INVALID_PARAMETER;
					}
					if (FALSE == common_util_check_same_org(
						domain_id, logon_object_get_account_id(plogon))) {
						return EC_INVALID_PARAMETER;
					}
					if (FALSE == exmdb_client_get_mapping_replid(
						logon_object_get_dir(plogon),
						tmp_xid.guid, &b_found, &replid)) {
						return EC_ERROR;
					}
					if (FALSE == b_found) {
						return EC_INVALID_PARAMETER;
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
				return EC_ERROR;	
			}
		} else {
			if (FALSE == exmdb_client_check_folder_id(
				logon_object_get_dir(plogon), eid, &b_exist)) {
				return EC_ERROR;
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
					return EC_ERROR;	
				}
				if (FALSE == b_owner) {
					return EC_ACCESS_DENIED;
				}
			} else {
				if (FALSE == exmdb_client_check_folder_permission(
					logon_object_get_dir(plogon),
					eid, username, &permission)) {
					if (0 == (PERMISSION_FOLDEROWNER & permission))	{
						return EC_ACCESS_DENIED;
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
					return EC_ERROR;	
				}
				if (NULL == pvalue) {
					return EC_SUCCESS;
				}
				if (FOLDER_TYPE_SEARCH == *(uint32_t*)pvalue) {
					goto DELETE_FOLDER;
				}
			}
			if (FALSE == exmdb_client_empty_folder(
				logon_object_get_dir(plogon), pinfo->cpid,
				username, eid, b_hard, TRUE, TRUE, TRUE,
				&b_partial) || TRUE == b_partial) {
				return EC_ERROR;	
			}
DELETE_FOLDER:
			if (FALSE == exmdb_client_delete_folder(
				logon_object_get_dir(plogon), pinfo->cpid,
				eid, b_hard, &b_result) || FALSE == b_result) {
				return EC_ERROR;	
			}
		}
	}
	if (SYNC_TYPE_CONTENTS == sync_type && message_ids.count > 0) {
		if (FALSE == exmdb_client_delete_messages(
			logon_object_get_dir(plogon),
			logon_object_get_account_id(plogon),
			pinfo->cpid, NULL, folder_id, &message_ids,
			b_hard, &b_partial) || TRUE == b_partial) {
			return EC_ERROR;
		}
	}
	return EC_SUCCESS;
}

uint32_t rop_syncimportmessagemove(
	const BINARY *psrc_folder_id, const BINARY *psrc_message_id,
	const BINARY *pchange_list, const BINARY *pdst_message_id,
	const BINARY *pchange_number, uint64_t *pmessage_id,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_fai;
	XID xid_src;
	XID xid_dst;
	XID xid_fsrc;
	void *pvalue;
	BOOL b_exist;
	BOOL b_owner;
	BOOL b_newer;
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
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	TAGGED_PROPVAL tmp_propval;
	
	if (22 != psrc_folder_id->cb ||
		22 != psrc_message_id->cb ||
		22 != pdst_message_id->cb) {
		return EC_INVALID_PARAMETER;
	}
	if (pchange_number->cb < 17 || pchange_number->cb > 24) {
		return EC_INVALID_PARAMETER;
	}
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pctx = rop_processor_get_object(plogmap,
			logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSUPCTX != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (SYNC_TYPE_CONTENTS != icsupctx_object_get_sync_type(pctx)) {
		return EC_NOT_SUPPORTED;
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
		return EC_ERROR;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		tmp_guid = rop_util_make_user_guid(
			logon_object_get_account_id(plogon));
	} else {
		tmp_guid = rop_util_make_domain_guid(
			logon_object_get_account_id(plogon));
	}
	if (0 != guid_compare(&tmp_guid, &xid_fsrc.guid) ||
		0 != guid_compare(&tmp_guid, &xid_src.guid) ||
		0 != guid_compare(&tmp_guid, &xid_dst.guid)) {
		return EC_INVALID_PARAMETER;
	}
	src_fid = rop_util_make_eid(1, xid_fsrc.local_id);
	src_mid = rop_util_make_eid(1, xid_src.local_id);
	dst_mid = rop_util_make_eid(1, xid_dst.local_id);
	if (FALSE == exmdb_client_check_message(
		logon_object_get_dir(plogon),
		src_fid, src_mid, &b_exist)) {
		return EC_ERROR;	
	}
	if (FALSE == b_exist) {
		return EC_NOT_FOUND;
	}
	rpc_info = get_rpc_info();
	if (LOGON_MODE_OWNER != logon_object_get_mode(plogon)) {
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), src_fid,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (PERMISSION_DELETEANY & permission) {
			/* do nothing */
		} else if (PERMISSION_DELETEOWNED & permission) {
			if (FALSE == exmdb_client_check_message_owner(
				logon_object_get_dir(plogon), src_mid,
				rpc_info.username, &b_owner)) {
				return EC_ERROR;	
			}
			if (FALSE == b_owner) {
				return EC_ACCESS_DENIED;
			}
		} else {
			return EC_ACCESS_DENIED;
		}
		if (FALSE == exmdb_client_check_folder_permission(
			logon_object_get_dir(plogon), folder_id,
			rpc_info.username, &permission)) {
			return EC_ERROR;	
		}
		if (0 == (permission & PERMISSION_CREATE)) {
			return EC_ACCESS_DENIED;
		}
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0,
		src_mid, PROP_TAG_ASSOCIATED, &pvalue)) {
		return EC_ERROR;	
	}
	if (NULL == pvalue) {
		return EC_NOT_FOUND;
	}
	if (0 != *(uint8_t*)pvalue) {
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0, src_mid,
		PROP_TAG_PREDECESSORCHANGELIST, &pvalue)) {
		return EC_ERROR;	
	}
	if (NULL == pvalue) {
		return EC_ERROR;
	}
	if (FALSE == common_util_pcl_compare(
		pvalue, pchange_list, &result)) {
		return EC_ERROR;
	}
	if (PCL_INCLUDED == result){
		b_newer = TRUE;
	} else {
		b_newer = FALSE;
	}
	pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_movecopy_message(
		logon_object_get_dir(plogon),
		logon_object_get_account_id(plogon),
		pinfo->cpid, src_mid, folder_id, dst_mid,
		TRUE, &b_result) || FALSE == b_result) {
		return EC_ERROR;	
	}
	if (TRUE == b_newer) {
		tmp_propval.proptag = PROP_TAG_PREDECESSORCHANGELIST;
		tmp_propval.pvalue = pvalue;
		exmdb_client_set_message_property(
			logon_object_get_dir(plogon), NULL,
			0, dst_mid, &tmp_propval, &b_result);
	}
	if (FALSE == exmdb_client_get_message_property(
		logon_object_get_dir(plogon), NULL, 0, dst_mid,
		PROP_TAG_CHANGENUMBER, &pvalue) || NULL == pvalue) {
		return EC_ERROR;	
	}
	if (TRUE == b_fai) {
		idset_append(pctx->pstate->pseen_fai, *(uint64_t*)pvalue);
	} else {
		idset_append(pctx->pstate->pseen, *(uint64_t*)pvalue);
	}
	idset_append(pctx->pstate->pgiven, dst_mid);
	*pmessage_id = 0;
	if (TRUE == b_newer) {
		return EC_NEW_CLIENT_CHANGE;
	}
	return EC_SUCCESS;
}

uint32_t rop_syncopencollector(uint8_t is_content_collector,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	int object_type;
	uint8_t sync_type;
	LOGON_OBJECT *plogon;
	ICSUPCTX_OBJECT *pctx;
	FOLDER_OBJECT *pfolder;
	
	plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (NULL == plogon) {
		return EC_ERROR;
	}
	pfolder = rop_processor_get_object(plogmap,
					logon_id, hin, &object_type);
	if (NULL == pfolder) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_FOLDER != object_type) {
		return EC_NOT_SUPPORTED;
	}
	if (0 == is_content_collector) {
		sync_type = SYNC_TYPE_HIERARCHY;
	} else {
		sync_type = SYNC_TYPE_CONTENTS;
	}
	pctx = icsupctx_object_create(plogon, pfolder, sync_type);
	*phout = rop_processor_add_object_handle(plogmap,
			logon_id, hin, OBJECT_TYPE_ICSUPCTX, pctx);
	if (*phout < 0) {
		icsupctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
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
		return EC_ERROR;
	}
	pobject = rop_processor_get_object(plogmap,
					logon_id, hin, &object_type);
	if (NULL == pobject) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		pstate = icsdownctx_object_get_state(pobject);
		if (NULL == pstate) {
			return EC_ERROR;
		}
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		pstate = icsupctx_object_get_state(pobject);
		if (NULL == pstate) {
			return EC_ERROR;
		}
	} else {
		return EC_NOT_SUPPORTED;
	}
	if (NULL == pstate) {
		return EC_ERROR;
	}
	pctx = fastdownctx_object_create(plogon, 0);
	if (NULL == pctx) {
		return EC_ERROR;
	}
	if (FALSE == fastdownctx_object_make_state(pctx, pstate)) {
		fastdownctx_object_free(pctx);
		return EC_ERROR;
	}
	*phout = rop_processor_add_object_handle(plogmap,
		logon_id, hin, OBJECT_TYPE_FASTDOWNCTX, pctx);
	if (*phout < 0) {
		fastdownctx_object_free(pctx);
		return EC_ERROR;
	}
	return EC_SUCCESS;
}

uint32_t rop_syncuploadstatestreambegin(uint32_t proptag_state,
	uint32_t buffer_size, void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pctx;
	int object_type;
	
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (FALSE == icsdownctx_object_begin_state_stream(
			pctx, proptag_state)) {
			return EC_ERROR;
		}
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		if (FALSE == icsupctx_object_begin_state_stream(
			pctx, proptag_state)) {
			return EC_ERROR;	
		}
	} else {
		return EC_NOT_SUPPORTED;
	}
	return EC_SUCCESS;
}

uint32_t rop_syncuploadstatestreamcontinue(const BINARY *pstream_data,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pctx;
	int object_type;
	
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (FALSE == icsdownctx_object_continue_state_stream(
			pctx, pstream_data)) {
			return EC_ERROR;
		}
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		if (FALSE == icsupctx_object_continue_state_stream(
			pctx, pstream_data)) {
			return EC_ERROR;	
		}
	} else {
		return EC_NOT_SUPPORTED;
	}
	return EC_SUCCESS;
}

uint32_t rop_syncuploadstatestreamend(void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	void *pctx;
	int object_type;
	
	pctx = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == pctx) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_ICSDOWNCTX == object_type) {
		if (FALSE == icsdownctx_object_end_state_stream(pctx)) {
			return EC_ERROR;
		}
	} else if (OBJECT_TYPE_ICSUPCTX == object_type) {
		if (FALSE == icsupctx_object_end_state_stream(pctx)) {
			return EC_ERROR;	
		}
	} else {
		return EC_NOT_SUPPORTED;
	}
	return EC_SUCCESS;
}

uint32_t rop_setlocalreplicamidsetdeleted(uint32_t count,
	const LONG_TERM_ID_RANGE *prange, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	return EC_SUCCESS;
}

uint32_t rop_getlocalreplicaids(uint32_t count,
	GUID *pguid, uint8_t *pglobal_count,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	uint64_t begin_eid;
	LOGON_OBJECT *plogon;
	
	plogon = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == plogon) {
		return EC_NULL_OBJECT;
	}
	if (OBJECT_TYPE_LOGON != object_type) {
		return EC_ERROR;
	}
	if (FALSE == exmdb_client_allocate_ids(
		logon_object_get_dir(plogon), count, &begin_eid)) {
		return EC_ERROR;	
	}
	/* allocate too many eids within an interval */
	if (0 == begin_eid) {
		return EC_ERROR;
	}
	if (TRUE == logon_object_check_private(plogon)) {
		*pguid = rop_util_make_user_guid(
			logon_object_get_account_id(plogon));
	} else {
		*pguid = rop_util_make_domain_guid(
			logon_object_get_account_id(plogon));
	}
	rop_util_get_gc_array(begin_eid, pglobal_count);
	return EC_SUCCESS;
}
