#include <gromox/defs.h>
#include "emsmdb_interface.h"
#include "rop_dispatch.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "rops.h"
#include "util.h"


int rop_dispatch(ROP_REQUEST *prequest,
	ROP_RESPONSE **ppresponse,
	uint32_t *phandles, uint8_t hnum)
{
	void *pdata;
	uint8_t rop_id;
	uint16_t max_rop;
	EXT_PUSH ext_push;
	void *perr_response;
	EMSMDB_INFO *pemsmdb_info;
	uint8_t partial_completion;
	
	pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	if (prequest->hindex >= hnum) {
		return ecInvalidObject;
	}
	if (prequest->rop_id == ropRelease) {
		rop_release(pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex]);
		*ppresponse = NULL;
		return ecSuccess;
	}
	*ppresponse = common_util_alloc(sizeof(ROP_RESPONSE));
	if (NULL == *ppresponse) {
		return ecMAPIOOM;
	}
	(*ppresponse)->rop_id = prequest->rop_id;
	(*ppresponse)->ppayload = NULL;
	
	switch (prequest->rop_id) {
	case ropLogon: {
		(*ppresponse)->hindex = prequest->hindex;
		perr_response = common_util_alloc(sizeof(LOGON_REDIRECT_RESPONSE));
		if (NULL == perr_response) {
			return ecMAPIOOM;
		}
		LOGON_REQUEST *rq = prequest->ppayload;
		LOGON_REDIRECT_RESPONSE *rdr = perr_response;
		if (rq->pessdn != nullptr)
			strncpy(rdr->pserver_name, rq->pessdn, 1024);
		else
			rdr->pserver_name[0] = '\0';
		if (rq->logon_flags & LOGON_FLAG_PRIVATE) {
			(*ppresponse)->ppayload =
				common_util_alloc(sizeof(LOGON_PMB_RESPONSE));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			LOGON_PMB_RESPONSE *pmb = (*ppresponse)->ppayload;
			pmb->logon_flags = rq->logon_flags;
			(*ppresponse)->result = rop_logon_pmb(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, pmb->folder_ids,
				&pmb->response_flags, &pmb->mailbox_guid,
				&pmb->replica_id, &pmb->replica_guid,
				&pmb->logon_time, &pmb->gwart_time,
				&pmb->store_stat,
				pemsmdb_info->plogmap, prequest->logon_id, phandles + prequest->hindex);
		} else {
			(*ppresponse)->ppayload = common_util_alloc(sizeof(LOGON_PF_RESPONSE));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			LOGON_PF_RESPONSE *pfr = (*ppresponse)->ppayload;
			pfr->logon_flags = rq->logon_flags;
			(*ppresponse)->result = rop_logon_pf(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, pfr->folder_ids,
				&pfr->replica_id, &pfr->replica_guid,
				&pfr->per_user_guid,
				pemsmdb_info->plogmap, prequest->logon_id, phandles + prequest->hindex);
		}
		if ((*ppresponse)->result == ecWrongServer) {
			rdr->logon_flags = rq->logon_flags;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	}
	case ropGetReceiveFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETRECEIVEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETRECEIVEFOLDER_REQUEST *rq = prequest->ppayload;
		GETRECEIVEFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getreceivefolder(rq->pstr_class,
			&rsp->folder_id, &rsp->pstr_class,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetReceiveFolder: {
		SETRECEIVEFOLDER_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setreceivefolder(
			rq->folder_id, rq->pstr_class,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetReceiveFolderTable: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETRECEIVEFOLDERTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETRECEIVEFOLDERTABLE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getreceivefoldertable(&rsp->rows,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetStoreState: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSTORESTAT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETSTORESTAT_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getstorestat(&rsp->stat,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetOwningServers: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETOWNINGSERVERS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETOWNINGSERVERS_REQUEST *rq = prequest->ppayload;
		GETOWNINGSERVERS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getowningservers(
			rq->folder_id, &rsp->ghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropPublicFolderIsGhosted: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(PUBLICFOLDERISGHOSTED_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		PUBLICFOLDERISGHOSTED_REQUEST *rq = prequest->ppayload;
		PUBLICFOLDERISGHOSTED_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_publicfolderisghosted(
			rq->folder_id, &rsp->pghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropLongTermIdFromId: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(LONGTERMIDFROMID_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		LONGTERMIDFROMID_REQUEST *rq = prequest->ppayload;
		LONGTERMIDFROMID_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_longtermidfromid(
			rq->id, &rsp->long_term_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropIdFromLongTermId: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(IDFROMLONGTERMID_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		IDFROMLONGTERMID_REQUEST *rq = prequest->ppayload;
		IDFROMLONGTERMID_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_idfromlongtermid(
			&rq->long_term_id, &rsp->id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPerUserLongTermIds: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPERUSERLONGTERMIDS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETPERUSERLONGTERMIDS_REQUEST *rq = prequest->ppayload;
		GETPERUSERLONGTERMIDS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getperuserlongtermids(
			&rq->guid, &rsp->ids,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPerUserGuid: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPERUSERGUID_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETPERUSERGUID_REQUEST *rq = prequest->ppayload;
		GETPERUSERGUID_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getperuserguid(
			&rq->long_term_id, &rsp->guid,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadPerUserInformation: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(READPERUSERINFORMATION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		READPERUSERINFORMATION_REQUEST *rq = prequest->ppayload;
		READPERUSERINFORMATION_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_readperuserinformation(
			&rq->long_folder_id, rq->reserved, rq->data_offset,
			rq->max_data_size, &rsp->has_finished, &rsp->data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWritePerUserInformation: {
		WRITEPERUSERINFORMATION_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_writeperuserinformation(
			&rq->long_folder_id, rq->has_finished,
			rq->offset, &rq->data, rq->pguid,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenFolder: {
		OPENFOLDER_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		OPENFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_openfolder(rq->folder_id,
			rq->open_flags, &rsp->has_rules, &rsp->pghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropCreateFolder: {
		CREATEFOLDER_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		CREATEFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_createfolder(rq->folder_type,
			rq->use_unicode, rq->open_existing, rq->reserved,
			rq->pfolder_name, rq->pfolder_comment,
			&rsp->folder_id, &rsp->is_existing, &rsp->has_rules,
			&rsp->pghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropDeleteFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		DELETEFOLDER_REQUEST *rq = prequest->ppayload;
		DELETEFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_deletefolder(rq->flags,
			rq->folder_id, &rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetSearchCriteria: {
		SETSEARCHCRITERIA_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setsearchcriteria(rq->pres,
			&rq->folder_ids, rq->search_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetSearchCriteria: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSEARCHCRITERIA_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETSEARCHCRITERIA_REQUEST *rq = prequest->ppayload;
		GETSEARCHCRITERIA_RESPONSE *rsp = (*ppresponse)->ppayload;
		rsp->logon_id = prequest->logon_id;
		(*ppresponse)->result = rop_getsearchcriteria(rq->use_unicode,
			rq->include_restriction, rq->include_folders,
			&rsp->pres, &rsp->folder_ids, &rsp->search_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropMoveCopyMessages: {
		MOVECOPYMESSAGES_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(MOVECOPYMESSAGES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		MOVECOPYMESSAGES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_movecopymessages(&rq->message_ids,
			rq->want_asynchronous, rq->want_copy,
			&rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			perr_response = common_util_alloc(sizeof(NULL_DST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			NULL_DST_RESPONSE *nr = perr_response;
			nr->hindex = rq->hindex;
			nr->partial_completion = rsp->partial_completion;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	}
	case ropMoveFolder: {
		MOVEFOLDER_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(MOVEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		MOVEFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_movefolder(rq->want_asynchronous,
			rq->use_unicode, rq->folder_id, rq->pnew_name,
			&rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			perr_response = common_util_alloc(sizeof(NULL_DST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			NULL_DST_RESPONSE *nr = perr_response;
			nr->hindex = rq->hindex;
			nr->partial_completion = rsp->partial_completion;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	}
	case ropCopyFolder: {
		COPYFOLDER_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		COPYFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_copyfolder(rq->want_asynchronous,
			rq->want_recursive, rq->use_unicode, rq->folder_id,
			rq->pnew_name, &rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			perr_response = common_util_alloc(sizeof(NULL_DST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			NULL_DST_RESPONSE *nr = perr_response;
			nr->hindex = rq->hindex;
			nr->partial_completion = rsp->partial_completion;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	}
	case ropEmptyFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(EMPTYFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		EMPTYFOLDER_REQUEST *rq = prequest->ppayload;
		EMPTYFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_emptyfolder(rq->want_asynchronous,
			rq->want_delete_associated, &rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropHardDeleteMessagesAndSubfolders: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(EMPTYFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST *rq = prequest->ppayload;
		HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_harddeletemessagesandsubfolders(
			rq->want_asynchronous, rq->want_delete_associated,
			&rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeleteMessages: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEMESSAGES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		DELETEMESSAGES_REQUEST *rq = prequest->ppayload;
		DELETEMESSAGES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_deletemessages(rq->want_asynchronous,
			rq->notify_non_read, &rq->message_ids,
			&rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropHardDeleteMessages: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(HARDDELETEMESSAGES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		HARDDELETEMESSAGES_REQUEST *rq = prequest->ppayload;
		HARDDELETEMESSAGES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_harddeletemessages(
			rq->want_asynchronous, rq->notify_non_read,
			&rq->message_ids, &rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetHierarchyTable: {
		GETHIERARCHYTABLE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETHIERARCHYTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETHIERARCHYTABLE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_gethierarchytable(
			rq->table_flags, &rsp->row_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropGetContentsTable: {
		GETCONTENTSTABLE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETCONTENTSTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETCONTENTSTABLE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getcontentstable(rq->table_flags,
			&rsp->row_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSetColumns: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETCOLUMNS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETCOLUMNS_REQUEST *rq = prequest->ppayload;
		SETCOLUMNS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_setcolumns(rq->table_flags,
			&rq->proptags, &rsp->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSortTable: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SORTTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SORTTABLE_REQUEST *rq = prequest->ppayload;
		SORTTABLE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_sorttable(rq->table_flags,
			&rq->sort_criteria, &rsp->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropRestrict: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(RESTRICT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		RESTRICT_REQUEST *rq = prequest->ppayload;
		RESTRICT_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_restrict(rq->res_flags, rq->pres,
			&rsp->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryRows: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYROWS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80) {
			return ecBufferTooSmall;
		}
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (NULL == pdata) {
			return ecMAPIOOM;
		}
		ext_buffer_push_init(&ext_push, pdata, max_rop, EXT_FLAG_UTF16|EXT_FLAG_TBLLMT);
		QUERYROWS_REQUEST *rq = prequest->ppayload;
		QUERYROWS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_queryrows(rq->flags,
			rq->forward_read, rq->row_count, &rsp->seek_pos,
			&rsp->count,
			&ext_push, pemsmdb_info->plogmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			rsp->bin_rows.pb = pdata;
			rsp->bin_rows.cb = ext_push.offset;
		}
		break;
	}
	case ropAbort: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(ABORT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		ABORT_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_abort(&rsp->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetStatus: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSTATUS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETSTATUS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getstatus(&rsp->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryPosition: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYPOSITION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		QUERYPOSITION_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_queryposition(
			&rsp->numerator, &rsp->denominator,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRow: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYPOSITION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SEEKROW_REQUEST *rq = prequest->ppayload;
		SEEKROW_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_seekrow(rq->seek_pos, rq->offset,
			rq->want_moved_count, &rsp->has_soughtless,
			&rsp->offset_sought,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRowBookmark: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SEEKROWBOOKMARK_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SEEKROWBOOKMARK_REQUEST *rq = prequest->ppayload;
		SEEKROWBOOKMARK_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_seekrowbookmark(&rq->bookmark,
			rq->offset, rq->want_moved_count, &rsp->row_invisible,
			&rsp->has_soughtless, &rsp->offset_sought,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRowFractional: {
		SEEKROWFRACTIONAL_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_seekrowfractional(rq->numerator, rq->denominator,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCreateBookmark: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEBOOKMARK_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		CREATEBOOKMARK_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_createbookmark(&rsp->bookmark,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryColumnsAll: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYCOLUMNSALL_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		QUERYCOLUMNSALL_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_querycolumnsall(&rsp->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFindRow: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(FINDROW_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		FINDROW_REQUEST *rq = prequest->ppayload;
		FINDROW_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_findrow(rq->flags, rq->pres,
			rq->seek_pos, &rq->bookmark, &rsp->bookmark_invisible,
			&rsp->prow, &rsp->pcolumns,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFreeBookmark: {
		FREEBOOKMARK_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_freebookmark(&rq->bookmark,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropResetTable:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_resettable(pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropExpandRow: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(EXPANDROW_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80) {
			return ecBufferTooSmall;
		}
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (NULL == pdata) {
			return ecMAPIOOM;
		}
		ext_buffer_push_init(&ext_push, pdata, max_rop, EXT_FLAG_UTF16);
		EXPANDROW_REQUEST *rq = prequest->ppayload;
		EXPANDROW_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_expandrow(rq->max_count,
			rq->category_id, &rsp->expanded_count,
			&rsp->count, &ext_push,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			rsp->bin_rows.pb = pdata;
			rsp->bin_rows.cb = ext_push.offset;
		}
		break;
	}
	case ropCollapseRow: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COLLAPSEROW_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		COLLAPSEROW_REQUEST *rq = prequest->ppayload;
		COLLAPSEROW_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_collapserow(
			rq->category_id, &rsp->collapsed_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetCollapseState: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETCOLLAPSESTATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETCOLLAPSESTATE_REQUEST *rq = prequest->ppayload;
		GETCOLLAPSESTATE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getcollapsestate(rq->row_id,
			rq->row_instance, &rsp->collapse_state,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetCollapseState: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETCOLLAPSESTATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETCOLLAPSESTATE_REQUEST *rq = prequest->ppayload;
		SETCOLLAPSESTATE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_setcollapsestate(
			&rq->collapse_state, &rsp->bookmark,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenMessage: {
		OPENMESSAGE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		OPENMESSAGE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_openmessage(rq->cpid, rq->folder_id,
			rq->open_mode_flags, rq->message_id,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			 pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			 phandles + (*ppresponse)->hindex);
		break;
	}
	case ropCreateMessage: {
		CREATEMESSAGE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		CREATEMESSAGE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_createmessage(rq->cpid,
			rq->folder_id, rq->associated_flag, &rsp->pmessage_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSaveChangesMessage: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SAVECHANGESMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SAVECHANGESMESSAGE_REQUEST *rq = prequest->ppayload;
		SAVECHANGESMESSAGE_RESPONSE *rsp = (*ppresponse)->ppayload;
		rsp->hindex = rq->hindex;
		(*ppresponse)->result = rop_savechangesmessage(rq->save_flags,
			&rsp->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		break;
	}
	case ropRemoveAllRecipients: {
		REMOVEALLRECIPIENTS_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_removeallrecipients(rq->reserved,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropModifyRecipients: {
		MODIFYRECIPIENTS_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifyrecipients(&rq->proptags,
			rq->count, rq->prow,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadRecipients: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(READRECIPIENTS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80) {
			return ecBufferTooSmall;
		}
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (NULL == pdata) {
			return ecMAPIOOM;
		}
		ext_buffer_push_init(&ext_push, pdata, max_rop, EXT_FLAG_UTF16);
		READRECIPIENTS_REQUEST *rq = prequest->ppayload;
		READRECIPIENTS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_readrecipients(rq->row_id,
			rq->reserved, &rsp->count,
			&ext_push, pemsmdb_info->plogmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			rsp->bin_recipients.pb = pdata;
			rsp->bin_recipients.cb = ext_push.offset;
		}
		break;
	}
	case ropReloadCachedInformation: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(RELOADCACHEDINFORMATION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		RELOADCACHEDINFORMATION_REQUEST *rq = prequest->ppayload;
		RELOADCACHEDINFORMATION_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_reloadcachedinformation(rq->reserved,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetMessageStatus: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETMESSAGESTATUS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETMESSAGESTATUS_REQUEST *rq = prequest->ppayload;
		SETMESSAGESTATUS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_setmessagestatus(rq->message_id,
			rq->message_status, rq->status_mask,
			&rsp->message_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetMessageStatus: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETMESSAGESTATUS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETMESSAGESTATUS_REQUEST *rq = prequest->ppayload;
		GETMESSAGESTATUS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getmessagestatus(
			rq->message_id, &rsp->message_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetReadFlags: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETREADFLAGS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETREADFLAGS_REQUEST *rq = prequest->ppayload;
		SETREADFLAGS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_setreadflags(rq->want_asynchronous,
			rq->read_flags, &rq->message_ids,
			&rsp->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetMessageReadFlag: {
		SETMESSAGEREADFLAG_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETMESSAGEREADFLAG_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETMESSAGEREADFLAG_RESPONSE *rsp = (*ppresponse)->ppayload;
		rsp->logon_id = prequest->logon_id;
		rsp->pclient_data = rq->pclient_data;
		(*ppresponse)->result = rop_setmessagereadflag(
			rq->flags, rq->pclient_data, &rsp->read_changed,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		break;
	}
	case ropOpenAttachment: {
		OPENATTACHMENT_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_openattachment(
			rq->flags, rq->attachment_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropCreateAttachment: {
		CREATEATTACHMENT_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEATTACHMENT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		CREATEATTACHMENT_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_createattachment(
			&rsp->attachment_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropDeleteAttachment: {
		DELETEATTACHMENT_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_deleteattachment(rq->attachment_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSaveChangesAttachment: {
		SAVECHANGESATTACHMENT_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_savechangesattachment(
			rq->save_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		break;
	}
	case ropOpenEmbeddedMessage: {
		OPENEMBEDDEDMESSAGE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENEMBEDDEDMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		OPENEMBEDDEDMESSAGE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_openembeddedmessage(rq->cpid,
			rq->open_embedded_flags, &rsp->reserved,
			&rsp->message_id, &rsp->has_named_properties,
			&rsp->subject_prefix, &rsp->normalized_subject,
			&rsp->recipient_count, &rsp->recipient_columns,
			&rsp->row_count, &rsp->precipient_row,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropGetAttachmentTable: {
		GETATTACHMENTTABLE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_getattachmenttable(rq->table_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropGetValidAttachments: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETVALIDATTACHMENTS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETVALIDATTACHMENTS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getvalidattachments(&rsp->attachment_ids,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSubmitMessage: {
		SUBMITMESSAGE_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_submitmessage(rq->submit_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropAbortSubmit: {
		ABORTSUBMIT_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_abortsubmit(
			rq->folder_id, rq->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetAddressTypes: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETADDRESSTYPES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETADDRESSTYPES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getaddresstypes(&rsp->address_types,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetSpooler:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setspooler(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSpoolerLockMessage: {
		SPOOLERLOCKMESSAGE_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_spoolerlockmessage(
			rq->message_id, rq->lock_stat,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportSend: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(TRANSPORTSEND_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		TRANSPORTSEND_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_transportsend(&rsp->ppropvals,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportNewMail: {
		TRANSPORTNEWMAIL_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_transportnewmail(rq->message_id,
			rq->folder_id, rq->pstr_class, rq->message_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetTransportFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETTRANSPORTFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETTRANSPORTFOLDER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_gettransportfolder(&rsp->folder_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOptionsData: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPTIONSDATA_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		OPTIONSDATA_REQUEST *rq = prequest->ppayload;
		OPTIONSDATA_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_optionsdata(rq->paddress_type,
			rq->want_win32, &rsp->reserved, &rsp->options_info,
			&rsp->help_file, &rsp->pfile_name,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertyIdsFromNames: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTYIDSFROMNAMES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETPROPERTYIDSFROMNAMES_REQUEST *rq = prequest->ppayload;
		GETPROPERTYIDSFROMNAMES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getpropertyidsfromnames(
			rq->flags, &rq->propnames, &rsp->propids,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetNamesFromPropertyIds: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETNAMESFROMPROPERTYIDS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETNAMESFROMPROPERTYIDS_REQUEST *rq = prequest->ppayload;
		GETNAMESFROMPROPERTYIDS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getnamesfrompropertyids(
			&rq->propids, &rsp->propnames,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesSpecific: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTIESSPECIFIC_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETPROPERTIESSPECIFIC_REQUEST *rq = prequest->ppayload;
		GETPROPERTIESSPECIFIC_RESPONSE *rsp = (*ppresponse)->ppayload;
		rsp->pproptags = &rq->proptags;
		(*ppresponse)->result = rop_getpropertiesspecific(
			rq->size_limit, rq->want_unicode, &rq->proptags, &rsp->row,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesAll: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTIESALL_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETPROPERTIESALL_REQUEST *rq = prequest->ppayload;
		GETPROPERTIESALL_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getpropertiesall(rq->size_limit,
			rq->want_unicode, &rsp->propvals,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesLIst: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTIESLIST_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETPROPERTIESLIST_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getpropertieslist(&rsp->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetProperties: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETPROPERTIES_REQUEST *rq = prequest->ppayload;
		SETPROPERTIES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_setproperties(
			&rq->propvals, &rsp->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetPropertiesNoReplicate: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETPROPERTIESNOREPLICATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SETPROPERTIESNOREPLICATE_REQUEST *rq = prequest->ppayload;
		SETPROPERTIESNOREPLICATE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_setpropertiesnoreplicate(
			&rq->propvals, &rsp->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeleteProperties: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		DELETEPROPERTIES_REQUEST *rq = prequest->ppayload;
		DELETEPROPERTIES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_deleteproperties(
			&rq->proptags, &rsp->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeletePropertiesNoReplicate: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEPROPERTIESNOREPLICATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		DELETEPROPERTIESNOREPLICATE_REQUEST *rq = prequest->ppayload;
		DELETEPROPERTIESNOREPLICATE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_deletepropertiesnoreplicate(
			&rq->proptags, &rsp->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryNamedProperties: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYNAMEDPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		QUERYNAMEDPROPERTIES_REQUEST *rq = prequest->ppayload;
		QUERYNAMEDPROPERTIES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_querynamedproperties(
			rq->query_flags, rq->pguid, &rsp->propidnames,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCopyProperties: {
		COPYPROPERTIES_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		COPYPROPERTIES_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_copyproperties(
			rq->want_asynchronous, rq->copy_flags, &rq->proptags,
			&rsp->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			(*ppresponse)->ppayload = common_util_alloc(sizeof(uint32_t));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			*static_cast(uint32_t *, (*ppresponse)->ppayload) = rq->hindex;
		}
		break;
	}
	case ropCopyTo: {
		COPYTO_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYTO_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		COPYTO_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_copyto(rq->want_asynchronous,
			rq->want_subobjects, rq->copy_flags,
			&rq->excluded_proptags, &rsp->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			(*ppresponse)->ppayload = common_util_alloc(sizeof(uint32_t));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			*static_cast(uint32_t *, (*ppresponse)->ppayload) = rq->hindex;
		}
		break;
	}
	case ropProgress: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(PROGRESS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		PROGRESS_REQUEST *rq = prequest->ppayload;
		PROGRESS_RESPONSE *rsp = (*ppresponse)->ppayload;
		rsp->logon_id = prequest->logon_id;
		(*ppresponse)->result = rop_progress(rq->want_cancel,
			&rsp->completed_count, &rsp->total_count,
			&rop_id, &partial_completion, pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenStream: {
		OPENSTREAM_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		OPENSTREAM_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_openstream(rq->proptag,
			rq->flags, &rsp->stream_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropReadStream: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(READSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		READSTREAM_REQUEST *rq = prequest->ppayload;
		READSTREAM_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_readstream(rq->byte_count,
			rq->max_byte_count, &rsp->data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteStream: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(WRITESTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		WRITESTREAM_REQUEST *rq = prequest->ppayload;
		WRITESTREAM_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_writestream(
			&rq->data, &rsp->written_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCommitStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_commitstream(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStreamSize: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSTREAMSIZE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETSTREAMSIZE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getstreamsize(&rsp->stream_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetStreamSize: {
		SETSTREAMSIZE_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setstreamsize(rq->stream_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekStream: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SEEKSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SEEKSTREAM_REQUEST *rq = prequest->ppayload;
		SEEKSTREAM_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_seekstream(rq->seek_pos,
			rq->offset, &rsp->new_pos,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCopyToStream: {
		COPYTOSTREAM_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum) {
			return ecInvalidObject;
		}
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYTOSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		COPYTOSTREAM_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_copytostream(rq->byte_count,
			&rsp->read_bytes, &rsp->written_bytes,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			perr_response = common_util_alloc(sizeof(COPYTOSTREAM_NULL_DEST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			COPYTOSTREAM_NULL_DEST_RESPONSE *nr = perr_response;
			nr->hindex = rq->hindex;
			nr->read_bytes = 0;
			nr->written_bytes = 0;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	}
	case ropLockRegionStream: {
		LOCKREGIONSTREAM_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_lockregionstream(rq->region_offset,
			rq->region_size, rq->lock_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropUnlockRegionStream: {
		UNLOCKREGIONSTREAM_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_unlockregionstream(
			rq->region_offset, rq->region_size, rq->lock_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteAndCommitStream: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(WRITEANDCOMMITSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		WRITEANDCOMMITSTREAM_REQUEST *rq = prequest->ppayload;
		WRITEANDCOMMITSTREAM_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_writeandcommitstream(
			&rq->data, &rsp->written_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCloneStream: {
		CLONESTREAM_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_clonestream(pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropModifyPermissions: {
		MODIFYPERMISSIONS_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifypermissions(
			rq->flags, rq->count, rq->prow,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPermissionsTable: {
		GETPERMISSIONSTABLE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_getpermissionstable(rq->flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropModifyRules: {
		MODIFYRULES_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifyrules(
			rq->flags, rq->count, rq->prow,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetRulesTable: {
		GETRULESTABLE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_getrulestable(rq->flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropUpdateDeferredActionMessages: {
		UPDATEDEFERREDACTIONMESSAGES_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_updatedeferredactionmessages(
			&rq->server_entry_id, &rq->client_entry_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferDestinationConfigure: {
		FASTTRANSFERDESTCONFIGURE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_fasttransferdestconfigure(
			rq->source_operation, rq->flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferDestinationPutBuffer: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(FASTTRANSFERDESTPUTBUFFER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		FASTTRANSFERDESTPUTBUFFER_REQUEST *rq = prequest->ppayload;
		FASTTRANSFERDESTPUTBUFFER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_fasttransferdestputbuffer(
			&rq->transfer_data, &rsp->transfer_status,
			&rsp->in_progress_count, &rsp->total_step_count,
			&rsp->reserved, &rsp->used_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferSourceGetBuffer: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(FASTTRANSFERSOURCEGETBUFFER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		FASTTRANSFERSOURCEGETBUFFER_REQUEST *rq = prequest->ppayload;
		FASTTRANSFERSOURCEGETBUFFER_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_fasttransfersourcegetbuffer(
			rq->buffer_size, rq->max_buffer_size,
			&rsp->transfer_status, &rsp->in_progress_count,
			&rsp->total_step_count, &rsp->reserved,
			&rsp->transfer_data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecBufferTooSmall)
			return ecBufferTooSmall;
		break;
	}
	case ropFastTransferSourceCopyFolder: {
		FASTTRANSFERSOURCECOPYFOLDER_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyfolder(
			rq->flags, rq->send_options,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferSourceCopyMessages: {
		FASTTRANSFERSOURCECOPYMESSAGES_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_fasttransfersourcecopymessages(
			&rq->message_ids, rq->flags, rq->send_options,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferSourceCopyTo: {
		FASTTRANSFERSOURCECOPYTO_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyto(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferSourceCopyProperties: {
		FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyproperties(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropTellVersion: {
		TELLVERSION_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_tellversion(rq->version,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationConfigure: {
		SYNCCONFIGURE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_syncconfigure(rq->sync_type,
			rq->send_options, rq->sync_flags, rq->pres,
			rq->extra_flags, &rq->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationImportMessageChange: {
		SYNCIMPORTMESSAGECHANGE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SYNCIMPORTMESSAGECHANGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SYNCIMPORTMESSAGECHANGE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_syncimportmessagechange(
			rq->import_flags, &rq->propvals, &rsp->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationImportReadStateChanges: {
		SYNCIMPORTREADSTATECHANGES_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncimportreadstatechanges(
			rq->count, rq->pread_stat,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportHierarchyChange: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SYNCIMPORTHIERARCHYCHANGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SYNCIMPORTHIERARCHYCHANGE_REQUEST *rq = prequest->ppayload;
		SYNCIMPORTHIERARCHYCHANGE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_syncimporthierarchychange(
			&rq->hichyvals, &rq->propvals, &rsp->folder_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportDeletes: {
		SYNCIMPORTDELETES_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncimportdeletes(
			rq->flags, &rq->propvals,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportMessageMove: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SYNCIMPORTMESSAGEMOVE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		SYNCIMPORTMESSAGEMOVE_REQUEST *rq = prequest->ppayload;
		SYNCIMPORTMESSAGEMOVE_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_syncimportmessagemove(
			&rq->src_folder_id, &rq->src_message_id,
			&rq->change_list, &rq->dst_message_id,
			&rq->change_number, &rsp->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationOpenCollector: {
		SYNCOPENCOLLECTOR_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_syncopencollector(
			rq->is_content_collector,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationGetTransferState: {
		SYNCGETTRANSFERSTATE_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_syncgettransferstate(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationUploadStateStreamBegin: {
		SYNCUPLOADSTATESTREAMBEGIN_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreambegin(
			rq->proptag_stat, rq->buffer_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamContinue: {
		SYNCUPLOADSTATESTREAMCONTINUE_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreamcontinue(&rq->stream_data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamEnd:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreamend(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetLocalReplicaMidsetDeleted: {
		SETLOCALREPLICAMIDSETDELETED_REQUEST *rq = prequest->ppayload;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setlocalreplicamidsetdeleted(
			rq->count, rq->prange,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetLocalReplicaIds: {
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETLOCALREPLICAIDS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		GETLOCALREPLICAIDS_REQUEST *rq = prequest->ppayload;
		GETLOCALREPLICAIDS_RESPONSE *rsp = (*ppresponse)->ppayload;
		(*ppresponse)->result = rop_getlocalreplicaids(
			rq->count, &rsp->guid, rsp->global_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropRegisterNotification: {
		REGISTERNOTIFICATION_REQUEST *rq = prequest->ppayload;
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_registernotification(
			rq->notification_types, rq->reserved,
			rq->want_whole_store, rq->pfolder_id, rq->pmessage_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	default:
		debug_info("[exchange_emsmdb]: rop 0x%.2x not implemented!\n",
			prequest->rop_id);
		return ecError;
	}
	return ecSuccess;
}
