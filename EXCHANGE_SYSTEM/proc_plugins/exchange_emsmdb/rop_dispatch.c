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
		return EC_INVALID_OBJECT;
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
	case ropLogon:
		(*ppresponse)->hindex = prequest->hindex;
		perr_response = common_util_alloc(sizeof(LOGON_REDIRECT_RESPONSE));
		if (NULL == perr_response) {
			return ecMAPIOOM;
		}
		if (NULL != ((LOGON_REQUEST*)prequest->ppayload)->pessdn) {
			strncpy(((LOGON_REDIRECT_RESPONSE*)perr_response)->pserver_name,
				((LOGON_REQUEST*)prequest->ppayload)->pessdn, 1024);
		} else {
			((LOGON_REDIRECT_RESPONSE*)perr_response)->pserver_name[0] = '\0';
		}
		if (LOGON_FLAG_PRIVATE & ((LOGON_REQUEST*)prequest->ppayload)->logon_flags) {
			(*ppresponse)->ppayload =
				common_util_alloc(sizeof(LOGON_PMB_RESPONSE));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->logon_flags = 
				((LOGON_REQUEST*)prequest->ppayload)->logon_flags;
			(*ppresponse)->result = rop_logon_pmb(
				((LOGON_REQUEST*)prequest->ppayload)->logon_flags,
				((LOGON_REQUEST*)prequest->ppayload)->open_flags,
				((LOGON_REQUEST*)prequest->ppayload)->store_stat,
				((LOGON_REDIRECT_RESPONSE*)perr_response)->pserver_name,
				((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->folder_ids,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->response_flags,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->mailbox_guid,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->replica_id,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->replica_guid,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->logon_time,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->gwart_time,
				&((LOGON_PMB_RESPONSE*)(*ppresponse)->ppayload)->store_stat,
				pemsmdb_info->plogmap, prequest->logon_id, phandles + prequest->hindex);
		} else {
			(*ppresponse)->ppayload = common_util_alloc(sizeof(LOGON_PF_RESPONSE));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			((LOGON_PF_RESPONSE*)(*ppresponse)->ppayload)->logon_flags = 
				((LOGON_REQUEST*)prequest->ppayload)->logon_flags;
			(*ppresponse)->result = rop_logon_pf(
				((LOGON_REQUEST*)prequest->ppayload)->logon_flags,
				((LOGON_REQUEST*)prequest->ppayload)->open_flags,
				((LOGON_REQUEST*)prequest->ppayload)->store_stat,
				((LOGON_REDIRECT_RESPONSE*)perr_response)->pserver_name,
				((LOGON_PF_RESPONSE*)(*ppresponse)->ppayload)->folder_ids,
				&((LOGON_PF_RESPONSE*)(*ppresponse)->ppayload)->replica_id,
				&((LOGON_PF_RESPONSE*)(*ppresponse)->ppayload)->replica_guid,
				&((LOGON_PF_RESPONSE*)(*ppresponse)->ppayload)->per_user_guid,
				pemsmdb_info->plogmap, prequest->logon_id, phandles + prequest->hindex);
		}
		if (EC_WRONG_SERVER == (*ppresponse)->result) {
			((LOGON_REDIRECT_RESPONSE*)perr_response)->logon_flags =
				((LOGON_REQUEST*)prequest->ppayload)->logon_flags;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	case ropGetReceiveFolder:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETRECEIVEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getreceivefolder(
			((GETRECEIVEFOLDER_REQUEST*)prequest->ppayload)->pstr_class,
			&((GETRECEIVEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->folder_id,
			&((GETRECEIVEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->pstr_class,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetReceiveFolder:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setreceivefolder(
			((SETRECEIVEFOLDER_REQUEST*)prequest->ppayload)->folder_id,
			((SETRECEIVEFOLDER_REQUEST*)prequest->ppayload)->pstr_class,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetReceiveFolderTable:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETRECEIVEFOLDERTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getreceivefoldertable(
			&((GETRECEIVEFOLDERTABLE_RESPONSE*)(*ppresponse)->ppayload)->rows,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStoreState:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSTORESTAT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getstorestat(
			&((GETSTORESTAT_RESPONSE*)(*ppresponse)->ppayload)->stat,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetOwningServers:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETOWNINGSERVERS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getowningservers(
			((GETOWNINGSERVERS_REQUEST*)prequest->ppayload)->folder_id,
			&((GETOWNINGSERVERS_RESPONSE*)(*ppresponse)->ppayload)->ghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropPublicFolderIsGhosted:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(PUBLICFOLDERISGHOSTED_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_publicfolderisghosted(
			((PUBLICFOLDERISGHOSTED_REQUEST*)prequest->ppayload)->folder_id,
			&((PUBLICFOLDERISGHOSTED_RESPONSE*)(*ppresponse)->ppayload)->pghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropLongTermIdFromId:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(LONGTERMIDFROMID_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_longtermidfromid(
			((LONGTERMIDFROMID_REQUEST*)prequest->ppayload)->id,
			&((LONGTERMIDFROMID_RESPONSE*)(*ppresponse)->ppayload)->long_term_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropIdFromLongTermId:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(IDFROMLONGTERMID_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_idfromlongtermid(
			&((IDFROMLONGTERMID_REQUEST*)prequest->ppayload)->long_term_id,
			&((IDFROMLONGTERMID_RESPONSE*)(*ppresponse)->ppayload)->id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPerUserLongTermIds:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPERUSERLONGTERMIDS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getperuserlongtermids(
			&((GETPERUSERLONGTERMIDS_REQUEST*)prequest->ppayload)->guid,
			&((GETPERUSERLONGTERMIDS_RESPONSE*)(*ppresponse)->ppayload)->ids,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPerUserGuid:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPERUSERGUID_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getperuserguid(
			&((GETPERUSERGUID_REQUEST*)prequest->ppayload)->long_term_id,
			&((GETPERUSERGUID_RESPONSE*)(*ppresponse)->ppayload)->guid,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropReadPerUserInformation:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(READPERUSERINFORMATION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_readperuserinformation(
			&((READPERUSERINFORMATION_REQUEST*)prequest->ppayload)->long_folder_id,
			((READPERUSERINFORMATION_REQUEST*)prequest->ppayload)->reserved,
			((READPERUSERINFORMATION_REQUEST*)prequest->ppayload)->data_offset,
			((READPERUSERINFORMATION_REQUEST*)prequest->ppayload)->max_data_size,
			&((READPERUSERINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->has_finished,
			&((READPERUSERINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropWritePerUserInformation:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_writeperuserinformation(
			&((WRITEPERUSERINFORMATION_REQUEST*)prequest->ppayload)->long_folder_id,
			((WRITEPERUSERINFORMATION_REQUEST*)prequest->ppayload)->has_finished,
			((WRITEPERUSERINFORMATION_REQUEST*)prequest->ppayload)->offset,
			&((WRITEPERUSERINFORMATION_REQUEST*)prequest->ppayload)->data,
			((WRITEPERUSERINFORMATION_REQUEST*)prequest->ppayload)->pguid,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropOpenFolder:
		if (((OPENFOLDER_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((OPENFOLDER_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_openfolder(
			((OPENFOLDER_REQUEST*)prequest->ppayload)->folder_id,
			((OPENFOLDER_REQUEST*)prequest->ppayload)->open_flags,
			&((OPENFOLDER_RESPONSE*)(*ppresponse)->ppayload)->has_rules,
			&((OPENFOLDER_RESPONSE*)(*ppresponse)->ppayload)->pghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropCreateFolder:
		if (((CREATEFOLDER_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((CREATEFOLDER_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_createfolder(
			((CREATEFOLDER_REQUEST*)prequest->ppayload)->folder_type,
			((CREATEFOLDER_REQUEST*)prequest->ppayload)->use_unicode,
			((CREATEFOLDER_REQUEST*)prequest->ppayload)->open_existing,
			((CREATEFOLDER_REQUEST*)prequest->ppayload)->reserved,
			((CREATEFOLDER_REQUEST*)prequest->ppayload)->pfolder_name,
			((CREATEFOLDER_REQUEST*)prequest->ppayload)->pfolder_comment,
			&((CREATEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->folder_id,
			&((CREATEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->is_existing,
			&((CREATEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->has_rules,
			&((CREATEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->pghost,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropDeleteFolder:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_deletefolder(
			((DELETEFOLDER_REQUEST*)prequest->ppayload)->flags,
			((DELETEFOLDER_REQUEST*)prequest->ppayload)->folder_id,
			&((DELETEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetSearchCriteria:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setsearchcriteria(
			((SETSEARCHCRITERIA_REQUEST*)prequest->ppayload)->pres,
			&((SETSEARCHCRITERIA_REQUEST*)prequest->ppayload)->folder_ids,
			((SETSEARCHCRITERIA_REQUEST*)prequest->ppayload)->search_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetSearchCriteria:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSEARCHCRITERIA_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		((GETSEARCHCRITERIA_RESPONSE*)(*ppresponse)->ppayload)->logon_id = prequest->logon_id;
		(*ppresponse)->result = rop_getsearchcriteria(
			((GETSEARCHCRITERIA_REQUEST*)prequest->ppayload)->use_unicode,
			((GETSEARCHCRITERIA_REQUEST*)prequest->ppayload)->include_restriction,
			((GETSEARCHCRITERIA_REQUEST*)prequest->ppayload)->include_folders,
			&((GETSEARCHCRITERIA_RESPONSE*)(*ppresponse)->ppayload)->pres,
			&((GETSEARCHCRITERIA_RESPONSE*)(*ppresponse)->ppayload)->folder_ids,
			&((GETSEARCHCRITERIA_RESPONSE*)(*ppresponse)->ppayload)->search_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropMoveCopyMessages:
		if (((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(MOVECOPYMESSAGES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_movecopymessages(
			&((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->message_ids,
			((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->want_asynchronous,
			((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->want_copy,
			&((MOVECOPYMESSAGES_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex]);
		if (EC_DST_NULL_OBJECT == (*ppresponse)->result) {
			perr_response = common_util_alloc(sizeof(NULL_DST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			((NULL_DST_RESPONSE*)perr_response)->hindex =
				((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex;
			((NULL_DST_RESPONSE*)perr_response)->partial_completion =
				((MOVECOPYMESSAGES_RESPONSE*)(*ppresponse)->ppayload)->partial_completion;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	case ropMoveFolder:
		if (((MOVEFOLDER_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(MOVEFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_movefolder(
			((MOVEFOLDER_REQUEST*)prequest->ppayload)->want_asynchronous,
			((MOVEFOLDER_REQUEST*)prequest->ppayload)->use_unicode,
			((MOVEFOLDER_REQUEST*)prequest->ppayload)->folder_id,
			((MOVEFOLDER_REQUEST*)prequest->ppayload)->pnew_name,
			&((MOVEFOLDER_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((MOVEFOLDER_REQUEST*)prequest->ppayload)->hindex]);
		if (EC_DST_NULL_OBJECT == (*ppresponse)->result) {
			perr_response = common_util_alloc(sizeof(NULL_DST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			((NULL_DST_RESPONSE*)perr_response)->hindex =
				((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex;
			((NULL_DST_RESPONSE*)perr_response)->partial_completion =
				((MOVECOPYMESSAGES_RESPONSE*)(*ppresponse)->ppayload)->partial_completion;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	case ropCopyFolder:
		if (((COPYFOLDER_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_copyfolder(
			((COPYFOLDER_REQUEST*)(prequest->ppayload))->want_asynchronous,
			((COPYFOLDER_REQUEST*)(prequest->ppayload))->want_recursive,
			((COPYFOLDER_REQUEST*)(prequest->ppayload))->use_unicode,
			((COPYFOLDER_REQUEST*)(prequest->ppayload))->folder_id,
			((COPYFOLDER_REQUEST*)(prequest->ppayload))->pnew_name, 
			&((COPYFOLDER_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((COPYFOLDER_REQUEST*)prequest->ppayload)->hindex]);
		if (EC_DST_NULL_OBJECT == (*ppresponse)->result) {
			perr_response = common_util_alloc(sizeof(NULL_DST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			((NULL_DST_RESPONSE*)perr_response)->hindex =
				((MOVECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex;
			((NULL_DST_RESPONSE*)perr_response)->partial_completion =
				((MOVECOPYMESSAGES_RESPONSE*)(*ppresponse)->ppayload)->partial_completion;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	case ropEmptyFolder:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(EMPTYFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_emptyfolder(
			((EMPTYFOLDER_REQUEST*)prequest->ppayload)->want_asynchronous,
			((EMPTYFOLDER_REQUEST*)prequest->ppayload)->want_delete_associated,
			&((EMPTYFOLDER_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropHardDeleteMessagesAndSubfolders:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(EMPTYFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_harddeletemessagesandsubfolders(
			((HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST*)prequest->ppayload)->want_asynchronous,
			((HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST*)prequest->ppayload)->want_delete_associated,
			&((HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropDeleteMessages:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEMESSAGES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_deletemessages(
			((DELETEMESSAGES_REQUEST*)prequest->ppayload)->want_asynchronous,
			((DELETEMESSAGES_REQUEST*)prequest->ppayload)->notify_non_read,
			&((DELETEMESSAGES_REQUEST*)prequest->ppayload)->message_ids,
			&((DELETEMESSAGES_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropHardDeleteMessages:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(HARDDELETEMESSAGES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_harddeletemessages(
			((HARDDELETEMESSAGES_REQUEST*)prequest->ppayload)->want_asynchronous,
			((HARDDELETEMESSAGES_REQUEST*)prequest->ppayload)->notify_non_read,
			&((HARDDELETEMESSAGES_REQUEST*)prequest->ppayload)->message_ids,
			&((HARDDELETEMESSAGES_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetHierarchyTable:
		if (((GETHIERARCHYTABLE_REQUEST*)prequest->ppayload)->hindex > hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((GETHIERARCHYTABLE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETHIERARCHYTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_gethierarchytable(
			((GETHIERARCHYTABLE_REQUEST*)prequest->ppayload)->table_flags,
			&((GETHIERARCHYTABLE_RESPONSE*)((*ppresponse)->ppayload))->row_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropGetContentsTable:
		if (((GETCONTENTSTABLE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((GETCONTENTSTABLE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETCONTENTSTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getcontentstable(
			((GETCONTENTSTABLE_REQUEST*)prequest->ppayload)->table_flags,
			&((GETCONTENTSTABLE_RESPONSE*)((*ppresponse)->ppayload))->row_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropSetColumns:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETCOLUMNS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_setcolumns(
			((SETCOLUMNS_REQUEST*)prequest->ppayload)->table_flags,
			&((SETCOLUMNS_REQUEST*)prequest->ppayload)->proptags,
			&((SETCOLUMNS_RESPONSE*)(*ppresponse)->ppayload)->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSortTable:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SORTTABLE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_sorttable(
			((SORTTABLE_REQUEST*)prequest->ppayload)->table_flags,
			&((SORTTABLE_REQUEST*)prequest->ppayload)->sort_criteria,
			&((SORTTABLE_RESPONSE*)(*ppresponse)->ppayload)->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropRestrict:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(RESTRICT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_restrict(
			((RESTRICT_REQUEST*)prequest->ppayload)->res_flags,
			((RESTRICT_REQUEST*)prequest->ppayload)->pres,
			&((RESTRICT_RESPONSE*)(*ppresponse)->ppayload)->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropQueryRows:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYROWS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80) {
			return EC_BUFFER_TOO_SMALL;
		}
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (NULL == pdata) {
			return ecMAPIOOM;
		}
		ext_buffer_push_init(&ext_push, pdata, max_rop, EXT_FLAG_UTF16|EXT_FLAG_TBLLMT);
		(*ppresponse)->result = rop_queryrows(
			((QUERYROWS_REQUEST*)prequest->ppayload)->flags,
			((QUERYROWS_REQUEST*)prequest->ppayload)->forward_read,
			((QUERYROWS_REQUEST*)prequest->ppayload)->row_count,
			&((QUERYROWS_RESPONSE*)(*ppresponse)->ppayload)->seek_pos,
			&((QUERYROWS_RESPONSE*)(*ppresponse)->ppayload)->count,
			&ext_push, pemsmdb_info->plogmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			((QUERYROWS_RESPONSE*)(*ppresponse)->ppayload)->bin_rows.pb = pdata;
			((QUERYROWS_RESPONSE*)(*ppresponse)->ppayload)->bin_rows.cb = ext_push.offset;
		}
		break;
	case ropAbort:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(ABORT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_abort(
			&((ABORT_RESPONSE*)(*ppresponse)->ppayload)->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStatus:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSTATUS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getstatus(
			&((GETSTATUS_RESPONSE*)(*ppresponse)->ppayload)->table_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropQueryPosition:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYPOSITION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_queryposition(
			&((QUERYPOSITION_RESPONSE*)(*ppresponse)->ppayload)->numerator,
			&((QUERYPOSITION_RESPONSE*)(*ppresponse)->ppayload)->denominator,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSeekRow:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYPOSITION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_seekrow(
			((SEEKROW_REQUEST*)prequest->ppayload)->seek_pos,
			((SEEKROW_REQUEST*)prequest->ppayload)->offset,
			((SEEKROW_REQUEST*)prequest->ppayload)->want_moved_count,
			&((SEEKROW_RESPONSE*)(*ppresponse)->ppayload)->has_soughtless,
			&((SEEKROW_RESPONSE*)(*ppresponse)->ppayload)->offset_sought,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSeekRowBookmark:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SEEKROWBOOKMARK_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_seekrowbookmark(
			&((SEEKROWBOOKMARK_REQUEST*)prequest->ppayload)->bookmark,
			((SEEKROWBOOKMARK_REQUEST*)prequest->ppayload)->offset,
			((SEEKROWBOOKMARK_REQUEST*)prequest->ppayload)->want_moved_count,
			&((SEEKROWBOOKMARK_RESPONSE*)(*ppresponse)->ppayload)->row_invisible,
			&((SEEKROWBOOKMARK_RESPONSE*)(*ppresponse)->ppayload)->has_soughtless,
			&((SEEKROWBOOKMARK_RESPONSE*)(*ppresponse)->ppayload)->offset_sought,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSeekRowFractional:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_seekrowfractional(
			((SEEKROWFRACTIONAL_REQUEST*)prequest->ppayload)->numerator,
			((SEEKROWFRACTIONAL_REQUEST*)prequest->ppayload)->denominator,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropCreateBookmark:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEBOOKMARK_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_createbookmark(
			&((CREATEBOOKMARK_RESPONSE*)(*ppresponse)->ppayload)->bookmark,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropQueryColumnsAll:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYCOLUMNSALL_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_querycolumnsall(
			&((QUERYCOLUMNSALL_RESPONSE*)(*ppresponse)->ppayload)->proptags, 
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropFindRow:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(FINDROW_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_findrow(
			((FINDROW_REQUEST*)prequest->ppayload)->flags,
			((FINDROW_REQUEST*)prequest->ppayload)->pres,
			((FINDROW_REQUEST*)prequest->ppayload)->seek_pos,
			&((FINDROW_REQUEST*)prequest->ppayload)->bookmark,
			&((FINDROW_RESPONSE*)(*ppresponse)->ppayload)->bookmark_invisible,
			&((FINDROW_RESPONSE*)(*ppresponse)->ppayload)->prow,
			&((FINDROW_RESPONSE*)(*ppresponse)->ppayload)->pcolumns,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropFreeBookmark:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_freebookmark(
			&((FREEBOOKMARK_REQUEST*)prequest->ppayload)->bookmark,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropResetTable:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_resettable(pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropExpandRow:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(EXPANDROW_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80) {
			return EC_BUFFER_TOO_SMALL;
		}
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (NULL == pdata) {
			return ecMAPIOOM;
		}
		ext_buffer_push_init(&ext_push, pdata, max_rop, EXT_FLAG_UTF16);
		(*ppresponse)->result = rop_expandrow(
			((EXPANDROW_REQUEST*)prequest->ppayload)->max_count,
			((EXPANDROW_REQUEST*)prequest->ppayload)->category_id,
			&((EXPANDROW_RESPONSE*)(*ppresponse)->ppayload)->expanded_count,
			&((EXPANDROW_RESPONSE*)(*ppresponse)->ppayload)->count, &ext_push,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			((EXPANDROW_RESPONSE*)(*ppresponse)->ppayload)->bin_rows.pb = pdata;
			((EXPANDROW_RESPONSE*)(*ppresponse)->ppayload)->bin_rows.cb = ext_push.offset;
		}
		break;
	case ropCollapseRow:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COLLAPSEROW_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_collapserow(
			((COLLAPSEROW_REQUEST*)prequest->ppayload)->category_id,
			&((COLLAPSEROW_RESPONSE*)(*ppresponse)->ppayload)->collapsed_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetCollapseState:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETCOLLAPSESTATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getcollapsestate(
			((GETCOLLAPSESTATE_REQUEST*)prequest->ppayload)->row_id,
			((GETCOLLAPSESTATE_REQUEST*)prequest->ppayload)->row_instance,
			&((GETCOLLAPSESTATE_RESPONSE*)(*ppresponse)->ppayload)->collapse_state,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetCollapseState:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETCOLLAPSESTATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_setcollapsestate(
			&((SETCOLLAPSESTATE_REQUEST*)prequest->ppayload)->collapse_state,
			&((SETCOLLAPSESTATE_RESPONSE*)(*ppresponse)->ppayload)->bookmark,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropOpenMessage:
		if (((OPENMESSAGE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((OPENMESSAGE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_openmessage(
			((OPENMESSAGE_REQUEST*)prequest->ppayload)->cpid,
			((OPENMESSAGE_REQUEST*)prequest->ppayload)->folder_id,
			((OPENMESSAGE_REQUEST*)prequest->ppayload)->open_mode_flags,
			((OPENMESSAGE_REQUEST*)prequest->ppayload)->message_id,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->has_named_properties,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->subject_prefix,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->normalized_subject,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->recipient_count,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->recipient_columns,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->row_count,
			&((OPENMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->precipient_row,
			 pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			 phandles + (*ppresponse)->hindex);
		break;
	case ropCreateMessage:
		if (((CREATEMESSAGE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((CREATEMESSAGE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_createmessage(
			((CREATEMESSAGE_REQUEST*)prequest->ppayload)->cpid,
			((CREATEMESSAGE_REQUEST*)prequest->ppayload)->folder_id,
			((CREATEMESSAGE_REQUEST*)prequest->ppayload)->associated_flag,
			&((CREATEMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->pmessage_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropSaveChangesMessage:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SAVECHANGESMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		((SAVECHANGESMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->hindex =
				((SAVECHANGESMESSAGE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_savechangesmessage(
			((SAVECHANGESMESSAGE_REQUEST*)prequest->ppayload)->save_flags,
			&((SAVECHANGESMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((SAVECHANGESMESSAGE_REQUEST*)prequest->ppayload)->hindex]);
		break;
	case ropRemoveAllRecipients:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_removeallrecipients(
			((REMOVEALLRECIPIENTS_REQUEST*)prequest->ppayload)->reserved,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropModifyRecipients:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifyrecipients(
			&((MODIFYRECIPIENTS_REQUEST*)prequest->ppayload)->proptags,
			((MODIFYRECIPIENTS_REQUEST*)prequest->ppayload)->count,
			((MODIFYRECIPIENTS_REQUEST*)prequest->ppayload)->prow,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropReadRecipients:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(READRECIPIENTS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80) {
			return EC_BUFFER_TOO_SMALL;
		}
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (NULL == pdata) {
			return ecMAPIOOM;
		}
		ext_buffer_push_init(&ext_push, pdata, max_rop, EXT_FLAG_UTF16);
		(*ppresponse)->result = rop_readrecipients(
			((READRECIPIENTS_REQUEST*)prequest->ppayload)->row_id,
			((READRECIPIENTS_REQUEST*)prequest->ppayload)->reserved,
			&((READRECIPIENTS_RESPONSE*)(*ppresponse)->ppayload)->count,
			&ext_push, pemsmdb_info->plogmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			((READRECIPIENTS_RESPONSE*)(*ppresponse)->ppayload)->bin_recipients.pb = pdata;
			((READRECIPIENTS_RESPONSE*)(*ppresponse)->ppayload)->bin_recipients.cb = ext_push.offset;
		}
		break;
	case ropReloadCachedInformation:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(RELOADCACHEDINFORMATION_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_reloadcachedinformation(
			((RELOADCACHEDINFORMATION_REQUEST*)prequest->ppayload)->reserved,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->has_named_properties,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->subject_prefix,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->normalized_subject,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->recipient_count,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->recipient_columns,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->row_count,
			&((RELOADCACHEDINFORMATION_RESPONSE*)(*ppresponse)->ppayload)->precipient_row,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetMessageStatus:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETMESSAGESTATUS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_setmessagestatus(
			((SETMESSAGESTATUS_REQUEST*)prequest->ppayload)->message_id,
			((SETMESSAGESTATUS_REQUEST*)prequest->ppayload)->message_status,
			((SETMESSAGESTATUS_REQUEST*)prequest->ppayload)->status_mask,
			&((SETMESSAGESTATUS_RESPONSE*)(*ppresponse)->ppayload)->message_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetMessageStatus:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETMESSAGESTATUS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getmessagestatus(
			((GETMESSAGESTATUS_REQUEST*)prequest->ppayload)->message_id,
			&((GETMESSAGESTATUS_RESPONSE*)(*ppresponse)->ppayload)->message_status,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetReadFlags:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETREADFLAGS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_setreadflags(
			((SETREADFLAGS_REQUEST*)prequest->ppayload)->want_asynchronous,
			((SETREADFLAGS_REQUEST*)prequest->ppayload)->read_flags,
			&((SETREADFLAGS_REQUEST*)prequest->ppayload)->message_ids,
			&((SETREADFLAGS_RESPONSE*)(*ppresponse)->ppayload)->partial_completion,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetMessageReadFlag:
		if (((SETMESSAGEREADFLAG_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETMESSAGEREADFLAG_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		((SETMESSAGEREADFLAG_RESPONSE*)(*ppresponse)->ppayload)->logon_id =
																prequest->logon_id;
		((SETMESSAGEREADFLAG_RESPONSE*)(*ppresponse)->ppayload)->pclient_data =
					((SETMESSAGEREADFLAG_REQUEST*)prequest->ppayload)->pclient_data;
		(*ppresponse)->result = rop_setmessagereadflag(
			((SETMESSAGEREADFLAG_REQUEST*)prequest->ppayload)->flags,
			((SETMESSAGEREADFLAG_REQUEST*)prequest->ppayload)->pclient_data,
			&((SETMESSAGEREADFLAG_RESPONSE*)(*ppresponse)->ppayload)->read_changed,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((SETMESSAGEREADFLAG_REQUEST*)prequest->ppayload)->hindex]);
		break;
	case ropOpenAttachment:
		if (((OPENATTACHMENT_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((OPENATTACHMENT_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_openattachment(
			((OPENATTACHMENT_REQUEST*)prequest->ppayload)->flags,
			((OPENATTACHMENT_REQUEST*)prequest->ppayload)->attachment_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropCreateAttachment:
		if (((CREATEATTACHMENT_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((CREATEATTACHMENT_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(CREATEATTACHMENT_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_createattachment(
			&((CREATEATTACHMENT_RESPONSE*)(*ppresponse)->ppayload)->attachment_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropDeleteAttachment:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_deleteattachment(
			((DELETEATTACHMENT_REQUEST*)prequest->ppayload)->attachment_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSaveChangesAttachment:
		if (((SAVECHANGESATTACHMENT_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_savechangesattachment(
			((SAVECHANGESATTACHMENT_REQUEST*)prequest->ppayload)->save_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((SAVECHANGESATTACHMENT_REQUEST*)prequest->ppayload)->hindex]);
		break;
	case ropOpenEmbeddedMessage:
		if (((OPENEMBEDDEDMESSAGE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((OPENEMBEDDEDMESSAGE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENEMBEDDEDMESSAGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_openembeddedmessage(
			((OPENEMBEDDEDMESSAGE_REQUEST*)prequest->ppayload)->cpid,
			((OPENEMBEDDEDMESSAGE_REQUEST*)prequest->ppayload)->open_embedded_flags,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->reserved,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->message_id,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->has_named_properties,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->subject_prefix,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->normalized_subject,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->recipient_count,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->recipient_columns,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->row_count,
			&((OPENEMBEDDEDMESSAGE_RESPONSE*)(*ppresponse)->ppayload)->precipient_row,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropGetAttachmentTable:
		if (((GETATTACHMENTTABLE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((GETATTACHMENTTABLE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_getattachmenttable(
			((GETATTACHMENTTABLE_REQUEST*)prequest->ppayload)->table_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropGetValidAttachments:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETVALIDATTACHMENTS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getvalidattachments(
			&((GETVALIDATTACHMENTS_RESPONSE*)(*ppresponse)->ppayload)->attachment_ids,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSubmitMessage:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_submitmessage(
			((SUBMITMESSAGE_REQUEST*)(prequest->ppayload))->submit_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropAbortSubmit:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_abortsubmit(
			((ABORTSUBMIT_REQUEST*)(prequest->ppayload))->folder_id,
			((ABORTSUBMIT_REQUEST*)(prequest->ppayload))->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetAddressTypes:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETADDRESSTYPES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getaddresstypes(
			&((GETADDRESSTYPES_RESPONSE*)(*ppresponse)->ppayload)->address_types,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetSpooler:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setspooler(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSpoolerLockMessage:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_spoolerlockmessage(
			((SPOOLERLOCKMESSAGE_REQUEST*)prequest->ppayload)->message_id,
			((SPOOLERLOCKMESSAGE_REQUEST*)prequest->ppayload)->lock_stat,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropTransportSend:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(TRANSPORTSEND_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_transportsend(
			&((TRANSPORTSEND_RESPONSE*)(*ppresponse)->ppayload)->ppropvals,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropTransportNewMail:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_transportnewmail(
			((TRANSPORTNEWMAIL_REQUEST*)prequest->ppayload)->message_id,
			((TRANSPORTNEWMAIL_REQUEST*)prequest->ppayload)->folder_id,
			((TRANSPORTNEWMAIL_REQUEST*)prequest->ppayload)->pstr_class,
			((TRANSPORTNEWMAIL_REQUEST*)prequest->ppayload)->message_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetTransportFolder:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETTRANSPORTFOLDER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_gettransportfolder(
			&((GETTRANSPORTFOLDER_RESPONSE*)(*ppresponse)->ppayload)->folder_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropOptionsData:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPTIONSDATA_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_optionsdata(
			((OPTIONSDATA_REQUEST*)prequest->ppayload)->paddress_type,
			((OPTIONSDATA_REQUEST*)prequest->ppayload)->want_win32,
			&((OPTIONSDATA_RESPONSE*)(*ppresponse)->ppayload)->reserved,
			&((OPTIONSDATA_RESPONSE*)(*ppresponse)->ppayload)->options_info,
			&((OPTIONSDATA_RESPONSE*)(*ppresponse)->ppayload)->help_file,
			&((OPTIONSDATA_RESPONSE*)(*ppresponse)->ppayload)->pfile_name,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPropertyIdsFromNames:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTYIDSFROMNAMES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getpropertyidsfromnames(
			((GETPROPERTYIDSFROMNAMES_REQUEST*)prequest->ppayload)->flags,
			&((GETPROPERTYIDSFROMNAMES_REQUEST*)prequest->ppayload)->propnames,
			&((GETPROPERTYIDSFROMNAMES_RESPONSE*)(*ppresponse)->ppayload)->propids,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetNamesFromPropertyIds:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETNAMESFROMPROPERTYIDS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getnamesfrompropertyids(
			&((GETNAMESFROMPROPERTYIDS_REQUEST*)prequest->ppayload)->propids,
			&((GETNAMESFROMPROPERTYIDS_RESPONSE*)(*ppresponse)->ppayload)->propnames,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPropertiesSpecific:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTIESSPECIFIC_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		((GETPROPERTIESSPECIFIC_RESPONSE*)(*ppresponse)->ppayload)->pproptags =
			&((GETPROPERTIESSPECIFIC_REQUEST*)prequest->ppayload)->proptags;
		(*ppresponse)->result = rop_getpropertiesspecific(
			((GETPROPERTIESSPECIFIC_REQUEST*)prequest->ppayload)->size_limit,
			((GETPROPERTIESSPECIFIC_REQUEST*)prequest->ppayload)->want_unicode,
			&((GETPROPERTIESSPECIFIC_REQUEST*)prequest->ppayload)->proptags,
			&((GETPROPERTIESSPECIFIC_RESPONSE*)(*ppresponse)->ppayload)->row,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPropertiesAll:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTIESALL_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getpropertiesall(
			((GETPROPERTIESALL_REQUEST*)(prequest->ppayload))->size_limit,
			((GETPROPERTIESALL_REQUEST*)(prequest->ppayload))->want_unicode,
			&((GETPROPERTIESALL_RESPONSE*)(*ppresponse)->ppayload)->propvals,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPropertiesLIst:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETPROPERTIESLIST_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getpropertieslist(
			&((GETPROPERTIESLIST_RESPONSE*)(*ppresponse)->ppayload)->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetProperties:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_setproperties(
			&((SETPROPERTIES_REQUEST*)prequest->ppayload)->propvals,
			&((SETPROPERTIES_RESPONSE*)(*ppresponse)->ppayload)->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetPropertiesNoReplicate:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SETPROPERTIESNOREPLICATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_setpropertiesnoreplicate(
			&((SETPROPERTIESNOREPLICATE_REQUEST*)prequest->ppayload)->propvals,
			&((SETPROPERTIESNOREPLICATE_RESPONSE*)(*ppresponse)->ppayload)->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropDeleteProperties:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_deleteproperties(
			&((DELETEPROPERTIES_REQUEST*)prequest->ppayload)->proptags,
			&((DELETEPROPERTIES_RESPONSE*)(*ppresponse)->ppayload)->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropDeletePropertiesNoReplicate:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(DELETEPROPERTIESNOREPLICATE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_deletepropertiesnoreplicate(
			&((DELETEPROPERTIESNOREPLICATE_REQUEST*)prequest->ppayload)->proptags,
			&((DELETEPROPERTIESNOREPLICATE_RESPONSE*)(*ppresponse)->ppayload)->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropQueryNamedProperties:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(QUERYNAMEDPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_querynamedproperties(
			((QUERYNAMEDPROPERTIES_REQUEST*)prequest->ppayload)->query_flags,
			((QUERYNAMEDPROPERTIES_REQUEST*)prequest->ppayload)->pguid,
			&((QUERYNAMEDPROPERTIES_RESPONSE*)(*ppresponse)->ppayload)->propidnames,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropCopyProperties:
		if (((COPYPROPERTIES_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYPROPERTIES_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_copyproperties(
			((COPYPROPERTIES_REQUEST*)prequest->ppayload)->want_asynchronous,
			((COPYPROPERTIES_REQUEST*)prequest->ppayload)->copy_flags,
			&((COPYPROPERTIES_REQUEST*)prequest->ppayload)->proptags,
			&((COPYPROPERTIES_RESPONSE*)(*ppresponse)->ppayload)->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((COPYPROPERTIES_REQUEST*)prequest->ppayload)->hindex]);
		if (EC_DST_NULL_OBJECT == (*ppresponse)->result) {
			(*ppresponse)->ppayload = common_util_alloc(sizeof(uint32_t));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			*(uint32_t*)(*ppresponse)->ppayload =
				((COPYPROPERTIES_REQUEST*)prequest->ppayload)->hindex;
		}
		break;
	case ropCopyTo:
		if (((COPYTO_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYTO_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_copyto(
			((COPYTO_REQUEST*)prequest->ppayload)->want_asynchronous,
			((COPYTO_REQUEST*)prequest->ppayload)->want_subobjects,
			((COPYTO_REQUEST*)prequest->ppayload)->copy_flags,
			&((COPYTO_REQUEST*)prequest->ppayload)->excluded_proptags,
			&((COPYTO_RESPONSE*)(*ppresponse)->ppayload)->problems,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((COPYTO_REQUEST*)prequest->ppayload)->hindex]);
		if (EC_DST_NULL_OBJECT == (*ppresponse)->result) {
			(*ppresponse)->ppayload = common_util_alloc(sizeof(uint32_t));
			if (NULL == (*ppresponse)->ppayload) {
				return ecMAPIOOM;
			}
			*(uint32_t*)(*ppresponse)->ppayload =
				((COPYPROPERTIES_REQUEST*)prequest->ppayload)->hindex;
		}
		break;
	case ropProgress:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(PROGRESS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		((PROGRESS_RESPONSE*)(*ppresponse)->ppayload)->logon_id = prequest->logon_id;
		(*ppresponse)->result = rop_progress(
			((PROGRESS_REQUEST*)prequest->ppayload)->want_cancel,
			&((PROGRESS_RESPONSE*)(*ppresponse)->ppayload)->completed_count,
			&((PROGRESS_RESPONSE*)(*ppresponse)->ppayload)->total_count,
			&rop_id, &partial_completion, pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropOpenStream:
		if (((OPENSTREAM_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((OPENSTREAM_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(OPENSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_openstream(
			((OPENSTREAM_REQUEST*)prequest->ppayload)->proptag,
			((OPENSTREAM_REQUEST*)prequest->ppayload)->flags,
			&((OPENSTREAM_RESPONSE*)(*ppresponse)->ppayload)->stream_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropReadStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(READSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_readstream(
			((READSTREAM_REQUEST*)prequest->ppayload)->byte_count,
			((READSTREAM_REQUEST*)prequest->ppayload)->max_byte_count,
			&((READSTREAM_RESPONSE*)(*ppresponse)->ppayload)->data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropWriteStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(WRITESTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_writestream(
			&((WRITESTREAM_REQUEST*)prequest->ppayload)->data,
			&((WRITESTREAM_RESPONSE*)(*ppresponse)->ppayload)->written_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropCommitStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_commitstream(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStreamSize:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETSTREAMSIZE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getstreamsize(
			&((GETSTREAMSIZE_RESPONSE*)(*ppresponse)->ppayload)->stream_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetStreamSize:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setstreamsize(
			((SETSTREAMSIZE_REQUEST*)prequest->ppayload)->stream_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSeekStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SEEKSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_seekstream(
			((SEEKSTREAM_REQUEST*)prequest->ppayload)->seek_pos,
			((SEEKSTREAM_REQUEST*)prequest->ppayload)->offset,
			&((SEEKSTREAM_RESPONSE*)(*ppresponse)->ppayload)->new_pos,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropCopyToStream:
		if (((COPYTOSTREAM_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->ppayload = common_util_alloc(sizeof(COPYTOSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_copytostream(
			((COPYTOSTREAM_REQUEST*)prequest->ppayload)->byte_count,
			&((COPYTOSTREAM_RESPONSE*)(*ppresponse)->ppayload)->read_bytes,
			&((COPYTOSTREAM_RESPONSE*)(*ppresponse)->ppayload)->written_bytes,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[((COPYTOSTREAM_REQUEST*)prequest->ppayload)->hindex]);
		if (EC_DST_NULL_OBJECT == (*ppresponse)->result) {
			perr_response = common_util_alloc(sizeof(COPYTOSTREAM_NULL_DEST_RESPONSE));
			if (NULL == perr_response) {
				return ecMAPIOOM;
			}
			((COPYTOSTREAM_NULL_DEST_RESPONSE*)perr_response)->hindex =
				((COPYTOSTREAM_REQUEST*)prequest->ppayload)->hindex;
			((COPYTOSTREAM_NULL_DEST_RESPONSE*)perr_response)->read_bytes = 0;
			((COPYTOSTREAM_NULL_DEST_RESPONSE*)perr_response)->written_bytes = 0;
			(*ppresponse)->ppayload = perr_response;
		}
		break;
	case ropLockRegionStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_lockregionstream(
			((LOCKREGIONSTREAM_REQUEST*)prequest->ppayload)->region_offset,
			((LOCKREGIONSTREAM_REQUEST*)prequest->ppayload)->region_size,
			((LOCKREGIONSTREAM_REQUEST*)prequest->ppayload)->lock_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropUnlockRegionStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_unlockregionstream(
			((UNLOCKREGIONSTREAM_REQUEST*)prequest->ppayload)->region_offset,
			((UNLOCKREGIONSTREAM_REQUEST*)prequest->ppayload)->region_size,
			((UNLOCKREGIONSTREAM_REQUEST*)prequest->ppayload)->lock_flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropWriteAndCommitStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(WRITEANDCOMMITSTREAM_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_writeandcommitstream(
			&((WRITEANDCOMMITSTREAM_REQUEST*)prequest->ppayload)->data,
			&((WRITEANDCOMMITSTREAM_RESPONSE*)(*ppresponse)->ppayload)->written_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropCloneStream:
		if (((CLONESTREAM_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((CLONESTREAM_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_clonestream(pemsmdb_info->plogmap,
			prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropModifyPermissions:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifypermissions(
			((MODIFYPERMISSIONS_REQUEST*)prequest->ppayload)->flags,
			((MODIFYPERMISSIONS_REQUEST*)prequest->ppayload)->count,
			((MODIFYPERMISSIONS_REQUEST*)prequest->ppayload)->prow,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetPermissionsTable:
		if (((GETPERMISSIONSTABLE_REQUEST*)prequest->ppayload)->hindex > hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((GETPERMISSIONSTABLE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_getpermissionstable(
			((GETPERMISSIONSTABLE_REQUEST*)prequest->ppayload)->flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropModifyRules:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifyrules(
			((MODIFYRULES_REQUEST*)prequest->ppayload)->flags,
			((MODIFYRULES_REQUEST*)prequest->ppayload)->count,
			((MODIFYRULES_REQUEST*)prequest->ppayload)->prow,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetRulesTable:
		if (((GETRULESTABLE_REQUEST*)prequest->ppayload)->hindex > hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((GETRULESTABLE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_getrulestable(
			((GETRULESTABLE_REQUEST*)prequest->ppayload)->flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropUpdateDeferredActionMessages:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_updatedeferredactionmessages(
			&((UPDATEDEFERREDACTIONMESSAGES_REQUEST*)prequest->ppayload)->server_entry_id,
			&((UPDATEDEFERREDACTIONMESSAGES_REQUEST*)prequest->ppayload)->client_entry_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropFastTransferDestinationConfigure:
		if (((FASTTRANSFERDESTCONFIGURE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((FASTTRANSFERDESTCONFIGURE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_fasttransferdestconfigure(
			((FASTTRANSFERDESTCONFIGURE_REQUEST*)prequest->ppayload)->source_operation,
			((FASTTRANSFERDESTCONFIGURE_REQUEST*)prequest->ppayload)->flags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropFastTransferDestinationPutBuffer:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(FASTTRANSFERDESTPUTBUFFER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_fasttransferdestputbuffer(
			&((FASTTRANSFERDESTPUTBUFFER_REQUEST*)prequest->ppayload)->transfer_data,
			&((FASTTRANSFERDESTPUTBUFFER_RESPONSE*)(*ppresponse)->ppayload)->transfer_status,
			&((FASTTRANSFERDESTPUTBUFFER_RESPONSE*)(*ppresponse)->ppayload)->in_progress_count,
			&((FASTTRANSFERDESTPUTBUFFER_RESPONSE*)(*ppresponse)->ppayload)->total_step_count,
			&((FASTTRANSFERDESTPUTBUFFER_RESPONSE*)(*ppresponse)->ppayload)->reserved,
			&((FASTTRANSFERDESTPUTBUFFER_RESPONSE*)(*ppresponse)->ppayload)->used_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropFastTransferSourceGetBuffer:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(FASTTRANSFERSOURCEGETBUFFER_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_fasttransfersourcegetbuffer(
			((FASTTRANSFERSOURCEGETBUFFER_REQUEST*)prequest->ppayload)->buffer_size,
			((FASTTRANSFERSOURCEGETBUFFER_REQUEST*)prequest->ppayload)->max_buffer_size,
			&((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)(*ppresponse)->ppayload)->transfer_status,
			&((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)(*ppresponse)->ppayload)->in_progress_count,
			&((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)(*ppresponse)->ppayload)->total_step_count,
			&((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)(*ppresponse)->ppayload)->reserved,
			&((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)(*ppresponse)->ppayload)->transfer_data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		if (EC_BUFFER_TOO_SMALL == (*ppresponse)->result) {
			return EC_BUFFER_TOO_SMALL;
		}
		break;
	case ropFastTransferSourceCopyFolder:
		if (((FASTTRANSFERSOURCECOPYFOLDER_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((FASTTRANSFERSOURCECOPYFOLDER_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyfolder(
			((FASTTRANSFERSOURCECOPYFOLDER_REQUEST*)prequest->ppayload)->flags,
			((FASTTRANSFERSOURCECOPYFOLDER_REQUEST*)prequest->ppayload)->send_options,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropFastTransferSourceCopyMessages:
		if (((FASTTRANSFERSOURCECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((FASTTRANSFERSOURCECOPYMESSAGES_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_fasttransfersourcecopymessages(
			&((FASTTRANSFERSOURCECOPYMESSAGES_REQUEST*)prequest->ppayload)->message_ids,
			((FASTTRANSFERSOURCECOPYMESSAGES_REQUEST*)prequest->ppayload)->flags,
			((FASTTRANSFERSOURCECOPYMESSAGES_REQUEST*)prequest->ppayload)->send_options,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropFastTransferSourceCopyTo:
		if (((FASTTRANSFERSOURCECOPYTO_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((FASTTRANSFERSOURCECOPYTO_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyto(
			((FASTTRANSFERSOURCECOPYTO_REQUEST*)prequest->ppayload)->level,
			((FASTTRANSFERSOURCECOPYTO_REQUEST*)prequest->ppayload)->flags,
			((FASTTRANSFERSOURCECOPYTO_REQUEST*)prequest->ppayload)->send_options,
			&((FASTTRANSFERSOURCECOPYTO_REQUEST*)prequest->ppayload)->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropFastTransferSourceCopyProperties:
		if (((FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyproperties(
			((FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST*)prequest->ppayload)->level,
			((FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST*)prequest->ppayload)->flags,
			((FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST*)prequest->ppayload)->send_options,
			&((FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST*)prequest->ppayload)->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropTellVersion:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_tellversion(
			((TELLVERSION_REQUEST*)prequest->ppayload)->version,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationConfigure:
		if (((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_syncconfigure(
			((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->sync_type,
			((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->send_options,
			((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->sync_flags,
			((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->pres,
			((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->extra_flags,
			&((SYNCCONFIGURE_REQUEST*)prequest->ppayload)->proptags,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropSynchronizationImportMessageChange:
		if (((SYNCIMPORTMESSAGECHANGE_REQUEST*)prequest->ppayload)->hindex > hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((SYNCIMPORTMESSAGECHANGE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SYNCIMPORTMESSAGECHANGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_syncimportmessagechange(
			((SYNCIMPORTMESSAGECHANGE_REQUEST*)prequest->ppayload)->import_flags,
			&((SYNCIMPORTMESSAGECHANGE_REQUEST*)prequest->ppayload)->propvals,
			&((SYNCIMPORTMESSAGECHANGE_RESPONSE*)(*ppresponse)->ppayload)->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropSynchronizationImportReadStateChanges:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncimportreadstatechanges(
			((SYNCIMPORTREADSTATECHANGES_REQUEST*)prequest->ppayload)->count,
			((SYNCIMPORTREADSTATECHANGES_REQUEST*)prequest->ppayload)->pread_stat,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationImportHierarchyChange:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SYNCIMPORTHIERARCHYCHANGE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_syncimporthierarchychange(
			&((SYNCIMPORTHIERARCHYCHANGE_REQUEST*)prequest->ppayload)->hichyvals,
			&((SYNCIMPORTHIERARCHYCHANGE_REQUEST*)prequest->ppayload)->propvals,
			&((SYNCIMPORTHIERARCHYCHANGE_RESPONSE*)(*ppresponse)->ppayload)->folder_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationImportDeletes:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncimportdeletes(
			((SYNCIMPORTDELETES_REQUEST*)prequest->ppayload)->flags,
			&((SYNCIMPORTDELETES_REQUEST*)prequest->ppayload)->propvals,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationImportMessageMove:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(SYNCIMPORTMESSAGEMOVE_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_syncimportmessagemove(
			&((SYNCIMPORTMESSAGEMOVE_REQUEST*)prequest->ppayload)->src_folder_id,
			&((SYNCIMPORTMESSAGEMOVE_REQUEST*)prequest->ppayload)->src_message_id,
			&((SYNCIMPORTMESSAGEMOVE_REQUEST*)prequest->ppayload)->change_list,
			&((SYNCIMPORTMESSAGEMOVE_REQUEST*)prequest->ppayload)->dst_message_id,
			&((SYNCIMPORTMESSAGEMOVE_REQUEST*)prequest->ppayload)->change_number,
			&((SYNCIMPORTMESSAGEMOVE_RESPONSE*)(*ppresponse)->ppayload)->message_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationOpenCollector:
		if (((SYNCOPENCOLLECTOR_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((SYNCOPENCOLLECTOR_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_syncopencollector(
			((SYNCOPENCOLLECTOR_REQUEST*)prequest->ppayload)->is_content_collector,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropSynchronizationGetTransferState:
		if (((SYNCGETTRANSFERSTATE_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((SYNCGETTRANSFERSTATE_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_syncgettransferstate(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	case ropSynchronizationUploadStateStreamBegin:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreambegin(
			((SYNCUPLOADSTATESTREAMBEGIN_REQUEST*)prequest->ppayload)->proptag_stat,
			((SYNCUPLOADSTATESTREAMBEGIN_REQUEST*)prequest->ppayload)->buffer_size,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationUploadStateStreamContinue:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreamcontinue(
			&((SYNCUPLOADSTATESTREAMCONTINUE_REQUEST*)prequest->ppayload)->stream_data,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSynchronizationUploadStateStreamEnd:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreamend(
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetLocalReplicaMidsetDeleted:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setlocalreplicamidsetdeleted(
			((SETLOCALREPLICAMIDSETDELETED_REQUEST*)prequest->ppayload)->count,
			((SETLOCALREPLICAMIDSETDELETED_REQUEST*)prequest->ppayload)->prange,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetLocalReplicaIds:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->ppayload = common_util_alloc(sizeof(GETLOCALREPLICAIDS_RESPONSE));
		if (NULL == (*ppresponse)->ppayload) {
			return ecMAPIOOM;
		}
		(*ppresponse)->result = rop_getlocalreplicaids(
			((GETLOCALREPLICAIDS_REQUEST*)prequest->ppayload)->count,
			&((GETLOCALREPLICAIDS_RESPONSE*)(*ppresponse)->ppayload)->guid,
			((GETLOCALREPLICAIDS_RESPONSE*)(*ppresponse)->ppayload)->global_count,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropRegisterNotification:
		if (((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->hindex >= hnum) {
			return EC_INVALID_OBJECT;
		}
		(*ppresponse)->hindex = ((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->hindex;
		(*ppresponse)->result = rop_registernotification(
			((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->notification_types,
			((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->reserved,
			((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->want_whole_store,
			((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->pfolder_id,
			((REGISTERNOTIFICATION_REQUEST*)prequest->ppayload)->pmessage_id,
			pemsmdb_info->plogmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	default:
		debug_info("[exchange_emsmdb]: rop 0x%.2x not implemented!\n",
			prequest->rop_id);
		return ecError;
	}
	return ecSuccess;
}
