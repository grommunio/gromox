// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "rop_dispatch.h"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"

using namespace gromox;

unsigned int g_rop_debug;

int rop_dispatch(ROP_REQUEST *prequest,
	ROP_RESPONSE **ppresponse,
	uint32_t *phandles, uint8_t hnum)
{
	void *pdata;
	uint8_t rop_id;
	uint16_t max_rop;
	EXT_PUSH ext_push;
	EMSMDB_INFO *pemsmdb_info;
	uint8_t partial_completion;
	
	*ppresponse = NULL;
	pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	if (prequest->hindex >= hnum)
		return ecInvalidObject;
	if (prequest->rop_id == ropRelease) {
		rop_release(pemsmdb_info->plogmap.get(),
			prequest->logon_id, phandles[prequest->hindex]);
		return ecSuccess;
	}
	*ppresponse = cu_alloc<ROP_RESPONSE>();
	if (*ppresponse == nullptr)
		return ecServerOOM;
	(*ppresponse)->rop_id = prequest->rop_id;
	(*ppresponse)->ppayload = NULL;
	
	switch (prequest->rop_id) {
	case ropLogon: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rq = static_cast<LOGON_REQUEST *>(prequest->ppayload);
		auto rdr = cu_alloc<LOGON_REDIRECT_RESPONSE>();
		if (rdr == nullptr)
			return ecServerOOM;
		if (rq->pessdn != nullptr)
			gx_strlcpy(rdr->pserver_name, rq->pessdn, GX_ARRAY_SIZE(rdr->pserver_name));
		else
			rdr->pserver_name[0] = '\0';
		if (rq->logon_flags & LOGON_FLAG_PRIVATE) {
			auto pmb = cu_alloc<LOGON_PMB_RESPONSE>();
			(*ppresponse)->ppayload = pmb;
			if (pmb == nullptr)
				return ecServerOOM;
			pmb->logon_flags = rq->logon_flags;
			(*ppresponse)->result = rop_logon_pmb(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, GX_ARRAY_SIZE(rdr->pserver_name), pmb->folder_ids,
				&pmb->response_flags, &pmb->mailbox_guid,
				&pmb->replid, &pmb->replguid,
				&pmb->logon_time, &pmb->gwart_time,
				&pmb->store_stat,
				pemsmdb_info->plogmap.get(), prequest->logon_id, &phandles[prequest->hindex]);
		} else {
			auto pfr = cu_alloc<LOGON_PF_RESPONSE>();
			(*ppresponse)->ppayload = pfr;
			if (pfr == nullptr)
				return ecServerOOM;
			pfr->logon_flags = rq->logon_flags;
			(*ppresponse)->result = rop_logon_pf(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, pfr->folder_ids,
				&pfr->replid, &pfr->replguid,
				&pfr->per_user_guid,
				pemsmdb_info->plogmap.get(), prequest->logon_id, &phandles[prequest->hindex]);
		}
		if ((*ppresponse)->result == ecWrongServer) {
			rdr->logon_flags = rq->logon_flags;
			(*ppresponse)->ppayload = rdr;
		}
		break;
	}
	case ropGetReceiveFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETRECEIVEFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETRECEIVEFOLDER_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getreceivefolder(rq->pstr_class,
			&rsp->folder_id, &rsp->pstr_class,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetReceiveFolder: {
		auto rq = static_cast<SETRECEIVEFOLDER_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setreceivefolder(
			rq->folder_id, rq->pstr_class,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetReceiveFolderTable: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETRECEIVEFOLDERTABLE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getreceivefoldertable(&rsp->rows,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetStoreState: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETSTORESTAT_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getstorestat(&rsp->stat,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetOwningServers: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETOWNINGSERVERS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETOWNINGSERVERS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getowningservers(
			rq->folder_id, &rsp->ghost,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropPublicFolderIsGhosted: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<PUBLICFOLDERISGHOSTED_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<PUBLICFOLDERISGHOSTED_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_publicfolderisghosted(
			rq->folder_id, &rsp->pghost,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropLongTermIdFromId: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<LONGTERMIDFROMID_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<LONGTERMIDFROMID_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_longtermidfromid(
			rq->id, &rsp->long_term_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropIdFromLongTermId: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<IDFROMLONGTERMID_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<IDFROMLONGTERMID_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_idfromlongtermid(
			&rq->long_term_id, &rsp->id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPerUserLongTermIds: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETPERUSERLONGTERMIDS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETPERUSERLONGTERMIDS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getperuserlongtermids(
			&rq->guid, &rsp->ids,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPerUserGuid: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETPERUSERGUID_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETPERUSERGUID_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getperuserguid(
			&rq->long_term_id, &rsp->guid,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadPerUserInformation: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<READPERUSERINFORMATION_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<READPERUSERINFORMATION_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_readperuserinformation(
			&rq->long_folder_id, rq->reserved, rq->data_offset,
			rq->max_data_size, &rsp->has_finished, &rsp->data,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWritePerUserInformation: {
		auto rq = static_cast<WRITEPERUSERINFORMATION_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_writeperuserinformation(
			&rq->long_folder_id, rq->has_finished,
			rq->offset, &rq->data, rq->pguid,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenFolder: {
		auto rq = static_cast<OPENFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<OPENFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_openfolder(rq->folder_id,
			rq->open_flags, &rsp->has_rules, &rsp->pghost,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropCreateFolder: {
		auto rq = static_cast<CREATEFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<CREATEFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_createfolder(rq->folder_type,
			rq->use_unicode, rq->open_existing, rq->reserved,
			rq->pfolder_name, rq->pfolder_comment,
			&rsp->folder_id, &rsp->is_existing, &rsp->has_rules,
			&rsp->pghost,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropDeleteFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<DELETEFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<DELETEFOLDER_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_deletefolder(rq->flags,
			rq->folder_id, &rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetSearchCriteria: {
		auto rq = static_cast<SETSEARCHCRITERIA_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setsearchcriteria(rq->pres,
			&rq->folder_ids, rq->search_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetSearchCriteria: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETSEARCHCRITERIA_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETSEARCHCRITERIA_REQUEST *>(prequest->ppayload);
		rsp->logon_id = prequest->logon_id;
		(*ppresponse)->result = rop_getsearchcriteria(rq->use_unicode,
			rq->include_restriction, rq->include_folders,
			&rsp->pres, &rsp->folder_ids, &rsp->search_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropMoveCopyMessages: {
		auto rq = static_cast<MOVECOPYMESSAGES_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<MOVECOPYMESSAGES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_movecopymessages(&rq->message_ids,
			rq->want_asynchronous, rq->want_copy,
			&rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			auto nr = cu_alloc<NULL_DST_RESPONSE>();
			if (nr == nullptr)
				return ecServerOOM;
			nr->hindex = rq->hindex;
			nr->partial_completion = rsp->partial_completion;
			(*ppresponse)->ppayload = nr;
		}
		break;
	}
	case ropMoveFolder: {
		auto rq = static_cast<MOVEFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<MOVEFOLDER_RESPONSE>();;
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_movefolder(rq->want_asynchronous,
			rq->use_unicode, rq->folder_id, rq->pnew_name,
			&rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			auto nr = cu_alloc<NULL_DST_RESPONSE>();
			if (nr == nullptr)
				return ecServerOOM;
			nr->hindex = rq->hindex;
			nr->partial_completion = rsp->partial_completion;
			(*ppresponse)->ppayload = nr;
		}
		break;
	}
	case ropCopyFolder: {
		auto rq = static_cast<COPYFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<COPYFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_copyfolder(rq->want_asynchronous,
			rq->want_recursive, rq->use_unicode, rq->folder_id,
			rq->pnew_name, &rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			auto nr = cu_alloc<NULL_DST_RESPONSE>();
			if (nr == nullptr)
				return ecServerOOM;
			nr->hindex = rq->hindex;
			nr->partial_completion = rsp->partial_completion;
			(*ppresponse)->ppayload = nr;
		}
		break;
	}
	case ropEmptyFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<EMPTYFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<EMPTYFOLDER_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_emptyfolder(rq->want_asynchronous,
			rq->want_delete_associated, &rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropHardDeleteMessagesAndSubfolders: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<EMPTYFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_harddeletemessagesandsubfolders(
			rq->want_asynchronous, rq->want_delete_associated,
			&rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeleteMessages: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<DELETEMESSAGES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<DELETEMESSAGES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_deletemessages(rq->want_asynchronous,
			rq->notify_non_read, &rq->message_ids,
			&rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropHardDeleteMessages: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<HARDDELETEMESSAGES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<HARDDELETEMESSAGES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_harddeletemessages(
			rq->want_asynchronous, rq->notify_non_read,
			&rq->message_ids, &rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetHierarchyTable: {
		auto rq = static_cast<GETHIERARCHYTABLE_REQUEST *>(prequest->ppayload);
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<GETHIERARCHYTABLE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_gethierarchytable(
			rq->table_flags, &rsp->row_count,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropGetContentsTable: {
		auto rq = static_cast<GETCONTENTSTABLE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<GETCONTENTSTABLE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getcontentstable(rq->table_flags,
			&rsp->row_count,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSetColumns: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETCOLUMNS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SETCOLUMNS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_setcolumns(rq->table_flags,
			&rq->proptags, &rsp->table_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSortTable: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SORTTABLE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SORTTABLE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_sorttable(rq->table_flags,
			&rq->sort_criteria, &rsp->table_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropRestrict: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<RESTRICT_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<RESTRICT_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_restrict(rq->res_flags, rq->pres,
			&rsp->table_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryRows: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<QUERYROWS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80)
			return ecBufferTooSmall;
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (pdata == nullptr ||
		    !ext_push.init(pdata, max_rop, EXT_FLAG_UTF16 | EXT_FLAG_TBLLMT))
			return ecServerOOM;
		auto rq = static_cast<QUERYROWS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_queryrows(rq->flags,
			rq->forward_read, rq->row_count, &rsp->seek_pos,
			&rsp->count,
			&ext_push, pemsmdb_info->plogmap.get(), prequest->logon_id,
			phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			rsp->bin_rows.pv = pdata;
			rsp->bin_rows.cb = ext_push.m_offset;
		}
		break;
	}
	case ropAbort: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<ABORT_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_abort(&rsp->table_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetStatus: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETSTATUS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getstatus(&rsp->table_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryPosition: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<QUERYPOSITION_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_queryposition(
			&rsp->numerator, &rsp->denominator,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRow: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SEEKROW_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SEEKROW_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_seekrow(rq->seek_pos, rq->offset,
			rq->want_moved_count, &rsp->has_soughtless,
			&rsp->offset_sought,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRowBookmark: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SEEKROWBOOKMARK_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SEEKROWBOOKMARK_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_seekrowbookmark(&rq->bookmark,
			rq->offset, rq->want_moved_count, &rsp->row_invisible,
			&rsp->has_soughtless, &rsp->offset_sought,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRowFractional: {
		auto rq = static_cast<SEEKROWFRACTIONAL_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_seekrowfractional(rq->numerator, rq->denominator,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCreateBookmark: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<CREATEBOOKMARK_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_createbookmark(&rsp->bookmark,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryColumnsAll: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<QUERYCOLUMNSALL_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_querycolumnsall(&rsp->proptags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFindRow: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<FINDROW_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<FINDROW_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_findrow(rq->flags, rq->pres,
			rq->seek_pos, &rq->bookmark, &rsp->bookmark_invisible,
			&rsp->prow, &rsp->pcolumns,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFreeBookmark: {
		auto rq = static_cast<FREEBOOKMARK_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_freebookmark(&rq->bookmark,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropResetTable:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_resettable(pemsmdb_info->plogmap.get(),
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropExpandRow: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<EXPANDROW_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80)
			return ecBufferTooSmall;
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (pdata == nullptr ||
		    !ext_push.init(pdata, max_rop, EXT_FLAG_UTF16))
			return ecServerOOM;
		auto rq = static_cast<EXPANDROW_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_expandrow(rq->max_count,
			rq->category_id, &rsp->expanded_count,
			&rsp->count, &ext_push,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			rsp->bin_rows.pv = pdata;
			rsp->bin_rows.cb = ext_push.m_offset;
		}
		break;
	}
	case ropCollapseRow: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<COLLAPSEROW_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<COLLAPSEROW_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_collapserow(
			rq->category_id, &rsp->collapsed_count,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetCollapseState: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETCOLLAPSESTATE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETCOLLAPSESTATE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getcollapsestate(rq->row_id,
			rq->row_instance, &rsp->collapse_state,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetCollapseState: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETCOLLAPSESTATE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SETCOLLAPSESTATE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_setcollapsestate(
			&rq->collapse_state, &rsp->bookmark,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenMessage: {
		auto rq = static_cast<OPENMESSAGE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<OPENMESSAGE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_openmessage(rq->cpid, rq->folder_id,
			rq->open_mode_flags, rq->message_id,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			 pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			 phandles + (*ppresponse)->hindex);
		break;
	}
	case ropCreateMessage: {
		auto rq = static_cast<CREATEMESSAGE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<CREATEMESSAGE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_createmessage(rq->cpid,
			rq->folder_id, rq->associated_flag, &rsp->pmessage_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSaveChangesMessage: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SAVECHANGESMESSAGE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SAVECHANGESMESSAGE_REQUEST *>(prequest->ppayload);
		rsp->hindex = rq->hindex;
		(*ppresponse)->result = rop_savechangesmessage(rq->save_flags,
			&rsp->message_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		break;
	}
	case ropRemoveAllRecipients: {
		auto rq = static_cast<REMOVEALLRECIPIENTS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_removeallrecipients(rq->reserved,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropModifyRecipients: {
		auto rq = static_cast<MODIFYRECIPIENTS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifyrecipients(&rq->proptags,
			rq->count, rq->prow,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadRecipients: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<READRECIPIENTS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		emsmdb_interface_get_rop_left(&max_rop);
		if (max_rop < 0x80)
			return ecBufferTooSmall;
		max_rop -= 0x80;
		pdata = common_util_alloc(max_rop);
		if (pdata == nullptr ||
		    !ext_push.init(pdata, max_rop, EXT_FLAG_UTF16))
			return ecServerOOM;
		auto rq = static_cast<READRECIPIENTS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_readrecipients(rq->row_id,
			rq->reserved, &rsp->count,
			&ext_push, pemsmdb_info->plogmap.get(), prequest->logon_id,
			phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecSuccess) {
			rsp->bin_recipients.pv = pdata;
			rsp->bin_recipients.cb = ext_push.m_offset;
		}
		break;
	}
	case ropReloadCachedInformation: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<RELOADCACHEDINFORMATION_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<RELOADCACHEDINFORMATION_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_reloadcachedinformation(rq->reserved,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetMessageStatus: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETMESSAGESTATUS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SETMESSAGESTATUS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_setmessagestatus(rq->message_id,
			rq->message_status, rq->status_mask,
			&rsp->message_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetMessageStatus: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETMESSAGESTATUS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETMESSAGESTATUS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getmessagestatus(
			rq->message_id, &rsp->message_status,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetReadFlags: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETREADFLAGS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SETREADFLAGS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_setreadflags(rq->want_asynchronous,
			rq->read_flags, &rq->message_ids,
			&rsp->partial_completion,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetMessageReadFlag: {
		auto rq = static_cast<SETMESSAGEREADFLAG_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETMESSAGEREADFLAG_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->logon_id = prequest->logon_id;
		rsp->pclient_data = rq->pclient_data;
		(*ppresponse)->result = rop_setmessagereadflag(
			rq->flags, rq->pclient_data, &rsp->read_changed,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		break;
	}
	case ropOpenAttachment: {
		auto rq = static_cast<OPENATTACHMENT_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_openattachment(
			rq->flags, rq->attachment_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropCreateAttachment: {
		auto rq = static_cast<CREATEATTACHMENT_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<CREATEATTACHMENT_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_createattachment(
			&rsp->attachment_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropDeleteAttachment: {
		auto rq = static_cast<DELETEATTACHMENT_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_deleteattachment(rq->attachment_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSaveChangesAttachment: {
		auto rq = static_cast<SAVECHANGESATTACHMENT_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_savechangesattachment(
			rq->save_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		break;
	}
	case ropOpenEmbeddedMessage: {
		auto rq = static_cast<OPENEMBEDDEDMESSAGE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<OPENEMBEDDEDMESSAGE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_openembeddedmessage(rq->cpid,
			rq->open_embedded_flags, &rsp->reserved,
			&rsp->message_id, &rsp->has_named_properties,
			&rsp->subject_prefix, &rsp->normalized_subject,
			&rsp->recipient_count, &rsp->recipient_columns,
			&rsp->row_count, &rsp->precipient_row,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropGetAttachmentTable: {
		auto rq = static_cast<GETATTACHMENTTABLE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_getattachmenttable(rq->table_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropGetValidAttachments: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETVALIDATTACHMENTS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getvalidattachments(&rsp->attachment_ids,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSubmitMessage: {
		auto rq = static_cast<SUBMITMESSAGE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_submitmessage(rq->submit_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropAbortSubmit: {
		auto rq = static_cast<ABORTSUBMIT_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_abortsubmit(
			rq->folder_id, rq->message_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetAddressTypes: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETADDRESSTYPES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getaddresstypes(&rsp->address_types,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetSpooler:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setspooler(
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSpoolerLockMessage: {
		auto rq = static_cast<SPOOLERLOCKMESSAGE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_spoolerlockmessage(
			rq->message_id, rq->lock_stat,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportSend: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<TRANSPORTSEND_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_transportsend(&rsp->ppropvals,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportNewMail: {
		auto rq = static_cast<TRANSPORTNEWMAIL_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_transportnewmail(rq->message_id,
			rq->folder_id, rq->pstr_class, rq->message_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetTransportFolder: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETTRANSPORTFOLDER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_gettransportfolder(&rsp->folder_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOptionsData: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<OPTIONSDATA_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<OPTIONSDATA_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_optionsdata(rq->paddress_type,
			rq->want_win32, &rsp->reserved, &rsp->options_info,
			&rsp->help_file, &rsp->pfile_name,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertyIdsFromNames: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETPROPERTYIDSFROMNAMES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETPROPERTYIDSFROMNAMES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getpropertyidsfromnames(
			rq->flags, &rq->propnames, &rsp->propids,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetNamesFromPropertyIds: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETNAMESFROMPROPERTYIDS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETNAMESFROMPROPERTYIDS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getnamesfrompropertyids(
			&rq->propids, &rsp->propnames,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesSpecific: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETPROPERTIESSPECIFIC_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETPROPERTIESSPECIFIC_REQUEST *>(prequest->ppayload);
		rsp->pproptags = &rq->proptags;
		(*ppresponse)->result = rop_getpropertiesspecific(
			rq->size_limit, rq->want_unicode, &rq->proptags, &rsp->row,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesAll: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETPROPERTIESALL_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETPROPERTIESALL_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getpropertiesall(rq->size_limit,
			rq->want_unicode, &rsp->propvals,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesList: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETPROPERTIESLIST_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getpropertieslist(&rsp->proptags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetProperties: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETPROPERTIES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SETPROPERTIES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_setproperties(
			&rq->propvals, &rsp->problems,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetPropertiesNoReplicate: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SETPROPERTIESNOREPLICATE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SETPROPERTIESNOREPLICATE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_setpropertiesnoreplicate(
			&rq->propvals, &rsp->problems,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeleteProperties: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<DELETEPROPERTIES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<DELETEPROPERTIES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_deleteproperties(
			&rq->proptags, &rsp->problems,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeletePropertiesNoReplicate: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<DELETEPROPERTIESNOREPLICATE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<DELETEPROPERTIESNOREPLICATE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_deletepropertiesnoreplicate(
			&rq->proptags, &rsp->problems,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryNamedProperties: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<QUERYNAMEDPROPERTIES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<QUERYNAMEDPROPERTIES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_querynamedproperties(
			rq->query_flags, rq->pguid, &rsp->propidnames,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCopyProperties: {
		auto rq = static_cast<COPYPROPERTIES_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<COPYPROPERTIES_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_copyproperties(
			rq->want_asynchronous, rq->copy_flags, &rq->proptags,
			&rsp->problems,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			auto v = cu_alloc<uint32_t>();
			(*ppresponse)->ppayload = v;
			if (v == nullptr)
				return ecServerOOM;
			*v = rq->hindex;
		}
		break;
	}
	case ropCopyTo: {
		auto rq = static_cast<COPYTO_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<COPYTO_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_copyto(rq->want_asynchronous,
			rq->want_subobjects, rq->copy_flags,
			&rq->excluded_proptags, &rsp->problems,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			auto v = cu_alloc<uint32_t>();
			(*ppresponse)->ppayload = v;
			if (v == nullptr)
				return ecServerOOM;
			*v = rq->hindex;
		}
		break;
	}
	case ropProgress: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<PROGRESS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<PROGRESS_REQUEST *>(prequest->ppayload);
		rsp->logon_id = prequest->logon_id;
		(*ppresponse)->result = rop_progress(rq->want_cancel,
			&rsp->completed_count, &rsp->total_count,
			&rop_id, &partial_completion, pemsmdb_info->plogmap.get(),
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenStream: {
		auto rq = static_cast<OPENSTREAM_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<OPENSTREAM_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_openstream(rq->proptag,
			rq->flags, &rsp->stream_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropReadStream: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<READSTREAM_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<READSTREAM_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_readstream(rq->byte_count,
			rq->max_byte_count, &rsp->data,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteStream: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<WRITESTREAM_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<WRITESTREAM_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_writestream(
			&rq->data, &rsp->written_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCommitStream:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_commitstream(
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStreamSize: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETSTREAMSIZE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_getstreamsize(&rsp->stream_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetStreamSize: {
		auto rq = static_cast<SETSTREAMSIZE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setstreamsize(rq->stream_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekStream: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SEEKSTREAM_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SEEKSTREAM_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_seekstream(rq->seek_pos,
			rq->offset, &rsp->new_pos,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCopyToStream: {
		auto rq = static_cast<COPYTOSTREAM_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYTOSTREAM_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_copytostream(rq->byte_count,
			&rsp->read_bytes, &rsp->written_bytes,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->hindex]);
		if ((*ppresponse)->result == ecDstNullObject) {
			auto nr = cu_alloc<COPYTOSTREAM_NULL_DEST_RESPONSE>();
			if (nr == nullptr)
				return ecServerOOM;
			nr->hindex = rq->hindex;
			nr->read_bytes = 0;
			nr->written_bytes = 0;
			(*ppresponse)->ppayload = nr;
		}
		break;
	}
	case ropLockRegionStream: {
		auto rq = static_cast<LOCKREGIONSTREAM_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_lockregionstream(rq->region_offset,
			rq->region_size, rq->lock_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropUnlockRegionStream: {
		auto rq = static_cast<UNLOCKREGIONSTREAM_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_unlockregionstream(
			rq->region_offset, rq->region_size, rq->lock_flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteAndCommitStream: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<WRITEANDCOMMITSTREAM_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<WRITEANDCOMMITSTREAM_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_writeandcommitstream(
			&rq->data, &rsp->written_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCloneStream: {
		auto rq = static_cast<CLONESTREAM_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_clonestream(pemsmdb_info->plogmap.get(),
			prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropModifyPermissions: {
		auto rq = static_cast<MODIFYPERMISSIONS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifypermissions(
			rq->flags, rq->count, rq->prow,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPermissionsTable: {
		auto rq = static_cast<GETPERMISSIONSTABLE_REQUEST *>(prequest->ppayload);
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_getpermissionstable(rq->flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropModifyRules: {
		auto rq = static_cast<MODIFYRULES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_modifyrules(
			rq->flags, rq->count, rq->prow,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetRulesTable: {
		auto rq = static_cast<GETRULESTABLE_REQUEST *>(prequest->ppayload);
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_getrulestable(rq->flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropUpdateDeferredActionMessages: {
		auto rq = static_cast<UPDATEDEFERREDACTIONMESSAGES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_updatedeferredactionmessages(
			&rq->server_entry_id, &rq->client_entry_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferDestinationConfigure: {
		auto rq = static_cast<FASTTRANSFERDESTCONFIGURE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_fasttransferdestconfigure(
			rq->source_operation, rq->flags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferDestinationPutBuffer: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<FASTTRANSFERDESTPUTBUFFER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<FASTTRANSFERDESTPUTBUFFER_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_fasttransferdestputbuffer(
			&rq->transfer_data, &rsp->transfer_status,
			&rsp->in_progress_count, &rsp->total_step_count,
			&rsp->reserved, &rsp->used_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferSourceGetBuffer: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<FASTTRANSFERSOURCEGETBUFFER_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<FASTTRANSFERSOURCEGETBUFFER_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_fasttransfersourcegetbuffer(
			rq->buffer_size, rq->max_buffer_size,
			&rsp->transfer_status, &rsp->in_progress_count,
			&rsp->total_step_count, &rsp->reserved,
			&rsp->transfer_data,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		if ((*ppresponse)->result == ecBufferTooSmall)
			return ecBufferTooSmall;
		break;
	}
	case ropFastTransferSourceCopyFolder: {
		auto rq = static_cast<FASTTRANSFERSOURCECOPYFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyfolder(
			rq->flags, rq->send_options,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferSourceCopyMessages: {
		auto rq = static_cast<FASTTRANSFERSOURCECOPYMESSAGES_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_fasttransfersourcecopymessages(
			&rq->message_ids, rq->flags, rq->send_options,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferSourceCopyTo: {
		auto rq = static_cast<FASTTRANSFERSOURCECOPYTO_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyto(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropFastTransferSourceCopyProperties: {
		auto rq = static_cast<FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result =	rop_fasttransfersourcecopyproperties(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropTellVersion: {
		auto rq = static_cast<TELLVERSION_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_tellversion(rq->version,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationConfigure: {
		auto rq = static_cast<SYNCCONFIGURE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_syncconfigure(rq->sync_type,
			rq->send_options, rq->sync_flags, rq->pres,
			rq->extra_flags, &rq->proptags,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationImportMessageChange: {
		auto rq = static_cast<SYNCIMPORTMESSAGECHANGE_REQUEST *>(prequest->ppayload);
		if (rq->hindex > hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		auto rsp = cu_alloc<SYNCIMPORTMESSAGECHANGE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		(*ppresponse)->result = rop_syncimportmessagechange(
			rq->import_flags, &rq->propvals, &rsp->message_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationImportReadStateChanges: {
		auto rq = static_cast<SYNCIMPORTREADSTATECHANGES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncimportreadstatechanges(
			rq->count, rq->pread_stat,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportHierarchyChange: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SYNCIMPORTHIERARCHYCHANGE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SYNCIMPORTHIERARCHYCHANGE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_syncimporthierarchychange(
			&rq->hichyvals, &rq->propvals, &rsp->folder_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportDeletes: {
		auto rq = static_cast<SYNCIMPORTDELETES_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncimportdeletes(
			rq->flags, &rq->propvals,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportMessageMove: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<SYNCIMPORTMESSAGEMOVE_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<SYNCIMPORTMESSAGEMOVE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_syncimportmessagemove(
			&rq->src_folder_id, &rq->src_message_id,
			&rq->change_list, &rq->dst_message_id,
			&rq->change_number, &rsp->message_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationOpenCollector: {
		auto rq = static_cast<SYNCOPENCOLLECTOR_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_syncopencollector(
			rq->is_content_collector,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationGetTransferState: {
		auto rq = static_cast<SYNCGETTRANSFERSTATE_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_syncgettransferstate(
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	case ropSynchronizationUploadStateStreamBegin: {
		auto rq = static_cast<SYNCUPLOADSTATESTREAMBEGIN_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreambegin(
			rq->proptag_stat, rq->buffer_size,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamContinue: {
		auto rq = static_cast<SYNCUPLOADSTATESTREAMCONTINUE_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreamcontinue(&rq->stream_data,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamEnd:
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_syncuploadstatestreamend(
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetLocalReplicaMidsetDeleted: {
		auto rq = static_cast<SETLOCALREPLICAMIDSETDELETED_REQUEST *>(prequest->ppayload);
		(*ppresponse)->hindex = prequest->hindex;
		(*ppresponse)->result = rop_setlocalreplicamidsetdeleted(
			rq->count, rq->prange,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetLocalReplicaIds: {
		(*ppresponse)->hindex = prequest->hindex;
		auto rsp = cu_alloc<GETLOCALREPLICAIDS_RESPONSE>();
		(*ppresponse)->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<GETLOCALREPLICAIDS_REQUEST *>(prequest->ppayload);
		(*ppresponse)->result = rop_getlocalreplicaids(
			rq->count, &rsp->replguid, &rsp->global_count,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropRegisterNotification: {
		auto rq = static_cast<REGISTERNOTIFICATION_REQUEST *>(prequest->ppayload);
		if (rq->hindex >= hnum)
			return ecInvalidObject;
		(*ppresponse)->hindex = rq->hindex;
		(*ppresponse)->result = rop_registernotification(
			rq->notification_types, rq->reserved,
			rq->want_whole_store, rq->pfolder_id, rq->pmessage_id,
			pemsmdb_info->plogmap.get(), prequest->logon_id, phandles[prequest->hindex],
			phandles + (*ppresponse)->hindex);
		break;
	}
	default:
		mlog(LV_DEBUG, "emsmdb: rop 0x%.2x not implemented!",
			prequest->rop_id);
		return ecError;
	}
	return ecSuccess;
}
