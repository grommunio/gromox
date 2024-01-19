// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
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

ec_error_t rop_dispatch(const rop_request &request, rop_response *&rshead,
    uint32_t *phandles, uint8_t hnum)
{
	auto prequest = &request;
	const auto ppresponse = &rshead;
	void *pdata;
	uint8_t rop_id;
	uint16_t max_rop;
	EXT_PUSH ext_push;
	uint8_t partial_completion;
	
	*ppresponse = NULL;
	auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	if (prequest->hindex >= hnum)
		return ecInvalidObject;
	if (prequest->rop_id == ropRelease) {
		rop_release(&pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex]);
		return ecSuccess;
	}
	*ppresponse = cu_alloc<rop_response>();
	if (*ppresponse == nullptr)
		return ecServerOOM;
	rshead->rop_id = prequest->rop_id;
	rshead->ppayload = NULL;
	
	switch (prequest->rop_id) {
	case ropLogon: {
		rshead->hindex = prequest->hindex;
		auto rq = static_cast<const LOGON_REQUEST *>(prequest->ppayload);
		auto rdr = cu_alloc<LOGON_REDIRECT_RESPONSE>();
		if (rdr == nullptr)
			return ecServerOOM;
		if (rq->pessdn != nullptr)
			gx_strlcpy(rdr->pserver_name, rq->pessdn, std::size(rdr->pserver_name));
		else
			rdr->pserver_name[0] = '\0';
		if (rq->logon_flags & LOGON_FLAG_PRIVATE) {
			auto pmb = cu_alloc<LOGON_PMB_RESPONSE>();
			rshead->ppayload = pmb;
			if (pmb == nullptr)
				return ecServerOOM;
			pmb->logon_flags = rq->logon_flags;
			rshead->result = rop_logon_pmb(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, std::size(rdr->pserver_name), pmb->folder_ids,
				&pmb->response_flags, &pmb->mailbox_guid,
				&pmb->replid, &pmb->replguid,
				&pmb->logon_time, &pmb->gwart_time,
				&pmb->store_stat,
				&pemsmdb_info->logmap, prequest->logon_id, &phandles[prequest->hindex]);
		} else {
			auto pfr = cu_alloc<LOGON_PF_RESPONSE>();
			rshead->ppayload = pfr;
			if (pfr == nullptr)
				return ecServerOOM;
			pfr->logon_flags = rq->logon_flags;
			rshead->result = rop_logon_pf(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, pfr->folder_ids,
				&pfr->replid, &pfr->replguid,
				&pfr->per_user_guid,
				&pemsmdb_info->logmap, prequest->logon_id, &phandles[prequest->hindex]);
		}
		if (rshead->result == ecWrongServer) {
			rdr->logon_flags = rq->logon_flags;
			rshead->ppayload = rdr;
		}
		break;
	}
	case ropGetReceiveFolder: {
		auto rsp = cu_alloc<GETRECEIVEFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETRECEIVEFOLDER_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getreceivefolder(rq->pstr_class,
			&rsp->folder_id, &rsp->pstr_class,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetReceiveFolder: {
		auto rq = static_cast<const SETRECEIVEFOLDER_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setreceivefolder(
			rq->folder_id, rq->pstr_class,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetReceiveFolderTable: {
		auto rsp = cu_alloc<GETRECEIVEFOLDERTABLE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getreceivefoldertable(&rsp->rows,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetStoreState: {
		auto rsp = cu_alloc<GETSTORESTAT_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getstorestat(&rsp->stat,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetOwningServers: {
		auto rsp = cu_alloc<GETOWNINGSERVERS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETOWNINGSERVERS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getowningservers(
			rq->folder_id, &rsp->ghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropPublicFolderIsGhosted: {
		auto rsp = cu_alloc<PUBLICFOLDERISGHOSTED_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const PUBLICFOLDERISGHOSTED_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_publicfolderisghosted(
			rq->folder_id, &rsp->pghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropLongTermIdFromId: {
		auto rsp = cu_alloc<LONGTERMIDFROMID_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const LONGTERMIDFROMID_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_longtermidfromid(
			rq->id, &rsp->long_term_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropIdFromLongTermId: {
		auto rsp = cu_alloc<IDFROMLONGTERMID_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const IDFROMLONGTERMID_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_idfromlongtermid(
			&rq->long_term_id, &rsp->id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPerUserLongTermIds: {
		auto rsp = cu_alloc<GETPERUSERLONGTERMIDS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETPERUSERLONGTERMIDS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getperuserlongtermids(
			&rq->guid, &rsp->ids,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPerUserGuid: {
		auto rsp = cu_alloc<GETPERUSERGUID_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETPERUSERGUID_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getperuserguid(
			&rq->long_term_id, &rsp->guid,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadPerUserInformation: {
		auto rsp = cu_alloc<READPERUSERINFORMATION_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const READPERUSERINFORMATION_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_readperuserinformation(
			&rq->long_folder_id, rq->reserved, rq->data_offset,
			rq->max_data_size, &rsp->has_finished, &rsp->data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWritePerUserInformation: {
		auto rq = static_cast<const WRITEPERUSERINFORMATION_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_writeperuserinformation(
			&rq->long_folder_id, rq->has_finished,
			rq->offset, &rq->data, rq->pguid,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenFolder: {
		auto rq = static_cast<const OPENFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_openfolder(rq->folder_id,
			rq->open_flags, &rsp->has_rules, &rsp->pghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropCreateFolder: {
		auto rq = static_cast<const CREATEFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<CREATEFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_createfolder(rq->folder_type,
			rq->use_unicode, rq->open_existing, rq->reserved,
			rq->pfolder_name, rq->pfolder_comment,
			&rsp->folder_id, &rsp->is_existing, &rsp->has_rules,
			&rsp->pghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropDeleteFolder: {
		auto rsp = cu_alloc<DELETEFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const DELETEFOLDER_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_deletefolder(rq->flags,
			rq->folder_id, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetSearchCriteria: {
		auto rq = static_cast<const SETSEARCHCRITERIA_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setsearchcriteria(rq->pres,
			&rq->folder_ids, rq->search_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetSearchCriteria: {
		auto rsp = cu_alloc<GETSEARCHCRITERIA_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETSEARCHCRITERIA_REQUEST *>(prequest->ppayload);
		rsp->logon_id = prequest->logon_id;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getsearchcriteria(rq->use_unicode,
			rq->include_restriction, rq->include_folders,
			&rsp->pres, &rsp->folder_ids, &rsp->search_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropMoveCopyMessages: {
		auto rq = static_cast<const MOVECOPYMESSAGES_REQUEST *>(prequest->ppayload);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<MOVECOPYMESSAGES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_movecopymessages(&rq->message_ids,
			rq->want_asynchronous, rq->want_copy,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		nr->dhindex = rq->dhindex;
		nr->partial_completion = rsp->partial_completion;
		rshead->ppayload = nr;
		break;
	}
	case ropMoveFolder: {
		auto rq = static_cast<const MOVEFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<MOVEFOLDER_RESPONSE>();;
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_movefolder(rq->want_asynchronous,
			rq->use_unicode, rq->folder_id, rq->pnew_name,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		nr->dhindex = rq->dhindex;
		nr->partial_completion = rsp->partial_completion;
		rshead->ppayload = nr;
		break;
	}
	case ropCopyFolder: {
		auto rq = static_cast<const COPYFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_copyfolder(rq->want_asynchronous,
			rq->want_recursive, rq->use_unicode, rq->folder_id,
			rq->pnew_name, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		nr->dhindex = rq->dhindex;
		nr->partial_completion = rsp->partial_completion;
		rshead->ppayload = nr;
		break;
	}
	case ropEmptyFolder: {
		auto rsp = cu_alloc<EMPTYFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const EMPTYFOLDER_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_emptyfolder(rq->want_asynchronous,
			rq->want_delete_associated, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropHardDeleteMessagesAndSubfolders: {
		auto rsp = cu_alloc<EMPTYFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_harddeletemessagesandsubfolders(
			rq->want_asynchronous, rq->want_delete_associated,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeleteMessages: {
		auto rsp = cu_alloc<DELETEMESSAGES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const DELETEMESSAGES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_deletemessages(rq->want_asynchronous,
			rq->notify_non_read, &rq->message_ids,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropHardDeleteMessages: {
		auto rsp = cu_alloc<HARDDELETEMESSAGES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const HARDDELETEMESSAGES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_harddeletemessages(
			rq->want_asynchronous, rq->notify_non_read,
			&rq->message_ids, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetHierarchyTable: {
		auto rq = static_cast<const GETHIERARCHYTABLE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<GETHIERARCHYTABLE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_gethierarchytable(
			rq->table_flags, &rsp->row_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropGetContentsTable: {
		auto rq = static_cast<const GETCONTENTSTABLE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<GETCONTENTSTABLE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_getcontentstable(rq->table_flags,
			&rsp->row_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSetColumns: {
		auto rsp = cu_alloc<SETCOLUMNS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETCOLUMNS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setcolumns(rq->table_flags,
			&rq->proptags, &rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSortTable: {
		auto rsp = cu_alloc<SORTTABLE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SORTTABLE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_sorttable(rq->table_flags,
			&rq->sort_criteria, &rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropRestrict: {
		auto rsp = cu_alloc<RESTRICT_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const RESTRICT_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_restrict(rq->res_flags, rq->pres,
			&rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryRows: {
		auto rsp = cu_alloc<QUERYROWS_RESPONSE>();
		rshead->ppayload = rsp;
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
		auto rq = static_cast<const QUERYROWS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_queryrows(rq->flags,
			rq->forward_read, rq->row_count, &rsp->seek_pos,
			&rsp->count,
			&ext_push, &pemsmdb_info->logmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if (rshead->result != ecSuccess)
			break;
		rsp->bin_rows.pv = pdata;
		rsp->bin_rows.cb = ext_push.m_offset;
		break;
	}
	case ropAbort: {
		auto rsp = cu_alloc<ABORT_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_abort(&rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetStatus: {
		auto rsp = cu_alloc<GETSTATUS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getstatus(&rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryPosition: {
		auto rsp = cu_alloc<QUERYPOSITION_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_queryposition(
			&rsp->numerator, &rsp->denominator,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRow: {
		auto rsp = cu_alloc<SEEKROW_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SEEKROW_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_seekrow(rq->seek_pos, rq->offset,
			rq->want_moved_count, &rsp->has_soughtless,
			&rsp->offset_sought,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRowBookmark: {
		auto rsp = cu_alloc<SEEKROWBOOKMARK_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SEEKROWBOOKMARK_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_seekrowbookmark(&rq->bookmark,
			rq->offset, rq->want_moved_count, &rsp->row_invisible,
			&rsp->has_soughtless, &rsp->offset_sought,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekRowFractional: {
		auto rq = static_cast<const SEEKROWFRACTIONAL_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_seekrowfractional(rq->numerator, rq->denominator,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCreateBookmark: {
		auto rsp = cu_alloc<CREATEBOOKMARK_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_createbookmark(&rsp->bookmark,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryColumnsAll: {
		auto rsp = cu_alloc<QUERYCOLUMNSALL_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_querycolumnsall(&rsp->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFindRow: {
		auto rsp = cu_alloc<FINDROW_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const FINDROW_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_findrow(rq->flags, rq->pres,
			rq->seek_pos, &rq->bookmark, &rsp->bookmark_invisible,
			&rsp->prow, &rsp->pcolumns,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFreeBookmark: {
		auto rq = static_cast<const FREEBOOKMARK_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_freebookmark(&rq->bookmark,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropResetTable:
		rshead->hindex = prequest->hindex;
		rshead->result = rop_resettable(&pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropExpandRow: {
		auto rsp = cu_alloc<EXPANDROW_RESPONSE>();
		rshead->ppayload = rsp;
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
		auto rq = static_cast<const EXPANDROW_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_expandrow(rq->max_count,
			rq->category_id, &rsp->expanded_count,
			&rsp->count, &ext_push,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		if (rshead->result != ecSuccess)
			break;
		rsp->bin_rows.pv = pdata;
		rsp->bin_rows.cb = ext_push.m_offset;
		break;
	}
	case ropCollapseRow: {
		auto rsp = cu_alloc<COLLAPSEROW_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const COLLAPSEROW_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_collapserow(
			rq->category_id, &rsp->collapsed_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetCollapseState: {
		auto rsp = cu_alloc<GETCOLLAPSESTATE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETCOLLAPSESTATE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getcollapsestate(rq->row_id,
			rq->row_instance, &rsp->collapse_state,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetCollapseState: {
		auto rsp = cu_alloc<SETCOLLAPSESTATE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETCOLLAPSESTATE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setcollapsestate(
			&rq->collapse_state, &rsp->bookmark,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenMessage: {
		auto rq = static_cast<const OPENMESSAGE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENMESSAGE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_openmessage(rq->cpid, rq->folder_id,
			rq->open_mode_flags, rq->message_id,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			 &pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			 phandles + rshead->hindex);
		break;
	}
	case ropCreateMessage: {
		auto rq = static_cast<const CREATEMESSAGE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<CREATEMESSAGE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_createmessage(rq->cpid,
			rq->folder_id, rq->associated_flag, &rsp->pmessage_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSaveChangesMessage: {
		auto rsp = cu_alloc<SAVECHANGESMESSAGE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SAVECHANGESMESSAGE_REQUEST *>(prequest->ppayload);
		rsp->ihindex2 = rq->ihindex2;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_savechangesmessage(rq->save_flags,
			&rsp->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->ihindex2]);
		break;
	}
	case ropRemoveAllRecipients: {
		auto rq = static_cast<const REMOVEALLRECIPIENTS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_removeallrecipients(rq->reserved,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropModifyRecipients: {
		auto rq = static_cast<const MODIFYRECIPIENTS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_modifyrecipients(&rq->proptags,
			rq->count, rq->prow,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadRecipients: {
		auto rsp = cu_alloc<READRECIPIENTS_RESPONSE>();
		rshead->ppayload = rsp;
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
		auto rq = static_cast<const READRECIPIENTS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_readrecipients(rq->row_id,
			rq->reserved, &rsp->count,
			&ext_push, &pemsmdb_info->logmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if (rshead->result != ecSuccess)
			break;
		rsp->bin_recipients.pv = pdata;
		rsp->bin_recipients.cb = ext_push.m_offset;
		break;
	}
	case ropReloadCachedInformation: {
		auto rsp = cu_alloc<RELOADCACHEDINFORMATION_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const RELOADCACHEDINFORMATION_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_reloadcachedinformation(rq->reserved,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetMessageStatus: {
		auto rsp = cu_alloc<SETMESSAGESTATUS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETMESSAGESTATUS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setmessagestatus(rq->message_id,
			rq->message_status, rq->status_mask,
			&rsp->message_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetMessageStatus: {
		auto rsp = cu_alloc<GETMESSAGESTATUS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETMESSAGESTATUS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getmessagestatus(
			rq->message_id, &rsp->message_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetReadFlags: {
		auto rsp = cu_alloc<SETREADFLAGS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETREADFLAGS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setreadflags(rq->want_asynchronous,
			rq->read_flags, &rq->message_ids,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetMessageReadFlag: {
		auto rq = static_cast<const SETMESSAGEREADFLAG_REQUEST *>(prequest->ppayload);
		if (rq->ihindex2 >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<SETMESSAGEREADFLAG_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->logon_id = prequest->logon_id;
		rsp->pclient_data = rq->pclient_data;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setmessagereadflag(
			rq->flags, rq->pclient_data, &rsp->read_changed,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->ihindex2]);
		break;
	}
	case ropOpenAttachment: {
		auto rq = static_cast<const OPENATTACHMENT_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_openattachment(
			rq->flags, rq->attachment_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropCreateAttachment: {
		auto rq = static_cast<const CREATEATTACHMENT_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<CREATEATTACHMENT_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_createattachment(
			&rsp->attachment_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropDeleteAttachment: {
		auto rq = static_cast<const DELETEATTACHMENT_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_deleteattachment(rq->attachment_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSaveChangesAttachment: {
		auto rq = static_cast<const SAVECHANGESATTACHMENT_REQUEST *>(prequest->ppayload);
		if (rq->ihindex2 >= hnum)
			return ecInvalidObject;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_savechangesattachment(
			rq->save_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->ihindex2]);
		break;
	}
	case ropOpenEmbeddedMessage: {
		auto rq = static_cast<const OPENEMBEDDEDMESSAGE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENEMBEDDEDMESSAGE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_openembeddedmessage(rq->cpid,
			rq->open_embedded_flags, &rsp->reserved,
			&rsp->message_id, &rsp->has_named_properties,
			&rsp->subject_prefix, &rsp->normalized_subject,
			&rsp->recipient_count, &rsp->recipient_columns,
			&rsp->row_count, &rsp->precipient_row,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropGetAttachmentTable: {
		auto rq = static_cast<const GETATTACHMENTTABLE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_getattachmenttable(rq->table_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropGetValidAttachments: {
		auto rsp = cu_alloc<GETVALIDATTACHMENTS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getvalidattachments(&rsp->attachment_ids,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSubmitMessage: {
		auto rq = static_cast<const SUBMITMESSAGE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_submitmessage(rq->submit_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropAbortSubmit: {
		auto rq = static_cast<const ABORTSUBMIT_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_abortsubmit(
			rq->folder_id, rq->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetAddressTypes: {
		auto rsp = cu_alloc<GETADDRESSTYPES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getaddresstypes(&rsp->address_types,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetSpooler:
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setspooler(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSpoolerLockMessage: {
		auto rq = static_cast<const SPOOLERLOCKMESSAGE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_spoolerlockmessage(
			rq->message_id, rq->lock_stat,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportSend: {
		auto rsp = cu_alloc<TRANSPORTSEND_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_transportsend(&rsp->ppropvals,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportNewMail: {
		auto rq = static_cast<const TRANSPORTNEWMAIL_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_transportnewmail(rq->message_id,
			rq->folder_id, rq->pstr_class, rq->message_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetTransportFolder: {
		auto rsp = cu_alloc<GETTRANSPORTFOLDER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_gettransportfolder(&rsp->folder_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOptionsData: {
		auto rsp = cu_alloc<OPTIONSDATA_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const OPTIONSDATA_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_optionsdata(rq->paddress_type,
			rq->want_win32, &rsp->reserved, &rsp->options_info,
			&rsp->help_file, &rsp->pfile_name,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertyIdsFromNames: {
		auto rsp = cu_alloc<GETPROPERTYIDSFROMNAMES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETPROPERTYIDSFROMNAMES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getpropertyidsfromnames(
			rq->flags, &rq->propnames, &rsp->propids,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetNamesFromPropertyIds: {
		auto rsp = cu_alloc<GETNAMESFROMPROPERTYIDS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETNAMESFROMPROPERTYIDS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getnamesfrompropertyids(
			&rq->propids, &rsp->propnames,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesSpecific: {
		auto rsp = cu_alloc<GETPROPERTIESSPECIFIC_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETPROPERTIESSPECIFIC_REQUEST *>(prequest->ppayload);
		rsp->pproptags = deconst(&rq->proptags);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getpropertiesspecific(
			rq->size_limit, rq->want_unicode, &rq->proptags, &rsp->row,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesAll: {
		auto rsp = cu_alloc<GETPROPERTIESALL_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETPROPERTIESALL_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getpropertiesall(rq->size_limit,
			rq->want_unicode, &rsp->propvals,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPropertiesList: {
		auto rsp = cu_alloc<GETPROPERTIESLIST_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getpropertieslist(&rsp->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetProperties: {
		auto rsp = cu_alloc<SETPROPERTIES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETPROPERTIES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setproperties(
			&rq->propvals, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetPropertiesNoReplicate: {
		auto rsp = cu_alloc<SETPROPERTIESNOREPLICATE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETPROPERTIESNOREPLICATE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setpropertiesnoreplicate(
			&rq->propvals, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeleteProperties: {
		auto rsp = cu_alloc<DELETEPROPERTIES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const DELETEPROPERTIES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_deleteproperties(
			&rq->proptags, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropDeletePropertiesNoReplicate: {
		auto rsp = cu_alloc<DELETEPROPERTIESNOREPLICATE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const DELETEPROPERTIESNOREPLICATE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_deletepropertiesnoreplicate(
			&rq->proptags, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropQueryNamedProperties: {
		auto rsp = cu_alloc<QUERYNAMEDPROPERTIES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const QUERYNAMEDPROPERTIES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_querynamedproperties(
			rq->query_flags, rq->pguid, &rsp->propidnames,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCopyProperties: {
		auto rq = static_cast<const COPYPROPERTIES_REQUEST *>(prequest->ppayload);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYPROPERTIES_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_copyproperties(
			rq->want_asynchronous, rq->copy_flags, &rq->proptags,
			&rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST1_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		nr->dhindex = rq->dhindex;
		rshead->ppayload = nr;
		break;
	}
	case ropCopyTo: {
		auto rq = static_cast<const COPYTO_REQUEST *>(prequest->ppayload);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYTO_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_copyto(rq->want_asynchronous,
			rq->want_subobjects, rq->copy_flags,
			&rq->excluded_proptags, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST1_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		nr->dhindex = rq->dhindex;
		rshead->ppayload = nr;
		break;
	}
	case ropProgress: {
		auto rsp = cu_alloc<PROGRESS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const PROGRESS_REQUEST *>(prequest->ppayload);
		rsp->logon_id = prequest->logon_id;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_progress(rq->want_cancel,
			&rsp->completed_count, &rsp->total_count,
			&rop_id, &partial_completion, &pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenStream: {
		auto rq = static_cast<const OPENSTREAM_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENSTREAM_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_openstream(rq->proptag,
			rq->flags, &rsp->stream_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropReadStream: {
		auto rsp = cu_alloc<READSTREAM_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const READSTREAM_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_readstream(rq->byte_count,
			rq->max_byte_count, &rsp->data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteStream: {
		auto rsp = cu_alloc<WRITESTREAM_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const WRITESTREAM_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_writestream(
			&rq->data, &rsp->written_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCommitStream:
		rshead->hindex = prequest->hindex;
		rshead->result = rop_commitstream(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStreamSize: {
		auto rsp = cu_alloc<GETSTREAMSIZE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getstreamsize(&rsp->stream_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSetStreamSize: {
		auto rq = static_cast<const SETSTREAMSIZE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setstreamsize(rq->stream_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekStream: {
		auto rsp = cu_alloc<SEEKSTREAM_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SEEKSTREAM_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_seekstream(rq->seek_pos,
			rq->offset, &rsp->new_pos,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCopyToStream: {
		auto rq = static_cast<const COPYTOSTREAM_REQUEST *>(prequest->ppayload);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYTOSTREAM_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = prequest->hindex;
		rshead->result = rop_copytostream(rq->byte_count,
			&rsp->read_bytes, &rsp->written_bytes,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<COPYTOSTREAM_NULL_DEST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		nr->dhindex = rq->dhindex;
		nr->read_bytes = 0;
		nr->written_bytes = 0;
		rshead->ppayload = nr;
		break;
	}
	case ropLockRegionStream: {
		auto rq = static_cast<const LOCKREGIONSTREAM_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_lockregionstream(rq->region_offset,
			rq->region_size, rq->lock_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropUnlockRegionStream: {
		auto rq = static_cast<const UNLOCKREGIONSTREAM_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_unlockregionstream(
			rq->region_offset, rq->region_size, rq->lock_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteAndCommitStream: {
		auto rsp = cu_alloc<WRITEANDCOMMITSTREAM_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const WRITEANDCOMMITSTREAM_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_writeandcommitstream(
			&rq->data, &rsp->written_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCloneStream: {
		auto rq = static_cast<const CLONESTREAM_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_clonestream(&pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropModifyPermissions: {
		auto rq = static_cast<const MODIFYPERMISSIONS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_modifypermissions(
			rq->flags, rq->count, rq->prow,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPermissionsTable: {
		auto rq = static_cast<const GETPERMISSIONSTABLE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_getpermissionstable(rq->flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropModifyRules: {
		auto rq = static_cast<const MODIFYRULES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_modifyrules(
			rq->flags, rq->count, rq->prow,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetRulesTable: {
		auto rq = static_cast<const GETRULESTABLE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_getrulestable(rq->flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropUpdateDeferredActionMessages: {
		auto rq = static_cast<const UPDATEDEFERREDACTIONMESSAGES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_updatedeferredactionmessages(
			&rq->server_entry_id, &rq->client_entry_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferDestinationConfigure: {
		auto rq = static_cast<const FASTTRANSFERDESTCONFIGURE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_fasttransferdestconfigure(
			rq->source_operation, rq->flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropFastTransferDestinationPutBuffer: {
		auto rsp = cu_alloc<FASTTRANSFERDESTPUTBUFFER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const FASTTRANSFERDESTPUTBUFFER_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_fasttransferdestputbuffer(
			&rq->transfer_data, &rsp->transfer_status,
			&rsp->in_progress_count, &rsp->total_step_count,
			&rsp->reserved, &rsp->used_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferSourceGetBuffer: {
		auto rsp = cu_alloc<FASTTRANSFERSOURCEGETBUFFER_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const FASTTRANSFERSOURCEGETBUFFER_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_fasttransfersourcegetbuffer(
			rq->buffer_size, rq->max_buffer_size,
			&rsp->transfer_status, &rsp->in_progress_count,
			&rsp->total_step_count, &rsp->reserved,
			&rsp->transfer_data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		if (rshead->result == ecBufferTooSmall)
			return ecBufferTooSmall;
		break;
	}
	case ropFastTransferSourceCopyFolder: {
		auto rq = static_cast<const FASTTRANSFERSOURCECOPYFOLDER_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result =	rop_fasttransfersourcecopyfolder(
			rq->flags, rq->send_options,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropFastTransferSourceCopyMessages: {
		auto rq = static_cast<const FASTTRANSFERSOURCECOPYMESSAGES_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_fasttransfersourcecopymessages(
			&rq->message_ids, rq->flags, rq->send_options,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropFastTransferSourceCopyTo: {
		auto rq = static_cast<const FASTTRANSFERSOURCECOPYTO_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result =	rop_fasttransfersourcecopyto(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropFastTransferSourceCopyProperties: {
		auto rq = static_cast<const FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result =	rop_fasttransfersourcecopyproperties(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropTellVersion: {
		auto rq = static_cast<const TELLVERSION_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_tellversion(rq->version,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationConfigure: {
		auto rq = static_cast<const SYNCCONFIGURE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_syncconfigure(rq->sync_type,
			rq->send_options, rq->sync_flags, rq->pres,
			rq->extra_flags, &rq->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSynchronizationImportMessageChange: {
		auto rq = static_cast<const SYNCIMPORTMESSAGECHANGE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<SYNCIMPORTMESSAGECHANGE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_syncimportmessagechange(
			rq->import_flags, &rq->propvals, &rsp->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSynchronizationImportReadStateChanges: {
		auto rq = static_cast<const SYNCIMPORTREADSTATECHANGES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncimportreadstatechanges(
			rq->count, rq->pread_stat,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportHierarchyChange: {
		auto rsp = cu_alloc<SYNCIMPORTHIERARCHYCHANGE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SYNCIMPORTHIERARCHYCHANGE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncimporthierarchychange(
			&rq->hichyvals, &rq->propvals, &rsp->folder_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportDeletes: {
		auto rq = static_cast<const SYNCIMPORTDELETES_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncimportdeletes(
			rq->flags, &rq->propvals,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportMessageMove: {
		auto rsp = cu_alloc<SYNCIMPORTMESSAGEMOVE_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SYNCIMPORTMESSAGEMOVE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncimportmessagemove(
			&rq->src_folder_id, &rq->src_message_id,
			&rq->change_list, &rq->dst_message_id,
			&rq->change_number, &rsp->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationOpenCollector: {
		auto rq = static_cast<const SYNCOPENCOLLECTOR_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_syncopencollector(
			rq->is_content_collector,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSynchronizationGetTransferState: {
		auto rq = static_cast<const SYNCGETTRANSFERSTATE_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_syncgettransferstate(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSynchronizationUploadStateStreamBegin: {
		auto rq = static_cast<const SYNCUPLOADSTATESTREAMBEGIN_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncuploadstatestreambegin(
			rq->proptag_stat, rq->buffer_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamContinue: {
		auto rq = static_cast<const SYNCUPLOADSTATESTREAMCONTINUE_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncuploadstatestreamcontinue(&rq->stream_data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamEnd:
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncuploadstatestreamend(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSetLocalReplicaMidsetDeleted: {
		auto rq = static_cast<const SETLOCALREPLICAMIDSETDELETED_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setlocalreplicamidsetdeleted(
			rq->count, rq->prange,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetLocalReplicaIds: {
		auto rsp = cu_alloc<GETLOCALREPLICAIDS_RESPONSE>();
		rshead->ppayload = rsp;
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const GETLOCALREPLICAIDS_REQUEST *>(prequest->ppayload);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_getlocalreplicaids(
			rq->count, &rsp->replguid, &rsp->global_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropRegisterNotification: {
		auto rq = static_cast<const REGISTERNOTIFICATION_REQUEST *>(prequest->ppayload);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_registernotification(
			rq->notification_types, rq->reserved,
			rq->want_whole_store, rq->pfolder_id, rq->pmessage_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	default:
		mlog(LV_DEBUG, "emsmdb: rop 0x%.2x not implemented!",
			prequest->rop_id);
		return ecError;
	}
	return ecSuccess;
}
