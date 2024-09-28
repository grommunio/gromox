// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "rop_dispatch.hpp"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"
#define CAST_TO(type) static_cast<const type ## _REQUEST *>(&request)

using namespace gromox;

unsigned int g_rop_debug;

ec_error_t rop_dispatch(const rop_request &request, rop_response *&rshead,
    uint32_t *phandles, uint8_t hnum)
{
	auto prequest = &request;
	void *pdata;
	uint8_t rop_id;
	uint16_t max_rop;
	EXT_PUSH ext_push;
	uint8_t partial_completion;

	auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	if (prequest->hindex >= hnum)
		return ecInvalidObject;
	if (prequest->rop_id == ropRelease) {
		rop_release(&pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex]);
		return ecSuccess;
	}

	/*
	 * Kinda redundant for cases like ropLogon, but not replicating it for
	 * all the empty-response cases also helps linecount.
	 */
	rshead = cu_alloc<rop_response>();
	if (rshead == nullptr)
		return ecServerOOM;
	
	switch (prequest->rop_id) {
	case ropLogon: {
		auto rq = CAST_TO(LOGON);
		auto rdr = cu_alloc<LOGON_REDIRECT_RESPONSE>();
		if (rdr == nullptr)
			return ecServerOOM;
		if (rq->pessdn != nullptr)
			gx_strlcpy(rdr->pserver_name, rq->pessdn, std::size(rdr->pserver_name));
		else
			rdr->pserver_name[0] = '\0';
		if (rq->logon_flags & LOGON_FLAG_PRIVATE) {
			auto pmb = cu_alloc<LOGON_PMB_RESPONSE>();
			if (pmb == nullptr)
				return ecServerOOM;
			pmb->logon_flags = rq->logon_flags;
			pmb->result = rop_logon_pmb(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, std::size(rdr->pserver_name), pmb->folder_ids,
				&pmb->response_flags, &pmb->mailbox_guid,
				&pmb->replid, &pmb->replguid,
				&pmb->logon_time, &pmb->gwart_time,
				&pmb->store_stat,
				&pemsmdb_info->logmap, prequest->logon_id, &phandles[prequest->hindex]);
			rshead = std::move(pmb);
		} else {
			auto pfr = cu_alloc<LOGON_PF_RESPONSE>();
			if (pfr == nullptr)
				return ecServerOOM;
			pfr->logon_flags = rq->logon_flags;
			pfr->result = rop_logon_pf(rq->logon_flags,
				rq->open_flags, rq->store_stat,
				rdr->pserver_name, pfr->folder_ids,
				&pfr->replid, &pfr->replguid,
				&pfr->per_user_guid,
				&pemsmdb_info->logmap, prequest->logon_id, &phandles[prequest->hindex]);
			rshead = std::move(pfr);
		}
		if (rshead->result == ecWrongServer) {
			rdr->logon_flags = rq->logon_flags;
			rshead = std::move(rdr);
		}
		rshead->hindex = prequest->hindex;
		break;
	}
	case ropGetReceiveFolder: {
		auto rsp = cu_alloc<GETRECEIVEFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETRECEIVEFOLDER);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getreceivefolder(rq->pstr_class,
			&rsp->folder_id, &rsp->pstr_class,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetReceiveFolder: {
		auto rq = CAST_TO(SETRECEIVEFOLDER);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setreceivefolder(
			rq->folder_id, rq->pstr_class,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetReceiveFolderTable: {
		auto rsp = cu_alloc<GETRECEIVEFOLDERTABLE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getreceivefoldertable(&rsp->rows,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetStoreState: {
		auto rsp = cu_alloc<GETSTORESTAT_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getstorestat(&rsp->stat,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetOwningServers: {
		auto rsp = cu_alloc<GETOWNINGSERVERS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETOWNINGSERVERS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getowningservers(
			rq->folder_id, &rsp->ghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropPublicFolderIsGhosted: {
		auto rsp = cu_alloc<PUBLICFOLDERISGHOSTED_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(PUBLICFOLDERISGHOSTED);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_publicfolderisghosted(
			rq->folder_id, &rsp->pghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropLongTermIdFromId: {
		auto rsp = cu_alloc<LONGTERMIDFROMID_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(LONGTERMIDFROMID);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_longtermidfromid(
			rq->id, &rsp->long_term_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropIdFromLongTermId: {
		auto rsp = cu_alloc<IDFROMLONGTERMID_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(IDFROMLONGTERMID);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_idfromlongtermid(
			&rq->long_term_id, &rsp->id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetPerUserLongTermIds: {
		auto rsp = cu_alloc<GETPERUSERLONGTERMIDS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETPERUSERLONGTERMIDS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getperuserlongtermids(
			&rq->guid, &rsp->ids,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetPerUserGuid: {
		auto rsp = cu_alloc<GETPERUSERGUID_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETPERUSERGUID);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getperuserguid(
			&rq->long_term_id, &rsp->guid,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropReadPerUserInformation: {
		auto rsp = cu_alloc<READPERUSERINFORMATION_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(READPERUSERINFORMATION);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_readperuserinformation(
			&rq->long_folder_id, rq->reserved, rq->data_offset,
			rq->max_data_size, &rsp->has_finished, &rsp->data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropWritePerUserInformation: {
		auto rq = CAST_TO(WRITEPERUSERINFORMATION);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_writeperuserinformation(
			&rq->long_folder_id, rq->has_finished,
			rq->offset, &rq->data, rq->pguid,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropOpenFolder: {
		auto rq = CAST_TO(OPENFOLDER);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_openfolder(rq->folder_id,
			rq->open_flags, &rsp->has_rules, &rsp->pghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropCreateFolder: {
		auto rq = CAST_TO(CREATEFOLDER);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<CREATEFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_createfolder(rq->folder_type,
			rq->use_unicode, rq->open_existing, rq->reserved,
			rq->pfolder_name, rq->pfolder_comment,
			&rsp->folder_id, &rsp->is_existing, &rsp->has_rules,
			&rsp->pghost,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropDeleteFolder: {
		auto rsp = cu_alloc<DELETEFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(DELETEFOLDER);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_deletefolder(rq->flags,
			rq->folder_id, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetSearchCriteria: {
		auto rq = CAST_TO(SETSEARCHCRITERIA);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setsearchcriteria(rq->pres,
			&rq->folder_ids, rq->search_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetSearchCriteria: {
		auto rsp = cu_alloc<GETSEARCHCRITERIA_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETSEARCHCRITERIA);
		rsp->logon_id = prequest->logon_id;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getsearchcriteria(rq->use_unicode,
			rq->include_restriction, rq->include_folders,
			&rsp->pres, &rsp->folder_ids, &rsp->search_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropMoveCopyMessages: {
		auto rq = CAST_TO(MOVECOPYMESSAGES);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<MOVECOPYMESSAGES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_movecopymessages(&rq->message_ids,
			rq->want_asynchronous, rq->want_copy,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		rshead = std::move(rsp);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		*static_cast<rop_response *>(nr) = *rshead;
		nr->dhindex = rq->dhindex;
		nr->partial_completion = static_cast<const MOVECOPYMESSAGES_RESPONSE *>(rshead)->partial_completion;
		rshead = std::move(nr);
		break;
	}
	case ropMoveFolder: {
		auto rq = CAST_TO(MOVEFOLDER);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<MOVEFOLDER_RESPONSE>();;
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_movefolder(rq->want_asynchronous,
			rq->use_unicode, rq->folder_id, rq->pnew_name,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		rshead = std::move(rsp);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		*static_cast<rop_response *>(nr) = *rshead;
		nr->dhindex = rq->dhindex;
		nr->partial_completion = static_cast<const MOVEFOLDER_RESPONSE *>(rshead)->partial_completion;
		rshead = std::move(nr);
		break;
	}
	case ropCopyFolder: {
		auto rq = CAST_TO(COPYFOLDER);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_copyfolder(rq->want_asynchronous,
			rq->want_recursive, rq->use_unicode, rq->folder_id,
			rq->pnew_name, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		rshead = std::move(rsp);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		*static_cast<rop_response *>(nr) = *rshead;
		nr->dhindex = rq->dhindex;
		nr->partial_completion = static_cast<COPYFOLDER_RESPONSE *>(rshead)->partial_completion;
		rshead = std::move(nr);
		break;
	}
	case ropEmptyFolder: {
		auto rsp = cu_alloc<EMPTYFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(EMPTYFOLDER);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_emptyfolder(rq->want_asynchronous,
			rq->want_delete_associated, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropHardDeleteMessagesAndSubfolders: {
		auto rsp = cu_alloc<EMPTYFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(HARDDELETEMESSAGESANDSUBFOLDERS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_harddeletemessagesandsubfolders(
			rq->want_asynchronous, rq->want_delete_associated,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropDeleteMessages: {
		auto rsp = cu_alloc<DELETEMESSAGES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(DELETEMESSAGES);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_deletemessages(rq->want_asynchronous,
			rq->notify_non_read, &rq->message_ids,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropHardDeleteMessages: {
		auto rsp = cu_alloc<HARDDELETEMESSAGES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(HARDDELETEMESSAGES);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_harddeletemessages(
			rq->want_asynchronous, rq->notify_non_read,
			&rq->message_ids, &rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetHierarchyTable: {
		auto rq = CAST_TO(GETHIERARCHYTABLE);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<GETHIERARCHYTABLE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_gethierarchytable(
			rq->table_flags, &rsp->row_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropGetContentsTable: {
		auto rq = CAST_TO(GETCONTENTSTABLE);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<GETCONTENTSTABLE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_getcontentstable(rq->table_flags,
			&rsp->row_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropSetColumns: {
		auto rsp = cu_alloc<SETCOLUMNS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SETCOLUMNS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setcolumns(rq->table_flags,
			&rq->proptags, &rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSortTable: {
		auto rsp = cu_alloc<SORTTABLE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SORTTABLE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_sorttable(rq->table_flags,
			&rq->sort_criteria, &rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropRestrict: {
		auto rsp = cu_alloc<RESTRICT_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(RESTRICT);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_restrict(rq->res_flags, rq->pres,
			&rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropQueryRows: {
		auto rsp = cu_alloc<QUERYROWS_RESPONSE>();
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
		auto rq = CAST_TO(QUERYROWS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_queryrows(rq->flags,
			rq->forward_read, rq->row_count, &rsp->seek_pos,
			&rsp->count,
			&ext_push, &pemsmdb_info->logmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if (rsp->result == ecSuccess) {
			rsp->bin_rows.pv = pdata;
			rsp->bin_rows.cb = ext_push.m_offset;
		}
		rshead = std::move(rsp);
		break;
	}
	case ropAbort: {
		auto rsp = cu_alloc<ABORT_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_abort(&rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetStatus: {
		auto rsp = cu_alloc<GETSTATUS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getstatus(&rsp->table_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropQueryPosition: {
		auto rsp = cu_alloc<QUERYPOSITION_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_queryposition(
			&rsp->numerator, &rsp->denominator,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSeekRow: {
		auto rsp = cu_alloc<SEEKROW_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SEEKROW);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_seekrow(rq->seek_pos, rq->offset,
			rq->want_moved_count, &rsp->has_soughtless,
			&rsp->offset_sought,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSeekRowBookmark: {
		auto rsp = cu_alloc<SEEKROWBOOKMARK_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SEEKROWBOOKMARK);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_seekrowbookmark(&rq->bookmark,
			rq->offset, rq->want_moved_count, &rsp->row_invisible,
			&rsp->has_soughtless, &rsp->offset_sought,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSeekRowFractional: {
		auto rq = CAST_TO(SEEKROWFRACTIONAL);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_seekrowfractional(rq->numerator, rq->denominator,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropCreateBookmark: {
		auto rsp = cu_alloc<CREATEBOOKMARK_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_createbookmark(&rsp->bookmark,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropQueryColumnsAll: {
		auto rsp = cu_alloc<QUERYCOLUMNSALL_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_querycolumnsall(&rsp->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropFindRow: {
		auto rsp = cu_alloc<FINDROW_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(FINDROW);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_findrow(rq->flags, rq->pres,
			rq->seek_pos, &rq->bookmark, &rsp->bookmark_invisible,
			&rsp->prow, &rsp->pcolumns,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropFreeBookmark: {
		auto rq = CAST_TO(FREEBOOKMARK);
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
		auto rq = CAST_TO(EXPANDROW);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_expandrow(rq->max_count,
			rq->category_id, &rsp->expanded_count,
			&rsp->count, &ext_push,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		if (rsp->result == ecSuccess) {
			rsp->bin_rows.pv = pdata;
			rsp->bin_rows.cb = ext_push.m_offset;
		}
		rshead = std::move(rsp);
		break;
	}
	case ropCollapseRow: {
		auto rsp = cu_alloc<COLLAPSEROW_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(COLLAPSEROW);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_collapserow(
			rq->category_id, &rsp->collapsed_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetCollapseState: {
		auto rsp = cu_alloc<GETCOLLAPSESTATE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETCOLLAPSESTATE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getcollapsestate(rq->row_id,
			rq->row_instance, &rsp->collapse_state,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetCollapseState: {
		auto rsp = cu_alloc<SETCOLLAPSESTATE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SETCOLLAPSESTATE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setcollapsestate(
			&rq->collapse_state, &rsp->bookmark,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropOpenMessage: {
		auto rq = CAST_TO(OPENMESSAGE);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENMESSAGE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_openmessage(rq->cpid, rq->folder_id,
			rq->open_mode_flags, rq->message_id,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			 &pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			 phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropCreateMessage: {
		auto rq = CAST_TO(CREATEMESSAGE);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<CREATEMESSAGE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_createmessage(rq->cpid,
			rq->folder_id, rq->associated_flag, &rsp->pmessage_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropSaveChangesMessage: {
		auto rsp = cu_alloc<SAVECHANGESMESSAGE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SAVECHANGESMESSAGE);
		rsp->ihindex2 = rq->ihindex2;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_savechangesmessage(rq->save_flags,
			&rsp->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->ihindex2]);
		rshead = std::move(rsp);
		break;
	}
	case ropRemoveAllRecipients: {
		auto rq = CAST_TO(REMOVEALLRECIPIENTS);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_removeallrecipients(rq->reserved,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropModifyRecipients: {
		auto rq = CAST_TO(MODIFYRECIPIENTS);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_modifyrecipients(&rq->proptags,
			rq->count, rq->prow,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropReadRecipients: {
		auto rsp = cu_alloc<READRECIPIENTS_RESPONSE>();
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
		auto rq = CAST_TO(READRECIPIENTS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_readrecipients(rq->row_id,
			rq->reserved, &rsp->count,
			&ext_push, &pemsmdb_info->logmap, prequest->logon_id,
			phandles[prequest->hindex]);
		if (rsp->result == ecSuccess) {
			rsp->bin_recipients.pv = pdata;
			rsp->bin_recipients.cb = ext_push.m_offset;
		}
		rshead = std::move(rsp);
		break;
	}
	case ropReloadCachedInformation: {
		auto rsp = cu_alloc<RELOADCACHEDINFORMATION_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(RELOADCACHEDINFORMATION);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_reloadcachedinformation(rq->reserved,
			&rsp->has_named_properties, &rsp->subject_prefix,
			&rsp->normalized_subject, &rsp->recipient_count,
			&rsp->recipient_columns, &rsp->row_count,
			&rsp->precipient_row,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetMessageStatus: {
		auto rsp = cu_alloc<SETMESSAGESTATUS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = static_cast<const SETMESSAGESTATUS_REQUEST *>(prequest);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setmessagestatus(rq->message_id,
			rq->message_status, rq->status_mask,
			&rsp->message_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetMessageStatus: {
		auto rsp = cu_alloc<GETMESSAGESTATUS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETMESSAGESTATUS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getmessagestatus(
			rq->message_id, &rsp->message_status,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetReadFlags: {
		auto rsp = cu_alloc<SETREADFLAGS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SETREADFLAGS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setreadflags(rq->want_asynchronous,
			rq->read_flags, &rq->message_ids,
			&rsp->partial_completion,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetMessageReadFlag: {
		auto rq = CAST_TO(SETMESSAGEREADFLAG);
		if (rq->ihindex2 >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<SETMESSAGEREADFLAG_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->logon_id = prequest->logon_id;
		rsp->pclient_data = rq->pclient_data;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setmessagereadflag(
			rq->flags, rq->pclient_data, &rsp->read_changed,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->ihindex2]);
		rshead = std::move(rsp);
		break;
	}
	case ropOpenAttachment: {
		auto rq = CAST_TO(OPENATTACHMENT);
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
		auto rq = CAST_TO(CREATEATTACHMENT);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<CREATEATTACHMENT_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_createattachment(
			&rsp->attachment_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropDeleteAttachment: {
		auto rq = CAST_TO(DELETEATTACHMENT);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_deleteattachment(rq->attachment_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSaveChangesAttachment: {
		auto rq = CAST_TO(SAVECHANGESATTACHMENT);
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
		auto rq = CAST_TO(OPENEMBEDDEDMESSAGE);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENEMBEDDEDMESSAGE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_openembeddedmessage(rq->cpid,
			rq->open_embedded_flags, &rsp->reserved,
			&rsp->message_id, &rsp->has_named_properties,
			&rsp->subject_prefix, &rsp->normalized_subject,
			&rsp->recipient_count, &rsp->recipient_columns,
			&rsp->row_count, &rsp->precipient_row,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropGetAttachmentTable: {
		auto rq = CAST_TO(GETATTACHMENTTABLE);
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
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getvalidattachments(&rsp->attachment_ids,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSubmitMessage: {
		auto rq = CAST_TO(SUBMITMESSAGE);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_submitmessage(rq->submit_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropAbortSubmit: {
		auto rq = CAST_TO(ABORTSUBMIT);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_abortsubmit(
			rq->folder_id, rq->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetAddressTypes: {
		auto rsp = cu_alloc<GETADDRESSTYPES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getaddresstypes(&rsp->address_types,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetSpooler:
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setspooler(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropSpoolerLockMessage: {
		auto rq = CAST_TO(SPOOLERLOCKMESSAGE);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_spoolerlockmessage(
			rq->message_id, rq->lock_stat,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropTransportSend: {
		auto rsp = cu_alloc<TRANSPORTSEND_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_transportsend(&rsp->ppropvals,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropTransportNewMail: {
		auto rq = CAST_TO(TRANSPORTNEWMAIL);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_transportnewmail(rq->message_id,
			rq->folder_id, rq->pstr_class, rq->message_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetTransportFolder: {
		auto rsp = cu_alloc<GETTRANSPORTFOLDER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_gettransportfolder(&rsp->folder_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropOptionsData: {
		auto rsp = cu_alloc<OPTIONSDATA_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(OPTIONSDATA);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_optionsdata(rq->paddress_type,
			rq->want_win32, &rsp->reserved, &rsp->options_info,
			&rsp->help_file, &rsp->pfile_name,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetPropertyIdsFromNames: {
		auto rsp = cu_alloc<GETPROPERTYIDSFROMNAMES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETPROPERTYIDSFROMNAMES);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getpropertyidsfromnames(
			rq->flags, &rq->propnames, &rsp->propids,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetNamesFromPropertyIds: {
		auto rsp = cu_alloc<GETNAMESFROMPROPERTYIDS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETNAMESFROMPROPERTYIDS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getnamesfrompropertyids(
			&rq->propids, &rsp->propnames,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetPropertiesSpecific: {
		auto rsp = cu_alloc<GETPROPERTIESSPECIFIC_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETPROPERTIESSPECIFIC);
		rsp->pproptags = deconst(&rq->proptags);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getpropertiesspecific(
			rq->size_limit, rq->want_unicode, &rq->proptags, &rsp->row,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetPropertiesAll: {
		auto rsp = cu_alloc<GETPROPERTIESALL_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETPROPERTIESALL);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getpropertiesall(rq->size_limit,
			rq->want_unicode, &rsp->propvals,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropGetPropertiesList: {
		auto rsp = cu_alloc<GETPROPERTIESLIST_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getpropertieslist(&rsp->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetProperties: {
		auto rsp = cu_alloc<SETPROPERTIES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SETPROPERTIES);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setproperties(
			&rq->propvals, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetPropertiesNoReplicate: {
		auto rsp = cu_alloc<SETPROPERTIESNOREPLICATE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SETPROPERTIESNOREPLICATE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_setpropertiesnoreplicate(
			&rq->propvals, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropDeleteProperties: {
		auto rsp = cu_alloc<DELETEPROPERTIES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(DELETEPROPERTIES);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_deleteproperties(
			&rq->proptags, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropDeletePropertiesNoReplicate: {
		auto rsp = cu_alloc<DELETEPROPERTIESNOREPLICATE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(DELETEPROPERTIESNOREPLICATE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_deletepropertiesnoreplicate(
			&rq->proptags, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropQueryNamedProperties: {
		auto rsp = cu_alloc<QUERYNAMEDPROPERTIES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(QUERYNAMEDPROPERTIES);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_querynamedproperties(
			rq->query_flags, rq->pguid, &rsp->propidnames,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropCopyProperties: {
		auto rq = CAST_TO(COPYPROPERTIES);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYPROPERTIES_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_copyproperties(
			rq->want_asynchronous, rq->copy_flags, &rq->proptags,
			&rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		rshead = std::move(rsp);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST1_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		*static_cast<rop_response *>(nr) = *rshead;
		nr->dhindex = rq->dhindex;
		rshead = std::move(nr);
		break;
	}
	case ropCopyTo: {
		auto rq = CAST_TO(COPYTO);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYTO_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_copyto(rq->want_asynchronous,
			rq->want_subobjects, rq->copy_flags,
			&rq->excluded_proptags, &rsp->problems,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		rshead = std::move(rsp);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<NULL_DST1_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		*static_cast<rop_response *>(nr) = *rshead;
		nr->dhindex = rq->dhindex;
		rshead = std::move(nr);
		break;
	}
	case ropProgress: {
		auto rsp = cu_alloc<PROGRESS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(PROGRESS);
		rsp->logon_id = prequest->logon_id;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_progress(rq->want_cancel,
			&rsp->completed_count, &rsp->total_count,
			&rop_id, &partial_completion, &pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropOpenStream: {
		auto rq = CAST_TO(OPENSTREAM);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<OPENSTREAM_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_openstream(rq->proptag,
			rq->flags, &rsp->stream_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropReadStream: {
		auto rsp = cu_alloc<READSTREAM_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(READSTREAM);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_readstream(rq->byte_count,
			rq->max_byte_count, &rsp->data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropWriteStream: {
		auto rsp = cu_alloc<WRITESTREAM_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(WRITESTREAM);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_writestream(
			&rq->data, &rsp->written_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropCommitStream:
		rshead->hindex = prequest->hindex;
		rshead->result = rop_commitstream(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	case ropGetStreamSize: {
		auto rsp = cu_alloc<GETSTREAMSIZE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getstreamsize(&rsp->stream_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSetStreamSize: {
		auto rq = CAST_TO(SETSTREAMSIZE);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setstreamsize(rq->stream_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSeekStream: {
		auto rsp = cu_alloc<SEEKSTREAM_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SEEKSTREAM);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_seekstream(rq->seek_pos,
			rq->offset, &rsp->new_pos,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropCopyToStream: {
		auto rq = CAST_TO(COPYTOSTREAM);
		if (rq->dhindex >= hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<COPYTOSTREAM_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = prequest->hindex;
		rsp->result = rop_copytostream(rq->byte_count,
			&rsp->read_bytes, &rsp->written_bytes,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles[rq->dhindex]);
		rshead = std::move(rsp);
		if (rshead->result != ecDstNullObject)
			break;
		auto nr = cu_alloc<COPYTOSTREAM_NULL_DEST_RESPONSE>();
		if (nr == nullptr)
			return ecServerOOM;
		*static_cast<rop_response *>(nr) = *rshead;
		nr->dhindex = rq->dhindex;
		nr->read_bytes = 0;
		nr->written_bytes = 0;
		rshead = std::move(nr);
		break;
	}
	case ropLockRegionStream: {
		auto rq = CAST_TO(LOCKREGIONSTREAM);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_lockregionstream(rq->region_offset,
			rq->region_size, rq->lock_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropUnlockRegionStream: {
		auto rq = CAST_TO(UNLOCKREGIONSTREAM);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_unlockregionstream(
			rq->region_offset, rq->region_size, rq->lock_flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropWriteAndCommitStream: {
		auto rsp = cu_alloc<WRITEANDCOMMITSTREAM_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(WRITEANDCOMMITSTREAM);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_writeandcommitstream(
			&rq->data, &rsp->written_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropCloneStream: {
		auto rq = CAST_TO(CLONESTREAM);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_clonestream(&pemsmdb_info->logmap,
			prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropModifyPermissions: {
		auto rq = CAST_TO(MODIFYPERMISSIONS);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_modifypermissions(
			rq->flags, rq->count, rq->prow,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetPermissionsTable: {
		auto rq = CAST_TO(GETPERMISSIONSTABLE);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_getpermissionstable(rq->flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropModifyRules: {
		auto rq = CAST_TO(MODIFYRULES);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_modifyrules(
			rq->flags, rq->count, rq->prow,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetRulesTable: {
		auto rq = CAST_TO(GETRULESTABLE);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_getrulestable(rq->flags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropUpdateDeferredActionMessages: {
		auto rq = CAST_TO(UPDATEDEFERREDACTIONMESSAGES);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_updatedeferredactionmessages(
			&rq->server_entry_id, &rq->client_entry_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropFastTransferDestinationConfigure: {
		auto rq = CAST_TO(FASTTRANSFERDESTCONFIGURE);
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
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(FASTTRANSFERDESTPUTBUFFER);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_fasttransferdestputbuffer(
			&rq->transfer_data, &rsp->transfer_status,
			&rsp->in_progress_count, &rsp->total_step_count,
			&rsp->reserved, &rsp->used_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropFastTransferSourceGetBuffer: {
		auto rsp = cu_alloc<FASTTRANSFERSOURCEGETBUFFER_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(FASTTRANSFERSOURCEGETBUFFER);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_fasttransfersourcegetbuffer(
			rq->buffer_size, rq->max_buffer_size,
			&rsp->transfer_status, &rsp->in_progress_count,
			&rsp->total_step_count, &rsp->reserved,
			&rsp->transfer_data,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		if (rshead->result == ecBufferTooSmall)
			return ecBufferTooSmall;
		break;
	}
	case ropFastTransferSourceCopyFolder: {
		auto rq = CAST_TO(FASTTRANSFERSOURCECOPYFOLDER);
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
		auto rq = CAST_TO(FASTTRANSFERSOURCECOPYMESSAGES);
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
		auto rq = CAST_TO(FASTTRANSFERSOURCECOPYTO);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_fasttransfersourcecopyto(
			rq->level, rq->flags, rq->send_options, &rq->proptags,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropFastTransferSourceCopyProperties: {
		auto rq = CAST_TO(FASTTRANSFERSOURCECOPYPROPERTIES);
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
		auto rq = CAST_TO(TELLVERSION);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_tellversion(rq->version,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationConfigure: {
		auto rq = CAST_TO(SYNCCONFIGURE);
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
		auto rq = CAST_TO(SYNCIMPORTMESSAGECHANGE);
		if (rq->ohindex > hnum)
			return ecInvalidObject;
		auto rsp = cu_alloc<SYNCIMPORTMESSAGECHANGE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		rsp->hindex = rq->ohindex;
		rsp->result = rop_syncimportmessagechange(
			rq->import_flags, &rq->propvals, &rsp->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rsp->hindex);
		rshead = std::move(rsp);
		break;
	}
	case ropSynchronizationImportReadStateChanges: {
		auto rq = CAST_TO(SYNCIMPORTREADSTATECHANGES);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncimportreadstatechanges(
			rq->count, rq->pread_stat,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportHierarchyChange: {
		auto rsp = cu_alloc<SYNCIMPORTHIERARCHYCHANGE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SYNCIMPORTHIERARCHYCHANGE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_syncimporthierarchychange(
			&rq->hichyvals, &rq->propvals, &rsp->folder_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSynchronizationImportDeletes: {
		auto rq = CAST_TO(SYNCIMPORTDELETES);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncimportdeletes(
			rq->flags, &rq->propvals,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationImportMessageMove: {
		auto rsp = cu_alloc<SYNCIMPORTMESSAGEMOVE_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(SYNCIMPORTMESSAGEMOVE);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_syncimportmessagemove(
			&rq->src_folder_id, &rq->src_message_id,
			&rq->change_list, &rq->dst_message_id,
			&rq->change_number, &rsp->message_id,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropSynchronizationOpenCollector: {
		auto rq = CAST_TO(SYNCOPENCOLLECTOR);
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
		auto rq = CAST_TO(SYNCGETTRANSFERSTATE);
		if (rq->ohindex >= hnum)
			return ecInvalidObject;
		rshead->hindex = rq->ohindex;
		rshead->result = rop_syncgettransferstate(
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex],
			phandles + rshead->hindex);
		break;
	}
	case ropSynchronizationUploadStateStreamBegin: {
		auto rq = CAST_TO(SYNCUPLOADSTATESTREAMBEGIN);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_syncuploadstatestreambegin(
			rq->proptag_stat, rq->buffer_size,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropSynchronizationUploadStateStreamContinue: {
		auto rq = CAST_TO(SYNCUPLOADSTATESTREAMCONTINUE);
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
		auto rq = CAST_TO(SETLOCALREPLICAMIDSETDELETED);
		rshead->hindex = prequest->hindex;
		rshead->result = rop_setlocalreplicamidsetdeleted(
			rq->count, rq->prange,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		break;
	}
	case ropGetLocalReplicaIds: {
		auto rsp = cu_alloc<GETLOCALREPLICAIDS_RESPONSE>();
		if (rsp == nullptr)
			return ecServerOOM;
		auto rq = CAST_TO(GETLOCALREPLICAIDS);
		rsp->hindex = prequest->hindex;
		rsp->result = rop_getlocalreplicaids(
			rq->count, &rsp->replguid, &rsp->global_count,
			&pemsmdb_info->logmap, prequest->logon_id, phandles[prequest->hindex]);
		rshead = std::move(rsp);
		break;
	}
	case ropRegisterNotification: {
		auto rq = CAST_TO(REGISTERNOTIFICATION);
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
	rshead->rop_id = request.rop_id;
	return ecSuccess;
}
