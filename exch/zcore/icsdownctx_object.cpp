// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/algorithm.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "ics_state.hpp"
#include "objects.hpp"
#include "store_object.hpp"
#include "zserver.hpp"

using namespace gromox;
using gromox::exmdb_client;

std::unique_ptr<icsdownctx_object>
icsdownctx_object::create(folder_object *pfolder, uint8_t sync_type)
{
	std::unique_ptr<icsdownctx_object> pctx;
	try {
		pctx.reset(new icsdownctx_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pctx->pstate = ics_state::create(sync_type);
	if (pctx->pstate == nullptr)
		return NULL;
	pctx->pstore = pfolder->pstore;
	pctx->folder_id = pfolder->folder_id;
	pctx->sync_type = sync_type;
	pctx->b_started = FALSE;
	pctx->eid_pos = 0;
	return pctx;
}

ec_error_t icsdownctx_object::make_content(const BINARY &pstate_bin,
    const RESTRICTION *prestriction, uint16_t sync_flags,
    bool *pb_changed, uint32_t *pmsg_count) try
{
	auto pctx = this;
	uint32_t count_fai;
	uint64_t total_fai;
	uint64_t total_normal;
	uint32_t count_normal;
	EID_ARRAY chg_messages, read_messages, given_messages, unread_messages;
	EID_ARRAY updated_messages, deleted_messages, nolonger_messages;
	
	*pb_changed = FALSE;
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return ecInvalidParam;
	if (!pctx->pstate->deserialize(pstate_bin))
		return ecError;
	auto pinfo = zs_get_info();
	auto pread     = (sync_flags & SYNC_READ_STATE) ? pctx->pstate->pread.get()     : nullptr;
	auto pseen_fai = (sync_flags & SYNC_ASSOCIATED) ? pctx->pstate->pseen_fai.get() : nullptr;
	auto pseen     = (sync_flags & SYNC_NORMAL)     ? pctx->pstate->pseen.get()     : nullptr;
	auto username = pctx->pstore->b_private ? nullptr : pinfo->get_username();
	if (!exmdb_client->get_content_sync(pctx->pstore->get_dir(),
	    pctx->folder_id, username, pctx->pstate->pgiven.get(), pseen, pseen_fai,
	    pread, pinfo->cpid, prestriction, TRUE, &count_fai, &total_fai,
	    &count_normal, &total_normal, &updated_messages, &chg_messages,
	    &pctx->last_changenum, &given_messages, &deleted_messages,
	    &nolonger_messages, &read_messages, &unread_messages,
	    &pctx->last_readcn))
		return ecRpcFailed;

	pgiven_eids.emplace(given_messages.cbegin(), given_messages.cend());
	if (sync_flags & (SYNC_ASSOCIATED | SYNC_NORMAL)) {
		pchg_eids.emplace(chg_messages.cbegin(), chg_messages.cend());
		pupdated_eids.emplace(updated_messages.cbegin(), updated_messages.cend());
		*pmsg_count = chg_messages.count;
		if (chg_messages.count > 0)
			*pb_changed = TRUE;
	} else {
		*pmsg_count = 0;
	}
	if (!(sync_flags & SYNC_NO_DELETIONS)) {
		pdeleted_eids.emplace(deleted_messages.cbegin(), deleted_messages.cend());
		pnolonger_messages.emplace(nolonger_messages.cbegin(), nolonger_messages.cend());
		if (deleted_messages.count > 0 || nolonger_messages.count > 0)
			*pb_changed = TRUE;
	}
	if (sync_flags & SYNC_READ_STATE) {
		pread_messages.emplace(read_messages.cbegin(), read_messages.cend());
		punread_messages.emplace(unread_messages.cbegin(), unread_messages.cend());
		if (read_messages.count > 0 || unread_messages.count > 0)
			*pb_changed = TRUE;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return ecServerOOM;
}

ec_error_t icsdownctx_object::make_hierarchy(const BINARY &state,
    uint16_t sync_flags, bool *pb_changed, uint32_t *pfld_count) try
{
	auto pctx = this;
	FOLDER_CHANGES fldchgs;
	EID_ARRAY given_folders;
	EID_ARRAY deleted_folders;
	
	*pb_changed = FALSE;
	if (pctx->sync_type != SYNC_TYPE_HIERARCHY)
		return ecInvalidParam;
	if (!pctx->pstate->deserialize(state))
		return ecError;
	auto pinfo = zs_get_info();
	auto username = pctx->pstore->owner_mode() ? nullptr : pinfo->get_username();
	if (!exmdb_client->get_hierarchy_sync(pctx->pstore->get_dir(),
	    pctx->folder_id, username, pctx->pstate->pgiven.get(),
	    pctx->pstate->pseen.get(), &fldchgs, &pctx->last_changenum,
	    &given_folders, &deleted_folders))
		return ecRpcFailed;

	pgiven_eids.emplace(given_folders.cbegin(), given_folders.cend());
	if (!(sync_flags & SYNC_NO_DELETIONS)) {
		pdeleted_eids.emplace(deleted_folders.cbegin(), deleted_folders.cend());
		if (deleted_folders.count > 0)
			*pb_changed = TRUE;
	}
	pchg_eids.emplace();
	for (const auto &chg : fldchgs) {
		auto pvalue = chg.get<const uint64_t>(PidTagFolderId);
		if (pvalue == nullptr)
			return ecNotFound;
		pchg_eids->emplace_back(*pvalue);
	}
	if (fldchgs.count > 0)
		*pb_changed = TRUE;
	*pfld_count = fldchgs.count;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return ecServerOOM;
}

BINARY *icsdownctx_object::get_state()
{
	auto pctx = this;
	if (pgiven_eids.has_value() && pchg_eids.has_value() &&
	    eid_pos >= pchg_eids->size() && !pdeleted_eids.has_value() &&
	    !pnolonger_messages.has_value()) {
		pctx->pstate->pgiven->clear();
		for (auto eid : *pctx->pgiven_eids)
			if (!pctx->pstate->pgiven->append(eid))
				return nullptr;
		pctx->pstate->pseen->clear();
		if (pctx->last_changenum != 0 &&
		    !pctx->pstate->pseen->append_range(1, 1,
		    rop_util_get_gc_value(pctx->last_changenum)))
			return nullptr;
		if (SYNC_TYPE_CONTENTS == pctx->sync_type) {
			pctx->pstate->pseen_fai->clear();
			if (pctx->last_changenum != 0 &&
			    !pctx->pstate->pseen_fai->append_range(1, 1,
			    rop_util_get_gc_value(pctx->last_changenum)))
				return nullptr;
		}
		pctx->last_changenum = 0;
		pctx->pgiven_eids.reset();
		pctx->pchg_eids.reset();
		pctx->pupdated_eids.reset();
	}
	return pctx->pstate->serialize();
}

ec_error_t icsdownctx_object::sync_message_change(bool *pb_found, bool *pb_new,
    TPROPVAL_ARRAY *pproplist)
{
	auto pctx = this;
	void *pvalue;
	uint64_t message_id;
	
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return ecInvalidParam;
	if (!pchg_eids.has_value() || !pupdated_eids.has_value()) {
		*pb_found = FALSE;
		return ecSuccess;
	}
	do {
		if (eid_pos >= pchg_eids->size()) {
			*pb_found = FALSE;
			return ecSuccess;
		}
		message_id = (*pchg_eids)[eid_pos++];
		if (!exmdb_client_get_message_property(pctx->pstore->get_dir(),
		    nullptr, CP_ACP, message_id, PidTagChangeNumber, &pvalue))
			return ecRpcFailed;
	} while (NULL == pvalue);
	*pb_new = !ct_contains(*pupdated_eids, message_id);
	pproplist->count = 2;
	pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(2);
	if (pproplist->ppropval == nullptr)
		return ecServerOOM;
	pproplist->ppropval[0].proptag = PR_SOURCE_KEY;
	pproplist->ppropval[0].pvalue = cu_mid_to_sk(*pctx->pstore, message_id);
	if (pproplist->ppropval[0].pvalue == nullptr)
		return ecError;
	pproplist->ppropval[1].proptag = PR_PARENT_SOURCE_KEY;
	pproplist->ppropval[1].pvalue = cu_fid_to_sk(*pctx->pstore, pctx->folder_id);
	if (pproplist->ppropval[1].pvalue == nullptr)
		return ecError;
	*pb_found = TRUE;
	if (!pctx->pstate->pgiven->append(message_id) ||
	    !pctx->pstate->pseen->append(*static_cast<uint64_t *>(pvalue)) ||
	    !pctx->pstate->pseen_fai->append(*static_cast<uint64_t *>(pvalue)))
		return ecServerOOM;
	return ecSuccess;
}

ec_error_t icsdownctx_object::sync_folder_change(bool *pb_found,
    TPROPVAL_ARRAY *pproplist)
{
	auto pctx = this;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint8_t fake_false = false;
	
	if (pctx->sync_type != SYNC_TYPE_HIERARCHY)
		return ecInvalidParam;
	if (!pchg_eids.has_value() || eid_pos >= pchg_eids->size()) {
		*pb_found = FALSE;
		return ecSuccess;
	}
	auto fid = (*pchg_eids)[eid_pos++];
	pproplist->count = 0;
	pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(8);
	if (pproplist->ppropval == nullptr)
		return ecServerOOM;
	void *pvalue = cu_fid_to_sk(*pctx->pstore, fid);
	if (pvalue == nullptr)
		return ecError;
	pproplist->emplace_back(PR_SOURCE_KEY, pvalue);

	pvalue = cu_fid_to_entryid(*pctx->pstore, fid);
	if (pvalue == nullptr)
		return ecError;
	pproplist->emplace_back(PR_ENTRYID, pvalue);
	static constexpr gromox::proptag_t proptag_buff[] =
		{PidTagParentFolderId, PR_DISPLAY_NAME, PR_CONTAINER_CLASS,
		PR_ATTR_HIDDEN, PR_EXTENDED_FOLDER_FLAGS, PidTagChangeNumber};
	if (!exmdb_client->get_folder_properties(pctx->pstore->get_dir(), CP_ACP,
	    fid, proptag_buff, &tmp_propvals))
		return ecRpcFailed;
	auto lnum = tmp_propvals.get<const uint64_t>(PidTagChangeNumber);
	if (lnum == nullptr) {
		*pb_found = FALSE;
		return ecSuccess;
	}
	auto change_num = *lnum;
	lnum = tmp_propvals.get<uint64_t>(PidTagParentFolderId);
	if (lnum != nullptr) {
		auto parent_fid = *lnum;
		pvalue = cu_fid_to_sk(*pctx->pstore, parent_fid);
		if (pvalue == nullptr)
			return ecError;
		pproplist->emplace_back(PR_PARENT_SOURCE_KEY, pvalue);

		pvalue = cu_fid_to_entryid(*pctx->pstore, parent_fid);
		if (pvalue == nullptr)
			return ecError;
		pproplist->emplace_back(PR_PARENT_ENTRYID, pvalue);
	}
	pvalue = tmp_propvals.getval(PR_DISPLAY_NAME);
	if (pvalue != nullptr)
		pproplist->emplace_back(PR_DISPLAY_NAME, pvalue);
	pvalue = tmp_propvals.getval(PR_CONTAINER_CLASS);
	if (pvalue != nullptr)
		pproplist->emplace_back(PR_CONTAINER_CLASS, pvalue);
	pvalue = tmp_propvals.getval(PR_ATTR_HIDDEN);
	pproplist->emplace_back(PR_ATTR_HIDDEN,
		pvalue != nullptr ? pvalue : deconst(&fake_false));

	pvalue = tmp_propvals.getval(PR_EXTENDED_FOLDER_FLAGS);
	if (pvalue != nullptr)
		pproplist->emplace_back(PR_EXTENDED_FOLDER_FLAGS, pvalue);
	*pb_found = TRUE;
	if (!pctx->pstate->pgiven->append(fid) ||
	    !pctx->pstate->pseen->append(change_num))
		return ecServerOOM;
	return ecSuccess;
}

ec_error_t icsdownctx_object::sync_deletions(uint32_t flags, BINARY_ARRAY *pbins)
{
	auto pctx = this;
	
	if (!(flags & SYNC_SOFT_DELETE)) {
		if (!pdeleted_eids.has_value() || pdeleted_eids->empty()) {
			pbins->count = 0;
			pbins->pbin = NULL;
			pdeleted_eids.reset();
			return ecSuccess;
		}
		pbins->pbin = cu_alloc<BINARY>(pdeleted_eids->size());
		if (pbins->pbin == nullptr)
			return ecServerOOM;
		for (size_t i = 0; i < pdeleted_eids->size(); ++i) {
			auto pbin = pctx->sync_type == SYNC_TYPE_CONTENTS ?
			            cu_mid_to_sk(*pctx->pstore, (*pdeleted_eids)[i]) :
			            cu_fid_to_sk(*pctx->pstore, (*pdeleted_eids)[i]);
			if (pbin == nullptr)
				return ecError;
			pbins->pbin[i] = *pbin;
			pctx->pstate->pgiven->remove((*pdeleted_eids)[i]);
		}
		pbins->count = pdeleted_eids->size();
		pdeleted_eids.reset();
		return ecSuccess;
	}

	if (sync_type == SYNC_TYPE_HIERARCHY || !pnolonger_messages.has_value()) {
		pbins->count = 0;
		pbins->pbin = NULL;
		/* Retains pnolonger_messages if sync_type is something else */
		return ecSuccess;
	} else if (pnolonger_messages->empty()) {
		pbins->count = 0;
		pbins->pbin = NULL;
		pnolonger_messages.reset();
		return ecSuccess;
	}
	pbins->pbin = cu_alloc<BINARY>(pnolonger_messages->size());
	if (pbins->pbin == nullptr)
		return ecServerOOM;
	for (size_t i = 0; i < pnolonger_messages->size(); ++i) {
		auto pbin = cu_mid_to_sk(*pctx->pstore, (*pnolonger_messages)[i]);
		if (pbin == nullptr)
			return ecError;
		pbins->pbin[i] = *pbin;
		pctx->pstate->pgiven->remove((*pnolonger_messages)[i]);
	}
	pbins->count = pnolonger_messages->size();
	pnolonger_messages.reset();
	return ecSuccess;
}

ec_error_t icsdownctx_object::sync_readstates(STATE_ARRAY *pstates)
{
	auto pctx = this;
	
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return ecInvalidParam;
	if (!pread_messages.has_value() || !punread_messages.has_value()) {
		pstates->count = 0;
		pstates->pstate = NULL;
		return ecSuccess;
	}
	pstates->count = pread_messages->size() + punread_messages->size();
	if (0 == pstates->count) {
		pstates->count = 0;
		pstates->pstate = NULL;
	} else {
		pstates->pstate = cu_alloc<MESSAGE_STATE>(pstates->count);
		if (NULL == pstates->pstate) {
			pstates->count = 0;
			return ecServerOOM;
		}
		pstates->count = 0;
		for (auto mid : *pctx->pread_messages) {
			auto pbin = cu_mid_to_sk(*pctx->pstore, mid);
			if (pbin == nullptr)
				return ecError;
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count++].message_flags = MSGFLAG_READ;
		}
		for (auto mid : *pctx->punread_messages) {
			auto pbin = cu_mid_to_sk(*pctx->pstore, mid);
			if (pbin == nullptr)
				return ecError;
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count++].message_flags = 0;
		}
	}
	pread_messages.reset();
	punread_messages.reset();
	pctx->pstate->pread->clear();
	if (0 != pctx->last_readcn) {
		if (!pctx->pstate->pread->append_range(1, 1,
		    rop_util_get_gc_value(pctx->last_readcn)))
			return ecServerOOM;
		pctx->last_readcn = 0;
	}
	return ecSuccess;
}
