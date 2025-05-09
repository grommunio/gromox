// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/eid_array.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "ics_state.hpp"
#include "objects.hpp"
#include "store_object.hpp"
#include "zserver.hpp"

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
	pctx->pgiven_eids = NULL;
	pctx->pchg_eids = NULL;
	pctx->pupdated_eids = NULL;
	pctx->pread_messages = nullptr;
	pctx->punread_messages = nullptr;
	pctx->pdeleted_eids = NULL;
	pctx->pnolonger_messages = NULL;
	pctx->b_started = FALSE;
	pctx->eid_pos = 0;
	return pctx;
}

BOOL icsdownctx_object::make_content(const BINARY &pstate_bin,
    const RESTRICTION *prestriction, uint16_t sync_flags,
    BOOL *pb_changed, uint32_t *pmsg_count)
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
		return FALSE;
	if (!pctx->pstate->deserialize(pstate_bin))
		return FALSE;
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
		return FALSE;
	if (pctx->pgiven_eids != nullptr)
		eid_array_free(pctx->pgiven_eids);
	pctx->pgiven_eids = eid_array_dup(&given_messages);
	if (pctx->pgiven_eids == nullptr)
		return FALSE;
	if (sync_flags & (SYNC_ASSOCIATED | SYNC_NORMAL)) {
		if (pctx->pchg_eids != nullptr)
			eid_array_free(pctx->pchg_eids);
		pctx->pchg_eids = eid_array_dup(&chg_messages);
		if (pctx->pchg_eids == nullptr)
			return FALSE;
		if (pctx->pupdated_eids != nullptr)
			eid_array_free(pctx->pupdated_eids);
		pctx->pupdated_eids = eid_array_dup(&updated_messages);
		if (pctx->pupdated_eids == nullptr)
			return FALSE;
		*pmsg_count = chg_messages.count;
		if (chg_messages.count > 0)
			*pb_changed = TRUE;
	} else {
		*pmsg_count = 0;
	}
	if (!(sync_flags & SYNC_NO_DELETIONS)) {
		if (pctx->pdeleted_eids != nullptr)
			eid_array_free(pctx->pdeleted_eids);
		pctx->pdeleted_eids = eid_array_dup(&deleted_messages);
		if (pctx->pdeleted_eids == nullptr)
			return FALSE;
		if (pctx->pnolonger_messages != nullptr)
			eid_array_free(pctx->pnolonger_messages);
		pctx->pnolonger_messages = eid_array_dup(&nolonger_messages);
		if (pctx->pnolonger_messages == nullptr)
			return FALSE;
		if (deleted_messages.count > 0 || nolonger_messages.count > 0)
			*pb_changed = TRUE;
	}
	if (sync_flags & SYNC_READ_STATE) {
		if (pctx->pread_messages != nullptr)
			eid_array_free(pctx->pread_messages);
		pctx->pread_messages = eid_array_dup(&read_messages);
		if (pctx->pread_messages == nullptr)
			return FALSE;
		if (pctx->punread_messages != nullptr)
			eid_array_free(pctx->punread_messages);
		pctx->punread_messages = eid_array_dup(&unread_messages);
		if (pctx->punread_messages == nullptr)
			return FALSE;
		if (read_messages.count > 0 || unread_messages.count > 0)
			*pb_changed = TRUE;
	}
	return TRUE;
}

BOOL icsdownctx_object::make_hierarchy(const BINARY &state,
    uint16_t sync_flags, BOOL *pb_changed, uint32_t *pfld_count)
{
	auto pctx = this;
	FOLDER_CHANGES fldchgs;
	EID_ARRAY given_folders;
	EID_ARRAY deleted_folders;
	
	*pb_changed = FALSE;
	if (pctx->sync_type != SYNC_TYPE_HIERARCHY)
		return FALSE;
	if (!pctx->pstate->deserialize(state))
		return FALSE;
	auto pinfo = zs_get_info();
	auto username = pctx->pstore->owner_mode() ? nullptr : pinfo->get_username();
	if (!exmdb_client->get_hierarchy_sync(pctx->pstore->get_dir(),
	    pctx->folder_id, username, pctx->pstate->pgiven.get(),
	    pctx->pstate->pseen.get(), &fldchgs, &pctx->last_changenum,
	    &given_folders, &deleted_folders))
		return FALSE;
	if (pctx->pgiven_eids != nullptr)
		eid_array_free(pctx->pgiven_eids);
	pctx->pgiven_eids = eid_array_dup(&given_folders);
	if (pctx->pgiven_eids == nullptr)
		return FALSE;
	if (!(sync_flags & SYNC_NO_DELETIONS)) {
		if (pctx->pdeleted_eids != nullptr)
			eid_array_free(pctx->pdeleted_eids);
		pctx->pdeleted_eids = eid_array_dup(&deleted_folders);
		if (pctx->pdeleted_eids == nullptr)
			return FALSE;
		if (deleted_folders.count > 0)
			*pb_changed = TRUE;
	}
	pctx->pchg_eids = eid_array_init();
	if (pctx->pchg_eids == nullptr)
		return FALSE;
	for (const auto &chg : fldchgs) {
		auto pvalue = chg.get<const uint64_t>(PidTagFolderId);
		if (pvalue == nullptr)
			return FALSE;
		if (!eid_array_append(pctx->pchg_eids, *pvalue))
			return FALSE;	
	}
	if (fldchgs.count > 0)
		*pb_changed = TRUE;
	*pfld_count = fldchgs.count;
	return TRUE;
}

BINARY *icsdownctx_object::get_state()
{
	auto pctx = this;
	if (NULL != pctx->pgiven_eids && NULL != pctx->pchg_eids
		&& pctx->eid_pos >= pctx->pchg_eids->count && NULL ==
		pctx->pdeleted_eids && NULL == pctx->pnolonger_messages) {
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
		eid_array_free(pctx->pgiven_eids);
		pctx->pgiven_eids = NULL;
		eid_array_free(pctx->pchg_eids);
		pctx->pchg_eids = NULL;
		if (NULL != pctx->pupdated_eids) {
			eid_array_free(pctx->pupdated_eids);
			pctx->pupdated_eids = NULL;
		}
	}
	return pctx->pstate->serialize();
}

icsdownctx_object::~icsdownctx_object()
{
	auto pctx = this;
	if (pctx->pgiven_eids != nullptr)
		eid_array_free(pctx->pgiven_eids);
	if (pctx->pchg_eids != nullptr)
		eid_array_free(pctx->pchg_eids);
	if (pctx->pupdated_eids != nullptr)
		eid_array_free(pctx->pupdated_eids);
	if (pctx->pdeleted_eids != nullptr)
		eid_array_free(pctx->pdeleted_eids);
	if (pctx->pnolonger_messages != nullptr)
		eid_array_free(pctx->pnolonger_messages);
	if (pctx->pread_messages != nullptr)
		eid_array_free(pctx->pread_messages);
	if (pctx->punread_messages != nullptr)
		eid_array_free(pctx->punread_messages);
}

BOOL icsdownctx_object::sync_message_change(BOOL *pb_found, BOOL *pb_new,
    TPROPVAL_ARRAY *pproplist)
{
	auto pctx = this;
	void *pvalue;
	uint64_t message_id;
	
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return FALSE;
	if (NULL == pctx->pchg_eids || NULL == pctx->pupdated_eids) {
		*pb_found = FALSE;
		return TRUE;
	}
	do {
		if (pctx->eid_pos >= pctx->pchg_eids->count) {
			*pb_found = FALSE;
			return TRUE;
		}
		message_id = pctx->pchg_eids->pids[pctx->eid_pos++];
		if (!exmdb_client_get_message_property(pctx->pstore->get_dir(),
		    nullptr, CP_ACP, message_id, PidTagChangeNumber, &pvalue))
			return FALSE;	
	} while (NULL == pvalue);
	*pb_new = !eid_array_check(pctx->pupdated_eids, message_id) ? TRUE : false;
	pproplist->count = 2;
	pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(2);
	if (pproplist->ppropval == nullptr)
		return FALSE;
	pproplist->ppropval[0].proptag = PR_SOURCE_KEY;
	pproplist->ppropval[0].pvalue = cu_mid_to_sk(*pctx->pstore, message_id);
	if (pproplist->ppropval[0].pvalue == nullptr)
		return FALSE;
	pproplist->ppropval[1].proptag = PR_PARENT_SOURCE_KEY;
	pproplist->ppropval[1].pvalue = cu_fid_to_sk(*pctx->pstore, pctx->folder_id);
	if (pproplist->ppropval[1].pvalue == nullptr)
		return FALSE;
	*pb_found = TRUE;
	if (!pctx->pstate->pgiven->append(message_id) ||
	    !pctx->pstate->pseen->append(*static_cast<uint64_t *>(pvalue)) ||
	    !pctx->pstate->pseen_fai->append(*static_cast<uint64_t *>(pvalue)))
		return FALSE;
	return TRUE;
}

BOOL icsdownctx_object::sync_folder_change(BOOL *pb_found,
    TPROPVAL_ARRAY *pproplist)
{
	auto pctx = this;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint8_t fake_false = false;
	
	if (pctx->sync_type != SYNC_TYPE_HIERARCHY)
		return FALSE;
	if (NULL == pctx->pchg_eids ||
		pctx->eid_pos >= pctx->pchg_eids->count) {
		*pb_found = FALSE;
		return TRUE;
	}
	uint64_t fid = pctx->pchg_eids->pids[pctx->eid_pos++];
	pproplist->count = 0;
	pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(8);
	if (pproplist->ppropval == nullptr)
		return FALSE;
	void *pvalue = cu_fid_to_sk(*pctx->pstore, fid);
	if (pvalue == nullptr)
		return FALSE;
	pproplist->emplace_back(PR_SOURCE_KEY, pvalue);

	pvalue = cu_fid_to_entryid(*pctx->pstore, fid);
	if (pvalue == nullptr)
		return FALSE;
	pproplist->emplace_back(PR_ENTRYID, pvalue);
	static constexpr gromox::proptag_t proptag_buff[] =
		{PidTagParentFolderId, PR_DISPLAY_NAME, PR_CONTAINER_CLASS,
		PR_ATTR_HIDDEN, PR_EXTENDED_FOLDER_FLAGS, PidTagChangeNumber};
	static constexpr PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	if (!exmdb_client->get_folder_properties(pctx->pstore->get_dir(), CP_ACP,
	    fid, &proptags, &tmp_propvals))
		return FALSE;
	auto lnum = tmp_propvals.get<const uint64_t>(PidTagChangeNumber);
	if (lnum == nullptr) {
		*pb_found = FALSE;
		return TRUE;
	}
	auto change_num = *lnum;
	lnum = tmp_propvals.get<uint64_t>(PidTagParentFolderId);
	if (lnum != nullptr) {
		auto parent_fid = *lnum;
		pvalue = cu_fid_to_sk(*pctx->pstore, parent_fid);
		if (pvalue == nullptr)
			return FALSE;
		pproplist->emplace_back(PR_PARENT_SOURCE_KEY, pvalue);

		pvalue = cu_fid_to_entryid(*pctx->pstore, parent_fid);
		if (pvalue == nullptr)
			return FALSE;
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
		return FALSE;
	return TRUE;
}

BOOL icsdownctx_object::sync_deletions(uint32_t flags, BINARY_ARRAY *pbins)
{
	auto pctx = this;
	
	if (!(flags & SYNC_SOFT_DELETE)) {
		if (NULL == pctx->pdeleted_eids) {
			pbins->count = 0;
			pbins->pbin = NULL;
			return TRUE;
		}
		if (0 == pctx->pdeleted_eids->count) {
			pbins->count = 0;
			pbins->pbin = NULL;
			eid_array_free(pctx->pdeleted_eids);
			pctx->pdeleted_eids = NULL;
			return TRUE;
		}
		pbins->pbin = cu_alloc<BINARY>(pctx->pdeleted_eids->count);
		if (pbins->pbin == nullptr)
			return FALSE;
		for (size_t i = 0; i < pctx->pdeleted_eids->count; ++i) {
			auto pbin = pctx->sync_type == SYNC_TYPE_CONTENTS ?
			            cu_mid_to_sk(*pctx->pstore, pctx->pdeleted_eids->pids[i]) :
			            cu_fid_to_sk(*pctx->pstore, pctx->pdeleted_eids->pids[i]);
			if (pbin == nullptr)
				return FALSE;
			pbins->pbin[i] = *pbin;
			pctx->pstate->pgiven->remove(pctx->pdeleted_eids->pids[i]);
		}
		pbins->count = pctx->pdeleted_eids->count;
		eid_array_free(pctx->pdeleted_eids);
		pctx->pdeleted_eids = NULL;
		return TRUE;
	}

	if (SYNC_TYPE_HIERARCHY == pctx->sync_type
	    || NULL == pctx->pnolonger_messages) {
		pbins->count = 0;
		pbins->pbin = NULL;
		return TRUE;
	}
	if (0 == pctx->pnolonger_messages->count) {
		pbins->count = 0;
		pbins->pbin = NULL;
		eid_array_free(pctx->pnolonger_messages);
		pctx->pnolonger_messages = NULL;
		return TRUE;
	}
	pbins->pbin = cu_alloc<BINARY>(pctx->pnolonger_messages->count);
	if (pbins->pbin == nullptr)
		return FALSE;
	for (size_t i = 0; i < pctx->pnolonger_messages->count; ++i) {
		auto pbin = cu_mid_to_sk(*pctx->pstore, pctx->pnolonger_messages->pids[i]);
		if (pbin == nullptr)
			return FALSE;
		pbins->pbin[i] = *pbin;
		pctx->pstate->pgiven->remove(pctx->pnolonger_messages->pids[i]);
	}
	pbins->count = pctx->pnolonger_messages->count;
	eid_array_free(pctx->pnolonger_messages);
	pctx->pnolonger_messages = NULL;
	return TRUE;
}

BOOL icsdownctx_object::sync_readstates(STATE_ARRAY *pstates)
{
	auto pctx = this;
	
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return FALSE;
	if (pctx->pread_messages == nullptr || pctx->punread_messages == nullptr) {
		pstates->count = 0;
		pstates->pstate = NULL;
		return TRUE;
	}
	pstates->count = pctx->pread_messages->count + pctx->punread_messages->count;
	if (0 == pstates->count) {
		pstates->count = 0;
		pstates->pstate = NULL;
	} else {
		pstates->pstate = cu_alloc<MESSAGE_STATE>(pstates->count);
		if (NULL == pstates->pstate) {
			pstates->count = 0;
			return FALSE;
		}
		pstates->count = 0;
		for (auto mid : *pctx->pread_messages) {
			auto pbin = cu_mid_to_sk(*pctx->pstore, mid);
			if (pbin == nullptr)
				return FALSE;
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count++].message_flags = MSGFLAG_READ;
		}
		for (auto mid : *pctx->punread_messages) {
			auto pbin = cu_mid_to_sk(*pctx->pstore, mid);
			if (pbin == nullptr)
				return FALSE;
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count++].message_flags = 0;
		}
	}
	eid_array_free(pctx->pread_messages);
	pctx->pread_messages = nullptr;
	eid_array_free(pctx->punread_messages);
	pctx->punread_messages = nullptr;
	pctx->pstate->pread->clear();
	if (0 != pctx->last_readcn) {
		if (!pctx->pstate->pread->append_range(1, 1,
		    rop_util_get_gc_value(pctx->last_readcn)))
			return FALSE;
		pctx->last_readcn = 0;
	}
	return TRUE;
}
