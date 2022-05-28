// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/eid_array.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "ics_state.h"
#include "icsdownctx_object.h"
#include "store_object.h"
#include "zarafa_server.h"

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
	pctx->pread_messags = NULL;
	pctx->punread_messags = NULL;
	pctx->pdeleted_eids = NULL;
	pctx->pnolonger_messages = NULL;
	pctx->b_started = FALSE;
	pctx->eid_pos = 0;
	return pctx;
}

BOOL icsdownctx_object::make_content(const BINARY *pstate_bin,
    const RESTRICTION *prestriction, uint16_t sync_flags,
    BOOL *pb_changed, uint32_t *pmsg_count)
{
	auto pctx = this;
	uint32_t count_fai;
	uint64_t total_fai;
	uint64_t total_normal;
	uint32_t count_normal;
	EID_ARRAY chg_messages;
	EID_ARRAY read_messags;
	EID_ARRAY given_messages;
	EID_ARRAY unread_messags;
	EID_ARRAY updated_messages;
	EID_ARRAY deleted_messages;
	EID_ARRAY nolonger_messages;
	
	*pb_changed = FALSE;
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return FALSE;
	if (!pctx->pstate->deserialize(pstate_bin))
		return FALSE;
	auto pinfo = zarafa_server_get_info();
	auto pread = (sync_flags & SYNC_FLAG_READSTATE) ? pctx->pstate->pread.get() : nullptr;
	auto pseen_fai = (sync_flags & SYNC_FLAG_FAI) ? pctx->pstate->pseen_fai.get() : nullptr;
	auto pseen = (sync_flags & SYNC_FLAG_NORMAL) ? pctx->pstate->pseen.get() : nullptr;
	auto username = pctx->pstore->b_private ? nullptr : pinfo->get_username();
	if (!exmdb_client::get_content_sync(pctx->pstore->get_dir(),
	    pctx->folder_id, username, pctx->pstate->pgiven.get(), pseen, pseen_fai,
	    pread, pinfo->cpid, prestriction, TRUE, &count_fai, &total_fai,
	    &count_normal, &total_normal, &updated_messages, &chg_messages,
	    &pctx->last_changenum, &given_messages, &deleted_messages,
	    &nolonger_messages, &read_messags, &unread_messags,
	    &pctx->last_readcn))
		return FALSE;
	if (pctx->pgiven_eids != nullptr)
		eid_array_free(pctx->pgiven_eids);
	pctx->pgiven_eids = eid_array_dup(&given_messages);
	if (pctx->pgiven_eids == nullptr)
		return FALSE;
	if ((sync_flags & SYNC_FLAG_FAI) ||
		(sync_flags & SYNC_FLAG_NORMAL)) {
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
	if (0 == (sync_flags & SYNC_FLAG_NODELETIONS)) {
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
	if (sync_flags & SYNC_FLAG_READSTATE) {
		if (pctx->pread_messags != nullptr)
			eid_array_free(pctx->pread_messags);
		pctx->pread_messags = eid_array_dup(&read_messags);
		if (pctx->pread_messags == nullptr)
			return FALSE;
		if (pctx->punread_messags != nullptr)
			eid_array_free(pctx->punread_messags);
		pctx->punread_messags = eid_array_dup(&unread_messags);
		if (pctx->punread_messags == nullptr)
			return FALSE;
		if (read_messags.count > 0 || unread_messags.count > 0)
			*pb_changed = TRUE;
	}
	return TRUE;
}

BOOL icsdownctx_object::make_hierarchy(const BINARY *state,
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
	auto pinfo = zarafa_server_get_info();
	auto username = pctx->pstore->check_owner_mode() ? nullptr : pinfo->get_username();
	if (!exmdb_client::get_hierarchy_sync(pctx->pstore->get_dir(),
	    pctx->folder_id, username, pctx->pstate->pgiven.get(),
	    pctx->pstate->pseen.get(), &fldchgs, &pctx->last_changenum,
	    &given_folders, &deleted_folders))
		return FALSE;
	if (pctx->pgiven_eids != nullptr)
		eid_array_free(pctx->pgiven_eids);
	pctx->pgiven_eids = eid_array_dup(&given_folders);
	if (pctx->pgiven_eids == nullptr)
		return FALSE;
	if (0 == (sync_flags & SYNC_FLAG_NODELETIONS)) {
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
	for (size_t i = 0; i < fldchgs.count; ++i) {
		auto pvalue = fldchgs.pfldchgs[i].get<uint64_t>(PidTagFolderId);
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
		for (size_t i = 0; i < pctx->pgiven_eids->count; ++i)
			if (!pctx->pstate->pgiven->append(pctx->pgiven_eids->pids[i]))
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
	if (pctx->pread_messags != nullptr)
		eid_array_free(pctx->pread_messags);
	if (pctx->punread_messags != nullptr)
		eid_array_free(pctx->punread_messags);
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
		message_id = pctx->pchg_eids->pids[pctx->eid_pos];
		pctx->eid_pos ++;
		if (!exmdb_client_get_message_property(pctx->pstore->get_dir(),
		    nullptr, 0, message_id, PidTagChangeNumber, &pvalue))
			return FALSE;	
	} while (NULL == pvalue);
	*pb_new = !eid_array_check(pctx->pupdated_eids, message_id) ? TRUE : false;
	pproplist->count = 2;
	pproplist->ppropval = cu_alloc<TAGGED_PROPVAL>(2);
	if (pproplist->ppropval == nullptr)
		return FALSE;
	pproplist->ppropval[0].proptag = PR_SOURCE_KEY;
	pproplist->ppropval[0].pvalue =
		common_util_calculate_message_sourcekey(
		pctx->pstore, message_id);
	if (pproplist->ppropval[0].pvalue == nullptr)
		return FALSE;
	pproplist->ppropval[1].proptag = PR_PARENT_SOURCE_KEY;
	pproplist->ppropval[1].pvalue =
		common_util_calculate_folder_sourcekey(
		pctx->pstore, pctx->folder_id);
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
	uint64_t parent_fid;
	uint64_t change_num;
	PROPTAG_ARRAY proptags;
	uint32_t proptag_buff[6];
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
	pproplist->ppropval[pproplist->count].proptag = PR_SOURCE_KEY;
	void *pvalue = common_util_calculate_folder_sourcekey(pctx->pstore, fid);
	if (pvalue == nullptr)
		return FALSE;
	pproplist->ppropval[pproplist->count++].pvalue = pvalue;

	pproplist->ppropval[pproplist->count].proptag = PR_ENTRYID;
	pvalue = common_util_to_folder_entryid(pctx->pstore, fid);
	if (pvalue == nullptr)
		return FALSE;
	pproplist->ppropval[pproplist->count++].pvalue = pvalue;
	proptags.count = 6;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PidTagParentFolderId;
	proptag_buff[1] = PR_DISPLAY_NAME;
	proptag_buff[2] = PR_CONTAINER_CLASS;
	proptag_buff[3] = PR_ATTR_HIDDEN;
	proptag_buff[4] = PR_EXTENDED_FOLDER_FLAGS;
	proptag_buff[5] = PidTagChangeNumber;
	if (!exmdb_client::get_folder_properties(pctx->pstore->get_dir(), 0,
	    fid, &proptags, &tmp_propvals))
		return FALSE;
	pvalue = tmp_propvals.getval(PidTagChangeNumber);
	if (NULL == pvalue) {
		*pb_found = FALSE;
		return TRUE;
	}
	change_num = *(uint64_t*)pvalue;
	pvalue = tmp_propvals.getval(PidTagParentFolderId);
	if (NULL != pvalue) {
		parent_fid = *(uint64_t*)pvalue;
		pproplist->ppropval[pproplist->count].proptag = PR_PARENT_SOURCE_KEY;
		pvalue = common_util_calculate_folder_sourcekey(
								pctx->pstore, parent_fid);
		if (pvalue == nullptr)
			return FALSE;
		pproplist->ppropval[pproplist->count++].pvalue = pvalue;

		pproplist->ppropval[pproplist->count].proptag = PR_PARENT_ENTRYID;
		pvalue = common_util_to_folder_entryid(
						pctx->pstore, parent_fid);
		if (pvalue == nullptr)
			return FALSE;
		pproplist->ppropval[pproplist->count++].pvalue = pvalue;
	}
	pproplist->ppropval[pproplist->count].proptag = PR_DISPLAY_NAME;
	pvalue = tmp_propvals.getval(PR_DISPLAY_NAME);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count++].pvalue = pvalue;
	}
	pproplist->ppropval[pproplist->count].proptag = PR_CONTAINER_CLASS;
	pvalue = tmp_propvals.getval(PR_CONTAINER_CLASS);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count++].pvalue = pvalue;
	}
	pproplist->ppropval[pproplist->count].proptag = PR_ATTR_HIDDEN;
	pvalue = tmp_propvals.getval(PR_ATTR_HIDDEN);
	pproplist->ppropval[pproplist->count++].pvalue =
		pvalue != nullptr ? pvalue : deconst(&fake_false);

	pproplist->ppropval[pproplist->count].proptag = PR_EXTENDED_FOLDER_FLAGS;
	pvalue = tmp_propvals.getval(PR_EXTENDED_FOLDER_FLAGS);
	if (NULL != pvalue) {
		pproplist->ppropval[pproplist->count++].pvalue = pvalue;
	}
	*pb_found = TRUE;
	if (!pctx->pstate->pgiven->append(fid) ||
	    !pctx->pstate->pseen->append(change_num))
		return FALSE;
	return TRUE;
}

BOOL icsdownctx_object::sync_deletions(uint32_t flags, BINARY_ARRAY *pbins)
{
	auto pctx = this;
	
	if (0 == (flags & SYNC_SOFT_DELETE)) {
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
			            common_util_calculate_message_sourcekey(pctx->pstore, pctx->pdeleted_eids->pids[i]) :
			            common_util_calculate_folder_sourcekey(pctx->pstore, pctx->pdeleted_eids->pids[i]);
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
		auto pbin = common_util_calculate_message_sourcekey(
		            pctx->pstore, pctx->pnolonger_messages->pids[i]);
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
	BINARY *pbin;
	
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return FALSE;
	if (NULL == pctx->pread_messags ||
		NULL == pctx->punread_messags) {
		pstates->count = 0;
		pstates->pstate = NULL;
		return TRUE;
	}
	pstates->count = pctx->pread_messags->count
				+ pctx->punread_messags->count;
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
		for (size_t i = 0; i < pctx->pread_messags->count; ++i) {
			pbin = common_util_calculate_message_sourcekey(
				pctx->pstore, pctx->pread_messags->pids[i]);
			if (pbin == nullptr)
				return FALSE;
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count++].message_flags = MSGFLAG_READ;
		}
		for (size_t i = 0; i < pctx->punread_messags->count; ++i) {
			pbin = common_util_calculate_message_sourcekey(
				pctx->pstore, pctx->punread_messags->pids[i]);
			if (pbin == nullptr)
				return FALSE;
			pstates->pstate[pstates->count].source_key = *pbin;
			pstates->pstate[pstates->count++].message_flags = 0;
		}
	}
	eid_array_free(pctx->pread_messags);
	pctx->pread_messags = NULL;
	eid_array_free(pctx->punread_messags);
	pctx->punread_messags = NULL;
	pctx->pstate->pread->clear();
	if (0 != pctx->last_readcn) {
		if (!pctx->pstate->pread->append_range(1, 1,
		    rop_util_get_gc_value(pctx->last_readcn)))
			return FALSE;
		pctx->last_readcn = 0;
	}
	return TRUE;
}
