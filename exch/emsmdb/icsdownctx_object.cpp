// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <string_view>
#include <utility>
#include <gromox/eid_array.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/proc_common.h>
#include <gromox/proptag_array.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "ftstream_producer.h"
#include "ics_state.h"
#include "icsdownctx_object.h"
#include "logon_object.h"

using namespace gromox;
using LLU = unsigned long long;

#define MAX_PARTIAL_ON_ROP		100	/* for limit of memory accumulation */

bool ics_flow_list::record_node(ics_flow_func func_id, uint64_t param) try
{
	emplace_back(func_id, param);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1598: ENOMEM");
	return false;
}

bool ics_flow_list::record_node(ics_flow_func func_id, const void *param)
{
	static_assert(sizeof(void *) <= sizeof(uint64_t));
	return record_node(func_id, reinterpret_cast<uintptr_t>(param));
}

std::unique_ptr<icsdownctx_object> icsdownctx_object::create(logon_object *plogon,
    folder_object *pfolder, uint8_t sync_type, uint8_t send_options,
	uint16_t sync_flags, const RESTRICTION *prestriction,
	uint32_t extra_flags, const PROPTAG_ARRAY *pproptags)
{
	int state_type = sync_type == SYNC_TYPE_CONTENTS ? ICS_STATE_CONTENTS_DOWN : ICS_STATE_HIERARCHY_DOWN;
	std::unique_ptr<icsdownctx_object> pctx;
	try {
		pctx.reset(new icsdownctx_object);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1454: ENOMEM");
		return NULL;
	}
	pctx->pstate = ics_state::create(plogon, state_type);
	if (pctx->pstate == nullptr)
		return NULL;
	pctx->pfolder = pfolder;
	pctx->sync_type = sync_type;
	pctx->send_options = send_options;
	pctx->sync_flags = sync_flags;
	pctx->extra_flags = extra_flags;
	pctx->pproptags = proptag_array_dup(pproptags);
	if (pctx->pproptags == nullptr)
		return NULL;
	/* OL produces PR_BODY from PR_PREVIEW if the former is missing, which is meh. */
	if (!proptag_array_append(pctx->pproptags, PR_PREVIEW))
		return nullptr;
	if (NULL != prestriction) {
		pctx->prestriction = restriction_dup(prestriction);
		if (pctx->prestriction == nullptr)
			return NULL;
	}
	pctx->pstream = ftstream_producer::create(plogon, send_options & 0x0F);
	if (pctx->pstream == nullptr)
		return NULL;
	return pctx;
}

static BOOL icsdownctx_object_make_content(icsdownctx_object *pctx)
{
	uint32_t count_fai;
	uint64_t total_fai;
	uint64_t total_normal;
	uint32_t count_normal;
	EID_ARRAY chg_messages, read_messages, given_messages, unread_messages;
	EID_ARRAY updated_messages, deleted_messages, nolonger_messages;
	
	if (pctx->sync_type != SYNC_TYPE_CONTENTS)
		return FALSE;
	if (pctx->sync_flags & SYNC_PROGRESS_MODE) {
		pctx->pprogtotal = gromox::me_alloc<PROGRESS_INFORMATION>();
		if (pctx->pprogtotal == nullptr)
			return FALSE;
	}
	auto pread     = (pctx->sync_flags & SYNC_READ_STATE) ? pctx->pstate->pread.get() : nullptr;
	auto pseen_fai = (pctx->sync_flags & SYNC_ASSOCIATED) ? pctx->pstate->pseen_fai.get() : nullptr;
	auto pseen     = (pctx->sync_flags & SYNC_NORMAL) ? pctx->pstate->pseen.get() : nullptr;
	BOOL b_ordered = (pctx->extra_flags & SYNC_EXTRA_FLAG_ORDERBYDELIVERYTIME) ? TRUE : false;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::get_content_sync(pctx->pstream->plogon->get_dir(),
	    pctx->pfolder->folder_id, pctx->pstream->plogon->readstate_user(),
	    pctx->pstate->pgiven.get(), pseen, pseen_fai, pread,
	    pinfo->cpid, pctx->prestriction, b_ordered,
	    &count_fai, &total_fai, &count_normal, &total_normal,
	    &updated_messages, &chg_messages, &pctx->last_changenum,
	    &given_messages, &deleted_messages, &nolonger_messages,
	    &read_messages, &unread_messages, &pctx->last_readcn))
		return FALSE;
	
	pctx->pstate->pgiven->clear();
	for (auto mid : given_messages)
		if (!pctx->pstate->pgiven->append(mid))
			return FALSE;	
	if (pctx->sync_flags & (SYNC_ASSOCIATED | SYNC_NORMAL)) {
		pctx->pmessages = eid_array_dup(&chg_messages);
		if (pctx->pmessages == nullptr)
			return FALSE;
	}
	if (pctx->sync_flags & SYNC_PROGRESS_MODE) {
		pctx->pprogtotal->version = 0;
		pctx->pprogtotal->padding1 = 0;
		pctx->pprogtotal->fai_count = count_fai;
		pctx->pprogtotal->fai_size = total_fai;
		pctx->pprogtotal->normal_count = count_normal;
		pctx->pprogtotal->padding2 = 0;
		pctx->pprogtotal->normal_size = total_normal;
	}
	if (!(pctx->sync_flags & SYNC_NO_DELETIONS)) {
		pctx->pdeleted_messages = eid_array_dup(&deleted_messages);
		if (pctx->pdeleted_messages == nullptr)
			return FALSE;
		pctx->pnolonger_messages = eid_array_dup(&nolonger_messages);
		if (pctx->pnolonger_messages == nullptr)
			return FALSE;
	}
	if (pctx->sync_flags & SYNC_READ_STATE) {
		pctx->pread_messages = eid_array_dup(&read_messages);
		if (pctx->pread_messages == nullptr)
			return FALSE;
		pctx->punread_messages = eid_array_dup(&unread_messages);
		if (pctx->punread_messages == nullptr)
			return FALSE;
	}
	if (pctx->sync_flags & SYNC_PROGRESS_MODE &&
	    !pctx->flow_list.record_node(ics_flow_func::progress))
		return FALSE;
	if (pctx->sync_flags & (SYNC_ASSOCIATED | SYNC_NORMAL)) {
		for (uint64_t i_mid : *pctx->pmessages) {
			size_t j;
			for (j = 0; j < updated_messages.count; ++j)
				if (updated_messages.pids[j] == i_mid)
					break;
			if (!pctx->flow_list.record_node(j < updated_messages.count ?
			    ics_flow_func::upd_msg_id : ics_flow_func::new_msg_id,
			    i_mid))
				return FALSE;	
		}
	}
	if (!(pctx->sync_flags & SYNC_NO_DELETIONS) &&
	    !pctx->flow_list.record_node(ics_flow_func::deletions))
		return FALSE;
	if (pctx->sync_flags & SYNC_READ_STATE &&
	    !pctx->flow_list.record_node(ics_flow_func::read_state_chg))
		return FALSE;
	if (!pctx->flow_list.record_node(ics_flow_func::state) ||
	    !pctx->flow_list.record_tag(INCRSYNCEND))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->next_progress_steps = 0;
	pctx->total_steps = total_normal + total_fai;
	pctx->divisor = fx_divisor(pctx->total_steps);
	return TRUE;
}

static void icsdownctx_object_adjust_fldchgs(FOLDER_CHANGES *pfldchgs,
    const PROPTAG_ARRAY *pproptags, bool b_exclude)
{
	if (b_exclude) {
		for (auto &chg : *pfldchgs)
			for (size_t j = 0; j < pproptags->count; ++j)
				common_util_remove_propvals(&chg, pproptags->pproptag[j]);
		return;
	}
	for (auto &chg : *pfldchgs) {
		size_t j = 0;
		while (j < chg.count) {
			if (!pproptags->has(chg.ppropval[j].proptag))
				common_util_remove_propvals(&chg, chg.ppropval[j].proptag);
			else
				j++;
		}
	}
}

static BOOL icsdownctx_object_make_hierarchy(icsdownctx_object *pctx)
{
	BINARY *pbin = nullptr;
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	char temp_buff[1024];
	FOLDER_CHANGES fldchgs;
	EID_ARRAY given_folders;
	uint64_t last_changenum;
	EID_ARRAY deleted_folders;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_proplist;
	static constexpr uint8_t fake_byte = 0;
	PERSISTDATA_ARRAY persistdatas;
	TPROPVAL_ARRAY *pproplist_deletions;
	
	if (pctx->sync_type != SYNC_TYPE_HIERARCHY)
		return FALSE;
	auto dir = pctx->pstream->plogon->get_dir();
	if (!exmdb_client::get_hierarchy_sync(dir,
	    pctx->pfolder->folder_id, pctx->pstream->plogon->eff_user(),
	    pctx->pstate->pgiven.get(),
	    pctx->pstate->pseen.get(), &fldchgs, &last_changenum, &given_folders,
	    &deleted_folders))
		return FALSE;
	pctx->pstate->pgiven->clear();
	for (auto fid : given_folders)
		if (!pctx->pstate->pgiven->append(fid))
			return FALSE;	
	for (auto &chg : fldchgs) {
		static constexpr uint32_t tags[] = {
			PR_FOLDER_PATHNAME, PR_NORMAL_MESSAGE_SIZE,
			PR_NORMAL_MESSAGE_SIZE_EXTENDED, PR_MESSAGE_SIZE_EXTENDED,
			PR_ASSOC_MESSAGE_SIZE, PR_ASSOC_MESSAGE_SIZE_EXTENDED,
			PR_FOLDER_CHILD_COUNT, PR_DELETED_FOLDER_COUNT,
			PR_INTERNET_ARTICLE_NUMBER_NEXT, PR_FOLDER_FLAGS,
		};
		for (auto t : tags)
			common_util_remove_propvals(&chg, t);
		for (size_t j = 0; j < chg.count; ) {
			if (PROP_ID(chg.ppropval[j].proptag) >= 0x8000)
				/* emsmdb32.dll stinks */
				common_util_remove_propvals(&chg, chg.ppropval[j].proptag);
			else
				++j;
		}
		if (!chg.has(PR_ATTR_HIDDEN))
			cu_set_propval(&chg, PR_ATTR_HIDDEN, &fake_byte);
		if (!chg.has(PR_ATTR_SYSTEM))
			cu_set_propval(&chg, PR_ATTR_SYSTEM, &fake_byte);
		if (!chg.has(PR_ATTR_READONLY))
			cu_set_propval(&chg, PR_ATTR_READONLY, &fake_byte);
		if (!chg.has(PR_CREATOR_SID)) {
			tmp_bin.cb = 0;
			tmp_bin.pb = NULL;
			cu_set_propval(&chg, PR_CREATOR_SID, &tmp_bin);
		}
		auto lnum = chg.get<const uint64_t>(PidTagFolderId);
		if (lnum == nullptr)
			return FALSE;
		auto folder_id = *lnum;
		if (!(pctx->extra_flags & SYNC_EXTRA_FLAG_EID))
			common_util_remove_propvals(&chg, PidTagFolderId);
		lnum = chg.get<uint64_t>(PidTagParentFolderId);
		if (lnum == nullptr)
			return FALSE;
		auto parent_fid = *lnum;
		if (pctx->sync_flags & SYNC_NO_FOREIGN_KEYS) {
			common_util_remove_propvals(&chg, PR_SOURCE_KEY);
			auto psk = cu_fid_to_sk(pctx->pstream->plogon, folder_id);
			if (psk == nullptr)
				return FALSE;
			cu_set_propval(&chg, PR_SOURCE_KEY, psk);
			if (pctx->pfolder->folder_id == parent_fid) {
				tmp_bin.cb = 0;
				tmp_bin.pb = NULL;
				psk = &tmp_bin;
			} else {
				psk = cu_fid_to_sk(pctx->pstream->plogon, parent_fid);
				if (psk == nullptr)
					return FALSE;
			}
			cu_set_propval(&chg, PR_PARENT_SOURCE_KEY, psk);
		} else {
			if (!chg.has(PR_SOURCE_KEY)) {
				auto psk = cu_fid_to_sk(pctx->pstream->plogon, folder_id);
				if (psk == nullptr)
					return FALSE;
				cu_set_propval(&chg, PR_SOURCE_KEY, psk);
			}
			void *psk;
			if (pctx->pfolder->folder_id == parent_fid) {
				tmp_bin.cb = 0;
				tmp_bin.pb = NULL;
				psk = &tmp_bin;
			} else {
				if (!exmdb_client::get_folder_property(dir,
				    CP_ACP, parent_fid, PR_SOURCE_KEY, &psk))
					return FALSE;	
				if (psk == nullptr) {
					psk = cu_fid_to_sk(pctx->pstream->plogon, parent_fid);
					if (psk == nullptr)
						return FALSE;
				}
			}
			cu_set_propval(&chg, PR_PARENT_SOURCE_KEY, psk);
		}
		auto inboxy = pctx->pstream->plogon->is_private() &&
		              (folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) ||
		              folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_INBOX));
		if (!inboxy)
			continue;
		auto ppropval = cu_alloc<TAGGED_PROPVAL>(chg.count + 10);
		if (ppropval == nullptr)
			return FALSE;
		memcpy(ppropval, chg.ppropval, sizeof(TAGGED_PROPVAL) * chg.count);
		chg.ppropval = ppropval;
		auto pvalue = cu_fid_to_entryid(pctx->pstream->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_DRAFT));
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&chg, PR_IPM_DRAFTS_ENTRYID, pvalue);
		pvalue = cu_fid_to_entryid(pctx->pstream->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS));
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&chg, PR_IPM_CONTACT_ENTRYID, pvalue);
		pvalue = cu_fid_to_entryid(pctx->pstream->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR));
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&chg, PR_IPM_APPOINTMENT_ENTRYID, pvalue);
		pvalue = cu_fid_to_entryid(pctx->pstream->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_JOURNAL));
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&chg, PR_IPM_JOURNAL_ENTRYID, pvalue);
		pvalue = cu_fid_to_entryid(pctx->pstream->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_NOTES));
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&chg, PR_IPM_NOTE_ENTRYID, pvalue);
		pvalue = cu_fid_to_entryid(pctx->pstream->plogon, rop_util_make_eid_ex(1, PRIVATE_FID_TASKS));
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&chg, PR_IPM_TASK_ENTRYID, pvalue);
		if (!chg.has(PR_ADDITIONAL_REN_ENTRYIDS)) {
			auto ba = cu_alloc<BINARY_ARRAY>();
			if (ba == nullptr)
				return FALSE;
			ba->count = 5;
			ba->pbin = cu_alloc<BINARY>(ba->count);
			if (ba->pbin == nullptr)
				return FALSE;
			pbin = cu_fid_to_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
			if (pbin == nullptr)
				return FALSE;
			ba->pbin[0] = *pbin;
			pbin = cu_fid_to_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
			if (pbin == nullptr)
				return FALSE;
			ba->pbin[1] = *pbin;
			pbin = cu_fid_to_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
			if (pbin == nullptr)
				return FALSE;
			ba->pbin[2] = *pbin;
			pbin = cu_fid_to_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
			if (pbin == nullptr)
				return FALSE;
			ba->pbin[3] = *pbin;
			pbin = cu_fid_to_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
			if (pbin == nullptr)
				return FALSE;
			ba->pbin[4] = *pbin;
			cu_set_propval(&chg, PR_ADDITIONAL_REN_ENTRYIDS, ba);
		}
		if (!chg.has(PR_ADDITIONAL_REN_ENTRYIDS_EX)) {
			auto bv = cu_alloc<BINARY>();
			if (bv == nullptr)
				return FALSE;
			persistdatas.count = 3;
			persistdatas.ppitems = cu_alloc<PERSISTDATA *>(persistdatas.count);
			if (persistdatas.ppitems == nullptr)
				return FALSE;
			auto ppersistdata = cu_alloc<PERSISTDATA>(persistdatas.count);
			if (ppersistdata == nullptr)
				return FALSE;
			persistdatas.ppitems[0] = ppersistdata;
			persistdatas.ppitems[0]->persist_id = RSF_PID_CONV_ACTIONS;
			persistdatas.ppitems[0]->element.element_id = RSF_ELID_ENTRYID;
			persistdatas.ppitems[0]->element.pentry_id =
				cu_fid_to_entryid(pctx->pstream->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS));
			persistdatas.ppitems[1] = ppersistdata + 1;
			persistdatas.ppitems[1]->persist_id = RSF_PID_BUDDYLIST_PDLS;
			persistdatas.ppitems[1]->element.element_id = RSF_ELID_ENTRYID;
			persistdatas.ppitems[1]->element.pentry_id =
				cu_fid_to_entryid(pctx->pstream->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST));
			persistdatas.ppitems[2] = ppersistdata + 2;
			persistdatas.ppitems[2]->persist_id = RSF_PID_BUDDYLIST_CONTACTS;
			persistdatas.ppitems[2]->element.element_id = RSF_ELID_ENTRYID;
			persistdatas.ppitems[2]->element.pentry_id =
				cu_fid_to_entryid(pctx->pstream->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_QUICKCONTACTS));
			if (!ext_push.init(temp_buff, sizeof(temp_buff), 0) ||
			    ext_push.p_persistdata_a(persistdatas) != EXT_ERR_SUCCESS)
				return false;
			bv->cb = ext_push.m_offset;
			bv->pv = common_util_alloc(bv->cb);
			if (bv->pv == nullptr)
				return FALSE;
			memcpy(bv->pv, ext_push.m_udata, bv->cb);
			cu_set_propval(&chg, PR_ADDITIONAL_REN_ENTRYIDS_EX, bv);
		}
		if (!chg.has(PR_FREEBUSY_ENTRYIDS)) {
			auto ba = cu_alloc<BINARY_ARRAY>();
			if (ba == nullptr)
				return FALSE;
			ba->count = 4;
			ba->pbin = cu_alloc<BINARY>(ba->count);
			if (ba->pbin == nullptr)
				return FALSE;
			ba->pbin[0].cb = 0;
			ba->pbin[0].pb = nullptr;
			ba->pbin[1].cb = 0;
			ba->pbin[1].pb = nullptr;
			ba->pbin[2].cb = 0;
			ba->pbin[2].pb = nullptr;
			pbin = cu_fid_to_entryid(pctx->pstream->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
			if (pbin == nullptr)
				return FALSE;
			ba->pbin[3] = *pbin;
			cu_set_propval(&chg, PR_FREEBUSY_ENTRYIDS, ba);
		}
	}
	icsdownctx_object_adjust_fldchgs(&fldchgs, pctx->pproptags,
		!(pctx->sync_flags & SYNC_ONLY_SPECIFIED_PROPS));
	if ((pctx->sync_flags & SYNC_NO_DELETIONS) || deleted_folders.count == 0) {
		pproplist_deletions = NULL;
	} else {
		idset xset(true, REPL_TYPE_ID);
		for (auto fid : deleted_folders)
			if (!xset.append(fid))
				return FALSE;
		pbin = xset.serialize();
		if (pbin == nullptr)
			return false;
		pproplist_deletions = &tmp_proplist;
		pproplist_deletions->count = 1;
		pproplist_deletions->ppropval = &tmp_propval;
		tmp_propval.proptag = MetaTagIdsetDeleted;
		tmp_propval.pvalue = pbin;
	}
	if (0 != last_changenum) {
		pctx->pstate->pseen->clear();
		if (!pctx->pstate->pseen->append_range(1, 1,
			rop_util_get_gc_value(last_changenum))) {
			if (pproplist_deletions != nullptr)
				rop_util_free_binary(pbin);
			return FALSE;
		}
	}
	auto pproplist_state = pctx->pstate->serialize();
	if (NULL == pproplist_state) {
		if (pproplist_deletions != nullptr)
			rop_util_free_binary(pbin);
		return FALSE;
	}
	if (!pctx->pstream->write_hierarchysync(&fldchgs,
	    pproplist_deletions, pproplist_state)) {
		tpropval_array_free(pproplist_state);
		if (pproplist_deletions != nullptr)
			rop_util_free_binary(pbin);
		return FALSE;	
	}
	tpropval_array_free(pproplist_state);
	if (pproplist_deletions != nullptr)
		rop_util_free_binary(pbin);
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	pctx->divisor = fx_divisor(pctx->total_steps);
	return TRUE;
}

BOOL icsdownctx_object::make_sync()
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (SYNC_TYPE_CONTENTS == pctx->sync_type) {
		if (!icsdownctx_object_make_content(pctx))
			return FALSE;
	} else {
		if (!icsdownctx_object_make_hierarchy(pctx))
			return FALSE;
	}
	pctx->b_started = TRUE;
	return TRUE;
}

static BOOL icsdownctx_object_extract_msgctntinfo(MESSAGE_CONTENT *pmsgctnt,
    uint8_t extra_flags, uint64_t message_id, TPROPVAL_ARRAY *pchgheader,
    PROGRESS_MESSAGE *pprogmsg)
{
	pchgheader->ppropval = cu_alloc<TAGGED_PROPVAL>(8);
	if (pchgheader->ppropval == nullptr)
		return FALSE;
	pchgheader->count = 0;
	auto bin = pmsgctnt->proplist.get<const BINARY>(PR_SOURCE_KEY);
	if (bin == nullptr)
		return FALSE;
	pchgheader->emplace_back(PR_SOURCE_KEY, bin);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_SOURCE_KEY);
	
	auto ts = pmsgctnt->proplist.get<const uint64_t>(PR_LAST_MODIFICATION_TIME);
	uint64_t now = rop_util_unix_to_nttime(time(nullptr));
	if (ts == nullptr)
		/* Faking it seems to work */
		ts = &now;
	pchgheader->emplace_back(PR_LAST_MODIFICATION_TIME, ts);
	
	bin = pmsgctnt->proplist.get<BINARY>(PR_CHANGE_KEY);
	if (bin == nullptr) {
		mlog(LV_INFO, "I-2362: ICS: cannot transfer msg %llxh without PR_CHANGE_KEY\n",
			LLU{message_id});
		return FALSE;
	}
	pchgheader->emplace_back(PR_CHANGE_KEY, bin);
	
	bin = pmsgctnt->proplist.get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	if (bin == nullptr)
		return FALSE;
	pchgheader->emplace_back(PR_PREDECESSOR_CHANGE_LIST, bin);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_PREDECESSOR_CHANGE_LIST);
	
	auto flag = pmsgctnt->proplist.get<const uint8_t>(PR_ASSOCIATED);
	if (flag == nullptr)
		return FALSE;
	pprogmsg->b_fai = flag != nullptr && *flag != 0 ? TRUE : false;
	pchgheader->emplace_back(PR_ASSOCIATED, flag);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_ASSOCIATED);
	
	if (SYNC_EXTRA_FLAG_EID & extra_flags) {
		auto lnum = pmsgctnt->proplist.get<const uint64_t>(PidTagMid);
		if (lnum == nullptr)
			return FALSE;
		pchgheader->emplace_back(PidTagMid, lnum);
	}
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagMid);
	
	auto num = pmsgctnt->proplist.get<const uint32_t>(PR_MESSAGE_SIZE);
	if (num == nullptr)
		return FALSE;
	pprogmsg->message_size = *num;
	if (extra_flags & SYNC_EXTRA_FLAG_MESSAGESIZE)
		pchgheader->emplace_back(PR_MESSAGE_SIZE, num);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_MESSAGE_SIZE);
	
	if (SYNC_EXTRA_FLAG_CN & extra_flags) {
		auto cn = pmsgctnt->proplist.get<const eid_t>(PidTagChangeNumber);
		if (cn == nullptr)
			return FALSE;
		pchgheader->emplace_back(PidTagChangeNumber, cn);
	}
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagChangeNumber);
	return TRUE;
}

static void icsdownctx_object_adjust_msgctnt(MESSAGE_CONTENT *pmsgctnt,
    const PROPTAG_ARRAY *pproptags, bool b_exclude)
{
	if (b_exclude) {
		for (unsigned int i = 0; i < pproptags->count; ++i) {
			const auto tag = pproptags->pproptag[i];
			switch (tag) {
			case PR_MESSAGE_RECIPIENTS:
				pmsgctnt->children.prcpts = NULL;
				break;
			case PR_MESSAGE_ATTACHMENTS:
				pmsgctnt->children.pattachments = NULL;
				break;
			default:
				common_util_remove_propvals(&pmsgctnt->proplist, tag);
				break;
			}
		}
		return;
	}
	for (unsigned int i = 0; i < pmsgctnt->proplist.count; ) {
		if (!pproptags->has(pmsgctnt->proplist.ppropval[i].proptag))
			common_util_remove_propvals(&pmsgctnt->proplist,
				pmsgctnt->proplist.ppropval[i].proptag);
		else
			i++;
	}
	if (!pproptags->has(PR_MESSAGE_RECIPIENTS))
		pmsgctnt->children.prcpts = NULL;
	if (!pproptags->has(PR_MESSAGE_ATTACHMENTS))
		pmsgctnt->children.pattachments = NULL;
}

static const property_groupinfo fake_gpinfo = {UINT32_MAX};

static BOOL icsdownctx_object_get_changepartial(icsdownctx_object *pctx,
    MESSAGE_CONTENT *pmsgctnt, uint32_t group_id, const INDEX_ARRAY *pindices,
	const PROPTAG_ARRAY *pproptags, MSGCHG_PARTIAL *pmsg)
{
	int i;
	uint32_t index;
	PROPTAG_ARRAY *pchangetags;
	static constexpr BINARY fake_bin{};
	
	auto pgpinfo = pctx->pstream->plogon->get_property_groupinfo(group_id);
	if (pgpinfo == nullptr)
		return FALSE;
	auto b_written = std::find(pctx->group_list.cbegin(), pctx->group_list.cend(), group_id) !=
	                 pctx->group_list.cend();
	pmsg->group_id = group_id;
	if (b_written) {
		pmsg->pgpinfo = &fake_gpinfo;
	} else {
		pmsg->pgpinfo = pgpinfo;
		try {
			pctx->group_list.push_back(group_id);
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1597: ENOMEM");
			return false;
		}
	}
	pmsg->count = pindices->count;
	if (pproptags->count != 0)
		++pmsg->count;
	pmsg->pchanges = cu_alloc<CHANGE_PART>(pmsg->count);
	if (NULL == pmsg->pchanges) {
		pmsg->count = 0;
		return FALSE;
	}
	for (i=0; i<pindices->count; i++) {
		index = pindices->pproptag[i];
		pmsg->pchanges[i].index = index;
		pchangetags = pgpinfo->pgroups + index;
		auto &pl = pmsg->pchanges[i].proplist;
		pl.ppropval = cu_alloc<TAGGED_PROPVAL>(pchangetags->count);
		unsigned int count = 0;
		for (unsigned int j = 0; j < pchangetags->count; ++j) {
			const auto proptag = pchangetags->pproptag[j];
			switch (proptag) {
			case PR_MESSAGE_RECIPIENTS:
				pl.ppropval[count].proptag = PR_MESSAGE_RECIPIENTS;
				pl.ppropval[count++].pvalue = deconst(&fake_bin);
				pmsg->children.prcpts = pmsgctnt->children.prcpts;
				break;
			case PR_MESSAGE_ATTACHMENTS:
				pl.ppropval[count].proptag = PR_MESSAGE_ATTACHMENTS;
				pl.ppropval[count++].pvalue = deconst(&fake_bin);
				pmsg->children.pattachments =
					pmsgctnt->children.pattachments;
				break;
			default: {
				auto pvalue = pmsgctnt->proplist.getval(proptag);
				if (NULL != pvalue) {
					pl.ppropval[count].proptag = proptag;
					pl.ppropval[count++].pvalue = pvalue;
				}
				break;
			}
			}
		}
		pl.count = count;
	}
	if (pproptags->count == 0)
		return TRUE;
	auto &pl = pmsg->pchanges[i].proplist;
	pmsg->pchanges[i].index = UINT32_MAX;
	pl.ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	unsigned int count = 0;
	for (unsigned int j = 0; j < pproptags->count; ++j) {
		const auto proptag = pproptags->pproptag[j];
		switch (proptag) {
		case PR_MESSAGE_RECIPIENTS:
			pl.ppropval[count].proptag = PR_MESSAGE_RECIPIENTS;
			pl.ppropval[count++].pvalue = deconst(&fake_bin);
			pmsg->children.prcpts = pmsgctnt->children.prcpts;
			break;
		case PR_MESSAGE_ATTACHMENTS:
			pl.ppropval[count].proptag = PR_MESSAGE_ATTACHMENTS;
			pl.ppropval[count++].pvalue = deconst(&fake_bin);
			pmsg->children.pattachments =
				pmsgctnt->children.pattachments;
			break;
		default: {
			auto pvalue = pmsgctnt->proplist.getval(proptag);
			if (pvalue == nullptr)
				break;
			pl.ppropval[count].proptag = proptag;
			pl.ppropval[count++].pvalue = pvalue;
			break;
		}
		}
	}
	pl.count = count;
	return TRUE;
}

static void icsdownctx_object_trim_embedded(
	MESSAGE_CONTENT *pmsgctnt)
{
	if (pmsgctnt->children.pattachments == nullptr)
		return;
	for (auto &at : *pmsgctnt->children.pattachments) {
		auto pembedded = at.pembedded;
		if (pembedded == nullptr)
			continue;
		for (unsigned int j = 0; j < pembedded->proplist.count; ++j) {
			if (pembedded->proplist.ppropval[j].proptag == PidTagMid) {
				*static_cast<uint64_t *>(pembedded->proplist.ppropval[j].pvalue) = 0;
				break;
			}
		}
		common_util_remove_propvals(&pembedded->proplist, PidTagChangeNumber);
		common_util_remove_propvals(&pembedded->proplist, PR_MSG_STATUS);
		icsdownctx_object_trim_embedded(pembedded);
	}
}

/* Outlook 2016 does not accept recipients
	of report messages, get rid of them */
static void icsdownctx_object_trim_report_recipients(
	MESSAGE_CONTENT *pmsgctnt)
{
	auto pvalue = pmsgctnt->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (pvalue != nullptr && strncasecmp(pvalue, "REPORT.IPM.Note.", 16) == 0)
		pmsgctnt->children.prcpts = NULL;
	if (pmsgctnt->children.pattachments == nullptr)
		return;
	for (auto &at : *pmsgctnt->children.pattachments)
		if (at.pembedded != nullptr)
			icsdownctx_object_trim_report_recipients(at.pembedded);
}

static BOOL icsdownctx_object_write_message_change(icsdownctx_object *pctx,
	uint64_t message_id, BOOL b_downloaded, int *ppartial_count)
{
	BOOL b_full;
	void *pvalue;
	uint64_t last_cn;
	INDEX_ARRAY indices;
	uint32_t *pgroup_id;
	PROPTAG_ARRAY proptags;
	PROGRESS_MESSAGE progmsg;
	TPROPVAL_ARRAY chgheader;
	MESSAGE_CONTENT *pmsgctnt;
	MSGCHG_PARTIAL msg_partial;
	static constexpr uint8_t fake_true = 1;
	static constexpr uint8_t fake_false = 0;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto dir = pctx->pstream->plogon->get_dir();
	if (!exmdb_client::read_message(dir, pctx->pstream->plogon->readstate_user(),
	    pinfo->cpid, message_id, &pmsgctnt))
		return FALSE;
	if (NULL == pmsgctnt) {
		pctx->pstate->pgiven->remove(message_id);
		if (b_downloaded) {
			if (!(pctx->sync_flags & SYNC_NO_DELETIONS) &&
			    !eid_array_append(pctx->pdeleted_messages, message_id))
				return FALSE;
			if (pctx->sync_flags & SYNC_READ_STATE) {
				eid_array_remove(pctx->pread_messages, message_id);
				eid_array_remove(pctx->punread_messages, message_id);
			}
		}
		return TRUE;
	}
	icsdownctx_object_trim_report_recipients(pmsgctnt);
	auto folder_id = pctx->pfolder->folder_id;
	auto pstatus = pmsgctnt->proplist.get<uint32_t>(PR_MSG_STATUS);
	if (pstatus == nullptr) {
		mlog(LV_INFO, "I-2384: ICS: cannot transfer msg %llxh without PR_MSG_STATUS", LLU{message_id});
		return FALSE;
	}
	if (*pstatus & MSGSTATUS_IN_CONFLICT) {
		if (!(pctx->sync_flags & SYNC_NO_FOREIGN_KEYS)) {
			if (!exmdb_client::get_folder_property(dir,
			    CP_ACP, folder_id, PR_SOURCE_KEY, &pvalue))
				return FALSE;	
			if (pvalue == nullptr)
				pvalue = cu_fid_to_sk(pctx->pstream->plogon, folder_id);
		} else {
			pvalue = cu_fid_to_sk(pctx->pstream->plogon, folder_id);
		}
		if (pvalue == nullptr)
			return FALSE;
		for (auto &at : *pmsgctnt->children.pattachments) {
			if (!at.proplist.has(PR_IN_CONFLICT))
				continue;
			auto pembedded = at.pembedded;
			if (pembedded == nullptr)
				return FALSE;
			icsdownctx_object_trim_embedded(pembedded);
			auto ppropval = cu_alloc<TAGGED_PROPVAL>(pembedded->proplist.count + 2);
			if (ppropval == nullptr)
				return FALSE;
			memcpy(ppropval, pembedded->proplist.ppropval,
				sizeof(TAGGED_PROPVAL)*pembedded->proplist.count);
			pembedded->proplist.ppropval = ppropval;
			cu_set_propval(&pembedded->proplist, PidTagMid, &message_id);
			cu_set_propval(&pembedded->proplist, PR_PARENT_SOURCE_KEY, pvalue);
			if (!pembedded->proplist.has(PR_SOURCE_KEY)) {
				auto psk = cu_mid_to_sk(pctx->pstream->plogon, message_id);
				if (psk == nullptr)
					return FALSE;
				cu_set_propval(&pembedded->proplist, PR_SOURCE_KEY, psk);
			}
			if (!icsdownctx_object_extract_msgctntinfo(pembedded,
			    pctx->extra_flags, message_id, &chgheader, &progmsg))
				return FALSE;
			icsdownctx_object_adjust_msgctnt(pembedded, pctx->pproptags,
				!(pctx->sync_flags & SYNC_ONLY_SPECIFIED_PROPS));
			if (pctx->sync_flags & SYNC_PROGRESS_MODE &&
			    !pctx->pstream->write_progresspermessage(&progmsg))
				return FALSE;
			common_util_remove_propvals(&pembedded->proplist, PR_READ);
			common_util_remove_propvals(&pembedded->proplist, PR_CHANGE_KEY);
			common_util_remove_propvals(&pembedded->proplist, PR_MSG_STATUS);
			auto flags = pembedded->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
			auto xbit = flags != nullptr && (*flags & MSGFLAG_RN_PENDING) ?
			                     deconst(&fake_true) : deconst(&fake_false);
			cu_set_propval(&pembedded->proplist, PR_READ_RECEIPT_REQUESTED, xbit);
			xbit = flags != nullptr && (*flags & MSGFLAG_NRN_PENDING) ?
			                     deconst(&fake_true) : deconst(&fake_false);
			cu_set_propval(&pembedded->proplist, PR_NON_RECEIPT_NOTIFICATION_REQUESTED, xbit);
			fxs_propsort(*pembedded);
			if (!pctx->pstream->write_messagechangefull(&chgheader, pembedded))
				return FALSE;
		}
		return TRUE;
	}
	icsdownctx_object_trim_embedded(pmsgctnt);
	auto ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 10);
	if (ppropval == nullptr)
		return FALSE;
	memcpy(ppropval, pmsgctnt->proplist.ppropval,
		sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
	pmsgctnt->proplist.ppropval = ppropval;
	if (!(pctx->sync_flags & SYNC_NO_FOREIGN_KEYS)) {
		if (!exmdb_client::get_folder_property(dir,
		    CP_ACP, folder_id, PR_SOURCE_KEY, &pvalue))
			return FALSE;	
		if (NULL == pvalue) {
			pvalue = cu_fid_to_sk(pctx->pstream->plogon, folder_id);
			if (pvalue == nullptr)
				return FALSE;
		}
		cu_set_propval(&pmsgctnt->proplist, PR_PARENT_SOURCE_KEY, pvalue);
		if (!pmsgctnt->proplist.has(PR_SOURCE_KEY)) {
			pvalue = cu_mid_to_sk(pctx->pstream->plogon, message_id);
			if (pvalue == nullptr)
				return FALSE;
			cu_set_propval(&pmsgctnt->proplist, PR_SOURCE_KEY, pvalue);
		}
	} else {
		pvalue = cu_fid_to_sk(pctx->pstream->plogon, folder_id);
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&pmsgctnt->proplist, PR_PARENT_SOURCE_KEY, pvalue);
		pvalue = cu_mid_to_sk(pctx->pstream->plogon, message_id);
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&pmsgctnt->proplist, PR_SOURCE_KEY, pvalue);
	}
	if (!icsdownctx_object_extract_msgctntinfo(pmsgctnt,
	    pctx->extra_flags, message_id, &chgheader, &progmsg))
		return FALSE;
	auto cond1 = !(pctx->sync_flags & SYNC_ONLY_SPECIFIED_PROPS);
	if (!(pctx->sync_flags & SYNC_IGNORE_SPECIFIED_ON_ASSOCIATED) ||
	    cond1 || !progmsg.b_fai)
		icsdownctx_object_adjust_msgctnt(pmsgctnt, pctx->pproptags, cond1);
	if (!b_downloaded || progmsg.b_fai) {
		b_full = TRUE;
	} else {
		/* Downloaded && Normal message */
		if (!exmdb_client::get_message_group_id(dir,
		    message_id, &pgroup_id))
			return FALSE;
		if (!(pctx->send_options & SEND_OPTIONS_PARTIAL) ||
		    pgroup_id == nullptr ||
		    *ppartial_count > MAX_PARTIAL_ON_ROP) {
			b_full = TRUE;
		} else {
			if (!pctx->pstate->pseen->get_repl_first_max(1, &last_cn))
				return false;
			if (!exmdb_client::get_change_indices(dir,
			    message_id, last_cn, &indices, &proptags))
				return FALSE;	
			if (0 == indices.count && 0 == proptags.count) {
				b_full = TRUE;
			} else {
				b_full = FALSE;
				(*ppartial_count) ++;
			}
		}
		if (!b_full && !icsdownctx_object_get_changepartial(pctx,
		    pmsgctnt, *pgroup_id, &indices, &proptags, &msg_partial))
			return FALSE;
	}
	if (pctx->sync_flags & SYNC_PROGRESS_MODE &&
	    !pctx->pstream->write_progresspermessage(&progmsg))
		return FALSE;
	pctx->next_progress_steps += progmsg.message_size;
	if (!b_full)
		return pctx->pstream->write_messagechangepartial(&chgheader, &msg_partial);

	common_util_remove_propvals(&pmsgctnt->proplist, PR_READ);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_CHANGE_KEY);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_MSG_STATUS);
	auto flags = pmsgctnt->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
	auto xbit = flags != nullptr && (*flags & MSGFLAG_RN_PENDING) ?
	            deconst(&fake_true) : deconst(&fake_false);
	cu_set_propval(&pmsgctnt->proplist, PR_READ_RECEIPT_REQUESTED, xbit);
	xbit = flags != nullptr && (*flags & MSGFLAG_NRN_PENDING) ?
	       deconst(&fake_true) : deconst(&fake_false);
	cu_set_propval(&pmsgctnt->proplist, PR_NON_RECEIPT_NOTIFICATION_REQUESTED, xbit);
	fxs_propsort(*pmsgctnt);
	return pctx->pstream->write_messagechangefull(&chgheader, pmsgctnt);
}

/* only be called under content sync */
static BOOL icsdownctx_object_write_deletions(icsdownctx_object *pctx)
{
	BINARY *pbin1;
	BINARY *pbin2;
	TPROPVAL_ARRAY proplist;
	TAGGED_PROPVAL tmp_propvals[2];
	
	proplist.count = 0;
	proplist.ppropval = tmp_propvals;
	pbin1 = NULL;
	pbin2 = NULL;
	if (pctx->pdeleted_messages->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (auto mid : *pctx->pdeleted_messages)
			if (!xset.append(mid))
				return FALSE;
		pbin1 = xset.serialize();
		if (pbin1 == nullptr)
			return FALSE;
		proplist.emplace_back(MetaTagIdsetDeleted, pbin1);
	}
	if (!(pctx->sync_flags & SYNC_NO_SOFT_DELETIONS) &&
	    pctx->pnolonger_messages->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (auto mid : *pctx->pnolonger_messages) {
			if (!xset.append(mid)) {
				if (pbin1 != nullptr)
					rop_util_free_binary(pbin1);
				return FALSE;
			}
		}
		pbin2 = xset.serialize();
		if (NULL == pbin2) {
			if (pbin1 != nullptr)
				rop_util_free_binary(pbin1);
			return FALSE;
		}
		proplist.emplace_back(MetaTagIdsetNoLongerInScope, pbin2);
	}
	if (proplist.count == 0)
		return TRUE;
	if (!pctx->pstream->write_deletions(&proplist)) {
		if (pbin1 != nullptr)
			rop_util_free_binary(pbin1);
		if (pbin2 != nullptr)
			rop_util_free_binary(pbin2);
		return FALSE;
	}
	if (pbin1 != nullptr)
		rop_util_free_binary(pbin1);
	if (pbin2 != nullptr)
		rop_util_free_binary(pbin2);
	return TRUE;
}

/* only be called under content sync */
static BOOL icsdownctx_object_write_readstate_changes(icsdownctx_object *pctx)
{
	BINARY *pbin1 = nullptr, *pbin2 = nullptr;
	auto cl_0 = gromox::make_scope_exit([&]() {
		if (pbin1 != nullptr)
			rop_util_free_binary(pbin1);
		if (pbin2 != nullptr)
			rop_util_free_binary(pbin2);
	});
	TPROPVAL_ARRAY proplist;
	TAGGED_PROPVAL tmp_propvals[2];
	
	proplist.count = 0;
	proplist.ppropval = tmp_propvals;
	if (pctx->pread_messages->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (auto mid : *pctx->pread_messages)
			if (!xset.append(mid))
				return FALSE;
		pbin1 = xset.serialize();
		if (pbin1 == nullptr)
			return FALSE;
		proplist.emplace_back(MetaTagIdsetRead, pbin1);
	}
	if (pctx->punread_messages->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (auto mid : *pctx->punread_messages)
			if (!xset.append(mid))
				return FALSE;
		pbin2 = xset.serialize();
		if (pbin2 == nullptr)
			return FALSE;
		proplist.emplace_back(MetaTagIdsetUnread, pbin2);
	}
	if (proplist.count == 0)
		return TRUE;
	if (!pctx->pstream->write_readstatechanges(&proplist))
		return FALSE;
	return TRUE;
}

/* only be called under content sync */
static BOOL icsdownctx_object_write_state(icsdownctx_object *pctx)
{
	pctx->pstate->pseen->clear();
	if (pctx->sync_flags & SYNC_NORMAL && pctx->last_changenum != 0 &&
	    !pctx->pstate->pseen->append_range(1, 1,
	    rop_util_get_gc_value(pctx->last_changenum)))
		return FALSE;
	pctx->pstate->pseen_fai->clear();
	if (pctx->sync_flags & SYNC_ASSOCIATED && pctx->last_changenum != 0 &&
	    !pctx->pstate->pseen_fai->append_range(1, 1,
	    rop_util_get_gc_value(pctx->last_changenum)))
		return FALSE;
	pctx->pstate->pread->clear();
	if (pctx->sync_flags & SYNC_READ_STATE) {
		if (0 == pctx->last_readcn) {
			if (pctx->last_changenum != 0 &&
			    !pctx->pstate->pread->append_range(1, 1, CHANGE_NUMBER_BEGIN - 1))
				return FALSE;
		} else if (!pctx->pstate->pread->append_range(1, 1,
		    rop_util_get_gc_value(pctx->last_readcn))) {
			return FALSE;
		}
	}
	auto pproplist = pctx->pstate->serialize();
	if (pproplist == nullptr)
		return FALSE;
	if (!pctx->pstream->write_state(pproplist)) {
		tpropval_array_free(pproplist);
		return FALSE;
	}
	tpropval_array_free(pproplist);
	return TRUE;
}

static BOOL icsdownctx_object_get_buffer_internal(icsdownctx_object *pctx,
    void *pbuff, uint16_t *plen, BOOL *pb_last)
{
	BOOL b_last;
	uint16_t len;
	uint16_t len1;
	int partial_count;
	
	if (pctx->flow_list.size() == 0) {
		if (!pctx->pstream->read_buffer(pbuff, plen, pb_last))
			return FALSE;	
		if (pctx->sync_type == SYNC_TYPE_HIERARCHY)
			pctx->progress_steps += *plen;
		return TRUE;
	}
	len = 0;
	if (pctx->pstream->total_length() > 0) {
		len = *plen;
		if (!pctx->pstream->read_buffer(pbuff, &len, &b_last))
			return FALSE;	
		if (!b_last || *plen - len < 2 * FTSTREAM_PRODUCER_POINT_LENGTH) {
			*plen = len;
			*pb_last = FALSE;
			return TRUE;
		}
	}
	partial_count = 0;
	len1 = *plen - len;
	size_t funcs_processed = 0;
	for (auto [func_id, obj_id] : pctx->flow_list) {
		pctx->progress_steps = pctx->next_progress_steps;
		switch (func_id) {
		case ics_flow_func::immed32:
			if (!pctx->pstream->write_uint32(obj_id))
				return FALSE;
			break;
		case ics_flow_func::progress:
			if (!pctx->pstream->write_progresstotal(pctx->pprogtotal))
				return FALSE;
			break;
		case ics_flow_func::upd_msg_id:
			if (!icsdownctx_object_write_message_change(pctx,
			    obj_id, TRUE, &partial_count))
				return FALSE;
			break;
		case ics_flow_func::new_msg_id:
			if (!icsdownctx_object_write_message_change(pctx,
			    obj_id, FALSE, &partial_count))
				return FALSE;
			break;
		case ics_flow_func::deletions:
			if (!icsdownctx_object_write_deletions(pctx))
				return FALSE;
			break;
		case ics_flow_func::read_state_chg:
			if (!icsdownctx_object_write_readstate_changes(pctx))
				return FALSE;
			break;
		case ics_flow_func::state:
			if (!icsdownctx_object_write_state(pctx))
				return FALSE;
			break;
		default:
			return FALSE;
		}
		++funcs_processed;
		if (pctx->pstream->total_length() > len1)
			break;
	}
	pctx->flow_list.erase(pctx->flow_list.begin(), pctx->flow_list.begin() + funcs_processed);
	if (!pctx->pstream->read_buffer(static_cast<char *>(pbuff) + len, &len1, &b_last))
		return FALSE;	
	*plen = len + len1;
	*pb_last = pctx->flow_list.size() == 0 && b_last ? TRUE : false;
	return TRUE;
}

BOOL icsdownctx_object::get_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal)
{
	*pprogress = progress_steps / divisor;
	*ptotal = total_steps / divisor;
	if (*ptotal == 0)
		*ptotal = 1;
	if (!icsdownctx_object_get_buffer_internal(this, pbuff, plen, pb_last))
		return FALSE;	
	if (*pb_last)
		*pprogress = *ptotal;
	return TRUE;
}

icsdownctx_object::~icsdownctx_object()
{
	auto pctx = this;
	if (pctx->pprogtotal != nullptr)
		free(pctx->pprogtotal);
	if (pctx->pmessages != nullptr)
		eid_array_free(pctx->pmessages);
	if (pctx->pdeleted_messages != nullptr)
		eid_array_free(pctx->pdeleted_messages);
	if (pctx->pnolonger_messages != nullptr)
		eid_array_free(pctx->pnolonger_messages);
	if (pctx->pread_messages != nullptr)
		eid_array_free(pctx->pread_messages);
	if (pctx->punread_messages != nullptr)
		eid_array_free(pctx->punread_messages);
	proptag_array_free(pctx->pproptags);
	if (pctx->prestriction != nullptr)
		restriction_free(pctx->prestriction);
}

BOOL icsdownctx_object::begin_state_stream(uint32_t new_state_prop)
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (pctx->state_property != 0)
		return FALSE;
	switch (new_state_prop) {
	case MetaTagIdsetGiven:
	case MetaTagIdsetGiven1:
	case MetaTagCnsetSeen:
		break;
	case MetaTagCnsetSeenFAI:
	case MetaTagCnsetRead:
		if (pctx->sync_type != SYNC_TYPE_CONTENTS)
			return FALSE;
		break;
	default:
		return FALSE;
	}
	pctx->state_property = new_state_prop;
	f_state_stream.clear();
	return TRUE;
}

BOOL icsdownctx_object::continue_state_stream(const BINARY *pstream_data) try
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (pctx->state_property == 0)
		return FALSE;
	f_state_stream += std::string_view(pstream_data->pc, pstream_data->cb);
	if (f_state_stream.size() >= UINT32_MAX) {
		mlog(LV_INFO, "I-1089: Too much ICS state sent by client");
		return false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1088: ENOMEM");
	return false;
}

BOOL icsdownctx_object::end_state_stream()
{
	auto pctx = this;
	BINARY tmp_bin;
	
	if (pctx->b_started)
		return FALSE;
	if (pctx->state_property == 0)
		return FALSE;
	auto pset = idset::create(false, REPL_TYPE_GUID);
	if (pset == nullptr)
		return FALSE;
	auto saved_state_property = pctx->state_property;
	pctx->state_property = 0;
	tmp_bin.pv = f_state_stream.data();
	tmp_bin.cb = f_state_stream.size();
	if (!pset->deserialize(std::move(tmp_bin)))
		return FALSE;
	f_state_stream.clear();
	f_state_stream.shrink_to_fit();
	if (!pset->register_mapping(pctx->pstream->plogon, common_util_mapping_replica))
		return FALSE;
	if (!pset->convert())
		return FALSE;
	if (!pctx->pstate->append_idset(saved_state_property, std::move(pset)))
		return FALSE;
	return TRUE;
}
