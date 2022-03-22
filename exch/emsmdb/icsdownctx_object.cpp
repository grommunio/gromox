// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <gromox/eid_array.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/proc_common.h>
#include <gromox/proptag_array.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "folder_object.h"
#include "ftstream_producer.h"
#include "ics_state.h"
#include "icsdownctx_object.h"
#include "logon_object.h"

enum {
	FUNC_ID_UINT32,
	FUNC_ID_PROGRESSTOTAL,
	FUNC_ID_UPDATED_MESSAGE,
	FUNC_ID_NEW_MESSAGE,
	FUNC_ID_DELETIONS,
	FUNC_ID_READSTATECHANGES,
	FUNC_ID_STATE
};

#define MAX_PARTIAL_ON_ROP		100	/* for limit of memory accumulation */

bool ics_flow_list::record_node(uint8_t func_id, const void *param) try
{
	emplace_back(func_id, param);
	return true;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1598: ENOMEM\n");
	return false;
}

bool ics_flow_list::record_tag(uint32_t tag)
{
	static_assert(sizeof(void *) >= sizeof(tag));
	return record_node(FUNC_ID_UINT32, reinterpret_cast<void *>(static_cast<uintptr_t>(tag)));
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
		fprintf(stderr, "E-1454: ENOMEM\n");
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
	if (NULL == pctx->pproptags) {
		return NULL;
	}
	if (NULL != prestriction) {
		pctx->prestriction = restriction_dup(prestriction);
		if (NULL == pctx->prestriction) {
			return NULL;
		}
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
	DCERPC_INFO rpc_info;
	const char *username;
	uint64_t total_normal;
	uint32_t count_normal;
	EID_ARRAY chg_messages;
	EID_ARRAY read_messags;
	EID_ARRAY given_messages;
	EID_ARRAY unread_messags;
	EID_ARRAY updated_messages;
	EID_ARRAY deleted_messages;
	EID_ARRAY nolonger_messages;
	
	
	if (SYNC_TYPE_CONTENTS != pctx->sync_type) {
		return FALSE;
	}
	
	if (pctx->sync_flags & SYNC_FLAG_PROGRESS) {
		pctx->pprogtotal = gromox::me_alloc<PROGRESS_INFORMATION>();
		if (NULL == pctx->pprogtotal) {
			return FALSE;
		}
	}
	auto pread     = (pctx->sync_flags & SYNC_FLAG_READSTATE) ? pctx->pstate->pread.get() : nullptr;
	auto pseen_fai = (pctx->sync_flags & SYNC_FLAG_FAI) ? pctx->pstate->pseen_fai.get() : nullptr;
	auto pseen     = (pctx->sync_flags & SYNC_FLAG_NORMAL) ? pctx->pstate->pseen.get() : nullptr;
	BOOL b_ordered = (pctx->extra_flags & SYNC_EXTRA_FLAG_ORDERBYDELIVERYTIME) ? TRUE : false;
	if (!pctx->pstream->plogon->check_private()) {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	} else {
		username = NULL;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client_get_content_sync(pctx->pstream->plogon->get_dir(),
	    pctx->pfolder->folder_id, username,
	    pctx->pstate->pgiven.get(), pseen, pseen_fai, pread,
	    pinfo->cpid, pctx->prestriction, b_ordered,
	    &count_fai, &total_fai, &count_normal, &total_normal,
	    &updated_messages, &chg_messages, &pctx->last_changenum,
	    &given_messages, &deleted_messages, &nolonger_messages,
	    &read_messags, &unread_messags, &pctx->last_readcn))
		return FALSE;
	
	pctx->pstate->pgiven->clear();
	for (size_t i = 0; i < given_messages.count; ++i) {
		if (!pctx->pstate->pgiven->append(given_messages.pids[i]))
			return FALSE;	
	}
	
	if ((pctx->sync_flags & SYNC_FLAG_FAI) ||
		(pctx->sync_flags & SYNC_FLAG_NORMAL)) {
		pctx->pmessages = eid_array_dup(&chg_messages);
		if (NULL == pctx->pmessages) {
			return FALSE;
		}
	}
	
	if (SYNC_FLAG_PROGRESS & pctx->sync_flags) {
		pctx->pprogtotal->version = 0;
		pctx->pprogtotal->padding1 = 0;
		pctx->pprogtotal->fai_count = count_fai;
		pctx->pprogtotal->fai_size = total_fai;
		pctx->pprogtotal->normal_count = count_normal;
		pctx->pprogtotal->padding2 = 0;
		pctx->pprogtotal->normal_size = total_normal;
	}
	
	if (0 == (pctx->sync_flags & SYNC_FLAG_NODELETIONS)) {
		pctx->pdeleted_messages = eid_array_dup(&deleted_messages);
		if (NULL == pctx->pdeleted_messages) {
			return FALSE;
		}
		pctx->pnolonger_messages = eid_array_dup(&nolonger_messages);
		if (NULL == pctx->pnolonger_messages) {
			return FALSE;
		}
	}
	
	if (pctx->sync_flags & SYNC_FLAG_READSTATE) {
		pctx->pread_messags = eid_array_dup(&read_messags);
		if (NULL == pctx->pread_messags) {
			return FALSE;
		}
		pctx->punread_messags = eid_array_dup(&unread_messags);
		if (NULL == pctx->punread_messags) {
			return FALSE;
		}
	}
	if (SYNC_FLAG_PROGRESS & pctx->sync_flags) {
		if (!pctx->flow_list.record_node(FUNC_ID_PROGRESSTOTAL))
			return FALSE;
	}
	
	if ((pctx->sync_flags & SYNC_FLAG_FAI) ||
		(pctx->sync_flags & SYNC_FLAG_NORMAL)) {
		for (size_t i = 0; i < pctx->pmessages->count; ++i) {
			size_t j;
			for (j=0; j<updated_messages.count; j++) {
				if (updated_messages.pids[j] == pctx->pmessages->pids[i]) {
					break;
				}
			}
			if (!pctx->flow_list.record_node(j < updated_messages.count ?
			    FUNC_ID_UPDATED_MESSAGE : FUNC_ID_NEW_MESSAGE, &pctx->pmessages->pids[i]))
				return FALSE;	
		}
	}
	
	if (0 == (pctx->sync_flags & SYNC_FLAG_NODELETIONS)) {
		if (!pctx->flow_list.record_node(FUNC_ID_DELETIONS))
			return FALSE;
	}
	
	if (pctx->sync_flags & SYNC_FLAG_READSTATE) {
		if (!pctx->flow_list.record_node(FUNC_ID_READSTATECHANGES))
			return FALSE;
	}
	if (!pctx->flow_list.record_node(FUNC_ID_STATE) ||
	    !pctx->flow_list.record_tag(INCRSYNCEND))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->next_progress_steps = 0;
	pctx->total_steps = total_normal + total_fai;
	size_t i;
	for (i=0; i<64; i++) {
		if ((pctx->total_steps >> i) <= 0xFFFF) {
			break;
		}
	}
	pctx->ratio = 1ULL << i;
	return TRUE;
}

static void icsdownctx_object_adjust_fldchgs(FOLDER_CHANGES *pfldchgs,
    const PROPTAG_ARRAY *pproptags, bool b_exclude)
{
	if (b_exclude) {
		for (size_t i = 0; i < pfldchgs->count; ++i) {
			for (size_t j = 0; j < pproptags->count; ++j) {
				common_util_remove_propvals(
					pfldchgs->pfldchgs + i,
					pproptags->pproptag[j]);
			}
		}
		return;
	}
	for (size_t i = 0; i < pfldchgs->count; ++i) {
		size_t j = 0;
		while (j < pfldchgs->pfldchgs[i].count) {
			if (!pproptags->has(pfldchgs->pfldchgs[i].ppropval[j].proptag)) {
				common_util_remove_propvals(pfldchgs->pfldchgs + i,
					pfldchgs->pfldchgs[i].ppropval[j].proptag);
				continue;
			}
			j++;
		}
	}
}

static BOOL icsdownctx_object_make_hierarchy(icsdownctx_object *pctx)
{
	BINARY *pbin = nullptr;
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	uint64_t folder_id;
	uint64_t parent_fid;
	const char *username;
	DCERPC_INFO rpc_info;
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
	
	if (SYNC_TYPE_HIERARCHY != pctx->sync_type) {
		return FALSE;
	}
	if (pctx->pstream->plogon->logon_mode == LOGON_MODE_OWNER) {
		username = NULL;
	} else {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	}
	if (!exmdb_client_get_hierarchy_sync(pctx->pstream->plogon->get_dir(),
	    pctx->pfolder->folder_id, username, pctx->pstate->pgiven.get(),
	    pctx->pstate->pseen.get(), &fldchgs, &last_changenum, &given_folders,
	    &deleted_folders))
		return FALSE;
	pctx->pstate->pgiven->clear();
	for (size_t i = 0; i < given_folders.count; ++i) {
		if (!pctx->pstate->pgiven->append(given_folders.pids[i]))
			return FALSE;	
	}
	for (size_t i = 0; i < fldchgs.count; ++i) {
		auto &chg = fldchgs.pfldchgs[i];
		static constexpr uint32_t tags[] = {
			PROP_TAG_FOLDERPATHNAME, PR_NORMAL_MESSAGE_SIZE,
			PR_NORMAL_MESSAGE_SIZE_EXTENDED, PR_MESSAGE_SIZE_EXTENDED,
			PR_ASSOC_MESSAGE_SIZE, PR_ASSOC_MESSAGE_SIZE_EXTENDED,
			PROP_TAG_FOLDERCHILDCOUNT, PR_DELETED_FOLDER_COUNT,
			PROP_TAG_ARTICLENUMBERNEXT, PROP_TAG_FOLDERFLAGS,
		};
		for (auto t : tags)
			common_util_remove_propvals(&chg, t);
		if (!chg.has(PR_ATTR_HIDDEN))
			cu_set_propval(&chg, PR_ATTR_HIDDEN, &fake_byte);
		if (!chg.has(PROP_TAG_ATTRIBUTESYSTEM))
			cu_set_propval(&chg, PROP_TAG_ATTRIBUTESYSTEM, &fake_byte);
		if (!chg.has(PROP_TAG_ATTRIBUTEREADONLY))
			cu_set_propval(&chg, PROP_TAG_ATTRIBUTEREADONLY, &fake_byte);
		if (!chg.has(PR_CREATOR_SID)) {
			tmp_bin.cb = 0;
			tmp_bin.pb = NULL;
			cu_set_propval(&chg, PR_CREATOR_SID, &tmp_bin);
		}
		auto pvalue = chg.getval(PidTagFolderId);
		if (NULL == pvalue) {
			return FALSE;
		}
		folder_id = *(uint64_t*)pvalue;
		if (0 == (SYNC_EXTRA_FLAG_EID & pctx->extra_flags)) {
			common_util_remove_propvals(&chg, PidTagFolderId);
		}
		pvalue = chg.getval(PidTagParentFolderId);
		if (NULL == pvalue) {
			return FALSE;
		}
		parent_fid = *(uint64_t*)pvalue;
		if (SYNC_FLAG_NOFOREIGNIDENTIFIERS & pctx->sync_flags) {
			common_util_remove_propvals(&chg, PR_SOURCE_KEY);
			auto psk = common_util_calculate_folder_sourcekey(pctx->pstream->plogon, folder_id);
			if (psk == nullptr)
				return FALSE;
			cu_set_propval(&chg, PR_SOURCE_KEY, psk);
			if (pctx->pfolder->folder_id == parent_fid) {
				tmp_bin.cb = 0;
				tmp_bin.pb = NULL;
				psk = &tmp_bin;
			} else {
				psk = common_util_calculate_folder_sourcekey(pctx->pstream->plogon, parent_fid);
				if (psk == nullptr)
					return FALSE;
			}
			cu_set_propval(&chg, PR_PARENT_SOURCE_KEY, psk);
		} else {
			if (!chg.has(PR_SOURCE_KEY)) {
				auto psk = common_util_calculate_folder_sourcekey(pctx->pstream->plogon, folder_id);
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
				if (!exmdb_client_get_folder_property(pctx->pstream->plogon->get_dir(),
				    0, parent_fid, PR_SOURCE_KEY, &psk))
					return FALSE;	
				if (psk == nullptr) {
					psk = common_util_calculate_folder_sourcekey(pctx->pstream->plogon, parent_fid);
					if (psk == nullptr)
						return FALSE;
				}
			}
			cu_set_propval(&chg, PR_PARENT_SOURCE_KEY, psk);
		}
		auto inboxy = pctx->pstream->plogon->check_private() &&
		              (folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_ROOT) ||
		              folder_id == rop_util_make_eid_ex(1, PRIVATE_FID_INBOX));
		if (!inboxy)
			continue;
		auto ppropval = cu_alloc<TAGGED_PROPVAL>(chg.count + 10);
		if (NULL == ppropval) {
			return FALSE;
		}
		memcpy(ppropval, chg.ppropval, sizeof(TAGGED_PROPVAL) * chg.count);
		chg.ppropval = ppropval;
		tmp_propval.proptag = PR_IPM_DRAFTS_ENTRYID;
		tmp_propval.pvalue = common_util_to_folder_entryid(
			pctx->pstream->plogon, rop_util_make_eid_ex(1,
			PRIVATE_FID_DRAFT));
		if (NULL == tmp_propval.pvalue) {
			return FALSE;
		}
		common_util_set_propvals(fldchgs.pfldchgs + i, &tmp_propval);
		tmp_propval.proptag = PR_IPM_CONTACT_ENTRYID;
		tmp_propval.pvalue = common_util_to_folder_entryid(
			pctx->pstream->plogon, rop_util_make_eid_ex(1,
			PRIVATE_FID_CONTACTS));
		if (NULL == tmp_propval.pvalue) {
			return FALSE;
		}
		common_util_set_propvals(fldchgs.pfldchgs + i, &tmp_propval);
		tmp_propval.proptag = PR_IPM_APPOINTMENT_ENTRYID;
		tmp_propval.pvalue = common_util_to_folder_entryid(
			pctx->pstream->plogon, rop_util_make_eid_ex(1,
			PRIVATE_FID_CALENDAR));
		if (NULL == tmp_propval.pvalue) {
			return FALSE;
		}
		common_util_set_propvals(fldchgs.pfldchgs + i, &tmp_propval);
		tmp_propval.proptag = PR_IPM_JOURNAL_ENTRYID;
		tmp_propval.pvalue = common_util_to_folder_entryid(
			pctx->pstream->plogon, rop_util_make_eid_ex(1,
			PRIVATE_FID_JOURNAL));
		if (NULL == tmp_propval.pvalue) {
			return FALSE;
		}
		common_util_set_propvals(fldchgs.pfldchgs + i, &tmp_propval);
		tmp_propval.proptag = PR_IPM_NOTE_ENTRYID;
		tmp_propval.pvalue = common_util_to_folder_entryid(
			pctx->pstream->plogon, rop_util_make_eid_ex(1,
			PRIVATE_FID_NOTES));
		if (NULL == tmp_propval.pvalue) {
			return FALSE;
		}
		common_util_set_propvals(fldchgs.pfldchgs + i, &tmp_propval);
		tmp_propval.proptag = PR_IPM_TASK_ENTRYID;
		tmp_propval.pvalue = common_util_to_folder_entryid(
			pctx->pstream->plogon, rop_util_make_eid_ex(1,
			PRIVATE_FID_TASKS));
		if (NULL == tmp_propval.pvalue) {
			return FALSE;
		}
		common_util_set_propvals(fldchgs.pfldchgs + i, &tmp_propval);
		if (!chg.has(PR_ADDITIONAL_REN_ENTRYIDS)) {
			tmp_propval.proptag = PR_ADDITIONAL_REN_ENTRYIDS;
			auto ba = cu_alloc<BINARY_ARRAY>();
			if (ba == nullptr)
				return FALSE;
			tmp_propval.pvalue = ba;
			ba->count = 5;
			ba->pbin = cu_alloc<BINARY>(ba->count);
			if (ba->pbin == nullptr) {
				return FALSE;
			}
			pbin = common_util_to_folder_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_CONFLICTS));
			if (NULL == pbin) {
				return FALSE;
			}
			ba->pbin[0] = *pbin;
			pbin = common_util_to_folder_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_SYNC_ISSUES));
			if (NULL == pbin) {
				return FALSE;
			}
			ba->pbin[1] = *pbin;
			pbin = common_util_to_folder_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FAILURES));
			if (NULL == pbin) {
				return FALSE;
			}
			ba->pbin[2] = *pbin;
			pbin = common_util_to_folder_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_SERVER_FAILURES));
			if (NULL == pbin) {
				return FALSE;
			}
			ba->pbin[3] = *pbin;
			pbin = common_util_to_folder_entryid(pctx->pstream->plogon,
			       rop_util_make_eid_ex(1, PRIVATE_FID_JUNK));
			if (NULL == pbin) {
				return FALSE;
			}
			ba->pbin[4] = *pbin;
			common_util_set_propvals(
				fldchgs.pfldchgs + i, &tmp_propval);
		}
		if (!chg.has(PR_ADDITIONAL_REN_ENTRYIDS_EX)) {
			tmp_propval.proptag = PR_ADDITIONAL_REN_ENTRYIDS_EX;
			auto bv = cu_alloc<BINARY>();
			if (bv == nullptr)
				return FALSE;
			tmp_propval.pvalue = bv;
			persistdatas.count = 3;
			persistdatas.ppitems = cu_alloc<PERSISTDATA *>(persistdatas.count);
			if (NULL == persistdatas.ppitems) {
				return FALSE;
			}
			auto ppersistdata = cu_alloc<PERSISTDATA>(persistdatas.count);
			if (NULL == ppersistdata) {
				return FALSE;
			}
			persistdatas.ppitems[0] = ppersistdata;
			persistdatas.ppitems[0]->persist_id = RSF_PID_CONV_ACTIONS;
			persistdatas.ppitems[0]->element.element_id = RSF_ELID_ENTRYID;
			persistdatas.ppitems[0]->element.pentry_id =
				common_util_to_folder_entryid(pctx->pstream->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_CONVERSATION_ACTION_SETTINGS));
			persistdatas.ppitems[1] = ppersistdata + 1;
			persistdatas.ppitems[1]->persist_id = RSF_PID_BUDDYLIST_PDLS;
			persistdatas.ppitems[1]->element.element_id = RSF_ELID_ENTRYID;
			persistdatas.ppitems[1]->element.pentry_id =
				common_util_to_folder_entryid(pctx->pstream->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_IMCONTACTLIST));
			persistdatas.ppitems[2] = ppersistdata + 2;
			persistdatas.ppitems[2]->persist_id = RSF_PID_BUDDYLIST_CONTACTS;
			persistdatas.ppitems[2]->element.element_id = RSF_ELID_ENTRYID;
			persistdatas.ppitems[2]->element.pentry_id =
				common_util_to_folder_entryid(pctx->pstream->plogon,
				rop_util_make_eid_ex(1, PRIVATE_FID_QUICKCONTACTS));
			if (!ext_push.init(temp_buff, sizeof(temp_buff), 0) ||
			    ext_push.p_persistdata_a(persistdatas) != EXT_ERR_SUCCESS)
				return false;
			bv->cb = ext_push.m_offset;
			bv->pv = common_util_alloc(bv->cb);
			if (bv->pv == nullptr)
				return FALSE;
			memcpy(bv->pv, ext_push.m_udata, bv->cb);
			common_util_set_propvals(
				fldchgs.pfldchgs + i, &tmp_propval);
		}
		if (!chg.has(PR_FREEBUSY_ENTRYIDS)) {
			tmp_propval.proptag = PR_FREEBUSY_ENTRYIDS;
			auto ba = cu_alloc<BINARY_ARRAY>();
			if (ba == nullptr)
				return FALSE;
			tmp_propval.pvalue = ba;
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
			pbin = common_util_to_folder_entryid(pctx->pstream->plogon,
					rop_util_make_eid_ex(1, PRIVATE_FID_LOCAL_FREEBUSY));
			if (NULL == pbin) {
				return FALSE;
			}
			ba->pbin[3] = *pbin;
			common_util_set_propvals(
				fldchgs.pfldchgs + i, &tmp_propval);
		}
	}
	icsdownctx_object_adjust_fldchgs(&fldchgs, pctx->pproptags, !(pctx->sync_flags & SYNC_FLAG_ONLYSPECIFIEDPROPERTIES));
	if ((pctx->sync_flags & SYNC_FLAG_NODELETIONS) || deleted_folders.count == 0) {
		pproplist_deletions = NULL;
	} else {
		idset xset(true, REPL_TYPE_ID);
		for (size_t i = 0; i < deleted_folders.count; ++i) {
			if (!xset.append(deleted_folders.pids[i]))
				return FALSE;
		}
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
			if (NULL != pproplist_deletions) {
				rop_util_free_binary(pbin);
			}
			return FALSE;
		}
	}
	auto pproplist_state = pctx->pstate->serialize();
	if (NULL == pproplist_state) {
		if (NULL != pproplist_deletions) {
			rop_util_free_binary(pbin);
		}
		return FALSE;
	}
	if (!pctx->pstream->write_hierarchysync(&fldchgs,
	    pproplist_deletions, pproplist_state)) {
		tpropval_array_free(pproplist_state);
		if (NULL != pproplist_deletions) {
			rop_util_free_binary(pbin);
		}
		return FALSE;	
	}
	tpropval_array_free(pproplist_state);
	if (NULL != pproplist_deletions) {
		rop_util_free_binary(pbin);
	}
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	pctx->ratio = 1;
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

static BOOL icsdownctx_object_extract_msgctntinfo(
	MESSAGE_CONTENT *pmsgctnt, uint8_t extra_flags,
	TPROPVAL_ARRAY *pchgheader, PROGRESS_MESSAGE *pprogmsg)
{
	pchgheader->ppropval = cu_alloc<TAGGED_PROPVAL>(8);
	if (NULL == pchgheader->ppropval) {
		return FALSE;
	}
	pchgheader->count = 0;
	auto pvalue = pmsgctnt->proplist.getval(PR_SOURCE_KEY);
	if (NULL == pvalue) {
		return FALSE;
	}
	pchgheader->ppropval[pchgheader->count].proptag = PR_SOURCE_KEY;
	pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	common_util_remove_propvals(&pmsgctnt->proplist, PR_SOURCE_KEY);
	
	pvalue = pmsgctnt->proplist.getval(PR_LAST_MODIFICATION_TIME);
	if (NULL == pvalue) {
		return FALSE;
	}
	pchgheader->ppropval[pchgheader->count].proptag = PR_LAST_MODIFICATION_TIME;
	pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	
	pvalue = pmsgctnt->proplist.getval(PR_CHANGE_KEY);
	if (NULL == pvalue) {
		return FALSE;
	}
	pchgheader->ppropval[pchgheader->count].proptag = PR_CHANGE_KEY;
	pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	
	pvalue = pmsgctnt->proplist.getval(PR_PREDECESSOR_CHANGE_LIST);
	if (NULL == pvalue) {
		return FALSE;
	}
	pchgheader->ppropval[pchgheader->count].proptag = PR_PREDECESSOR_CHANGE_LIST;
	pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	common_util_remove_propvals(&pmsgctnt->proplist, PR_PREDECESSOR_CHANGE_LIST);
	
	pvalue = pmsgctnt->proplist.getval(PR_ASSOCIATED);
	if (NULL == pvalue) {
		return FALSE;
	}
	pprogmsg->b_fai = *static_cast<uint8_t *>(pvalue) == 0 ? false : TRUE;
	pchgheader->ppropval[pchgheader->count].proptag = PR_ASSOCIATED;
	pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	common_util_remove_propvals(&pmsgctnt->proplist, PR_ASSOCIATED);
	
	if (SYNC_EXTRA_FLAG_EID & extra_flags) {
		pvalue = pmsgctnt->proplist.getval(PidTagMid);
		if (NULL == pvalue) {
			return FALSE;
		}
		pchgheader->ppropval[pchgheader->count].proptag = PidTagMid;
		pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	}
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagMid);
	
	pvalue = pmsgctnt->proplist.getval(PR_MESSAGE_SIZE);
	if (NULL == pvalue) {
		return FALSE;
	}
	pprogmsg->message_size = *(uint32_t*)pvalue;
	if (SYNC_EXTRA_FLAG_MESSAGESIZE & extra_flags) {
		pchgheader->ppropval[pchgheader->count].proptag = PR_MESSAGE_SIZE;
		pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	}
	common_util_remove_propvals(&pmsgctnt->proplist, PR_MESSAGE_SIZE);
	
	if (SYNC_EXTRA_FLAG_CN & extra_flags) {
		pvalue = pmsgctnt->proplist.getval(PidTagChangeNumber);
		if (NULL == pvalue) {
			return FALSE;
		}
		pchgheader->ppropval[pchgheader->count].proptag = PidTagChangeNumber;
		pchgheader->ppropval[pchgheader->count++].pvalue = pvalue;
	}
	common_util_remove_propvals(&pmsgctnt->proplist, PidTagChangeNumber);
	return TRUE;
}

static void icsdownctx_object_adjust_msgctnt(MESSAGE_CONTENT *pmsgctnt,
    const PROPTAG_ARRAY *pproptags, bool b_exclude)
{
	int i;
	
	if (b_exclude) {
		for (i=0; i<pproptags->count; i++) {
			switch (pproptags->pproptag[i]) {
			case PR_MESSAGE_RECIPIENTS:
				pmsgctnt->children.prcpts = NULL;
				break;
			case PR_MESSAGE_ATTACHMENTS:
				pmsgctnt->children.pattachments = NULL;
				break;
			default:
				common_util_remove_propvals(&pmsgctnt->proplist,
										pproptags->pproptag[i]);
				break;
			}
		}
		return;
	}
	i = 0;
	while (i < pmsgctnt->proplist.count) {
		if (!pproptags->has(pmsgctnt->proplist.ppropval[i].proptag)) {
			common_util_remove_propvals(&pmsgctnt->proplist,
				pmsgctnt->proplist.ppropval[i].proptag);
			continue;
		}
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
	int i, j;
	uint16_t count;
	uint32_t index;
	uint32_t proptag;
	PROPTAG_ARRAY *pchangetags;
	static constexpr BINARY fake_bin{};
	
	auto pgpinfo = pctx->pstream->plogon->get_property_groupinfo(group_id);
	if (NULL == pgpinfo) {
		return FALSE;
	}
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
			fprintf(stderr, "E-1597: ENOMEM\n");
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
		count = 0;
		for (j=0; j<pchangetags->count; j++) {
			proptag = pchangetags->pproptag[j];
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
	if (0 == pproptags->count) {
		return TRUE;
	}
	auto &pl = pmsg->pchanges[i].proplist;
	pmsg->pchanges[i].index = UINT32_MAX;
	pl.ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	count = 0;
	for (j=0; j<pproptags->count; j++) {
		proptag = pproptags->pproptag[j];
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
	return TRUE;
}

static void icsdownctx_object_trim_embedded(
	MESSAGE_CONTENT *pmsgctnt)
{
	int i, j;
	MESSAGE_CONTENT *pembedded;
	ATTACHMENT_CONTENT *pattachment;
	
	if (NULL == pmsgctnt->children.pattachments) {
		return;
	}
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		pattachment = pmsgctnt->children.pattachments->pplist[i];
		if (NULL == pattachment->pembedded) {
			continue;
		}
		pembedded = pattachment->pembedded;
		for (j=0; j<pembedded->proplist.count; j++) {
			if (pembedded->proplist.ppropval[j].proptag == PidTagMid) {
				*(uint64_t*)pembedded->proplist.ppropval[j].pvalue = 0;
				break;
			}
		}
		common_util_remove_propvals(&pembedded->proplist, PidTagChangeNumber);
		common_util_remove_propvals(
			&pembedded->proplist, PROP_TAG_MESSAGESTATUS);
		icsdownctx_object_trim_embedded(pembedded);
	}
}

/* Outlook 2016 does not accept recipients
	of report messages, get rid of them */
static void icsdownctx_object_trim_report_recipients(
	MESSAGE_CONTENT *pmsgctnt)
{
	int i;
	ATTACHMENT_CONTENT *pattachment;
	
	auto pvalue = pmsgctnt->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (NULL != pvalue && 0 == strncasecmp(
		pvalue, "REPORT.IPM.Note.", 16)) {
		pmsgctnt->children.prcpts = NULL;
	}
	if (NULL == pmsgctnt->children.pattachments) {
		return;
	}
	for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
		pattachment = pmsgctnt->children.pattachments->pplist[i];
		if (NULL != pattachment->pembedded) {
			icsdownctx_object_trim_report_recipients(
							pattachment->pembedded);
		}
	}
}

static BOOL icsdownctx_object_write_message_change(icsdownctx_object *pctx,
	uint64_t message_id, BOOL b_downloaded, int *ppartial_count)
{
	int i;
	BOOL b_full;
	void *pvalue;
	uint64_t last_cn;
	INDEX_ARRAY indices;
	uint32_t *pgroup_id;
	PROPTAG_ARRAY proptags;
	PROGRESS_MESSAGE progmsg;
	TPROPVAL_ARRAY chgheader;
	MESSAGE_CONTENT *pmsgctnt;
	MESSAGE_CONTENT *pembedded;
	MSGCHG_PARTIAL msg_partial;
	static constexpr uint8_t fake_true = 1;
	static constexpr uint8_t fake_false = 0;
	
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pctx->pstream->plogon->check_private()) {
		if (!exmdb_client_read_message(pctx->pstream->plogon->get_dir(),
		    nullptr, pinfo->cpid, message_id, &pmsgctnt))
			return FALSE;
	} else {
		auto rpc_info = get_rpc_info();
		if (!exmdb_client_read_message(pctx->pstream->plogon->get_dir(),
		    rpc_info.username, pinfo->cpid, message_id, &pmsgctnt))
			return FALSE;
	}
	if (NULL == pmsgctnt) {
		pctx->pstate->pgiven->remove(message_id);
		if (b_downloaded) {
			if (0 == (SYNC_FLAG_NODELETIONS & pctx->sync_flags)) {
				if (!eid_array_append(pctx->pdeleted_messages, message_id))
					return FALSE;	
			}
			if (SYNC_FLAG_READSTATE & pctx->sync_flags) {
				eid_array_remove(pctx->pread_messags, message_id);
				eid_array_remove(pctx->punread_messags, message_id);
			}
		}
		return TRUE;
	}
	icsdownctx_object_trim_report_recipients(pmsgctnt);
	auto folder_id = pctx->pfolder->folder_id;
	auto pstatus = pmsgctnt->proplist.get<uint32_t>(PROP_TAG_MESSAGESTATUS);
	if (NULL == pstatus) {
		return FALSE;
	}
	if (*pstatus & MSGSTATUS_IN_CONFLICT) {
		if (0 == (pctx->sync_flags & SYNC_FLAG_NOFOREIGNIDENTIFIERS)) {
			if (!exmdb_client_get_folder_property(pctx->pstream->plogon->get_dir(),
			    0, folder_id, PR_SOURCE_KEY, &pvalue))
				return FALSE;	
			if (NULL == pvalue) {
				pvalue = common_util_calculate_folder_sourcekey(
								pctx->pstream->plogon, folder_id);
			}
		} else {
			pvalue = common_util_calculate_folder_sourcekey(
							pctx->pstream->plogon, folder_id);
		}
		if (NULL == pvalue) {
			return FALSE;
		}
		for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
			if (!pmsgctnt->children.pattachments->pplist[i]->proplist.has(PROP_TAG_INCONFLICT))
				continue;
			pembedded = pmsgctnt->children.pattachments->pplist[i]->pembedded;
			if (NULL == pembedded) {
				return FALSE;
			}
			icsdownctx_object_trim_embedded(pembedded);
			auto ppropval = cu_alloc<TAGGED_PROPVAL>(pembedded->proplist.count + 2);
			if (NULL == ppropval) {
				return FALSE;
			}
			memcpy(ppropval, pembedded->proplist.ppropval,
				sizeof(TAGGED_PROPVAL)*pembedded->proplist.count);
			pembedded->proplist.ppropval = ppropval;
			cu_set_propval(&pembedded->proplist, PidTagMid, &message_id);
			cu_set_propval(&pembedded->proplist, PR_PARENT_SOURCE_KEY, pvalue);
			if (!pembedded->proplist.has(PR_SOURCE_KEY)) {
				auto psk = common_util_calculate_message_sourcekey(pctx->pstream->plogon, message_id);
				if (psk == nullptr)
					return FALSE;
				cu_set_propval(&pembedded->proplist, PR_SOURCE_KEY, psk);
			}
			if (!icsdownctx_object_extract_msgctntinfo(pembedded,
			    pctx->extra_flags, &chgheader, &progmsg))
				return FALSE;
			icsdownctx_object_adjust_msgctnt(pembedded, pctx->pproptags, !(pctx->sync_flags & SYNC_FLAG_ONLYSPECIFIEDPROPERTIES));
			if (pctx->sync_flags & SYNC_FLAG_PROGRESS &&
			    !pctx->pstream->write_progresspermessage(&progmsg))
				return FALSE;
			common_util_remove_propvals(&pembedded->proplist, PR_READ);
			common_util_remove_propvals(&pembedded->proplist, PR_CHANGE_KEY);
			common_util_remove_propvals(
				&pembedded->proplist, PROP_TAG_MESSAGESTATUS);
			auto flags = pembedded->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
			auto xbit = flags != nullptr && (*flags & MSGFLAG_RN_PENDING) ?
			                     deconst(&fake_true) : deconst(&fake_false);
			cu_set_propval(&pembedded->proplist, PR_READ_RECEIPT_REQUESTED, xbit);
			xbit = flags != nullptr && (*flags & MSGFLAG_NRN_PENDING) ?
			                     deconst(&fake_true) : deconst(&fake_false);
			cu_set_propval(&pembedded->proplist, PR_NON_RECEIPT_NOTIFICATION_REQUESTED, xbit);
			if (!pctx->pstream->write_messagechangefull(&chgheader, pembedded))
				return FALSE;
		}
		return TRUE;
	}
	icsdownctx_object_trim_embedded(pmsgctnt);
	auto ppropval = cu_alloc<TAGGED_PROPVAL>(pmsgctnt->proplist.count + 10);
	if (NULL == ppropval) {
		return FALSE;
	}
	memcpy(ppropval, pmsgctnt->proplist.ppropval,
		sizeof(TAGGED_PROPVAL)*pmsgctnt->proplist.count);
	pmsgctnt->proplist.ppropval = ppropval;
	if (0 == (pctx->sync_flags & SYNC_FLAG_NOFOREIGNIDENTIFIERS)) {
		if (!exmdb_client_get_folder_property(pctx->pstream->plogon->get_dir(),
		    0, folder_id, PR_SOURCE_KEY, &pvalue))
			return FALSE;	
		if (NULL == pvalue) {
			pvalue = common_util_calculate_folder_sourcekey(pctx->pstream->plogon, folder_id);
			if (pvalue == nullptr)
				return FALSE;
		}
		cu_set_propval(&pmsgctnt->proplist, PR_PARENT_SOURCE_KEY, pvalue);
		if (!pmsgctnt->proplist.has(PR_SOURCE_KEY)) {
			pvalue = common_util_calculate_message_sourcekey(pctx->pstream->plogon, message_id);
			if (pvalue == nullptr)
				return FALSE;
			cu_set_propval(&pmsgctnt->proplist, PR_SOURCE_KEY, pvalue);
		}
	} else {
		pvalue = common_util_calculate_folder_sourcekey(pctx->pstream->plogon, folder_id);
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&pmsgctnt->proplist, PR_PARENT_SOURCE_KEY, pvalue);
		pvalue = common_util_calculate_message_sourcekey(pctx->pstream->plogon, message_id);
		if (pvalue == nullptr)
			return FALSE;
		cu_set_propval(&pmsgctnt->proplist, PR_SOURCE_KEY, pvalue);
	}
	if (!icsdownctx_object_extract_msgctntinfo(pmsgctnt,
	    pctx->extra_flags, &chgheader, &progmsg))
		return FALSE;
	auto cond1 = !(pctx->sync_flags & SYNC_FLAG_ONLYSPECIFIEDPROPERTIES);
	if (!(pctx->sync_flags & SYNC_FLAG_IGNORESPECIFIEDONFAI) ||
	    cond1 || !progmsg.b_fai)
		icsdownctx_object_adjust_msgctnt(pmsgctnt, pctx->pproptags, cond1);
	if (!b_downloaded || progmsg.b_fai) {
		b_full = TRUE;
	} else {
		if (!exmdb_client_get_message_group_id(pctx->pstream->plogon->get_dir(),
		    message_id, &pgroup_id))
			return FALSE;
		if (!(pctx->send_options & SEND_OPTIONS_PARTIAL) ||
		    progmsg.b_fai || pgroup_id == nullptr ||
		    *ppartial_count > MAX_PARTIAL_ON_ROP) {
			b_full = TRUE;
		} else {
			auto &ps = progmsg.b_fai ? pctx->pstate->pseen_fai : pctx->pstate->pseen;
			if (!ps->get_repl_first_max(1, &last_cn))
				return false;
			if (!exmdb_client_get_change_indices(pctx->pstream->plogon->get_dir(),
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
	if (pctx->sync_flags & SYNC_FLAG_PROGRESS &&
	    !pctx->pstream->write_progresspermessage(&progmsg))
		return FALSE;
	pctx->next_progress_steps += progmsg.message_size;
	if (!b_full) {
		return pctx->pstream->write_messagechangepartial(&chgheader, &msg_partial);
	}
	common_util_remove_propvals(&pmsgctnt->proplist, PR_READ);
	common_util_remove_propvals(&pmsgctnt->proplist, PR_CHANGE_KEY);
	common_util_remove_propvals(
		&pmsgctnt->proplist, PROP_TAG_MESSAGESTATUS);
	auto flags = pmsgctnt->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
	auto xbit = flags != nullptr && (*flags & MSGFLAG_RN_PENDING) ?
	            deconst(&fake_true) : deconst(&fake_false);
	cu_set_propval(&pmsgctnt->proplist, PR_READ_RECEIPT_REQUESTED, xbit);
	xbit = flags != nullptr && (*flags & MSGFLAG_NRN_PENDING) ?
	       deconst(&fake_true) : deconst(&fake_false);
	cu_set_propval(&pmsgctnt->proplist, PR_NON_RECEIPT_NOTIFICATION_REQUESTED, xbit);
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
		for (size_t i = 0; i < pctx->pdeleted_messages->count; ++i) {
			if (!xset.append(pctx->pdeleted_messages->pids[i]))
				return FALSE;
		}
		pbin1 = xset.serialize();
		if (NULL == pbin1) {
			return FALSE;
		}
		proplist.ppropval[proplist.count].proptag = MetaTagIdsetDeleted;
		proplist.ppropval[proplist.count++].pvalue = pbin1;
	}
	if (0 == (SYNC_FLAG_IGNORENOLONGERINSCOPE & pctx->sync_flags)
		&& pctx->pnolonger_messages->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (size_t i = 0; i < pctx->pnolonger_messages->count; ++i) {
			if (!xset.append(pctx->pnolonger_messages->pids[i])) {
				if (NULL != pbin1) {
					rop_util_free_binary(pbin1);
				}
				return FALSE;
			}
		}
		pbin2 = xset.serialize();
		if (NULL == pbin2) {
			if (NULL != pbin1) {
				rop_util_free_binary(pbin1);
			}
			return FALSE;
		}
		proplist.ppropval[proplist.count].proptag = MetaTagIdsetNoLongerInScope;
		proplist.ppropval[proplist.count++].pvalue = pbin2;
	}
	if (0 == proplist.count) {
		return TRUE;
	}
	if (!pctx->pstream->write_deletions(&proplist)) {
		if (NULL != pbin1) {
			rop_util_free_binary(pbin1);
		}
		if (NULL != pbin2) {
			rop_util_free_binary(pbin2);
		}
		return FALSE;
	}
	if (NULL != pbin1) {
		rop_util_free_binary(pbin1);
	}
	if (NULL != pbin2) {
		rop_util_free_binary(pbin2);
	}
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
	if (pctx->pread_messags->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (size_t i = 0; i < pctx->pread_messags->count; ++i) {
			if (!xset.append(pctx->pread_messags->pids[i]))
				return FALSE;
		}
		pbin1 = xset.serialize();
		if (NULL == pbin1) {
			return FALSE;
		}
		proplist.ppropval[proplist.count].proptag = MetaTagIdsetRead;
		proplist.ppropval[proplist.count++].pvalue = pbin1;
	}
	if (pctx->punread_messags->count > 0) {
		idset xset(true, REPL_TYPE_ID);
		for (size_t i = 0; i < pctx->punread_messags->count; ++i) {
			if (!xset.append(pctx->punread_messags->pids[i]))
				return FALSE;
		}
		pbin2 = xset.serialize();
		if (NULL == pbin2) {
			return FALSE;
		}
		proplist.ppropval[proplist.count].proptag = MetaTagIdsetUnread;
		proplist.ppropval[proplist.count++].pvalue = pbin2;
	}
	if (0 == proplist.count) {
		return TRUE;
	}
	if (!pctx->pstream->write_readstatechanges(&proplist)) {
		return FALSE;
	}
	return TRUE;
}

/* only be called under content sync */
static BOOL icsdownctx_object_write_state(icsdownctx_object *pctx)
{
	pctx->pstate->pseen->clear();
	if (pctx->sync_flags & SYNC_FLAG_NORMAL && pctx->last_changenum != 0 &&
	    !pctx->pstate->pseen->append_range(1, 1,
	    rop_util_get_gc_value(pctx->last_changenum)))
		return FALSE;
	pctx->pstate->pseen_fai->clear();
	if (pctx->sync_flags & SYNC_FLAG_FAI && pctx->last_changenum != 0 &&
	    !pctx->pstate->pseen_fai->append_range(1, 1,
	    rop_util_get_gc_value(pctx->last_changenum)))
		return FALSE;
	pctx->pstate->pread->clear();
	if (pctx->sync_flags & SYNC_FLAG_READSTATE) {
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
	if (NULL == pproplist) {
		return FALSE;
	}
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
		if (SYNC_TYPE_HIERARCHY == pctx->sync_type) {
			pctx->progress_steps += *plen;
		}
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
	while (pctx->flow_list.size() > 0) {
		auto [func_id, pparam] = pctx->flow_list.front();
		pctx->flow_list.pop_front();
		pctx->progress_steps = pctx->next_progress_steps;
		switch (func_id) {
		case FUNC_ID_UINT32:
			if (!pctx->pstream->write_uint32(reinterpret_cast<uintptr_t>(pparam)))
				return FALSE;
			break;
		case FUNC_ID_PROGRESSTOTAL:
			if (!pctx->pstream->write_progresstotal(pctx->pprogtotal)) {
				return FALSE;
			}
			break;
		case FUNC_ID_UPDATED_MESSAGE: {
			auto message_id = *static_cast<const uint64_t *>(pparam);
			if (!icsdownctx_object_write_message_change(pctx,
			    message_id, TRUE, &partial_count))
				return FALSE;
			break;
		}
		case FUNC_ID_NEW_MESSAGE: {
			auto message_id = *static_cast<const uint64_t *>(pparam);
			if (!icsdownctx_object_write_message_change(pctx,
			    message_id, FALSE, &partial_count))
				return FALSE;
			break;
		}
		case FUNC_ID_DELETIONS:
			if (!icsdownctx_object_write_deletions(pctx))
				return FALSE;
			break;
		case FUNC_ID_READSTATECHANGES:
			if (!icsdownctx_object_write_readstate_changes(pctx))
				return FALSE;
			break;
		case FUNC_ID_STATE:
			if (!icsdownctx_object_write_state(pctx))
				return FALSE;
			break;
		default:
			return FALSE;
		}
		if (pctx->pstream->total_length() > len1)
			break;
	}
	if (!pctx->pstream->read_buffer(static_cast<char *>(pbuff) + len, &len1, &b_last))
		return FALSE;	
	*plen = len + len1;
	*pb_last = pctx->flow_list.size() == 0 && b_last ? TRUE : false;
	return TRUE;
}

BOOL icsdownctx_object::get_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal)
{
	auto pctx = this;
	*pprogress = pctx->progress_steps / pctx->ratio;
	*ptotal = pctx->total_steps / pctx->ratio;
	if (0 == *ptotal) {
		*ptotal = 1;
	}
	if (!icsdownctx_object_get_buffer_internal(pctx, pbuff, plen, pb_last))
		return FALSE;	
	if (*pb_last)
		*pprogress = *ptotal;
	return TRUE;
}

icsdownctx_object::~icsdownctx_object()
{
	auto pctx = this;
	if (NULL != pctx->pprogtotal) {
		free(pctx->pprogtotal);
	}
	if (NULL != pctx->pmessages) {
		eid_array_free(pctx->pmessages);
	}
	if (NULL != pctx->pdeleted_messages) {
		eid_array_free(pctx->pdeleted_messages);
	}
	if (NULL != pctx->pnolonger_messages) {
		eid_array_free(pctx->pnolonger_messages);
	}
	if (NULL != pctx->pread_messags) {
		eid_array_free(pctx->pread_messags);
	}
	if (NULL != pctx->punread_messags) {
		eid_array_free(pctx->punread_messags);
	}
	if (0 != pctx->state_property) {
		mem_file_free(&pctx->f_state_stream);
	}
	proptag_array_free(pctx->pproptags);
	if (NULL != pctx->prestriction) {
		restriction_free(pctx->prestriction);
	}
}

BOOL icsdownctx_object::begin_state_stream(uint32_t new_state_prop)
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (0 != pctx->state_property) {
		return FALSE;
	}
	switch (new_state_prop) {
	case MetaTagIdsetGiven:
	case MetaTagIdsetGiven1:
	case MetaTagCnsetSeen:
		break;
	case MetaTagCnsetSeenFAI:
	case MetaTagCnsetRead:
		if (SYNC_TYPE_CONTENTS != pctx->sync_type) {
			return FALSE;
		}
		break;
	default:
		return FALSE;
	}
	pctx->state_property = new_state_prop;
	mem_file_init(&pctx->f_state_stream, common_util_get_allocator());
	return TRUE;
}

BOOL icsdownctx_object::continue_state_stream(const BINARY *pstream_data)
{
	auto pctx = this;
	if (pctx->b_started)
		return FALSE;
	if (0 == pctx->state_property) {
		return FALSE;
	}
	return f_state_stream.write(pstream_data->pb, pstream_data->cb) ==
	       pstream_data->cb ? TRUE : false;
}

BOOL icsdownctx_object::end_state_stream()
{
	auto pctx = this;
	BINARY tmp_bin;
	
	if (pctx->b_started)
		return FALSE;
	if (0 == pctx->state_property) {
		return FALSE;
	}
	auto pset = idset::create(false, REPL_TYPE_GUID);
	if (pset == nullptr)
		return FALSE;
	tmp_bin.cb = pctx->f_state_stream.get_total_length();
	tmp_bin.pv = common_util_alloc(tmp_bin.cb);
	if (tmp_bin.pv == nullptr) {
		return FALSE;
	}
	pctx->f_state_stream.read(tmp_bin.pv, tmp_bin.cb);
	mem_file_free(&pctx->f_state_stream);
	auto saved_state_property = pctx->state_property;
	pctx->state_property = 0;
	if (!pset->deserialize(&tmp_bin))
		return FALSE;
	tmp_bin.cb = sizeof(void*);
	tmp_bin.pv = &pctx->pstream->plogon;
	if (!pset->register_mapping(&tmp_bin, common_util_mapping_replica))
		return FALSE;
	if (!pset->convert())
		return FALSE;
	if (!pctx->pstate->append_idset(saved_state_property, std::move(pset)))
		return FALSE;
	return TRUE;
}
