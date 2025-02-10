// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <gromox/eid_array.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"
#include "fastdownctx_object.hpp"
#include "ftstream_producer.hpp"
#include "ics_state.hpp"
#include "logon_object.hpp"

using namespace gromox;

bool fxdown_flow_list::record_node(fxdown_flow_func func_id, uint64_t param) try
{
	emplace_back(func_id, param);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1599: ENOMEM");
	return false;
}

bool fxdown_flow_list::record_node(fxdown_flow_func func_id, const void *param)
{
	static_assert(sizeof(void *) <= sizeof(uint64_t));
	return record_node(func_id, reinterpret_cast<uintptr_t>(param));
}

bool fxdown_flow_list::record_messagelist(EID_ARRAY *pmsglst)
{
	for (uint64_t mid : *pmsglst)
		if (!record_node(fxdown_flow_func::msg_id, mid))
			return false;
	return true;
}

bool fxdown_flow_list::record_foldermessages(const FOLDER_MESSAGES *pfldmsgs)
{	
	if (NULL != pfldmsgs->pfai_msglst) {
		if (!record_tag(MetaTagFXDelProp) ||
		    !record_tag(PR_FOLDER_ASSOCIATED_CONTENTS) ||
		    !record_messagelist(pfldmsgs->pfai_msglst))
			return false;
	}
	if (NULL != pfldmsgs->pnormal_msglst) {
		if (!record_tag(MetaTagFXDelProp) ||
		    !record_tag(PR_CONTAINER_CONTENTS) ||
		    !record_messagelist(pfldmsgs->pnormal_msglst))
			return false;
	}
	return true;
}

bool fxdown_flow_list::record_foldermessagesnodelprops(const FOLDER_MESSAGES *pfldmsgs)
{
	if (pfldmsgs->pfai_msglst != nullptr &&
	    !record_messagelist(pfldmsgs->pfai_msglst))
		return false;
	if (pfldmsgs->pnormal_msglst != nullptr &&
	    !record_messagelist(pfldmsgs->pnormal_msglst))
		return false;
	return true;
}

bool fxdown_flow_list::record_foldercontent(const FOLDER_CONTENT *pfldctnt)
{
	if (pfldctnt->proplist.has(MetaTagNewFXFolder))
		return record_node(fxdown_flow_func::proplist_ptr, &pfldctnt->proplist);
	if (!record_node(fxdown_flow_func::proplist_ptr, &pfldctnt->proplist) ||
	    !record_foldermessages(&pfldctnt->fldmsgs) ||
	    !record_tag(MetaTagFXDelProp) ||
	    !record_tag(PR_CONTAINER_HIERARCHY))
		return false;
	for (const auto &f : pfldctnt->psubflds)
		if (!record_subfolder(&f))
			return false;
	return true;
}

bool fxdown_flow_list::record_foldercontentnodelprops(const FOLDER_CONTENT *pfldctnt)
{
	if (!record_node(fxdown_flow_func::proplist_ptr, &pfldctnt->proplist) ||
	    !record_foldermessagesnodelprops(&pfldctnt->fldmsgs))
		return false;
	for (const auto &f : pfldctnt->psubflds)
		if (!record_subfoldernodelprops(&f))
			return false;
	return true;
}

bool fxdown_flow_list::record_subfoldernodelprops(const FOLDER_CONTENT *pfldctnt)
{
	return record_tag(STARTSUBFLD) &&
	       record_foldercontentnodelprops(pfldctnt) &&
	       record_tag(ENDFOLDER);
}

bool fxdown_flow_list::record_subfolder(const FOLDER_CONTENT *pfldctnt)
{
	return record_tag(STARTSUBFLD) && record_foldercontent(pfldctnt) &&
	       record_tag(ENDFOLDER);
}

BOOL fastdownctx_object::make_messagecontent(const message_content *pmsgctnt)
{
	auto pctx = this;
	if (!pctx->pstream->write_messagecontent(false, pmsgctnt))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	divisor = fx_divisor(total_steps);
	return TRUE;
}

BOOL fastdownctx_object::make_attachmentcontent(const attachment_content *pattachment)
{
	auto pctx = this;
	if (!pctx->pstream->write_attachmentcontent(false, pattachment))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	divisor = fx_divisor(total_steps);
	return TRUE;
}

BOOL fastdownctx_object::make_state(ics_state *pstate)
{
	auto pproplist = pstate->serialize();
	if (pproplist == nullptr)
		return FALSE;
	auto pctx = this;
	if (!pctx->pstream->write_state(pproplist)) {
		tpropval_array_free(pproplist);
		return FALSE;	
	}
	tpropval_array_free(pproplist);
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	divisor = fx_divisor(total_steps);
	return TRUE;
}

static bool is_message(const fxdown_flow_node &n)
{
	return n.first == fxdown_flow_func::msg_id;
}

static bool fxs_tagcmp_fld(const TAGGED_PROPVAL &a, const TAGGED_PROPVAL &b)
{
	switch (b.proptag) {
	default:
		if (a.proptag < b.proptag) return true;
		if (a.proptag == MetaTagEcWarning) return true;
		[[fallthrough]];
	case MetaTagEcWarning:
		if (a.proptag == PR_COMMENT) return true;
		[[fallthrough]];
	case PR_COMMENT:
		if (a.proptag == PR_DISPLAY_NAME) return true;
		[[fallthrough]];
	case PR_DISPLAY_NAME:
		if (a.proptag == PidTagFolderId) return true;
		[[fallthrough]];
	case PidTagFolderId:
		return false;
	}
}

static bool fxs_tagcmp_msg(const TAGGED_PROPVAL &a, const TAGGED_PROPVAL &b)
{
	switch (b.proptag) {
	default:
		if (a.proptag < b.proptag) return true;
		if (a.proptag == PidTagMid) return true;
		[[fallthrough]];
	case PidTagMid:
		return false;
	}
}

static bool fxs_tagcmp_rcpt(const TAGGED_PROPVAL &a, const TAGGED_PROPVAL &b)
{
	switch (b.proptag) {
	default:
		if (a.proptag < b.proptag) return true;
		if (a.proptag == PR_ROWID) return true;
		[[fallthrough]];
	case PR_ROWID:
		return false;
	}
}

namespace emsmdb {

static void fxs_propsort(FOLDER_CONTENT &fc)
{
	auto &p = fc.proplist.ppropval;
	if (p != nullptr)
		std::sort(&p[0], &p[fc.proplist.count], fxs_tagcmp_fld);
}

void fxs_propsort(MESSAGE_CONTENT &mc)
{
	auto &mp = mc.proplist.ppropval;
	std::sort(&mp[0], &mp[mc.proplist.count], fxs_tagcmp_msg);

	if (mc.children.prcpts != nullptr) {
		for (auto &rc : *mc.children.prcpts) {
			auto &rp = rc.ppropval;
			std::sort(&rp[0], &rp[rc.count], fxs_tagcmp_rcpt);
		}
	}
	if (mc.children.pattachments != nullptr) {
		for (auto &at : *mc.children.pattachments) {
			auto e = at.pembedded;
			if (e != nullptr)
				fxs_propsort(*e);
		}
	}
}

}

BOOL fastdownctx_object::make_foldercontent(BOOL b_subfolders,
    std::unique_ptr<FOLDER_CONTENT> &&fc)
{
	auto pctx = this;
	
	fxs_propsort(*fc);
	if (!flow_list.record_node(fxdown_flow_func::proplist_ptr, &fc->proplist) ||
	    !flow_list.record_foldermessages(&fc->fldmsgs))
		return FALSE;	
	if (b_subfolders) {
		if (!flow_list.record_tag(MetaTagFXDelProp) ||
		    !flow_list.record_tag(PR_CONTAINER_HIERARCHY))
			return FALSE;
		for (auto &f : fc->psubflds) {
			fxs_propsort(f);
			if (!flow_list.record_subfolder(&f))
				return FALSE;
		}
	}
	pctx->pfldctnt = std::move(fc);
	pctx->progress_steps = 0;
	total_steps = std::count_if(flow_list.cbegin(), flow_list.cend(), is_message);
	divisor = fx_divisor(total_steps);
	return TRUE;
}
	
BOOL fastdownctx_object::make_topfolder(std::unique_ptr<FOLDER_CONTENT> &&fc)
{
	auto pctx = this;
	
	if (!flow_list.record_tag(STARTTOPFLD) ||
	    !flow_list.record_foldercontentnodelprops(fc.get()) ||
	    !flow_list.record_tag(ENDFOLDER))
		return FALSE;
	pctx->pfldctnt = std::move(fc);
	pctx->progress_steps = 0;
	total_steps = std::count_if(flow_list.cbegin(), flow_list.cend(), is_message);
	divisor = fx_divisor(total_steps);
	return TRUE;
}

BOOL fastdownctx_object::make_messagelist(BOOL chginfo, EID_ARRAY *msglst)
{
	auto pctx = this;
	
	if (!flow_list.record_messagelist(msglst))
		return FALSE;
	pctx->b_chginfo = chginfo;
	pctx->pmsglst = msglst;
	pctx->progress_steps = 0;
	total_steps = std::count_if(flow_list.cbegin(), flow_list.cend(), is_message);
	divisor = fx_divisor(total_steps);
	return TRUE;
}

static BOOL fastdownctx_object_get_buffer_internal(fastdownctx_object *pctx,
    void *pbuff, uint16_t *plen, BOOL *pb_last)
{
	BOOL b_last;
	uint16_t len;
	uint16_t len1;
	
	if (pctx->flow_list.size() == 0) {
		if (!pctx->pstream->read_buffer(pbuff, plen, pb_last))
			return FALSE;	
		if (pctx->pmsglst == nullptr && pctx->pfldctnt == nullptr)
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
	len1 = *plen - len;
	size_t funcs_processed = 0;
	for (auto [func_id, param] : pctx->flow_list) {
		switch (func_id) {
		case fxdown_flow_func::immed32:
			if (!pctx->pstream->write_uint32(param))
				return FALSE;
			break;
		case fxdown_flow_func::proplist_ptr:
			/* Property sorting done by make_foldercontent. */
			if (!pctx->pstream->write_proplist(static_cast<const TPROPVAL_ARRAY *>(reinterpret_cast<const void *>(static_cast<uintptr_t>(param)))))
				return FALSE;
			break;
		case fxdown_flow_func::msg_id: {
			MESSAGE_CONTENT *pmsgctnt = nullptr;
			auto pinfo = emsmdb_interface_get_emsmdb_info();
			auto dir = pctx->pstream->plogon->get_dir();
			if (!exmdb_client->read_message(dir, pctx->pstream->plogon->readstate_user(),
			    pinfo->cpid, param, &pmsgctnt))
				return FALSE;
			if (pmsgctnt == nullptr)
				continue;
			if (pctx->pmsglst != nullptr) {
				common_util_remove_propvals(&pmsgctnt->proplist, PR_ENTRYID);
			} else if (!pctx->b_chginfo) {
				static constexpr uint32_t tags[] = {
					PR_ENTRYID, PR_SOURCE_KEY,
					PR_CHANGE_KEY,
					PR_ORIGINAL_ENTRYID,
					PR_LAST_MODIFICATION_TIME,
					PR_PREDECESSOR_CHANGE_LIST,
				};
				for (auto t : tags)
					common_util_remove_propvals(&pmsgctnt->proplist, t);
			} else {
				common_util_remove_propvals(&pmsgctnt->proplist, PR_ORIGINAL_ENTRYID);
				common_util_retag_propvals(&pmsgctnt->proplist,
					PR_ENTRYID, PR_ORIGINAL_ENTRYID);
			}
			fxs_propsort(*pmsgctnt);
			if (!pctx->pstream->write_message(pmsgctnt))
				return FALSE;
			pctx->progress_steps ++;
			break;
		}
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

BOOL fastdownctx_object::get_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal)
{
	*ptotal = total_steps / divisor;
	if (*ptotal == 0)
		*ptotal = 1;
	if (!fastdownctx_object_get_buffer_internal(this, pbuff, plen, pb_last))
		return FALSE;	
	*pprogress = progress_steps / divisor;
	if (*pb_last)
		*pprogress = *ptotal;
	return TRUE;
}

std::unique_ptr<fastdownctx_object>
fastdownctx_object::create(logon_object *plogon, uint8_t string_option)
{
	std::unique_ptr<fastdownctx_object> pctx;
	try {
		pctx.reset(new fastdownctx_object);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1453: ENOMEM");
		return NULL;
	}
	pctx->pstream = fxstream_producer::create(plogon, string_option);
	if (pctx->pstream == nullptr)
		return NULL;
	return pctx;
}

fastdownctx_object::~fastdownctx_object()
{
	auto pctx = this;
	if (pctx->pmsglst != nullptr)
		eid_array_free(pctx->pmsglst);
}
