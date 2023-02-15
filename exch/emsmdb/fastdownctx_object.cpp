// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
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
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "fastdownctx_object.h"
#include "ftstream_producer.h"
#include "ics_state.h"
#include "logon_object.h"

using namespace gromox;

enum {
	FUNC_ID_UINT32,
	FUNC_ID_PROPLIST,
	FUNC_ID_MESSAGE
};

bool fxdown_flow_list::record_node(uint8_t func_id, const void *param) try
{
	emplace_back(func_id, param);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1599: ENOMEM");
	return false;
}

bool fxdown_flow_list::record_tag(uint32_t tag)
{
	static_assert(sizeof(void *) >= sizeof(tag));
	return record_node(FUNC_ID_UINT32, reinterpret_cast<void *>(static_cast<uintptr_t>(tag)));
}

bool fxdown_flow_list::record_messagelist(EID_ARRAY *pmsglst)
{
	for (size_t i = 0; i < pmsglst->count; ++i) {
		if (!record_node(FUNC_ID_MESSAGE, &pmsglst->pids[i]))
			return false;
	}
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
	if (NULL != pfldmsgs->pfai_msglst) {
		if (!record_messagelist(pfldmsgs->pfai_msglst))
			return false;
	}
	if (NULL != pfldmsgs->pnormal_msglst) {
		if (!record_messagelist(pfldmsgs->pnormal_msglst))
			return false;
	}
	return true;
}

bool fxdown_flow_list::record_foldercontent(const FOLDER_CONTENT *pfldctnt)
{
	if (pfldctnt->proplist.has(MetaTagNewFXFolder))
		return record_node(FUNC_ID_PROPLIST, &pfldctnt->proplist);
	if (!record_node(FUNC_ID_PROPLIST, &pfldctnt->proplist) ||
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
	if (!record_node(FUNC_ID_PROPLIST, &pfldctnt->proplist) ||
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

BOOL fastdownctx_object::make_messagecontent(MESSAGE_CONTENT *pmsgctnt)
{
	auto pctx = this;
	if (!pctx->pstream->write_messagecontent(false, pmsgctnt))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	return TRUE;
}

BOOL fastdownctx_object::make_attachmentcontent(ATTACHMENT_CONTENT *pattachment)
{
	auto pctx = this;
	if (!pctx->pstream->write_attachmentcontent(false, pattachment))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	return TRUE;
}

BOOL fastdownctx_object::make_state(ICS_STATE *pstate)
{
	auto pproplist = pstate->serialize();
	if (NULL == pproplist) {
		return FALSE;
	}
	auto pctx = this;
	if (!pctx->pstream->write_state(pproplist)) {
		tpropval_array_free(pproplist);
		return FALSE;	
	}
	tpropval_array_free(pproplist);
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	return TRUE;
}

static bool is_message(const flow_node &n) { return n.first == FUNC_ID_MESSAGE; }

BOOL fastdownctx_object::make_foldercontent(BOOL b_subfolders,
    std::unique_ptr<FOLDER_CONTENT> &&fc)
{
	auto pctx = this;
	
	if (!flow_list.record_node(FUNC_ID_PROPLIST, &fc->proplist) ||
	    !flow_list.record_foldermessages(&fc->fldmsgs))
		return FALSE;	
	if (b_subfolders) {
		if (!flow_list.record_tag(MetaTagFXDelProp) ||
		    !flow_list.record_tag(PR_CONTAINER_HIERARCHY))
			return FALSE;
		for (const auto &f : fc->psubflds)
			if (!flow_list.record_subfolder(&f))
				return FALSE;	
	}
	pctx->pfldctnt = std::move(fc);
	pctx->progress_steps = 0;
	total_steps = std::count_if(flow_list.cbegin(), flow_list.cend(), is_message);
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
	return TRUE;
}

static BOOL fastdownctx_object_get_buffer_internal(fastdownctx_object *pctx,
    void *pbuff, uint16_t *plen, BOOL *pb_last)
{
	BOOL b_last;
	uint16_t len;
	uint16_t len1;
	MESSAGE_CONTENT *pmsgctnt;
	
	if (pctx->flow_list.size() == 0) {
		if (!pctx->pstream->read_buffer(pbuff, plen, pb_last))
			return FALSE;	
		if (NULL == pctx->pmsglst && NULL == pctx->pfldctnt) {
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
	len1 = *plen - len;
	while (pctx->flow_list.size() > 0) {
		auto [func_id, param] = pctx->flow_list.front();
		pctx->flow_list.pop_front();
		switch (func_id) {
		case FUNC_ID_UINT32:
			if (!pctx->pstream->write_uint32(reinterpret_cast<uintptr_t>(param)))
				return FALSE;
			break;
		case FUNC_ID_PROPLIST:
			if (!pctx->pstream->write_proplist(static_cast<const TPROPVAL_ARRAY *>(param)))
				return FALSE;
			break;
		case FUNC_ID_MESSAGE: {
			auto pinfo = emsmdb_interface_get_emsmdb_info();
			auto dir = pctx->pstream->plogon->get_dir();
			if (pctx->pstream->plogon->is_private()) {
				if (!exmdb_client::read_message(dir, nullptr, pinfo->cpid,
				    *static_cast<const uint64_t *>(param), &pmsgctnt))
					return FALSE;
			} else {
				auto rpc_info = get_rpc_info();
				if (!exmdb_client::read_message(dir,
				    rpc_info.username, pinfo->cpid,
				    *static_cast<const uint64_t *>(param), &pmsgctnt))
					return FALSE;
			}
			if (NULL == pmsgctnt) {
				continue;
			}
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
			if (!pctx->pstream->write_message(pmsgctnt)) {
				return FALSE;
			}
			pctx->progress_steps ++;
			break;
		}
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

BOOL fastdownctx_object::get_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal)
{
	auto pctx = this;
	uint16_t ratio;
	
	ratio = pctx->total_steps / 0xFFFF + 1;
	*ptotal = pctx->total_steps / ratio;
	if (0 == *ptotal) {
		*ptotal = 1;
	}
	if (!fastdownctx_object_get_buffer_internal(this, pbuff, plen, pb_last))
		return FALSE;	
	*pprogress = pctx->progress_steps / ratio;
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
	pctx->pstream = ftstream_producer::create(plogon, string_option);
	if (pctx->pstream == nullptr)
		return NULL;
	return pctx;
}

fastdownctx_object::~fastdownctx_object()
{
	auto pctx = this;
	if (NULL != pctx->pmsglst) {
		eid_array_free(pctx->pmsglst);
	}
}
