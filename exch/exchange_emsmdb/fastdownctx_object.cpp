// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "fastdownctx_object.h"
#include "emsmdb_interface.h"
#include <gromox/tpropval_array.hpp>
#include "exmdb_client.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include <gromox/eid_array.hpp>
#include <cstdlib>
#include <cstring>

enum {
	FUNC_ID_UINT32,
	FUNC_ID_PROPLIST,
	FUNC_ID_MESSAGE
};

namespace {

struct FAST_FLOW_NODE {
	DOUBLE_LIST_NODE node;
	uint8_t func_id;
	void *pparam;
};

}

static BOOL fastdownctx_object_record_subfoldernodelprops(
	DOUBLE_LIST *pflow_list, const FOLDER_CONTENT *pfldctnt);

static BOOL fastdownctx_object_record_subfolder(
	DOUBLE_LIST *pflow_list, const FOLDER_CONTENT *pfldctnt);

static BOOL fastdownctx_object_record_flow_node(
	DOUBLE_LIST *pflow_list, int func_id, void *pparam)
{
	auto pflow = me_alloc<FAST_FLOW_NODE>();
	if (NULL == pflow) {
		return FALSE;
	}
	pflow->node.pdata = pflow;
	pflow->func_id = func_id;
	pflow->pparam = pparam;
	double_list_append_as_tail(pflow_list, &pflow->node);
	return TRUE;
}

static BOOL fastdownctx_object_record_messagelist(
	DOUBLE_LIST *pflow_list, EID_ARRAY *pmsglst)
{
	for (size_t i = 0; i < pmsglst->count; ++i) {
		if (FALSE == fastdownctx_object_record_flow_node(
			pflow_list, FUNC_ID_MESSAGE, pmsglst->pids + i)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL fastdownctx_object_record_foldermessages(
	DOUBLE_LIST *pflow_list, const FOLDER_MESSAGES *pfldmsgs)
{	
	if (NULL != pfldmsgs->pfai_msglst) {
		if (FALSE == fastdownctx_object_record_flow_node(
			pflow_list, FUNC_ID_UINT32, (void*)META_TAG_FXDELPROP)) {
			return FALSE;
		}
		if (FALSE == fastdownctx_object_record_flow_node(pflow_list,
			FUNC_ID_UINT32, (void*)PROP_TAG_FOLDERASSOCIATEDCONTENTS)) {
			return FALSE;
		}
		if (FALSE == fastdownctx_object_record_messagelist(
			pflow_list, pfldmsgs->pfai_msglst)) {
			return FALSE;
		}
	}
	if (NULL != pfldmsgs->pnormal_msglst) {
		if (FALSE == fastdownctx_object_record_flow_node(
			pflow_list, FUNC_ID_UINT32, (void*)META_TAG_FXDELPROP)) {
			return FALSE;
		}
		if (FALSE == fastdownctx_object_record_flow_node(pflow_list,
			FUNC_ID_UINT32, (void*)PROP_TAG_CONTAINERCONTENTS)) {
			return FALSE;
		}
		if (FALSE == fastdownctx_object_record_messagelist(
			pflow_list, pfldmsgs->pnormal_msglst)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL fastdownctx_object_record_foldermessagesnodelprops(
	DOUBLE_LIST *pflow_list, const FOLDER_MESSAGES *pfldmsgs)
{
	if (NULL != pfldmsgs->pfai_msglst) {
		if (FALSE == fastdownctx_object_record_messagelist(
			pflow_list, pfldmsgs->pfai_msglst)) {
			return FALSE;
		}
	}
	if (NULL != pfldmsgs->pnormal_msglst) {
		if (FALSE == fastdownctx_object_record_messagelist(
			pflow_list, pfldmsgs->pnormal_msglst)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL fastdownctx_object_record_foldercontent(
	DOUBLE_LIST *pflow_list, const FOLDER_CONTENT *pfldctnt)
{
	if (NULL != common_util_get_propvals(
		(TPROPVAL_ARRAY*)&pfldctnt->proplist,
		META_TAG_NEWFXFOLDER)) {
		return fastdownctx_object_record_flow_node(
						pflow_list, FUNC_ID_PROPLIST,
						(void*)&pfldctnt->proplist);
	}
	if (FALSE == fastdownctx_object_record_flow_node(
		pflow_list, FUNC_ID_PROPLIST, (void*)&pfldctnt->proplist)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_foldermessages(
		pflow_list, &pfldctnt->fldmsgs)) {
		return FALSE;	
	}
	if (FALSE == fastdownctx_object_record_flow_node(pflow_list,
		FUNC_ID_UINT32, (void*)META_TAG_FXDELPROP)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_flow_node(pflow_list,
		FUNC_ID_UINT32, (void*)PROP_TAG_CONTAINERHIERARCHY)) {
		return FALSE;
	}
	for (const auto &f : pfldctnt->psubflds)
		if (!fastdownctx_object_record_subfolder(pflow_list, &f))
			return FALSE;	
	return TRUE;
}

static BOOL fastdownctx_object_record_foldercontentnodelprops(
	DOUBLE_LIST *pflow_list, const FOLDER_CONTENT *pfldctnt)
{
	if (FALSE == fastdownctx_object_record_flow_node(
		pflow_list, FUNC_ID_PROPLIST, (void*)&pfldctnt->proplist)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_foldermessagesnodelprops(
		pflow_list, &pfldctnt->fldmsgs)) {
		return FALSE;
	}
	for (const auto &f : pfldctnt->psubflds)
		if (!fastdownctx_object_record_subfoldernodelprops(pflow_list, &f))
			return FALSE;
	return TRUE;
}

static BOOL fastdownctx_object_record_subfoldernodelprops(
	DOUBLE_LIST *pflow_list, const FOLDER_CONTENT *pfldctnt)
{
	if (FALSE == fastdownctx_object_record_flow_node(
		pflow_list, FUNC_ID_UINT32, (void*)STARTSUBFLD)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_foldercontentnodelprops(
		pflow_list, pfldctnt)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_flow_node(
		pflow_list, FUNC_ID_UINT32, (void*)ENDFOLDER)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL fastdownctx_object_record_subfolder(
	DOUBLE_LIST *pflow_list, const FOLDER_CONTENT *pfldctnt)
{
	if (FALSE == fastdownctx_object_record_flow_node(
		pflow_list, FUNC_ID_UINT32, (void*)STARTSUBFLD)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_foldercontent(
		pflow_list, pfldctnt)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_flow_node(
		pflow_list, FUNC_ID_UINT32, (void*)ENDFOLDER)) {
		return FALSE;
	}
	return TRUE;
}

BOOL FASTDOWNCTX_OBJECT::make_messagecontent(MESSAGE_CONTENT *pmsgctnt)
{
	auto pctx = this;
	if (!pctx->pstream->write_messagecontent(false, pmsgctnt))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	return TRUE;
}

BOOL FASTDOWNCTX_OBJECT::make_attachmentcontent(ATTACHMENT_CONTENT *pattachment)
{
	auto pctx = this;
	if (!pctx->pstream->write_attachmentcontent(false, pattachment))
		return FALSE;	
	pctx->progress_steps = 0;
	pctx->total_steps = pctx->pstream->total_length();
	return TRUE;
}

BOOL FASTDOWNCTX_OBJECT::make_state(ICS_STATE *pstate)
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

BOOL FASTDOWNCTX_OBJECT::make_foldercontent(BOOL b_subfolders,
    std::unique_ptr<FOLDER_CONTENT> &&fc)
{
	auto pctx = this;
	DOUBLE_LIST_NODE *pnode;
	
	if (!fastdownctx_object_record_flow_node(&pctx->flow_list,
	    FUNC_ID_PROPLIST, &fc->proplist))
		return FALSE;
	if (!fastdownctx_object_record_foldermessages(&pctx->flow_list, &fc->fldmsgs))
		return FALSE;	
	if (TRUE == b_subfolders) {
		if (FALSE == fastdownctx_object_record_flow_node(
			&pctx->flow_list, FUNC_ID_UINT32,
			(void*)META_TAG_FXDELPROP)) {
			return FALSE;
		}
		if (FALSE == fastdownctx_object_record_flow_node(
			&pctx->flow_list, FUNC_ID_UINT32,
			(void*)PROP_TAG_CONTAINERHIERARCHY)) {
			return FALSE;
		}
		for (const auto &f : fc->psubflds)
			if (!fastdownctx_object_record_subfolder(&pctx->flow_list, &f))
				return FALSE;	
	}
	pctx->pfldctnt = std::move(fc);
	pctx->progress_steps = 0;
	pctx->total_steps = 0;
	for (pnode=double_list_get_head(&pctx->flow_list); NULL!=pnode;
		pnode=double_list_get_after(&pctx->flow_list, pnode)) {
		if (FUNC_ID_MESSAGE == ((FAST_FLOW_NODE*)
			pnode->pdata)->func_id) {
			pctx->total_steps ++;
		}
	}
	return TRUE;
}
	
BOOL FASTDOWNCTX_OBJECT::make_topfolder(std::unique_ptr<FOLDER_CONTENT> &&fc)
{
	auto pctx = this;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == fastdownctx_object_record_flow_node(
		&pctx->flow_list, FUNC_ID_UINT32, (void*)STARTTOPFLD)) {
		return FALSE;
	}
	if (!fastdownctx_object_record_foldercontentnodelprops(&pctx->flow_list, fc.get()))
		return FALSE;
	if (FALSE == fastdownctx_object_record_flow_node(
		&pctx->flow_list, FUNC_ID_UINT32, (void*)ENDFOLDER)) {
		return FALSE;
	}
	pctx->pfldctnt = std::move(fc);
	pctx->progress_steps = 0;
	pctx->total_steps = 0;
	for (pnode=double_list_get_head(&pctx->flow_list); NULL!=pnode;
		pnode=double_list_get_after(&pctx->flow_list, pnode)) {
		if (FUNC_ID_MESSAGE == ((FAST_FLOW_NODE*)
			pnode->pdata)->func_id) {
			pctx->total_steps ++;
		}
	}
	return TRUE;
}

BOOL FASTDOWNCTX_OBJECT::make_messagelist(BOOL chginfo, EID_ARRAY *msglst)
{
	auto pctx = this;
	DOUBLE_LIST_NODE *pnode;
	
	if (!fastdownctx_object_record_messagelist(&pctx->flow_list, msglst))
		return FALSE;
	pctx->b_chginfo = chginfo;
	pctx->pmsglst = msglst;
	pctx->progress_steps = 0;
	pctx->total_steps = 0;
	for (pnode=double_list_get_head(&pctx->flow_list); NULL!=pnode;
		pnode=double_list_get_after(&pctx->flow_list, pnode)) {
		if (FUNC_ID_MESSAGE == ((FAST_FLOW_NODE*)
			pnode->pdata)->func_id) {
			pctx->total_steps ++;
		}
	}
	return TRUE;
}

static BOOL fastdownctx_object_get_buffer_internal(
	FASTDOWNCTX_OBJECT *pctx, void *pbuff,
	uint16_t *plen, BOOL *pb_last)
{
	BOOL b_last;
	uint16_t len;
	uint16_t len1;
	FAST_FLOW_NODE *pflow;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTENT *pmsgctnt;
	
	if (0 == double_list_get_nodes_num(&pctx->flow_list)) {
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
		if (FALSE == b_last || *plen - len <
			2*FTSTREAM_PRODUCER_POINT_LENGTH) {
			*plen = len;
			*pb_last = FALSE;
			return TRUE;
		}
	}
	len1 = *plen - len;
	while ((pnode = double_list_pop_front(&pctx->flow_list)) != nullptr) {
		pflow = (FAST_FLOW_NODE*)pnode->pdata;
		switch (pflow->func_id) {
		case FUNC_ID_UINT32:
			if (!pctx->pstream->write_uint32(reinterpret_cast<uintptr_t>(pflow->pparam))) {
				free(pnode->pdata);
				return FALSE;
			}
			break;
		case FUNC_ID_PROPLIST:
			if (!pctx->pstream->write_proplist(static_cast<TPROPVAL_ARRAY *>(pflow->pparam))) {
				free(pnode->pdata);
				return FALSE;
			}
			break;
		case FUNC_ID_MESSAGE: {
			auto pinfo = emsmdb_interface_get_emsmdb_info();
			if (pctx->pstream->plogon->check_private()) {
				if (!exmdb_client_read_message(pctx->pstream->plogon->get_dir(),
				    nullptr, pinfo->cpid,
				    *static_cast<uint64_t *>(pflow->pparam), &pmsgctnt)) {
					free(pnode->pdata);
					return FALSE;
				}
			} else {
				auto rpc_info = get_rpc_info();
				if (!exmdb_client_read_message(pctx->pstream->plogon->get_dir(),
				    rpc_info.username, pinfo->cpid,
				    *static_cast<uint64_t *>(pflow->pparam), &pmsgctnt)) {
					free(pnode->pdata);
					return FALSE;
				}
			}
			if (NULL == pmsgctnt) {
				continue;
			}
			if (NULL == pctx->pmsglst) {
				if (FALSE == pctx->b_chginfo) {
					static constexpr uint32_t tags[] = {
						PR_ENTRYID, PR_SOURCE_KEY,
						PR_CHANGE_KEY,
						PROP_TAG_ORIGINALENTRYID,
						PR_LAST_MODIFICATION_TIME,
						PR_PREDECESSOR_CHANGE_LIST,
					};
					for (auto t : tags)
						common_util_remove_propvals(&pmsgctnt->proplist, t);
				} else {
					common_util_remove_propvals(&pmsgctnt->proplist,
										PROP_TAG_ORIGINALENTRYID);
					common_util_retag_propvals(&pmsgctnt->proplist,
						PR_ENTRYID, PROP_TAG_ORIGINALENTRYID);
				}
			} else {
				common_util_remove_propvals(&pmsgctnt->proplist, PR_ENTRYID);
			}
			if (!pctx->pstream->write_message(pmsgctnt)) {
				free(pnode->pdata);
				return FALSE;
			}
			pctx->progress_steps ++;
			break;
		}
		default:
			free(pnode->pdata);
			return FALSE;
		}
		free(pnode->pdata);
		if (pctx->pstream->total_length() > len1)
			break;
	}
	if (!pctx->pstream->read_buffer(static_cast<char *>(pbuff) + len, &len1, &b_last))
		return FALSE;
	*plen = len + len1;
	*pb_last = double_list_get_nodes_num(&pctx->flow_list) == 0 && b_last ? TRUE : false;
	return TRUE;
}

BOOL FASTDOWNCTX_OBJECT::get_buffer(void *pbuff, uint16_t *plen, BOOL *pb_last,
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
	if (TRUE == *pb_last) {
		*pprogress = *ptotal;
	}
	return TRUE;
}

std::unique_ptr<FASTDOWNCTX_OBJECT> fastdownctx_object_create(
	LOGON_OBJECT *plogon, uint8_t string_option)
{
	std::unique_ptr<FASTDOWNCTX_OBJECT> pctx;
	try {
		pctx = std::make_unique<FASTDOWNCTX_OBJECT>();
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1453: ENOMEM\n");
		return NULL;
	}
	pctx->pstream = ftstream_producer_create(
						plogon, string_option);
	if (NULL == pctx->pstream) {
		return NULL;
	}
	double_list_init(&pctx->flow_list);
	pctx->pmsglst = NULL;
	return pctx;
}

FASTDOWNCTX_OBJECT::~FASTDOWNCTX_OBJECT()
{
	auto pctx = this;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(&pctx->flow_list)) != nullptr)
		free(pnode->pdata);
	double_list_free(&pctx->flow_list);
	if (NULL != pctx->pmsglst) {
		eid_array_free(pctx->pmsglst);
	}
}
