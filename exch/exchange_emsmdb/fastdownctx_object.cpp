// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
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
	for (size_t i = 0; i < pfldctnt->count; ++i) {
		if (FALSE == fastdownctx_object_record_subfolder(
			pflow_list, pfldctnt->psubflds + i)) {
			return FALSE;	
		}
	}
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
	for (size_t i = 0; i < pfldctnt->count; ++i) {
		if (FALSE == fastdownctx_object_record_subfoldernodelprops(
			pflow_list, pfldctnt->psubflds + i)) {
			return FALSE;
		}
	}
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

BOOL fastdownctx_object_make_messagecontent(
	FASTDOWNCTX_OBJECT *pctx, MESSAGE_CONTENT *pmsgctnt)
{
	if (FALSE == ftstream_producer_write_messagecontent(
		pctx->pstream, FALSE, pmsgctnt)) {
		return FALSE;	
	}
	pctx->progress_steps = 0;
	pctx->total_steps = ftstream_producer_total_length(pctx->pstream);
	return TRUE;
}

BOOL fastdownctx_object_make_attachmentcontent(
	FASTDOWNCTX_OBJECT *pctx,
	ATTACHMENT_CONTENT *pattachment)
{
	if (FALSE == ftstream_producer_write_attachmentcontent(
		pctx->pstream, FALSE, pattachment)) {
		return FALSE;	
	}
	pctx->progress_steps = 0;
	pctx->total_steps = ftstream_producer_total_length(pctx->pstream);
	return TRUE;
}

BOOL fastdownctx_object_make_state(
	FASTDOWNCTX_OBJECT *pctx, ICS_STATE *pstate)
{
	TPROPVAL_ARRAY *pproplist;
	
	pproplist = ics_state_serialize(pstate);
	if (NULL == pproplist) {
		return FALSE;
	}
	if (FALSE == ftstream_producer_write_state(
		pctx->pstream, pproplist)) {
		tpropval_array_free(pproplist);
		return FALSE;	
	}
	tpropval_array_free(pproplist);
	pctx->progress_steps = 0;
	pctx->total_steps = ftstream_producer_total_length(pctx->pstream);
	return TRUE;
}

BOOL fastdownctx_object_make_foldercontent(
	FASTDOWNCTX_OBJECT *pctx,
	BOOL b_subfolders, FOLDER_CONTENT *pfldctnt)
{
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == fastdownctx_object_record_flow_node(
		&pctx->flow_list, FUNC_ID_PROPLIST,
		(void*)&pfldctnt->proplist)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_foldermessages(
		&pctx->flow_list, &pfldctnt->fldmsgs)) {
		return FALSE;	
	}
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
		for (size_t i = 0; i < pfldctnt->count; ++i) {
			if (FALSE == fastdownctx_object_record_subfolder(
				&pctx->flow_list, pfldctnt->psubflds + i)) {
				return FALSE;	
			}
		}
	}
	pctx->pfldctnt = pfldctnt;
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
	
BOOL fastdownctx_object_make_topfolder(
	FASTDOWNCTX_OBJECT *pctx, FOLDER_CONTENT *pfldctnt)
{
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == fastdownctx_object_record_flow_node(
		&pctx->flow_list, FUNC_ID_UINT32, (void*)STARTTOPFLD)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_foldercontentnodelprops(
		&pctx->flow_list, pfldctnt)) {
		return FALSE;
	}
	if (FALSE == fastdownctx_object_record_flow_node(
		&pctx->flow_list, FUNC_ID_UINT32, (void*)ENDFOLDER)) {
		return FALSE;
	}
	pctx->pfldctnt = pfldctnt;
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

BOOL fastdownctx_object_make_messagelist(
	FASTDOWNCTX_OBJECT *pctx,
	BOOL b_chginfo, EID_ARRAY *pmsglst)
{
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == fastdownctx_object_record_messagelist(
		&pctx->flow_list, pmsglst)) {
		return FALSE;
	}
	pctx->b_chginfo = b_chginfo;
	pctx->pmsglst = pmsglst;
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
	EMSMDB_INFO *pinfo;
	DCERPC_INFO rpc_info;
	FAST_FLOW_NODE *pflow;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTENT *pmsgctnt;
	
	if (0 == double_list_get_nodes_num(&pctx->flow_list)) {
		if (FALSE == ftstream_producer_read_buffer(
			pctx->pstream, pbuff, plen, pb_last)) {
			return FALSE;	
		}
		if (NULL == pctx->pmsglst && NULL == pctx->pfldctnt) {
			pctx->progress_steps += *plen;
		}
		return TRUE;
	}
	len = 0;
	if (ftstream_producer_total_length(pctx->pstream) > 0) {
		len = *plen;
		if (FALSE == ftstream_producer_read_buffer(
			pctx->pstream, pbuff, &len, &b_last)) {
			return FALSE;	
		}
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
			if (FALSE == ftstream_producer_write_uint32(pctx->pstream,
				(uint32_t)(unsigned long)pflow->pparam)) {
				free(pnode->pdata);
				return FALSE;
			}
			break;
		case FUNC_ID_PROPLIST:
			if (!ftstream_producer_write_proplist(pctx->pstream,
			    static_cast<TPROPVAL_ARRAY *>(pflow->pparam))) {
				free(pnode->pdata);
				return FALSE;
			}
			break;
		case FUNC_ID_MESSAGE:
			pinfo = emsmdb_interface_get_emsmdb_info();
			if (TRUE == logon_object_check_private(
				pctx->pstream->plogon)) {
				if (FALSE == exmdb_client_read_message(
					logon_object_get_dir(pctx->pstream->plogon),
					NULL, pinfo->cpid, *(uint64_t*)pflow->pparam,
					&pmsgctnt)) {
					free(pnode->pdata);
					return FALSE;
				}
			} else {
				rpc_info = get_rpc_info();
				if (FALSE == exmdb_client_read_message(
					logon_object_get_dir(pctx->pstream->plogon),
					rpc_info.username, pinfo->cpid,
					*(uint64_t*)pflow->pparam, &pmsgctnt)) {
					free(pnode->pdata);
					return FALSE;
				}
			}
			if (NULL == pmsgctnt) {
				continue;
			}
			if (NULL == pctx->pmsglst) {
				if (FALSE == pctx->b_chginfo) {
					common_util_remove_propvals(&pmsgctnt->proplist,
												PROP_TAG_ENTRYID);
					common_util_remove_propvals(&pmsgctnt->proplist,
												PROP_TAG_SOURCEKEY);
					common_util_remove_propvals(&pmsgctnt->proplist,
												PROP_TAG_CHANGEKEY);
					common_util_remove_propvals(&pmsgctnt->proplist,
										PROP_TAG_ORIGINALENTRYID);
					common_util_remove_propvals(&pmsgctnt->proplist,
									PROP_TAG_LASTMODIFICATIONTIME);
					common_util_remove_propvals(&pmsgctnt->proplist,
									PROP_TAG_PREDECESSORCHANGELIST);
				} else {
					common_util_remove_propvals(&pmsgctnt->proplist,
										PROP_TAG_ORIGINALENTRYID);
					common_util_retag_propvals(&pmsgctnt->proplist,
						PROP_TAG_ENTRYID, PROP_TAG_ORIGINALENTRYID);
				}
			} else {
				common_util_remove_propvals(
						&pmsgctnt->proplist, PROP_TAG_ENTRYID);
			}
			if (FALSE == ftstream_producer_write_message(
				pctx->pstream, pmsgctnt)) {
				free(pnode->pdata);
				return FALSE;
			}
			pctx->progress_steps ++;
			break;
		default:
			free(pnode->pdata);
			return FALSE;
		}
		free(pnode->pdata);
		if (ftstream_producer_total_length(
			pctx->pstream) > len1) {
			break;
		}
	}
	if (!ftstream_producer_read_buffer(pctx->pstream,
	    static_cast<char *>(pbuff) + len, &len1, &b_last))
		return FALSE;
	*plen = len + len1;
	*pb_last = double_list_get_nodes_num(&pctx->flow_list) == 0 && b_last ? TRUE : false;
	return TRUE;
}

BOOL fastdownctx_object_get_buffer(FASTDOWNCTX_OBJECT *pctx,
	void *pbuff, uint16_t *plen, BOOL *pb_last,
	uint16_t *pprogress, uint16_t *ptotal)
{
	uint16_t ratio;
	
	ratio = pctx->total_steps / 0xFFFF + 1;
	*ptotal = pctx->total_steps / ratio;
	if (0 == *ptotal) {
		*ptotal = 1;
	}
	if (FALSE == fastdownctx_object_get_buffer_internal(
		pctx, pbuff, plen, pb_last)) {
		return FALSE;	
	}
	*pprogress = pctx->progress_steps / ratio;
	if (TRUE == *pb_last) {
		*pprogress = *ptotal;
	}
	return TRUE;
}

FASTDOWNCTX_OBJECT* fastdownctx_object_create(
	LOGON_OBJECT *plogon, uint8_t string_option)
{
	auto pctx = me_alloc<FASTDOWNCTX_OBJECT>();
	if (NULL == pctx) {
		return NULL;
	}
	pctx->pstream = ftstream_producer_create(
						plogon, string_option);
	if (NULL == pctx->pstream) {
		free(pctx);
		return NULL;
	}
	double_list_init(&pctx->flow_list);
	pctx->pfldctnt = NULL;
	pctx->pmsglst = NULL;
	return pctx;
}

void fastdownctx_object_free(FASTDOWNCTX_OBJECT *pctx)
{
	DOUBLE_LIST_NODE *pnode;
	
	ftstream_producer_free(pctx->pstream);
	while ((pnode = double_list_pop_front(&pctx->flow_list)) != nullptr)
		free(pnode->pdata);
	double_list_free(&pctx->flow_list);
	if (NULL!= pctx->pfldctnt) {
		folder_content_free(pctx->pfldctnt);
	}
	if (NULL != pctx->pmsglst) {
		eid_array_free(pctx->pmsglst);
	}
	free(pctx);
}
