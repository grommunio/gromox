// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "attachment_object.h"
#include "fastupctx_object.h"
#include "emsmdb_interface.h"
#include "message_object.h"
#include <gromox/tpropval_array.hpp>
#include "folder_object.h"
#include "exmdb_client.h"
#include "common_util.h"
#include <gromox/tarray_set.hpp>
#include <gromox/rop_util.hpp>
#include <cstdlib>

namespace {

struct MARKER_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t marker;
	union {
		void *pelement;
		uint32_t instance_id;
		uint64_t folder_id;
	} data;
};

}

std::unique_ptr<FASTUPCTX_OBJECT> fastupctx_object_create(
	LOGON_OBJECT *plogon, void *pobject, int root_element)
{
	std::unique_ptr<FASTUPCTX_OBJECT> pctx;
	try {
		pctx = std::make_unique<FASTUPCTX_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pctx->pobject = pobject;
	pctx->b_ended = FALSE;
	pctx->root_element = root_element;
	pctx->pstream = ftstream_parser_create(plogon);
	if (NULL == pctx->pstream) {
		return NULL;
	}
	pctx->pproplist = NULL;
	pctx->pmsgctnt = NULL;
	switch (root_element) {
	case ROOT_ELEMENT_FOLDERCONTENT:
		pctx->pproplist = tpropval_array_init();
		if (NULL == pctx->pproplist) {
			return NULL;
		}
		break;
	case ROOT_ELEMENT_TOPFOLDER:
	case ROOT_ELEMENT_MESSAGECONTENT:
	case ROOT_ELEMENT_ATTACHMENTCONTENT:
	case ROOT_ELEMENT_MESSAGELIST:
		break;
	default:
		return NULL;
	}
	double_list_init(&pctx->marker_stack);
	return pctx;
}

FASTUPCTX_OBJECT::~FASTUPCTX_OBJECT()
{
	auto pctx = this;
	DOUBLE_LIST_NODE *pnode;
	
	ftstream_parser_free(pctx->pstream);
	if (NULL != pctx->pproplist) {
		tpropval_array_free(pctx->pproplist);
	}
	if (NULL != pctx->pmsgctnt) {
		message_content_free(pctx->pmsgctnt);
	}
	while ((pnode = double_list_pop_front(&pctx->marker_stack)) != nullptr)
		free(pnode->pdata);
	double_list_free(&pctx->marker_stack);
}

static uint64_t fastupctx_object_get_last_folder(
	FASTUPCTX_OBJECT *pctx)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_tail(&pctx->marker_stack); NULL!=pnode;
		pnode=double_list_get_before(&pctx->marker_stack, pnode)) {
		if (STARTSUBFLD == ((MARKER_NODE*)pnode->pdata)->marker) {
			return ((MARKER_NODE*)pnode->pdata)->data.folder_id;
		}
	}
	return folder_object_get_id(static_cast<FOLDER_OBJECT *>(pctx->pobject));
	;
}

static uint32_t fastupctx_object_get_last_attachment_instance(
	FASTUPCTX_OBJECT *pctx)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_tail(&pctx->marker_stack); NULL!=pnode;
		pnode=double_list_get_before(&pctx->marker_stack, pnode)) {
		if (NEWATTACH == ((MARKER_NODE*)pnode->pdata)->marker) {
			return ((MARKER_NODE*)pnode->pdata)->data.instance_id;
		}
	}
	return attachment_object_get_instance_id(static_cast<ATTACHMENT_OBJECT *>(pctx->pobject));
}

static uint32_t fastupctx_object_get_last_message_instance(
	FASTUPCTX_OBJECT *pctx)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_tail(&pctx->marker_stack); NULL!=pnode;
		pnode=double_list_get_before(&pctx->marker_stack, pnode)) {
		if (STARTEMBED == ((MARKER_NODE*)pnode->pdata)->marker) {
			return ((MARKER_NODE*)pnode->pdata)->data.instance_id;
		}
	}
	return message_object_get_instance_id(static_cast<MESSAGE_OBJECT *>(pctx->pobject));
}

static BOOL fastupctx_object_create_folder(
	FASTUPCTX_OBJECT *pctx, uint64_t parent_id,
	TPROPVAL_ARRAY *pproplist, uint64_t *pfolder_id)
{
	XID tmp_xid;
	BINARY *pbin;
	uint64_t tmp_id;
	BINARY *pentryid;
	uint32_t tmp_type;
	uint64_t change_num;
	uint32_t permission;
	TAGGED_PROPVAL propval;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	static constexpr uint32_t tags[] = {
		PR_ACCESS, PR_ACCESS_LEVEL, PROP_TAG_ADDRESSBOOKENTRYID,
		PROP_TAG_ASSOCIATEDCONTENTCOUNT, PROP_TAG_ATTRIBUTEREADONLY,
		PROP_TAG_CONTENTCOUNT, PROP_TAG_CONTENTUNREADCOUNT,
		PROP_TAG_DELETEDCOUNTTOTAL, PROP_TAG_DELETEDFOLDERTOTAL,
		PROP_TAG_ARTICLENUMBERNEXT, PROP_TAG_INTERNETARTICLENUMBER,
		PR_DISPLAY_TYPE, PROP_TAG_DELETEDON, PR_ENTRYID,
		PROP_TAG_FOLDERCHILDCOUNT, PROP_TAG_FOLDERFLAGS, PROP_TAG_FOLDERID,
		PROP_TAG_FOLDERTYPE, PROP_TAG_HASRULES, PROP_TAG_HIERARCHYCHANGENUMBER,
		PROP_TAG_LOCALCOMMITTIME, PROP_TAG_LOCALCOMMITTIMEMAX,
		PR_MESSAGE_SIZE, PR_MESSAGE_SIZE_EXTENDED, PROP_TAG_NATIVEBODY,
		PR_OBJECT_TYPE, PR_PARENT_ENTRYID, PR_RECORD_KEY,
		PROP_TAG_SEARCHKEY, PR_STORE_ENTRYID, PR_STORE_RECORD_KEY,
		PR_SOURCE_KEY, PR_PARENT_SOURCE_KEY,
	};
	for (auto t : tags)
		tpropval_array_remove_propval(pproplist, t);
	if (tpropval_array_get_propval(pproplist, PR_DISPLAY_NAME) == nullptr)
		return FALSE;
	propval.proptag = PROP_TAG_FOLDERTYPE;
	propval.pvalue = &tmp_type;
	tmp_type = FOLDER_TYPE_GENERIC;
	if (!tpropval_array_set_propval(pproplist, &propval))
		return FALSE;
	propval.proptag = PROP_TAG_PARENTFOLDERID;
	propval.pvalue = &parent_id;
	if (!tpropval_array_set_propval(pproplist, &propval))
		return FALSE;
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(pctx->pstream->plogon),
		&change_num)) {
		return FALSE;
	}
	propval.proptag = PROP_TAG_CHANGENUMBER;
	propval.pvalue = &change_num;
	if (!tpropval_array_set_propval(pproplist, &propval))
		return FALSE;
	tmp_xid.guid = logon_object_guid(pctx->pstream->plogon);
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin) {
		return FALSE;
	}
	propval.proptag = PR_CHANGE_KEY;
	propval.pvalue = pbin;
	if (!tpropval_array_set_propval(pproplist, &propval))
		return FALSE;
	auto pbin1 = static_cast<BINARY *>(tpropval_array_get_propval(pproplist,
	             PR_PREDECESSOR_CHANGE_LIST));
	propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval.pvalue = common_util_pcl_append(pbin1, pbin);
	if (NULL == propval.pvalue) {
		return FALSE;
	}
	if (!tpropval_array_set_propval(pproplist, &propval))
		return FALSE;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_create_folder_by_properties(
		logon_object_get_dir(pctx->pstream->plogon),
		pinfo->cpid, pproplist, pfolder_id) ||
		0 == *pfolder_id) {
		return FALSE;
	}
	if (LOGON_MODE_OWNER != logon_object_get_mode(
		pctx->pstream->plogon)) {
		auto rpc_info = get_rpc_info();
		pentryid = common_util_username_to_addressbook_entryid(
											rpc_info.username);
		if (NULL != pentryid) {
			tmp_id = 1;
			permission = PERMISSION_FOLDEROWNER|PERMISSION_READANY|
						PERMISSION_FOLDERVISIBLE|PERMISSION_CREATE|
						PERMISSION_EDITANY|PERMISSION_DELETEANY|
						PERMISSION_CREATESUBFOLDER;
			permission_row.flags = PERMISSION_DATA_FLAG_ADD_ROW;
			permission_row.propvals.count = 3;
			permission_row.propvals.ppropval = propval_buff;
			propval_buff[0].proptag = PR_ENTRYID;
			propval_buff[0].pvalue = pentryid;
			propval_buff[1].proptag = PROP_TAG_MEMBERID;
			propval_buff[1].pvalue = &tmp_id;
			propval_buff[2].proptag = PROP_TAG_MEMBERRIGHTS;
			propval_buff[2].pvalue = &permission;
			exmdb_client_update_folder_permission(
				logon_object_get_dir(pctx->pstream->plogon),
				*pfolder_id, FALSE, 1, &permission_row);
		}
	}
	return TRUE;
}

static BOOL fastupctx_object_empty_folder(
	FASTUPCTX_OBJECT *pctx, uint64_t folder_id,
	BOOL b_normal, BOOL b_fai, BOOL b_sub)
{
	BOOL b_partial;
	const char *username;
	DCERPC_INFO rpc_info;
	
	if (LOGON_MODE_OWNER == logon_object_get_mode(
		pctx->pstream->plogon)) {
		username = NULL;	
	} else {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (FALSE == exmdb_client_empty_folder(logon_object_get_dir(
		pctx->pstream->plogon), pinfo->cpid, username, folder_id,
		TRUE, b_normal, b_fai, b_sub, &b_partial)) {
		return FALSE;	
	}
	if (TRUE == b_partial) {
		return FALSE;
	}
	return TRUE;
}

static gxerr_t
fastupctx_object_write_message(FASTUPCTX_OBJECT *pctx, uint64_t folder_id)
{
	XID tmp_xid;
	BINARY *pbin;
	uint64_t change_num;
	TAGGED_PROPVAL propval;
	TPROPVAL_ARRAY *pproplist;
	
	pproplist = message_content_get_proplist(pctx->pmsgctnt);
	static constexpr uint32_t tags[] = {
		PROP_TAG_CONVERSATIONID, PR_DISPLAY_TO, PR_DISPLAY_TO_A,
		PR_DISPLAY_CC, PR_DISPLAY_CC_A, PR_DISPLAY_BCC,
		PR_DISPLAY_BCC_A, PROP_TAG_MID, PR_MESSAGE_SIZE,
		PR_MESSAGE_SIZE_EXTENDED, PROP_TAG_HASNAMEDPROPERTIES,
		PROP_TAG_HASATTACHMENTS, PR_ENTRYID, PROP_TAG_FOLDERID,
		PR_OBJECT_TYPE, PR_PARENT_ENTRYID, PR_STORE_RECORD_KEY,
	};
	for (auto t : tags)
		tpropval_array_remove_propval(pproplist, t);
	if (FALSE == exmdb_client_allocate_cn(
		logon_object_get_dir(pctx->pstream->plogon),
		&change_num)) {
		return GXERR_CALL_FAILED;
	}
	propval.proptag = PROP_TAG_CHANGENUMBER;
	propval.pvalue = &change_num;
	if (!tpropval_array_set_propval(pproplist, &propval))
		return GXERR_CALL_FAILED;
	tmp_xid.guid = logon_object_guid(pctx->pstream->plogon);
	rop_util_get_gc_array(change_num, tmp_xid.local_id);
	pbin = common_util_xid_to_binary(22, &tmp_xid);
	if (NULL == pbin) {
		return GXERR_CALL_FAILED;
	}
	propval.proptag = PR_CHANGE_KEY;
	propval.pvalue = pbin;
	if (!tpropval_array_set_propval(pproplist, &propval))
		return GXERR_CALL_FAILED;
	auto pbin1 = static_cast<BINARY *>(tpropval_array_get_propval(pproplist,
	             PR_PREDECESSOR_CHANGE_LIST));
	propval.proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval.pvalue = common_util_pcl_append(pbin1, pbin);
	if (NULL == propval.pvalue) {
		return GXERR_CALL_FAILED;
	}
	if (!tpropval_array_set_propval(pproplist, &propval))
		return GXERR_CALL_FAILED;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	gxerr_t e_result = GXERR_CALL_FAILED;
	if (!exmdb_client_write_message(logon_object_get_dir(pctx->pstream->plogon),
	    logon_object_get_account(pctx->pstream->plogon), pinfo->cpid,
	    folder_id, pctx->pmsgctnt, &e_result) || e_result != GXERR_SUCCESS)
		return e_result;
	return GXERR_SUCCESS;
}

static gxerr_t fastupctx_object_record_marker(FASTUPCTX_OBJECT *pctx,
    uint32_t marker)
{
	uint32_t tmp_id;
	uint32_t tmp_num;
	TARRAY_SET *prcpts;
	uint64_t folder_id;
	uint32_t instance_id;
	TARRAY_SET tmp_rcpts;
	MARKER_NODE *pmarker;
	TAGGED_PROPVAL propval;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	MESSAGE_CONTENT *pmsgctnt = nullptr;
	TPROPVAL_ARRAY *pproplist, *prcpt = nullptr;
	PROBLEM_ARRAY tmp_problems;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment = nullptr;
	
	pnode = double_list_get_tail(&pctx->marker_stack);
	uint32_t last_marker = pnode == nullptr ? 0 : static_cast<MARKER_NODE *>(pnode->pdata)->marker;
	switch (last_marker) {
	case STARTSUBFLD: {
		if (NULL == pctx->pproplist) {
			break;
		}
		if (0 == pctx->pproplist->count) {
			return GXERR_CALL_FAILED;
		}
		pnode1 = double_list_get_before(&pctx->marker_stack, pnode);
		uint64_t parent_id = pnode1 == nullptr ?
		                     folder_object_get_id(static_cast<FOLDER_OBJECT *>(pctx->pobject)) :
		                     static_cast<MARKER_NODE *>(pnode1->pdata)->data.folder_id;
		if (FALSE == fastupctx_object_create_folder(pctx,
			parent_id, pctx->pproplist, &folder_id)) {
			return GXERR_CALL_FAILED;
		}
		tpropval_array_free(pctx->pproplist);
		pctx->pproplist = NULL;
		((MARKER_NODE*)pnode->pdata)->data.folder_id = folder_id;
		break;
	}
	case STARTTOPFLD:
		if (NULL == pctx->pproplist) {
			break;
		}
		if (pctx->pproplist->count > 0) {
			if (!folder_object_set_properties(static_cast<FOLDER_OBJECT *>(pctx->pobject),
			    pctx->pproplist, &tmp_problems))
				return GXERR_CALL_FAILED;
		}
		tpropval_array_free(pctx->pproplist);
		pctx->pproplist = NULL;
		break;
	case 0:
		if (ROOT_ELEMENT_FOLDERCONTENT == pctx->root_element) {
			if (NULL == pctx->pproplist) {
				break;
			}
			if (pctx->pproplist->count > 0) {
				if (!folder_object_set_properties(static_cast<FOLDER_OBJECT *>(pctx->pobject),
				    pctx->pproplist, &tmp_problems))
					return GXERR_CALL_FAILED;
			}
			tpropval_array_free(pctx->pproplist);
			pctx->pproplist = NULL;
		}
		break;
	}
	switch (marker) {
	case STARTTOPFLD:
		if (ROOT_ELEMENT_TOPFOLDER !=
			pctx->root_element || 0 != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (NULL != pctx->pproplist) {
			return GXERR_CALL_FAILED;
		}
		pctx->pproplist = tpropval_array_init();
		if (NULL == pctx->pproplist) {
			return GXERR_CALL_FAILED;
		}
		pmarker = me_alloc<MARKER_NODE>();
		if (NULL == pmarker) {
			return GXERR_CALL_FAILED;
		}
		pmarker->node.pdata = pmarker;
		pmarker->marker = marker;
		break;
	case STARTSUBFLD:
		if (ROOT_ELEMENT_TOPFOLDER != pctx->root_element &&
			ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element) {
			return GXERR_CALL_FAILED;
		}
		if (NULL != pctx->pproplist) {
			return GXERR_CALL_FAILED;
		}
		pctx->pproplist = tpropval_array_init();
		if (NULL == pctx->pproplist) {
			return GXERR_CALL_FAILED;
		}
		pmarker = me_alloc<MARKER_NODE>();
		if (NULL == pmarker) {
			return GXERR_CALL_FAILED;
		}
		pmarker->node.pdata = pmarker;
		pmarker->marker = marker;
		break;
	case ENDFOLDER:
		if (STARTTOPFLD != last_marker &&
			STARTSUBFLD != last_marker) {
			return GXERR_CALL_FAILED;
		}
		double_list_remove(&pctx->marker_stack, pnode);
		free(pnode->pdata);
		if (STARTTOPFLD == last_marker) {
			/* mark fast stream ended */
			pctx->b_ended = TRUE;
		}
		return GXERR_SUCCESS;
	case STARTFAIMSG:
	case STARTMESSAGE: {
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGELIST:
			if (0 != last_marker) {
				return GXERR_CALL_FAILED;
			}
			break;
		case ROOT_ELEMENT_TOPFOLDER:
			if (STARTTOPFLD != last_marker &&
				STARTSUBFLD != last_marker) {
				return GXERR_CALL_FAILED;
			}
			break;
		case ROOT_ELEMENT_FOLDERCONTENT:
			break;
		default:
			return GXERR_CALL_FAILED;
		}
		if (NULL != pctx->pmsgctnt) {
			return GXERR_CALL_FAILED;
		}
		pctx->pmsgctnt = message_content_init();
		if (NULL == pctx->pmsgctnt) {
			return GXERR_CALL_FAILED;
		}
		prcpts = tarray_set_init();
		if (NULL == prcpts) {
			return GXERR_CALL_FAILED;
		}
		message_content_set_rcpts_internal(pctx->pmsgctnt, prcpts);
		pattachments = attachment_list_init();
		if (NULL == pattachments) {
			return GXERR_CALL_FAILED;
		}
		message_content_set_attachments_internal(
					pctx->pmsgctnt, pattachments);
		pproplist = message_content_get_proplist(pctx->pmsgctnt);
		propval.proptag = PROP_TAG_ASSOCIATED;
		uint8_t tmp_byte = marker == STARTFAIMSG;
		propval.pvalue = &tmp_byte;
		if (!tpropval_array_set_propval(pproplist, &propval))
			return GXERR_CALL_FAILED;
		pmarker = me_alloc<MARKER_NODE>();
		if (NULL == pmarker) {
			return GXERR_CALL_FAILED;
		}
		pmarker->node.pdata = pmarker;
		pmarker->marker = marker;
		pmarker->data.pelement = pctx->pmsgctnt;
		break;
	}
	case ENDMESSAGE: {
		if (STARTMESSAGE != last_marker &&
			STARTFAIMSG != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (NULL == pctx->pmsgctnt || pctx->pmsgctnt !=
			((MARKER_NODE*)pnode->pdata)->data.pelement) {
			return GXERR_CALL_FAILED;
		}
		double_list_remove(&pctx->marker_stack, pnode);
		free(pnode->pdata);
		folder_id = fastupctx_object_get_last_folder(pctx);
		gxerr_t err = fastupctx_object_write_message(pctx, folder_id);
		if (err != GXERR_SUCCESS)
			return err;
		message_content_free(pctx->pmsgctnt);
		pctx->pmsgctnt = NULL;
		return GXERR_SUCCESS;
	}
	case STARTRECIP:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
			case STARTEMBED:
				break;
			default:
				return GXERR_CALL_FAILED;
			}
			break;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			if (STARTEMBED != last_marker) {
				return GXERR_CALL_FAILED;
			}
			break;
		default:
			if (STARTMESSAGE != last_marker &&
				STARTFAIMSG != last_marker &&
				STARTEMBED != last_marker) {
				return GXERR_CALL_FAILED;
			}
			break;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			if (NULL != pctx->pproplist) {
				return GXERR_CALL_FAILED;
			}
			pctx->pproplist = tpropval_array_init();
			if (NULL == pctx->pproplist) {
				return GXERR_CALL_FAILED;
			}
		} else {
			prcpt = tpropval_array_init();
			if (NULL == prcpt) {
				return GXERR_CALL_FAILED;
			}
			pmsgctnt = static_cast<MESSAGE_CONTENT *>(static_cast<MARKER_NODE *>(pnode->pdata)->data.pelement);
			if (!tarray_set_append_internal(pmsgctnt->children.prcpts, prcpt)) {
				tpropval_array_free(prcpt);
				return GXERR_CALL_FAILED;
			}
		}
		pmarker = me_alloc<MARKER_NODE>();
		if (NULL == pmarker) {
			return GXERR_CALL_FAILED;
		}
		pmarker->node.pdata = pmarker;
		pmarker->marker = marker;
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			pmarker->data.instance_id =
				fastupctx_object_get_last_message_instance(pctx);
		} else {
			pmarker->data.pelement = prcpt;
		}
		break;
	case ENDTORECIP:
		if (STARTRECIP != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			tmp_rcpts.count = 1;
			tmp_rcpts.pparray = &pctx->pproplist;
			if (FALSE == exmdb_client_update_message_instance_rcpts(
				logon_object_get_dir(pctx->pstream->plogon),
				((MARKER_NODE*)pnode->pdata)->data.instance_id,
				&tmp_rcpts)) {
				return GXERR_CALL_FAILED;
			}
			tpropval_array_free(pctx->pproplist);
			pctx->pproplist = NULL;
		}
		double_list_remove(&pctx->marker_stack, pnode);
		free(pnode->pdata);
		return GXERR_SUCCESS;
	case NEWATTACH:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
			case STARTEMBED:
				break;
			default:
				return GXERR_CALL_FAILED;
			}
			break;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			if (STARTEMBED != last_marker) {
				return GXERR_CALL_FAILED;
			}
			break;
		default:
			if (STARTMESSAGE != last_marker &&
				STARTFAIMSG != last_marker &&
				STARTEMBED != last_marker) {
				return GXERR_CALL_FAILED;
			}
			break;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			instance_id = fastupctx_object_get_last_message_instance(pctx);
			if (FALSE == exmdb_client_create_attachment_instance(
				logon_object_get_dir(pctx->pstream->plogon),
				instance_id, &tmp_id, &tmp_num) || 0 == tmp_id) {
				return GXERR_CALL_FAILED;
			}
		} else {
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				return GXERR_CALL_FAILED;
			}
			pmsgctnt = static_cast<MESSAGE_CONTENT *>(static_cast<MARKER_NODE *>(pnode->pdata)->data.pelement);
			if (FALSE == attachment_list_append_internal(
				pmsgctnt->children.pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return GXERR_CALL_FAILED;
			}
		}
		pmarker = me_alloc<MARKER_NODE>();
		if (NULL == pmarker) {
			return GXERR_CALL_FAILED;
		}
		pmarker->node.pdata = pmarker;
		pmarker->marker = marker;
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			pmarker->data.instance_id = tmp_id;
		} else {
			pmarker->data.pelement = pattachment;
		}
		break;
	case ENDATTACH:
		if (NEWATTACH != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			gxerr_t e_result = GXERR_CALL_FAILED;
			if (!exmdb_client_flush_instance(logon_object_get_dir(pctx->pstream->plogon),
			    static_cast<MARKER_NODE *>(pnode->pdata)->data.instance_id,
			    nullptr, &e_result) || e_result != GXERR_SUCCESS)
				return e_result;
			if (FALSE == exmdb_client_unload_instance(
				logon_object_get_dir(pctx->pstream->plogon),
				((MARKER_NODE*)pnode->pdata)->data.instance_id)) {
				return GXERR_CALL_FAILED;
			}
		}
		double_list_remove(&pctx->marker_stack, pnode);
		free(pnode->pdata);
		return GXERR_SUCCESS;
	case STARTEMBED:
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
				if (NEWATTACH != last_marker) {
					return GXERR_CALL_FAILED;
				}
			} else {
				if (0 != last_marker && NEWATTACH != last_marker) {
					return GXERR_CALL_FAILED;
				}
			}
			instance_id = fastupctx_object_get_last_attachment_instance(pctx);
			if (FALSE == exmdb_client_load_embedded_instance(
				logon_object_get_dir(pctx->pstream->plogon),
				FALSE, instance_id, &tmp_id)) {
				return GXERR_CALL_FAILED;
			}
			if (0 == tmp_id) {
				if (FALSE == exmdb_client_load_embedded_instance(
					logon_object_get_dir(pctx->pstream->plogon),
					TRUE, instance_id, &tmp_id) || 0 == tmp_id) {
					return GXERR_CALL_FAILED;
				}
			} else {
				if (FALSE == exmdb_client_clear_message_instance(
					logon_object_get_dir(pctx->pstream->plogon),
					instance_id)) {
					return GXERR_CALL_FAILED;
				}
			}
		} else {
			if (NEWATTACH != last_marker) {
				return GXERR_CALL_FAILED;
			}
			pmsgctnt = message_content_init();
			if (NULL == pmsgctnt) {
				return GXERR_CALL_FAILED;
			}
			prcpts = tarray_set_init();
			if (NULL == prcpts) {
				message_content_free(pmsgctnt);
				return GXERR_CALL_FAILED;
			}
			message_content_set_rcpts_internal(pmsgctnt, prcpts);
			pattachments = attachment_list_init();
			if (NULL == pattachments) {
				message_content_free(pmsgctnt);
				return GXERR_CALL_FAILED;
			}
			message_content_set_attachments_internal(
							pmsgctnt, pattachments);
			attachment_content_set_embedded_internal(
				static_cast<ATTACHMENT_CONTENT *>(static_cast<MARKER_NODE *>(pnode->pdata)->data.pelement),
				pmsgctnt);
		}
		pmarker = me_alloc<MARKER_NODE>();
		if (NULL == pmarker) {
			return GXERR_CALL_FAILED;
		}
		pmarker->node.pdata = pmarker;
		pmarker->marker = marker;
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			pmarker->data.instance_id = tmp_id;
		} else {
			pmarker->data.pelement = pmsgctnt;
		}
		break;
	case ENDEMBED:
		if (STARTEMBED != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			gxerr_t e_result = GXERR_CALL_FAILED;
			if (!exmdb_client_flush_instance(logon_object_get_dir(pctx->pstream->plogon),
			    static_cast<MARKER_NODE *>(pnode->pdata)->data.instance_id,
			    nullptr, &e_result) || e_result != GXERR_SUCCESS)
				return e_result;
			if (FALSE == exmdb_client_unload_instance(
				logon_object_get_dir(pctx->pstream->plogon),
				((MARKER_NODE*)pnode->pdata)->data.instance_id)) {
				return GXERR_CALL_FAILED;
			}
		}
		double_list_remove(&pctx->marker_stack, pnode);
		free(pnode->pdata);
		return GXERR_SUCCESS;
	case FXERRORINFO:
		/* we do not support this feature */
		return GXERR_CALL_FAILED;
	default:
		return GXERR_CALL_FAILED;
	}
	double_list_append_as_tail(&pctx->marker_stack, &pmarker->node);
	return GXERR_SUCCESS;
}

static BOOL fastupctx_object_del_props(
	FASTUPCTX_OBJECT *pctx, uint32_t marker)
{
	int instance_id;
	DOUBLE_LIST_NODE *pnode;
	MESSAGE_CONTENT *pmsgctnt;
	
	pnode = double_list_get_tail(&pctx->marker_stack);
	uint32_t last_marker = pnode == nullptr ? 0 : static_cast<MARKER_NODE *>(pnode->pdata)->marker;
	switch (marker) {
	case PROP_TAG_MESSAGERECIPIENTS:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
				instance_id =
					fastupctx_object_get_last_message_instance(pctx);
				if (FALSE == exmdb_client_empty_message_instance_rcpts(
					logon_object_get_dir(pctx->pstream->plogon),
					instance_id)) {
					return FALSE;	
				}
			case STARTEMBED:
				break;
			default:
				return FALSE;
			}
			break;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			if (STARTEMBED != last_marker) {
				return FALSE;
			}
			break;
		default:
			if (STARTMESSAGE != last_marker &&
				STARTFAIMSG != last_marker &&
				STARTEMBED != last_marker) {
				return FALSE;	
			}
			pmsgctnt = static_cast<MESSAGE_CONTENT *>(static_cast<MARKER_NODE *>(pnode->pdata)->data.pelement);
			if (0 != pmsgctnt->children.prcpts->count) {
				return FALSE;
			}
			break;
		}
		break;
	case PROP_TAG_MESSAGEATTACHMENTS:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
				if (FALSE == exmdb_client_empty_message_instance_attachments(
					logon_object_get_dir(pctx->pstream->plogon),
					fastupctx_object_get_last_message_instance(pctx))) {
					return FALSE;
				}
				break;
			case STARTEMBED:
				break;
			default:
				return FALSE;
			}
			break;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			if (STARTEMBED != last_marker) {
				return FALSE;
			}
			break;
		default:
			if (STARTMESSAGE != last_marker &&
				STARTFAIMSG != last_marker &&
				STARTEMBED != last_marker) {
				return FALSE;	
			}
			pmsgctnt = static_cast<MESSAGE_CONTENT *>(static_cast<MARKER_NODE *>(pnode->pdata)->data.pelement);
			if (0 != pmsgctnt->children.pattachments->count) {
				return FALSE;
			}
			break;
		}
		break;
	case PROP_TAG_CONTAINERCONTENTS:
		if (ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element ||
			(STARTSUBFLD != last_marker && 0 != last_marker)) {
			return FALSE;	
		}
		if (0 == last_marker) {
			if (!fastupctx_object_empty_folder(pctx,
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pctx->pobject)),
			    TRUE, FALSE, FALSE))
				return FALSE;	
		}
		break;
	case PROP_TAG_FOLDERASSOCIATEDCONTENTS:
		if (ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element ||
			(STARTSUBFLD != last_marker && 0 != last_marker)) {
			return FALSE;	
		}
		if (0 == last_marker) {
			if (fastupctx_object_empty_folder(pctx,
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pctx->pobject)),
			    FALSE, TRUE, FALSE))
				return FALSE;	
		}
		break;
	case PROP_TAG_CONTAINERHIERARCHY:
		if (ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element ||
			(STARTSUBFLD != last_marker && 0 != last_marker)) {
			return FALSE;	
		}
		if (0 == last_marker) {
			if (!fastupctx_object_empty_folder(pctx,
			    folder_object_get_id(static_cast<FOLDER_OBJECT *>(pctx->pobject)),
			    FALSE, FALSE, TRUE))
				return FALSE;	
		}
		break;
	}
	return TRUE;
}

static gxerr_t fastupctx_object_record_propval(FASTUPCTX_OBJECT *pctx,
    const TAGGED_PROPVAL *ppropval)
{
	uint32_t b_result;
	DOUBLE_LIST_NODE *pnode;
	
	switch (ppropval->proptag) {
	case META_TAG_FXDELPROP:
		switch (*(uint32_t*)ppropval->pvalue) {
		case PROP_TAG_MESSAGERECIPIENTS:
		case PROP_TAG_MESSAGEATTACHMENTS:
		case PROP_TAG_CONTAINERCONTENTS:
		case PROP_TAG_FOLDERASSOCIATEDCONTENTS:
		case PROP_TAG_CONTAINERHIERARCHY:
			return fastupctx_object_del_props(pctx,
			       *static_cast<uint32_t *>(ppropval->pvalue)) == TRUE ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		default:
			return GXERR_CALL_FAILED;
		}
	case META_TAG_DNPREFIX:
	case META_TAG_ECWARNING:
		return GXERR_SUCCESS;
	case META_TAG_NEWFXFOLDER:
	case META_TAG_INCRSYNCGROUPID:
	case META_TAG_INCREMENTALSYNCMESSAGEPARTIAL:
	case META_TAG_IDSETGIVEN:
	case META_TAG_IDSETGIVEN1:
	case META_TAG_CNSETSEEN:
	case META_TAG_CNSETSEENFAI:
	case META_TAG_CNSETREAD:
	case META_TAG_IDSETDELETED:
	case META_TAG_IDSETNOLONGERINSCOPE:
	case META_TAG_IDSETEXPIRED:
	case META_TAG_IDSETREAD:
	case META_TAG_IDSETUNREAD:
		return GXERR_CALL_FAILED;
	}
	pnode = double_list_get_tail(&pctx->marker_stack);
	uint32_t last_marker = pnode != nullptr ? static_cast<MARKER_NODE *>(pnode->pdata)->marker : 0;
	if (PROP_TYPE(ppropval->proptag) == PT_OBJECT) {
		if (NEWATTACH == last_marker || (0 == last_marker &&
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element)) {
			if (ppropval->proptag != PR_ATTACH_DATA_OBJ)
				return GXERR_CALL_FAILED;
		} else {
			return GXERR_CALL_FAILED;
		}
	}
	switch (last_marker) {
	case 0:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_FOLDERCONTENT:
			return tpropval_array_set_propval(pctx->pproplist, ppropval) ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		case ROOT_ELEMENT_MESSAGECONTENT:
			return exmdb_client_set_instance_property(
					logon_object_get_dir(pctx->pstream->plogon),
			       message_object_get_instance_id(static_cast<MESSAGE_OBJECT *>(pctx->pobject)),
					ppropval, &b_result) == TRUE ?
					GXERR_SUCCESS : GXERR_CALL_FAILED;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			return exmdb_client_set_instance_property(
					logon_object_get_dir(pctx->pstream->plogon),
			       attachment_object_get_instance_id(static_cast<ATTACHMENT_OBJECT *>(pctx->pobject)),
					ppropval, &b_result) == TRUE ?
					GXERR_SUCCESS : GXERR_CALL_FAILED;
		case ROOT_ELEMENT_MESSAGELIST:
		case ROOT_ELEMENT_TOPFOLDER:
			return GXERR_CALL_FAILED;
		}
		return GXERR_CALL_FAILED;
	case STARTTOPFLD:
	case STARTSUBFLD:
		return tpropval_array_set_propval(pctx->pproplist, ppropval) ?
		       GXERR_SUCCESS : GXERR_CALL_FAILED;
	case STARTMESSAGE:
	case STARTFAIMSG: {
		auto mknd = static_cast<MARKER_NODE *>(pnode->pdata);
		auto tp = static_cast<TPROPVAL_ARRAY *>(mknd->data.pelement);
		return tpropval_array_set_propval(tp, ppropval) ?
				GXERR_SUCCESS : GXERR_CALL_FAILED;
	}
	case STARTEMBED:
	case NEWATTACH: {
		auto mknd = static_cast<MARKER_NODE *>(pnode->pdata);
		auto tp = static_cast<TPROPVAL_ARRAY *>(mknd->data.pelement);
		if (ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element ||
			ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
			return exmdb_client_set_instance_property(
					logon_object_get_dir(pctx->pstream->plogon),
					mknd->data.instance_id,
					ppropval, &b_result) == TRUE ?
					GXERR_SUCCESS : GXERR_CALL_FAILED;
		} else {
			return tpropval_array_set_propval(tp, ppropval) ?
					GXERR_SUCCESS : GXERR_CALL_FAILED;
		}
	}
	case STARTRECIP: {
		auto mknd = static_cast<MARKER_NODE *>(pnode->pdata);
		auto tp = static_cast<TPROPVAL_ARRAY *>(mknd->data.pelement);
		if (ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element ||
			ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
			return tpropval_array_set_propval(pctx->pproplist, ppropval) ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		} else {
			return tpropval_array_set_propval(tp, ppropval) ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		}
	}
	default:
		return GXERR_CALL_FAILED;
	}
}

gxerr_t fastupctx_object_write_buffer(FASTUPCTX_OBJECT *pctx,
    const BINARY *ptransfer_data)
{
	/* check if the fast stream is marked as ended */
	if (TRUE == pctx->b_ended) {
		return GXERR_CALL_FAILED;
	}
	if (FALSE == ftstream_parser_write_buffer(
		pctx->pstream, ptransfer_data)) {
		return GXERR_CALL_FAILED;
	}
	return ftstream_parser_process(pctx->pstream,
	       fastupctx_object_record_marker,
	       fastupctx_object_record_propval, pctx);
}
