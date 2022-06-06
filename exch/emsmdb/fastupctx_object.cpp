// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "fastupctx_object.h"
#include "folder_object.h"
#include "ftstream_parser.h"
#include "logon_object.h"
#include "message_object.h"

std::unique_ptr<fastupctx_object> fastupctx_object::create(logon_object *plogon,
    void *pobject, int root_element)
{
	std::unique_ptr<fastupctx_object> pctx;
	try {
		pctx.reset(new fastupctx_object);
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1451: ENOMEM\n");
		return NULL;
	}
	pctx->pobject = pobject;
	pctx->root_element = root_element;
	pctx->pstream = ftstream_parser::create(plogon);
	if (pctx->pstream == nullptr)
		return NULL;
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
	return pctx;
}

fastupctx_object::~fastupctx_object()
{
	auto pctx = this;
	
	if (NULL != pctx->pproplist) {
		tpropval_array_free(pctx->pproplist);
	}
	if (NULL != pctx->pmsgctnt) {
		message_content_free(pctx->pmsgctnt);
	}
}

static uint64_t fastupctx_object_get_last_folder(fastupctx_object *pctx)
{
	for (auto node = pctx->marker_stack.rbegin();
	     node != pctx->marker_stack.rend(); ++node)
		if (node->marker == STARTSUBFLD)
			return node->folder_id;
	return static_cast<folder_object *>(pctx->pobject)->folder_id;
}

static uint32_t fastupctx_object_get_last_attachment_instance(fastupctx_object *pctx)
{
	for (auto node = pctx->marker_stack.rbegin();
	     node != pctx->marker_stack.rend(); ++node)
		if (node->marker == NEWATTACH)
			return node->instance_id;
	return static_cast<attachment_object *>(pctx->pobject)->get_instance_id();
}

static uint32_t fastupctx_object_get_last_message_instance(fastupctx_object *pctx)
{
	for (auto node = pctx->marker_stack.rbegin();
	     node != pctx->marker_stack.rend(); ++node)
		if (node->marker == STARTEMBED)
			return node->instance_id;
	return static_cast<message_object *>(pctx->pobject)->get_instance_id();
}

static BOOL fastupctx_object_create_folder(fastupctx_object *pctx,
    uint64_t parent_id, TPROPVAL_ARRAY *pproplist, uint64_t *pfolder_id)
{
	uint64_t tmp_id;
	BINARY *pentryid;
	uint32_t tmp_type;
	uint64_t change_num;
	uint32_t permission;
	PERMISSION_DATA permission_row;
	TAGGED_PROPVAL propval_buff[10];
	
	static constexpr uint32_t tags[] = {
		PR_ACCESS, PR_ACCESS_LEVEL, PR_ADDRESS_BOOK_ENTRYID,
		PR_ASSOC_CONTENT_COUNT, PR_ATTR_READONLY,
		PR_CONTENT_COUNT, PR_CONTENT_UNREAD,
		PR_DELETED_COUNT_TOTAL, PR_DELETED_FOLDER_COUNT,
		PR_INTERNET_ARTICLE_NUMBER_NEXT, PR_INTERNET_ARTICLE_NUMBER,
		PR_DISPLAY_TYPE, PR_DELETED_ON, PR_ENTRYID,
		PR_FOLDER_CHILD_COUNT, PR_FOLDER_FLAGS, PidTagFolderId,
		PR_FOLDER_TYPE, PR_HAS_RULES, PR_HIERARCHY_CHANGE_NUM,
		PR_LOCAL_COMMIT_TIME, PR_LOCAL_COMMIT_TIME_MAX,
		PR_MESSAGE_SIZE, PR_MESSAGE_SIZE_EXTENDED, PR_NATIVE_BODY_INFO,
		PR_OBJECT_TYPE, PR_PARENT_ENTRYID, PR_RECORD_KEY,
		PR_SEARCH_KEY, PR_STORE_ENTRYID, PR_STORE_RECORD_KEY,
		PR_SOURCE_KEY, PR_PARENT_SOURCE_KEY,
	};
	for (auto t : tags)
		pproplist->erase(t);
	if (!pproplist->has(PR_DISPLAY_NAME))
		return FALSE;
	tmp_type = FOLDER_GENERIC;
	if (pproplist->set(PR_FOLDER_TYPE, &tmp_type) != 0)
		return FALSE;
	if (pproplist->set(PidTagParentFolderId, &parent_id) != 0)
		return FALSE;
	if (!exmdb_client_allocate_cn(pctx->pstream->plogon->get_dir(), &change_num))
		return FALSE;
	if (pproplist->set(PidTagChangeNumber, &change_num) != 0)
		return FALSE;
	auto pbin = cu_xid_to_bin({pctx->pstream->plogon->guid(), change_num});
	if (NULL == pbin) {
		return FALSE;
	}
	if (pproplist->set(PR_CHANGE_KEY, pbin) != 0)
		return FALSE;
	auto pbin1 = pproplist->get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	auto newval = common_util_pcl_append(pbin1, pbin);
	if (newval == nullptr)
		return FALSE;
	if (pproplist->set(PR_PREDECESSOR_CHANGE_LIST, newval) != 0)
		return FALSE;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client_create_folder_by_properties(pctx->pstream->plogon->get_dir(),
	    pinfo->cpid, pproplist, pfolder_id) || *pfolder_id == 0)
		return FALSE;
	if (pctx->pstream->plogon->logon_mode == LOGON_MODE_OWNER)
		return TRUE;
	auto rpc_info = get_rpc_info();
	pentryid = common_util_username_to_addressbook_entryid(
										rpc_info.username);
	if (pentryid == nullptr)
		return TRUE;
	tmp_id = 1;
	permission = rightsGromox7;
	permission_row.flags = ROW_ADD;
	permission_row.propvals.count = 3;
	permission_row.propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PR_ENTRYID;
	propval_buff[0].pvalue = pentryid;
	propval_buff[1].proptag = PR_MEMBER_ID;
	propval_buff[1].pvalue = &tmp_id;
	propval_buff[2].proptag = PR_MEMBER_RIGHTS;
	propval_buff[2].pvalue = &permission;
	exmdb_client_update_folder_permission(pctx->pstream->plogon->get_dir(),
		*pfolder_id, FALSE, 1, &permission_row);
	return TRUE;
}

static BOOL fastupctx_object_empty_folder(fastupctx_object *pctx,
    uint64_t folder_id, BOOL b_normal, BOOL b_fai, BOOL b_sub)
{
	BOOL b_partial;
	const char *username;
	DCERPC_INFO rpc_info;
	
	if (pctx->pstream->plogon->logon_mode == LOGON_MODE_OWNER) {
		username = NULL;	
	} else {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client_empty_folder(pctx->pstream->plogon->get_dir(),
	    pinfo->cpid, username, folder_id, TRUE, b_normal, b_fai,
	    b_sub, &b_partial))
		return FALSE;	
	if (b_partial)
		return FALSE;
	return TRUE;
}

static gxerr_t
fastupctx_object_write_message(fastupctx_object *pctx, uint64_t folder_id)
{
	uint64_t change_num;
	TPROPVAL_ARRAY *pproplist;
	
	pproplist = message_content_get_proplist(pctx->pmsgctnt);
	static constexpr uint32_t tags[] = {
		PR_CONVERSATION_ID, PR_DISPLAY_TO, PR_DISPLAY_TO_A,
		PR_DISPLAY_CC, PR_DISPLAY_CC_A, PR_DISPLAY_BCC,
		PR_DISPLAY_BCC_A, PidTagMid, PR_MESSAGE_SIZE,
		PR_MESSAGE_SIZE_EXTENDED, PR_HAS_NAMED_PROPERTIES,
		PR_HASATTACH, PR_ENTRYID, PidTagFolderId,
		PR_OBJECT_TYPE, PR_PARENT_ENTRYID, PR_STORE_RECORD_KEY,
	};
	for (auto t : tags)
		pproplist->erase(t);
	if (!exmdb_client_allocate_cn(pctx->pstream->plogon->get_dir(), &change_num))
		return GXERR_CALL_FAILED;
	if (pproplist->set(PidTagChangeNumber, &change_num) != 0)
		return GXERR_CALL_FAILED;
	auto pbin = cu_xid_to_bin({pctx->pstream->plogon->guid(), change_num});
	if (NULL == pbin) {
		return GXERR_CALL_FAILED;
	}
	if (pproplist->set(PR_CHANGE_KEY, pbin) != 0)
		return GXERR_CALL_FAILED;
	auto pbin1 = pproplist->get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	auto pvalue = common_util_pcl_append(pbin1, pbin);
	if (pvalue == nullptr)
		return GXERR_CALL_FAILED;
	if (pproplist->set(PR_PREDECESSOR_CHANGE_LIST, pvalue) != 0)
		return GXERR_CALL_FAILED;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	gxerr_t e_result = GXERR_CALL_FAILED;
	if (!exmdb_client_write_message(pctx->pstream->plogon->get_dir(),
	    pctx->pstream->plogon->get_account(), pinfo->cpid,
	    folder_id, pctx->pmsgctnt, &e_result) || e_result != GXERR_SUCCESS)
		return e_result;
	return GXERR_SUCCESS;
}

gxerr_t fastupctx_object::record_marker(uint32_t marker)
{
	auto pctx = this;
	uint32_t tmp_id;
	uint32_t tmp_num;
	TARRAY_SET *prcpts;
	uint64_t folder_id;
	uint32_t instance_id;
	TARRAY_SET tmp_rcpts;
	fxup_marker_node new_mark{}, *pmarker = &new_mark;
	MESSAGE_CONTENT *pmsgctnt = nullptr;
	TPROPVAL_ARRAY *pproplist, *prcpt = nullptr;
	PROBLEM_ARRAY tmp_problems;
	ATTACHMENT_LIST *pattachments;
	ATTACHMENT_CONTENT *pattachment = nullptr;
	
	auto pnode = pctx->marker_stack.end();
	uint32_t last_marker = 0;
	if (pnode != pctx->marker_stack.begin()) {
		--pnode;
		last_marker = pnode->marker;
	}
	switch (last_marker) {
	case STARTSUBFLD: {
		if (NULL == pctx->pproplist) {
			break;
		}
		if (0 == pctx->pproplist->count) {
			return GXERR_CALL_FAILED;
		}
		uint64_t parent_id = pnode == pctx->marker_stack.begin() ?
		                     static_cast<folder_object *>(pctx->pobject)->folder_id :
		                     std::prev(pnode)->folder_id;
		if (!fastupctx_object_create_folder(pctx, parent_id,
		    pctx->pproplist, &folder_id))
			return GXERR_CALL_FAILED;
		tpropval_array_free(pctx->pproplist);
		pctx->pproplist = NULL;
		pnode->folder_id = folder_id;
		break;
	}
	case STARTTOPFLD:
		if (NULL == pctx->pproplist) {
			break;
		}
		if (pctx->pproplist->count > 0) {
			if (!static_cast<folder_object *>(pctx->pobject)->set_properties(pctx->pproplist, &tmp_problems))
				return GXERR_CALL_FAILED;
		}
		tpropval_array_free(pctx->pproplist);
		pctx->pproplist = NULL;
		break;
	case 0:
		if (pctx->root_element != ROOT_ELEMENT_FOLDERCONTENT)
			break;
		if (NULL == pctx->pproplist) {
			break;
		}
		if (pctx->pproplist->count > 0 &&
		    !static_cast<folder_object *>(pctx->pobject)->set_properties(pctx->pproplist, &tmp_problems))
			return GXERR_CALL_FAILED;
		tpropval_array_free(pctx->pproplist);
		pctx->pproplist = NULL;
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
		pmarker->marker = marker;
		break;
	case ENDFOLDER:
		if (STARTTOPFLD != last_marker &&
			STARTSUBFLD != last_marker) {
			return GXERR_CALL_FAILED;
		}
		pctx->marker_stack.erase(pnode);
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
		uint8_t tmp_byte = marker == STARTFAIMSG;
		if (pproplist->set(PR_ASSOCIATED, &tmp_byte) != 0)
			return GXERR_CALL_FAILED;
		pmarker->marker = marker;
		pmarker->msg = pctx->pmsgctnt;
		break;
	}
	case ENDMESSAGE: {
		if (STARTMESSAGE != last_marker &&
			STARTFAIMSG != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (pctx->pmsgctnt == nullptr || pctx->pmsgctnt != pnode->msg)
			return GXERR_CALL_FAILED;
		pctx->marker_stack.erase(pnode);
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
			pmsgctnt = pnode->msg;
			prcpt = pmsgctnt->children.prcpts->emplace();
			if (prcpt == nullptr)
				return GXERR_CALL_FAILED;
		}
		pmarker->marker = marker;
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			pmarker->instance_id = fastupctx_object_get_last_message_instance(pctx);
		} else {
			pmarker->props = prcpt;
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
			if (!exmdb_client_update_message_instance_rcpts(pctx->pstream->plogon->get_dir(),
			    pnode->instance_id, &tmp_rcpts))
				return GXERR_CALL_FAILED;
			tpropval_array_free(pctx->pproplist);
			pctx->pproplist = NULL;
		}
		pctx->marker_stack.erase(pnode);
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
			if (!exmdb_client_create_attachment_instance(pctx->pstream->plogon->get_dir(),
			    instance_id, &tmp_id, &tmp_num) || tmp_id == 0)
				return GXERR_CALL_FAILED;
		} else {
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				return GXERR_CALL_FAILED;
			}
			pmsgctnt = pnode->msg;
			if (!attachment_list_append_internal(pmsgctnt->children.pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return GXERR_CALL_FAILED;
			}
		}
		pmarker->marker = marker;
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			pmarker->instance_id = tmp_id;
		} else {
			pmarker->atx = pattachment;
		}
		break;
	case ENDATTACH:
		if (NEWATTACH != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			gxerr_t e_result = GXERR_CALL_FAILED;
			if (!exmdb_client_flush_instance(pctx->pstream->plogon->get_dir(),
			    pnode->instance_id, nullptr, &e_result) ||
			    e_result != GXERR_SUCCESS)
				return e_result;
			if (!exmdb_client_unload_instance(pctx->pstream->plogon->get_dir(),
			    pnode->instance_id))
				return GXERR_CALL_FAILED;
		}
		pctx->marker_stack.erase(pnode);
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
			if (!exmdb_client_load_embedded_instance(pctx->pstream->plogon->get_dir(),
			    false, instance_id, &tmp_id))
				return GXERR_CALL_FAILED;
			if (0 == tmp_id) {
				if (!exmdb_client_load_embedded_instance(pctx->pstream->plogon->get_dir(),
				    TRUE, instance_id, &tmp_id) || tmp_id == 0)
					return GXERR_CALL_FAILED;
			} else {
				if (!exmdb_client_clear_message_instance(pctx->pstream->plogon->get_dir(),
				    instance_id))
					return GXERR_CALL_FAILED;
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
			attachment_content_set_embedded_internal(pnode->atx, pmsgctnt);
		}
		pmarker->marker = marker;
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			pmarker->instance_id = tmp_id;
		} else {
			pmarker->msg = pmsgctnt;
		}
		break;
	case ENDEMBED:
		if (STARTEMBED != last_marker) {
			return GXERR_CALL_FAILED;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			gxerr_t e_result = GXERR_CALL_FAILED;
			if (!exmdb_client_flush_instance(pctx->pstream->plogon->get_dir(),
			    pnode->instance_id, nullptr, &e_result) ||
			    e_result != GXERR_SUCCESS)
				return e_result;
			if (!exmdb_client_unload_instance(pctx->pstream->plogon->get_dir(),
			    pnode->instance_id))
				return GXERR_CALL_FAILED;
		}
		pctx->marker_stack.erase(pnode);
		return GXERR_SUCCESS;
	case FXERRORINFO:
		/* we do not support this feature */
		return GXERR_CALL_FAILED;
	default:
		return GXERR_CALL_FAILED;
	}
	try {
		pctx->marker_stack.emplace_back(std::move(new_mark));
	} catch (const std::bad_alloc &) {
		fprintf(stderr, "E-1600: ENOMEM\n");
		return GXERR_CALL_FAILED;
	}
	return GXERR_SUCCESS;
}

static BOOL fastupctx_object_del_props(fastupctx_object *pctx, uint32_t marker)
{
	int instance_id;
	
	auto pnode = pctx->marker_stack.rbegin();
	auto last_marker = pnode == pctx->marker_stack.rend() ? 0U : pnode->marker;
	switch (marker) {
	case PR_MESSAGE_RECIPIENTS:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
				instance_id =
					fastupctx_object_get_last_message_instance(pctx);
				if (!exmdb_client_empty_message_instance_rcpts(
				    pctx->pstream->plogon->get_dir(), instance_id))
					return FALSE;	
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
			auto pmsgctnt = pnode->msg;
			if (0 != pmsgctnt->children.prcpts->count) {
				return FALSE;
			}
			break;
		}
		break;
	case PR_MESSAGE_ATTACHMENTS:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
				if (!exmdb_client_empty_message_instance_attachments(
				    pctx->pstream->plogon->get_dir(),
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
			auto pmsgctnt = pnode->msg;
			if (0 != pmsgctnt->children.pattachments->count) {
				return FALSE;
			}
			break;
		}
		break;
	case PR_CONTAINER_CONTENTS:
		if (ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element ||
			(STARTSUBFLD != last_marker && 0 != last_marker)) {
			return FALSE;	
		}
		if (0 == last_marker) {
			if (!fastupctx_object_empty_folder(pctx,
			    static_cast<folder_object *>(pctx->pobject)->folder_id,
			    TRUE, FALSE, FALSE))
				return FALSE;	
		}
		break;
	case PR_FOLDER_ASSOCIATED_CONTENTS:
		if (ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element ||
			(STARTSUBFLD != last_marker && 0 != last_marker)) {
			return FALSE;	
		}
		if (0 == last_marker) {
			if (fastupctx_object_empty_folder(pctx,
			    static_cast<folder_object *>(pctx->pobject)->folder_id,
			    FALSE, TRUE, FALSE))
				return FALSE;	
		}
		break;
	case PR_CONTAINER_HIERARCHY:
		if (ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element ||
			(STARTSUBFLD != last_marker && 0 != last_marker)) {
			return FALSE;	
		}
		if (0 == last_marker) {
			if (!fastupctx_object_empty_folder(pctx,
			    static_cast<folder_object *>(pctx->pobject)->folder_id,
			    FALSE, FALSE, TRUE))
				return FALSE;	
		}
		break;
	}
	return TRUE;
}

gxerr_t fastupctx_object::record_propval(const TAGGED_PROPVAL *ppropval)
{
	auto pctx = this;
	uint32_t b_result;
	
	switch (ppropval->proptag) {
	case MetaTagFXDelProp:
		switch (*(uint32_t*)ppropval->pvalue) {
		case PR_MESSAGE_RECIPIENTS:
		case PR_MESSAGE_ATTACHMENTS:
		case PR_CONTAINER_CONTENTS:
		case PR_FOLDER_ASSOCIATED_CONTENTS:
		case PR_CONTAINER_HIERARCHY:
			return fastupctx_object_del_props(pctx,
			       *static_cast<uint32_t *>(ppropval->pvalue)) == TRUE ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		default:
			return GXERR_CALL_FAILED;
		}
	case MetaTagDnPrefix:
	case MetaTagEcWarning:
		return GXERR_SUCCESS;
	case MetaTagNewFXFolder:
	case MetaTagIncrSyncGroupId:
	case MetaTagIncrementalSyncMessagePartial:
	case MetaTagIdsetGiven:
	case MetaTagIdsetGiven1:
	case MetaTagCnsetSeen:
	case MetaTagCnsetSeenFAI:
	case MetaTagCnsetRead:
	case MetaTagIdsetDeleted:
	case MetaTagIdsetNoLongerInScope:
	case MetaTagIdsetExpired:
	case MetaTagIdsetRead:
	case MetaTagIdsetUnread:
		return GXERR_CALL_FAILED;
	}
	auto pnode = pctx->marker_stack.rbegin();
	auto last_marker = pnode == pctx->marker_stack.rend() ? 0U : pnode->marker;
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
			return pctx->pproplist->set(*ppropval) == 0 ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		case ROOT_ELEMENT_MESSAGECONTENT: {
			auto msg = static_cast<message_object *>(pctx->pobject);
			TPROPVAL_ARRAY av;
			av.count = 1;
			av.ppropval = deconst(ppropval);
			PROBLEM_ARRAY pa;
			return msg->set_properties(&av, &pa) == TRUE ? GXERR_SUCCESS : GXERR_CALL_FAILED;
		}
		case ROOT_ELEMENT_ATTACHMENTCONTENT: {
			auto atx = static_cast<attachment_object *>(pctx->pobject);
			TPROPVAL_ARRAY av;
			av.count = 1;
			av.ppropval = deconst(ppropval);
			PROBLEM_ARRAY pa;
			return atx->set_properties(&av, &pa) == TRUE ? GXERR_SUCCESS : GXERR_CALL_FAILED;
		}
		case ROOT_ELEMENT_MESSAGELIST:
		case ROOT_ELEMENT_TOPFOLDER:
			return GXERR_CALL_FAILED;
		}
		return GXERR_CALL_FAILED;
	case STARTTOPFLD:
	case STARTSUBFLD:
		return pctx->pproplist->set(*ppropval) == 0 ?
		       GXERR_SUCCESS : GXERR_CALL_FAILED;
	case STARTMESSAGE:
	case STARTFAIMSG:
		return pnode->props->set(*ppropval) == 0 ? GXERR_SUCCESS : GXERR_CALL_FAILED;
	case STARTEMBED:
	case NEWATTACH:
		if (ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element ||
			ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
			return exmdb_client_set_instance_property(pctx->pstream->plogon->get_dir(),
			       pnode->instance_id, ppropval, &b_result) == TRUE ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		}
		return pnode->props->set(*ppropval) == 0 ? GXERR_SUCCESS : GXERR_CALL_FAILED;
	case STARTRECIP:
		if (ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element ||
			ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
			return pctx->pproplist->set(*ppropval) == 0 ?
			       GXERR_SUCCESS : GXERR_CALL_FAILED;
		}
		return pnode->props->set(*ppropval) == 0 ? GXERR_SUCCESS : GXERR_CALL_FAILED;
	default:
		return GXERR_CALL_FAILED;
	}
}

gxerr_t fastupctx_object::write_buffer(const BINARY *ptransfer_data)
{
	auto pctx = this;
	/* check if the fast stream is marked as ended */
	if (pctx->b_ended)
		return GXERR_CALL_FAILED;
	if (!pstream->write_buffer(ptransfer_data))
		return GXERR_CALL_FAILED;
	return pstream->process(*this);
}
