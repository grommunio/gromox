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
#include <gromox/util.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "fastupctx_object.h"
#include "folder_object.h"
#include "ftstream_parser.h"
#include "logon_object.h"
#include "message_object.h"

using namespace gromox;

std::unique_ptr<fastupctx_object> fastupctx_object::create(logon_object *plogon,
    void *pobject, int root_element)
{
	std::unique_ptr<fastupctx_object> pctx;
	try {
		pctx.reset(new fastupctx_object);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1451: ENOMEM");
		return NULL;
	}
	pctx->pobject = pobject;
	pctx->root_element = root_element;
	pctx->pstream = ftstream_parser::create(plogon);
	if (pctx->pstream == nullptr)
		return NULL;
	switch (root_element) {
	case ROOT_ELEMENT_FOLDERCONTENT:
		pctx->m_props = tpropval_array_init();
		if (pctx->m_props == nullptr)
			return NULL;
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
	if (m_props != nullptr)
		tpropval_array_free(m_props);
	if (m_content != nullptr)
		message_content_free(m_content);
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
	auto dir = pctx->pstream->plogon->get_dir();
	if (!exmdb_client::allocate_cn(dir, &change_num))
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
	if (!exmdb_client::create_folder_by_properties(dir,
	    pinfo->cpid, pproplist, pfolder_id) || *pfolder_id == 0)
		return FALSE;
	if (pctx->pstream->plogon->logon_mode == logon_mode::owner)
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
	exmdb_client::update_folder_permission(dir,
		*pfolder_id, FALSE, 1, &permission_row);
	return TRUE;
}

static BOOL fastupctx_object_empty_folder(fastupctx_object *pctx,
    uint64_t folder_id, BOOL b_normal, BOOL b_fai, BOOL b_sub)
{
	BOOL b_partial;
	const char *username;
	DCERPC_INFO rpc_info;
	
	if (pctx->pstream->plogon->logon_mode == logon_mode::owner) {
		username = NULL;	
	} else {
		rpc_info = get_rpc_info();
		username = rpc_info.username;
	}
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (!exmdb_client::empty_folder(pctx->pstream->plogon->get_dir(),
	    pinfo->cpid, username, folder_id, TRUE, b_normal, b_fai,
	    b_sub, &b_partial))
		return FALSE;	
	if (b_partial)
		return FALSE;
	return TRUE;
}

static ec_error_t
fastupctx_object_write_message(fastupctx_object *pctx, uint64_t folder_id)
{
	uint64_t change_num;
	auto pproplist = pctx->m_content->get_proplist();
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
	auto plogon = pctx->pstream->plogon;
	auto dir = plogon->get_dir();
	if (!exmdb_client::allocate_cn(dir, &change_num))
		return ecRpcFailed;
	if (pproplist->set(PidTagChangeNumber, &change_num) != 0)
		return ecRpcFailed;
	auto pbin = cu_xid_to_bin({plogon->guid(), change_num});
	if (NULL == pbin) {
		return ecRpcFailed;
	}
	if (pproplist->set(PR_CHANGE_KEY, pbin) != 0)
		return ecRpcFailed;
	auto pbin1 = pproplist->get<BINARY>(PR_PREDECESSOR_CHANGE_LIST);
	auto pvalue = common_util_pcl_append(pbin1, pbin);
	if (pvalue == nullptr)
		return ecRpcFailed;
	if (pproplist->set(PR_PREDECESSOR_CHANGE_LIST, pvalue) != 0)
		return ecRpcFailed;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client::write_message(dir, plogon->get_account(), pinfo->cpid,
	    folder_id, pctx->m_content, &e_result) || e_result != ecSuccess)
		return e_result;
	return ecSuccess;
}

ec_error_t fastupctx_object::record_marker(uint32_t marker)
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
		if (m_props == nullptr)
			break;
		if (m_props->count == 0)
			return ecRpcFailed;
		/*
		 * Normally there should be a TOPFLD in the stack (hence using
		 * prev(node)->folder_id); but maybe there are cases when
		 * SUBFLD is the first in the stack?
		 */
		uint64_t parent_id = pnode == pctx->marker_stack.begin() ?
		                     static_cast<folder_object *>(pctx->pobject)->folder_id :
		                     std::prev(pnode)->folder_id;
		if (!fastupctx_object_create_folder(pctx, parent_id,
		    m_props, &folder_id))
			return ecRpcFailed;
		tpropval_array_free(m_props);
		m_props = nullptr;
		pnode->folder_id = folder_id;
		break;
	}
	case STARTTOPFLD:
		if (m_props == nullptr)
			break;
		if (m_props->count > 0 &&
		    !static_cast<folder_object *>(pctx->pobject)->set_properties(m_props, &tmp_problems))
			return ecRpcFailed;
		tpropval_array_free(m_props);
		m_props = nullptr;
		break;
	case 0:
		if (pctx->root_element != ROOT_ELEMENT_FOLDERCONTENT)
			break;
		if (m_props == nullptr)
			break;
		if (m_props->count > 0 &&
		    !static_cast<folder_object *>(pctx->pobject)->set_properties(m_props, &tmp_problems))
			return ecRpcFailed;
		tpropval_array_free(m_props);
		m_props = nullptr;
		break;
	}
	auto dir = pstream->plogon->get_dir();
	switch (marker) {
	case STARTTOPFLD:
		if (ROOT_ELEMENT_TOPFOLDER !=
			pctx->root_element || 0 != last_marker) {
			return ecRpcFailed;
		}
		if (m_props != nullptr)
			return ecRpcFailed;
		m_props = tpropval_array_init();
		if (m_props == nullptr)
			return ecServerOOM;
		pmarker->marker = marker;
		pmarker->folder_id = static_cast<folder_object *>(pctx->pobject)->folder_id;
		break;
	case STARTSUBFLD:
		if (ROOT_ELEMENT_TOPFOLDER != pctx->root_element &&
			ROOT_ELEMENT_FOLDERCONTENT != pctx->root_element) {
			return ecRpcFailed;
		}
		if (m_props != nullptr)
			return ecRpcFailed;
		m_props = tpropval_array_init();
		if (m_props == nullptr)
			return ecServerOOM;
		pmarker->marker = marker;
		break;
	case ENDFOLDER:
		if (STARTTOPFLD != last_marker &&
			STARTSUBFLD != last_marker) {
			return ecRpcFailed;
		}
		pctx->marker_stack.erase(pnode);
		if (STARTTOPFLD == last_marker) {
			/* mark fast stream ended */
			pctx->b_ended = TRUE;
		}
		return ecSuccess;
	case STARTFAIMSG:
	case STARTMESSAGE: {
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGELIST:
			if (0 != last_marker) {
				return ecRpcFailed;
			}
			break;
		case ROOT_ELEMENT_TOPFOLDER:
			if (STARTTOPFLD != last_marker &&
				STARTSUBFLD != last_marker) {
				return ecRpcFailed;
			}
			break;
		case ROOT_ELEMENT_FOLDERCONTENT:
			break;
		default:
			return ecRpcFailed;
		}
		if (m_content != nullptr)
			return ecRpcFailed;
		m_content = message_content_init();
		if (m_content == nullptr)
			return ecServerOOM;
		prcpts = tarray_set_init();
		if (NULL == prcpts) {
			return ecServerOOM;
		}
		m_content->set_rcpts_internal(prcpts);
		pattachments = attachment_list_init();
		if (NULL == pattachments) {
			return ecServerOOM;
		}
		m_content->set_attachments_internal(pattachments);
		pproplist = m_content->get_proplist();
		uint8_t tmp_byte = marker == STARTFAIMSG;
		if (pproplist->set(PR_ASSOCIATED, &tmp_byte) != 0)
			return ecRpcFailed;
		pmarker->marker = marker;
		pmarker->msg = m_content;
		break;
	}
	case ENDMESSAGE: {
		if (STARTMESSAGE != last_marker &&
			STARTFAIMSG != last_marker) {
			return ecRpcFailed;
		}
		if (m_content == nullptr || m_content != pnode->msg)
			return ecRpcFailed;
		pctx->marker_stack.erase(pnode);
		folder_id = fastupctx_object_get_last_folder(pctx);
		auto err = fastupctx_object_write_message(pctx, folder_id);
		if (err != ecSuccess)
			return err;
		message_content_free(m_content);
		m_content = nullptr;
		return ecSuccess;
	}
	case STARTRECIP:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
			case STARTEMBED:
				break;
			default:
				return ecRpcFailed;
			}
			break;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			if (STARTEMBED != last_marker) {
				return ecRpcFailed;
			}
			break;
		default:
			if (STARTMESSAGE != last_marker &&
				STARTFAIMSG != last_marker &&
				STARTEMBED != last_marker) {
				return ecRpcFailed;
			}
			break;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			if (m_props != nullptr)
				return ecRpcFailed;
			m_props = tpropval_array_init();
			if (m_props == nullptr)
				return ecServerOOM;
		} else {
			pmsgctnt = pnode->msg;
			prcpt = pmsgctnt->children.prcpts->emplace();
			if (prcpt == nullptr)
				return ecServerOOM;
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
			return ecRpcFailed;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			tmp_rcpts.count = 1;
			tmp_rcpts.pparray = &m_props;
			if (!exmdb_client::update_message_instance_rcpts(dir,
			    pnode->instance_id, &tmp_rcpts))
				return ecRpcFailed;
			tpropval_array_free(m_props);
			m_props = nullptr;
		}
		pctx->marker_stack.erase(pnode);
		return ecSuccess;
	case NEWATTACH:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
			case STARTEMBED:
				break;
			default:
				return ecRpcFailed;
			}
			break;
		case ROOT_ELEMENT_ATTACHMENTCONTENT:
			if (STARTEMBED != last_marker) {
				return ecRpcFailed;
			}
			break;
		default:
			if (STARTMESSAGE != last_marker &&
				STARTFAIMSG != last_marker &&
				STARTEMBED != last_marker) {
				return ecRpcFailed;
			}
			break;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			instance_id = fastupctx_object_get_last_message_instance(pctx);
			if (!exmdb_client::create_attachment_instance(dir,
			    instance_id, &tmp_id, &tmp_num) || tmp_id == 0)
				return ecRpcFailed;
		} else {
			pattachment = attachment_content_init();
			if (NULL == pattachment) {
				return ecServerOOM;
			}
			pmsgctnt = pnode->msg;
			if (!attachment_list_append_internal(pmsgctnt->children.pattachments, pattachment)) {
				attachment_content_free(pattachment);
				return ecRpcFailed;
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
			return ecRpcFailed;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			ec_error_t e_result = ecRpcFailed;
			if (!exmdb_client::flush_instance(dir, pnode->instance_id,
			    nullptr, &e_result) || e_result != ecSuccess)
				return e_result;
			if (!exmdb_client::unload_instance(dir, pnode->instance_id))
				return ecRpcFailed;
		}
		pctx->marker_stack.erase(pnode);
		return ecSuccess;
	case STARTEMBED:
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
				if (NEWATTACH != last_marker) {
					return ecRpcFailed;
				}
			} else {
				if (0 != last_marker && NEWATTACH != last_marker) {
					return ecRpcFailed;
				}
			}
			instance_id = fastupctx_object_get_last_attachment_instance(pctx);
			if (!exmdb_client::load_embedded_instance(dir,
			    false, instance_id, &tmp_id))
				return ecRpcFailed;
			if (0 == tmp_id) {
				if (!exmdb_client::load_embedded_instance(dir,
				    TRUE, instance_id, &tmp_id) || tmp_id == 0)
					return ecRpcFailed;
			} else {
				if (!exmdb_client::clear_message_instance(dir,
				    instance_id))
					return ecRpcFailed;
			}
		} else {
			if (NEWATTACH != last_marker) {
				return ecRpcFailed;
			}
			pmsgctnt = message_content_init();
			if (NULL == pmsgctnt) {
				return ecServerOOM;
			}
			prcpts = tarray_set_init();
			if (NULL == prcpts) {
				message_content_free(pmsgctnt);
				return ecServerOOM;
			}
			pmsgctnt->set_rcpts_internal(prcpts);
			pattachments = attachment_list_init();
			if (NULL == pattachments) {
				message_content_free(pmsgctnt);
				return ecServerOOM;
			}
			pmsgctnt->set_attachments_internal(pattachments);
			pnode->atx->set_embedded_internal(pmsgctnt);
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
			return ecRpcFailed;
		}
		if (ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element ||
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element) {
			ec_error_t e_result = ecRpcFailed;
			if (!exmdb_client::flush_instance(dir, pnode->instance_id,
			    nullptr, &e_result) || e_result != ecSuccess)
				return e_result;
			if (!exmdb_client::unload_instance(dir, pnode->instance_id))
				return ecRpcFailed;
		}
		pctx->marker_stack.erase(pnode);
		return ecSuccess;
	case FXERRORINFO:
		/* we do not support this feature */
		return ecRpcFailed;
	default:
		return ecRpcFailed;
	}
	try {
		pctx->marker_stack.emplace_back(std::move(new_mark));
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1600: ENOMEM");
		return ecRpcFailed;
	}
	return ecSuccess;
}

static BOOL fastupctx_object_del_props(fastupctx_object *pctx, uint32_t marker)
{
	int instance_id;
	
	auto pnode = pctx->marker_stack.rbegin();
	auto last_marker = pnode == pctx->marker_stack.rend() ? 0U : pnode->marker;
	auto dir = pctx->pstream->plogon->get_dir();
	switch (marker) {
	case PR_MESSAGE_RECIPIENTS:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_MESSAGECONTENT:
			switch (last_marker) {
			case 0:
				instance_id =
					fastupctx_object_get_last_message_instance(pctx);
				if (!exmdb_client::empty_message_instance_rcpts(dir,
				    instance_id))
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
				if (!exmdb_client::empty_message_instance_attachments(dir,
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

ec_error_t fastupctx_object::record_propval(const TAGGED_PROPVAL *ppropval)
{
	auto pctx = this;
	uint32_t b_result;
	
	switch (ppropval->proptag) {
	case MetaTagFXDelProp:
		switch (*static_cast<uint32_t *>(ppropval->pvalue)) {
		case PR_MESSAGE_RECIPIENTS:
		case PR_MESSAGE_ATTACHMENTS:
		case PR_CONTAINER_CONTENTS:
		case PR_FOLDER_ASSOCIATED_CONTENTS:
		case PR_CONTAINER_HIERARCHY:
			return fastupctx_object_del_props(pctx,
			       *static_cast<uint32_t *>(ppropval->pvalue)) == TRUE ?
			       ecSuccess : ecRpcFailed;
		default:
			return ecRpcFailed;
		}
	case MetaTagDnPrefix:
	case MetaTagEcWarning:
		return ecSuccess;
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
		return ecRpcFailed;
	}
	auto pnode = pctx->marker_stack.rbegin();
	auto last_marker = pnode == pctx->marker_stack.rend() ? 0U : pnode->marker;
	if (PROP_TYPE(ppropval->proptag) == PT_OBJECT) {
		if (NEWATTACH == last_marker || (0 == last_marker &&
			ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element)) {
			if (ppropval->proptag != PR_ATTACH_DATA_OBJ)
				return ecRpcFailed;
		} else {
			return ecRpcFailed;
		}
	}
	switch (last_marker) {
	case 0:
		switch (pctx->root_element) {
		case ROOT_ELEMENT_FOLDERCONTENT:
			return m_props->set(*ppropval) == 0 ?
			       ecSuccess : ecRpcFailed;
		case ROOT_ELEMENT_MESSAGECONTENT: {
			auto msg = static_cast<message_object *>(pctx->pobject);
			TPROPVAL_ARRAY av;
			av.count = 1;
			av.ppropval = deconst(ppropval);
			PROBLEM_ARRAY pa;
			return msg->set_properties(&av, &pa) == TRUE ? ecSuccess : ecRpcFailed;
		}
		case ROOT_ELEMENT_ATTACHMENTCONTENT: {
			auto atx = static_cast<attachment_object *>(pctx->pobject);
			TPROPVAL_ARRAY av;
			av.count = 1;
			av.ppropval = deconst(ppropval);
			PROBLEM_ARRAY pa;
			return atx->set_properties(&av, &pa) == TRUE ? ecSuccess : ecRpcFailed;
		}
		case ROOT_ELEMENT_MESSAGELIST:
		case ROOT_ELEMENT_TOPFOLDER:
			return ecRpcFailed;
		}
		return ecRpcFailed;
	case STARTTOPFLD:
	case STARTSUBFLD:
		return m_props->set(*ppropval) == 0 ? ecSuccess : ecRpcFailed;
	case STARTMESSAGE:
	case STARTFAIMSG:
		return pnode->props->set(*ppropval) == 0 ? ecSuccess : ecRpcFailed;
	case STARTEMBED:
	case NEWATTACH:
		if (ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element ||
			ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
			return exmdb_client::set_instance_property(pctx->pstream->plogon->get_dir(),
			       pnode->instance_id, ppropval, &b_result) == TRUE ?
			       ecSuccess : ecRpcFailed;
		}
		return pnode->props->set(*ppropval) == 0 ? ecSuccess : ecRpcFailed;
	case STARTRECIP:
		if (ROOT_ELEMENT_ATTACHMENTCONTENT == pctx->root_element ||
			ROOT_ELEMENT_MESSAGECONTENT == pctx->root_element) {
			return m_props->set(*ppropval) == 0 ?
			       ecSuccess : ecRpcFailed;
		}
		return pnode->props->set(*ppropval) == 0 ? ecSuccess : ecRpcFailed;
	default:
		return ecRpcFailed;
	}
}

ec_error_t fastupctx_object::write_buffer(const BINARY *ptransfer_data)
{
	auto pctx = this;
	/* check if the fast stream is marked as ended */
	if (pctx->b_ended)
		return ecRpcFailed;
	if (!pstream->write_buffer(ptransfer_data))
		return ecRpcFailed;
	return pstream->process(*this);
}
