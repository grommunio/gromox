// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include "attachment_object.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "message_object.h"
#include "processor_types.h"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"
#include "rop_processor.h"
#include "table_object.h"

using namespace gromox;

ec_error_t rop_openmessage(uint16_t cpid, uint64_t folder_id,
    uint8_t open_mode_flags, uint64_t message_id,
    uint8_t *phas_named_properties, TYPED_STRING *psubject_prefix,
    TYPED_STRING *pnormalized_subject, uint16_t *precipient_count,
    PROPTAG_ARRAY *precipient_columns, uint8_t *prow_count,
    OPENRECIPIENT_ROW **pprecipient_row, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin, uint32_t *phout)
{
	BOOL b_del;
	int rop_num;
	BOOL b_exist;
	BOOL b_owner;
	void *pvalue;
	ems_objtype object_type;
	TARRAY_SET rcpts;
	uint32_t tag_access;
	uint32_t permission;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[3];
	
	if (0x0FFF == cpid) {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
	}
	if (!verify_cpid(cpid))
		return MAPI_E_UNKNOWN_CPID;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_LOGON && object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	if (!exmdb_client::check_message(plogon->get_dir(), folder_id,
	    message_id, &b_exist))
		return ecError;
	if (!b_exist)
		return ecNotFound;
	if (!exmdb_client::get_message_property(plogon->get_dir(), nullptr, 0,
	    message_id, PidTagFolderId, &pvalue) || pvalue == nullptr)
		return ecError;
	folder_id = *static_cast<uint64_t *>(pvalue);
	if (!exmdb_client::check_message_deleted(plogon->get_dir(), message_id, &b_del))
		return ecError;
	if (b_del && !(open_mode_flags & OPEN_MODE_FLAG_OPENSOFTDELETE))
		return ecNotFound;
	
	tag_access = 0;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode == logon_mode::owner) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client::get_folder_perm(plogon->get_dir(), folder_id,
	    rpc_info.username, &permission))
		return ecError;
	if (!(permission & (frightsReadAny | frightsVisible | frightsOwner)))
		return ecAccessDenied;
	if (permission & frightsOwner) {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
		goto PERMISSION_CHECK;
	}
	if (!exmdb_client::check_message_owner(plogon->get_dir(), message_id,
	    rpc_info.username, &b_owner))
		return ecError;
	if (b_owner || (permission & frightsReadAny))
		tag_access |= MAPI_ACCESS_READ;
	if ((permission & frightsEditAny) ||
	    (b_owner && (permission & frightsEditOwned)))
		tag_access |= MAPI_ACCESS_MODIFY;
	if ((permission & frightsDeleteAny) ||
	    (b_owner && (permission & frightsDeleteOwned)))
		tag_access |= MAPI_ACCESS_DELETE;
 PERMISSION_CHECK:
	if (!(tag_access & MAPI_ACCESS_READ))
		return ecAccessDenied;
	if (!(open_mode_flags & OPEN_MODE_FLAG_READWRITE) &&
	    !(tag_access & MAPI_ACCESS_MODIFY)) {
		if (!(open_mode_flags & OPEN_MODE_FLAG_BESTACCESS))
			return ecAccessDenied;
		open_mode_flags &= ~OPEN_MODE_FLAG_BESTACCESS;
	}
	
	auto pmessage = message_object::create(plogon, false, cpid, message_id,
	                &folder_id, tag_access, open_mode_flags, nullptr);
	if (pmessage == nullptr)
		return ecServerOOM;
	proptags.count = 3;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_HAS_NAMED_PROPERTIES;
	proptag_buff[1] = PR_SUBJECT_PREFIX;
	proptag_buff[2] = PR_NORMALIZED_SUBJECT;
	if (!pmessage->get_properties(0, &proptags, &propvals))
		return ecError;
	auto flag = propvals.get<const uint8_t>(PR_HAS_NAMED_PROPERTIES);
	*phas_named_properties = flag != nullptr && *flag != 0;
	auto str = propvals.get<const char>(PR_SUBJECT_PREFIX);
	if (str == nullptr) {
		psubject_prefix->string_type = STRING_TYPE_EMPTY;
		psubject_prefix->pstring = NULL;
	} else {
		psubject_prefix->string_type = STRING_TYPE_UNICODE;
		psubject_prefix->pstring = deconst(str);
	}
	str = propvals.get<char>(PR_NORMALIZED_SUBJECT);
	if (str == nullptr) {
		pnormalized_subject->string_type = STRING_TYPE_EMPTY;
		pnormalized_subject->pstring = NULL;
	} else {
		pnormalized_subject->string_type = STRING_TYPE_UNICODE;
		pnormalized_subject->pstring = deconst(str);
	}
	if (!pmessage->get_recipient_num(precipient_count))
		return ecError;
	auto pcolumns = pmessage->get_rcpt_columns();
	*precipient_columns = *pcolumns;
	emsmdb_interface_get_rop_num(&rop_num);
	uint8_t rcpt_num = rop_num == 1 ? 0xFE : 5;
	if (!pmessage->read_recipients(0, rcpt_num, &rcpts))
		return ecError;
	*prow_count = rcpts.count;
	if (rcpts.count > 0) {
		*pprecipient_row = cu_alloc<OPENRECIPIENT_ROW>(rcpts.count);
		if (NULL == *pprecipient_row) {
			return ecServerOOM;
		}
	}
	for (size_t i = 0; i < rcpts.count; ++i) {
		if (!common_util_propvals_to_openrecipient(cpid,
		    rcpts.pparray[i], pcolumns, &(*pprecipient_row)[i]))
			return ecServerOOM;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_MESSAGE, std::move(pmessage)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_createmessage(uint16_t cpid, uint64_t folder_id,
    uint8_t associated_flag, uint64_t **ppmessage_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	uint32_t tag_access;
	uint32_t permission;
	uint32_t proptag_buff[4];
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (0x0FFF == cpid) {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
	}
	if (!verify_cpid(cpid))
		return MAPI_E_UNKNOWN_CPID;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_LOGON && object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	auto rpc_info = get_rpc_info();
	if (plogon->logon_mode != logon_mode::owner) {
		if (!exmdb_client::get_folder_perm(plogon->get_dir(),
		    folder_id, rpc_info.username, &permission))
			return ecError;
		if (!(permission & (frightsOwner | frightsCreate)))
			return ecAccessDenied;
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ;
		if (permission & (frightsDeleteOwned | frightsDeleteAny))
			tag_access |= MAPI_ACCESS_DELETE;
	} else {
		tag_access = MAPI_ACCESS_MODIFY | MAPI_ACCESS_READ | MAPI_ACCESS_DELETE;
	}
	tmp_proptags.count = 4;
	tmp_proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_MESSAGE_SIZE_EXTENDED;
	proptag_buff[1] = PR_STORAGE_QUOTA_LIMIT;
	proptag_buff[2] = PR_ASSOC_CONTENT_COUNT;
	proptag_buff[3] = PR_CONTENT_COUNT;
	if (!plogon->get_properties(&tmp_proptags, &tmp_propvals))
		return ecError;
	auto num = tmp_propvals.get<const uint32_t>(PR_STORAGE_QUOTA_LIMIT);
	uint64_t max_quota = ULLONG_MAX;
	if (num != nullptr) {
		max_quota = *num;
		max_quota = max_quota >= ULLONG_MAX / 1024 ? ULLONG_MAX : max_quota * 1024ULL;
	}
	auto lnum = tmp_propvals.get<const uint64_t>(PR_MESSAGE_SIZE_EXTENDED);
	uint64_t total_size = lnum != nullptr ? *lnum : 0;
	if (total_size > max_quota)
		return ecQuotaExceeded;
	num = tmp_propvals.get<uint32_t>(PR_ASSOC_CONTENT_COUNT);
	uint32_t total_mail = num != nullptr ? *num : 0;
	num = tmp_propvals.get<uint32_t>(PR_CONTENT_COUNT);
	if (num != nullptr)
		total_mail += *num;
	if (total_mail > g_max_message)
		return ecQuotaExceeded;
	*ppmessage_id = cu_alloc<uint64_t>();
	if (NULL == *ppmessage_id) {
		return ecServerOOM;
	}
	if (!exmdb_client::allocate_message_id(plogon->get_dir(),
	    folder_id, *ppmessage_id))
		return ecError;
	auto pmessage = message_object::create(plogon, TRUE, cpid,
	                **ppmessage_id, &folder_id, tag_access,
	                OPEN_MODE_FLAG_READWRITE, nullptr);
	if (pmessage == nullptr)
		return ecServerOOM;
	BOOL b_fai = associated_flag == 0 ? false : TRUE;
	if (pmessage->init_message(b_fai, cpid) != 0)
		return ecError;
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_MESSAGE, std::move(pmessage)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_savechangesmessage(uint8_t save_flags, uint64_t *pmessage_id,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hresponse, uint32_t hin)
{
	ems_objtype object_type;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	
	save_flags &= SAVE_FLAG_KEEPOPENREADONLY |
					SAVE_FLAG_KEEPOPENREADWRITE |
					SAVE_FLAG_FORCESAVE;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	auto tag_access = pmessage->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY))
		return ecAccessDenied;
	auto open_flags = pmessage->get_open_flags();
	if (!(open_flags & OPEN_MODE_FLAG_READWRITE) &&
	    save_flags != SAVE_FLAG_FORCESAVE)
		return ecAccessDenied;
	if (SAVE_FLAG_FORCESAVE != save_flags) {
		auto ret = pmessage->check_original_touched();
		if (ret != ecSuccess)
			return ret;
	}
	uint32_t tmp_proptag = PidTagMid;
	proptags.count = 1;
	proptags.pproptag = &tmp_proptag;
	if (!pmessage->get_properties(0, &proptags, &propvals))
		return ecError;
	auto pvalue = propvals.get<uint64_t>(PidTagMid);
	if (NULL == pvalue) {
		return ecError;
	}
	*pmessage_id = *pvalue;
	auto err = pmessage->save();
	if (err != ecSuccess)
		return err;
	switch (save_flags) {
	case SAVE_FLAG_KEEPOPENREADWRITE:
	case SAVE_FLAG_FORCESAVE:
		open_flags = OPEN_MODE_FLAG_READWRITE;
		pmessage->set_open_flags(open_flags);
		break;
	}
	return ecSuccess;
}

ec_error_t rop_removeallrecipients(uint32_t reserved, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	pmessage->empty_rcpts();
	return ecSuccess;
}

ec_error_t rop_modifyrecipients(const PROPTAG_ARRAY *pproptags, uint16_t count,
    const MODIFYRECIPIENT_ROW *prow, LOGMAP *plogmap, uint8_t logon_id,
    uint32_t hin)
{
	int i;
	ems_objtype object_type;
	TARRAY_SET tmp_set;
	TPROPVAL_ARRAY *ppropvals;
	
	if (pproptags->count >= 0x7FEF || count >= 0x7FEF) {
		return ecInvalidParam;
	}
	for (i=0; i<pproptags->count; i++) {
		switch (pproptags->pproptag[i]) {
		case PR_ADDRTYPE:
		case PR_DISPLAY_NAME:
		case PR_EMAIL_ADDRESS:
		case PR_ENTRYID:
		case PR_INSTANCE_KEY:
		case PR_RECIPIENT_TYPE:
		case PR_SEARCH_KEY:
		case PR_SEND_RICH_INFO:
		case PR_TRANSMITABLE_DISPLAY_NAME:
			return ecInvalidParam;
		}
	}
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	if (pinfo == nullptr)
		return ecError;
	tmp_set.count = count;
	tmp_set.pparray = cu_alloc<TPROPVAL_ARRAY *>(count);
	if (NULL == tmp_set.pparray) {
		return ecServerOOM;
	}
	for (i=0; i<count; i++) {
		ppropvals = cu_alloc<TPROPVAL_ARRAY>();
		if (NULL == ppropvals) {
			return ecServerOOM;
		}
		if (NULL == prow[i].precipient_row) {
			ppropvals->count = 1;
			ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>();
			if (NULL == ppropvals->ppropval) {
				return ecServerOOM;
			}
			ppropvals->ppropval->proptag = PR_ROWID;
			ppropvals->ppropval->pvalue = deconst(&prow[i].row_id);
		} else {
			if (!common_util_modifyrecipient_to_propvals(pinfo->cpid,
			    &prow[i], pproptags, ppropvals))
				return ecServerOOM;
		}
		tmp_set.pparray[i] = ppropvals;
	}
	if (!pmessage->set_rcpts(&tmp_set))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_readrecipients(uint32_t row_id, uint16_t reserved, uint8_t *pcount,
    EXT_PUSH *pext, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	auto &ext = *pext;
	size_t i;
	ems_objtype object_type;
	TARRAY_SET tmp_set;
	READRECIPIENT_ROW tmp_row;
	
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	if (!pmessage->read_recipients(row_id, 0xFE, &tmp_set))
		return ecError;
	if (0 == tmp_set.count) {
		return ecNotFound;
	}
	for (i = 0; i < tmp_set.count; ++i) {
		if (!common_util_propvals_to_readrecipient(pmessage->get_cpid(),
		    tmp_set.pparray[i], pmessage->get_rcpt_columns(), &tmp_row))
			return ecServerOOM;
		uint32_t last_offset = ext.m_offset;
		if (pext->p_readrecipient_row(*pmessage->get_rcpt_columns(),
		    tmp_row) != EXT_ERR_SUCCESS) {
			ext.m_offset = last_offset;
			break;
		}
	}
	if (0 == i) {
		return ecBufferTooSmall;
	}
	*pcount = i;
	return ecSuccess;
}

ec_error_t rop_reloadcachedinformation(uint16_t reserved,
    uint8_t *phas_named_properties, TYPED_STRING *psubject_prefix,
    TYPED_STRING *pnormalized_subject, uint16_t *precipient_count,
    PROPTAG_ARRAY *precipient_columns, uint8_t *prow_count,
    OPENRECIPIENT_ROW **pprecipient_row, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	TARRAY_SET rcpts;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[3];
	
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	proptags.count = 3;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PR_HAS_NAMED_PROPERTIES;
	proptag_buff[1] = PR_SUBJECT_PREFIX;
	proptag_buff[2] = PR_NORMALIZED_SUBJECT;
	if (!pmessage->get_properties(0, &proptags, &propvals))
		return ecError;
	auto flag = propvals.get<const uint8_t>(PR_HAS_NAMED_PROPERTIES);
	*phas_named_properties = flag != nullptr && *flag != 0;
	auto str = propvals.get<const char>(PR_SUBJECT_PREFIX);
	if (str == nullptr) {
		psubject_prefix->string_type = STRING_TYPE_EMPTY;
		psubject_prefix->pstring = NULL;
	} else {
		psubject_prefix->string_type = STRING_TYPE_UNICODE;
		psubject_prefix->pstring = deconst(str);
	}
	str = propvals.get<char>(PR_NORMALIZED_SUBJECT);
	if (str == nullptr) {
		pnormalized_subject->string_type = STRING_TYPE_EMPTY;
		pnormalized_subject->pstring = NULL;
	} else {
		pnormalized_subject->string_type = STRING_TYPE_UNICODE;
		pnormalized_subject->pstring = deconst(str);
	}
	if (!pmessage->get_recipient_num(precipient_count))
		return ecError;
	auto pcolumns = pmessage->get_rcpt_columns();
	*precipient_columns = *pcolumns;
	if (!pmessage->read_recipients(0, 0xFE, &rcpts))
		return ecError;
	*prow_count = rcpts.count;
	*pprecipient_row = cu_alloc<OPENRECIPIENT_ROW>(rcpts.count);
	if (NULL == *pprecipient_row) {
		return ecServerOOM;
	}
	for (size_t i = 0; i < rcpts.count; ++i) {
		if (!common_util_propvals_to_openrecipient(pmessage->get_cpid(),
		    rcpts.pparray[i], pcolumns, *pprecipient_row + i))
			return ecServerOOM;
	}
	return ecSuccess;
}

ec_error_t rop_setmessagestatus(uint64_t message_id, uint32_t message_status,
    uint32_t status_mask, uint32_t *pmessage_status, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	uint32_t result;
	ems_objtype object_type;
	uint32_t new_status;
	TAGGED_PROPVAL propval;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	/* we do not check permission because it's maybe
		not an important property for the message.
		also, we don't know the message location */
	if (!exmdb_client::get_message_property(plogon->get_dir(), nullptr, 0,
	    message_id, PR_MSG_STATUS, &pvalue))
		return ecError;
	if (NULL == pvalue) {
		return ecNotFound;
	}
	auto original_status = *static_cast<uint32_t *>(pvalue);
	new_status = message_status & status_mask;
	if (new_status & MSGSTATUS_IN_CONFLICT)
		return ecAccessDenied;
	new_status |= original_status & ~(status_mask & ~new_status);
	*pmessage_status = new_status;
	propval.proptag = PR_MSG_STATUS;
	propval.pvalue = &new_status;
	if (!exmdb_client::set_message_property(plogon->get_dir(), nullptr, 0,
	    message_id, &propval, &result))
		return ecError;
	return static_cast<ec_error_t>(result);
}

ec_error_t rop_getmessagestatus(uint64_t message_id, uint32_t *pmessage_status,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	void *pvalue;
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	if (!exmdb_client::get_message_property(plogon->get_dir(), nullptr, 0,
	    message_id, PR_MSG_STATUS, &pvalue))
		return ecError;
	if (NULL == pvalue) {
		return ecNotFound;
	}
	*pmessage_status = *static_cast<uint32_t *>(pvalue);
	return ecSuccess;
}

static BOOL oxcmsg_setreadflag(logon_object *plogon,
	uint64_t message_id, uint8_t read_flag)
{
	void *pvalue;
	BOOL b_notify;
	BOOL b_changed;
	uint64_t read_cn;
	uint8_t tmp_byte;
	PROBLEM_ARRAY problems;
	MESSAGE_CONTENT *pbrief;
	TPROPVAL_ARRAY propvals;
	static constexpr uint8_t fake_false = 0;
	TAGGED_PROPVAL propval_buff[2];
	
	auto rpc_info = get_rpc_info();
	auto pinfo = emsmdb_interface_get_emsmdb_info();
	auto username = plogon->is_private() ? nullptr : rpc_info.username;
	b_notify = FALSE;
	b_changed = FALSE;
	auto dir = plogon->get_dir();

	switch (read_flag) {
	case MSG_READ_FLAG_DEFAULT:
	case MSG_READ_FLAG_SUPPRESS_RECEIPT:
		if (!exmdb_client::get_message_property(dir,
		    username, 0, message_id, PR_READ, &pvalue))
			return FALSE;	
		if (pvb_enabled(pvalue))
			break;
		tmp_byte = 1;
		b_changed = TRUE;
		if (read_flag != MSG_READ_FLAG_DEFAULT)
			break;
		if (!exmdb_client::get_message_property(dir,
		    username, 0, message_id,
		    PR_READ_RECEIPT_REQUESTED, &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue))
			b_notify = TRUE;
		break;
	case MSG_READ_FLAG_CLEAR_READ_FLAG:
		if (!exmdb_client::get_message_property(dir,
		    username, 0, message_id, PR_READ, &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue)) {
			tmp_byte = 0;
			b_changed = TRUE;
		}
		break;
	case MSG_READ_FLAG_GENERATE_RECEIPT_ONLY:
		if (!exmdb_client::get_message_property(dir,
		    username, 0, message_id, PR_READ_RECEIPT_REQUESTED,
		    &pvalue))
			return FALSE;
		if (pvb_enabled(pvalue))
			b_notify = TRUE;
		break;
	case MSG_READ_FLAG_CLEAR_NOTIFY_READ:
	case MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD:
	case MSG_READ_FLAG_CLEAR_NOTIFY_READ |
		MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD:
		if ((read_flag & MSG_READ_FLAG_CLEAR_NOTIFY_READ) &&
		    exmdb_client::get_message_property(dir, username, 0,
		    message_id, PR_READ_RECEIPT_REQUESTED, &pvalue) &&
		    pvb_enabled(pvalue) &&
		    !exmdb_client::remove_message_property(dir,
		    pinfo->cpid, message_id, PR_READ_RECEIPT_REQUESTED))
			return FALSE;
		if ((read_flag & MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD) &&
		    exmdb_client::get_message_property(dir,
		    username, 0, message_id,
		    PR_NON_RECEIPT_NOTIFICATION_REQUESTED, &pvalue) &&
		    pvb_enabled(pvalue) &&
		    !exmdb_client::remove_message_property(dir, pinfo->cpid,
		    message_id, PR_NON_RECEIPT_NOTIFICATION_REQUESTED))
			return FALSE;
		if (!exmdb_client::mark_modified(dir, message_id))
			return FALSE;	
		return TRUE;
	default:
		return TRUE;
	}
	if (b_changed && !exmdb_client::set_message_read_state(dir,
	    username, message_id, tmp_byte, &read_cn))
		return FALSE;
	if (!b_notify)
		return TRUE;
	if (!exmdb_client::get_message_brief(dir, pinfo->cpid, message_id, &pbrief))
		return FALSE;	
	if (NULL != pbrief) {
		common_util_notify_receipt(plogon->get_account(),
			NOTIFY_RECEIPT_READ, pbrief);
	}
	propvals.count = 2;
	propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PR_READ_RECEIPT_REQUESTED;
	propval_buff[0].pvalue = deconst(&fake_false);
	propval_buff[1].proptag = PR_NON_RECEIPT_NOTIFICATION_REQUESTED;
	propval_buff[1].pvalue = deconst(&fake_false);
	exmdb_client::set_message_properties(dir, username,
		0, message_id, &propvals, &problems);
	return TRUE;
}

ec_error_t rop_setreadflags(uint8_t want_asynchronous, uint8_t read_flags,
    const LONGLONG_ARRAY *pmessage_ids, uint8_t *ppartial_completion,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_partial;
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hin, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_FOLDER)
		return ecNotSupported;
	b_partial = FALSE;
	for (size_t i = 0; i < pmessage_ids->count; ++i) {
		if (!oxcmsg_setreadflag(plogon, pmessage_ids->pll[i], read_flags))
			b_partial = TRUE;	
	}
	*ppartial_completion = !!b_partial;
	return ecSuccess;
}

ec_error_t rop_setmessagereadflag(uint8_t read_flags,
    const LONG_TERM_ID *pclient_data, uint8_t *pread_change, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hresponse, uint32_t hin)
{
	BOOL b_changed;
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	if (rop_processor_get_object(plogmap, logon_id, hresponse, &object_type) == nullptr)
		return ecNullObject;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	if (!pmessage->set_readflag(read_flags, &b_changed))
		return ecError;
	*pread_change = !b_changed;
	return ecSuccess;
}

ec_error_t rop_openattachment(uint8_t flags, uint32_t attachment_id,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	if (flags & OPEN_MODE_FLAG_READWRITE) {
		auto tag_access = pmessage->get_tag_access();
		if (!(tag_access & MAPI_ACCESS_MODIFY)) {
			if (flags & OPEN_MODE_FLAG_BESTACCESS) {
				flags &= ~OPEN_MODE_FLAG_BESTACCESS;
			} else {
				return ecAccessDenied;
			}
		}
	}
	auto pattachment = attachment_object::create(pmessage, attachment_id, flags);
	if (pattachment == nullptr)
		return ecError;
	if (pattachment->get_instance_id() == 0)
		return ecNotFound;
	auto hnd = rop_processor_add_object_handle(plogmap, logon_id,
	           hin, {OBJECT_TYPE_ATTACHMENT, std::move(pattachment)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_createattachment(uint32_t *pattachment_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	auto tag_access = pmessage->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY))
		return ecAccessDenied;
	auto pattachment = attachment_object::create(pmessage,
		ATTACHMENT_NUM_INVALID, OPEN_MODE_FLAG_READWRITE);
	if (pattachment == nullptr)
		return ecError;
	*pattachment_id = pattachment->get_attachment_num();
	if (ATTACHMENT_NUM_INVALID == *pattachment_id) {
		return ecMaxAttachmentExceeded;
	}
	if (!pattachment->init_attachment())
		return ecError;
	auto hnd = rop_processor_add_object_handle(plogmap, logon_id,
	           hin, {OBJECT_TYPE_ATTACHMENT, std::move(pattachment)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_deleteattachment(uint32_t attachment_id, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	auto tag_access = pmessage->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY & tag_access))
		return ecAccessDenied;
	if (!pmessage->delete_attachment(attachment_id))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_savechangesattachment(uint8_t save_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hresponse, uint32_t hin)
{
	ems_objtype object_type;
	
	save_flags &= SAVE_FLAG_KEEPOPENREADONLY |
					SAVE_FLAG_KEEPOPENREADWRITE |
					SAVE_FLAG_FORCESAVE;
	if (rop_processor_get_object(plogmap, logon_id, hresponse, &object_type) == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	auto pattachment = rop_proc_get_obj<attachment_object>(plogmap, logon_id, hin, &object_type);
	if (pattachment == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_ATTACHMENT)
		return ecNotSupported;
	auto tag_access = pattachment->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY))
		return ecAccessDenied;
	auto open_flags = pattachment->get_open_flags();
	if (!(open_flags & OPEN_MODE_FLAG_READWRITE) &&
	    save_flags != SAVE_FLAG_FORCESAVE)
		return ecAccessDenied;
	auto err = pattachment->save();
	if (err != ecSuccess)
		return err;
	switch (save_flags) {
	case SAVE_FLAG_KEEPOPENREADWRITE:
	case SAVE_FLAG_FORCESAVE:
		open_flags = OPEN_MODE_FLAG_READWRITE;
		pattachment->set_open_flags(open_flags);
		break;
	}
	return ecSuccess;
}

ec_error_t rop_openembeddedmessage(uint16_t cpid, uint8_t open_embedded_flags,
    uint8_t *preserved, uint64_t *pmessage_id, uint8_t *phas_named_properties,
    TYPED_STRING *psubject_prefix, TYPED_STRING *pnormalized_subject,
    uint16_t *precipient_count, PROPTAG_ARRAY *precipient_columns,
    uint8_t *prow_count, OPENRECIPIENT_ROW **pprecipient_row, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	TARRAY_SET rcpts;
	PROPTAG_ARRAY proptags;
	TPROPVAL_ARRAY propvals;
	uint32_t proptag_buff[4];
	
	*preserved = 0;
	if (0x0FFF == cpid) {
		auto pinfo = emsmdb_interface_get_emsmdb_info();
		if (pinfo == nullptr)
			return ecError;
		cpid = pinfo->cpid;
	}
	if (!verify_cpid(cpid))
		return MAPI_E_UNKNOWN_CPID;
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pattachment = rop_proc_get_obj<attachment_object>(plogmap, logon_id, hin, &object_type);
	if (pattachment == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_ATTACHMENT)
		return ecNotSupported;
	auto tag_access = pattachment->get_tag_access();
	if (!(tag_access & MAPI_ACCESS_MODIFY) &&
	    open_embedded_flags & OPEN_EMBEDDED_FLAG_READWRITE)
		return ecAccessDenied;
	auto pmessage = message_object::create(plogon, false, cpid, 0,
	                pattachment, tag_access, open_embedded_flags, nullptr);
	if (pmessage == nullptr)
		return ecError;
	if (pmessage->get_instance_id() == 0) {
		if (!(open_embedded_flags & OPEN_EMBEDDED_FLAG_CREATE))
			return ecNotFound;
		if (!(tag_access & MAPI_ACCESS_MODIFY))
			return ecAccessDenied;
		pmessage = message_object::create(plogon, TRUE, cpid, 0,
		           pattachment, tag_access, OPEN_MODE_FLAG_READWRITE,
		           nullptr);
		if (pmessage == nullptr)
			return ecError;
		if (pmessage->init_message(false, cpid) != 0)
			return ecError;
		proptags.count = 1;
		proptags.pproptag = proptag_buff;
		proptag_buff[0] = PidTagMid;
		if (!pmessage->get_properties(0, &proptags, &propvals))
			return ecError;
		auto mid_p = propvals.get<const eid_t>(PidTagMid);
		if (mid_p == nullptr)
			return ecError;
		*pmessage_id = *mid_p;
		auto hnd = rop_processor_add_object_handle(plogmap,
		           logon_id, hin, {OBJECT_TYPE_MESSAGE, std::move(pmessage)});
		if (hnd < 0)
			return ecError;
		*phout = hnd;
		*phas_named_properties = 0;
		psubject_prefix->string_type = STRING_TYPE_EMPTY;
		psubject_prefix->pstring = NULL;
		pnormalized_subject->string_type = STRING_TYPE_EMPTY;
		pnormalized_subject->pstring = NULL;
		precipient_columns->count = 0;
		precipient_columns->pproptag = NULL;
		*precipient_count = 0;
		*prow_count = 0;
		*pprecipient_row = NULL;
		return ecSuccess;
	}
	proptags.count = 4;
	proptags.pproptag = proptag_buff;
	proptag_buff[0] = PidTagMid;
	proptag_buff[1] = PR_HAS_NAMED_PROPERTIES;
	proptag_buff[2] = PR_SUBJECT_PREFIX;
	proptag_buff[3] = PR_NORMALIZED_SUBJECT;
	if (!pmessage->get_properties(0, &proptags, &propvals))
		return ecError;
	auto mid_p = propvals.get<const eid_t>(PidTagMid);
	if (mid_p == nullptr)
		return ecError;
	*pmessage_id = *mid_p;
	auto flag = propvals.get<const uint8_t>(PR_HAS_NAMED_PROPERTIES);
	*phas_named_properties = flag != nullptr && *flag != 0;
	auto str = propvals.get<const char>(PR_SUBJECT_PREFIX);
	if (str == nullptr) {
		psubject_prefix->string_type = STRING_TYPE_EMPTY;
		psubject_prefix->pstring = NULL;
	} else {
		psubject_prefix->string_type = STRING_TYPE_UNICODE;
		psubject_prefix->pstring = deconst(str);
	}
	str = propvals.get<char>(PR_NORMALIZED_SUBJECT);
	if (str == nullptr) {
		pnormalized_subject->string_type = STRING_TYPE_EMPTY;
		pnormalized_subject->pstring = NULL;
	} else {
		pnormalized_subject->string_type = STRING_TYPE_UNICODE;
		pnormalized_subject->pstring = deconst(str);
	}
	if (!pmessage->get_recipient_num(precipient_count))
		return ecError;
	auto pcolumns = pmessage->get_rcpt_columns();
	*precipient_columns = *pcolumns;
	if (!pmessage->read_recipients(0, 0xFE, &rcpts))
		return ecError;
	*prow_count = rcpts.count;
	*pprecipient_row = cu_alloc<OPENRECIPIENT_ROW>(rcpts.count);
	if (NULL == *pprecipient_row) {
		return ecServerOOM;
	}
	for (size_t i = 0; i < rcpts.count; ++i) {
		if (!common_util_propvals_to_openrecipient(pmessage->get_cpid(),
		    rcpts.pparray[i], pcolumns, *pprecipient_row + i))
			return ecServerOOM;
	}
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_MESSAGE, std::move(pmessage)});
	if (hnd < 0)
		return ecError;
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_getattachmenttable(uint8_t table_flags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin, uint32_t *phout)
{
	ems_objtype object_type;
	
	auto plogon = rop_processor_get_logon_object(plogmap, logon_id);
	if (plogon == nullptr)
		return ecError;
	auto pmessage = rop_proc_get_obj<message_object>(plogmap, logon_id, hin, &object_type);
	if (pmessage == nullptr)
		return ecNullObject;
	if (object_type != OBJECT_TYPE_MESSAGE)
		return ecNotSupported;
	auto ptable = table_object::create(plogon, pmessage, table_flags,
	              ropGetAttachmentTable, logon_id);
	if (ptable == nullptr)
		return ecServerOOM;
	auto rtable = ptable.get();
	auto hnd = rop_processor_add_object_handle(plogmap,
	           logon_id, hin, {OBJECT_TYPE_TABLE, std::move(ptable)});
	if (hnd < 0)
		return ecError;
	rtable->set_handle(hnd);
	*phout = hnd;
	return ecSuccess;
}

ec_error_t rop_getvalidattachments(LONG_ARRAY *pattachment_ids, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	/* just like exchange 2010 or later,
		we do not implement this rop */
	return NotImplemented;
}
