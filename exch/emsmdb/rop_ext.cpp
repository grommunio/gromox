// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstring>
#include <gromox/defs.h>
#include <gromox/endian.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/lzxpress.hpp>
#include <gromox/proc_common.h>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "logon_object.h"
#include "notify_response.h"
#include "rop_ext.h"
#include "rop_ids.hpp"
#include "rop_processor.h"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

using namespace gromox;

static pack_result rop_ext_push(EXT_PUSH &x, const LOGON_TIME &r)
{
	TRY(x.p_uint8(r.second));
	TRY(x.p_uint8(r.minute));
	TRY(x.p_uint8(r.hour));
	TRY(x.p_uint8(r.day_of_week));
	TRY(x.p_uint8(r.day));
	TRY(x.p_uint8(r.month));
	return x.p_uint16(r.year);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GHOST_SERVER &r)
{
	if (r.server_count == 0 || r.cheap_server_count > r.server_count)
		return EXT_ERR_FORMAT;
	TRY(x.p_uint16(r.server_count));
	TRY(x.p_uint16(r.cheap_server_count));
	for (size_t i = 0; i < r.server_count; ++i)
		TRY(x.p_str(r.ppservers[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x, const NULL_DST_RESPONSE &r)
{
	TRY(x.p_uint32(r.dhindex));
	return x.p_uint8(r.partial_completion);
}

static pack_result rop_ext_push(EXT_PUSH &x, const PROPERTY_PROBLEM &r)
{
	TRY(x.p_uint16(r.index));
	TRY(x.p_uint32(r.proptag));
	return x.p_uint32(r.err);
}

static pack_result rop_ext_push(EXT_PUSH &x, const PROBLEM_ARRAY &r)
{
	TRY(x.p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(rop_ext_push(x, r.pproblem[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x, const PROPIDNAME_ARRAY &r)
{
	TRY(x.p_uint16(r.count));
	for (size_t i = 0; i < r.count; ++i)
		TRY(x.p_uint16(r.ppropid[i]));
	for (size_t i = 0; i < r.count; ++i)
		TRY(x.p_propname(r.ppropname[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, MESSAGE_READ_STAT &r)
{
	TRY(x.g_sbin(&r.message_xid));
	return x.g_uint8(&r.mark_as_read);
}

static pack_result rop_ext_pull(EXT_PULL &x, LOGON_REQUEST &r)
{
	uint16_t size;
	
	TRY(x.g_uint8(&r.logon_flags));
	TRY(x.g_uint32(&r.open_flags));
	TRY(x.g_uint32(&r.store_stat));
	TRY(x.g_uint16(&size));
	if (0 == size) {
		r.pessdn = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r.pessdn = x.anew<char>(size);
	if (r.pessdn == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_bytes(r.pessdn, size));
	if (r.pessdn[size-1] != '\0')
		return EXT_ERR_FORMAT;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x, const LOGON_PMB_RESPONSE &r)
{
	TRY(x.p_uint8(r.logon_flags));
	for (size_t i = 0; i < 13; ++i)
		TRY(x.p_uint64(r.folder_ids[i]));
	TRY(x.p_uint8(r.response_flags));
	TRY(x.p_guid(r.mailbox_guid));
	TRY(x.p_uint16(r.replid));
	TRY(x.p_guid(r.replguid));
	TRY(rop_ext_push(x, r.logon_time));
	TRY(x.p_uint64(r.gwart_time));
	return x.p_uint32(r.store_stat);
}

static pack_result rop_ext_push(EXT_PUSH &x, const LOGON_PF_RESPONSE &r)
{
	TRY(x.p_uint8(r.logon_flags));
	for (size_t i = 0; i < 13; ++i)
		TRY(x.p_uint64(r.folder_ids[i]));
	TRY(x.p_uint16(r.replid));
	TRY(x.p_guid(r.replguid));
	return x.p_guid(r.per_user_guid);
}

static pack_result rop_ext_push(EXT_PUSH &x, const LOGON_REDIRECT_RESPONSE &r)
{
	uint8_t size;
	
	TRY(x.p_uint8(r.logon_flags));
	size = strlen(r.pserver_name) + 1;
	TRY(x.p_uint8(size));
	return x.p_bytes(r.pserver_name, size);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETRECEIVEFOLDER_REQUEST &r)
{
	return x.g_str(&r.pstr_class);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETRECEIVEFOLDER_RESPONSE &r)
{
	TRY(x.p_uint64(r.folder_id));
	return x.p_str(r.pstr_class);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETRECEIVEFOLDER_REQUEST &r)
{
	TRY(x.g_uint64(&r.folder_id));
	return x.g_str(&r.pstr_class);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETRECEIVEFOLDERTABLE_RESPONSE &r)
{
	PROPTAG_ARRAY columns;
	static constexpr uint32_t proptags[] =
		{PidTagFolderId, PR_MESSAGE_CLASS_A, PR_LAST_MODIFICATION_TIME};
	
	columns.count = std::size(proptags);
	columns.pproptag = deconst(proptags);
	TRY(x.p_uint32(r.rows.count));
	for (size_t i = 0; i < r.rows.count; ++i)
		TRY(x.p_proprow(columns, r.rows.prows[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETSTORESTAT_RESPONSE &r)
{
	return x.p_uint32(r.stat);	
}

static pack_result rop_ext_pull(EXT_PULL &x, GETOWNINGSERVERS_REQUEST &r)
{
	return x.g_uint64(&r.folder_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETOWNINGSERVERS_RESPONSE &r)
{
	return rop_ext_push(x, r.ghost);
}

static pack_result rop_ext_pull(EXT_PULL &x, PUBLICFOLDERISGHOSTED_REQUEST &r)
{
	return x.g_uint64(&r.folder_id);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const PUBLICFOLDERISGHOSTED_RESPONSE &r)
{
	if (r.pghost == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return rop_ext_push(x, *r.pghost);
}

static pack_result rop_ext_pull(EXT_PULL &x, LONGTERMIDFROMID_REQUEST &r)
{
	return x.g_uint64(&r.id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const LONGTERMIDFROMID_RESPONSE &r)
{
	return x.p_longterm(r.long_term_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, IDFROMLONGTERMID_REQUEST &r)
{
	return x.g_longterm(&r.long_term_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const IDFROMLONGTERMID_RESPONSE &r)
{
	return x.p_uint64(r.id);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETPERUSERLONGTERMIDS_REQUEST &r)
{
	return x.g_guid(&r.guid);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETPERUSERLONGTERMIDS_RESPONSE &r)
{	
	return x.p_longterm_a(r.ids);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETPERUSERGUID_REQUEST &r)
{
	return x.g_longterm(&r.long_term_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETPERUSERGUID_RESPONSE &r)
{
	return x.p_guid(r.guid);
}

static pack_result rop_ext_pull(EXT_PULL &x, READPERUSERINFORMATION_REQUEST &r)
{
	TRY(x.g_longterm(&r.long_folder_id));
	TRY(x.g_uint8(&r.reserved));
	TRY(x.g_uint32(&r.data_offset));
	return x.g_uint16(&r.max_data_size);
}

static pack_result rop_ext_push(EXT_PUSH &x, const READPERUSERINFORMATION_RESPONSE &r)
{
	TRY(x.p_uint8(r.has_finished));
	return x.p_bin_s(r.data);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    WRITEPERUSERINFORMATION_REQUEST &r, BOOL b_private)
{
	TRY(x.g_longterm(&r.long_folder_id));
	TRY(x.g_uint8(&r.has_finished));
	TRY(x.g_uint32(&r.offset));
	TRY(x.g_sbin(&r.data));
	if (r.offset == 0 && b_private) {
		r.pguid = x.anew<GUID>();
		if (r.pguid == nullptr)
			return EXT_ERR_ALLOC;
		return x.g_guid(r.pguid);
	}
	r.pguid = nullptr;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, OPENFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint64(&r.folder_id));
	return x.g_uint8(&r.open_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const OPENFOLDER_RESPONSE &r)
{
	TRY(x.p_uint8(r.has_rules));
	if (r.pghost == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return rop_ext_push(x, *r.pghost);
}

static pack_result rop_ext_pull(EXT_PULL &x, CREATEFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.folder_type));
	TRY(x.g_uint8(&r.use_unicode));
	TRY(x.g_uint8(&r.open_existing));
	TRY(x.g_uint8(&r.reserved));
	if (!r.use_unicode) {
		TRY(x.g_str(&r.pfolder_name));
		return x.g_str(&r.pfolder_comment);
	}
	TRY(x.g_wstr(&r.pfolder_name));
	return x.g_wstr(&r.pfolder_comment);
}

static pack_result rop_ext_push(EXT_PUSH &x, const CREATEFOLDER_RESPONSE &r)
{
	TRY(x.p_uint64(r.folder_id));
	TRY(x.p_uint8(r.is_existing));
	if (r.is_existing == 0)
		return EXT_ERR_SUCCESS;
	TRY(x.p_uint8(r.has_rules));
	if (r.pghost == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return rop_ext_push(x, *r.pghost);
}

static pack_result rop_ext_pull(EXT_PULL &x, DELETEFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.flags));
	return x.g_uint64(&r.folder_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const PARTIAL_COMPLETION_RESPONSE &r)
{
	return x.p_uint8(r.partial_completion);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETSEARCHCRITERIA_REQUEST &r)
{
	uint16_t res_size;
	
	TRY(x.g_uint16(&res_size));
	if (0 == res_size) {
		r.pres = nullptr;
	} else {
		r.pres = x.anew<RESTRICTION>();
		if (r.pres == nullptr)
			return EXT_ERR_ALLOC;
		uint32_t offset = x.m_offset + res_size;
		TRY(x.g_restriction(r.pres));
		if (x.m_offset > offset)
			return EXT_ERR_FORMAT;
		x.m_offset = offset;
	}
	TRY(x.g_uint64_sa(&r.folder_ids));
	return x.g_uint32(&r.search_flags);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETSEARCHCRITERIA_REQUEST &r)
{
	TRY(x.g_uint8(&r.use_unicode));
	TRY(x.g_uint8(&r.include_restriction));
	return x.g_uint8(&r.include_folders);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETSEARCHCRITERIA_RESPONSE &r)
{
	if (r.pres == nullptr) {
		TRY(x.p_uint16(0));
	} else {
		uint32_t offset1 = x.m_offset;
		TRY(x.advance(sizeof(uint16_t)));
		TRY(x.p_restriction(*r.pres));
		uint16_t res_size = x.m_offset - (offset1 + sizeof(uint16_t));
		uint32_t offset2 = x.m_offset;
		x.m_offset = offset1;
		TRY(x.p_uint16(res_size));
		x.m_offset = offset2;
	}
	TRY(x.p_uint8(r.logon_id));
	TRY(x.p_uint64_sa(r.folder_ids));
	return x.p_uint32(r.search_status);
}

static pack_result rop_ext_pull(EXT_PULL &x, MOVECOPYMESSAGES_REQUEST &r)
{
	TRY(x.g_uint8(&r.dhindex));
	TRY(x.g_uint64_sa(&r.message_ids));
	TRY(x.g_uint8(&r.want_asynchronous));
	return x.g_uint8(&r.want_copy);
}

static pack_result rop_ext_pull(EXT_PULL &x, MOVEFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.dhindex));
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.use_unicode));
	TRY(x.g_uint64(&r.folder_id));
	return r.use_unicode ? x.g_wstr(&r.pnew_name) : x.g_str(&r.pnew_name);
}

static pack_result rop_ext_pull(EXT_PULL &x, COPYFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.dhindex));
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.want_recursive));
	TRY(x.g_uint8(&r.use_unicode));
	TRY(x.g_uint64(&r.folder_id));
	return r.use_unicode ? x.g_wstr(&r.pnew_name) : x.g_str(&r.pnew_name);
}

static pack_result rop_ext_pull(EXT_PULL &x, EMPTYFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.want_asynchronous));
	return x.g_uint8(&r.want_delete_associated);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST &r)
{
	TRY(x.g_uint8(&r.want_asynchronous));
	return x.g_uint8(&r.want_delete_associated);
}

static pack_result rop_ext_pull(EXT_PULL &x, DELETEMESSAGES_REQUEST &r)
{
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.notify_non_read));
	return x.g_uint64_sa(&r.message_ids);
}

static pack_result rop_ext_pull(EXT_PULL &x, HARDDELETEMESSAGES_REQUEST &r)
{
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.notify_non_read));
	return x.g_uint64_sa(&r.message_ids);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETHIERARCHYTABLE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	return x.g_uint8(&r.table_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETHIERARCHYTABLE_RESPONSE &r)
{
	return x.p_uint32(r.row_count);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETCONTENTSTABLE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	return x.g_uint8(&r.table_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETCONTENTSTABLE_RESPONSE &r)
{
	return x.p_uint32(r.row_count);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETCOLUMNS_REQUEST &r)
{
	TRY(x.g_uint8(&r.table_flags));
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const TABLE_STATUS_RESPONSE &r)
{
	return x.p_uint8(r.table_status);
}

static pack_result rop_ext_pull(EXT_PULL &x, SORTTABLE_REQUEST &r)
{
	TRY(x.g_uint8(&r.table_flags));
	return x.g_sortorder_set(&r.sort_criteria);
}

static pack_result rop_ext_pull(EXT_PULL &x, RESTRICT_REQUEST &r)
{
	uint16_t res_size;
	
	TRY(x.g_uint8(&r.res_flags));
	TRY(x.g_uint16(&res_size));
	if (0 == res_size) {
		r.pres = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r.pres = x.anew<RESTRICTION>();
	if (r.pres == nullptr)
		return EXT_ERR_ALLOC;
	uint32_t offset = x.m_offset + res_size;
	TRY(x.g_restriction(r.pres));
	if (x.m_offset > offset)
		return EXT_ERR_FORMAT;
	x.m_offset = offset;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, QUERYROWS_REQUEST &r)
{
	TRY(x.g_uint8(&r.flags));
	TRY(x.g_uint8(&r.forward_read));
	return x.g_uint16(&r.row_count);
}

static pack_result rop_ext_push(EXT_PUSH &x, const QUERYROWS_RESPONSE &r)
{
	TRY(x.p_uint8(r.seek_pos));
	TRY(x.p_uint16(r.count));
	return x.p_bytes(r.bin_rows.pb, r.bin_rows.cb);
}

static pack_result rop_ext_push(EXT_PUSH &x, const QUERYPOSITION_RESPONSE &r)
{
	TRY(x.p_uint32(r.numerator));
	return x.p_uint32(r.denominator);
}

static pack_result rop_ext_pull(EXT_PULL &x, SEEKROW_REQUEST &r)
{
	TRY(x.g_uint8(&r.seek_pos));
	TRY(x.g_int32(&r.offset));
	return x.g_uint8(&r.want_moved_count);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SEEKROW_RESPONSE &r)
{
	TRY(x.p_uint8(r.has_soughtless));
	return x.p_int32(r.offset_sought);
}

static pack_result rop_ext_pull(EXT_PULL &x, SEEKROWBOOKMARK_REQUEST &r)
{
	TRY(x.g_sbin(&r.bookmark));
	TRY(x.g_int32(&r.offset));
	return x.g_uint8(&r.want_moved_count);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SEEKROWBOOKMARK_RESPONSE &r)
{
	TRY(x.p_uint8(r.row_invisible));
	TRY(x.p_uint8(r.has_soughtless));
	return x.p_uint32(r.offset_sought);
}

static pack_result rop_ext_pull(EXT_PULL &x, SEEKROWFRACTIONAL_REQUEST &r)
{
	TRY(x.g_uint32(&r.numerator));
	return x.g_uint32(&r.denominator);
}

static pack_result rop_ext_push(EXT_PUSH &x, const CREATEBOOKMARK_RESPONSE &r)
{
	return x.p_bin_s(r.bookmark);
}

static pack_result rop_ext_push(EXT_PUSH &x, const QUERYCOLUMNSALL_RESPONSE &r)
{
	return x.p_proptag_a(r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, FINDROW_REQUEST &r)
{
	uint16_t res_size;
	
	TRY(x.g_uint8(&r.flags));
	TRY(x.g_uint16(&res_size));
	if (0 == res_size) {
		r.pres = nullptr;
	} else {
		r.pres = x.anew<RESTRICTION>();
		if (r.pres == nullptr)
			return EXT_ERR_ALLOC;
		uint32_t offset = x.m_offset + res_size;
		TRY(x.g_restriction(r.pres));
		if (x.m_offset > offset)
			return EXT_ERR_FORMAT;
		x.m_offset = offset;
	}
	TRY(x.g_uint8(&r.seek_pos));
	return x.g_sbin(&r.bookmark);
}

static pack_result rop_ext_push(EXT_PUSH &x, const FINDROW_RESPONSE &r)
{
	TRY(x.p_uint8(r.bookmark_invisible));
	if (r.prow == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	TRY(x.p_proprow(*r.pcolumns, *r.prow));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, FREEBOOKMARK_REQUEST &r)
{
	return x.g_sbin(&r.bookmark);
}

static pack_result rop_ext_pull(EXT_PULL &x, EXPANDROW_REQUEST &r)
{
	TRY(x.g_uint16(&r.max_count));
	return x.g_uint64(&r.category_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const EXPANDROW_RESPONSE &r)
{
	TRY(x.p_uint32(r.expanded_count));
	TRY(x.p_uint16(r.count));
	return x.p_bytes(r.bin_rows.pb, r.bin_rows.cb);
}

static pack_result rop_ext_pull(EXT_PULL &x, COLLAPSEROW_REQUEST &r)
{
	return x.g_uint64(&r.category_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const COLLAPSEROW_RESPONSE &r)
{
	return x.p_uint32(r.collapsed_count);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETCOLLAPSESTATE_REQUEST &r)
{
	TRY(x.g_uint64(&r.row_id));
	return x.g_uint32(&r.row_instance);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETCOLLAPSESTATE_RESPONSE &r)
{
	return x.p_bin_s(r.collapse_state);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETCOLLAPSESTATE_REQUEST &r)
{
	return x.g_sbin(&r.collapse_state);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SETCOLLAPSESTATE_RESPONSE &r)
{
	return x.p_bin_s(r.bookmark);
}

static pack_result rop_ext_pull(EXT_PULL &x, OPENMESSAGE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint16(&r.cpid));
	TRY(x.g_uint64(&r.folder_id));
	TRY(x.g_uint8(&r.open_mode_flags));
	return x.g_uint64(&r.message_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const OPENMESSAGE_RESPONSE &r)
{
	TRY(x.p_uint8(r.has_named_properties));
	TRY(x.p_typed_str(r.subject_prefix));
	TRY(x.p_typed_str(r.normalized_subject));
	TRY(x.p_uint16(r.recipient_count));
	TRY(x.p_proptag_a(r.recipient_columns));
	if (r.row_count == 0)
		return x.p_uint8(0);
	uint32_t offset = x.m_offset;
	TRY(x.advance(sizeof(uint8_t)));
	unsigned int i;
	for (i = 0; i < r.row_count; ++i) {
		uint32_t last_offset = x.m_offset;
		auto status = x.p_openrecipient_row(r.recipient_columns, r.precipient_row[i]);
		if (EXT_ERR_SUCCESS != status ||
		    x.m_alloc_size - x.m_offset < 256) {
			x.m_offset = last_offset;
			break;
		}
	}
	if (i == 0)
		return EXT_ERR_SUCCESS;
	uint32_t offset1 = x.m_offset;
	x.m_offset = offset;
	TRY(x.p_uint8(i));
	x.m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, CREATEMESSAGE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint16(&r.cpid));
	TRY(x.g_uint64(&r.folder_id));
	return x.g_uint8(&r.associated_flag);
}

static pack_result rop_ext_push(EXT_PUSH &x, const CREATEMESSAGE_RESPONSE &r)
{
	if (r.pmessage_id == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	return x.p_uint64(*r.pmessage_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, SAVECHANGESMESSAGE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ihindex2));
	return x.g_uint8(&r.save_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SAVECHANGESMESSAGE_RESPONSE &r)
{
	TRY(x.p_uint8(r.ihindex2));
	return x.p_uint64(r.message_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, REMOVEALLRECIPIENTS_REQUEST &r)
{
	return x.g_uint32(&r.reserved);
}

static pack_result rop_ext_pull(EXT_PULL &x, MODIFYRECIPIENTS_REQUEST &r)
{
	TRY(x.g_proptag_a(&r.proptags));
	TRY(x.g_uint16(&r.count));
	if (r.count == 0) {
		r.prow = nullptr;
	} else {
		r.prow = x.anew<MODIFYRECIPIENT_ROW>(r.count);
		if (r.prow == nullptr) {
			r.count = 0;
			return EXT_ERR_ALLOC;
		}
	}
	for (size_t i = 0; i < r.count; ++i)
		TRY(x.g_modrcpt_row(&r.proptags, &r.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, READRECIPIENTS_REQUEST &r)
{
	TRY(x.g_uint32(&r.row_id));
	return x.g_uint16(&r.reserved);
}

static pack_result rop_ext_push(EXT_PUSH &x, const READRECIPIENTS_RESPONSE &r)
{
	TRY(x.p_uint8(r.count));
	return x.p_bytes(r.bin_recipients.pb, r.bin_recipients.cb);
}

static pack_result rop_ext_pull(EXT_PULL &x, RELOADCACHEDINFORMATION_REQUEST &r)
{
	return x.g_uint16(&r.reserved);
}

static pack_result rop_ext_push(EXT_PUSH &x, const RELOADCACHEDINFORMATION_RESPONSE &r)
{
	TRY(x.p_uint8(r.has_named_properties));
	TRY(x.p_typed_str(r.subject_prefix));
	TRY(x.p_typed_str(r.normalized_subject));
	TRY(x.p_uint16(r.recipient_count));
	TRY(x.p_proptag_a(r.recipient_columns));
	if (r.row_count == 0)
		return x.p_uint8(0);
	uint32_t offset = x.m_offset;
	TRY(x.advance(sizeof(uint8_t)));
	unsigned int i;
	for (i = 0; i < r.row_count; ++i) {
		uint32_t last_offset = x.m_offset;
		auto status = x.p_openrecipient_row(r.recipient_columns, r.precipient_row[i]);
		if (EXT_ERR_SUCCESS != status ||
		    x.m_alloc_size - x.m_offset < 256) {
			x.m_offset = last_offset;
			break;
		}
	}
	if (i == 0)
		return EXT_ERR_SUCCESS;
	uint32_t offset1 = x.m_offset;
	x.m_offset = offset;
	TRY(x.p_uint8(i));
	x.m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, SETMESSAGESTATUS_REQUEST &r)
{
	TRY(x.g_uint64(&r.message_id));
	TRY(x.g_uint32(&r.message_status));
	return x.g_uint32(&r.status_mask);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SETMESSAGESTATUS_RESPONSE &r)
{
	return x.p_uint32(r.message_status);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETMESSAGESTATUS_REQUEST &r)
{
	return x.g_uint64(&r.message_id);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETMESSAGESTATUS_RESPONSE &r)
{
	return x.p_uint32(r.message_status);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETREADFLAGS_REQUEST &r)
{
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.read_flags));
	return x.g_uint64_sa(&r.message_ids);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETMESSAGEREADFLAG_REQUEST &r,
    BOOL b_private)
{
	TRY(x.g_uint8(&r.ihindex2));
	TRY(x.g_uint8(&r.flags));
	if (b_private) {
		r.pclient_data = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r.pclient_data = x.anew<LONG_TERM_ID>();
	if (r.pclient_data == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_longterm(r.pclient_data);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SETMESSAGEREADFLAG_RESPONSE &r)
{
	if (r.read_changed == 0 || r.pclient_data == nullptr)
		return x.p_uint8(0);
	TRY(x.p_uint8(1));
	TRY(x.p_uint8(r.logon_id));
	return x.p_longterm(*r.pclient_data);
}

static pack_result rop_ext_pull(EXT_PULL &x, OPENATTACHMENT_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.flags));
	return x.g_uint32(&r.attachment_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, CREATEATTACHMENT_REQUEST &r)
{
	return x.g_uint8(&r.ohindex);
}

static pack_result rop_ext_push(EXT_PUSH &x, const CREATEATTACHMENT_RESPONSE &r)
{
	return x.p_uint32(r.attachment_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, DELETEATTACHMENT_REQUEST &r)
{
	return x.g_uint32(&r.attachment_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, SAVECHANGESATTACHMENT_REQUEST &r)
{
	TRY(x.g_uint8(&r.ihindex2));
	return x.g_uint8(&r.save_flags);
}

static pack_result rop_ext_pull(EXT_PULL &x, OPENEMBEDDEDMESSAGE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint16(&r.cpid));
	return x.g_uint8(&r.open_embedded_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const OPENEMBEDDEDMESSAGE_RESPONSE &r)
{
	TRY(x.p_uint8(r.reserved));
	TRY(x.p_uint64(r.message_id));
	TRY(x.p_uint8(r.has_named_properties));
	TRY(x.p_typed_str(r.subject_prefix));
	TRY(x.p_typed_str(r.normalized_subject));
	TRY(x.p_uint16(r.recipient_count));
	TRY(x.p_proptag_a(r.recipient_columns));
	if (r.row_count == 0)
		return x.p_uint8(0);
	uint32_t offset = x.m_offset;
	TRY(x.advance(sizeof(uint8_t)));
	unsigned int i;
	for (i = 0; i < r.row_count; ++i) {
		uint32_t last_offset = x.m_offset;
		auto status = x.p_openrecipient_row(r.recipient_columns, r.precipient_row[i]);
		if (EXT_ERR_SUCCESS != status ||
		    x.m_alloc_size - x.m_offset < 256) {
			x.m_offset = last_offset;
			break;
		}
	}
	if (i == 0)
		return EXT_ERR_SUCCESS;
	uint32_t offset1 = x.m_offset;
	x.m_offset = offset;
	TRY(x.p_uint8(i));
	x.m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, GETATTACHMENTTABLE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	return x.g_uint8(&r.table_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETVALIDATTACHMENTS_RESPONSE &r)
{	
	return x.p_uint32_a(r.attachment_ids);
}

static pack_result rop_ext_pull(EXT_PULL &x, SUBMITMESSAGE_REQUEST &r)
{
	return x.g_uint8(&r.submit_flags);
}

static pack_result rop_ext_pull(EXT_PULL &x, ABORTSUBMIT_REQUEST &r)
{
	TRY(x.g_uint64(&r.folder_id));
	return x.g_uint64(&r.message_id);
}


static pack_result rop_ext_push(EXT_PUSH &x, const GETADDRESSTYPES_RESPONSE &r)
{
	TRY(x.p_uint16(r.address_types.count));
	uint32_t offset = x.m_offset;
	TRY(x.advance(sizeof(uint16_t)));
	for (size_t i = 0; i < r.address_types.count; ++i)
		TRY(x.p_str(r.address_types.ppstr[i]));
	uint16_t size = x.m_offset - (offset + sizeof(uint16_t));
	uint32_t offset1 = x.m_offset;
	x.m_offset = offset;
	TRY(x.p_uint16(size));
	x.m_offset = offset1;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, SPOOLERLOCKMESSAGE_REQUEST &r)
{
	TRY(x.g_uint64(&r.message_id));
	return x.g_uint8(&r.lock_stat);
}

static pack_result rop_ext_push(EXT_PUSH &x, const TRANSPORTSEND_RESPONSE &r)
{
	if (r.ppropvals == nullptr)
		return x.p_uint8(1);
	TRY(x.p_uint8(0));
	return x.p_tpropval_a(*r.ppropvals);
}

static pack_result rop_ext_pull(EXT_PULL &x, TRANSPORTNEWMAIL_REQUEST &r)
{
	TRY(x.g_uint64(&r.message_id));
	TRY(x.g_uint64(&r.folder_id));
	TRY(x.g_str(&r.pstr_class));
	return x.g_uint32(&r.message_flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETTRANSPORTFOLDER_RESPONSE &r)
{
	return x.p_uint64(r.folder_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, OPTIONSDATA_REQUEST &r)
{
	TRY(x.g_str(&r.paddress_type));
	return x.g_uint8(&r.want_win32);
}

static pack_result rop_ext_push(EXT_PUSH &x, const OPTIONSDATA_RESPONSE &r)
{
	TRY(x.p_uint8(r.reserved));
	TRY(x.p_bin_s(r.options_info));
	TRY(x.p_bin_s(r.help_file));
	if (r.help_file.cb > 0)
		return x.p_str(r.pfile_name);
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, GETPROPERTYIDSFROMNAMES_REQUEST &r)
{
	TRY(x.g_uint8(&r.flags));
	return x.g_propname_a(&r.propnames);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const GETPROPERTYIDSFROMNAMES_RESPONSE &r)
{
	return x.p_propid_a(r.propids);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETNAMESFROMPROPERTYIDS_REQUEST &r)
{
	return x.g_propid_a(&r.propids);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const GETNAMESFROMPROPERTYIDS_RESPONSE &r)
{
	return x.p_propname_a(r.propnames);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETPROPERTIESSPECIFIC_REQUEST &r)
{
	TRY(x.g_uint16(&r.size_limit));
	TRY(x.g_uint16(&r.want_unicode));
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const GETPROPERTIESSPECIFIC_RESPONSE &r)
{
	return x.p_proprow(*r.pproptags, r.row);
}

static pack_result rop_ext_pull(EXT_PULL &x, GETPROPERTIESALL_REQUEST &r)
{
	TRY(x.g_uint16(&r.size_limit));
	return x.g_uint16(&r.want_unicode);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETPROPERTIESALL_RESPONSE &r)
{
	return x.p_tpropval_a(r.propvals);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETPROPERTIESLIST_RESPONSE &r)
{
	return x.p_proptag_a(r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETPROPERTIES_REQUEST &r)
{
	uint16_t size;
	
	TRY(x.g_uint16(&size));
	uint32_t offset = x.m_offset + size;
	TRY(x.g_tpropval_a(&r.propvals));
	if (x.m_offset > offset)
		return EXT_ERR_FORMAT;
	x.m_offset = offset;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x, const PROBLEM_RESPONSE &r)
{
	return rop_ext_push(x, r.problems);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETPROPERTIESNOREPLICATE_REQUEST &r)
{
	uint16_t size;
	
	TRY(x.g_uint16(&size));
	uint32_t offset = x.m_offset + size;
	TRY(x.g_tpropval_a(&r.propvals));
	if (x.m_offset > offset)
		return EXT_ERR_FORMAT;
	x.m_offset = offset;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, DELETEPROPERTIES_REQUEST &r)
{
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, DELETEPROPERTIESNOREPLICATE_REQUEST &r)
{
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, QUERYNAMEDPROPERTIES_REQUEST &r)
{
	uint8_t has_guid;
	
	TRY(x.g_uint8(&r.query_flags));
	TRY(x.g_uint8(&has_guid));
	if (0 == has_guid) {
		r.pguid = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r.pguid = x.anew<GUID>();
	if (r.pguid == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_guid(r.pguid);
}

static pack_result rop_ext_push(EXT_PUSH &x, const QUERYNAMEDPROPERTIES_RESPONSE &r)
{
	return rop_ext_push(x, r.propidnames);
}

static pack_result rop_ext_pull(EXT_PULL &x, COPYPROPERTIES_REQUEST &r)
{
	TRY(x.g_uint8(&r.dhindex));
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.copy_flags));
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, COPYTO_REQUEST &r)
{
	TRY(x.g_uint8(&r.dhindex));
	TRY(x.g_uint8(&r.want_asynchronous));
	TRY(x.g_uint8(&r.want_subobjects));
	TRY(x.g_uint8(&r.copy_flags));
	return x.g_proptag_a(&r.excluded_proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, PROGRESS_REQUEST &r)
{
	return x.g_uint8(&r.want_cancel);
}

static pack_result rop_ext_push(EXT_PUSH &x, const PROGRESS_RESPONSE &r)
{
	TRY(x.p_uint8(r.logon_id));
	TRY(x.p_uint32(r.completed_count));
	return x.p_uint32(r.total_count);
}

static pack_result rop_ext_pull(EXT_PULL &x, OPENSTREAM_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint32(&r.proptag));
	return x.g_uint8(&r.flags);
}

static pack_result rop_ext_push(EXT_PUSH &x, const OPENSTREAM_RESPONSE &r)
{
	return x.p_uint32(r.stream_size);
}

static pack_result rop_ext_pull(EXT_PULL &x, READSTREAM_REQUEST &r)
{
	TRY(x.g_uint16(&r.byte_count));
	if (r.byte_count == 0xBABE)
		return x.g_uint32(&r.max_byte_count);
	r.max_byte_count = 0;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x, const READSTREAM_RESPONSE &r)
{
	return x.p_bin_s(r.data);
}

static pack_result rop_ext_pull(EXT_PULL &x, WRITESTREAM_REQUEST &r)
{
	return x.g_sbin(&r.data);
}

static pack_result rop_ext_push(EXT_PUSH &x, const WRITESTREAM_RESPONSE &r)
{
	return x.p_uint16(r.written_size);
}

static pack_result rop_ext_push(EXT_PUSH &x, const GETSTREAMSIZE_RESPONSE &r)
{
	return x.p_uint32(r.stream_size);
}

static pack_result rop_ext_pull(EXT_PULL &x, SETSTREAMSIZE_REQUEST &r)
{
	return x.g_uint64(&r.stream_size);
}

static pack_result rop_ext_pull(EXT_PULL &x, SEEKSTREAM_REQUEST &r)
{
	TRY(x.g_uint8(&r.seek_pos));
	return x.g_int64(&r.offset);
}

static pack_result rop_ext_push(EXT_PUSH &x, const SEEKSTREAM_RESPONSE &r)
{
	return x.p_uint64(r.new_pos);
}

static pack_result rop_ext_pull(EXT_PULL &x, COPYTOSTREAM_REQUEST &r)
{
	TRY(x.g_uint8(&r.dhindex));
	return x.g_uint64(&r.byte_count);
}

static pack_result rop_ext_push(EXT_PUSH &x, const COPYTOSTREAM_RESPONSE &r)
{
	TRY(x.p_uint64(r.read_bytes));
	return x.p_uint64(r.written_bytes);
}

static pack_result rop_ext_push(EXT_PUSH &x, const COPYTOSTREAM_NULL_DEST_RESPONSE &r)
{
	TRY(x.p_uint32(r.dhindex));
	TRY(x.p_uint64(r.read_bytes));
	return x.p_uint64(r.written_bytes);
}

static pack_result rop_ext_pull(EXT_PULL &x, LOCKREGIONSTREAM_REQUEST &r)
{
	TRY(x.g_uint64(&r.region_offset));
	TRY(x.g_uint64(&r.region_size));
	return x.g_uint32(&r.lock_flags);
}

static pack_result rop_ext_pull(EXT_PULL &x, UNLOCKREGIONSTREAM_REQUEST &r)
{
	TRY(x.g_uint64(&r.region_offset));
	TRY(x.g_uint64(&r.region_size));
	return x.g_uint32(&r.lock_flags);
}

static pack_result rop_ext_pull(EXT_PULL &x, WRITEANDCOMMITSTREAM_REQUEST &r)
{
	return x.g_sbin(&r.data);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const WRITEANDCOMMITSTREAM_RESPONSE &r)
{
	return x.p_uint16(r.written_size);
}

static pack_result rop_ext_pull(EXT_PULL &x, CLONESTREAM_REQUEST &r)
{
	return x.g_uint8(&r.ohindex);
}

static pack_result rop_ext_pull(EXT_PULL &x, MODIFYPERMISSIONS_REQUEST &r)
{
	TRY(x.g_uint8(&r.flags));
	TRY(x.g_uint16(&r.count));
	if (r.count == 0) {
		r.prow = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r.prow = x.anew<PERMISSION_DATA>(r.count);
	if (r.prow == nullptr) {
		r.count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r.count; ++i)
		TRY(x.g_permission_data(&r.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, GETPERMISSIONSTABLE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	return x.g_uint8(&r.flags);
}

static pack_result rop_ext_pull(EXT_PULL &x, MODIFYRULES_REQUEST &r)
{
	TRY(x.g_uint8(&r.flags));
	TRY(x.g_uint16(&r.count));
	if (r.count == 0)
		return EXT_ERR_FORMAT;
	r.prow = x.anew<RULE_DATA>(r.count);
	if (r.prow == nullptr) {
		r.count = 0;
		return EXT_ERR_SUCCESS;
	}
	for (size_t i = 0; i < r.count; ++i)
		TRY(x.g_rule_data(&r.prow[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, GETRULESTABLE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	return x.g_uint8(&r.flags);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    UPDATEDEFERREDACTIONMESSAGES_REQUEST &r)
{
	TRY(x.g_sbin(&r.server_entry_id));
	return x.g_sbin(&r.client_entry_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, FASTTRANSFERDESTCONFIGURE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.source_operation));
	return x.g_uint8(&r.flags);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    FASTTRANSFERDESTPUTBUFFER_REQUEST &r)
{
	return x.g_sbin(&r.transfer_data);	
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const FASTTRANSFERDESTPUTBUFFER_RESPONSE &r)
{
	TRY(x.p_uint16(r.transfer_status));
	TRY(x.p_uint16(r.in_progress_count));
	TRY(x.p_uint16(r.total_step_count));
	TRY(x.p_uint8(r.reserved));
	return x.p_uint16(r.used_size);
}

static pack_result rop_ext_pull(EXT_PULL &x, FASTTRANSFERSOURCEGETBUFFER_REQUEST &r)
{
	TRY(x.g_uint16(&r.buffer_size));
	if (r.buffer_size == 0xBABE)
		return x.g_uint16(&r.max_buffer_size);
	r.max_buffer_size = 0;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const FASTTRANSFERSOURCEGETBUFFER_RESPONSE &r)
{
	TRY(x.p_uint16(r.transfer_status));
	TRY(x.p_uint16(r.in_progress_count));
	TRY(x.p_uint16(r.total_step_count));
	TRY(x.p_uint8(r.reserved));
	return x.p_bin_s(r.transfer_data);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    FASTTRANSFERSOURCECOPYFOLDER_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.flags));
	return x.g_uint8(&r.send_options);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    FASTTRANSFERSOURCECOPYMESSAGES_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint64_sa(&r.message_ids));
	TRY(x.g_uint8(&r.flags));
	return x.g_uint8(&r.send_options);
}

static pack_result rop_ext_pull(EXT_PULL &x, FASTTRANSFERSOURCECOPYTO_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.level));
	TRY(x.g_uint32(&r.flags));
	TRY(x.g_uint8(&r.send_options));
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.level));
	TRY(x.g_uint8(&r.flags));
	TRY(x.g_uint8(&r.send_options));
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, TELLVERSION_REQUEST &r)
{
	for (size_t i = 0; i < 3; ++i)
		TRY(x.g_uint16(&r.version[i]));
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCCONFIGURE_REQUEST &r)
{
	uint16_t res_size;
	
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.sync_type));
	TRY(x.g_uint8(&r.send_options));
	TRY(x.g_uint16(&r.sync_flags));
	TRY(x.g_uint16(&res_size));
	if (0 == res_size) {
		r.pres = nullptr;
	} else {
		r.pres = x.anew<RESTRICTION>();
		if (r.pres == nullptr)
			return EXT_ERR_ALLOC;
		uint32_t offset = x.m_offset + res_size;
		TRY(x.g_restriction(r.pres));
		if (x.m_offset > offset)
			return EXT_ERR_FORMAT;
		x.m_offset = offset;
	}
	TRY(x.g_uint32(&r.extra_flags));
	return x.g_proptag_a(&r.proptags);
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCIMPORTMESSAGECHANGE_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.import_flags));
	return x.g_tpropval_a(&r.propvals);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const SYNCIMPORTMESSAGECHANGE_RESPONSE &r)
{
	return x.p_uint64(r.message_id);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    SYNCIMPORTREADSTATECHANGES_REQUEST &r) try
{
	uint16_t size;
	static constexpr size_t ta_size = 0x1000;
	auto tmp_array = std::make_unique<MESSAGE_READ_STAT[]>(ta_size);
	
	TRY(x.g_uint16(&size));
	if (size == 0)
		return EXT_ERR_FORMAT;
	r.count = 0;
	uint32_t offset = x.m_offset + size;
	while (x.m_offset < offset && r.count < ta_size)
		TRY(rop_ext_pull(x, tmp_array[r.count++]));
	if (x.m_offset != offset)
		return EXT_ERR_FORMAT;
	r.pread_stat = x.anew<MESSAGE_READ_STAT>(r.count);
	if (r.pread_stat == nullptr) {
		r.count = 0;
		return EXT_ERR_ALLOC;
	}
	memcpy(r.pread_stat, tmp_array.get(), sizeof(tmp_array[0]) * r.count);
	return EXT_ERR_SUCCESS;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1171: ENOMEM");
	return EXT_ERR_ALLOC;
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCIMPORTHIERARCHYCHANGE_REQUEST &r)
{
	TRY(x.g_tpropval_a(&r.hichyvals));
	return x.g_tpropval_a(&r.propvals);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const SYNCIMPORTHIERARCHYCHANGE_RESPONSE &r)
{
	return x.p_uint64(r.folder_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCIMPORTDELETES_REQUEST &r)
{
	TRY(x.g_uint8(&r.flags));
	return x.g_tpropval_a(&r.propvals);
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCIMPORTMESSAGEMOVE_REQUEST &r)
{
	TRY(x.g_bin_ex(&r.src_folder_id));
	TRY(x.g_bin_ex(&r.src_message_id));
	TRY(x.g_bin_ex(&r.change_list));
	TRY(x.g_bin_ex(&r.dst_message_id));
	return x.g_bin_ex(&r.change_number);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const SYNCIMPORTMESSAGEMOVE_RESPONSE &r)
{
	return x.p_uint64(r.message_id);
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCOPENCOLLECTOR_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	return x.g_uint8(&r.is_content_collector);
}

static pack_result rop_ext_pull(EXT_PULL &x, SYNCGETTRANSFERSTATE_REQUEST &r)
{
	return x.g_uint8(&r.ohindex);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    SYNCUPLOADSTATESTREAMBEGIN_REQUEST &r)
{
	TRY(x.g_uint32(&r.proptag_stat));
	return x.g_uint32(&r.buffer_size);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    SYNCUPLOADSTATESTREAMCONTINUE_REQUEST &r)
{
	return x.g_bin_ex(&r.stream_data);
}

static pack_result rop_ext_pull(EXT_PULL &x,
    SETLOCALREPLICAMIDSETDELETED_REQUEST &r)
{
	uint16_t data_size;
	
	TRY(x.g_uint16(&data_size));
	uint32_t offset = x.m_offset + data_size;
	TRY(x.g_uint32(&r.count));
	if (r.count == 0)
		return EXT_ERR_FORMAT;
	r.prange = x.anew<LONG_TERM_ID_RANGE>(r.count);
	if (r.prange == nullptr) {
		r.count = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r.count; ++i)
		TRY(x.g_longterm_range(&r.prange[i]));
	if (x.m_offset > offset)
		return EXT_ERR_FORMAT;
	x.m_offset = offset;
	return EXT_ERR_SUCCESS;
}

static pack_result rop_ext_pull(EXT_PULL &x, GETLOCALREPLICAIDS_REQUEST &r)
{
	return x.g_uint32(&r.count);
}

static pack_result rop_ext_push(EXT_PUSH &x,
    const GETLOCALREPLICAIDS_RESPONSE &r)
{
	TRY(x.p_guid(r.replguid));
	return x.p_bytes(r.global_count.ab, 6);
}

static pack_result rop_ext_pull(EXT_PULL &x, REGISTERNOTIFICATION_REQUEST &r)
{
	TRY(x.g_uint8(&r.ohindex));
	TRY(x.g_uint8(&r.notification_types));
	TRY(x.g_uint8(&r.reserved));
	TRY(x.g_uint8(&r.want_whole_store));
	if (r.want_whole_store) {
		r.pfolder_id  = nullptr;
		r.pmessage_id = nullptr;
		return EXT_ERR_SUCCESS;
	}
	r.pfolder_id = x.anew<uint64_t>();
	if (r.pfolder_id == nullptr)
		return EXT_ERR_ALLOC;
	TRY(x.g_uint64(r.pfolder_id));
	r.pmessage_id = x.anew<uint64_t>();
	if (r.pmessage_id == nullptr)
		return EXT_ERR_ALLOC;
	return x.g_uint64(r.pmessage_id);
}

pack_result rop_ext_push(EXT_PUSH &x, const PENDING_RESPONSE &r)
{
	TRY(x.p_uint8(ropPending));
	return x.p_uint16(r.session_index);
}

static pack_result rop_ext_pull(EXT_PULL &x, rop_request &r)
{
	r.rq_bookmark.pb = deconst(x.m_udata) + x.m_offset;
	r.rq_bookmark.cb = x.m_data_size - x.m_offset;
	TRY(x.g_uint8(&r.rop_id));
	TRY(x.g_uint8(&r.logon_id));
	TRY(x.g_uint8(&r.hindex));
	r.ppayload = nullptr;
	
#define H(rop, t) \
	case (rop): { \
		auto r0 = x.anew<t ## _REQUEST>(); \
		r.ppayload = r0; \
		return r0 != nullptr ? rop_ext_pull(x, *r0) : pack_result::alloc; \
	}

	switch (r.rop_id) {
	H(ropLogon, LOGON);
	H(ropGetReceiveFolder, GETRECEIVEFOLDER);
	H(ropSetReceiveFolder, SETRECEIVEFOLDER);
	H(ropGetOwningServers, GETOWNINGSERVERS);
	H(ropPublicFolderIsGhosted, PUBLICFOLDERISGHOSTED);
	H(ropLongTermIdFromId, LONGTERMIDFROMID);
	H(ropIdFromLongTermId, IDFROMLONGTERMID);
	H(ropGetPerUserLongTermIds, GETPERUSERLONGTERMIDS);
	H(ropGetPerUserGuid, GETPERUSERGUID);
	H(ropReadPerUserInformation, READPERUSERINFORMATION);
	case ropWritePerUserInformation: {
		r.ppayload = x.anew<WRITEPERUSERINFORMATION_REQUEST>();
		if (r.ppayload == nullptr)
			return EXT_ERR_ALLOC;
		auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		auto plogon = rop_processor_get_logon_object(&pemsmdb_info->logmap, r.logon_id);
		if (plogon == nullptr)
			return EXT_ERR_INVALID_OBJECT;
		return rop_ext_pull(x, *static_cast<WRITEPERUSERINFORMATION_REQUEST *>(r.ppayload),
		       plogon->is_private());
	}
	H(ropOpenFolder, OPENFOLDER);
	H(ropCreateFolder, CREATEFOLDER);
	H(ropDeleteFolder, DELETEFOLDER);
	H(ropSetSearchCriteria, SETSEARCHCRITERIA);
	H(ropGetSearchCriteria, GETSEARCHCRITERIA);
	H(ropMoveCopyMessages, MOVECOPYMESSAGES);
	H(ropMoveFolder, MOVEFOLDER);
	H(ropCopyFolder, COPYFOLDER);
	H(ropEmptyFolder, EMPTYFOLDER);
	H(ropHardDeleteMessagesAndSubfolders, HARDDELETEMESSAGESANDSUBFOLDERS);
	H(ropDeleteMessages, DELETEMESSAGES);
	H(ropHardDeleteMessages, HARDDELETEMESSAGES);
	H(ropGetHierarchyTable, GETHIERARCHYTABLE);
	H(ropGetContentsTable, GETCONTENTSTABLE);
	H(ropSetColumns, SETCOLUMNS);
	H(ropSortTable, SORTTABLE);
	H(ropRestrict, RESTRICT);
	H(ropQueryRows, QUERYROWS);
	H(ropSeekRow, SEEKROW);
	H(ropSeekRowBookmark, SEEKROWBOOKMARK);
	H(ropSeekRowFractional, SEEKROWFRACTIONAL);
	H(ropFindRow, FINDROW);
	H(ropFreeBookmark, FREEBOOKMARK);
	H(ropExpandRow, EXPANDROW);
	H(ropCollapseRow, COLLAPSEROW);
	H(ropGetCollapseState, GETCOLLAPSESTATE);
	H(ropSetCollapseState, SETCOLLAPSESTATE);
	H(ropOpenMessage, OPENMESSAGE);
	H(ropCreateMessage, CREATEMESSAGE);
	H(ropSaveChangesMessage, SAVECHANGESMESSAGE);
	H(ropRemoveAllRecipients, REMOVEALLRECIPIENTS);
	H(ropModifyRecipients, MODIFYRECIPIENTS);
	H(ropReadRecipients, READRECIPIENTS);
	H(ropReloadCachedInformation, RELOADCACHEDINFORMATION);
	H(ropSetMessageStatus, SETMESSAGESTATUS);
	H(ropGetMessageStatus, GETMESSAGESTATUS);
	H(ropSetReadFlags, SETREADFLAGS);
	case ropSetMessageReadFlag: {
		r.ppayload = x.anew<SETMESSAGEREADFLAG_REQUEST>();
		if (r.ppayload == nullptr)
			return EXT_ERR_ALLOC;
		auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		auto plogon = rop_processor_get_logon_object(&pemsmdb_info->logmap, r.logon_id);
		if (plogon == nullptr)
			return EXT_ERR_INVALID_OBJECT;
		return rop_ext_pull(x, *static_cast<SETMESSAGEREADFLAG_REQUEST *>(r.ppayload),
		       plogon->is_private());
	}
	H(ropOpenAttachment, OPENATTACHMENT);
	H(ropCreateAttachment, CREATEATTACHMENT);
	H(ropDeleteAttachment, DELETEATTACHMENT);
	H(ropSaveChangesAttachment, SAVECHANGESATTACHMENT);
	H(ropOpenEmbeddedMessage, OPENEMBEDDEDMESSAGE);
	H(ropGetAttachmentTable, GETATTACHMENTTABLE);
	H(ropSubmitMessage, SUBMITMESSAGE);
	H(ropAbortSubmit, ABORTSUBMIT);
	H(ropSpoolerLockMessage, SPOOLERLOCKMESSAGE);
	H(ropTransportNewMail, TRANSPORTNEWMAIL);
	H(ropOptionsData, OPTIONSDATA);
	H(ropGetPropertyIdsFromNames, GETPROPERTYIDSFROMNAMES);
	H(ropGetNamesFromPropertyIds, GETNAMESFROMPROPERTYIDS);
	H(ropGetPropertiesSpecific, GETPROPERTIESSPECIFIC);
	H(ropGetPropertiesAll, GETPROPERTIESALL);
	H(ropSetProperties, SETPROPERTIES);
	H(ropSetPropertiesNoReplicate, SETPROPERTIESNOREPLICATE);
	H(ropDeleteProperties, DELETEPROPERTIES);
	H(ropDeletePropertiesNoReplicate, DELETEPROPERTIESNOREPLICATE);
	H(ropQueryNamedProperties, QUERYNAMEDPROPERTIES);
	H(ropCopyProperties, COPYPROPERTIES);
	H(ropCopyTo, COPYTO);
	H(ropProgress, PROGRESS);
	H(ropOpenStream, OPENSTREAM);
	H(ropReadStream, READSTREAM);
	H(ropWriteStream, WRITESTREAM);
	H(ropSetStreamSize, SETSTREAMSIZE);
	H(ropSeekStream, SEEKSTREAM);
	H(ropCopyToStream, COPYTOSTREAM);
	H(ropLockRegionStream, LOCKREGIONSTREAM);
	H(ropUnlockRegionStream, UNLOCKREGIONSTREAM);
	H(ropWriteAndCommitStream, WRITEANDCOMMITSTREAM);
	H(ropCloneStream, CLONESTREAM);
	H(ropModifyPermissions, MODIFYPERMISSIONS);
	H(ropGetPermissionsTable, GETPERMISSIONSTABLE);
	H(ropModifyRules, MODIFYRULES);
	H(ropGetRulesTable, GETRULESTABLE);
	H(ropUpdateDeferredActionMessages, UPDATEDEFERREDACTIONMESSAGES);
	H(ropFastTransferDestinationConfigure, FASTTRANSFERDESTCONFIGURE);
	H(ropFastTransferDestinationPutBuffer, FASTTRANSFERDESTPUTBUFFER);
	H(ropFastTransferSourceGetBuffer, FASTTRANSFERSOURCEGETBUFFER);
	H(ropFastTransferSourceCopyFolder, FASTTRANSFERSOURCECOPYFOLDER);
	H(ropFastTransferSourceCopyMessages, FASTTRANSFERSOURCECOPYMESSAGES);
	H(ropFastTransferSourceCopyTo, FASTTRANSFERSOURCECOPYTO);
	H(ropFastTransferSourceCopyProperties, FASTTRANSFERSOURCECOPYPROPERTIES);
	H(ropTellVersion, TELLVERSION);
	H(ropSynchronizationConfigure, SYNCCONFIGURE);
	H(ropSynchronizationImportMessageChange, SYNCIMPORTMESSAGECHANGE);
	H(ropSynchronizationImportReadStateChanges, SYNCIMPORTREADSTATECHANGES);
	H(ropSynchronizationImportHierarchyChange, SYNCIMPORTHIERARCHYCHANGE);
	H(ropSynchronizationImportDeletes, SYNCIMPORTDELETES);
	H(ropSynchronizationImportMessageMove, SYNCIMPORTMESSAGEMOVE);
	H(ropSynchronizationOpenCollector, SYNCOPENCOLLECTOR);
	H(ropSynchronizationGetTransferState, SYNCGETTRANSFERSTATE);
	H(ropSynchronizationUploadStateStreamBegin, SYNCUPLOADSTATESTREAMBEGIN);
	H(ropSynchronizationUploadStateStreamContinue, SYNCUPLOADSTATESTREAMCONTINUE);
	H(ropSetLocalReplicaMidsetDeleted, SETLOCALREPLICAMIDSETDELETED);
	H(ropGetLocalReplicaIds, GETLOCALREPLICAIDS);
	H(ropRegisterNotification, REGISTERNOTIFICATION);
	case ropGetReceiveFolderTable:
	case ropGetStoreState:
	case ropAbort:
	case ropGetStatus:
	case ropQueryPosition:
	case ropCreateBookmark:
	case ropQueryColumnsAll:
	case ropResetTable:
	case ropGetValidAttachments:
	case ropGetAddressTypes:
	case ropSetSpooler:
	case ropTransportSend:
	case ropGetTransportFolder:
	case ropGetPropertiesList:
	case ropCommitStream:
	case ropGetStreamSize:
	case ropSynchronizationUploadStateStreamEnd:
	case ropRelease:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
#undef H
}

/* not including ropNotify, ropPending, ropBackoff, ropBufferTooSmall */
pack_result rop_ext_push(EXT_PUSH &x, uint8_t logon_id, const rop_response &r)
{
	TRY(x.p_uint8(r.rop_id != ropGetMessageStatus ? r.rop_id : ropSetMessageStatus));
	TRY(x.p_uint8(r.hindex));
	TRY(x.p_uint32(r.result));
	if (r.result != ecSuccess) {
		switch (r.rop_id) {
		case ropLogon:
			if (r.result == ecWrongServer)
				return rop_ext_push(x, *static_cast<const LOGON_REDIRECT_RESPONSE *>(r.ppayload));
			return pack_result::success;
		case ropGetPropertyIdsFromNames:
			if (r.result == ecWarnWithErrors)
				break;
			return pack_result::success;
		case ropMoveCopyMessages:
		case ropMoveFolder:
		case ropCopyFolder:
			if (r.result == ecDstNullObject)
				return rop_ext_push(x, *static_cast<const NULL_DST_RESPONSE *>(r.ppayload));
			break;
		case ropCopyProperties:
		case ropCopyTo:
			if (r.result == ecDstNullObject)
				return x.p_uint32(static_cast<const NULL_DST1_RESPONSE *>(r.ppayload)->dhindex);
			return pack_result::success;
		case ropCopyToStream:
			if (r.result == ecDstNullObject)
				return rop_ext_push(x, *static_cast<const COPYTOSTREAM_NULL_DEST_RESPONSE *>(r.ppayload));
			return pack_result::success;
		case ropEmptyFolder:
		case ropDeleteFolder:
		case ropDeleteMessages:
		case ropHardDeleteMessages:
		case ropHardDeleteMessagesAndSubfolders:
		case ropFastTransferDestinationPutBuffer:
		case ropFastTransferSourceGetBuffer:
			break;
		default:
			return pack_result::success;
		}
	}

#define H(rop, t) \
	case (rop): \
		return rop_ext_push(x, *static_cast<const t ## _RESPONSE *>(r.ppayload));

	switch (r.rop_id) {
	case ropLogon: {
		auto pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		auto plogon = rop_processor_get_logon_object(&pemsmdb_info->logmap, logon_id);
		if (plogon == nullptr)
			return EXT_ERR_INVALID_OBJECT;
		return plogon->is_private() ?
		       rop_ext_push(x, *static_cast<const LOGON_PMB_RESPONSE *>(r.ppayload)) :
		       rop_ext_push(x, *static_cast<const LOGON_PF_RESPONSE *>(r.ppayload));
	}
	H(ropGetReceiveFolder, GETRECEIVEFOLDER);
	H(ropGetReceiveFolderTable, GETRECEIVEFOLDERTABLE);
	H(ropGetStoreState, GETSTORESTAT);
	H(ropGetOwningServers, GETOWNINGSERVERS);
	H(ropPublicFolderIsGhosted, PUBLICFOLDERISGHOSTED);
	H(ropLongTermIdFromId, LONGTERMIDFROMID);
	H(ropIdFromLongTermId, IDFROMLONGTERMID);
	H(ropGetPerUserLongTermIds, GETPERUSERLONGTERMIDS);
	H(ropGetPerUserGuid, GETPERUSERGUID);
	H(ropReadPerUserInformation, READPERUSERINFORMATION);
	H(ropOpenFolder, OPENFOLDER);
	H(ropCreateFolder, CREATEFOLDER);
	H(ropDeleteFolder, DELETEFOLDER);
	H(ropGetSearchCriteria, GETSEARCHCRITERIA);
	H(ropMoveCopyMessages, MOVECOPYMESSAGES);
	H(ropMoveFolder, MOVEFOLDER);
	H(ropCopyFolder, COPYFOLDER);
	H(ropEmptyFolder, EMPTYFOLDER);
	H(ropHardDeleteMessagesAndSubfolders, HARDDELETEMESSAGESANDSUBFOLDERS);
	H(ropDeleteMessages, DELETEMESSAGES);
	H(ropHardDeleteMessages, DELETEMESSAGES);
	H(ropGetHierarchyTable, GETHIERARCHYTABLE);
	H(ropGetContentsTable, GETCONTENTSTABLE);
	H(ropSetColumns, SETCOLUMNS);
	H(ropSortTable, SORTTABLE);
	H(ropRestrict, RESTRICT);
	H(ropQueryRows, QUERYROWS);
	H(ropAbort, ABORT);
	H(ropGetStatus, GETSTATUS);
	H(ropQueryPosition, QUERYPOSITION);
	H(ropSeekRow, SEEKROW);
	H(ropSeekRowBookmark, SEEKROWBOOKMARK);
	H(ropCreateBookmark, CREATEBOOKMARK);
	H(ropQueryColumnsAll, QUERYCOLUMNSALL);
	H(ropFindRow, FINDROW);
	H(ropExpandRow, EXPANDROW);
	H(ropCollapseRow, COLLAPSEROW);
	H(ropGetCollapseState, GETCOLLAPSESTATE);
	H(ropSetCollapseState, SETCOLLAPSESTATE);
	H(ropOpenMessage, OPENMESSAGE);
	H(ropCreateMessage, CREATEMESSAGE);
	H(ropSaveChangesMessage, SAVECHANGESMESSAGE);
	H(ropReadRecipients, READRECIPIENTS);
	H(ropReloadCachedInformation, RELOADCACHEDINFORMATION);
	H(ropSetMessageStatus, SETMESSAGESTATUS);
	H(ropGetMessageStatus, GETMESSAGESTATUS);
	H(ropSetReadFlags, SETREADFLAGS);
	H(ropSetMessageReadFlag, SETMESSAGEREADFLAG);
	H(ropCreateAttachment, CREATEATTACHMENT);
	H(ropOpenEmbeddedMessage, OPENEMBEDDEDMESSAGE);
	H(ropGetValidAttachments, GETVALIDATTACHMENTS);
	H(ropGetAddressTypes, GETADDRESSTYPES);
	H(ropTransportSend, TRANSPORTSEND);
	H(ropGetTransportFolder, GETTRANSPORTFOLDER);
	H(ropOptionsData, OPTIONSDATA);
	H(ropGetPropertyIdsFromNames, GETPROPERTYIDSFROMNAMES);
	H(ropGetNamesFromPropertyIds, GETNAMESFROMPROPERTYIDS);
	H(ropGetPropertiesSpecific, GETPROPERTIESSPECIFIC);
	H(ropGetPropertiesAll, GETPROPERTIESALL);
	H(ropGetPropertiesList, GETPROPERTIESLIST);
	H(ropSetProperties, SETPROPERTIES);
	H(ropSetPropertiesNoReplicate, SETPROPERTIESNOREPLICATE);
	H(ropDeleteProperties, DELETEPROPERTIES);
	H(ropDeletePropertiesNoReplicate, DELETEPROPERTIESNOREPLICATE);
	H(ropQueryNamedProperties, QUERYNAMEDPROPERTIES);
	H(ropCopyProperties, COPYPROPERTIES);
	H(ropCopyTo, COPYTO);
	H(ropProgress, PROGRESS);
	H(ropOpenStream, OPENSTREAM);
	H(ropReadStream, READSTREAM);
	H(ropWriteStream, WRITESTREAM);
	H(ropGetStreamSize, GETSTREAMSIZE);
	H(ropSeekStream, SEEKSTREAM);
	H(ropCopyToStream, COPYTOSTREAM);
	H(ropWriteAndCommitStream, WRITEANDCOMMITSTREAM);
	H(ropFastTransferDestinationPutBuffer, FASTTRANSFERDESTPUTBUFFER);
	H(ropFastTransferSourceGetBuffer, FASTTRANSFERSOURCEGETBUFFER);
	H(ropSynchronizationImportMessageChange, SYNCIMPORTMESSAGECHANGE);
	H(ropSynchronizationImportHierarchyChange, SYNCIMPORTHIERARCHYCHANGE);
	H(ropSynchronizationImportMessageMove, SYNCIMPORTMESSAGEMOVE);
	H(ropGetLocalReplicaIds, GETLOCALREPLICAIDS);
	case ropSetReceiveFolder:
	case ropWritePerUserInformation:
	case ropSetSearchCriteria:
	case ropSeekRowFractional:
	case ropFreeBookmark:
	case ropResetTable:
	case ropRemoveAllRecipients:
	case ropModifyRecipients:
	case ropOpenAttachment:
	case ropDeleteAttachment:
	case ropSaveChangesAttachment:
	case ropGetAttachmentTable:
	case ropSubmitMessage:
	case ropAbortSubmit:
	case ropSetSpooler:
	case ropSpoolerLockMessage:
	case ropTransportNewMail:
	case ropCommitStream:
	case ropSetStreamSize:
	case ropLockRegionStream:
	case ropUnlockRegionStream:
	case ropCloneStream:
	case ropModifyPermissions:
	case ropGetPermissionsTable:
	case ropModifyRules:
	case ropGetRulesTable:
	case ropUpdateDeferredActionMessages:
	case ropFastTransferDestinationConfigure:
	case ropFastTransferSourceCopyFolder:
	case ropFastTransferSourceCopyMessages:
	case ropFastTransferSourceCopyTo:
	case ropFastTransferSourceCopyProperties:
	case ropTellVersion:
	case ropSynchronizationConfigure:
	case ropSynchronizationImportReadStateChanges:
	case ropSynchronizationImportDeletes:
	case ropSynchronizationOpenCollector:
	case ropSynchronizationGetTransferState:
	case ropSynchronizationUploadStateStreamBegin:
	case ropSynchronizationUploadStateStreamContinue:
	case ropSynchronizationUploadStateStreamEnd:
	case ropSetLocalReplicaMidsetDeleted:
	case ropRegisterNotification:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
#undef H
}

pack_result rop_ext_pull(EXT_PULL &x, ROP_BUFFER &r)
{
	int tmp_num;
	uint16_t size;
	EXT_PULL subext;
	DOUBLE_LIST_NODE *pnode;
	uint32_t decompressed_len;
	RPC_HEADER_EXT rpc_header_ext;
	
	TRY(x.g_rpc_header_ext(&rpc_header_ext));
	if (!(rpc_header_ext.flags & RHE_FLAG_LAST))
		return EXT_ERR_HEADER_FLAGS;
	r.rhe_version = rpc_header_ext.version;
	r.rhe_flags = rpc_header_ext.flags;
	double_list_init(&r.rop_list);
	if (rpc_header_ext.size == 0)
		return EXT_ERR_HEADER_SIZE;
	auto pbuff = x.anew<uint8_t>(0x8000);
	if (pbuff == nullptr)
		return EXT_ERR_ALLOC;
	auto pdata = x.m_udata + x.m_offset;
	/*
	 * Obfuscation case - modify data in place (devs: ensure callers
	 * have the object actually mutable)
	 */
	if (rpc_header_ext.flags & RHE_FLAG_XORMAGIC)
		common_util_obfuscate_data(deconst(pdata), rpc_header_ext.size);
	/* lzxpress case */
	if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
		decompressed_len = lzxpress_decompress(pdata,
					rpc_header_ext.size, pbuff, 0x8000);
		if (decompressed_len < rpc_header_ext.size_actual) {
			mlog(LV_WARN, "W-1097: lzxdecompress failed for client input (z=%u, exp=%u, got=%u)",
				rpc_header_ext.size, rpc_header_ext.size_actual,
				decompressed_len);
			return EXT_ERR_LZXPRESS;
		}
	} else {
		memcpy(pbuff, pdata, rpc_header_ext.size_actual);
	}
	subext.init(pbuff, rpc_header_ext.size_actual, common_util_alloc, EXT_FLAG_UTF16);
	TRY(subext.g_uint16(&size));
	while (subext.m_offset < size) {
		pnode = x.anew<DOUBLE_LIST_NODE>();
		if (pnode == nullptr)
			return EXT_ERR_ALLOC;
		pnode->pdata = x.anew<rop_request>();
		if (pnode->pdata == nullptr)
			return EXT_ERR_ALLOC;
		TRY(rop_ext_pull(subext, *static_cast<rop_request *>(pnode->pdata)));
		double_list_append_as_tail(&r.rop_list, pnode);
	}
	tmp_num = (rpc_header_ext.size_actual - size) / sizeof(uint32_t);
	if (0 == tmp_num) {
		r.hnum = 0;
		r.phandles = nullptr;
		return EXT_ERR_SUCCESS;
	}
	if (tmp_num > 255)
		return EXT_ERR_RANGE;
	r.hnum = tmp_num;
	r.phandles = x.anew<uint32_t>(r.hnum);
	if (r.phandles == nullptr) {
		r.hnum = 0;
		return EXT_ERR_ALLOC;
	}
	for (size_t i = 0; i < r.hnum; ++i)
		TRY(subext.g_uint32(&r.phandles[i]));
	return EXT_ERR_SUCCESS;
}

pack_result rop_ext_make_rpc_ext(const void *pbuff_in, uint32_t in_len,
    const ROP_BUFFER *prop_buff, void *pbuff_out, uint32_t *pout_len) try
{
	EXT_PUSH subext;
	EXT_PUSH ext_push;
	static constexpr size_t ext_buff_size = 0x10000;
	auto ext_buff = std::make_unique<uint8_t[]>(ext_buff_size);
	auto tmp_buff = std::make_unique<uint8_t[]>(ext_buff_size);
	RPC_HEADER_EXT rpc_header_ext;
	
	if (!subext.init(ext_buff.get(), ext_buff_size, EXT_FLAG_UTF16))
		return EXT_ERR_ALLOC;
	TRY(subext.p_uint16(in_len + sizeof(uint16_t)));
	TRY(subext.p_bytes(pbuff_in, in_len));
	for (size_t i = 0; i < prop_buff->hnum; ++i)
		TRY(subext.p_uint32(prop_buff->phandles[i]));
	rpc_header_ext.version = prop_buff->rhe_version;
	rpc_header_ext.flags = prop_buff->rhe_flags;
	rpc_header_ext.size_actual = subext.m_offset;
	rpc_header_ext.size = rpc_header_ext.size_actual;
	if (rpc_header_ext.flags & RHE_FLAG_COMPRESSED) {
		if (rpc_header_ext.size_actual < MINIMUM_COMPRESS_SIZE) {
			rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
		} else {
			uint32_t compressed_len = lzxpress_compress(ext_buff.get(), subext.m_offset, tmp_buff.get());
			if (compressed_len == 0 || compressed_len >= subext.m_offset) {
				/* if we can not get benefit from the
					compression, unmask the compress bit */
				rpc_header_ext.flags &= ~RHE_FLAG_COMPRESSED;
			} else {
				rpc_header_ext.size = compressed_len;
				memcpy(ext_buff.get(), tmp_buff.get(), compressed_len);
			}
		}
	}
	rpc_header_ext.flags &= ~RHE_FLAG_XORMAGIC;
	if (!ext_push.init(pbuff_out, *pout_len, EXT_FLAG_UTF16))
		return EXT_ERR_ALLOC;
	TRY(ext_push.p_rpchdr(rpc_header_ext));
	TRY(ext_push.p_bytes(ext_buff.get(), rpc_header_ext.size));
	*pout_len = ext_push.m_offset;
	return EXT_ERR_SUCCESS;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1172: ENOMEM");
	return EXT_ERR_ALLOC;
}

void rop_ext_set_rhe_flag_last(uint8_t *pdata, uint32_t last_offset)
{
	auto p = &pdata[last_offset+sizeof(uint16_t)];
	cpu_to_le16p(p, le16p_to_cpu(p) | RHE_FLAG_LAST);
}
