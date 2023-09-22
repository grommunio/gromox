// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/ext_buffer.hpp>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "notify_response.h"
#include "processor_types.h"
#include "rop_ext.h"
#include "rop_ids.hpp"

using namespace gromox;

NOTIFY_RESPONSE *notify_response::create(uint32_t handle, uint8_t logon_id) try
{
	return new notify_response{handle, logon_id};
} catch (const std::bad_alloc &) {
	return nullptr;
}

notify_response::~notify_response()
{
	if (proptags.pproptag != nullptr)
		free(proptags.pproptag);
	free(msg_class);
}

static ec_error_t cvt_new_mail(notify_response &n,
    const DB_NOTIFY_NEW_MAIL &x, BOOL b_unicode)
{
	n.nflags       = NF_NEW_MAIL | NF_BY_MESSAGE;
	n.folder_id    = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id   = rop_util_make_eid_ex(1, x.message_id);
	n.msg_flags    = x.message_flags;
	n.unicode_flag = !!b_unicode;
	n.msg_class    = strdup(x.pmessage_class);
	if (n.msg_class == nullptr)
		return ecServerOOM;
	return ecSuccess;
}

static ec_error_t copy_tags(notify_response &m, const PROPTAG_ARRAY &tags)
{
	m.proptags.count = tags.count;
	if (m.proptags.count == 0)
		return ecSuccess;
	m.proptags.pproptag = me_alloc<uint32_t>(tags.count);
	if (m.proptags.pproptag == nullptr)
		return ecServerOOM;
	memcpy(m.proptags.pproptag, tags.pproptag, sizeof(uint32_t) * tags.count);
	return ecSuccess;
}

static ec_error_t cvt_fld_created(notify_response &n,
    const DB_NOTIFY_FOLDER_CREATED &x)
{
	n.nflags    = NF_OBJECT_CREATED;
	n.folder_id = rop_util_nfid_to_eid(x.folder_id);
	n.parent_id = rop_util_make_eid_ex(1, x.parent_id);
	return copy_tags(n, x.proptags);
}

static ec_error_t cvt_msg_created(notify_response &n,
    const DB_NOTIFY_MESSAGE_CREATED &x)
{
	n.nflags     = NF_OBJECT_CREATED | NF_BY_MESSAGE;
	n.folder_id  = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id = rop_util_make_eid_ex(1, x.message_id);
	return copy_tags(n, x.proptags);
}

static ec_error_t cvt_link_created(notify_response &n,
    const DB_NOTIFY_LINK_CREATED &x)
{
	n.nflags     = NF_OBJECT_CREATED | NF_BY_SEARCH | NF_BY_MESSAGE;
	n.folder_id  = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id = rop_util_make_eid_ex(1, x.message_id);
	n.parent_id  = rop_util_make_eid_ex(1, x.parent_id);
	return copy_tags(n, x.proptags);
}

static ec_error_t cvt_fld_deleted(notify_response &n,
    const DB_NOTIFY_FOLDER_DELETED &x)
{
	n.nflags    = NF_OBJECT_DELETED;
	n.folder_id = rop_util_nfid_to_eid(x.folder_id);
	n.parent_id = rop_util_make_eid_ex(1, x.parent_id);
	return ecSuccess;
}

static ec_error_t cvt_msg_deleted(notify_response &n,
    const DB_NOTIFY_MESSAGE_DELETED &x)
{
	n.nflags     = NF_OBJECT_DELETED | NF_BY_MESSAGE;
	n.folder_id  = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id = rop_util_make_eid_ex(1, x.message_id);
	return ecSuccess;
}

static ec_error_t cvt_link_deleted(notify_response &n,
    const DB_NOTIFY_LINK_DELETED &x)
{
	n.nflags     = NF_OBJECT_DELETED | NF_BY_SEARCH | NF_BY_MESSAGE;
	n.folder_id  = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id = rop_util_make_eid_ex(1, x.message_id);
	n.parent_id  = rop_util_make_eid_ex(1, x.parent_id);
	return ecSuccess;
}

static ec_error_t cvt_fld_modified(notify_response &n,
    const DB_NOTIFY_FOLDER_MODIFIED &x)
{
	n.nflags    = NF_OBJECT_MODIFIED;
	n.folder_id = rop_util_nfid_to_eid(x.folder_id);
	if (x.ptotal != nullptr) {
		n.nflags |= NF_HAS_TOTAL;
		n.total_count = *x.ptotal;
	}
	if (x.punread != nullptr) {
		n.nflags |= NF_HAS_UNREAD;
		n.unread_count = *x.punread;
	}
	return copy_tags(n, x.proptags);
}

static ec_error_t cvt_msg_modified(notify_response &n,
    const DB_NOTIFY_MESSAGE_MODIFIED &x)
{
	n.nflags     = NF_OBJECT_MODIFIED | NF_BY_MESSAGE;
	n.folder_id  = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id = rop_util_make_eid_ex(1, x.message_id);
	return copy_tags(n, x.proptags);
}

static ec_error_t cvt_fld_mvcp(notify_response &n, uint8_t nflags,
    const DB_NOTIFY_FOLDER_MVCP &x)
{
	n.nflags        = nflags;
	n.folder_id     = rop_util_nfid_to_eid(x.folder_id);
	n.parent_id     = rop_util_make_eid_ex(1, x.parent_id);
	n.old_folder_id = rop_util_nfid_to_eid(x.old_folder_id);
	n.old_parent_id = rop_util_make_eid_ex(1, x.old_parent_id);
	return ecSuccess;
}

static ec_error_t cvt_msg_mvcp(notify_response &n, uint8_t nflags,
    const DB_NOTIFY_MESSAGE_MVCP &x)
{
	n.nflags         = nflags | NF_BY_MESSAGE;
	n.folder_id      = rop_util_make_eid_ex(1, x.folder_id);
	n.message_id     = rop_util_make_eid_ex(1, x.message_id);
	n.old_folder_id  = rop_util_make_eid_ex(1, x.old_folder_id);
	n.old_message_id = rop_util_make_eid_ex(1, x.old_message_id);
	return ecSuccess;
}

static ec_error_t cvt_fld_search_completed(notify_response &n,
    const DB_NOTIFY_SEARCH_COMPLETED &x)
{
	n.nflags    = NF_SEARCH_COMPLETE;
	n.folder_id = rop_util_make_eid_ex(1, x.folder_id);
	return ecSuccess;
}

static ec_error_t cvt_hiertbl_changed(notify_response &n)
{
	n.nflags      = NF_TABLE_MODIFIED;
	n.table_event = TABLE_EVENT_TABLE_CHANGED;
	return ecSuccess;
}

static ec_error_t cvt_cttbl_changed(notify_response &n)
{
	n.nflags      = NF_TABLE_MODIFIED | NF_BY_MESSAGE;
	n.table_event = TABLE_EVENT_TABLE_CHANGED;
	return ecSuccess;
}

static ec_error_t cvt_srchtbl_changed(notify_response &n)
{
	n.nflags      = NF_TABLE_MODIFIED | NF_BY_SEARCH | NF_BY_MESSAGE;
	n.table_event = TABLE_EVENT_TABLE_CHANGED;
	return ecSuccess;
}

static ec_error_t cvt_hierrow_added(notify_response &n,
    const DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED &x)
{
	n.nflags          = NF_TABLE_MODIFIED;
	n.table_event     = TABLE_EVENT_ROW_ADDED;
	n.row_folder_id   = rop_util_nfid_to_eid(x.row_folder_id);
	n.after_folder_id = x.after_folder_id == 0 ? eid_t(0) :
	                    rop_util_nfid_to_eid(x.after_folder_id);
	return ecSuccess;
}

static ec_error_t cvt_ctrow_added(notify_response &n,
    const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED &x)
{
	n.nflags          = NF_TABLE_MODIFIED | NF_BY_MESSAGE;
	n.table_event     = TABLE_EVENT_ROW_ADDED;
	n.row_folder_id   = rop_util_make_eid_ex(1, x.row_folder_id);
	n.row_message_id  = rop_util_nfid_to_eid2(x.row_message_id);
	n.row_instance    = x.row_instance;
	n.after_folder_id = x.after_folder_id == 0 ? eid_t(0) :
	                    rop_util_make_eid_ex(1, x.after_folder_id);
	n.after_row_id    = x.after_row_id == 0 ? eid_t(0) :
	                    rop_util_nfid_to_eid2(x.after_row_id);
	n.after_instance  = x.after_instance;
	return ecSuccess;
}

static ec_error_t cvt_srchrow_added(notify_response &n,
    const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED &x)
{
	n.nflags          = NF_TABLE_MODIFIED | NF_BY_SEARCH | NF_BY_MESSAGE;
	n.table_event     = TABLE_EVENT_ROW_ADDED;
	n.row_folder_id   = rop_util_make_eid_ex(1, x.row_folder_id);
	n.row_message_id  = rop_util_nfid_to_eid2(x.row_message_id);
	n.row_instance    = x.row_instance;
	n.after_folder_id = x.after_folder_id == 0 ? eid_t(0) :
	                    rop_util_make_eid_ex(1, x.after_folder_id);
	n.after_row_id    = x.after_row_id == 0 ? eid_t(0) :
	                    rop_util_nfid_to_eid2(x.after_row_id);
	n.after_instance  = x.after_instance;
	return ecSuccess;
}

static ec_error_t cvt_hierrow_deleted(notify_response &n,
    const DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED &x)
{
	n.nflags        = NF_TABLE_MODIFIED;
	n.table_event   = TABLE_EVENT_ROW_DELETED;
	n.row_folder_id = rop_util_nfid_to_eid(x.row_folder_id);
	return ecSuccess;
}

static ec_error_t cvt_ctrow_deleted(notify_response &n,
    const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED &x)
{
	n.nflags         = NF_TABLE_MODIFIED | NF_BY_MESSAGE;
	n.table_event    = TABLE_EVENT_ROW_DELETED;
	n.row_folder_id  = rop_util_make_eid_ex(1, x.row_folder_id);
	n.row_message_id = rop_util_nfid_to_eid2(x.row_message_id);
	n.row_instance   = x.row_instance;
	return ecSuccess;
}

static ec_error_t cvt_srchrow_deleted(notify_response &n,
    const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED &x)
{
	n.nflags         = NF_TABLE_MODIFIED | NF_BY_SEARCH | NF_BY_MESSAGE;
	n.table_event    = TABLE_EVENT_ROW_DELETED;
	n.row_folder_id  = rop_util_make_eid_ex(1, x.row_folder_id);
	n.row_message_id = rop_util_nfid_to_eid2(x.row_message_id);
	n.row_instance   = x.row_instance;
	return ecSuccess;
}

static ec_error_t cvt_hierrow_modified(notify_response &n,
    const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED &x)
{
	n.nflags          = NF_TABLE_MODIFIED;
	n.table_event     = TABLE_EVENT_ROW_MODIFIED;
	n.row_folder_id   = rop_util_nfid_to_eid(x.row_folder_id);
	n.after_folder_id = x.after_folder_id == 0 ? eid_t(0) :
	                    rop_util_nfid_to_eid(x.after_folder_id);
	return ecSuccess;
}

static ec_error_t cvt_ctrow_modified(notify_response &n,
    const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED &x)
{
	n.nflags          = NF_TABLE_MODIFIED | NF_BY_MESSAGE;
	n.table_event     = TABLE_EVENT_ROW_MODIFIED;
	n.row_folder_id   = rop_util_make_eid_ex(1, x.row_folder_id);
	n.row_message_id  = rop_util_nfid_to_eid2(x.row_message_id);
	n.row_instance    = x.row_instance;
	n.after_folder_id = x.after_folder_id == 0 ? eid_t(0) :
	                    rop_util_make_eid_ex(1, x.after_folder_id);
	n.after_row_id    = x.after_row_id == 0 ? eid_t(0) :
	                    rop_util_nfid_to_eid2(x.after_row_id);
	n.after_instance  = x.after_instance;
	return ecSuccess;
}

static ec_error_t cvt_srchrow_modified(notify_response &n,
    const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED &x)
{
	n.nflags          = NF_TABLE_MODIFIED | NF_BY_SEARCH | NF_BY_MESSAGE;
	n.table_event     = TABLE_EVENT_ROW_MODIFIED;
	n.row_folder_id   = rop_util_make_eid_ex(1, x.row_folder_id);
	n.row_message_id  = rop_util_nfid_to_eid2(x.row_message_id);
	n.row_instance    = x.row_instance;
	n.after_folder_id = x.after_folder_id == 0 ? eid_t(0) :
	                    rop_util_make_eid_ex(1, x.after_folder_id);
	n.after_row_id    = x.after_row_id == 0 ? eid_t(0) :
	                    rop_util_nfid_to_eid2(x.after_row_id);
	n.after_instance  = x.after_instance;
	return ecSuccess;
}

ec_error_t notify_response::cvt_from_dbnotify(BOOL b_cache, const DB_NOTIFY &dbn)
{
	auto &n = *this;

	switch (dbn.type) {
	case db_notify_type::new_mail:
		return cvt_new_mail(n, *static_cast<const DB_NOTIFY_NEW_MAIL *>(dbn.pdata), b_cache);
	case db_notify_type::folder_created:
		return cvt_fld_created(n, *static_cast<const DB_NOTIFY_FOLDER_CREATED *>(dbn.pdata));
	case db_notify_type::message_created:
		return cvt_msg_created(n, *static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(dbn.pdata));
	case db_notify_type::link_created:
		return cvt_link_created(n, *static_cast<const DB_NOTIFY_LINK_CREATED *>(dbn.pdata));
	case db_notify_type::folder_deleted:
		return cvt_fld_deleted(n, *static_cast<const DB_NOTIFY_FOLDER_DELETED *>(dbn.pdata));
	case db_notify_type::message_deleted:
		return cvt_msg_deleted(n, *static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(dbn.pdata));
	case db_notify_type::link_deleted:
		return cvt_link_deleted(n, *static_cast<const DB_NOTIFY_LINK_DELETED *>(dbn.pdata));
	case db_notify_type::folder_modified:
		return cvt_fld_modified(n, *static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(dbn.pdata));
	case db_notify_type::message_modified:
		return cvt_msg_modified(n, *static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(dbn.pdata));
	case db_notify_type::folder_moved:
	case db_notify_type::folder_copied: {
		auto nflags = dbn.type == db_notify_type::folder_moved ?
		              NF_OBJECT_MOVED : NF_OBJECT_COPIED;
		return cvt_fld_mvcp(n, nflags, *static_cast<const DB_NOTIFY_FOLDER_MVCP *>(dbn.pdata));
	}
	case db_notify_type::message_moved:
	case db_notify_type::message_copied: {
		auto nflags = dbn.type == db_notify_type::message_moved ?
		              NF_OBJECT_MOVED : NF_OBJECT_COPIED;
		return cvt_msg_mvcp(n, nflags, *static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(dbn.pdata));
	}
	case db_notify_type::search_completed:
		return cvt_fld_search_completed(n, *static_cast<const DB_NOTIFY_SEARCH_COMPLETED *>(dbn.pdata));
	case db_notify_type::hierarchy_table_changed:
		return cvt_hiertbl_changed(n);
	case db_notify_type::content_table_changed:
		return cvt_cttbl_changed(n);
	case db_notify_type::search_table_changed:
		return cvt_srchtbl_changed(n);
	case db_notify_type::hierarchy_table_row_added:
		return cvt_hierrow_added(n, *static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *>(dbn.pdata));
	case db_notify_type::content_table_row_added:
		return cvt_ctrow_added(n, *static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *>(dbn.pdata));
	case db_notify_type::search_table_row_added:
		return cvt_srchrow_added(n, *static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *>(dbn.pdata));
	case db_notify_type::hierarchy_table_row_deleted:
		return cvt_hierrow_deleted(n, *static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *>(dbn.pdata));
	case db_notify_type::content_table_row_deleted:
		return cvt_ctrow_deleted(n, *static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *>(dbn.pdata));
	case db_notify_type::search_table_row_deleted:
		return cvt_srchrow_deleted(n, *static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *>(dbn.pdata));
	case db_notify_type::hierarchy_table_row_modified:
		return cvt_hierrow_modified(n, *static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *>(dbn.pdata));
	case db_notify_type::content_table_row_modified:
		return cvt_ctrow_modified(n, *static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *>(dbn.pdata));
	case db_notify_type::search_table_row_modified:
		return cvt_srchrow_modified(n, *static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *>(dbn.pdata));
	}
	return ecInvalidParam;
}

void notify_response::ctrow_event_to_change()
{
	*this       = NOTIFY_RESPONSE{handle, logon_id};
	nflags      = NF_TABLE_MODIFIED | NF_BY_MESSAGE;
	table_event = TABLE_EVENT_TABLE_CHANGED;
}

#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)
pack_result rop_ext_push(EXT_PUSH &x, const notify_response &n)
{
	TRY(x.p_uint8(ropRegisterNotify));
	TRY(x.p_uint32(n.handle));
	TRY(x.p_uint8(n.logon_id));

	TRY(x.p_uint16(n.nflags));
	if (__builtin_popcount(n.nflags & 0xfff) != 1)
		return pack_result::format;
	if (n.nflags & NF_TABLE_MODIFIED) {
		TRY(x.p_uint16(n.table_event));
		auto am  = n.table_event == TABLE_EVENT_ROW_ADDED ||
		           n.table_event == TABLE_EVENT_ROW_MODIFIED;
		auto amd = am || n.table_event == TABLE_EVENT_ROW_DELETED;
		if (amd)
			TRY(x.p_uint64(n.row_folder_id));
		if (amd && n.nflags & NF_BY_MESSAGE) {
			TRY(x.p_uint64(n.row_message_id));
			TRY(x.p_uint32(n.row_instance));
		}
		if (am)
			TRY(x.p_uint64(n.after_folder_id));
		if (am && n.nflags & NF_BY_MESSAGE) {
			TRY(x.p_uint64(n.after_row_id));
			TRY(x.p_uint32(n.after_instance));
		}
		if (am) {
			assert(n.row_data != nullptr);
			TRY(x.p_bin_s(*n.row_data));
		}
	}
	if ((n.nflags & (NF_TABLE_MODIFIED | NF_EXTENDED)) == 0)
		TRY(x.p_uint64(n.folder_id));
	if ((n.nflags & (NF_TABLE_MODIFIED | NF_EXTENDED | NF_BY_MESSAGE)) == NF_BY_MESSAGE)
		TRY(x.p_uint64(n.message_id));
	if (n.nflags & (NF_OBJECT_CREATED | NF_OBJECT_DELETED |
	    NF_OBJECT_MOVED | NF_OBJECT_COPIED) &&
	    (n.nflags & NF_BY_SEARCH) == !!(n.nflags & NF_BY_MESSAGE))
		TRY(x.p_uint64(n.parent_id));
	if (n.nflags & (NF_OBJECT_MOVED | NF_OBJECT_COPIED))
		TRY(x.p_uint64(n.old_folder_id));
	if (n.nflags & (NF_OBJECT_MOVED | NF_OBJECT_COPIED) &&
	    n.nflags & NF_BY_MESSAGE)
		TRY(x.p_uint64(n.old_message_id));
	if (n.nflags & (NF_OBJECT_MOVED | NF_OBJECT_COPIED) &&
	    !(n.nflags & NF_BY_MESSAGE))
		TRY(x.p_uint64(n.old_parent_id));
	if (n.nflags & (NF_OBJECT_CREATED | NF_OBJECT_MODIFIED)) {
		assert(n.proptags.count == 0 || n.proptags.pproptag != nullptr);
		TRY(x.p_proptag_a(n.proptags));
	}
	if (n.nflags & NF_HAS_TOTAL)
		TRY(x.p_uint32(n.total_count));
	if (n.nflags & NF_HAS_UNREAD)
		TRY(x.p_uint32(n.unread_count));
	if (n.nflags & NF_NEW_MAIL) {
		TRY(x.p_uint32(n.msg_flags));
		TRY(x.p_uint8(!!n.unicode_flag));
		if (!n.unicode_flag)
			TRY(x.p_str(n.msg_class));
		else
			TRY(x.p_wstr(n.msg_class));
	}
	return pack_result::success;
}
#undef TRY
