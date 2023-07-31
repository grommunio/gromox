// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "notify_response.h"
#include "processor_types.h"

using namespace gromox;

namespace {

struct NOTIFICATION_DATA_MEMORY {
	uint16_t table_event;
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint32_t row_instance;
	uint64_t after_folder_id;
	uint64_t after_row_id;
	uint32_t after_instance;
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
	uint64_t old_folder_id;
	uint64_t old_message_id;
	uint64_t old_parent_id;
	PROPTAG_ARRAY proptags;
	uint32_t total_count;
	uint32_t unread_count;
	uint32_t message_flags;
	uint8_t unicode_flag;
};

}

static inline NOTIFICATION_DATA_MEMORY *notify_to_ndm(NOTIFY_RESPONSE *z)
{
	return reinterpret_cast<NOTIFICATION_DATA_MEMORY *>(z + 1);
}

NOTIFY_RESPONSE* notify_response_init(uint32_t handle, uint8_t logon_id)
{
	auto pnotify = static_cast<NOTIFY_RESPONSE *>(malloc(sizeof(NOTIFY_RESPONSE) + sizeof(NOTIFICATION_DATA_MEMORY)));
	if (NULL == pnotify) {
		return NULL;
	}
	memset(pnotify, 0, sizeof(NOTIFY_RESPONSE));
	pnotify->handle = handle;
	pnotify->logon_id = logon_id;
	return pnotify;
}

void notify_response_free(NOTIFY_RESPONSE *pnotify)
{
	if (pnotify->notification_data.pproptags != nullptr &&
	    pnotify->notification_data.pproptags->pproptag != nullptr)
		free(pnotify->notification_data.pproptags->pproptag);
	if (NULL != pnotify->notification_data.pstr_class) {
		free(pnotify->notification_data.pstr_class);
	}
	free(pnotify);
}

static BOOL notify_response_specify_new_mail(NOTIFY_RESPONSE *pnotify,
	uint64_t folder_id, uint64_t message_id, uint32_t message_flags,
	BOOL b_unicode, const char *pmessage_class)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_NEWMAIL | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	pnotify->notification_data.pmessage_flags = &pmemory->message_flags;
	pmemory->message_flags = message_flags;
	pnotify->notification_data.punicode_flag = &pmemory->unicode_flag;
	pmemory->unicode_flag = !!b_unicode;
	pnotify->notification_data.pstr_class = strdup(pmessage_class);
	if (NULL == pnotify->notification_data.pstr_class) {
		return FALSE;
	}
	return TRUE;
}

static BOOL notify_response_specify_folder_created(NOTIFY_RESPONSE *pnotify,
    uint64_t folder_id, uint64_t parent_id, const PROPTAG_ARRAY *pproptags)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_OBJECTCREATED;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_nfid_to_eid(folder_id);
	pnotify->notification_data.pparent_id = &pmemory->parent_id;
	pmemory->parent_id = rop_util_make_eid_ex(1, parent_id);
	pnotify->notification_data.pproptags = &pmemory->proptags;
	pmemory->proptags.count = pproptags->count;
	if (0 == pmemory->proptags.count) {
		pmemory->proptags.pproptag = NULL;
		return TRUE;
	}
	pmemory->proptags.pproptag = me_alloc<uint32_t>(pproptags->count);
	if (NULL == pmemory->proptags.pproptag) {
		return FALSE;
	}
	memcpy(pmemory->proptags.pproptag, pproptags->pproptag,
		sizeof(uint32_t)*pproptags->count);
	return TRUE;
}

static BOOL notify_response_specify_message_created(NOTIFY_RESPONSE *pnotify,
    uint64_t folder_id, uint64_t message_id, const PROPTAG_ARRAY *pproptags)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_OBJECTCREATED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	pnotify->notification_data.pproptags = &pmemory->proptags;
	pmemory->proptags.count = pproptags->count;
	if (0 == pmemory->proptags.count) {
		pmemory->proptags.pproptag = NULL;
		return TRUE;
	}
	pmemory->proptags.pproptag = me_alloc<uint32_t>(pproptags->count);
	if (NULL == pmemory->proptags.pproptag) {
		return FALSE;
	}
	memcpy(pmemory->proptags.pproptag, pproptags->pproptag,
		sizeof(uint32_t)*pproptags->count);
	return TRUE;
}

static BOOL notify_response_specify_link_created(NOTIFY_RESPONSE *pnotify,
    uint64_t folder_id, uint64_t message_id, uint64_t parent_id,
    const PROPTAG_ARRAY *pproptags)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
						NOTIFICATION_FLAG_OBJECTCREATED |
						NOTIFICATION_FLAG_MOST_SEARCH |
						NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	pnotify->notification_data.pparent_id = &pmemory->parent_id;
	pmemory->parent_id = rop_util_make_eid_ex(1, parent_id);
	pnotify->notification_data.pproptags = &pmemory->proptags;
	pmemory->proptags.count = pproptags->count;
	if (0 == pmemory->proptags.count) {
		pmemory->proptags.pproptag = NULL;
		return TRUE;
	}
	pmemory->proptags.pproptag = me_alloc<uint32_t>(pproptags->count);
	if (NULL == pmemory->proptags.pproptag) {
		return FALSE;
	}
	memcpy(pmemory->proptags.pproptag, pproptags->pproptag,
		sizeof(uint32_t)*pproptags->count);
	return TRUE;
}

static BOOL notify_response_specify_folder_deleted(
	NOTIFY_RESPONSE *pnotify, uint64_t folder_id, uint64_t parent_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_OBJECTDELETED;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_nfid_to_eid(folder_id);
	pnotify->notification_data.pparent_id = &pmemory->parent_id;
	pmemory->parent_id = rop_util_make_eid_ex(1, parent_id);
	return TRUE;
}

static BOOL notify_response_specify_message_deleted(
	NOTIFY_RESPONSE *pnotify, uint64_t folder_id, uint64_t message_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_OBJECTDELETED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	return TRUE;
}
	
static BOOL notify_response_specify_link_deleted(
	NOTIFY_RESPONSE *pnotify, uint64_t folder_id,
	uint64_t message_id, uint64_t parent_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
						NOTIFICATION_FLAG_OBJECTDELETED |
						NOTIFICATION_FLAG_MOST_SEARCH |
						NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	pnotify->notification_data.pparent_id = &pmemory->parent_id;
	pmemory->parent_id = rop_util_make_eid_ex(1, parent_id);
	return TRUE;
}

static BOOL notify_response_specify_folder_modified(NOTIFY_RESPONSE *pnotify,
    uint64_t folder_id, uint32_t *ptotal, uint32_t *punread,
    const PROPTAG_ARRAY *pproptags)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_OBJECTMODIFIED;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_nfid_to_eid(folder_id);
	if (NULL != ptotal) {
		pnotify->notification_data.notification_flags |=
								NOTIFICATION_FLAG_MOST_TOTAL;
		pnotify->notification_data.ptotal_count = &pmemory->total_count;
		pmemory->total_count = *ptotal;
	}
	if (NULL != punread) {
		pnotify->notification_data.notification_flags |=
								NOTIFICATION_FLAG_MOST_UNREAD;
		pnotify->notification_data.punread_count = &pmemory->unread_count;
		pmemory->unread_count = *punread;
	}
	pnotify->notification_data.pproptags = &pmemory->proptags;
	pmemory->proptags.count = pproptags->count;
	if (0 == pmemory->proptags.count) {
		pmemory->proptags.pproptag = NULL;
		return TRUE;
	}
	pmemory->proptags.pproptag = me_alloc<uint32_t>(pproptags->count);
	if (NULL == pmemory->proptags.pproptag) {
		return FALSE;
	}
	memcpy(pmemory->proptags.pproptag, pproptags->pproptag,
		sizeof(uint32_t)*pproptags->count);
	return TRUE;
}
	
static BOOL notify_response_specify_message_modified(NOTIFY_RESPONSE *pnotify,
     uint64_t folder_id, uint64_t message_id, const PROPTAG_ARRAY *pproptags)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_OBJECTMODIFIED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	pnotify->notification_data.pproptags = &pmemory->proptags;
	pmemory->proptags.count = pproptags->count;
	if (0 == pmemory->proptags.count) {
		pmemory->proptags.pproptag = NULL;
		return TRUE;
	}
	pmemory->proptags.pproptag = me_alloc<uint32_t>(pproptags->count);
	if (NULL == pmemory->proptags.pproptag) {
		return FALSE;
	}
	memcpy(pmemory->proptags.pproptag, pproptags->pproptag,
		sizeof(uint32_t)*pproptags->count);
	return TRUE;
}

static BOOL notify_response_specify_folder_mvcp(
	NOTIFY_RESPONSE *pnotify, uint8_t notification_flags,
	uint64_t folder_id, uint64_t parent_id,
	uint64_t old_folder_id, uint64_t old_parent_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
								notification_flags;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_nfid_to_eid(folder_id);
	pnotify->notification_data.pparent_id = &pmemory->parent_id;
	pmemory->parent_id = rop_util_make_eid_ex(1, parent_id);
	pnotify->notification_data.pold_folder_id = &pmemory->old_folder_id;
	pmemory->old_folder_id = rop_util_nfid_to_eid(old_folder_id);
	pnotify->notification_data.pold_parent_id = &pmemory->old_parent_id;
	pmemory->old_parent_id = rop_util_make_eid_ex(1, old_parent_id);
	return TRUE;
}

static BOOL notify_response_specify_message_mvcp(
	NOTIFY_RESPONSE *pnotify, uint8_t notification_flags,
	uint64_t folder_id, uint64_t message_id,
	uint64_t old_folder_id, uint64_t old_message_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		notification_flags | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	pnotify->notification_data.pmessage_id = &pmemory->message_id;
	pmemory->message_id = rop_util_make_eid_ex(1, message_id);
	pnotify->notification_data.pold_folder_id = &pmemory->old_folder_id;
	pmemory->old_folder_id = rop_util_make_eid_ex(1, old_folder_id);
	pnotify->notification_data.pold_message_id = &pmemory->old_message_id;
	pmemory->old_message_id = rop_util_make_eid_ex(1, old_message_id);
	return TRUE;
}

static BOOL notify_response_specify_folder_search_completed(
	NOTIFY_RESPONSE *pnotify, uint64_t folder_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_SEARCHCOMPLETE;
	pnotify->notification_data.pfolder_id = &pmemory->folder_id;
	pmemory->folder_id = rop_util_make_eid_ex(1, folder_id);
	return TRUE;
}

static BOOL notify_response_specify_hierarchy_table_changed(
	NOTIFY_RESPONSE *pnotify)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_TABLE_MODIFIED;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_TABLE_CHANGED;
	return TRUE;
}

static BOOL notify_response_specify_content_table_changed(
	NOTIFY_RESPONSE *pnotify)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_TABLE_MODIFIED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_TABLE_CHANGED;
	return TRUE;
}

static BOOL notify_response_specify_search_table_changed(
	NOTIFY_RESPONSE *pnotify)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
					NOTIFICATION_FLAG_TABLE_MODIFIED |
					NOTIFICATION_FLAG_MOST_SEARCH |
					NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_TABLE_CHANGED;
	return TRUE;
}

static BOOL notify_response_specify_hierarchy_table_row_added(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t after_folder_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_TABLE_MODIFIED;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_ADDED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_nfid_to_eid(row_folder_id);
	pnotify->notification_data.pafter_folder_id = &pmemory->after_folder_id;
	pmemory->after_folder_id = after_folder_id == 0 ? eid_t(0) :
	                           rop_util_nfid_to_eid(after_folder_id);
	return TRUE;
}

static BOOL notify_response_specify_content_table_row_added(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t row_message_id, uint64_t row_instance,
	uint64_t after_folder_id, uint64_t after_row_id,
	uint64_t after_instance)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_TABLE_MODIFIED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_ADDED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_make_eid_ex(1, row_folder_id);
	pnotify->notification_data.prow_message_id = &pmemory->row_message_id;
	pmemory->row_message_id = rop_util_nfid_to_eid2(row_message_id);
	pnotify->notification_data.prow_instance = &pmemory->row_instance;
	pmemory->row_instance = row_instance;
	pnotify->notification_data.pafter_folder_id = &pmemory->after_folder_id;
	pmemory->after_folder_id = after_folder_id == 0 ? eid_t(0) :
	                           rop_util_make_eid_ex(1, after_folder_id);
	pnotify->notification_data.pafter_row_id = &pmemory->after_row_id;
	pmemory->after_row_id = after_row_id == 0 ? eid_t(0) :
	                        rop_util_nfid_to_eid2(after_row_id);
	pnotify->notification_data.pafter_instance = &pmemory->after_instance;
	pmemory->after_instance = after_instance;
	return TRUE;
}

static BOOL notify_response_specify_search_table_row_added(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t row_message_id, uint64_t row_instance,
	uint64_t after_folder_id, uint64_t after_row_id,
	uint64_t after_instance)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
					NOTIFICATION_FLAG_TABLE_MODIFIED |
					NOTIFICATION_FLAG_MOST_SEARCH |
					NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_ADDED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_make_eid_ex(1, row_folder_id);
	pnotify->notification_data.prow_message_id = &pmemory->row_message_id;
	pmemory->row_message_id = rop_util_nfid_to_eid2(row_message_id);
	pnotify->notification_data.prow_instance = &pmemory->row_instance;
	pmemory->row_instance = row_instance;
	pnotify->notification_data.pafter_folder_id = &pmemory->after_folder_id;
	pmemory->after_folder_id = after_folder_id == 0 ? eid_t(0) :
	                           rop_util_make_eid_ex(1, after_folder_id);
	pnotify->notification_data.pafter_row_id = &pmemory->after_row_id;
	pmemory->after_row_id = after_row_id == 0 ? eid_t(0) :
	                        rop_util_nfid_to_eid2(after_row_id);
	pnotify->notification_data.pafter_instance = &pmemory->after_instance;
	pmemory->after_instance = after_instance;
	return TRUE;
}

static BOOL notify_response_specify_hierarchy_table_row_deleted(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_TABLE_MODIFIED;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_DELETED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_nfid_to_eid(row_folder_id);
	return TRUE;
}

static BOOL notify_response_specify_content_table_row_deleted(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t row_message_id, uint64_t row_instance)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_TABLE_MODIFIED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_DELETED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_make_eid_ex(1, row_folder_id);
	pnotify->notification_data.prow_message_id = &pmemory->row_message_id;
	pmemory->row_message_id = rop_util_nfid_to_eid2(row_message_id);
	pnotify->notification_data.prow_instance = &pmemory->row_instance;
	pmemory->row_instance = row_instance;
	return TRUE;
}

static BOOL notify_response_specify_search_table_row_deleted(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t row_message_id, uint64_t row_instance)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
					NOTIFICATION_FLAG_TABLE_MODIFIED |
					NOTIFICATION_FLAG_MOST_SEARCH |
					NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_DELETED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_make_eid_ex(1, row_folder_id);
	pnotify->notification_data.prow_message_id = &pmemory->row_message_id;
	pmemory->row_message_id = rop_util_nfid_to_eid2(row_message_id);
	pnotify->notification_data.prow_instance = &pmemory->row_instance;
	pmemory->row_instance = row_instance;
	return TRUE;
}

static BOOL notify_response_specify_hierarchy_table_row_modified(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t after_folder_id)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
							NOTIFICATION_FLAG_TABLE_MODIFIED;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_MODIFIED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_nfid_to_eid(row_folder_id);
	pnotify->notification_data.pafter_folder_id = &pmemory->after_folder_id;
	pmemory->after_folder_id = after_folder_id == 0 ? eid_t(0) :
	                           rop_util_nfid_to_eid(after_folder_id);
	return TRUE;
}
	
static BOOL notify_response_specify_content_table_row_modified(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t row_message_id, uint64_t row_instance,
	uint64_t after_folder_id, uint64_t after_row_id,
	uint64_t after_instance)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
		NOTIFICATION_FLAG_TABLE_MODIFIED | NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_MODIFIED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_make_eid_ex(1, row_folder_id);
	pnotify->notification_data.prow_message_id = &pmemory->row_message_id;
	pmemory->row_message_id = rop_util_nfid_to_eid2(row_message_id);
	pnotify->notification_data.prow_instance = &pmemory->row_instance;
	pmemory->row_instance = row_instance;
	pnotify->notification_data.pafter_folder_id = &pmemory->after_folder_id;
	pmemory->after_folder_id = after_folder_id == 0 ? eid_t(0) :
	                           rop_util_make_eid_ex(1, after_folder_id);
	pnotify->notification_data.pafter_row_id = &pmemory->after_row_id;
	pmemory->after_row_id = after_row_id == 0 ? eid_t(0) :
	                        rop_util_nfid_to_eid2(after_row_id);
	pnotify->notification_data.pafter_instance = &pmemory->after_instance;
	pmemory->after_instance = after_instance;
	return TRUE;
}

static BOOL notify_response_specify_search_table_row_modified(
	NOTIFY_RESPONSE *pnotify, uint64_t row_folder_id,
	uint64_t row_message_id, uint64_t row_instance,
	uint64_t after_folder_id, uint64_t after_row_id,
	uint64_t after_instance)
{
	auto pmemory = notify_to_ndm(pnotify);
	pnotify->notification_data.notification_flags =
					NOTIFICATION_FLAG_TABLE_MODIFIED |
					NOTIFICATION_FLAG_MOST_SEARCH |
					NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = &pmemory->table_event;
	pmemory->table_event = TABLE_EVENT_ROW_MODIFIED;
	pnotify->notification_data.prow_folder_id = &pmemory->row_folder_id;
	pmemory->row_folder_id = rop_util_make_eid_ex(1, row_folder_id);
	pnotify->notification_data.prow_message_id = &pmemory->row_message_id;
	pmemory->row_message_id = rop_util_nfid_to_eid2(row_message_id);
	pnotify->notification_data.prow_instance = &pmemory->row_instance;
	pmemory->row_instance = row_instance;
	pnotify->notification_data.pafter_folder_id = &pmemory->after_folder_id;
	pmemory->after_folder_id = after_folder_id == 0 ? eid_t(0) :
	                           rop_util_make_eid_ex(1, after_folder_id);
	pnotify->notification_data.pafter_row_id = &pmemory->after_row_id;
	pmemory->after_row_id = after_row_id == 0 ? eid_t(0) :
	                        rop_util_nfid_to_eid2(after_row_id);
	pnotify->notification_data.pafter_instance = &pmemory->after_instance;
	pmemory->after_instance = after_instance;
	return TRUE;
}


BOOL notify_response_retrieve(NOTIFY_RESPONSE *pnotify,
	BOOL b_cache, const DB_NOTIFY *pdb_notify)
{
	uint8_t notification_flags;
	
	switch (pdb_notify->type) {
	case db_notify_type::new_mail: {
		auto x = static_cast<const DB_NOTIFY_NEW_MAIL *>(pdb_notify->pdata);
		return notify_response_specify_new_mail(pnotify, x->folder_id,
		       x->message_id, x->message_flags, b_cache,
		       x->pmessage_class);
	}
	case db_notify_type::folder_created: {
		auto x = static_cast<const DB_NOTIFY_FOLDER_CREATED *>(pdb_notify->pdata);
		return notify_response_specify_folder_created(pnotify,
		       x->folder_id, x->parent_id, &x->proptags);
	}
	case db_notify_type::message_created: {
		auto x = static_cast<const DB_NOTIFY_MESSAGE_CREATED *>(pdb_notify->pdata);
		return notify_response_specify_message_created(pnotify,
		       x->folder_id, x->message_id, &x->proptags);
	}
	case db_notify_type::link_created: {
		auto x = static_cast<const DB_NOTIFY_LINK_CREATED *>(pdb_notify->pdata);
		return notify_response_specify_link_created(pnotify,
		       x->folder_id, x->message_id, x->parent_id, &x->proptags);
	}
	case db_notify_type::folder_deleted: {
		auto x = static_cast<const DB_NOTIFY_FOLDER_DELETED *>(pdb_notify->pdata);
		return notify_response_specify_folder_deleted(pnotify,
		       x->folder_id, x->parent_id);
	}
	case db_notify_type::message_deleted: {
		auto x = static_cast<const DB_NOTIFY_MESSAGE_DELETED *>(pdb_notify->pdata);
		return notify_response_specify_message_deleted(pnotify,
		       x->folder_id, x->message_id);
	}
	case db_notify_type::link_deleted: {
		auto x = static_cast<const DB_NOTIFY_LINK_DELETED *>(pdb_notify->pdata);
		return notify_response_specify_link_deleted(pnotify,
		       x->folder_id, x->message_id, x->parent_id);
	}
	case db_notify_type::folder_modified: {
		auto x = static_cast<const DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata);
		return notify_response_specify_folder_modified(pnotify,
		       x->folder_id, x->ptotal, x->punread, &x->proptags);
	}
	case db_notify_type::message_modified: {
		auto x = static_cast<const DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata);
		return notify_response_specify_message_modified(pnotify,
		       x->folder_id, x->message_id, &x->proptags);
	}
	case db_notify_type::folder_moved:
	case db_notify_type::folder_copied: {
		auto x = static_cast<const DB_NOTIFY_FOLDER_MVCP *>(pdb_notify->pdata);
		notification_flags = pdb_notify->type == db_notify_type::folder_moved ?
		                     NOTIFICATION_FLAG_OBJECTMOVED : NOTIFICATION_FLAG_OBJECTCOPIED;
		return notify_response_specify_folder_mvcp(pnotify,
		       notification_flags, x->folder_id, x->parent_id,
		       x->old_folder_id, x->old_parent_id);
	}
	case db_notify_type::message_moved:
	case db_notify_type::message_copied: {
		auto x = static_cast<const DB_NOTIFY_MESSAGE_MVCP *>(pdb_notify->pdata);
		notification_flags = pdb_notify->type == db_notify_type::message_moved ?
		                     NOTIFICATION_FLAG_OBJECTMOVED : NOTIFICATION_FLAG_OBJECTCOPIED;
		return notify_response_specify_message_mvcp(pnotify,
		       notification_flags, x->folder_id, x->message_id,
		       x->old_folder_id, x->old_message_id);
	}
	case db_notify_type::search_completed: {
		auto x = static_cast<const DB_NOTIFY_SEARCH_COMPLETED *>(pdb_notify->pdata);
		return notify_response_specify_folder_search_completed(pnotify,
		       x->folder_id);
	}
	case db_notify_type::hierarchy_table_changed:
		return notify_response_specify_hierarchy_table_changed(pnotify);
	case db_notify_type::content_table_changed:
		return notify_response_specify_content_table_changed(pnotify);
	case db_notify_type::search_table_changed:
		return notify_response_specify_search_table_changed(pnotify);
	case db_notify_type::hierarchy_table_row_added: {
		auto x = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *>(pdb_notify->pdata);
		return notify_response_specify_hierarchy_table_row_added(pnotify,
		       x->row_folder_id, x->after_folder_id);
	}
	case db_notify_type::content_table_row_added: {
		auto x = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *>(pdb_notify->pdata);
		return notify_response_specify_content_table_row_added(pnotify,
		       x->row_folder_id, x->row_message_id, x->row_instance,
		       x->after_folder_id, x->after_row_id, x->after_instance);
	}
	case db_notify_type::search_table_row_added: {
		auto x = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *>(pdb_notify->pdata);
		return notify_response_specify_search_table_row_added(pnotify,
		       x->row_folder_id, x->row_message_id, x->row_instance,
		       x->after_folder_id, x->after_row_id, x->after_instance);
	}
	case db_notify_type::hierarchy_table_row_deleted: {
		auto x = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *>(pdb_notify->pdata);
		return notify_response_specify_hierarchy_table_row_deleted(pnotify,
		       x->row_folder_id);
	}
	case db_notify_type::content_table_row_deleted: {
		auto x = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *>(pdb_notify->pdata);
		return notify_response_specify_content_table_row_deleted(pnotify,
		       x->row_folder_id, x->row_message_id, x->row_instance);
	}
	case db_notify_type::search_table_row_deleted: {
		auto x = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *>(pdb_notify->pdata);
		return notify_response_specify_search_table_row_deleted(pnotify,
		       x->row_folder_id, x->row_message_id, x->row_instance);
	}
	case db_notify_type::hierarchy_table_row_modified: {
		auto x = static_cast<const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *>(pdb_notify->pdata);
		return notify_response_specify_hierarchy_table_row_modified(pnotify,
		       x->row_folder_id, x->after_folder_id);
	}
	case db_notify_type::content_table_row_modified: {
		auto x = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *>(pdb_notify->pdata);
		return notify_response_specify_content_table_row_modified(pnotify,
		       x->row_folder_id, x->row_message_id, x->row_instance,
		       x->after_folder_id, x->after_row_id, x->after_instance);
	}
	case db_notify_type::search_table_row_modified: {
		auto x = static_cast<const DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *>(pdb_notify->pdata);
		return notify_response_specify_search_table_row_modified(pnotify,
		       x->row_folder_id, x->row_message_id, x->row_instance,
		       x->after_folder_id, x->after_row_id, x->after_instance);
	}
	}
	return FALSE;
}

void notify_response_content_table_row_event_to_change(
	NOTIFY_RESPONSE *pnotify)
{
	uint16_t *ptable_event;
	
	ptable_event = pnotify->notification_data.ptable_event;
	memset(&pnotify->notification_data, 0, sizeof(NOTIFICATION_DATA));
	pnotify->notification_data.notification_flags =
					NOTIFICATION_FLAG_TABLE_MODIFIED |
					NOTIFICATION_FLAG_MOST_MESSAGE;
	pnotify->notification_data.ptable_event = ptable_event;
	*ptable_event = TABLE_EVENT_TABLE_CHANGED;
}
