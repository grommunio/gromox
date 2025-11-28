#pragma once
#include <any>
#include <cstdint>
#include <gromox/mapidefs.h>

enum class db_notify_type : uint8_t {
	new_mail = 1, folder_created, message_created, link_created,
	folder_deleted, message_deleted, link_deleted, folder_modified,
	message_modified, folder_moved, message_moved, folder_copied,
	message_copied, search_completed, hiertbl_changed, cttbl_changed,
	srchtbl_changed, hiertbl_row_added, cttbl_row_added, srchtbl_row_added,
	hiertbl_row_deleted, cttbl_row_deleted, srchtbl_row_deleted,
	hiertbl_row_modified, cttbl_row_modified, srchtbl_row_modified,
};

using db_notify_base = gromox::universal_base;

struct GX_EXPORT DB_NOTIFY {
	enum db_notify_type type{};
	std::any pdata;
};

struct GX_EXPORT DB_NOTIFY_NEW_MAIL {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	const char *pmessage_class;
};

struct GX_EXPORT DB_NOTIFY_FOLDER_CREATED {
	uint64_t folder_id;
	uint64_t parent_id;
	PROPTAG_ARRAY proptags;
};

struct GX_EXPORT DB_NOTIFY_MESSAGE_CREATED {
	uint64_t folder_id;
	uint64_t message_id;
	PROPTAG_ARRAY proptags;
};

struct GX_EXPORT DB_NOTIFY_LINK_CREATED {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
	PROPTAG_ARRAY proptags;
};

struct GX_EXPORT DB_NOTIFY_FOLDER_DELETED {
	uint64_t folder_id;
	uint64_t parent_id;
};

struct GX_EXPORT DB_NOTIFY_MESSAGE_DELETED {
	uint64_t folder_id;
	uint64_t message_id;
};

struct GX_EXPORT DB_NOTIFY_LINK_DELETED {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
};

struct GX_EXPORT DB_NOTIFY_FOLDER_MODIFIED {
	uint64_t folder_id;
	uint64_t parent_id;
	uint32_t *ptotal;
	uint32_t *punread;
	PROPTAG_ARRAY proptags;
};

struct GX_EXPORT DB_NOTIFY_MESSAGE_MODIFIED {
	uint64_t folder_id;
	uint64_t message_id;
	PROPTAG_ARRAY proptags;
};

struct GX_EXPORT DB_NOTIFY_FOLDER_MVCP {
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t old_folder_id;
	uint64_t old_parent_id;
};

struct GX_EXPORT DB_NOTIFY_MESSAGE_MVCP {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t old_folder_id;
	uint64_t old_message_id;
};

struct GX_EXPORT DB_NOTIFY_SEARCH_COMPLETED {
	uint64_t folder_id;
};

struct GX_EXPORT DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED {
	uint64_t row_folder_id;
	uint64_t after_folder_id;
};
using DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED = DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED;

struct GX_EXPORT DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED {
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint64_t row_instance;
	uint64_t after_folder_id;
	uint64_t after_row_id;
	uint64_t after_instance;
};
using DB_NOTIFY_CONTENT_TABLE_ROW_ADDED = DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED;

struct GX_EXPORT DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED {
	uint64_t row_folder_id;
};

struct GX_EXPORT DB_NOTIFY_CONTENT_TABLE_ROW_DELETED {
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint64_t row_instance;
};
