#pragma once
#include <cstdint>
#include <string>
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

/*
 * new_mail:         folder_id, message_id, message_flags, message_class;
 * folder_created:   parent_id, folder_id, proptags;
 * message_created:  folder_id, message_id, proptags;
 * link_created:     folder_id(anchor), message_id, parent_id(srchfld);
 * folder_deleted:   parent_id, folder_id;
 * message_deleted:  folder_id, message_id;
 * link_deleted:     folder_id(anchor), message_id, parent_id(srchfld);
 * folder_modified:  parent_id, folder_id, fld_total, fld_unread, proptags;
 * message_modified: folder_id, message_id, proptags;
 * folder_mvcp:      parent_id, folder_id, old_parent_id, old_folder_id;
 * message_mvcp:     folder_id, message_id, old_folder_id, old_message_id;
 * search_completed: folder_id;
 *
 * hiertblrow_added:    row_folder_id, after_folder_id;
 * hiertblrow_modified: row_folder_id, after_folder_id;
 * hiertblrow_deleted:  row_folder_id;
 * cttblrow_added:      row_folder_id, row_message_id, row_instance,
 *                      after_folder_id, after_row_id, after_instance;
 * cttblrow_modified:   <like cttblrow_added>
 * cttblrow_deleted:    row_folder_id, row_message_id, row_instance;
 */
struct GX_EXPORT DB_NOTIFY {
	enum db_notify_type type{};
	uint64_t parent_id = 0, folder_id = 0, message_id = 0;
	uint64_t old_parent_id = 0, old_folder_id = 0, old_message_id = 0;
	uint64_t row_folder_id = 0, row_message_id = 0, row_instance = 0;
	uint64_t after_folder_id = 0, after_row_id = 0, after_instance = 0;
	uint32_t message_flags = 0;
	std::string pmessage_class;
	PROPTAG_ARRAY proptags{};

	const char *type_repr() const;
	std::string repr() const;
};
