#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

struct DB_NOTIFY;

struct notify_response {
	static notify_response *create(uint32_t, uint8_t);
	~notify_response();
	ec_error_t cvt_from_dbnotify(BOOL b_cache, const DB_NOTIFY &);
	void ctrow_event_to_change();

	uint32_t handle = 0;
	uint8_t logon_id = 0, unicode_flag = 0;

	uint32_t msg_flags = 0;
	uint16_t nflags = 0;
	uint16_t table_event = 0;
	uint64_t row_folder_id = 0, row_message_id = 0;
	uint64_t after_folder_id = 0, after_row_id = 0;
	uint32_t row_instance = 0, after_instance = 0;
	uint64_t folder_id = 0, old_folder_id = 0;
	uint64_t message_id = 0, old_message_id = 0;
	uint64_t parent_id = 0, old_parent_id = 0;
	PROPTAG_ARRAY proptags{};
	uint32_t total_count = 0, unread_count = 0;
	char *msg_class = nullptr;
	BINARY *row_data = nullptr;
};
