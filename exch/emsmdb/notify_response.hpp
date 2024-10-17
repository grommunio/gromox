#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include <gromox/rpc_types.hpp>
#include "processor_types.hpp"

struct DB_NOTIFY;
struct logon_object;

struct notify_response : public rop_response {
	static notify_response *create(uint32_t, uint8_t);
	notify_response() = default;
	NOMOVE(notify_response);
	~notify_response();
	void clear();
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

struct subscription_object {
	protected:
	subscription_object() = default;
	NOMOVE(subscription_object)

	public:
	~subscription_object();
	static std::unique_ptr<subscription_object> create(logon_object *, uint8_t logon_id, uint16_t notification_types, BOOL whole, uint64_t folder_id, uint64_t message_id);
	void set_handle(uint32_t handle);

	logon_object *plogon = nullptr;
	CXH cxh{};
	uint16_t client_mode = 0;
	uint8_t logon_id = 0;
	uint32_t handle = 0, sub_id = 0;
};
