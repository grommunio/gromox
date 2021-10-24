#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include <gromox/rpc_types.hpp>

struct logon_object;

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
