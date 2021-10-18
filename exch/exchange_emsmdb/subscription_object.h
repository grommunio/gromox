#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include <gromox/rpc_types.hpp>

struct LOGON_OBJECT;

struct SUBSCRIPTION_OBJECT {
	~SUBSCRIPTION_OBJECT();
	void set_handle(uint32_t handle);

	LOGON_OBJECT *plogon = nullptr;
	CXH cxh{};
	uint16_t client_mode = 0;
	uint8_t logon_id = 0;
	uint32_t handle = 0, sub_id = 0;
};

extern std::unique_ptr<SUBSCRIPTION_OBJECT> subscription_object_create(LOGON_OBJECT *, uint8_t logon_id, uint16_t notification_types, BOOL whole, uint64_t folder_id, uint64_t message_id);
