#pragma once
#include <cstdint>
#include "emsmdb_interface.h"
#include "logon_object.h"

struct SUBSCRIPTION_OBJECT {
	LOGON_OBJECT *plogon;
	CXH cxh;
	uint16_t client_mode;
	uint8_t logon_id;
	uint32_t handle;
	uint32_t sub_id;
};

SUBSCRIPTION_OBJECT* subscription_object_create(
	LOGON_OBJECT *plogon, uint8_t logon_id,
	uint16_t notification_types, BOOL b_whole,
	uint64_t folder_id, uint64_t message_id);
void subscription_object_set_handle(
	SUBSCRIPTION_OBJECT *psub, uint32_t handle);
void subscription_object_free(SUBSCRIPTION_OBJECT *psub);
