#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

struct DB_NOTIFY;
struct notify_response;
using NOTIFY_RESPONSE = notify_response;

NOTIFY_RESPONSE* notify_response_init(uint32_t handle, uint8_t logon_id);
void notify_response_free(NOTIFY_RESPONSE *pnotify);
BOOL notify_response_retrieve(NOTIFY_RESPONSE *pnotify,
	BOOL b_cache, const DB_NOTIFY *pdb_notify);
void notify_response_content_table_row_event_to_change(
	NOTIFY_RESPONSE *pnotify);
