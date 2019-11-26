#ifndef _H_NOTIFY_RESPONSE_
#define _H_NOTIFY_RESPONSE_
#include "mapi_types.h"
#include "processor_types.h"


NOTIFY_RESPONSE* notify_response_init(uint32_t handle, uint8_t logon_id);

void notify_response_free(NOTIFY_RESPONSE *pnotify);

BOOL notify_response_retrieve(NOTIFY_RESPONSE *pnotify,
	BOOL b_cache, const DB_NOTIFY *pdb_notify);

void notify_response_content_table_row_event_to_change(
	NOTIFY_RESPONSE *pnotify);

#endif /* _H_NOTIFY_RESPONSE_ */
