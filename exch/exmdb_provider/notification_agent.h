#pragma once
#include "exmdb_parser.h"
#include "common_util.h"

#ifdef __cplusplus
extern "C" {
#endif

void notification_agent_backward_notify(
	const char *remote_id, DB_NOTIFY_DATAGRAM *pnotify);

void notification_agent_thread_work(ROUTER_CONNECTION *prouter);

#ifdef __cplusplus
} /* extern "C" */
#endif
