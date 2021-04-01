#pragma once
#include <memory>
#include "exmdb_parser.h"
#include "common_util.h"

void notification_agent_backward_notify(
	const char *remote_id, DB_NOTIFY_DATAGRAM *pnotify);
extern void notification_agent_thread_work(std::shared_ptr<ROUTER_CONNECTION> &&);
