#pragma once
#include <memory>
#include <gromox/exmdb_common_util.hpp>
#include "exmdb_parser.h"
extern void notification_agent_backward_notify(const char *remote_id, const DB_NOTIFY_DATAGRAM *);
extern void notification_agent_thread_work(std::shared_ptr<ROUTER_CONNECTION> &&);
