#ifndef _H_NOTIFICATION_AGENT_
#define _H_NOTIFICATION_AGENT_
#include "exmdb_parser.h"
#include "common_util.h"

void notification_agent_backward_notify(
	const char *remote_id, DB_NOTIFY_DATAGRAM *pnotify);

void notification_agent_thread_work(ROUTER_CONNECTION *prouter);

#endif /* _H_NOTIFICATION_AGENT_ */
