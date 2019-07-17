#ifndef _H_RELAY_BRIDGE_
#define _H_RELAY_BRIDGE_
#include "common_types.h"

void relay_bridge_init(int port, const char *list_path, const char *mess_path,
	const char *save_path, const char *token_path);

int relay_bridge_run();

int relay_bridge_stop();

void relay_bridge_free();

BOOL relay_bridge_refresh_table();

#endif
