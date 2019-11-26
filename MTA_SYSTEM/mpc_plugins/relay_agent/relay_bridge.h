#ifndef _H_RELAY_BRIDGE_
#define _H_RELAY_BRIDGE_
#include "common_types.h"

void relay_bridge_init(int port, const char *list_path, const char *mess_path,
	const char *save_path, const char *token_path);
extern int relay_bridge_run(void);
extern int relay_bridge_stop(void);
extern void relay_bridge_free(void);
extern BOOL relay_bridge_refresh_table(void);

#endif
