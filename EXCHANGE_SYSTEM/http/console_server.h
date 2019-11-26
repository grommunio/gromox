#ifndef _H_CONSOLE_SERVER_
#define _H_CONSOLE_SERVER_
#include "common_types.h"

void console_server_init(const char* bind_ip, int port);
extern void console_server_free(void);
extern int console_server_run(void);
extern int console_server_stop(void);
int  console_server_reply_to_client(const char* format, ...);
extern void console_server_notify_main_stop(void);

#endif /* _H_CONSOLE_SERVER_ */

