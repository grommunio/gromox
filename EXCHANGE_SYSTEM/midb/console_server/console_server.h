#ifndef _H_CONSOLE_SERVER_
#define _H_CONSOLE_SERVER_
#include "common_types.h"

void console_server_init(const char* bind_ip, int port);

void console_server_free();

int console_server_run();

int console_server_stop();

int  console_server_reply_to_client(const char* format, ...);

void console_server_notify_main_stop();

#endif /* _H_CONSOLE_SERVER_ */
