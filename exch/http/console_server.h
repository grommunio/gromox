#pragma once
#include <gromox/common_types.hpp>

#ifdef __cplusplus
extern "C" {
#endif

void console_server_init(const char* bind_ip, int port);
extern void console_server_free(void);
extern int console_server_run(void);
extern int console_server_stop(void);
int  console_server_reply_to_client(const char* format, ...);
extern void console_server_notify_main_stop(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
