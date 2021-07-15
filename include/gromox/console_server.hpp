#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>

using COMMAND_HANDLER = BOOL (*)(int argc, char **argv);

extern void console_server_init(const char *host, uint16_t port);
extern void console_server_free();
extern int console_server_run();
extern int console_server_stop();
int  console_server_reply_to_client(const char* format, ...);
extern void console_server_notify_main_stop();
extern BOOL console_server_register_command(const char *cmd, COMMAND_HANDLER);
