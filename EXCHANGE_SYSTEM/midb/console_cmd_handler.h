#ifndef _H_CONSOLE_CMD_HANDLER_
#define _H_CONSOLE_CMD_HANDLER_
#include "common_types.h"

BOOL cmd_handler_midb_control(int argc, char** argv);

BOOL cmd_handler_service_control(int argc, char** argv);

BOOL cmd_handler_help(int argc, char** argv);

BOOL cmd_handler_server_control(int argc, char** argv);

BOOL cmd_handler_system_control(int argc, char** argv);

BOOL cmd_handler_service_plugins(int argc, char** argv);

#endif /* _H_CONSOLE_CMD_HANDLER_ */
