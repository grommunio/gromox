#pragma once
#include <gromox/common_types.hpp>

BOOL cmd_handler_smtp_error_code_control(int argc, char** argv);
BOOL cmd_handler_smtp_control(int argc, char** argv);
BOOL cmd_handler_help(int argc, char** argv);

BOOL cmd_handler_server_control(int argc, char** argv);

BOOL cmd_handler_system_control(int argc, char** argv);

BOOL cmd_handler_flusher_control(int argc, char** argv);
BOOL cmd_handler_service_plugins(int argc, char** argv);
