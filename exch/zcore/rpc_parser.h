#pragma once
#include <gromox/common_types.hpp>

void rpc_parser_init(int thread_num);
extern int rpc_parser_run();
extern int rpc_parser_stop();
extern void rpc_parser_free();
BOOL rpc_parser_activate_connection(int clifd);
