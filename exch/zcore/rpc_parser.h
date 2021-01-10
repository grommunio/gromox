#pragma once
#include <gromox/common_types.hpp>

void rpc_parser_init(int thread_num);
extern int rpc_parser_run(void);
extern int rpc_parser_stop(void);
extern void rpc_parser_free(void);
BOOL rpc_parser_activate_connection(int clifd);
