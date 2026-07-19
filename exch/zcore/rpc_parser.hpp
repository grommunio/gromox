#pragma once
#include <gromox/common_types.hpp>
#include <gromox/fileio.h>

extern void rpc_parser_init(unsigned int thread_num);
extern int rpc_parser_run();
extern void rpc_parser_stop();
extern void rpc_parser_activate_connection(gromox::wrapfd &&);

extern unsigned int g_zrpc_debug;
