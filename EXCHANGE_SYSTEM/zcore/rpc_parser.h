#ifndef _H_RPC_PARSER_
#define _H_RPC_PARSER_
#include "common_types.h"

void rpc_parser_init(int thread_num);

int rpc_parser_run();

int rpc_parser_stop();

void rpc_parser_free();

BOOL rpc_parser_activate_connection(int clifd);

#endif	/* _H_RPC_PARSER_ */
