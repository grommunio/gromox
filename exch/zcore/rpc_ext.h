#pragma once
#include <gromox/mapi_types.hpp>
#include <gromox/zcore_rpc.hpp>
extern BOOL rpc_ext_pull_request(const BINARY *, ZCORE_RPC_REQUEST *);
extern BOOL rpc_ext_push_response(const ZCORE_RPC_RESPONSE *, BINARY *);
