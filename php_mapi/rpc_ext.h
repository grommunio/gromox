#pragma once
#include <gromox/zcore_rpc.hpp>
#include "ext_pack.h"
extern zend_bool rpc_ext_push_request(const ZCORE_RPC_REQUEST *, BINARY *);
extern zend_bool rpc_ext_pull_response(const BINARY *, ZCORE_RPC_RESPONSE *);
