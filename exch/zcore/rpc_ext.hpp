#pragma once
#include <memory>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/zcore_rpc.hpp>
extern pack_result rpc_ext_pull_request(const BINARY *, std::unique_ptr<zcreq> &);
extern pack_result rpc_ext_push_response(const zcresp *, BINARY *);
