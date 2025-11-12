#pragma once
#include <cstdint>
#include <memory>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#define DCERPC_CALL_STAT_FLAG_HEADER_SIGNING 0x04
#define DCERPC_CALL_STAT_FLAG_MULTIPLEXED 0x10

struct NDR_PULL;
struct NDR_PUSH;

/**
 * Used for proc plugins to det DCERPC information.
 * Pointee lifetime is bound by the PDU processor object.
 */
struct GX_EXPORT DCERPC_INFO {
	const char *client_addr = nullptr;
	const char *server_addr = nullptr; /* HTTP server address */
	const char *ep_host = nullptr; /* endpoint host name */
	uint16_t client_port = 0;
	uint16_t server_port = 0; /* HTTP server port */
	uint16_t ep_port = 0; /* endpoint port */
	BOOL is_login = false; /* if client login */
	const char *username = nullptr; /* username of client by http auth */
	const char *maildir = nullptr, *lang = nullptr;
	uint32_t stat_flags = 0; /* state flags of rpc context */
};

using rpc_request = gromox::universal_base;
using rpc_response = gromox::universal_base;

struct DCERPC_INTERFACE {
	char name[128]{};
	GUID uuid{};
	uint32_t version = 0;
	/* the ndr_pull function for the chosen interface. */
	pack_result (*ndr_pull)(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &) = nullptr;
	/* the dispatch function for the chosen interface. */
	int (*dispatch)(unsigned int op, const GUID *, uint64_t handle, const rpc_request *in, std::unique_ptr<rpc_response> &out, ec_error_t *) = nullptr;
	/* the ndr_push function for the chosen interface. */
	pack_result (*ndr_push)(unsigned int op, NDR_PUSH &, const rpc_response *pout) = nullptr;
	/* the unbind function for the chosen interface */
	void (*unbind)(uint64_t handle) = nullptr;
	/* the reclaim function for the chosen interface */
	void (*reclaim)(uint32_t async_id) = nullptr;
};
