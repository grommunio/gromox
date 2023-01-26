#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#define DCERPC_CALL_STAT_FLAG_HEADER_SIGNING 0x04
#define DCERPC_CALL_STAT_FLAG_MULTIPLEXED 0x10

struct NDR_PULL;
struct NDR_PUSH;

struct DCERPC_INFO {
	const char *client_ip;
	const char *server_ip; /* http server ip */
	const char *ep_host;   /* endpoint host name */
	uint16_t client_port;
	uint16_t server_port; /* HTTP server port */
	uint16_t ep_port; /* endpoint port */
	BOOL is_login;         /* if client login */
	const char *username;  /* username of client by http auth */
	const char *maildir;
	const char *lang;
	uint32_t stat_flags;   /* state flags of rpc context */
}; /* used for proc plugin to get dcerpc information */

struct DCERPC_INTERFACE {
	char name[128]{};
	GUID uuid{};
	uint32_t version = 0;
	/* the ndr_pull function for the chosen interface. */
	pack_result (*ndr_pull)(int opnum, NDR_PULL* pndr, void **ppin) = nullptr;
	/* the dispatch function for the chosen interface. */
	int (*dispatch)(unsigned int op, const GUID *, uint64_t handle, void *in, void **out, uint32_t *ecode) = nullptr;
	/* the ndr_push function for the chosen interface. */
	pack_result (*ndr_push)(int opnum, NDR_PUSH *pndr, void *pout) = nullptr;
	/* the unbind function for the chosen interface */
	void (*unbind)(uint64_t handle) = nullptr;
	/* the reclaim function for the chosen interface */
	void (*reclaim)(uint32_t async_id) = nullptr;
};
