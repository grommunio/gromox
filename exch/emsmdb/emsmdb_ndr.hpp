#pragma once
#define ZZNDR_NS emsmdb
#include <cstdint>
#include <gromox/ext_buffer.hpp>
#include <gromox/proc_common.h>
#include <gromox/rpc_types.hpp>

DECLARE_PROC_API(emsmdb, extern);
using namespace emsmdb;

#include <gromox/zz_ndr_stack.hpp>

enum {
	// ecDoConnect = 0,
	ecDoDisconnect = 1,
	// ecDoRpc = 2,
	// ecGetMoreRpc = 3,
	ecRRegisterPushNotification = 4,
	// ecRUnregisterPushNotification = 5,
	ecDummyRpc = 6,
	// ecRGetDCName = 7,
	// ecRNetGetDCName = 8,
	// ecDoRpcExt = 9,
	ecDoConnectEx = 10,
	ecDoRpcExt2 = 11,
	// ecDoAsyncConnect = 12,
	// ecDoAsyncWait = 13,
	ecDoAsyncConnectEx = 14,
};

enum {
	ecDoAsyncWaitEx = 0,
};

struct NDR_PULL;
struct NDR_PUSH;

/* warning: replicated from emsmdb/emsmdb.cpp, definitions must match! */
struct ECDOASYNCWAITEX_IN final : public rpc_request {
	ACXH acxh;
	uint32_t flags_in;
};

struct ECDOASYNCWAITEX_OUT final : public rpc_response {
	uint32_t flags_out;
	ec_error_t result;
};

struct ECDODISCONNECT_IN final : public rpc_request {
	CXH cxh;
};

struct ECDODISCONNECT_OUT final : public rpc_response {
	CXH cxh;
	ec_error_t result;
};

struct ECRREGISTERPUSHNOTIFICATION_IN final : public rpc_request {
	CXH cxh;
	uint32_t rpc;
	uint8_t *pctx;
	uint16_t cb_ctx;
	uint32_t advise_bits;
	uint8_t *paddr;
	uint16_t cb_addr;
};

struct ECDUMMYRPC_OUT final : public rpc_response {
	ec_error_t result;
};

struct ECRREGISTERPUSHNOTIFICATION_OUT final : public rpc_response {
	CXH cxh;
	uint32_t hnotification;
	ec_error_t result;
};

struct ECDOCONNECTEX_IN final : public rpc_request {
	char puserdn[1024];
	uint32_t flags;
	uint32_t conmod;
	uint32_t limit;
	cpid_t cpid;
	uint32_t lcid_string;
	uint32_t lcid_sort;
	uint32_t cxr_link;
	uint16_t cnvt_cps;
	uint16_t pclient_vers[3];
	uint32_t timestamp;
	uint8_t *pauxin;
	uint32_t cb_auxin;
	uint32_t cb_auxout;
};

struct ECDOCONNECTEX_OUT final : public rpc_response {
	CXH cxh;
	uint32_t max_polls;
	uint32_t max_retry;
	uint32_t retry_delay;
	uint16_t cxr;
	std::string pdn_prefix, pdisplayname;
	uint16_t pserver_vers[3];
	uint16_t pbest_vers[3];
	uint32_t timestamp;
	uint8_t pauxout[0x1008];
	uint32_t cb_auxout;
	ec_error_t result;
};

struct ECDORPCEXT2_IN final : public rpc_request {
	CXH cxh;
	uint32_t flags;
	uint8_t *pin;
	uint32_t cb_in;
	uint32_t cb_out;
	uint8_t *pauxin;
	uint32_t cb_auxin;
	uint32_t cb_auxout;
};

struct ECDORPCEXT2_OUT final : public rpc_response {
	CXH cxh;
	uint32_t flags;
	uint8_t pout[0x40000];
	uint32_t cb_out;
	uint8_t pauxout[0x1008];
	uint32_t cb_auxout;
	uint32_t trans_time;
	ec_error_t result;
};

struct ECDOASYNCCONNECTEX_IN final : public rpc_request {
	CXH cxh;
};

struct ECDOASYNCCONNECTEX_OUT final : public rpc_response {
	ACXH acxh;
	ec_error_t result;
};

extern pack_result asyncemsmdb_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
extern pack_result asyncemsmdb_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);
extern pack_result emsmdb_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
extern pack_result emsmdb_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);
