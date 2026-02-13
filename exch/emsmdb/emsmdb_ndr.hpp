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
	ACXH acxh{};
	uint32_t flags_in = 0;
};

struct ECDOASYNCWAITEX_OUT final : public rpc_response {
	uint32_t flags_out = 0;
	ec_error_t result{};
};

struct ECDODISCONNECT_IN final : public rpc_request {
	CXH cxh{};
};

struct ECDODISCONNECT_OUT final : public rpc_response {
	CXH cxh{};
	ec_error_t result{};
};

struct ECRREGISTERPUSHNOTIFICATION_IN final : public rpc_request {
	CXH cxh{};
	uint32_t rpc = 0, advise_bits = 0;
	uint8_t *pctx = nullptr, *paddr = nullptr;
	uint16_t cb_ctx = 0, cb_addr = 0;
};

struct ECDUMMYRPC_OUT final : public rpc_response {
	ec_error_t result{};
};

struct ECRREGISTERPUSHNOTIFICATION_OUT final : public rpc_response {
	CXH cxh{};
	uint32_t hnotification = 0;
	ec_error_t result{};
};

struct ECDOCONNECTEX_IN final : public rpc_request {
	char puserdn[1024]{};
	uint32_t flags = 0, conmod = 0, limit = 0;
	cpid_t cpid{};
	uint32_t lcid_string = 0, lcid_sort = 0, cxr_link = 0;
	uint16_t cnvt_cps = 0;
	uint16_t pclient_vers[3]{};
	uint8_t *pauxin = nullptr;
	uint32_t cb_auxin = 0, cb_auxout = 0, timestamp = 0;
};

struct ECDOCONNECTEX_OUT final : public rpc_response {
	CXH cxh{};
	uint32_t max_polls = 0, max_retry = 0, retry_delay = 0;
	uint16_t cxr = 0;
	std::string pdn_prefix, pdisplayname;
	uint16_t pserver_vers[3]{};
	uint16_t pbest_vers[3]{};
	uint32_t timestamp = 0;
	uint8_t pauxout[0x1008]{};
	uint32_t cb_auxout = 0;
	ec_error_t result{};
};

struct ECDORPCEXT2_IN final : public rpc_request {
	CXH cxh{};
	uint32_t flags = 0, cb_in = 0, cb_out = 0, cb_auxin = 0, cb_auxout = 0;
	uint8_t *pin = nullptr, *pauxin = nullptr;
};

struct ECDORPCEXT2_OUT final : public rpc_response {
	CXH cxh{};
	uint32_t flags = 0, cb_out = 0, cb_auxout = 0, trans_time = 0;
	uint8_t pout[0x40000]{}, pauxout[0x1008]{};
	ec_error_t result{};
};

struct ECDOASYNCCONNECTEX_IN final : public rpc_request {
	CXH cxh{};
};

struct ECDOASYNCCONNECTEX_OUT final : public rpc_response {
	ACXH acxh{};
	ec_error_t result{};
};

extern pack_result asyncemsmdb_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
extern pack_result asyncemsmdb_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);
extern pack_result emsmdb_ndr_pull(unsigned int op, NDR_PULL &, std::unique_ptr<rpc_request> &);
extern pack_result emsmdb_ndr_push(unsigned int op, NDR_PUSH &, const rpc_response *);
