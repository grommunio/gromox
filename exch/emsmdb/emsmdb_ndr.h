#pragma once
#include <cstdint>
#include <gromox/proc_common.h>
#include <gromox/rpc_types.hpp>
#include <gromox/zz_ndr_stack.hpp>

struct NDR_PULL;
struct NDR_PUSH;

struct ECDOASYNCWAITEX_IN {
	ACXH acxh;
	uint32_t flags_in;
};

struct ECDOASYNCWAITEX_OUT {
	uint32_t flags_out;
	int32_t result;
};

struct ECDODISCONNECT_IN {
	CXH cxh;
};

struct ECDODISCONNECT_OUT {
	CXH cxh;
	int32_t result;
};

struct ECRREGISTERPUSHNOTIFICATION_IN {
	CXH cxh;
	uint32_t rpc;
	uint8_t *pctx;
	uint16_t cb_ctx;
	uint32_t advise_bits;
	uint8_t *paddr;
	uint16_t cb_addr;
};

struct ECRREGISTERPUSHNOTIFICATION_OUT {
	CXH cxh;
	uint32_t hnotification;
	int32_t result;
};

struct ECDOCONNECTEX_IN {
	char puserdn[1024];
	uint32_t flags;
	uint32_t conmod;
	uint32_t limit;
	uint32_t cpid;
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

struct ECDOCONNECTEX_OUT {
	CXH cxh;
	uint32_t max_polls;
	uint32_t max_retry;
	uint32_t retry_delay;
	uint16_t cxr;
	char pdn_prefix[1024];
	char pdisplayname[1024];
	uint16_t pserver_vers[3];
	uint16_t pbest_vers[3];
	uint32_t timestamp;
	uint8_t pauxout[0x1008];
	uint32_t cb_auxout;
	int32_t result;
};

struct ECDORPCEXT2_IN {
	CXH cxh;
	uint32_t flags;
	uint8_t *pin;
	uint32_t cb_in;
	uint32_t cb_out;
	uint8_t *pauxin;
	uint32_t cb_auxin;
	uint32_t cb_auxout;
};

struct ECDORPCEXT2_OUT {
	CXH cxh;
	uint32_t flags;
	uint8_t pout[0x40000];
	uint32_t cb_out;
	uint8_t pauxout[0x1008];
	uint32_t cb_auxout;
	uint32_t trans_time;
	int32_t result;
};

struct ECDOASYNCCONNECTEX_IN {
	CXH cxh;
};

struct ECDOASYNCCONNECTEX_OUT {
	ACXH acxh;
	int32_t result;
};

extern int asyncemsmdb_ndr_pull_ecdoasyncwaitex(NDR_PULL *, ECDOASYNCWAITEX_IN *);
extern int asyncemsmdb_ndr_push_ecdoasyncwaitex(NDR_PUSH *, const ECDOASYNCWAITEX_OUT *);
int emsmdb_ndr_pull_ecdodisconnect(NDR_PULL *pndr, ECDODISCONNECT_IN *r);
int emsmdb_ndr_push_ecdodisconnect(NDR_PUSH *pndr,
	const ECDODISCONNECT_OUT *r);
int emsmdb_ndr_pull_ecrregisterpushnotification(NDR_PULL *pndr,
	ECRREGISTERPUSHNOTIFICATION_IN *r);
int emsmdb_ndr_push_ecrregisterpushnotification(NDR_PUSH *pndr,
	const ECRREGISTERPUSHNOTIFICATION_OUT *r);
int emsmdb_ndr_push_ecdummyrpc(NDR_PUSH *pndr, int32_t *r);
int emsmdb_ndr_pull_ecdoconnectex(NDR_PULL *pndr, ECDOCONNECTEX_IN *r);
int emsmdb_ndr_push_ecdoconnectex(NDR_PUSH *pndr, const ECDOCONNECTEX_OUT *r);
int emsmdb_ndr_pull_ecdorpcext2(NDR_PULL *pndr, ECDORPCEXT2_IN *r);
int emsmdb_ndr_push_ecdorpcext2(NDR_PUSH *pndr, const ECDORPCEXT2_OUT *r);
int emsmdb_ndr_pull_ecdoasyncconnectex(NDR_PULL *pndr,
	ECDOASYNCCONNECTEX_IN *r);
int emsmdb_ndr_push_ecdoasyncconnectex(NDR_PUSH *pndr,
	const ECDOASYNCCONNECTEX_OUT *r);
