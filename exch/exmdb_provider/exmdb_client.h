#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_rpc.hpp>

enum {
	ALIVE_PROXY_CONNECTIONS,
	LOST_PROXY_CONNECTIONS
};

struct EXMDB_REQUEST;
struct EXMDB_RESPONSE;

int exmdb_client_get_param(int param);
extern void exmdb_client_init(int conn_num, int threads_num);
extern int exmdb_client_run(const char *config_path);
extern int exmdb_client_stop();
extern BOOL exmdb_client_check_local(const char *prefix, BOOL *b_private);
extern BOOL exmdb_client_do_rpc(const char *dir, const EXMDB_REQUEST *, EXMDB_RESPONSE *);
BOOL exmdb_client_relay_delivery(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult);

namespace exmdb_client_local {
#define IDLOUT
#define EXMIDL(n, p) extern GX_EXPORT BOOL n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
}

namespace exmdb_client = exmdb_client_local;
