#pragma once
#include <cstdint>
#include <memory>
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
extern int exmdb_client_run(const char *configdir);
extern int exmdb_client_stop();
void exmdb_client_register_proc(void *pproc);
extern BOOL exmdb_client_do_rpc(const char *dir, const EXMDB_REQUEST *, EXMDB_RESPONSE *);
