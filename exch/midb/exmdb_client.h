#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_rpc.hpp>

namespace exmdb_client = exmdb_client_remote;

struct EXMDB_REQUEST;
struct EXMDB_RESPONSE;

extern int exmdb_client_run_front(const char *);
void exmdb_client_register_proc(void *pproc);
extern BOOL exmdb_client_do_rpc(const char *dir, const EXMDB_REQUEST *, EXMDB_RESPONSE *);
