#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapi_types.hpp>

namespace exmdb_client = exmdb_client_remote;

extern int exmdb_client_run_front(const char *);
void exmdb_client_register_proc(void *pproc);
