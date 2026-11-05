#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/idset.hpp>
#include <gromox/mapi_types.hpp>

struct message_content;

extern int exmdb_client_run_front(const char *);

namespace exmdb_client_local {
#define IDLOUT
#define EXMIDL(n, p) extern GX_EXPORT EXMIDL_RETTYPE n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
}
