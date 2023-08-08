#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapi_types.hpp>

extern int exmdb_client_run_front(const char *);
extern BOOL exmdb_client_relay_delivery(const char *dir, const char *ev_from, const char *ev_to, cpid_t, const MESSAGE_CONTENT *, const char *digest, uint32_t *result);

namespace exmdb_client_local {
#define IDLOUT
#define EXMIDL(n, p) extern GX_EXPORT BOOL n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
}
