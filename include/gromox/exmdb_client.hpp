#pragma once
#include <atomic>
#include <condition_variable>
#include <ctime>
#include <list>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/idset.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>

struct DB_NOTIFY;
struct exreq;
struct exresp;

namespace gromox {

enum {
	EXMDB_CLIENT_NO_FLAGS = 0,
	/* Skip over public folders */
	EXMDB_CLIENT_SKIP_PUBLIC = 0x1U,
	/* Skip over exmdb_list.txt entries that are remote */
	EXMDB_CLIENT_SKIP_REMOTE = 0x2U,
	/* Go via filesystem instead of TCP */
	EXMDB_CLIENT_ALLOW_DIRECT = 0x4U,
	/*
	 * N.B.: Combining EXMDB_CLIENT_SKIP_REMOTE +
	 * !EXMDB_CLIENT_ALLOW_DIRECT means all "local" locations will be
	 * accessed via TCP.
	 */
};

extern GX_EXPORT int exmdb_client_run(const char *cfgdir, unsigned int fl = EXMDB_CLIENT_NO_FLAGS, void (*build_cb)(bool) = nullptr, void (*free_cb)() = nullptr, void (*event_cb)(const char *, BOOL, uint32_t, const DB_NOTIFY *) = nullptr);
extern GX_EXPORT bool exmdb_client_can_use_lpc(const char *pfx, BOOL *pvt);
extern GX_EXPORT BOOL exmdb_client_do_rpc(const exreq *, exresp *);

class GX_EXPORT exmdb_client_remote {
	public:
	exmdb_client_remote(unsigned int conn_max, unsigned int notify_threads_max);
	~exmdb_client_remote();

#define IDLOUT
#define EXMIDL(n, p) static EXMIDL_RETTYPE n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
};

extern GX_EXPORT std::optional<exmdb_client_remote> exmdb_client;
extern GX_EXPORT bool g_exmdb_allow_lpc;

}
