#pragma once
#include <optional>
#include <string>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/idset.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>

struct DB_NOTIFY;
struct exreq;
struct exresp;

namespace exmdb_client_impl {
class locator;
}

namespace gromox {

extern GX_EXPORT int exmdb_client_run(const char *cfgdir, void (*build_cb)(bool) = nullptr, void (*free_cb)() = nullptr);
extern GX_EXPORT bool exmdb_client_can_use_lpc(const char *dir, const char *ourhost, bool *pvt);
extern GX_EXPORT BOOL exmdb_client_do_rpc(const exreq *, exresp *);

class GX_EXPORT exmdb_client_remote {
	public:
	exmdb_client_remote(unsigned int conn_max = 1);
	~exmdb_client_remote();
	using async_handler_t = void (*)(const char *, BOOL, uint32_t, const DB_NOTIFY *);
	void set_async_notif(async_handler_t h) { m_event_proc = h; }
	exmdb_client_impl::locator *locator() { return m_locator.get(); }

#define IDLOUT
#define EXMIDL(n, p) static EXMIDL_RETTYPE n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

	public:
	std::string m_client_id;
	std::unique_ptr<exmdb_client_impl::locator> m_locator;
	void (*m_build_env)(bool pvt) = nullptr;
	void (*m_free_env)() = nullptr;
	void (*m_event_proc)(const char *, BOOL, uint32_t, const DB_NOTIFY *) = nullptr;
	int m_rpc_timeout = -1;
	gromox::atomic_bool m_notify_stop;
	bool m_allow_lpc = false;
};

extern GX_EXPORT std::optional<exmdb_client_remote> exmdb_client;

}
