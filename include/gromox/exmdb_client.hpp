#pragma once
#include <ctime>
#include <list>
#include <mutex>
#include <pthread.h>
#include <gromox/atomic.hpp>
#include <gromox/common_types.hpp>
#include <gromox/list_file.hpp>

struct EXMDB_REQUEST;
struct EXMDB_RESPONSE;

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

struct remote_svr;

struct agent_thread {
	remote_svr *pserver = nullptr;
	pthread_t thr_id{};
	int sockd = -1;
};

struct remote_conn {
	remote_svr *psvr = nullptr;
	time_t last_time = 0;
	int sockd = -1;
};

struct GX_EXPORT remote_svr : public EXMDB_ITEM {
	remote_svr(EXMDB_ITEM &&o) : EXMDB_ITEM(std::move(o)) {}
	std::list<remote_conn> conn_list;
};

struct GX_EXPORT remote_conn_ref {
	remote_conn_ref() = default;
	remote_conn_ref(remote_conn_ref &&);
	~remote_conn_ref() { reset(true); }
	void operator=(remote_conn &&) = delete;
	remote_conn *operator->() { return tmplist.size() != 0 ? &tmplist.front() : nullptr; }
	bool operator==(std::nullptr_t) const { return tmplist.size() == 0; }
	bool operator!=(std::nullptr_t) const { return tmplist.size() != 0; }
	void reset(bool lost = false);

	std::list<remote_conn> tmplist;
};

using AGENT_THREAD = agent_thread;
using REMOTE_CONN = remote_conn;
using REMOTE_SVR = remote_svr;
using REMOTE_CONN_floating = remote_conn_ref;

extern GX_EXPORT std::vector<EXMDB_ITEM> mdcl_local_list;
extern GX_EXPORT std::list<agent_thread> mdcl_agent_list;
extern GX_EXPORT std::list<remote_conn> mdcl_lost_list;
extern GX_EXPORT std::list<remote_svr> mdcl_server_list;
extern GX_EXPORT std::mutex mdcl_server_lock;
extern GX_EXPORT gromox::atomic_bool mdcl_notify_stop;
extern GX_EXPORT unsigned int mdcl_conn_num, mdcl_threads_num;
extern GX_EXPORT pthread_t mdcl_scan_id;

extern GX_EXPORT void exmdb_client_init(unsigned int conn_num, unsigned int threads_num);
extern GX_EXPORT void exmdb_client_stop();
extern GX_EXPORT int exmdb_client_connect_exmdb(remote_svr &, bool listen, const char *prog_id, void (*)(const remote_svr &), void (*)());
extern GX_EXPORT int exmdb_client_run(const char *dir, unsigned int fl, void *(*)(void *), void *(*)(void *));
extern GX_EXPORT bool exmdb_client_check_local(const char *pfx, BOOL *pvt);
extern GX_EXPORT remote_conn_ref exmdb_client_get_connection(const char *dir);
extern GX_EXPORT BOOL exmdb_client_do_rpc(const char *dir, const EXMDB_REQUEST *, EXMDB_RESPONSE *);

}
