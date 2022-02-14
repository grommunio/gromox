#pragma once
#include <ctime>
#include <list>
#include <mutex>
#include <pthread.h>
#include <gromox/atomic.hpp>
#include <gromox/list_file.hpp>

namespace gromox {

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

extern GX_EXPORT std::list<agent_thread> mdcl_agent_list;
extern GX_EXPORT std::list<remote_conn> mdcl_lost_list;
extern GX_EXPORT std::list<remote_svr> mdcl_server_list;
extern GX_EXPORT std::mutex mdcl_server_lock;
extern GX_EXPORT gromox::atomic_bool mdcl_notify_stop;
extern GX_EXPORT unsigned int mdcl_conn_num, mdcl_threads_num;
extern GX_EXPORT pthread_t mdcl_scan_id;

extern GX_EXPORT void exmdb_client_init(unsigned int conn_num, unsigned int threads_num);
extern GX_EXPORT void exmdb_client_stop();

}
