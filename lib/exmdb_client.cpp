// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <list>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <vector>
#include <libHX/endian.h>
#include <libHX/scope.hpp>
#include <libHX/socket.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>
#ifndef AI_V4MAPPED
#	define AI_V4MAPPED 0
#endif

namespace {

struct remote_svr;

struct agent_thread {
	agent_thread() = default;
	agent_thread(agent_thread &&o) :
		pserver(o.pserver), thr_id(o.thr_id), sockd(o.sockd),
		startup_wait(o.startup_wait.load())
	{
		o.pserver = nullptr;
		o.thr_id = {};
		o.sockd = -1;
	}
	~agent_thread();
	void operator=(agent_thread &&) = delete;

	remote_svr *pserver = nullptr;
	pthread_t thr_id{};
	int sockd = -1;
	gromox::atomic_bool startup_wait{false};
	std::condition_variable startup_cv;
};

struct remote_conn {
	remote_conn(remote_svr *s) : psvr(s) {}
	NOMOVE(remote_conn);
	~remote_conn();

	remote_svr *psvr = nullptr;
	time_t last_time = 0;
	int sockd = -1;
};

struct remote_conn_ref {
	remote_conn_ref() = default;
	remote_conn_ref(remote_conn_ref &&);
	~remote_conn_ref() { reset(true); }
	void operator=(remote_conn &&) = delete;
	remote_conn *operator->() { return tmplist.size() != 0 ? &tmplist.front() : nullptr; }
	bool operator==(std::nullptr_t) const { return tmplist.size() == 0; }
	void reset(bool lost = false);

	std::list<remote_conn> tmplist;
};

struct remote_svr {
	std::string prefix, host;
	uint16_t port = 0;
	enum {
		EXMDB_PRIVATE,
		EXMDB_PUBLIC,
	} type;

	std::list<remote_conn> conn_list;
	std::optional<agent_thread> m_agent;
	unsigned int in_flight = 0; /* conns borrowed into remote_conn_ref::tmplist */
};

}

namespace gromox {

std::optional<exmdb_client_remote> exmdb_client;
bool g_exmdb_allow_lpc;

static int mdcl_rpc_timeout = -1;
static std::list<remote_svr> mdcl_server_list;
static std::mutex mdcl_server_lock; /* he protecc mdcl_server_list+mdcl_agent_list and contents */
static atomic_bool mdcl_notify_stop;
static unsigned int mdcl_conn_max;
static void (*mdcl_build_env)(bool pvt);
static void (*mdcl_free_env)();
static void (*mdcl_event_proc)(const char *, BOOL, uint32_t, const DB_NOTIFY *);
static char mdcl_remote_id[128];
static std::atomic<unsigned int> g_exmdbcl_active_handles;

}

agent_thread::~agent_thread()
{
	pthread_kill(thr_id, SIGALRM);
	pthread_join(thr_id, nullptr);
	if (sockd >= 0)
		close(sockd);
}

remote_conn::~remote_conn()
{
	if (sockd < 0)
		return;
	gromox::mlog(LV_DEBUG, "exmdb_client: disconnect [%s]:%hu/%s, fd %d, ah=%u",
		psvr->host.c_str(), psvr->port, psvr->prefix.c_str(), sockd,
		gromox::g_exmdbcl_active_handles.load());
	close(sockd);
	sockd = -1;
	do {
		unsigned int curr = gromox::g_exmdbcl_active_handles;
		if (curr == 0)
			break;
		unsigned int next = curr - 1;
		if (gromox::g_exmdbcl_active_handles.compare_exchange_weak(curr, next))
			return;
	} while (true);
}

remote_conn_ref::remote_conn_ref(remote_conn_ref &&o)
{
	reset(true);
	tmplist = std::move(o.tmplist);
}

void remote_conn_ref::reset(bool lost)
{
	if (tmplist.size() == 0)
		return;
	auto pconn = &tmplist.front();
	std::lock_guard sv_hold(gromox::mdcl_server_lock);
	if (pconn->psvr != nullptr)
		--pconn->psvr->in_flight;
	if (pconn->sockd < 0 || lost) {
		tmplist.clear();
		return;
	}
	pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), tmplist, tmplist.begin());
}

static constexpr cfg_directive exmdb_client_dflt[] = {
	{"exmdb_client_rpc_timeout", "0", CFG_TIME, "0"},
	CFG_TABLE_END,
};

namespace gromox {

exmdb_client_remote::exmdb_client_remote(unsigned int conn_max)
{
	auto cfg = config_file_initd("gromox.cfg", PKGSYSCONFDIR, exmdb_client_dflt);
	if (cfg == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd gromox.cfg: %s",
			strerror(errno));
	} else {
		mdcl_rpc_timeout = cfg->get_ll("exmdb_client_rpc_timeout");
		if (mdcl_rpc_timeout <= 0)
			mdcl_rpc_timeout = -1;
		if (mdcl_rpc_timeout > 0)
			mdcl_rpc_timeout *= 1000;
	}
	setup_signal_defaults();
	mdcl_notify_stop = true;
	mdcl_conn_max = conn_max;
	snprintf(mdcl_remote_id, std::size(mdcl_remote_id), "%u.", static_cast<unsigned int>(getpid()));
	auto z = strlen(mdcl_remote_id);
	GUID::machine_id().to_str(mdcl_remote_id + z, std::size(mdcl_remote_id) - z, 32);
}

exmdb_client_remote::~exmdb_client_remote()
{
	if (mdcl_conn_max != 0 && !mdcl_notify_stop)
		mdcl_notify_stop = true;
	mdcl_notify_stop = true;
	std::lock_guard sv_hold(mdcl_server_lock);
	mdcl_server_list.clear();
	mdcl_build_env = nullptr;
	mdcl_free_env = nullptr;
	mdcl_event_proc = nullptr;
}

static int exmdb_client_connect_exmdb(const remote_svr &srv, bool b_listen,
    const char *prog_id)
{
	int sockd = HX_inet_connect(srv.host.c_str(), srv.port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> mdcl_lastwarn_time;
		auto prev = mdcl_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && mdcl_lastwarn_time.compare_exchange_strong(prev, now))
			mlog(LV_ERR, "exmdb_client: HX_inet_connect to [%s]:%hu: %s",
			        srv.host.c_str(), srv.port, strerror(-sockd));
	        return -2;
	}
	auto cl_sock = HX::make_scope_exit([&]() { close(sockd); });
	BINARY bin;
	if (!b_listen) {
		exreq_connect rqc;
		rqc.call_id = exmdb_callid::connect;
		rqc.prefix = deconst(srv.prefix.c_str());
		rqc.remote_id = mdcl_remote_id;
		rqc.b_private = srv.type == remote_svr::EXMDB_PRIVATE ? TRUE : false;
		if (exmdb_ext_push_request(&rqc, &bin) != pack_result::ok)
			return -1;
	} else {
		exreq_listen_notification rql;
		rql.call_id = exmdb_callid::listen_notification;
		rql.remote_id = mdcl_remote_id;
		if (exmdb_ext_push_request(&rql, &bin) != pack_result::ok)
			return -1;
	}
	if (!exmdb_client_write_socket(sockd, bin, SOCKET_TIMEOUT * 1000)) {
		free(bin.pb);
		return -1;
	}
	free(bin.pb);
	bin.pb = nullptr;
	if (mdcl_build_env != nullptr)
		mdcl_build_env(srv.type == remote_svr::EXMDB_PRIVATE);
	auto cl_0 = HX::make_scope_exit([]() { if (mdcl_free_env != nullptr) mdcl_free_env(); });
	if (!exmdb_client_read_socket(sockd, bin, mdcl_rpc_timeout) ||
	    bin.pb == nullptr)
		return -1;
	auto response_code = static_cast<exmdb_response>(bin.pb[0]);
	exmdb_rpc_free(bin.pb);
	bin.pb = nullptr;
	if (response_code != exmdb_response::success) {
		mlog(LV_ERR, "exmdb_client: Failed to connect to [%s]:%hu/%s: %s",
		       srv.host.c_str(), srv.port, srv.prefix.c_str(),
		       exmdb_rpc_strerror(response_code));
		return -1;
	} else if (bin.cb != 5) {
		mlog(LV_ERR, "exmdb_client: response format error "
		       "during connect to [%s]:%hu/%s",
		       srv.host.c_str(), srv.port, srv.prefix.c_str());
		return -1;
	}
	cl_sock.release();
	return sockd;
}

static int cl_notif_reader3(agent_thread &agent, pollfd &pfd,
    std::string &buff, size_t &offset)
{
	if (poll(&pfd, 1, SOCKET_TIMEOUT * 1000) != 1)
		return -1;
	if (buff.size() == 0) {
		uint32_t buff_len = 0;
		if (read(agent.sockd, &buff_len, sizeof(buff_len)) != sizeof(buff_len))
			return -1;
		/* ping packet */
		if (buff_len == 0) {
			auto resp_code = exmdb_response::success;
			if (write(agent.sockd, &resp_code, 1) != 1)
				return -1;
		}
		buff.resize(buff_len);
		offset = 0;
		return 0;
	}
	auto read_len = read(agent.sockd, &buff.data()[offset], buff.size() - offset);
	if (read_len <= 0)
		return -1;
	offset += read_len;
	if (offset != buff.size())
		return 0;

	/* packet complete */
	BINARY bin;
	bin.cb = buff.size();
	bin.pc = buff.data();
	if (mdcl_build_env != nullptr)
		mdcl_build_env(agent.pserver->type == remote_svr::EXMDB_PRIVATE);
	auto cl_0 = HX::make_scope_exit([]() { if (mdcl_free_env != nullptr) mdcl_free_env(); });
	DB_NOTIFY_DATAGRAM notify;
	auto resp_code = exmdb_ext_pull_db_notify(&bin, &notify) == pack_result::ok ?
	                 exmdb_response::success : exmdb_response::pull_error;
	if (write(agent.sockd, &resp_code, 1) != 1)
		return -1;
	if (resp_code == exmdb_response::success)
		for (size_t i = 0; i < notify.id_array.size(); ++i)
			mdcl_event_proc(notify.dir, notify.b_table,
				notify.id_array[i], &notify.db_notify);
	buff.clear();
	offset = 0;
	return 0;
}

static void cl_notif_reader2(agent_thread &agent)
{
	agent.sockd = exmdb_client_connect_exmdb(*agent.pserver, true, "mdclntfy");
	if (agent.sockd < 0) {
		sleep(1);
		return;
	}
	agent.startup_wait = false;
	agent.startup_cv.notify_one();
	struct pollfd pfd = {agent.sockd, POLLIN | POLLPRI};
	size_t offset = 0;
	std::string buff;
	while (cl_notif_reader3(agent, pfd, buff, offset) == 0)
		/* */;
	close(agent.sockd);
	agent.sockd = -1;
}

static void *cl_notif_reader(void *vargs)
{
	while (!mdcl_notify_stop)
		cl_notif_reader2(*static_cast<agent_thread *>(vargs));
	return nullptr;
}

static int launch_notify_listener(remote_svr &srv) try
{
	/* Notification thread creates its own socket. */
	auto &ag = srv.m_agent.emplace();
	auto thrtxt = std::string("mcn") + mdcl_remote_id;
	ag.pserver = &srv;
	ag.sockd = -1;
	ag.startup_wait = true;
	auto ret = pthread_create4(&ag.thr_id, nullptr, cl_notif_reader, &ag);
	if (ret != 0) {
		mlog(LV_ERR, "E-1449: pthread_create: %s", strerror(ret));
		srv.m_agent.reset();
		return 8;
	}
	ret = pthread_setname_np(ag.thr_id, thrtxt.c_str());
#ifdef __GLIBC__
	/* prctl truncates the name. Why can't you do the same, glibc? */
	if (ret != 0) {
		thrtxt.resize(15);
		ret = pthread_setname_np(ag.thr_id, thrtxt.c_str());
	}
#endif
	if (ret != 0)
		mlog(LV_ERR, "pthread_setname_np: %s", strerror(ret));
	/*
	 * Wait for the notify thread to be up before allowing
	 * current thread to send any commands.
	 */
	std::mutex mtx;
	std::unique_lock lk(mtx);
	ag.startup_cv.wait(lk, [&]() { return !ag.startup_wait; });
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "exmdb_client: failed to allocate memory for exmdb");
	return 7;
}

/**
 * @ep:     callback function for notifications
 */
void exmdb_client_remote::set_async_notif(void (*ep)(const char *, BOOL, uint32_t, const DB_NOTIFY *))
{
	mdcl_event_proc = ep;
}

int exmdb_client_run(const char *cfgdir, unsigned int flags,
    void (*build_env)(bool), void (*free_env)())
{
	if (service_run_library({"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}) != PLUGIN_LOAD_OK)
		return -1;
	mdcl_build_env = build_env;
	mdcl_free_env = free_env;

	mdcl_notify_stop = false;
	if (mdcl_conn_max == 0)
		return 0;
	return 0;
}

/**
 * Indicate whether this host is responsible for serving a mailbox
 * and whether we can actually exercise it (usually only in the
 * specific setup when exchange_emsmdb is in the same process image
 * as exmdb_provider).
 *
 * @prefix:  a mailbox directory
 * @ourhost: caller's hostname
 * @pvt:     returns whether the directory refers to a private or public store
 *
 * A similar function body is located in exmdb_parser_is_local().
 */
bool exmdb_client_can_use_lpc(const char *prefix, const char *ourhost,
    bool *is_pvt)
{
	if (!g_exmdb_allow_lpc)
		return false;
	if (*prefix == '\0')
		return true;
	std::string remotehost;
	auto err = mysql_adaptor_get_homeserver_for_dir(prefix, is_pvt, remotehost);
	if (err == 0)
		return remotehost == znul(ourhost);
	else if (err == ENOENT)
		return false;
	mlog(LV_ERR, "%s: %s: %s", __func__, prefix, strerror(err));
	return false;
}

static bool sock_ready_for_write(int fd)
{
	struct pollfd pfd = {fd, POLLIN};
	/* The fd must not have any input data (or EOF) waiting */
	return poll(&pfd, 1, 0) == 0;
}

/**
 * @i: the one remote_svr entry we just added and which should not be removed
 */
static void close_older_connection(decltype(mdcl_server_list)::const_iterator i)
{
	/* Try closing one older connection. */
	for (auto j = mdcl_server_list.begin(); j != mdcl_server_list.end(); ) {
		if (j == i) {
			++j;
			continue;
		}
		bool do_pop = j->conn_list.size() > 0;
		if (do_pop) {
			mlog(LV_DEBUG, "exmdb_client: kicking [%s]:%hu/%s fd %d to make room",
				j->host.c_str(), j->port, j->prefix.c_str(), j->conn_list.back().sockd);
			j->conn_list.pop_back();
		}
		/* Do not touch async notifier threads, they are kind of separate anyway. */
		auto clean = j->conn_list.empty() && !j->m_agent.has_value() && j->in_flight == 0;
		if (do_pop) {
			if (clean)
				mdcl_server_list.erase(j);
			break;
		}
		if (clean)
			j = mdcl_server_list.erase(j);
		else
			++j;
	}
}

/**
 * Get a connection file descriptor for the given homedir.
 * If necessary, vivify a remote_svr entry and/or sockets.
 *
 * This function always produces a socket: If you want to do LPC call
 * exmdb_client_is_local instead (and if LPC is available, don't use
 * get_connection).
 */
static remote_conn_ref exmdb_client_get_connection(const char *dir)
{
	remote_conn_ref fc;
	std::unique_lock sv_hold(mdcl_server_lock);
	auto i = std::find_if(mdcl_server_list.begin(), mdcl_server_list.end(),
	         [&](const remote_svr &s) { return s.prefix == dir; });
	/* std::list iterators don't invalidate unless the element goes away */
	if (i == mdcl_server_list.end()) try {
		sv_hold.unlock();
		remote_svr itm;
		itm.prefix = dir;
		itm.port = 5000; /* XXX: hardcoded port number */
		bool is_pvt = false;
		auto err = mysql_adaptor_get_homeserver_for_dir(dir, &is_pvt, itm.host);
		if (err != 0) {
			mlog(LV_ERR, "exmdb_client: cannot find remote server for %s", dir);
			return fc;
		}
		if (itm.host.empty())
			itm.host = "localhost";
		itm.type = is_pvt ? remote_svr::EXMDB_PRIVATE : remote_svr::EXMDB_PUBLIC;
		sv_hold.lock();
		mdcl_server_list.emplace_back(std::move(itm));
		i = std::prev(mdcl_server_list.end());
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
		return fc;
	}
	while (i->conn_list.size() > 0) {
		if (sock_ready_for_write(i->conn_list.front().sockd)) {
			++i->in_flight;
			fc.tmplist.splice(fc.tmplist.end(), i->conn_list, i->conn_list.begin());
			return fc;
		}
		i->conn_list.pop_front();
	}
	if (g_exmdbcl_active_handles >= mdcl_conn_max)
		close_older_connection(i);
	if (g_exmdbcl_active_handles >= mdcl_conn_max) {
		mlog(LV_ERR, "exmdb_client: reached global maximum connections (max:%u)",
		        mdcl_conn_max);
		return fc;
	}

	++i->in_flight;
	sv_hold.unlock();
	/* i->{host,port,prefix} is unchanging after init, so should be ok to access without lock */
	fc.tmplist.emplace_back(&*i);
	auto &conn = fc.tmplist.back();
	conn.sockd = exmdb_client_connect_exmdb(*i, false, "mdcl");
	if (conn.sockd == -2) {
		fc.reset(true);
		return fc;
	} else if (conn.sockd < 0) {
		mlog(LV_ERR, "exmdb_client: protocol error connecting to [%s]:%hu/%s",
		        i->host.c_str(), i->port, i->prefix.c_str());
		fc.reset(true);
		return fc;
	}
	++g_exmdbcl_active_handles;
	mlog(LV_DEBUG, "exmdb_client: connected to [%s]:%hu/%s, fd %d, active_handles=%u",
		i->host.c_str(), i->port, i->prefix.c_str(), conn.sockd,
		g_exmdbcl_active_handles.load());
	sv_hold.lock();
	if (mdcl_event_proc != nullptr && !i->m_agent.has_value())
		launch_notify_listener(*i);
	return fc;
}

BOOL exmdb_client_do_rpc(const exreq *rq, exresp *rsp)
{
	BINARY bin;

	if (exmdb_ext_push_request(rq, &bin) != pack_result::ok)
		return false;
	auto conn = exmdb_client_get_connection(rq->dir);
	if (conn == nullptr || !exmdb_client_write_socket(conn->sockd,
	    bin, SOCKET_TIMEOUT * 1000)) {
		free(bin.pb);
		return false;
	}
	free(bin.pb);
	bin.pb = nullptr;
	if (!exmdb_client_read_socket(conn->sockd, bin, mdcl_rpc_timeout))
		return false;
	conn->last_time = time(nullptr);
	if (bin.pb == nullptr)
		return false;
	if (bin.cb == 1) {
		exmdb_rpc_free(bin.pb);
		/* Connection is still good in principle. */
		conn.reset();
		return false;
	}
	if (bin.cb < 5) {
		exmdb_rpc_free(bin.pb);
		/*
		 * Malformed packet? Let connection die
		 * (~exmdb_connection_ref), lest the next response might pick
		 * up garbage from the current response.
		 */
		return false;
	}
	conn.reset();
	rsp->call_id = rq->call_id;
	bin.cb -= 5;
	bin.pb += 5;
	auto ret = exmdb_ext_pull_response(&bin, rsp);
	bin.pb -= 5;
	exmdb_rpc_free(bin.pb);
	return ret == pack_result::ok ? TRUE : false;
}

}
