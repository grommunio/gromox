// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <libHX/io.h>
#include <libHX/scope.hpp>
#include <libHX/socket.h>
#include <gromox/atomic.hpp>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/paths.h>
#include <gromox/plugin.hpp>
#include <gromox/process.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/util.hpp>

using namespace gromox;

namespace {

enum class srv_type : uint8_t {
	undef, xprivate, xpublic,
};

/**
 * "Unique key" for a server, i.e. if any paramter (of @host, @port, @type) is
 * different, it constitutes a different server logically, and needs its own
 * set of file descriptors.
 *
 * The member order @host,@port,@type is fine, as we expect the overwhelming
 * amount of srv_ident instances to have the same @port and @type (5000 and
 * private), so that comparing port/type ahead of host would not buy much.
 */
struct srv_ident {
	std::string host;
	uint16_t port = 0;
	srv_type type = srv_type::undef;
	auto operator<=>(const srv_ident &o) const = default;
};

/* Augmented wrapfd with logging */
class srv_conn {
	public:
	~srv_conn();
	wrapfd m_fd;
	exmdb_client_impl::locator *m_locator = nullptr;
	srv_ident m_ident;
};

class srv_entry;

/**
 * @m_pool: where to return the fd to as the ref gets destroyed
 *
 * The class is designed such that connections do not implicitly get returned
 * to pools when an exception occurs somewhere. Putback to the pool is
 * explicit, and needs to be invoked with `ref.reset()`.
 *
 * Because srv_entry::conn_list is a std::list<>, it makes sense to also use
 * std::list in srv_conn_ref, so that, on putback, there is no memory
 * allocation. (There would be one if srv_conn_ref was based on a pure srv_conn
 * and we were to use m_pool.conn_list.emplace_back(std::move(*this)).)
 */
class srv_conn_ref {
	public:
	srv_conn_ref() = default;
	srv_conn_ref(srv_conn_ref &&o) noexcept = default;
	srv_conn_ref(gromox::wrapfd &&, std::shared_ptr<srv_entry> &, exmdb_client_impl::locator *);
	srv_conn_ref &operator=(srv_conn_ref &&o) noexcept = default;
	srv_conn *operator->() { return m_hold.size() != 0 ? &m_hold.front() : nullptr; }
	operator bool() const { return m_hold.size() != 0; }
	bool operator==(std::nullptr_t) const { return m_hold.size() == 0; }
	void putback();
	void splice_one_from_back(std::list<srv_conn> &);

	std::list<srv_conn> m_hold;
	std::weak_ptr<srv_entry> m_pool;
};

/**
 * Async notification listener.
 * @m_thr_id:     pthread internal identifier
 * @startup_wait: means to wait for the pthread being up
 * @startup_cv:   means to wait for the pthread being up
 * @m_ident:      connection parameter(s); it's a copy so we do not need to rely
 *                on srv_entry being around
 */
struct async_listener {
	async_listener() = default;
	async_listener(const srv_ident &ident, exmdb_client_remote *bp_client) :
		m_ident(ident), m_client(bp_client) {}
	NOMOVE(async_listener);
	~async_listener();
	errno_t launch();
	static void *thread_entry(void *);

	private:
	int process_packet(wrapfd &, pollfd &, std::string &, size_t &);
	void connect_and_listen();

	pthread_t m_thr_id{};
	atomic_bool startup_wait{false}, m_stop{false};
	std::condition_variable startup_cv;
	srv_ident m_ident;
	exmdb_client_remote *m_client = nullptr;
};

/**
 * Connection pool for one server
 *
 * @ident:     (re-)provided so we have something for logging
 * @conn_list: connections that are still open and can be re-used
 *             (older ones to the front, newer ones to the back)
 * @conn_lock: protects conn_list
 * @m_async:   notification listener thread (manages connections individually)
 */
class srv_entry {
	public:
	srv_conn_ref extract_one_connection();
	bool drop_one_connection();
	bool purgable() const;
	void launch_notify_listener(exmdb_client_remote *);

	/*
	 * Repeat the identifier so we have all the connection info even if the
	 * unordered_map entry is going away.
	 */
	srv_ident ident;
	std::list<srv_conn> conn_list;
	std::mutex conn_lock; /* protects conn_list & m_async */
	std::shared_ptr<async_listener> m_async;
};

} /* anon-ns */

namespace exmdb_client_impl {

/**
 * Connection tree helper class
 *
 * @dir_to_srv:   speedy direct map from directory to connection pool
 *                (meant for recently-used userdirs)
 * @name_to_srv:  semi-speedy map from homeserver to connection pool
 *                (meant for recently-used homeservers, but newly-seen userdirs)
 * @dts_lock:     protects dir_to_srv
 * @nts_lock:     protects name_to_srv
 * @maker_lock:   exclusion to wanting to increase m_active
 * @m_active:     current global connections
 * @m_maxconn:    maximum global connections
 */
class locator {
	public:
	locator(size_t maxconn, exmdb_client_remote *client) : m_maxconn(maxconn), m_client(client) {}
	srv_conn_ref get_connection(const char *dir);
	size_t bump_active_count() { return ++m_active; }
	size_t drop_active_count();

	private:
	srv_ident try_emplace_dir(const char *);
	std::shared_ptr<srv_entry> try_emplace_server(const srv_ident &);
	bool clean_some_connection(const srv_ident &dontclean);
	void cleanup_dts();
	void cleanup_nts();

	std::atomic<size_t> m_active{0};
	size_t m_maxconn = 0;
	exmdb_client_remote *m_client = nullptr;
	std::map<srv_ident, std::shared_ptr<srv_entry>> name_to_srv;
	std::unordered_map<std::string, std::pair<srv_ident, gromox::time_point>> dir_to_srv;
	std::mutex dts_lock, nts_lock, maker_lock;
	gromox::time_point m_last_dts_purge{}, m_last_nts_purge{};

	/* time after which mysql_adaptor_get_homeserver() should be called again */
	static constexpr std::chrono::seconds dts_refresh_time{60};
	/* time after which a dir_to_srv entry may be removed entirely */
	static constexpr std::chrono::seconds dts_purge_time{120};
};

}

using namespace exmdb_client_impl;

static constexpr cfg_directive exmdb_client_dflt[] = {
	{"exmdb_client_rpc_timeout", "0", CFG_TIME, "0"},
	CFG_TABLE_END,
};

namespace gromox {
std::optional<exmdb_client_remote> exmdb_client;
}

/**
 * Lower-level connection establisher
 *
 * @srv:      where to connect
 * @dir:      mailbox store
 * @b_listen: true if the connection should switch into becoming
 *            an async notify listener
 *
 * Returns the file descriptor number, or -2 on connection problems,
 * or -1 on data exchange problems.
 */
static wrapfd make_exmdb_connection(const srv_ident &ident, const char *dir,
    bool b_listen, exmdb_client_remote *bp_client)
{
	wrapfd fd = HX_inet_connect(ident.host.c_str(), ident.port, 0);
	if (fd.get() < 0) {
		static std::atomic<decltype(tp_now())> mdcl_lastwarn_time;
		auto prev = mdcl_lastwarn_time.load();
		auto next = prev + std::chrono::minutes(1);
		auto now = tp_now();
		if (next <= now && mdcl_lastwarn_time.compare_exchange_strong(prev, now))
			mlog(LV_ERR, "exmdb_client: HX_inet_connect to [%s]:%hu: %s",
				ident.host.c_str(), ident.port, strerror(-fd.get()));
		return -2;
	}

	BINARY bin;
	if (b_listen) {
		exreq_listen_notification rql;
		rql.call_id   = exmdb_callid::listen_notification;
		rql.remote_id = deconst(bp_client->m_client_id.c_str());
		if (exmdb_ext_push_request(&rql, &bin) != pack_result::ok)
			return -1;
	} else {
		/*
		 * "connect" is a misnomer; exmdb_server merely verifies that
		 * @dir is served (and that the serve check was done at least
		 * once). Any subsequent EXRPC can specify an arbitrary
		 * userdir.
		 */
		exreq_connect rqc;
		rqc.call_id   = exmdb_callid::connect;
		rqc.prefix    = deconst(dir);
		rqc.remote_id = deconst(bp_client->m_client_id.c_str());
		rqc.b_private = ident.type == srv_type::xprivate ? TRUE : false;
		if (exmdb_ext_push_request(&rqc, &bin) != pack_result::ok)
			return -1;
	}
	if (!exmdb_client_write_socket(fd.get(), bin, SOCKET_TIMEOUT * 1000)) {
		free(bin.pb);
		return -1;
	}
	free(bin.pb);
	bin.pb = nullptr;

	if (bp_client->m_build_env != nullptr)
		bp_client->m_build_env(ident.type == srv_type::xprivate);
	auto cl_0 = HX::make_scope_exit([bp_client]() {
		if (bp_client->m_free_env != nullptr)
			bp_client->m_free_env();
	});
	if (!exmdb_client_read_socket(fd.get(), bin, bp_client->m_rpc_timeout) ||
	    bin.pb == nullptr)
		return -1;
	auto response_code = static_cast<exmdb_response>(bin.pb[0]);
	exmdb_rpc_free(bin.pb);
	bin.pb = nullptr;

	if (response_code != exmdb_response::success) {
		mlog(LV_ERR, "exmdb_client: Failed to connect to [%s]:%hu: %s",
		       ident.host.c_str(), ident.port,
		       exmdb_rpc_strerror(response_code));
		return -1;
	} else if (bin.cb != 5) {
		mlog(LV_ERR, "exmdb_client: response format error "
		       "during connect to [%s]:%hu",
		       ident.host.c_str(), ident.port);
		return -1;
	}
	return fd;
}

errno_t async_listener::launch() try
{
	startup_wait = true;
	if (!pthread_equal(m_thr_id, {})) {
		mlog(LV_ERR, "%s:%u: assertion failed m_thr_id==null", __FILE__, __LINE__);
		return EINVAL;
	}
	auto procname = std::string("mcn") + m_client->m_client_id;
	auto ret = pthread_create4(&m_thr_id, nullptr, thread_entry, this);
	if (ret != 0) {
		m_thr_id = {};
		mlog(LV_ERR, "E-1449: pthread_create: %s", strerror(ret));
		return ret;
	}
	ret = pthread_setname_np(m_thr_id, procname.c_str());
#ifdef __GLIBC__
	/* prctl truncates the name. Why can't you do the same, glibc? */
	if (ret != 0) {
		procname.resize(15);
		ret = pthread_setname_np(m_thr_id, procname.c_str());
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
	if (!startup_cv.wait_for(lk, std::chrono::seconds(1),
	    [&]() { return !startup_wait; }))
		mlog(LV_WARN, "exmdb_client: notify thread for "
			"[%s]:%hu is a little slow in connecting",
			m_ident.host.c_str(), m_ident.port);
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return ENOMEM;
}

async_listener::~async_listener()
{
	m_stop = true;
	if (!pthread_equal(m_thr_id, {})) {
		pthread_kill(m_thr_id, SIGALRM);
		pthread_join(m_thr_id, nullptr);
	}
}

/**
 * Reads some bytes off the network and, if a complete EXRPC packet is formed,
 * processes it.
 *
 * Returns 0 on "success" or when waiting for more data.
 * Returns <0 when it has been determined that the current notify channel should
 * be recreated. (timeout, read errors, etc.)
 */
int async_listener::process_packet(wrapfd &fd, pollfd &pfd,
    std::string &buff, size_t &offset)
{
	if (poll(&pfd, 1, SOCKET_TIMEOUT * 1000) != 1)
		return -1;
	if (buff.size() == 0) {
		uint32_t buff_len = 0;
		if (HXio_fullread(fd.get(), &buff_len, sizeof(buff_len)) != sizeof(buff_len))
			return -1;
		/* ping packet */
		if (buff_len == 0) {
			auto resp_code = exmdb_response::success;
			if (write(fd.get(), &resp_code, 1) != 1)
				return -1;
			return 0;
		} else if (buff_len > 532*1024) {
			/*
			 * Datagram production is in function
			 * exmdb_ext_push_db_notify2. 532 KB was chosen based
			 * on an excessive notification packet for 64K object
			 * subscriptions with 65536 proptag as payload.
			 */
			mlog(LV_ERR, "exmdb_client: notify packet size is Too Damn High (%u bytes)", buff_len);
			return -1;
		}
		try {
			buff.resize(buff_len);
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "exmdb_client: notify alloc "
				"failed (%u bytes)", buff_len);
			return -1;
		}
		offset = 0;
		return 0;
	}
	auto read_len = read(fd.get(), &buff.data()[offset], buff.size() - offset);
	if (read_len <= 0)
		return -1;
	offset += read_len;
	if (offset != buff.size())
		return 0;

	/* packet complete */
	BINARY bin;
	bin.cb = buff.size();
	bin.pc = buff.data();
	if (m_client->m_build_env != nullptr)
		m_client->m_build_env(m_ident.type == srv_type::xprivate);
	auto lo_client = m_client;
	auto cl_0 = HX::make_scope_exit([lo_client]() {
		if (lo_client->m_free_env != nullptr)
			lo_client->m_free_env();
	});
	DB_NOTIFY_DATAGRAM notify;
	auto resp_code = exmdb_ext_pull_db_notify(&bin, &notify) == pack_result::ok ?
	                 exmdb_response::success : exmdb_response::pull_error;
	if (write(fd.get(), &resp_code, 1) != 1)
		return -1;
	if (resp_code == exmdb_response::success)
		for (size_t i = 0; i < notify.id_array.size(); ++i)
			m_client->m_event_proc(notify.dir, notify.b_table,
				notify.id_array[i], &notify.db_notify);
	buff.clear();
	offset = 0;
	return 0;
}

void async_listener::connect_and_listen()
{
	auto fd = make_exmdb_connection(m_ident, "", true, m_client);
	if (fd.get() < 0) {
		sleep(1);
		return;
	}
	startup_wait = false;
	startup_cv.notify_one();
	struct pollfd pfd = {fd.get(), POLLIN | POLLPRI};
	size_t offset = 0;
	std::string buff;
	while (process_packet(fd, pfd, buff, offset) == 0)
		/* */;
}

void *async_listener::thread_entry(void *vargs)
{
	auto asl = static_cast<async_listener *>(vargs);
	while (!asl->m_stop && !asl->m_client->m_notify_stop)
		asl->connect_and_listen();
	return nullptr;
}

srv_conn::~srv_conn()
{
	auto ofd = m_fd.get();
	if (ofd < 0)
		return; /* nothing interesting to log */
	m_fd.close_rd(); /* Ditch the fd before changing m_active */
	auto h_new = m_locator->drop_active_count();
	mlog(LV_DEBUG, "exmdb_client: disconnected from [%s]:%hu (fd %d), hnew=%zu",
		m_ident.host.c_str(), m_ident.port, ofd, h_new);
}

srv_conn_ref::srv_conn_ref(wrapfd &&fd, std::shared_ptr<srv_entry> &srv,
    exmdb_client_impl::locator *locator) :
	m_pool(srv)
{
	m_hold.emplace_back(std::move(fd), locator, srv->ident);
}

void srv_conn_ref::putback()
{
	if (m_hold.empty())
		return;
	auto &conn = m_hold.front();
	if (conn.m_fd.get() < 0) {
		m_hold.clear();
		return;
	}
	auto srv = m_pool.lock();
	if (srv == nullptr) {
		m_hold.clear();
		return;
	}
	std::lock_guard conn_guard(srv->conn_lock);
	srv->conn_list.splice(srv->conn_list.end(), m_hold, m_hold.begin());
}

void srv_conn_ref::splice_one_from_back(std::list<srv_conn> &pool)
{
	m_hold.splice(m_hold.end(), pool, std::prev(pool.end()));
}

/**
 * Drops any one connection (preferably the oldest).
 * The caller is in charge of acquiring srv_entry.conn_lock
 * (because they generally want to do more operations in a chain).
 *
 * Returns a bool indicating whether some cleanup happened.
 */
bool srv_entry::drop_one_connection()
{
	if (conn_list.empty())
		return false;
	/* Pick an old one (in the front) */
	mlog(LV_DEBUG, "exmdb_client: kicking [%s]:%hu (fd %d) to make room",
		ident.host.c_str(), ident.port, conn_list.front().m_fd.get());
	conn_list.pop_front();
	return true;
}

/**
 * Returns an indicator whether this srv_entry has nothing in it and could be
 * removed from data structures it might be embedded in.
 *
 * The caller is in charge of acquiring srv_entry.conn_lock.
 */
bool srv_entry::purgable() const
{
	return conn_list.empty() && m_async == nullptr;
}

static bool sock_is_idle(int fd)
{
	struct pollfd pfd = {fd, POLLIN};
	/* No unexpected input (error/EOF) must be pending */
	return poll(&pfd, 1, 0) == 0;
}

srv_conn_ref srv_entry::extract_one_connection()
{
	srv_conn_ref fc;
	std::lock_guard hold(conn_lock);
	while (conn_list.size() > 0) {
		/* Try reusing the most recent one (in the back) */
		/* Server may have closed the connection due to our idling, though. */
		if (sock_is_idle(conn_list.back().m_fd.get())) {
			fc.splice_one_from_back(conn_list);
			break;
		}
		conn_list.pop_back();
	}
	return fc;
}

/**
 * Launch an async notification listening thread for this srv_entry,
 * provided notifications are not globally disabled.
 *
 * conn_lock is acquired internally for the check+emplace of m_async,
 * but released before the potentially blocking launch() call.
 */
void srv_entry::launch_notify_listener(exmdb_client_remote *bp_client) try
{
	if (bp_client->m_event_proc == nullptr)
		return;

	std::shared_ptr<async_listener> asl;
	{
		std::lock_guard hold(conn_lock);
		if (m_async != nullptr)
			return;
		asl = m_async = std::make_shared<async_listener>(ident, bp_client);
	}
	if (asl->launch() != 0) {
		std::lock_guard hold(conn_lock);
		m_async.reset();
	}
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
}

/**
 * Erase dir_to_srv entries that have not been used for a while. The caller
 * must hold dts_lock. Throttled so it does not run too often.
 */
void locator::cleanup_dts()
{
	auto now = tp_now();
	if (now - m_last_dts_purge < dts_purge_time)
		return;
	m_last_dts_purge = now;
	std::erase_if(dir_to_srv, [now](const decltype(dir_to_srv)::value_type &entry) {
		return now - entry.second.second >= dts_purge_time;
	});
}

/**
 * Erase name_to_srv entries with no pooled connections and no async listener.
 * The caller must hold nts_lock. Throttled.
 */
void locator::cleanup_nts()
{
	auto now = tp_now();
	if (now - m_last_nts_purge < dts_purge_time)
		return;
	m_last_nts_purge = now;
	std::erase_if(name_to_srv, [now](const decltype(name_to_srv)::value_type &entry) {
		bool purgable;
		{
			std::lock_guard hold2(entry.second->conn_lock);
			purgable = entry.second->purgable();
		}
		return purgable;
	});
}

srv_ident locator::try_emplace_dir(const char *dir)
{
	auto now = tp_now();
	srv_ident srv;
	do {
		std::lock_guard hold(dts_lock);
		auto iter = dir_to_srv.find(dir);
		if (iter == dir_to_srv.end() ||
		    iter->second.first.type == srv_type::undef)
			break;
		srv = iter->second.first;
		if (now - iter->second.second < dts_refresh_time)
			return srv;
	} while (false);

	srv.port = 5000; /* XXX: hardcoded port number */
	bool is_pvt = false;
	auto err = mysql_adaptor_get_homeserver_for_dir(dir, &is_pvt, srv.host);
	if (err != 0) {
		mlog(LV_ERR, "exmdb_client: cannot find homeserver for %s", dir);
		return {};
	}
	if (srv.host.empty())
		srv.host = "localhost";
	srv.type = is_pvt ? srv_type::xprivate : srv_type::xpublic;

	now = tp_now();
	std::lock_guard hold(dts_lock);
	cleanup_dts();
	auto [dts_iter, added] = dir_to_srv.try_emplace(dir, srv, now);
	if (added)
		return srv;
	/* Update an existing DTS entry if we are the one with newer info */
	if (now > dts_iter->second.second)
		dts_iter->second = {srv, now};
	else
		srv = dts_iter->second.first;
	return srv;
}

std::shared_ptr<srv_entry> locator::try_emplace_server(const srv_ident &ident)
{
	std::lock_guard hold(nts_lock);
	auto it = name_to_srv.find(ident);
	if (it != name_to_srv.end())
		return it->second;
	cleanup_nts();
	auto [iter, added] = name_to_srv.emplace(ident, std::make_shared<srv_entry>(ident));
	return iter->second;
}

size_t locator::drop_active_count()
{
	while (true) {
		auto h_old = m_active.load();
		if (h_old == 0)
			return 0;
		auto h_new = h_old - 1;
		if (m_active.compare_exchange_weak(h_old, h_new))
			return h_new;
	}
}

/**
 * @dk:	the srv_entry for which we want to make a connection (dontkill)
 *
 * Evaluate whether the connection limits have been reached, and if so,
 * remove one connection (ideally the oldest one, but that is not guaranteed).
 *
 * The caller should have taken maker_lock before calling this function, to
 * guarantee that no other thread snatches a connection while this thread tries
 * to make room.
 *
 * Returns true if there is room / room has been made for a new connection.
 */
bool locator::clean_some_connection(const srv_ident &dk)
{
	if (m_active < m_maxconn)
		return true;

	std::lock_guard hold(nts_lock);
	for (auto iter = name_to_srv.begin(); iter != name_to_srv.end(); ) {
		if (iter->first == dk) {
			++iter;
			continue;
		}
		auto &srv = *iter->second;
		bool dropped, purgable;
		{
			std::lock_guard hold2(srv.conn_lock);
			dropped  = srv.drop_one_connection();
			purgable = srv.purgable();
			// (obviously need to release conn_lock before killing off srv)
		}
		if (dropped) {
			if (purgable)
				name_to_srv.erase(iter);
			return true;
		}
		/*
		 * Keep on clearing name_to_srv entries (only) for as long as
		 * no reusable fd was found.
		 */
		if (purgable)
			iter = name_to_srv.erase(iter);
		else
			++iter;
	}
	return false; /* found no connection for teardown */
}

/**
 * Get a connection file descriptor for the given homedir.
 * If necessary, vivify a srv_entry entry and/or sockets.
 *
 * This function always produces a socket: If you want to do LPC call
 * exmdb_client_is_local instead (and if LPC is available, don't use
 * get_connection).
 */
srv_conn_ref locator::get_connection(const char *dir) try
{
	auto ident = try_emplace_dir(dir);
	if (ident.type == srv_type::undef)
		return {};
	auto srv = try_emplace_server(ident);
	if (srv == nullptr)
		return {};
	auto cref = srv->extract_one_connection();
	if (cref != nullptr) {
		cref.m_pool = srv;
		return cref;
	}
	/*
	 * Larger-scoped lock so no other thread builds connections
	 * while we are trying to, as that could increase m_active
	 * beyond its limit.
	 */
	std::lock_guard maker_hold(maker_lock);
	if (!clean_some_connection(ident)) {
		mlog(LV_ERR, "exmdb_client: reached global maximum connections (max:%zu)", m_maxconn);
		return {};
	}

	cref = srv_conn_ref{make_exmdb_connection(ident, dir, false, m_client), srv, this};
	if (cref->m_fd.get() == -2) {
		return {};
	} else if (cref->m_fd.get() < 0) {
		mlog(LV_ERR, "exmdb_client: protocol error connecting to [%s]:%hu/%s",
		        ident.host.c_str(), ident.port, dir);
		return {};
	}
	auto h_new = bump_active_count();
	mlog(LV_DEBUG, "exmdb_client: connected to [%s]:%hu (fd %d), hnew=%zu",
		ident.host.c_str(), ident.port, cref->m_fd.get(), h_new);

	srv->launch_notify_listener(m_client);
	return cref;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return {};
}

exmdb_client_remote::exmdb_client_remote(unsigned int conn_max)
{
	auto cfg = config_file_initd("gromox.cfg", PKGSYSCONFDIR, exmdb_client_dflt);
	if (cfg == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd gromox.cfg: %s",
			strerror(errno));
	} else {
		m_rpc_timeout = cfg->get_ll("exmdb_client_rpc_timeout");
		if (m_rpc_timeout <= 0)
			m_rpc_timeout = -1;
		if (m_rpc_timeout > 0)
			m_rpc_timeout *= 1000;
	}
	setup_signal_defaults();
	char txt[GUIDSTR_SIZE];
	GUID::machine_id().to_str(txt, std::size(txt), 32);
	m_client_id = std::to_string(getpid()) + txt;
	m_notify_stop = true;
	m_locator = std::make_unique<exmdb_client_impl::locator>(conn_max, this);
}

exmdb_client_remote::~exmdb_client_remote()
{
	/*
	 * Careful: When `exmdb_client.reset()` is called, the std::optional
	 * may be marked disengaged before ~exmdb_client_remote and inner
	 * destructors like ~locator are run. Thus, access from member
	 * functions of exmdb_client_remote or other subordinate classes should
	 * only ever be done with "m_client"-style backpointers.
	 */
	m_notify_stop = true;
}

namespace gromox {

int exmdb_client_run(const char *cfgdir, unsigned int flags,
    void (*build_env)(bool), void (*free_env)())
{
	if (service_run_library({"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}) != PLUGIN_LOAD_OK)
		return -1;
	exmdb_client->m_build_env = build_env;
	exmdb_client->m_free_env = free_env;
	exmdb_client->m_notify_stop = false;
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
	if (!exmdb_client->m_allow_lpc)
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

BOOL exmdb_client_do_rpc(const exreq *rq, exresp *rsp)
{
	BINARY bin;

	if (exmdb_ext_push_request(rq, &bin) != pack_result::ok)
		return false;
	auto cref = exmdb_client->locator()->get_connection(rq->dir);
	if (cref == nullptr || !exmdb_client_write_socket(cref->m_fd.get(),
	    bin, SOCKET_TIMEOUT * 1000)) {
		free(bin.pb);
		return false;
	}
	free(bin.pb);
	bin.pb = nullptr;
	if (!exmdb_client_read_socket(cref->m_fd.get(), bin, exmdb_client->m_rpc_timeout))
		return false;
	if (bin.pb == nullptr)
		return false;
	if (bin.cb == 1) {
		exmdb_rpc_free(bin.pb);
		/* Connection is still good in principle. */
		cref.putback();
		return false;
	}
	if (bin.cb < 5) {
		exmdb_rpc_free(bin.pb);
		/*
		 * Malformed packet. Let connection die (~srv_conn_ref), as
		 * there may be bytes in the socket buffer that could be picked
		 * up as garbage if we issue another RPC.
		 */
		return false;
	}
	cref.putback();
	rsp->call_id = rq->call_id;
	bin.cb -= 5;
	bin.pb += 5;
	auto ret = exmdb_ext_pull_response(&bin, rsp);
	bin.pb -= 5;
	exmdb_rpc_free(bin.pb);
	return ret == pack_result::ok ? TRUE : false;
}

} /* namespace gromox */
