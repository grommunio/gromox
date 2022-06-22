// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <list>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <vector>
#include <gromox/atomic.hpp>
#include <gromox/endian.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/util.hpp>

namespace gromox {

static constexpr unsigned int mdcl_socket_timeout = 60;
static std::list<agent_thread> mdcl_agent_list;
static std::list<remote_svr> mdcl_server_list;
static std::mutex mdcl_server_lock;
static atomic_bool mdcl_notify_stop;
static unsigned int mdcl_conn_max, mdcl_threads_max;
static pthread_t mdcl_scan_id;
static void (*mdcl_build_env)(const remote_svr &);
static void (*mdcl_free_env)();
static void (*mdcl_event_proc)(const char *, BOOL, uint32_t, const DB_NOTIFY *);
static char mdcl_remote_id[128];

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
	if (pconn->sockd < 0) {
		tmplist.clear();
	} else if (!lost) {
		std::lock_guard sv_hold(mdcl_server_lock);
		pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), tmplist, tmplist.begin());
	} else {
		close(pconn->sockd);
		--pconn->psvr->active_handles;
		tmplist.clear();
	}
}

void exmdb_client_init(unsigned int conn_max, unsigned int notify_threads_max)
{
	setup_sigalrm();
	mdcl_notify_stop = true;
	mdcl_conn_max = conn_max;
	mdcl_threads_max = notify_threads_max;
	snprintf(mdcl_remote_id, arsizeof(mdcl_remote_id), "%u.", static_cast<unsigned int>(getpid()));
	auto z = strlen(mdcl_remote_id);
	GUID::machine_id().to_str(mdcl_remote_id + z, arsizeof(mdcl_remote_id) - z, 32);
}

void exmdb_client_stop()
{
	if (mdcl_conn_max != 0 && !mdcl_notify_stop) {
		mdcl_notify_stop = true;
		if (!pthread_equal(mdcl_scan_id, {})) {
			pthread_kill(mdcl_scan_id, SIGALRM);
			pthread_join(mdcl_scan_id, nullptr);
		}
	}
	mdcl_notify_stop = true;
	for (auto &ag : mdcl_agent_list) {
		pthread_kill(ag.thr_id, SIGALRM);
		pthread_join(ag.thr_id, nullptr);
		if (ag.sockd >= 0)
			close(ag.sockd);
	}
	for (auto &srv : mdcl_server_list)
		for (auto &conn : srv.conn_list)
			close(conn.sockd);
	mdcl_build_env = nullptr;
	mdcl_free_env = nullptr;
	mdcl_event_proc = nullptr;
}

static int exmdb_client_connect_exmdb(remote_svr &srv, bool b_listen,
    const char *prog_id)
{
	int sockd = gx_inet_connect(srv.host.c_str(), srv.port, 0);
	if (sockd < 0) {
		static std::atomic<time_t> mdcl_lastwarn_time;
		auto prev = mdcl_lastwarn_time.load();
		auto next = prev + 60;
		auto now = time(nullptr);
		if (next <= now && mdcl_lastwarn_time.compare_exchange_strong(prev, now))
			fprintf(stderr, "exmdb_client: gx_inet_connect to [%s]:%hu: %s\n",
			        srv.host.c_str(), srv.port, strerror(-sockd));
	        return -2;
	}
	auto cl_sock = make_scope_exit([&]() { close(sockd); });
	EXMDB_REQUEST rq;
	if (!b_listen) {
		rq.call_id = exmdb_callid::connect;
		rq.payload.connect.prefix = deconst(srv.prefix.c_str());
		rq.payload.connect.remote_id = mdcl_remote_id;
		rq.payload.connect.b_private = srv.type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false;
	} else {
		rq.call_id = exmdb_callid::listen_notification;
		rq.payload.listen_notification.remote_id = mdcl_remote_id;
	}
	BINARY bin;
	if (exmdb_ext_push_request(&rq, &bin) != EXT_ERR_SUCCESS)
		return -1;
	if (!exmdb_client_write_socket(sockd, bin, mdcl_socket_timeout * 1000)) {
		free(bin.pb);
		return -1;
	}
	free(bin.pb);
	if (mdcl_build_env != nullptr)
		mdcl_build_env(srv);
	auto cl_0 = make_scope_exit([]() { if (mdcl_free_env != nullptr) mdcl_free_env(); });
	if (!exmdb_client_read_socket(sockd, bin, mdcl_socket_timeout * 1000))
		return -1;
	auto response_code = static_cast<exmdb_response>(bin.pb[0]);
	exmdb_rpc_free(bin.pb);
	if (response_code != exmdb_response::success) {
		printf("exmdb_client: Failed to connect to [%s]:%hu/%s: %s\n",
		       srv.host.c_str(), srv.port, srv.prefix.c_str(),
		       exmdb_rpc_strerror(response_code));
		return -1;
	} else if (bin.cb != 5) {
		printf("[exmdb_client]: response format error "
		       "during connect to [%s]:%hu/%s\n",
		       srv.host.c_str(), srv.port, srv.prefix.c_str());
		return -1;
	}
	cl_sock.release();
	return sockd;
}

static void cl_pinger2()
{
	time_t now_time = time(nullptr);
	std::list<REMOTE_CONN> temp_list;
	std::unique_lock sv_hold(mdcl_server_lock);

	/* Extract nodes to ping */
	for (auto &srv : mdcl_server_list) {
		auto tail = srv.conn_list.size() > 0 ? &srv.conn_list.back() : nullptr;
		while (srv.conn_list.size() > 0) {
			auto conn = &srv.conn_list.front();
			if (now_time - conn->last_time >= mdcl_socket_timeout - 3)
				temp_list.splice(temp_list.end(), srv.conn_list, srv.conn_list.begin());
			else
				srv.conn_list.splice(srv.conn_list.end(), srv.conn_list, srv.conn_list.begin());
			if (conn == tail)
				break;
		}
	}
	sv_hold.unlock();

	/* Ping and reinsert (or discard) */
	while (temp_list.size() > 0) {
		auto conn = &temp_list.front();
		if (mdcl_notify_stop) {
			close(conn->sockd);
			--conn->psvr->active_handles;
			temp_list.pop_front();
			continue;
		}
		auto ping_buff = cpu_to_le32(0);
		if (write(conn->sockd, &ping_buff, sizeof(uint32_t)) != sizeof(uint32_t)) {
			close(conn->sockd);
			--conn->psvr->active_handles;
			temp_list.pop_front();
			continue;
		}
		struct pollfd pfd_read{conn->sockd, POLLIN | POLLPRI};
		auto resp_buff = exmdb_response::invalid;
		if (poll(&pfd_read, 1, mdcl_socket_timeout * 1000) != 1 ||
		    read(conn->sockd, &resp_buff, 1) != 1 ||
		    resp_buff != exmdb_response::success) {
			close(conn->sockd);
			--conn->psvr->active_handles;
			temp_list.pop_front();
		} else {
			time(&conn->last_time);
			sv_hold.lock();
			conn->psvr->conn_list.splice(conn->psvr->conn_list.end(), temp_list, temp_list.begin());
			sv_hold.unlock();
		}
	}
}

static void *cl_pinger(void *)
{
	while (!mdcl_notify_stop) {
		cl_pinger2();
		sleep(1);
	}
	return nullptr;
}

static int cl_notif_reader3(agent_thread &agent, pollfd &pfd,
    uint8_t (&buff)[0x8000], uint32_t &buff_len, uint32_t &offset)
{
	if (poll(&pfd, 1, mdcl_socket_timeout * 1000) != 1)
		return -1;
	if (buff_len == 0) {
		if (read(agent.sockd, &buff_len, sizeof(uint32_t)) != sizeof(uint32_t))
			return -1;
		/* ping packet */
		if (buff_len == 0) {
			auto resp_code = exmdb_response::success;
			if (write(agent.sockd, &resp_code, 1) != 1)
				return -1;
		}
		offset = 0;
		return 0;
	}
	auto read_len = read(agent.sockd, buff + offset, buff_len - offset);
	if (read_len <= 0)
		return -1;
	offset += read_len;
	if (offset != buff_len)
		return 0;

	/* packet complete */
	BINARY bin;
	bin.cb = buff_len;
	bin.pb = buff;
	mdcl_build_env(*agent.pserver);
	auto cl_0 = make_scope_exit([]() { if (mdcl_free_env != nullptr) mdcl_free_env(); });
	DB_NOTIFY_DATAGRAM notify;
	auto resp_code = exmdb_ext_pull_db_notify(&bin, &notify) == EXT_ERR_SUCCESS ?
	                 exmdb_response::success : exmdb_response::pull_error;
	if (write(agent.sockd, &resp_code, 1) != 1)
		return -1;
	if (resp_code == exmdb_response::success)
		for (size_t i = 0; i < notify.id_array.count; ++i)
			mdcl_event_proc(notify.dir, notify.b_table,
				notify.id_array.pl[i], &notify.db_notify);
	buff_len = 0;
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
	uint32_t buff_len = 0, offset = 0;
	uint8_t buff[0x8000];
	while (cl_notif_reader3(agent, pfd, buff, buff_len, offset) == 0)
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
	if (mdcl_event_proc == nullptr)
		return 0;
	mdcl_agent_list.emplace_back();
	auto &ag = mdcl_agent_list.back();
	ag.pserver = &srv;
	ag.sockd = -1;
	ag.startup_wait = true;
	auto ret = pthread_create(&ag.thr_id, nullptr, cl_notif_reader, &ag);
	if (ret != 0) {
		printf("exmdb_client: E-1449: pthread_create: %s\n", strerror(ret));
		mdcl_agent_list.pop_back();
		return 8;
	}
	auto thrtxt = std::string("mcn") + mdcl_remote_id;
	ret = pthread_setname_np(ag.thr_id, thrtxt.c_str());
#ifdef __GLIBC__
	/* prctl truncates the name. Why can't you do the same, glibc? */
	if (ret != 0) {
		thrtxt.resize(15);
		ret = pthread_setname_np(ag.thr_id, thrtxt.c_str());
	}
#endif
	if (ret != 0)
		fprintf(stderr, "pthread_setname_np: %s\n", strerror(ret));
	/*
	 * Wait for the notify thread to be up before allowing
	 * current thread to send any commands.
	 */
	while (ag.startup_wait) {
		std::mutex mtx;
		std::unique_lock lk(mtx);
		ag.startup_cv.wait(lk);
	}
	return 0;
} catch (const std::bad_alloc &) {
	printf("exmdb_client: failed to allocate memory for exmdb\n");
	return 7;
}

int exmdb_client_run(const char *cfgdir, unsigned int flags,
    void (*build_env)(const remote_svr &), void (*free_env)(),
    void (*event_proc)(const char *, BOOL, uint32_t, const DB_NOTIFY *))
{
	mdcl_build_env = build_env;
	mdcl_free_env = free_env;
	mdcl_event_proc = event_proc;
	std::vector<EXMDB_ITEM> xmlist;

	auto err = list_file_read_exmdb("exmdb_list.txt", cfgdir, xmlist);
	if (err != 0) {
		printf("exmdb_client: list_file_read_exmdb: %s\n", strerror(err));
		return 1;
	}
	mdcl_notify_stop = false;
	for (auto &&item : xmlist) {
		if (flags & EXMDB_CLIENT_SKIP_PUBLIC &&
		    item.type != EXMDB_ITEM::EXMDB_PRIVATE)
			continue; /* mostly used by midb */
		auto local = gx_peer_is_local(item.host.c_str());
		if (flags & EXMDB_CLIENT_SKIP_REMOTE && !local)
			continue; /* mostly used by midb */
		item.local = (flags & EXMDB_CLIENT_ALLOW_DIRECT) ? local : false;
		if (item.local) try {
			/* mostly used by exmdb_provider */
			mdcl_server_list.emplace_back(std::move(item));
			continue; /* do not start notify agent for locals */
		} catch (const std::bad_alloc &) {
			printf("exmdb_client: Failed to allocate memory\n");
			mdcl_notify_stop = true;
			return 3;
		}
		if (mdcl_conn_max == 0) {
			printf("exmdb_client: there's remote store media "
				"in exmdb list, but rpc proxy connection number is 0\n");
			mdcl_notify_stop = true;
			return 4;
		}

		try {
			mdcl_server_list.emplace_back(std::move(item));
		} catch (const std::bad_alloc &) {
			printf("exmdb_client: Failed to allocate memory for exmdb\n");
			mdcl_notify_stop = true;
			return 5;
		}
	}
	if (mdcl_conn_max == 0)
		return 0;
	if (!(flags & EXMDB_CLIENT_ASYNC_CONNECT))
		cl_pinger2();
	auto ret = pthread_create(&mdcl_scan_id, nullptr, cl_pinger, nullptr);
	if (ret != 0) {
		printf("exmdb_client: failed to create proxy scan thread: %s\n", strerror(ret));
		mdcl_notify_stop = true;
		return 9;
	}
	pthread_setname_np(mdcl_scan_id, "exmdbcl/scan");
	return 0;
}

bool exmdb_client_check_local(const char *prefix, BOOL *pvt)
{
	auto i = std::find_if(mdcl_server_list.cbegin(), mdcl_server_list.cend(),
	         [&](const EXMDB_ITEM &s) {
	         	return s.local && strncmp(s.prefix.c_str(),
	         	       prefix, s.prefix.size()) == 0;
	         });
	if (i == mdcl_server_list.cend())
		return false;
	*pvt = i->type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false;
	return true;
}

remote_conn_ref exmdb_client_get_connection(const char *dir)
{
	remote_conn_ref fc;
	std::lock_guard sv_hold(mdcl_server_lock);
	auto i = std::find_if(mdcl_server_list.begin(), mdcl_server_list.end(),
	         [&](const remote_svr &s) { return strncmp(dir, s.prefix.c_str(), s.prefix.size()) == 0; });
	if (i == mdcl_server_list.end()) {
		printf("exmdb_client: cannot find remote server for %s\n", dir);
		return fc;
	}
	if (i->conn_list.size() > 0) {
		fc.tmplist.splice(fc.tmplist.end(), i->conn_list, i->conn_list.begin());
		return fc;
	}
	if (i->active_handles >= mdcl_conn_max) {
		fprintf(stderr, "exmdb_client: reached maximum connections (%u) to [%s]:%hu/%s\n",
		        mdcl_conn_max, i->host.c_str(), i->port, i->prefix.c_str());
		return fc;
	}
	fc.tmplist.emplace_back(remote_conn{&*i});
	auto &conn = fc.tmplist.back();
	conn.sockd = exmdb_client_connect_exmdb(*i, false, "mdcl");
	if (conn.sockd == -2) {
		fc.tmplist.clear();
		return fc;
	} else if (conn.sockd < 0) {
		fc.tmplist.clear();
		fprintf(stderr, "exmdb_client: protocol error connecting to [%s]:%hu/%s failed\n",
		        i->host.c_str(), i->port, i->prefix.c_str());
		return fc;
	}
	++i->active_handles;
	if (mdcl_agent_list.size() < mdcl_threads_max)
		launch_notify_listener(*i);
	return fc;
}

BOOL exmdb_client_do_rpc(EXMDB_REQUEST &&rq, EXMDB_RESPONSE *rsp)
{
	BINARY bin;

	if (exmdb_ext_push_request(&rq, &bin) != EXT_ERR_SUCCESS)
		return false;
	auto conn = exmdb_client_get_connection(rq.dir);
	if (conn == nullptr || !exmdb_client_write_socket(conn->sockd,
	    bin, mdcl_socket_timeout * 1000)) {
		free(bin.pb);
		return false;
	}
	free(bin.pb);
	if (!exmdb_client_read_socket(conn->sockd, bin, mdcl_socket_timeout * 1000))
		return false;
	time(&conn->last_time);
	conn.reset();
	if (bin.cb < 5 || static_cast<exmdb_response>(bin.pb[0]) != exmdb_response::success) {
		exmdb_rpc_free(bin.pb);
		return false;
	}
	rsp->call_id = rq.call_id;
	bin.cb -= 5;
	bin.pb += 5;
	auto ret = exmdb_ext_pull_response(&bin, rsp);
	bin.pb -= 5;
	exmdb_rpc_free(bin.pb);
	return ret == EXT_ERR_SUCCESS ? TRUE : false;
}

}

#ifdef TEST1
int main(int argc, const char **argv)
{
	setup_sigalrm();
	exmdb_client_init(2, 0);
	auto cl_0 = make_scope_exit(exmdb_client_stop);
	auto ret = exmdb_client_run(PKGSYSCONFDIR);
	if (ret != 0)
		return EXIT_FAILURE;
	auto dir = argc >= 2 ? argv[1] : "/var/lib/gromox/user/test@";
	{
		auto fc1 = exmdb_client_get_connection(dir);
		assert(fc1 != nullptr);
		printf("C#1a: fd %d\n", fc1->sockd);
		//sleep(1);
		{
			auto fc2 = exmdb_client_get_connection(dir);
			assert(fc2 != nullptr);
			printf("C#2a: fd %d\n", fc2->sockd);
			auto fc3 = exmdb_client_get_connection(dir);
			printf("C#3: fd %d\n", fc3 != nullptr ? fc3->sockd : -1);
		}
		auto fc2 = exmdb_client_get_connection(dir);
		assert(fc2 != nullptr);
		printf("C#2b: fd %d\n", fc2->sockd);
		fc2.reset();
		sleep(64);
		// fc1 should now be dead (server-side timeout of 60)
		// give it back into the hands of cl_pinger2
		fc1.reset();
		sleep(2);
		auto fc3 = exmdb_client_get_connection(dir);
		assert(fc3 != nullptr);
		printf("C#3: fd %d\n", fc3->sockd);
		auto fc4 = exmdb_client_get_connection(dir);
		assert(fc4 != nullptr);
		printf("C#4: fd %d\n", fc4->sockd);
	}
	return EXIT_SUCCESS;
}
#endif
#ifdef TEST2
int main()
{
	exmdb_client_init(2, 0);
	exmdb_client_run(PKGSYSCONFDIR);
	{
		auto fc = exmdb_client_get_connection("/var/lib/gromox/user/test@grammm.com");
		printf("%s\n", fc != nullptr ? "OK" : "FAIL");
		printf("fd %d\n", fc != nullptr ? fc->sockd : -1);
		fc.reset();
	}
	sleep(64);
	printf("check state\n");
	sleep(9000);
}
#endif
