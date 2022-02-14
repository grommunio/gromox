// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <csignal>
#include <cstdio>
#include <cstring>
#include <list>
#include <mutex>
#include <vector>
#include <pthread.h>
#include <unistd.h>
#include <gromox/atomic.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/list_file.hpp>
#include <gromox/socket.h>

namespace gromox {

std::vector<EXMDB_ITEM> mdcl_local_list;
std::list<agent_thread> mdcl_agent_list;
std::list<remote_conn> mdcl_lost_list;
std::list<remote_svr> mdcl_server_list;
std::mutex mdcl_server_lock;
atomic_bool mdcl_notify_stop;
unsigned int mdcl_conn_num, mdcl_threads_num;
pthread_t mdcl_scan_id;

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
	if (!lost) {
		std::lock_guard sv_hold(mdcl_server_lock);
		pconn->psvr->conn_list.splice(pconn->psvr->conn_list.end(), tmplist, tmplist.begin());
	} else {
		close(pconn->sockd);
		pconn->sockd = -1;
		std::lock_guard sv_hold(mdcl_server_lock);
		mdcl_lost_list.splice(mdcl_lost_list.end(), tmplist, tmplist.begin());
	}
	tmplist.clear();
}

void exmdb_client_init(unsigned int conn_num, unsigned int threads_num)
{
	mdcl_notify_stop = true;
	mdcl_conn_num = conn_num;
	mdcl_threads_num = threads_num;
}

void exmdb_client_stop()
{
	if (mdcl_conn_num != 0 && !mdcl_notify_stop) {
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
}

int exmdb_client_run(const char *cfgdir, unsigned int flags,
    void *(*timeout_check)(void *), void *(*notif_reader)(void *))
{
	std::vector<EXMDB_ITEM> xmlist;
	size_t i = 0;

	auto ret = list_file_read_exmdb("exmdb_list.txt", cfgdir, xmlist);
	if (ret < 0) {
		printf("exmdb_client: list_file_read_exmdb: %s\n", strerror(-ret));
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
		if (flags & EXMDB_CLIENT_ALLOW_DIRECT) try {
			/* mostly used by exmdb_provider */
			mdcl_local_list.push_back(std::move(item));
			continue;
		} catch (const std::bad_alloc &) {
			printf("exmdb_client: Failed to allocate memory\n");
			mdcl_notify_stop = true;
			return 3;
		}
		if (mdcl_conn_num == 0) {
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
		auto &srv = mdcl_server_list.back();
		for (unsigned int j = 0; j < mdcl_conn_num; ++j) {
			remote_conn conn;
			conn.sockd = -1;
			conn.psvr = &srv;
			try {
				mdcl_lost_list.push_back(std::move(conn));
			} catch (const std::bad_alloc &) {
				printf("exmdb_client: fail to "
					"allocate memory for exmdb\n");
				mdcl_notify_stop = true;
				return 6;
			}
		}
		for (unsigned int j = 0; notif_reader != nullptr && j < mdcl_threads_num; ++j) {
			try {
				mdcl_agent_list.push_back(agent_thread{});
			} catch (const std::bad_alloc &) {
				printf("exmdb_client: fail to "
					"allocate memory for exmdb\n");
				mdcl_notify_stop = true;
				return 7;
			}
			auto &ag = mdcl_agent_list.back();
			ag.pserver = &srv;
			ag.sockd = -1;
			ret = pthread_create(&ag.thr_id, nullptr, notif_reader, &ag);
			if (ret != 0) {
				printf("exmdb_client: E-1449: pthread_create: %s\n", strerror(ret));
				mdcl_notify_stop = true;
				mdcl_agent_list.pop_back();
				return 8;
			}
			char buf[32];
			snprintf(buf, sizeof(buf), "mdclntfy/%zu-%u", i, j);
			pthread_setname_np(ag.thr_id, buf);
		}
		++i;
	}
	if (mdcl_conn_num == 0)
		return 0;
	ret = pthread_create(&mdcl_scan_id, nullptr, timeout_check, nullptr);
	if (ret != 0) {
		printf("exmdb_client: failed to create proxy scan thread: %s\n", strerror(ret));
		mdcl_notify_stop = true;
		return 9;
	}
	pthread_setname_np(mdcl_scan_id, "exmdbcl/scan");
	return 0;
}

}
