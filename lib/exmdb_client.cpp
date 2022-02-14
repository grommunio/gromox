// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <csignal>
#include <list>
#include <mutex>
#include <pthread.h>
#include <unistd.h>
#include <gromox/atomic.hpp>
#include <gromox/exmdb_client.hpp>

namespace gromox {

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

}
