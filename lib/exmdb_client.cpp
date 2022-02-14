// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <list>
#include <mutex>
#include <gromox/exmdb_client.hpp>

namespace gromox {

std::list<agent_thread> mdcl_agent_list;
std::list<remote_conn> mdcl_lost_list;
std::list<remote_svr> mdcl_server_list;
std::mutex mdcl_server_lock;

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

}
