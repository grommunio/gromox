// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <gromox/config_file.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;
static std::map<std::string, size_t> g_cont_tbl;
static std::mutex g_cont_lock;
static unsigned int g_max_num;

static BOOL ip6co_add(const char *addr)
{
	if (addr == nullptr)
		return false;
	try {
		std::lock_guard guard(g_cont_lock);
		auto p = g_cont_tbl.emplace(addr, 1);
		if (p.second)
			return TRUE;
		if (p.first->second >= g_max_num)
			return false;
		++p.first->second;
		return TRUE;
	} catch (...) {
	}
	return false;
}

static BOOL ip6co_remove(const char *addr)
{
	if (addr == nullptr)
		return false;
	std::lock_guard guard(g_cont_lock);
	auto i = g_cont_tbl.find(addr);
	if (i == g_cont_tbl.cend())
		return true;
	if (i->second <= 1)
		g_cont_tbl.erase(i);
	else
		--i->second;
	return TRUE;
}

static BOOL svc_ip6_container(int reason, void **data)
{
	if (reason == PLUGIN_FREE) {
		g_cont_tbl.clear();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(data);
	std::string filename;
	try {
		filename = get_plugin_name();
		auto pos = filename.find('.');
		if (pos != filename.npos)
			filename.erase(pos);
		filename += ".cfg";
	} catch (...) {
		return false;
	}
	auto pfile = config_file_initd(filename.c_str(), get_config_path(), nullptr);
	if (pfile == nullptr) {
		mlog(LV_ERR, "ip6_container: config_file_initd %s: %s",
		       filename.c_str(), strerror(errno));
		return false;
	}
	auto strv = pfile->get_value("CONNECTION_MAX_NUM");
	g_max_num = strv != nullptr ? strtoul(strv, nullptr, 0) : 200;
	mlog(LV_NOTICE, "ip6_container: maximum number of connections per client is %u", g_max_num);

	if (!register_service("ip_container_add", ip6co_add) ||
	    !register_service("ip_container_remove", ip6co_remove)) {
		mlog(LV_ERR, "ip6_container: can't register services (symbol clash?)");
		return false;
	}
	return TRUE;
}
SVC_ENTRY(svc_ip6_container);
