// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#define DECLARE_SVC_API_STATIC
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <libHX/string.h>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;
using duration = decltype(time_point() - time_point());

namespace {
struct IP_AUDIT {
	time_point first, last;
	size_t times;
};
}

static std::map<std::string, time_point> g_templist;
static std::map<std::string, IP_AUDIT> g_auditlist;
static std::mutex g_templist_lock, g_auditlist_lock;
static size_t g_templist_maxsize;
static duration g_audit_intvl;
static unsigned int g_max_within_interval, g_audit_max;

static size_t ip6tl_collect(time_point limit)
{
#if __cplusplus >= 202000L
	return std::erase_if(g_templist, [&](auto &&e) { return e.second > limit; });
#else
	size_t coll = 0;
	for (auto i = g_templist.begin(); i != g_templist.end(); ) {
		auto aff = i->second > limit;
		if (aff) {
			++coll;
			i = g_templist.erase(i);
		} else {
			++i;
		}
	}
	return coll;
#endif
}

static size_t ip6au_collect(time_point limit)
{
#if __cplusplus >= 202000L
	return std::erase_if(g_auditlist, [&](auto &&e) { return limit - e.second.last >= g_audit_intvl; });
#else
	size_t coll = 0;
	for (auto i = g_auditlist.begin(); i != g_auditlist.end(); ) {
		auto &au = i->second;
		if (limit - au.last >= g_audit_intvl) {
			i = g_auditlist.erase(i);
			++coll;
		} else {
			++i;
		}
	}
	return coll;
#endif
}

static BOOL ip6flt_add(const char *addr, int fwd)
{
	if (addr == nullptr)
		return false;
	auto tpoint = tp_now() + std::chrono::seconds(fwd);
	try {
		std::lock_guard guard(g_templist_lock);
		if (g_templist.size() >= g_templist_maxsize)
			return false;
		if (g_templist.emplace(addr, tpoint).second)
			return TRUE;
		if (ip6tl_collect(tpoint) == 0)
			return false;
		return g_templist.emplace(addr, tpoint).second ? TRUE : false;
	} catch (...) {
	}
	return false;
}

static bool ip6tl_query(const char *addr)
{
	std::lock_guard guard(g_templist_lock);
	auto i = g_templist.find(addr);
	if (i == g_templist.end())
		return false;
	if (tp_now() <= i->second)
		return true;
	g_templist.erase(i);
	return false;
}

static BOOL ip6flt_judge(const char *addr)
{
	if (addr == nullptr)
		return false;
	if (ip6tl_query(addr))
		return TRUE;
	std::lock_guard guard(g_auditlist_lock);
	auto current = tp_now();
	auto i = g_auditlist.find(addr);
	if (i == g_auditlist.end()) {
		IP_AUDIT au{current, current, 1};
		if (g_auditlist.try_emplace(addr, std::move(au)).second)
			return TRUE;
		if (ip6au_collect(current) == 0) {
			mlog(LV_DEBUG, "ip_filter: still cannot find one unit for auditing, giving up");
			return TRUE;
		}
		g_auditlist.emplace(addr, std::move(au));
		return TRUE;
	}
	auto &au = i->second;
	if (au.times < g_max_within_interval) {
		if (current - au.first > g_audit_intvl) {
			au.times = 0;
			au.first = current;
		}
		++au.times;
		au.last = current;
	} else if (current - au.last > g_audit_intvl) {
		au.times = 1;
		au.first = au.last = current;
	} else {
		++au.times;
		au.last = current;
		return false;
	}
	return TRUE;
}

static BOOL svc_ip6_filter(int reason, void **data)
{
	if (reason == PLUGIN_FREE) {
		g_templist.clear();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(data);
	std::string plugname, filename;
	try {
		plugname = get_plugin_name();
		auto pos = plugname.find('.');
		if (pos != plugname.npos)
			plugname.erase(pos);
		filename = plugname + ".cfg";
	} catch (...) {
		return false;
	}

	auto pfile = config_file_initd(filename.c_str(), get_config_path(), nullptr);
	if (pfile == nullptr) {
		mlog(LV_ERR, "ip6_container: config_file_initd %s: %s",
		       filename.c_str(), strerror(errno));
		return false;
	}
	auto strv = pfile->get_value("audit_max_num");
	g_audit_max = strv != nullptr ? strtoul(strv, nullptr, 0) : 0;
	strv = pfile->get_value("audit_interval");
	g_audit_intvl = std::chrono::seconds(strv != nullptr ? HX_strtoull_sec(strv, nullptr) : 60);
	strv = pfile->get_value("audit_times");
	g_max_within_interval = strv != nullptr ? strtoul(strv, nullptr, 0) : 10;
	strv = pfile->get_value("temp_list_size");
	g_templist_maxsize = strv != nullptr ? strtoul(strv, nullptr, 0) : 0;
	auto judge_name = pfile->get_value("judge_service_name");
	if (judge_name == nullptr)
		judge_name = "ip_filter_judge";
	auto add_name = pfile->get_value("add_service_name");
	if (add_name == nullptr)
		add_name = "ip_filter_add";
	char temp_buff[64];
	HX_unit_seconds(temp_buff, arsizeof(temp_buff), std::chrono::duration_cast<std::chrono::seconds>(g_audit_intvl).count(), 0);
	mlog(LV_INFO, "%s: audit capacity is %d", plugname.c_str(), g_audit_max);
	mlog(LV_INFO, "%s: audit interval is %s", plugname.c_str(), temp_buff);
	mlog(LV_INFO, "%s: audit times is %d", plugname.c_str(), g_max_within_interval);
	mlog(LV_INFO, "%s: temporary list capacity is %zu", plugname.c_str(), g_templist_maxsize);

	if ((add_name != nullptr && !register_service(add_name, ip6flt_add)) ||
	    (judge_name != nullptr && !register_service(judge_name, ip6flt_judge))) {
		mlog(LV_ERR, "ip6_filter: can't register services (symbol clash?)");
		return false;
	}
	return TRUE;
}
SVC_ENTRY(svc_ip6_filter);
