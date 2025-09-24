// SPDX-License-Identifier: AGPL-3.0-or-later 
// SPDX-FileCopyrightText: 2024 grommunio GmbH 
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <libHX/string.h>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/svc_common.h>
#include <gromox/util.hpp>

using namespace gromox;
DECLARE_SVC_API(,);

namespace {

class activity {
	public:
	time_point first{}, last{};
	size_t tries = 0;
};

class user_filter {
	public:
	user_filter() = default;
	user_filter(size_t maxbans, size_t maxact, size_t maxtries,
	    time_duration window, bool icase) :
		m_maxbans(maxbans), m_maxact(maxact), m_maxtries(maxtries),
		m_window(window), m_icase(icase)
	{}
	bool judge(std::string &&);
	void banlist_insert(std::string &&, std::chrono::seconds);

	private:
	bool banlist_contains(const std::string &);

	std::unordered_map<std::string, activity> m_activity;
	std::mutex m_act_lock;
	std::unordered_map<std::string, time_point> m_banlist;
	std::mutex m_bl_lock;
	size_t m_maxbans = 0, m_maxact = 0, m_maxtries = 0;
	time_duration m_window{};
	bool m_icase = true;
};

}

void user_filter::banlist_insert(std::string &&id, std::chrono::seconds bantime)
{
	auto now    = tp_now();
	auto expiry = now + bantime;
	if (m_icase)
		HX_strlower(id.data());
	std::lock_guard hold(m_bl_lock);
	if (m_banlist.size() >= m_maxbans)
		/* Attempt to purge some outdated entries */
		std::erase_if(m_banlist, [=](const auto &e) { return now >= e.second; });
	if (m_banlist.size() < m_maxbans)
		m_banlist.emplace(std::move(id), expiry);
}

bool user_filter::banlist_contains(const std::string &id)
{
	if (m_maxbans == 0)
		return false;
	auto now = tp_now();
	std::lock_guard hold(m_bl_lock);
	auto it = m_banlist.find(id);
	if (it == m_banlist.end())
		return false;
	if (now <= it->second)
		return true;
	m_banlist.erase(it); /* autopurge expired items */
	return false;
}

bool user_filter::judge(std::string &&id)
{
	if (m_icase)
		HX_strlower(id.data());

	/* Banlist mechanism as described in user_filter(4gx): */
	if (banlist_contains(id))
		return false;

	/* All below is the rate-limiter mechanism as described. */
	if (m_maxact == 0)
		return true;
	auto now = tp_now();
	std::lock_guard hold(m_act_lock);
	auto it = m_activity.find(id);
	if (it != m_activity.end()) {
		auto &act = it->second;
		if (act.tries < m_maxtries) {
			if (now - act.first >= m_window) {
				act.tries = 0;
				act.first = now;
			}
			++act.tries;
			act.last = now;
		} else if (now - act.last >= m_window) {
			act = {now, now, 1};
		} else {
			++act.tries;
			act.last = now;
			return false;
		}
		return true;
	}
	activity act = {now, now, 1};
	if (m_activity.size() >= m_maxact)
		/* try pruning some outdated activity entries */
		std::erase_if(m_activity, [&](const auto &it) { return now - it.second.last >= m_window; });
	if (m_activity.size() < m_maxact)
		m_activity.emplace(std::move(id), std::move(act));
	return true;
}

static std::optional<user_filter> g_userfilter_impl;

static bool userfilter_judge(const char *user) try
{
	return user == nullptr || g_userfilter_impl->judge(user);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2155: ENOMEM");
	return false;
}

static void userfilter_ban(const char *user, int bantime) try
{
	if (user != nullptr)
		g_userfilter_impl->banlist_insert(user, std::chrono::seconds(bantime));
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2157: ENOMEM");
}

static constexpr cfg_directive gromox_cfg_defaults[] = {
	{"userfilter_icase", "1", CFG_BOOL},
	{"userfilter_maxbans", "1000", CFG_SIZE},
	{"userfilter_maxusers", "0", CFG_SIZE},
	{"userfilter_rl_maxtries", "10", CFG_SIZE},
	{"userfilter_rl_window", "60s", CFG_TIME_NS},
	CFG_TABLE_END,
};

BOOL SVC_user_filter(enum plugin_op reason, const struct dlfuncs &fptrs) try
{
	if (reason == PLUGIN_FREE)
		g_userfilter_impl.reset();
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_SVC_API(fptrs);
	auto cfg = config_file_initd("gromox.cfg", get_config_path(), gromox_cfg_defaults);
	if (cfg == nullptr) {
		mlog(LV_ERR, "user_filter: config_file_initd gromox.cfg: %s",
			strerror(errno));
		return false;
	}
	auto val        = cfg->get_value("userfilter_icase");
	auto icase      = val == nullptr || parse_bool(val);
	size_t maxbans  = cfg->get_ll("userfilter_maxbans");
	size_t maxact   = cfg->get_ll("userfilter_maxusers");
	size_t maxtries = cfg->get_ll("userfilter_rl_maxtries");
	time_duration window = std::chrono::nanoseconds(cfg->get_ll("userfilter_rl_window"));
	char temp_buff[41];
	HX_unit_seconds(temp_buff, std::size(temp_buff),
		std::chrono::duration_cast<std::chrono::seconds>(window).count(), 0);
	if (maxact == 0)
		mlog(LV_INFO, "user_filter: not rate-limiting login attempts");
	else
		mlog(LV_INFO, "user_filter: rate-limiting login attempts "
			"to %zu per %s per user (tracking at most %zu users)",
			maxtries, temp_buff, maxact);
	if (maxbans == 0)
		mlog(LV_INFO, "user_filter: no banning of users with repeat failed logins");
	else
		mlog(LV_INFO, "user_filter: max entries for repeat failed login banlist is %zu", maxbans);
	g_userfilter_impl.emplace(maxbans, maxact, maxtries, window, icase);
	if (!register_service("user_filter_judge", userfilter_judge) ||
	    !register_service("user_filter_ban", userfilter_ban)) {
		mlog(LV_ERR, "user_filter: failed to register some service functions");
		return false;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2158: ENOMEM");
	return false;
}
