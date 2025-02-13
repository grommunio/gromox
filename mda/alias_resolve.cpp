// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021-2025 grommunio GmbH
// This file is part of Gromox.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/hook_common.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/scope.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "mdabounce.hpp"

using namespace gromox;

enum {
	ML_OK = 0,
	ML_NONE,
	ML_XDOMAIN,
	ML_XINTERNAL,
	ML_XSPECIFIED,
};

DECLARE_HOOK_API(alias_resolve, );
using namespace alias_resolve;

static std::atomic<bool> xa_notify_stop{false};
static std::condition_variable xa_thread_wake;
static sql_alias_map xa_empty_alias_map;
static sql_domain_set xa_empty_domain_set;
static std::shared_ptr<sql_alias_map> xa_alias_map;
static std::shared_ptr<sql_domain_set> xa_domain_set;
static std::mutex xa_alias_lock;
static std::thread xa_thread;
static std::chrono::seconds g_cache_lifetime;
static std::string g_rcpt_delimiter;

static const std::string &xa_lookup(const sql_alias_map &map, const char *key)
{
	static const std::string empty;
	auto i = map.find(key);
	return i == map.end() ? empty : i->second;
}

static void xa_refresh_once()
{
	auto newmap = std::make_shared<sql_alias_map>();
	auto newdom = std::make_shared<sql_domain_set>();
	size_t n_aliases = 0;
	auto err = mysql_adaptor_mda_alias_list(*newmap, n_aliases);
	if (err != 0)
		return;
	err = mysql_adaptor_mda_domain_list(*newdom);
	if (err != 0)
		return;
	auto n_contacts = newmap->size() - n_aliases;
	std::unique_lock lk(xa_alias_lock);
	if (newmap != nullptr)
		xa_alias_map = std::move(newmap);
	if (newdom != nullptr)
		xa_domain_set = std::move(newdom);
	mlog(LV_INFO, "I-1612: refreshed alias_resolve map with %zu aliases and %zu contact objects",
		n_aliases, n_contacts);
}

static void xa_refresh_thread()
{
	std::mutex slp_mtx;
	while (!xa_notify_stop) {
		{
			std::unique_lock slp_hold(slp_mtx);
			xa_thread_wake.wait_for(slp_hold, g_cache_lifetime);
		}
		xa_refresh_once();
	}
}

static hook_result xa_alias_subst(MESSAGE_CONTEXT *ctx) try
{
	decltype(xa_alias_map) alias_map_ptr;
	decltype(xa_domain_set) domset_ptr;
	{
		std::unique_lock lk(xa_alias_lock);
		alias_map_ptr = xa_alias_map;
		domset_ptr = xa_domain_set;
	}
	auto &alias_map = alias_map_ptr != nullptr ? *alias_map_ptr : xa_empty_alias_map;
	auto &domset = domset_ptr != nullptr ? *domset_ptr : xa_empty_domain_set;

	auto ctrl = &ctx->ctrl;
	if (strchr(ctrl->from, '@') != nullptr) {
		const auto &repl = xa_lookup(alias_map, ctrl->from);
		if (repl.size() > 0) {
			mlog(LV_DEBUG, "alias_resolve: subst FROM %s -> %s", ctrl->from, repl.c_str());
			gx_strlcpy(ctrl->from, repl.c_str(), std::size(ctrl->from));
		}
	}
	/*
	 * For diagnostic purposes, don't modify/steal from ctrl->rcpt until
	 * the replacement list is fully constructed.
	 */
	std::vector<std::string> output_rcpt;
	std::set<std::string> seen;
	std::vector<std::string> todo = ctrl->rcpt;

	for (size_t i = 0; i < todo.size(); ++i) {
		auto at = strchr(todo[i].c_str(), '@');
		if (at != nullptr && domset.find(&at[1]) != domset.cend()) {
			/*
			 * Contacts may resolve to remote addresses, which we
			 * do not want to strip anything from, so limit
			 * extension removal to our own domains.
			 */
			size_t atpos = at - todo[i].c_str();
			auto sv = atpos == todo[i].npos ? std::string_view(todo[i]) :
			          std::string_view(todo[i].c_str(), atpos);
			auto expos = sv.find_first_of(g_rcpt_delimiter);
			if (expos != todo[i].npos && expos < atpos)
				todo[i].erase(expos, atpos - expos);
		}
		auto repl = xa_lookup(alias_map, todo[i].c_str());
		if (repl.size() != 0) {
			mlog(LV_DEBUG, "alias_resolve: subst RCPT %s -> %s",
				todo[i].c_str(), repl.c_str());
			todo[i] = std::move(repl);
		}
		if (!seen.emplace(todo[i]).second) {
			todo[i] = {};
			continue;
		}
		if (strchr(todo[i].c_str(), '@') == nullptr) {
			output_rcpt.emplace_back(std::move(todo[i]));
			continue;
		}

		std::vector<std::string> exp_result;
		int gmm_result = 0;
		if (!mysql_adaptor_get_mlist_memb(todo[i].c_str(), ctx->ctrl.from, &gmm_result, exp_result))
			gmm_result = ML_NONE;
		switch (gmm_result) {
		case ML_NONE:
			output_rcpt.emplace_back(std::move(todo[i]));
			continue;
		case ML_OK:
			mlog(LV_DEBUG, "mlist_expand: subst RCPT %s -> %zu entities",
				todo[i].c_str(), exp_result.size());
			todo.insert(todo.begin() + i + 1,
				std::make_move_iterator(exp_result.begin()),
				std::make_move_iterator(exp_result.end()));
			continue;
		case ML_XDOMAIN:
		case ML_XINTERNAL:
		case ML_XSPECIFIED: {
			auto tpl = gmm_result == ML_XDOMAIN ? "BOUNCE_MLIST_DOMAIN" :
			           gmm_result == ML_XINTERNAL ? "BOUNCE_MLIST_INTERNAL" :
			           "BOUNCE_MLIST_SPECIFIED";
			auto bnctx = get_context();
			if (bnctx == nullptr || !mlex_bouncer_make(ctx->ctrl.from,
			    todo[i].c_str(), &ctx->mail, tpl, &bnctx->mail)) {
				output_rcpt.emplace_back(std::move(todo[i]));
				break;
			}
			bnctx->ctrl.need_bounce = false;
			gx_strlcpy(bnctx->ctrl.from, bounce_gen_postmaster(),
				std::size(bnctx->ctrl.from));
			bnctx->ctrl.rcpt.emplace_back(ctx->ctrl.from);
			throw_context(bnctx);
			mlog(LV_DEBUG, "mlist_expand: from=<%s> has no privilege to expand mlist <%s> (%s)",
				ctx->ctrl.from, todo[i].c_str(), tpl);
			break;
		}
		}
	}
	ctrl->rcpt = std::move(output_rcpt);
	return ctx->ctrl.rcpt.empty() ? hook_result::stop : hook_result::xcontinue;
} catch (const std::bad_alloc &) {
	mlog(LV_INFO, "E-1611: ENOMEM");
	return hook_result::proc_error;
}

static constexpr const cfg_directive xa_directives[] = {
	{"lda_alias_cache_lifetime", "1h", CFG_TIME},
	{"lda_recipient_delimiter", ""},
	CFG_TABLE_END,
};

static bool xa_reload_config(std::shared_ptr<CONFIG_FILE> &&acfg)
{
	if (acfg == nullptr)
		acfg = config_file_initd("gromox.cfg", get_config_path(),
		       xa_directives);
	if (acfg == nullptr) {
		mlog(LV_ERR, "alias_resolve: config_file_initd gromox.cfg: %s",
		       strerror(errno));
		return false;
	}
	g_cache_lifetime = std::chrono::seconds(acfg->get_ll("lda_alias_cache_lifetime"));
	g_rcpt_delimiter = znul(acfg->get_value("lda_recipient_delimiter"));
	return true;
}

BOOL HOOK_alias_resolve(enum plugin_op reason, const struct dlfuncs &data)
{
	if (reason == PLUGIN_RELOAD) {
		xa_reload_config(nullptr);
		xa_thread_wake.notify_one();
		return TRUE;
	}
	if (reason == PLUGIN_FREE) {
		xa_notify_stop = true;
		xa_thread_wake.notify_one();
		xa_thread.join();
		return TRUE;
	}
	if (reason != PLUGIN_INIT)
		return TRUE;
	LINK_HOOK_API(data);
	textmaps_init();
	if (mlex_bounce_init(get_config_path(), get_data_path(),
	    "mlist_bounce") != 0) {
		mlog(LV_ERR, "mlist_expand: failed to run bounce producer");
		return FALSE;
	}
	auto acfg = config_file_initd("gromox.cfg", get_config_path(),
	            xa_directives);
	if (acfg == nullptr) {
		mlog(LV_ERR, "alias_resolve: config_file_initd gromox.cfg: %s",
		       strerror(errno));
		return false;
	}
	if (!xa_reload_config(std::move(acfg)))
		return false;
	xa_refresh_once();
	if (!register_hook(xa_alias_subst))
		return false;
	try {
		xa_thread = std::thread(xa_refresh_thread);
	} catch (const std::system_error &e) {
		mlog(LV_ERR, "alias_resolve: %s", e.what());
		return false;
	}
	return true;
}
