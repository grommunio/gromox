// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021-2023 grommunio GmbH
// This file is part of Gromox.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
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
#include "mlist_expand/bounce_producer.h"

using namespace gromox;

enum {
	ML_OK = 0,
	ML_NONE,
	ML_XDOMAIN,
	ML_XINTERNAL,
	ML_XSPECIFIED,
};

DECLARE_HOOK_API();

static std::atomic<bool> xa_notify_stop{false};
static std::condition_variable xa_thread_wake;
static std::map<std::string, std::string, std::less<>> xa_alias_map;
static std::mutex xa_alias_lock;
static std::thread xa_thread;
static mysql_adaptor_init_param g_parm;
static std::chrono::seconds g_cache_lifetime;
static decltype(mysql_adaptor_get_mlist_memb) *get_mlist_memb;

static MYSQL *sql_make_conn()
{
	auto conn = mysql_init(nullptr);
	if (conn == nullptr)
		return nullptr;
	if (g_parm.timeout > 0) {
		mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &g_parm.timeout);
		mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &g_parm.timeout);
	}
	if (mysql_real_connect(conn, g_parm.host.c_str(), g_parm.user.c_str(),
	    g_parm.pass.size() != 0 ? g_parm.pass.c_str() : nullptr,
	    g_parm.dbname.c_str(), g_parm.port, nullptr, 0) == nullptr) {
		mlog(LV_ERR, "alias_resolve: Failed to connect to mysql server: %s",
		       mysql_error(conn));
		mysql_close(conn);
		return nullptr;
	}
	if (mysql_set_character_set(conn, "utf8mb4") != 0) {
		mlog(LV_ERR, "alias_resolve: \"utf8mb4\" not available: %s",
		        mysql_error(conn));
		mysql_close(conn);
		return nullptr;
	}
	return conn;
}

static std::string xa_alias_lookup(const char *srch)
{
	static const std::string empty;
	std::lock_guard hold(xa_alias_lock);
	auto i = xa_alias_map.find(srch);
	return i != xa_alias_map.cend() ? i->second : empty;
	/* return a copy, since the map may change after releasing the lock */
}

static void xa_refresh_aliases(MYSQL *conn) try
{
	static const char query[] = "SELECT aliasname, mainname FROM aliases";
	if (mysql_query(conn, query) != 0)
		return;
	DB_RESULT res = mysql_store_result(conn);
	decltype(xa_alias_map) newmap;
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr)
		if (row[0] != nullptr && row[1] != nullptr)
			newmap.emplace(row[0], row[1]);
	std::lock_guard hold(xa_alias_lock);
	std::swap(xa_alias_map, newmap);
	mlog(LV_INFO, "I-1612: refreshed alias map (%zu entries)",
	        xa_alias_map.size());
} catch (const std::bad_alloc &) {
}

static void xa_refresh_thread()
{
	std::mutex slp_mtx;
	{
		auto conn = sql_make_conn();
		std::unique_lock slp_hold(slp_mtx);
		xa_refresh_aliases(conn);
	}
	while (!xa_notify_stop) {
		std::unique_lock slp_hold(slp_mtx);
		xa_thread_wake.wait_for(slp_hold, g_cache_lifetime);
		if (xa_notify_stop)
			break;
		auto conn = sql_make_conn();
		xa_refresh_aliases(conn);
	}
}

static hook_result xa_alias_subst(MESSAGE_CONTEXT *ctx) try
{
	auto ctrl = &ctx->ctrl;
	if (strchr(ctrl->from, '@') != nullptr) {
		auto repl = xa_alias_lookup(ctrl->from);
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
		if (strchr(todo[i].c_str(), '@') == nullptr) {
			output_rcpt.emplace_back(std::move(todo[i]));
			continue;
		}
		auto repl = xa_alias_lookup(todo[i].c_str());
		if (repl.size() != 0) {
			mlog(LV_DEBUG, "alias_resolve: subst RCPT %s -> %s",
				todo[i].c_str(), repl.c_str());
			todo[i] = std::move(repl);
		}
		if (!seen.emplace(todo[i]).second) {
			todo[i] = {};
			continue;
		}

		std::vector<std::string> exp_result;
		int gmm_result = 0;
		if (!get_mlist_memb(todo[i].c_str(), ctx->ctrl.from, &gmm_result, exp_result))
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
			snprintf(bnctx->ctrl.from, std::size(bnctx->ctrl.from), "postmaster@%s", get_default_domain());
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

static constexpr const cfg_directive mysql_directives[] = {
	{"mysql_dbname", "email"},
	{"mysql_host", "localhost"},
	{"mysql_password", ""},
	{"mysql_port", "3306"},
	{"mysql_rdwr_timeout", "0", CFG_TIME},
	{"mysql_username", "root"},
	CFG_TABLE_END,
};
static constexpr const cfg_directive xa_directives[] = {
	{"cache_lifetime", "1h", CFG_TIME},
	CFG_TABLE_END,
};

static bool xa_reload_config(std::shared_ptr<CONFIG_FILE> mcfg,
    std::shared_ptr<CONFIG_FILE> acfg) try
{
	if (mcfg == nullptr)
		mcfg = config_file_initd("mysql_adaptor.cfg", get_config_path(),
		       mysql_directives);
	if (mcfg == nullptr) {
		mlog(LV_ERR, "alias_resolve: config_file_initd mysql_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	g_parm.host = mcfg->get_value("mysql_host");
	g_parm.port = mcfg->get_ll("mysql_port");
	g_parm.user = mcfg->get_value("mysql_username");
	g_parm.pass = mcfg->get_value("mysql_password");
	g_parm.dbname = mcfg->get_value("mysql_dbname");
	g_parm.timeout = mcfg->get_ll("mysql_rdwr_timeout");
	mlog(LV_NOTICE, "alias_resolve: mysql [%s]:%d, timeout=%d, db=%s",
	       g_parm.host.size() == 0 ? "*" : g_parm.host.c_str(), g_parm.port,
	       g_parm.timeout, g_parm.dbname.c_str());

	if (acfg == nullptr)
		acfg = config_file_initd("alias_resolve.cfg", get_config_path(),
		       xa_directives);
	if (acfg == nullptr) {
		mlog(LV_ERR, "alias_resolve: config_file_initd alias_resolve.cfg: %s",
		       strerror(errno));
		return false;
	}
	g_cache_lifetime = std::chrono::seconds(acfg->get_ll("cache_lifetime"));
	return true;
} catch (const cfg_error &) {
	return false;
}

static BOOL xa_main(int reason, void **data)
{
	if (reason == PLUGIN_RELOAD) {
		xa_reload_config(nullptr, nullptr);
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
	query_service2("get_mlist_memb", get_mlist_memb);
	if (get_mlist_memb == nullptr) {
		mlog(LV_ERR, "mlist_expand: failed to get service \"get_mlist_memb\"");
		return FALSE;
	}
	if (mlex_bounce_init(";", get_config_path(),
	    get_data_path(), "mlist_bounce") != 0) {
		mlog(LV_ERR, "mlist_expand: failed to run bounce producer");
		return FALSE;
	}
	auto mcfg = config_file_initd("mysql_adaptor.cfg", get_config_path(),
	            mysql_directives);
	if (mcfg == nullptr) {
		mlog(LV_ERR, "alias_resolve: config_file_initd mysql_adaptor.cfg: %s",
		       strerror(errno));
		return false;
	}
	auto acfg = config_file_initd("alias_resolve.cfg", get_config_path(),
	            xa_directives);
	if (acfg == nullptr) {
		mlog(LV_ERR, "alias_resolve: config_file_initd alias_resolve.cfg: %s",
		       strerror(errno));
		return false;
	}
	if (!xa_reload_config(mcfg, acfg) ||
	    !register_hook(xa_alias_subst))
		return false;
	try {
		xa_thread = std::thread(xa_refresh_thread);
	} catch (const std::system_error &e) {
		mlog(LV_ERR, "alias_resolve: %s", e.what());
		return false;
	}
	return true;
}
HOOK_ENTRY(xa_main);
