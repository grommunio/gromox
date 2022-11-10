// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#define DECLARE_HOOK_API_STATIC
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <libHX/string.h>
#include <gromox/config_file.hpp>
#include <gromox/database_mysql.hpp>
#include <gromox/hook_common.h>
#include <gromox/mem_file.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static std::atomic<bool> xa_notify_stop{false};
static std::condition_variable xa_thread_wake;
static std::map<std::string, std::string, std::less<>> xa_alias_map;
static std::mutex xa_alias_lock;
static std::thread xa_thread;
static mysql_adaptor_init_param g_parm;
static std::chrono::seconds g_cache_lifetime;

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

static BOOL xa_alias_subst(MESSAGE_CONTEXT *ctx) try
{
	auto ctrl = ctx->pcontrol;
	if (ctrl->bound_type >= BOUND_SELF)
		return false;

	MEM_FILE temp_file, rcpt_file;
	mem_file_init(&temp_file, ctrl->f_rcpt_to.allocator);
	auto cl_0 = make_scope_exit([&]() { mem_file_free(&temp_file); });
	mem_file_init(&rcpt_file, ctrl->f_rcpt_to.allocator);
	auto cl_1 = make_scope_exit([&]() { mem_file_free(&rcpt_file); });
	ctrl->f_rcpt_to.copy_to(rcpt_file);

	if (strchr(ctrl->from, '@') != nullptr) {
		auto repl = xa_alias_lookup(ctrl->from);
		if (repl.size() > 0) {
			mlog(LV_DEBUG, "alias_resolve: subst FROM %s -> %s", ctrl->from, repl.c_str());
			gx_strlcpy(ctrl->from, repl.c_str(), arsizeof(ctrl->from));
		}
	}

	bool replaced = false;
	char rcpt_to[UADDR_SIZE];
	while (rcpt_file.readline(rcpt_to, arsizeof(rcpt_to)) != MEM_END_OF_FILE) {
		if (strchr(rcpt_to, '@') == nullptr) {
			temp_file.writeline(rcpt_to);
			continue;
		}
		auto repl = xa_alias_lookup(rcpt_to);
		if (repl.size() == 0) {
			temp_file.writeline(rcpt_to);
			continue;
		}
		mlog(LV_DEBUG, "alias_resolve: subst RCPT %s -> %s", rcpt_to, repl.c_str());
		replaced = true;
		temp_file.writeline(repl.c_str());
	}
	if (replaced)
		temp_file.copy_to(ctrl->f_rcpt_to);
	return false;
} catch (const std::bad_alloc &) {
	mlog(LV_INFO, "E-1611: ENOMEM");
	return false;
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
