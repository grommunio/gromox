// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <future>
#include <semaphore>
#include <string>
#include <vector>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/process.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "mbop.hpp"

using namespace gromox;

namespace foreach_wrap {

static unsigned int g_numthreads = 1;
static constexpr HXoption g_options_table[] = {
	{{}, 'j', HXTYPE_UINT, &g_numthreads, {}, {}, {}, "Maximum concurrency for execution", "INTEGER"},
	MBOP_AUTOHELP,
	HXOPT_TABLEEND,
};

static int help()
{
	fprintf(stderr, "Usage: foreach[.filter]* [-j jobs] command [args...]\n");
	fprintf(stderr, " filter := secobj | user | mlist | sharedmb | contact |\n");
	fprintf(stderr, "           active | susp | deleted | mb | here\n");
	global::command_overview();
	return EXIT_PARAM;
}

static int filter_users(const char *mode, std::vector<sql_user> &ul)
{
	struct dtypx_nomatch {
		unsigned int m_flags = 0;
		constexpr dtypx_nomatch(unsigned int flags) : m_flags(flags) {}
		constexpr bool operator()(const sql_user &u) const { return (u.dtypx & DTE_MASK_LOCAL) != m_flags; };
	};
	struct adst_nomatch {
		unsigned int m_value = 0;
		constexpr adst_nomatch(unsigned int v) : m_value(v) {}
		constexpr bool operator()(const sql_user &u) const { return (u.addr_status & AF_USER__MASK) != m_value; };
	};

	if (strcmp(mode, "for-all-users") == 0)
		return 0;
	if (strncmp(mode, "foreach.", 8) != 0) {
		mlog(LV_ERR, "Unknown command: %s", mode);
		return -1;
	}
	std::string this_server;
	auto err = canonical_hostname(this_server);
	if (err != 0) {
		mlog(LV_ERR, "canonical_hostname: %s", strerror(err));
		return err;
	}

	const char *dot = "";
	for (mode += 8; dot != nullptr; mode = dot + 1) {
		dot = strchr(mode, '.');
		auto filter = dot != nullptr ? std::string_view{mode, static_cast<size_t>(dot - mode)} :
		              std::string_view{mode};
		if (filter == "secobj")
			continue;
		else if (filter == "user")
			std::erase_if(ul, dtypx_nomatch(DT_MAILUSER));
		else if (filter == "dl")
			std::erase_if(ul, dtypx_nomatch(DT_DISTLIST));
		else if (filter == "room")
			std::erase_if(ul, dtypx_nomatch(DT_ROOM));
		else if (filter == "equipment")
			std::erase_if(ul, dtypx_nomatch(DT_EQUIPMENT));
		else if (filter == "sharedmb")
			std::erase_if(ul, adst_nomatch(AF_USER_SHAREDMBOX));
		else if (filter == "contact")
			std::erase_if(ul, [](const sql_user &u) { return (u.addr_status & AF_USER__MASK) != AF_USER_CONTACT || (u.dtypx & DTE_MASK_LOCAL) != DT_REMOTE_MAILUSER; });
		else if (filter == "active")
			std::erase_if(ul, adst_nomatch(AF_USER_NORMAL));
		else if (filter == "susp")
			std::erase_if(ul, adst_nomatch(AF_USER_SUSPENDED));
		else if (filter == "deleted")
			std::erase_if(ul, adst_nomatch(AF_USER_DELETED));
		else if (filter == "mb")
			std::erase_if(ul, [](const sql_user &u) { return u.maildir.empty(); });
		else if (filter == "here")
			std::erase_if(ul, [&](const sql_user &u) {
				return u.homeserver_id > 0 &&
				       strcasecmp(u.homeserver.c_str(), this_server.c_str()) != 0;
			});
		else {
			mlog(LV_ERR, "Unknown filter: \"%.*s\"", static_cast<int>(filter.size()), filter.data());
			return -1;
		}
	}
	return 0;
}

/* async handlers */
using Sem = std::counting_semaphore<1>;

static void ah_ping(const std::string *maildir, Sem *sem, int *ret)
{
	if (!exmdb_client->ping_store(maildir->c_str()))
		*ret = EXIT_FAILURE;
	sem->release();
}

static void ah_unload_store(const std::string *maildir, Sem *sem, int *ret)
{
	if (!exmdb_client->unload_store(maildir->c_str()))
		*ret = EXIT_FAILURE;
	sem->release();
}

static void ah_vacuum(const std::string *maildir, Sem *sem, int *ret)
{
	if (!exmdb_client->vacuum(maildir->c_str()))
		*ret = EXIT_FAILURE;
	sem->release();
}

int main(int argc, char **argv)
{
	HXopt6_auto_result result;
	if (HX_getopt6(g_options_table, argc, argv, &result, HXOPT_USAGEONERR |
	    HXOPT_RQ_ORDER | HXOPT_ITER_ARGS) != HXOPT_ERR_SUCCESS ||
	    g_exit_after_optparse)
		return EXIT_PARAM;
	if (global::g_arg_username != nullptr || global::g_arg_userdir != nullptr) {
		fprintf(stderr, "Cannot use -d/-u with foreach.*\n");
		return EXIT_PARAM;
	} else if (g_numthreads == 0) {
		g_numthreads = gx_concurrency();
	}
	auto fe_mode = argv[0];
	argc = result.nargs;
	argv = result.uarg;
	++global::g_command_num;
	if (argc == 0)
		return help();

	std::vector<sql_user> ul;
	if (mysql_adaptor_mbop_userlist(ul) != 0 || filter_users(fe_mode, ul) != 0)
		return EXIT_FAILURE;
	auto ret = gi_startup_client(g_numthreads);
	if (ret != 0)
		return ret;
	auto cl_1 = HX::make_scope_exit(gi_shutdown);
	ret = EXIT_SUCCESS;
	std::vector<std::future<void>> futs;
	Sem sem(g_numthreads);

	if (strcmp(argv[0], "ping") == 0) {
		if (HX_getopt6(empty_options_table, argc, argv, nullptr,
		    HXOPT_RQ_ORDER | HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS ||
		    g_exit_after_optparse)
			return EXIT_PARAM;
		for (const auto &user : ul) {
			sem.acquire();
			if (ret != EXIT_SUCCESS && !global::g_continuous_mode)
				break;
			futs.emplace_back(std::async(ah_ping, &user.maildir, &sem, &ret));
		}
	} else if (strcmp(argv[0], "unload") == 0) {
		if (HX_getopt6(empty_options_table, argc, argv, nullptr,
		    HXOPT_RQ_ORDER | HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS ||
		    g_exit_after_optparse)
			return EXIT_PARAM;
		for (const auto &user : ul) {
			sem.acquire();
			if (ret != EXIT_SUCCESS && !global::g_continuous_mode)
				return ret;
			futs.emplace_back(std::async(ah_unload_store, &user.maildir, &sem, &ret));
		}
	} else if (strcmp(argv[0], "vacuum") == 0) {
		if (HX_getopt6(empty_options_table, argc, argv, nullptr,
		    HXOPT_RQ_ORDER | HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS ||
		    g_exit_after_optparse)
			return EXIT_PARAM;
		for (const auto &user : ul) {
			sem.acquire();
			if (ret != EXIT_SUCCESS && !global::g_continuous_mode)
				return ret;
			futs.emplace_back(std::async(ah_vacuum, &user.maildir, &sem, &ret));
		}
	} else {
		auto saved_cnum = global::g_command_num;
		for (auto &&user : ul) {
			/* cmd_parser is not thread-safe (global state), cannot parallelize */
			g_dstuser = std::move(user.username);
			g_storedir_s = std::move(user.maildir);
			g_storedir = g_storedir_s.c_str();
			global::g_command_num = saved_cnum;
			ret = global::cmd_parser(argc, argv);
			if (ret == EXIT_PARAM)
				return ret;
			else if (ret != EXIT_SUCCESS && !global::g_continuous_mode)
				return ret;
		}
	}
	return ret;
}

}
