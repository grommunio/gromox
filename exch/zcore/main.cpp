// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "service.h"
#include "ab_tree.h"
#include "listener.h"
#include <gromox/mail_func.hpp>
#include "rpc_parser.h"
#include "common_util.h"
#include <gromox/config_file.hpp>
#include "exmdb_client.h"
#include "zarafa_server.h"
#include "console_cmd_handler.h"
#include <gromox/console_server.hpp>
#include "msgchg_grouping.h"
#include "bounce_producer.h"
#include "system_services.h"
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>

using namespace gromox;

std::atomic<bool> g_notify_stop{false};
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;
static std::atomic<bool> g_hup_signalled{false};

static struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static const char *const g_dfl_svc_plugins[] = {
	"libgxs_codepage_lang.so",
	"libgxs_logthru.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_textmaps.so",
	"libgxs_timer_agent.so",
	NULL,
};

static void term_handler(int signo)
{
	g_notify_stop = true;
}

static bool zcore_reload_config(std::shared_ptr<CONFIG_FILE> pconfig)
{
	if (pconfig == nullptr)
		pconfig = config_file_prg(opt_config_file, "zcore.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[exmdb_provider]: config_file_init %s: %s\n",
		       opt_config_file, strerror(errno));
		return false;
	}
	auto v = pconfig->get_value("zrpc_debug");
	g_zrpc_debug = v != nullptr ? strtoul(v, nullptr, 0) : 0;
	return true;
}

int main(int argc, const char **argv)
{
	const char *str_value;
	char temp_buff[45];
	char host_name[256];
	std::shared_ptr<CONFIG_FILE> pconfig;
	
	exmdb_rpc_alloc = common_util_alloc;
	exmdb_rpc_free = [](void *) {};
	exmdb_rpc_exec = exmdb_client_do_rpc;
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
	sact.sa_handler = [](int) {};
	sigaction(SIGALRM, &sact, nullptr);
	sact.sa_handler = [](int) { g_hup_signalled = true; };
	sigaction(SIGHUP, &sact, nullptr);
	sact.sa_handler = SIG_IGN;
	sact.sa_flags   = SA_RESTART;
	sigaction(SIGPIPE, &sact, nullptr);
	g_config_file = pconfig = config_file_prg(opt_config_file, "zcore.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr)
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return 2;

	static constexpr cfg_directive cfg_default_values[] = {
		{"address_cache_interval", "5min", CFG_TIME, "1min", "1day"},
		{"address_item_num", "100000", CFG_SIZE, "1"},
		{"address_table_size", "3000", CFG_SIZE, "1"},
		{"config_file_path", PKGSYSCONFDIR "/zcore:" PKGSYSCONFDIR},
		{"console_server_ip", "::1"},
		{"console_server_port", "3344"},
		{"data_file_path", PKGDATADIR "/zcore:" PKGDATADIR},
		{"default_charset", "windows-1252"},
		{"default_timezone", "Asia/Shanghai"},
		{"freebusy_tool_path", PKGLIBEXECDIR "/freebusy"},
		{"mail_max_length", "64M", CFG_SIZE, "1"},
		{"mailbox_ping_interval", "5min", CFG_TIME, "1min", "1h"},
		{"max_ext_rule_length", "510K", CFG_SIZE, "1"},
		{"max_mail_num", "1000000", CFG_SIZE, "1"},
		{"max_rcpt_num", "256", CFG_SIZE, "1"},
		{"notify_stub_threads_num", "10", CFG_SIZE, "1", "100"},
		{"rpc_proxy_connection_num", "10", CFG_SIZE, "1", "100"},
		{"separator_for_bounce", ";"},
		{"service_plugin_path", PKGLIBDIR},
		{"smtp_server_ip", "::1"},
		{"smtp_server_port", "25"},
		{"state_path", PKGSTATEDIR},
		{"submit_command", "/usr/bin/php " PKGDATADIR "/sa/submit.php"},
		{"user_cache_interval", "1h", CFG_TIME, "1min", "1day"},
		{"user_table_size", "5000", CFG_SIZE, "100", "50000"},
		{"x500_org_name", "Gromox default"},
		{"zarafa_mime_number", "4096", CFG_SIZE, "1024"},
		{"zarafa_threads_num", "100", CFG_SIZE, "20", "1000"},
		{"zcore_listen", PKGRUNDIR "/zcore.sock"},
		{},
	};
	config_file_apply(*g_config_file, cfg_default_values);

	str_value = pconfig->get_value("HOST_ID");
	if (NULL == str_value) {
		gethostname(host_name, 256);
	} else {
		gx_strlcpy(host_name, str_value, GX_ARRAY_SIZE(host_name));
	}
	printf("[system]: hostname is %s\n", host_name);
	
	str_value = pconfig->get_value("SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = deconst(read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return 2;
		}
	}

	if (!zcore_reload_config(pconfig))
		return EXIT_FAILURE;
	
	msgchg_grouping_init(g_config_file->get_value("data_file_path"));
	auto cl_0c = make_scope_exit([&]() { msgchg_grouping_free(); });
	unsigned int threads_num = pconfig->get_ll("zarafa_threads_num");
	printf("[system]: connection threads number is %d\n", threads_num);

	service_init({g_config_file->get_value("service_plugin_path"),
		g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		parse_bool(g_config_file->get_value("service_plugin_ignore_errors")),
		threads_num});
	
	unsigned int table_size = pconfig->get_ll("address_table_size");
	printf("[system]: address table size is %d\n", table_size);

	int cache_interval = pconfig->get_ll("address_cache_interval");
	itvltoa(cache_interval, temp_buff);
	printf("[system]: address book tree item"
		" cache interval is %s\n", temp_buff);

	int max_item_num = pconfig->get_ll("address_item_num");
	printf("[system]: maximum item number is %d\n", max_item_num);
	
	ab_tree_init(g_config_file->get_value("x500_org_name"), table_size, cache_interval, max_item_num);
	bounce_producer_init(g_config_file->get_value("separator_for_bounce"));

	int mime_num = pconfig->get_ll("zarafa_mime_number");
	printf("[system]: mime number is %d\n", mime_num);
	
	int max_rcpt = pconfig->get_ll("max_rcpt_num");
	printf("[system]: maximum rcpt number is %d\n", max_rcpt);
	
	int max_mail = pconfig->get_ll("max_mail_num");
	printf("[system]: maximum mail number is %d\n", max_mail);
	
	int max_length = pconfig->get_ll("mail_max_length");
	bytetoa(max_length, temp_buff);
	printf("[system]: maximum mail length is %s\n", temp_buff);
	
	int max_rule_len = pconfig->get_ll("max_ext_rule_length");
	bytetoa(max_rule_len, temp_buff);
	printf("[system]: maximum extended rule length is %s\n", temp_buff);
	
	uint16_t smtp_port = pconfig->get_ll("smtp_server_port");
	printf("[system]: smtp server is [%s]:%hu\n",
	       g_config_file->get_value("smtp_server_ip"), smtp_port);
	
	common_util_init(g_config_file->get_value("x500_org_name"), host_name,
		g_config_file->get_value("default_charset"),
		g_config_file->get_value("default_timezone"), mime_num,
		max_rcpt, max_mail, max_length, max_rule_len,
		g_config_file->get_value("smtp_server_ip"), smtp_port,
		g_config_file->get_value("freebusy_tool_path"),
		g_config_file->get_value("submit_command"));
	auto cl_0b = make_scope_exit([&]() { common_util_free(); });
	
	int proxy_num = pconfig->get_ll("rpc_proxy_connection_num");
	printf("[system]: exmdb proxy connection number is %d\n", proxy_num);
	
	int stub_num = pconfig->get_ll("notify_stub_threads_num");
	printf("[system]: exmdb notify stub threads number is %d\n", stub_num);
	
	exmdb_client_init(proxy_num, stub_num);
	rpc_parser_init(threads_num);
	table_size = pconfig->get_ll("user_table_size");
	printf("[system]: hash table size is %d\n", table_size);

	cache_interval = pconfig->get_ll("user_cache_interval");
	itvltoa(cache_interval, temp_buff);
	printf("[system]: cache interval is %s\n", temp_buff);
	
	int ping_interval = pconfig->get_ll("mailbox_ping_interval");
	itvltoa(ping_interval, temp_buff);
	printf("[system]: mailbox ping interval is %s\n", temp_buff);
	
	zarafa_server_init(table_size, cache_interval, ping_interval);
	auto cleanup_2 = make_scope_exit(zarafa_server_free);
	
	auto console_ip = pconfig->get_value("console_server_ip");
	uint16_t console_port = pconfig->get_ll("console_server_port");
	printf("[system]: console server address is [%s]:%hu\n",
	       *console_ip == '\0' ? "*" : console_ip, console_port);
	console_server_init(console_ip, console_port);
	console_server_register_command("zcore", cmd_handler_zcore_control);
	console_server_register_command("system", cmd_handler_system_control);
	console_server_register_command("help", cmd_handler_help);
	console_server_register_command(nullptr, cmd_handler_service_plugins);

	listener_init();

	if (service_run_early() != 0) {
		printf("[system]: failed to run PLUGIN_EARLY_INIT\n");
		return 3;
	}
	if (0 != service_run()) {
		printf("[system]: failed to run service\n");
		return 3;
	}
	auto cl_0 = make_scope_exit(service_stop);
	if (0 != system_services_run()) {
		printf("[system]: failed to run system services\n");
		return 4;
	}
	auto cl_1 = make_scope_exit(system_services_stop);
	if (common_util_run(g_config_file->get_value("data_file_path")) != 0) {
		printf("[system]: failed to run common util\n");
		return 5;
	}
	auto cl_2 = make_scope_exit(common_util_stop);
	if (bounce_producer_run(g_config_file->get_value("data_file_path")) != 0) {
		printf("[system]: failed to run bounce producer\n");
		return 6;
	}
	if (0 != msgchg_grouping_run()) {
		printf("[system]: failed to run msgchg grouping\n");
		return 7;
	}
	auto cl_4 = make_scope_exit(msgchg_grouping_stop);
	if (0 != ab_tree_run()) {
		printf("[system]: failed to run address book tree\n");
		return 8;
	}
	auto cl_5 = make_scope_exit(ab_tree_stop);
	if (0 != rpc_parser_run()) {
		printf("[system]: failed to run rpc parser\n");
		return 9;
	}
	auto cl_6 = make_scope_exit(rpc_parser_stop);
	if (0 != zarafa_server_run()) {
		printf("[system]: failed to run zarafa server\n");
		return 10;
	}
	auto cl_7 = make_scope_exit(zarafa_server_stop);
	if (exmdb_client_run(g_config_file->get_value("config_file_path")) != 0) {
		printf("[system]: failed to run exmdb client\n");
		return 11;
	}
	auto cl_8 = make_scope_exit(exmdb_client_stop);
	if (0 != console_server_run()) {
		printf("[system]: failed to run console server\n");
		return 12;
	}
	auto cl_9 = make_scope_exit(console_server_stop);
	if (listener_run(g_config_file->get_value("zcore_listen")) != 0) {
		printf("[system]: failed to run listener\n");
		return 13;
	}
	auto cl_10 = make_scope_exit(listener_stop);
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	printf("[system]: zcore is now running\n");
	while (!g_notify_stop) {
		sleep(1);
		if (g_hup_signalled.exchange(false)) {
			zcore_reload_config(nullptr);
			service_reload_all();
			ab_tree_invalidate_cache();
		}
	}
	return 0;
}
