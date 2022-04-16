// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "ab_tree.h"
#include "bounce_producer.h"
#include "common_util.h"
#include "exmdb_client.h"
#include "listener.h"
#include "msgchg_grouping.h"
#include "object_tree.h"
#include "rpc_parser.h"
#include "service.h"
#include "system_services.h"
#include "zarafa_server.h"

using namespace gromox;

gromox::atomic_bool g_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;
static gromox::atomic_bool g_hup_signalled;

static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr const char *g_dfl_svc_plugins[] = {
	"libgxs_codepage_lang.so",
	"libgxs_logthru.so",
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_textmaps.so",
	"libgxs_timer_agent.so",
	NULL,
};

static constexpr cfg_directive zcore_cfg_defaults[] = {
	{"address_cache_interval", "5min", CFG_TIME, "1min", "1day"},
	{"address_item_num", "100000", CFG_SIZE, "1"},
	{"address_table_size", "3000", CFG_SIZE, "1"},
	{"config_file_path", PKGSYSCONFDIR "/zcore:" PKGSYSCONFDIR},
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
	{"zarafa_threads_num", "100", CFG_SIZE, "1", "1000"},
	{"zcore_listen", PKGRUNDIR "/zcore.sock"},
	{"zcore_max_obh_per_session", "500", CFG_SIZE, "100"},
	{"zrpc_debug", "0"},
	CFG_TABLE_END,
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
	config_file_apply(*pconfig, zcore_cfg_defaults);
	g_zrpc_debug = pconfig->get_ll("zrpc_debug");
	zcore_max_obh_per_session = pconfig->get_ll("zcore_max_obh_per_session");
	return true;
}

int main(int argc, const char **argv) try
{
	const char *str_value;
	char temp_buff[45];
	char host_name[UDOM_SIZE];
	std::shared_ptr<CONFIG_FILE> pconfig;
	
	exmdb_rpc_alloc = common_util_alloc;
	exmdb_rpc_free = [](void *) {};
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv,
	    HXOPT_USAGEONERR | HXOPT_KEEP_ARGV) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	startup_banner("gromox-zcore");
	if (opt_show_version)
		return EXIT_SUCCESS;
	setup_sigalrm();
	struct sigaction sact{};
	sigemptyset(&sact.sa_mask);
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
	if (!zcore_reload_config(pconfig))
		return EXIT_FAILURE;

	str_value = pconfig->get_value("HOST_ID");
	if (NULL == str_value) {
		gethostname(host_name, arsizeof(host_name));
		host_name[arsizeof(host_name)-1] = '\0';
	} else {
		gx_strlcpy(host_name, str_value, GX_ARRAY_SIZE(host_name));
	}
	printf("[system]: hostname is %s\n", host_name);
	
	str_value = pconfig->get_value("SERVICE_PLUGIN_LIST");
	char **service_plugin_list = nullptr;
	auto cl_0d = make_scope_exit([&]() { HX_zvecfree(service_plugin_list); });
	if (str_value != NULL) {
		service_plugin_list = read_file_by_line(str_value);
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return 2;
		}
	}
	
	msgchg_grouping_init(g_config_file->get_value("data_file_path"));
	auto cl_0c = make_scope_exit(msgchg_grouping_free);
	auto cl_4 = make_scope_exit(msgchg_grouping_stop);
	unsigned int threads_num = pconfig->get_ll("zarafa_threads_num");
	printf("[system]: connection threads number is %d\n", threads_num);

	service_init({g_config_file->get_value("service_plugin_path"),
		g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		parse_bool(g_config_file->get_value("service_plugin_ignore_errors")),
		threads_num});
	auto cl_0 = make_scope_exit(service_stop);
	
	unsigned int table_size = pconfig->get_ll("address_table_size");
	printf("[system]: address table size is %d\n", table_size);

	int cache_interval = pconfig->get_ll("address_cache_interval");
	itvltoa(cache_interval, temp_buff);
	printf("[system]: address book tree item"
		" cache interval is %s\n", temp_buff);

	ab_tree_init(g_config_file->get_value("x500_org_name"), table_size, cache_interval);
	auto cl_5 = make_scope_exit(ab_tree_stop);
	bounce_producer_init(g_config_file->get_value("separator_for_bounce"));

	int mime_num = pconfig->get_ll("zarafa_mime_number");
	printf("[system]: mime number is %d\n", mime_num);
	
	auto max_rcpt = pconfig->get_ll("max_rcpt_num");
	printf("[system]: maximum rcpt number is %lld\n", max_rcpt);
	
	auto max_mail = pconfig->get_ll("max_mail_num");
	printf("[system]: maximum mail number is %lld\n", max_mail);
	
	auto max_length = pconfig->get_ll("mail_max_length");
	HX_unit_size(temp_buff, arsizeof(temp_buff), max_length, 1024, 0);
	printf("[system]: maximum mail length is %s\n", temp_buff);
	
	auto max_rule_len = pconfig->get_ll("max_ext_rule_length");
	HX_unit_size(temp_buff, arsizeof(temp_buff), max_rule_len, 1024, 0);
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
	
	int proxy_num = pconfig->get_ll("rpc_proxy_connection_num");
	printf("[system]: exmdb proxy connection number is %d\n", proxy_num);
	
	int stub_num = pconfig->get_ll("notify_stub_threads_num");
	printf("[system]: exmdb notify stub threads number is %d\n", stub_num);
	
	exmdb_client_init(proxy_num, stub_num);
	auto cl_8 = make_scope_exit(exmdb_client_stop);
	table_size = pconfig->get_ll("user_table_size");
	printf("[system]: hash table size is %d\n", table_size);

	cache_interval = pconfig->get_ll("user_cache_interval");
	itvltoa(cache_interval, temp_buff);
	printf("[system]: cache interval is %s\n", temp_buff);
	
	int ping_interval = pconfig->get_ll("mailbox_ping_interval");
	itvltoa(ping_interval, temp_buff);
	printf("[system]: mailbox ping interval is %s\n", temp_buff);
	
	zarafa_server_init(table_size, cache_interval, ping_interval);
	auto cl_7 = make_scope_exit(zarafa_server_stop);
	rpc_parser_init(threads_num);
	auto cl_6 = make_scope_exit(rpc_parser_stop);

	if (service_run_early() != 0) {
		printf("[system]: failed to run PLUGIN_EARLY_INIT\n");
		return 3;
	}
	auto ret = switch_user_exec(*g_config_file, argv);
	if (ret < 0)
		return 3;
	if (0 != service_run()) {
		printf("[system]: failed to run service\n");
		return 3;
	}
	auto cl_1 = make_scope_exit(system_services_stop);
	if (0 != system_services_run()) {
		printf("[system]: failed to run system services\n");
		return 4;
	}
	listener_init();
	auto cl_10 = make_scope_exit(listener_stop);
	if (listener_run(g_config_file->get_value("zcore_listen")) != 0) {
		printf("[system]: failed to run listener\n");
		return 13;
	}
	if (common_util_run(g_config_file->get_value("data_file_path")) != 0) {
		printf("[system]: failed to run common util\n");
		return 5;
	}
	if (bounce_producer_run(g_config_file->get_value("data_file_path")) != 0) {
		printf("[system]: failed to run bounce producer\n");
		return 6;
	}
	if (0 != msgchg_grouping_run()) {
		printf("[system]: failed to run msgchg grouping\n");
		return 7;
	}
	if (0 != ab_tree_run()) {
		printf("[system]: failed to run address book tree\n");
		return 8;
	}
	if (0 != rpc_parser_run()) {
		printf("[system]: failed to run rpc parser\n");
		return 9;
	}
	if (0 != zarafa_server_run()) {
		printf("[system]: failed to run zarafa server\n");
		return 10;
	}
	if (exmdb_client_run_front(g_config_file->get_value("config_file_path")) != 0) {
		printf("[system]: failed to run exmdb client\n");
		return 11;
	}
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
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}
