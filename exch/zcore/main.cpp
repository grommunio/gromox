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
#include <pthread.h>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/misc.h>
#include <libHX/option.h>
#include <libHX/socket.h>
#include <libHX/string.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/atomic.hpp>
#include <gromox/authmgr.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/paths.h>
#include <gromox/scope.hpp>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "ab_tree.h"
#include "bounce_producer.hpp"
#include "common_util.h"
#include "exmdb_client.h"
#include "object_tree.h"
#include "rpc_parser.hpp"
#include "system_services.hpp"
#include "zserver.hpp"

using namespace gromox;

decltype(system_services_auth_login) system_services_auth_login;
decltype(system_services_auth_login_token) system_services_auth_login_token;
#define E(s) decltype(system_services_ ## s) system_services_ ## s;
E(check_same_org)
E(get_domain_groups)
E(get_domain_ids)
E(get_domain_info)
E(get_domain_users)
E(get_group_users)
E(get_homedir)
E(get_id_from_username)
E(get_maildir)
E(get_mlist_ids)
E(get_mlist_memb)
E(get_org_domains)
E(get_timezone)
E(get_user_displayname)
E(get_user_ids)
E(get_user_lang)
E(get_user_privilege_bits)
E(get_username_from_id)
E(setpasswd)
E(set_timezone)
E(set_user_lang)
E(scndstore_hints)
E(meta)
#undef E
int (*system_services_add_timer)(const char *, int);

gromox::atomic_bool g_main_notify_stop;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;
static gromox::atomic_bool g_hup_signalled;
static gromox::atomic_bool g_listener_notify_stop;
static int g_listen_sockd;
static pthread_t g_listener_id;

static constexpr struct HXoption g_options_table[] = {
	{nullptr, 'c', HXTYPE_STRING, &opt_config_file, nullptr, nullptr, 0, "Config file to read", "FILE"},
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static std::vector<std::string> g_dfl_svc_plugins = {
	"libgxs_ldap_adaptor.so",
	"libgxs_mysql_adaptor.so",
	"libgxs_authmgr.so",
	"libgxs_timer_agent.so",
};

static constexpr cfg_directive zcore_gxcfg_dflt[] = {
	{"backfill_transport_headers", "0", CFG_BOOL},
	CFG_TABLE_END,
};

static constexpr cfg_directive zcore_cfg_defaults[] = {
	{"address_cache_interval", "5min", CFG_TIME, "1min", "1day"},
	{"address_item_num", "100000", CFG_SIZE, "1"},
	{"address_table_size", "3000", CFG_SIZE, "1"},
	{"config_file_path", PKGSYSCONFDIR "/zcore:" PKGSYSCONFDIR},
	{"data_file_path", PKGDATADIR "/zcore:" PKGDATADIR},
	{"default_charset", "utf-8"},
	{"mail_max_length", "64M", CFG_SIZE, "1"},
	{"mailbox_ping_interval", "5min", CFG_TIME, "1min", "1h"},
	{"max_ext_rule_length", "510K", CFG_SIZE, "1"},
	{"max_mail_num", "1000000", CFG_SIZE, "1"},
	{"max_rcpt_num", "256", CFG_SIZE, "1"},
	{"notify_stub_threads_num", "10", CFG_SIZE, "1", "100"},
	{"oxcical_allday_ymd", "1", CFG_BOOL},
	{"rpc_proxy_connection_num", "10", CFG_SIZE, "1", "100"},
	{"smtp_server_ip", "::1"},
	{"smtp_server_port", "25"},
	{"state_path", PKGSTATEDIR},
	{"submit_command", "/usr/bin/php " PKGDATADIR "/sa/submit.php"},
	{"user_cache_interval", "1h", CFG_TIME, "1min", "1day"},
	{"user_table_size", "5000", CFG_SIZE, "100", "50000"},
	{"x500_org_name", "Gromox default"},
	{"zarafa_threads_num", "zcore_threads_num", CFG_ALIAS},
	{"zcore_listen", PKGRUNDIR "/zcore.sock"},
	{"zcore_log_file", "-"},
	{"zcore_log_level", "4" /* LV_NOTICE */},
	{"zcore_max_obh_per_session", "500", CFG_SIZE, "100"},
	{"zcore_threads_num", "10", CFG_SIZE, "1", "1000"},
	{"zrpc_debug", "0"},
	CFG_TABLE_END,
};

static void term_handler(int signo)
{
	g_main_notify_stop = true;
}

static bool zcore_reload_config(std::shared_ptr<CONFIG_FILE> gxcfg,
    std::shared_ptr<CONFIG_FILE> pconfig)
{
	if (gxcfg == nullptr)
		gxcfg = config_file_prg(opt_config_file, "gromox.cfg", zcore_gxcfg_dflt);
	if (opt_config_file != nullptr && gxcfg == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s", opt_config_file, strerror(errno));
		return false;
	}
	zcore_backfill_transporthdr = gxcfg->get_ll("backfill_transport_headers");

	if (pconfig == nullptr)
		pconfig = config_file_prg(opt_config_file, "zcore.cfg",
		          zcore_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr) {
		mlog(LV_ERR, "config_file_init %s: %s",
		       opt_config_file, strerror(errno));
		return false;
	}
	mlog_init(pconfig->get_value("zcore_log_file"), pconfig->get_ll("zcore_log_level"));
	g_zrpc_debug = pconfig->get_ll("zrpc_debug");
	g_oxcical_allday_ymd = pconfig->get_ll("oxcical_allday_ymd");
	zcore_max_obh_per_session = pconfig->get_ll("zcore_max_obh_per_session");
	return true;
}

static int system_services_run()
{
#define E(f, s) do { \
	(f) = reinterpret_cast<decltype(f)>(service_query((s), "system", typeid(*(f)))); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "system_services: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(system_services_get_user_lang, "get_user_lang");
	E(system_services_set_user_lang, "set_user_lang");
	E(system_services_get_maildir, "get_maildir");
	E(system_services_get_homedir, "get_homedir");
	E(system_services_get_timezone, "get_timezone");
	E(system_services_set_timezone, "set_timezone");
	E(system_services_get_username_from_id, "get_username_from_id");
	E(system_services_get_id_from_username, "get_id_from_username");
	E(system_services_get_domain_ids, "get_domain_ids");
	E(system_services_get_user_ids, "get_user_ids");
	E(system_services_auth_login, "auth_login_gen");
	E(system_services_auth_login_token, "auth_login_token");
	E(system_services_get_user_displayname, "get_user_displayname");
	E(system_services_get_org_domains, "get_org_domains");
	E(system_services_get_domain_info, "get_domain_info");
	E(system_services_get_domain_groups, "get_domain_groups");
	E(system_services_get_group_users, "get_group_users");
	E(system_services_get_domain_users, "get_domain_users");
	E(system_services_get_mlist_ids, "get_mlist_ids");
	E(system_services_get_mlist_memb, "get_mlist_memb");
	E(system_services_check_same_org, "check_same_org");
	E(system_services_setpasswd, "set_password");
	E(system_services_get_user_privilege_bits, "get_user_privilege_bits");
	E(system_services_add_timer, "add_timer");
	E(system_services_scndstore_hints, "scndstore_hints");
	return 0;
#undef E
}

static void system_services_stop()
{
#define E(b) service_release(b, "system")
	E("get_user_lang");
	E("set_user_lang");
	E("get_maildir");
	E("get_homedir");
	E("get_timezone");
	E("set_timezone");
	E("get_username_from_id");
	E("get_id_from_username");
	E("get_domain_ids");
	E("get_user_ids");
	E("auth_login_gen");	
	E("auth_login_token");
	E("get_user_displayname");
	E("get_org_domains");
	E("get_domain_info");
	E("get_domain_groups");
	E("get_group_users");
	E("get_domain_users");
	E("get_mlist_ids");
	E("get_mlist_memb");
	E("check_same_org");
	E("set_password");
	E("get_user_privilege_bits");
	E("add_timer");
	E("scndstore_hints");
#undef E
}

static void *zcls_thrwork(void *param)
{
	struct sockaddr_storage unix_addr;

	while (!g_listener_notify_stop) {
		socklen_t len = sizeof(unix_addr);
		memset(&unix_addr, 0, sizeof(unix_addr));
		auto clifd = accept4(g_listen_sockd, reinterpret_cast<struct sockaddr *>(&unix_addr),
		             &len, SOCK_CLOEXEC);
		if (clifd == -1)
			continue;
		if (!rpc_parser_activate_connection(clifd))
			close(clifd);
	}
	return nullptr;
}

static void listener_init()
{
	g_listen_sockd = -1;
	g_listener_notify_stop = true;
}

static int listener_run(const char *sockpath)
{
	g_listen_sockd = HX_local_listen(sockpath);
	if (g_listen_sockd < 0) {
		mlog(LV_ERR, "listen %s: %s", sockpath, strerror(-g_listen_sockd));
		return -1;
	}
	gx_reexec_record(g_listen_sockd);
	if (chmod(sockpath, FMODE_PUBLIC) < 0) {
		close(g_listen_sockd);
		mlog(LV_ERR, "listener: failed to change the access mode of %s", sockpath);
		return -3;
	}
	g_listener_notify_stop = false;
	auto ret = pthread_create4(&g_listener_id, nullptr, zcls_thrwork, nullptr);
	if (ret != 0) {
		close(g_listen_sockd);
		mlog(LV_ERR, "listener: failed to create accept thread: %s", strerror(ret));
		return -5;
	}
	pthread_setname_np(g_listener_id, "accept");
	return 0;
}

static void listener_stop()
{
	g_listener_notify_stop = true;
	if (g_listen_sockd >= 0)
		shutdown(g_listen_sockd, SHUT_RDWR);
	if (!pthread_equal(g_listener_id, {})) {
		pthread_kill(g_listener_id, SIGALRM);
		pthread_join(g_listener_id, nullptr);
	}
	if (g_listen_sockd >= 0)
		close(g_listen_sockd);
	g_listen_sockd = -1;
}

int main(int argc, const char **argv) try
{
	char temp_buff[45];
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
	g_config_file = pconfig = config_file_prg(opt_config_file, "zcore.cfg",
	                zcore_cfg_defaults);
	if (opt_config_file != nullptr && pconfig == nullptr)
		mlog(LV_ERR, "system: config_file_init %s: %s",
			opt_config_file, strerror(errno));
	if (pconfig == nullptr)
		return EXIT_FAILURE;
	if (!zcore_reload_config(nullptr, pconfig))
		return EXIT_FAILURE;

	msgchg_grouping_init(g_config_file->get_value("data_file_path"));
	auto cl_0c = make_scope_exit(msgchg_grouping_free);
	auto cl_4 = make_scope_exit(msgchg_grouping_stop);
	unsigned int threads_num = pconfig->get_ll("zcore_threads_num");
	mlog(LV_INFO, "system: connection threads number is %d", threads_num);

	service_init({g_config_file->get_value("config_file_path"),
		g_config_file->get_value("data_file_path"),
		g_config_file->get_value("state_path"),
		std::move(g_dfl_svc_plugins), threads_num});
	auto cl_0 = make_scope_exit(service_stop);
	
	unsigned int table_size = pconfig->get_ll("address_table_size");
	mlog(LV_INFO, "system: address table size is %d", table_size);

	int cache_interval = pconfig->get_ll("address_cache_interval");
	HX_unit_seconds(temp_buff, std::size(temp_buff), cache_interval, 0);
	mlog(LV_INFO, "system: address book tree item"
		" cache interval is %s", temp_buff);

	ab_tree_init(g_config_file->get_value("x500_org_name"), table_size, cache_interval);
	auto cl_5 = make_scope_exit(ab_tree_stop);

	auto max_rcpt = pconfig->get_ll("max_rcpt_num");
	mlog(LV_INFO, "system: maximum rcpt number is %lld", max_rcpt);
	
	auto max_mail = pconfig->get_ll("max_mail_num");
	mlog(LV_INFO, "system: maximum mail number is %lld", max_mail);
	
	auto max_length = pconfig->get_ll("mail_max_length");
	HX_unit_size(temp_buff, std::size(temp_buff), max_length, 1024, 0);
	mlog(LV_INFO, "system: maximum mail length is %s", temp_buff);
	
	auto max_rule_len = pconfig->get_ll("max_ext_rule_length");
	HX_unit_size(temp_buff, std::size(temp_buff), max_rule_len, 1024, 0);
	mlog(LV_INFO, "system: maximum extended rule length is %s", temp_buff);
	
	uint16_t smtp_port = pconfig->get_ll("smtp_server_port");
	mlog(LV_NOTICE, "system: SMTP server is [%s]:%hu",
	       g_config_file->get_value("smtp_server_ip"), smtp_port);
	
	common_util_init(g_config_file->get_value("x500_org_name"),
		g_config_file->get_value("default_charset"),
		max_rcpt, max_mail, max_length, max_rule_len,
		g_config_file->get_value("smtp_server_ip"), smtp_port,
		g_config_file->get_value("submit_command"));
	
	int proxy_num = pconfig->get_ll("rpc_proxy_connection_num");
	mlog(LV_INFO, "system: exmdb proxy connection number is %d", proxy_num);
	
	int stub_num = pconfig->get_ll("notify_stub_threads_num");
	mlog(LV_INFO, "system: exmdb notify stub threads number is %d", stub_num);
	
	exmdb_client_init(proxy_num, stub_num);
	auto cl_8 = make_scope_exit(exmdb_client_stop);
	table_size = pconfig->get_ll("user_table_size");
	mlog(LV_INFO, "system: hash table size is %d", table_size);

	cache_interval = pconfig->get_ll("user_cache_interval");
	HX_unit_seconds(temp_buff, std::size(temp_buff), cache_interval, 0);
	mlog(LV_INFO, "system: cache interval is %s", temp_buff);
	
	int ping_interval = pconfig->get_ll("mailbox_ping_interval");
	HX_unit_seconds(temp_buff, std::size(temp_buff), ping_interval, 0);
	mlog(LV_INFO, "system: mailbox ping interval is %s", temp_buff);
	
	zserver_init(table_size, cache_interval, ping_interval);
	auto cl_7 = make_scope_exit(zserver_stop);
	rpc_parser_init(threads_num);
	auto cl_6 = make_scope_exit(rpc_parser_stop);

	if (service_run_early() != 0) {
		mlog(LV_ERR, "system: failed to run PLUGIN_EARLY_INIT");
		return EXIT_FAILURE;
	}
	if (switch_user_exec(*g_config_file, argv) != 0)
		return EXIT_FAILURE;
	if (iconv_validate() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	textmaps_init();
	if (0 != service_run()) {
		mlog(LV_ERR, "system: failed to start services");
		return EXIT_FAILURE;
	}
	auto cl_1 = make_scope_exit(system_services_stop);
	if (0 != system_services_run()) {
		mlog(LV_ERR, "system: failed to start system services");
		return EXIT_FAILURE;
	}
	listener_init();
	auto cl_10 = make_scope_exit(listener_stop);
	if (listener_run(g_config_file->get_value("zcore_listen")) != 0) {
		mlog(LV_ERR, "system: failed to start listener");
		return EXIT_FAILURE;
	}
	if (common_util_run(g_config_file->get_value("data_file_path")) != 0) {
		mlog(LV_ERR, "system: failed to start common util");
		return EXIT_FAILURE;
	}
	if (bounce_gen_init(g_config_file->get_value("config_file_path"),
	    g_config_file->get_value("data_file_path"), "notify_bounce") != 0) {
		mlog(LV_ERR, "system: failed to start bounce producer");
		return EXIT_FAILURE;
	}
	if (0 != msgchg_grouping_run()) {
		mlog(LV_ERR, "system: failed to start msgchg grouping");
		return EXIT_FAILURE;
	}
	if (0 != ab_tree_run()) {
		mlog(LV_ERR, "system: failed to start address book tree");
		return EXIT_FAILURE;
	}
	if (0 != rpc_parser_run()) {
		mlog(LV_ERR, "system: failed to start ZRPC parser");
		return EXIT_FAILURE;
	}
	if (zserver_run() != 0) {
		mlog(LV_ERR, "system: failed to run zserver");
		return EXIT_FAILURE;
	}
	if (exmdb_client_run_front(g_config_file->get_value("config_file_path")) != 0) {
		mlog(LV_ERR, "system: failed to start exmdb client");
		return EXIT_FAILURE;
	}
	sact.sa_handler = term_handler;
	sact.sa_flags   = SA_RESETHAND;
	sigaction(SIGINT, &sact, nullptr);
	sigaction(SIGTERM, &sact, nullptr);
	mlog(LV_NOTICE, "system: zcore is now running");
	while (!g_main_notify_stop) {
		sleep(1);
		if (g_hup_signalled.exchange(false)) {
			zcore_reload_config(nullptr, nullptr);
			service_trigger_all(PLUGIN_RELOAD);
			ab_tree_invalidate_cache();
		}
	}
	return EXIT_SUCCESS;
} catch (const cfg_error &) {
	return EXIT_FAILURE;
}
