// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <libHX/string.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_provider_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/paths.h>
#include <gromox/svc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "db_engine.h"
#include "exmdb_listener.h"
#include "exmdb_parser.h"

using namespace std::string_literals;
using namespace gromox;

DECLARE_SVC_API();

static std::shared_ptr<CONFIG_FILE> g_config_during_init;

static constexpr cfg_directive exmdb_cfg_defaults[] = {
	{"cache_interval", "2h", CFG_TIME, "1s"},
	{"dbg_synthesize_content", "0"},
	{"enable_dam", "1", CFG_BOOL},
	{"exmdb_body_autosynthesis", "1", CFG_BOOL},
	{"exmdb_file_compression", "zstd-6"},
	{"exmdb_hosts_allow", ""}, /* ::1 default set later during startup */
	{"exmdb_listen_port", "5000"},
	{"exmdb_pf_read_per_user", "1"},
	{"exmdb_pf_read_states", "2"},
	{"exmdb_private_folder_softdelete", "0", CFG_BOOL},
	{"exmdb_schema_upgrades", "auto"},
	{"exmdb_search_nice", "0"},
	{"exmdb_search_pacing", "250", CFG_SIZE},
	{"exmdb_search_pacing_time", "0.5s", CFG_TIME_NS},
	{"exmdb_search_yield", "0", CFG_BOOL},
	{"exrpc_debug", "0"},
	{"listen_ip", "::1"},
	{"listen_port", "exmdb_listen_port", CFG_ALIAS},
	{"max_ext_rule_number", "20", CFG_SIZE, "1", "100"},
	{"max_router_connections", "4095M", CFG_SIZE},
	{"max_rpc_stub_threads", "4095M", CFG_SIZE},
	{"max_rule_number", "1000", CFG_SIZE, "1", "2000"},
	{"max_store_message_count", "0", CFG_SIZE},
	{"mbox_contention_reject", "0", CFG_SIZE},
	{"mbox_contention_warning", "10", CFG_SIZE},
	{"notify_stub_threads_num", "4", CFG_SIZE, "0"},
	{"populating_threads_num", "50", CFG_SIZE, "1", "50"},
	{"rpc_proxy_connection_num", "10", CFG_SIZE, "0"},
	{"sqlite_debug", "0"},
	{"table_size", "5000", CFG_SIZE, "100"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

unsigned int g_dbg_synth_content;
unsigned int g_mbox_contention_warning, g_mbox_contention_reject;

static bool exmdb_provider_reload(std::shared_ptr<CONFIG_FILE> pconfig)
{
	if (pconfig == nullptr)
		pconfig = config_file_initd("exmdb_provider.cfg", get_config_path(),
		          exmdb_cfg_defaults);
	if (pconfig == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd exmdb_provider.cfg: %s",
		       strerror(errno));
		return false;
	}
	g_exrpc_debug = pconfig->get_ll("exrpc_debug");
	gx_sqlite_debug = pconfig->get_ll("sqlite_debug");
	g_dbg_synth_content = pconfig->get_ll("dbg_synthesize_content");
	g_enable_dam = parse_bool(pconfig->get_value("enable_dam"));
	g_mbox_contention_warning = pconfig->get_ll("mbox_contention_warning");
	g_mbox_contention_reject = pconfig->get_ll("mbox_contention_reject");
	exmdb_body_autosynthesis = pconfig->get_ll("exmdb_body_autosynthesis");
	exmdb_pf_read_per_user = pconfig->get_ll("exmdb_pf_read_per_user");
	exmdb_pf_read_states = pconfig->get_ll("exmdb_pf_read_states");
	g_exmdb_pvt_folder_softdel = pconfig->get_ll("exmdb_private_folder_softdelete");
	g_exmdb_search_pacing = pconfig->get_ll("exmdb_search_pacing");
	g_exmdb_search_yield = pconfig->get_ll("exmdb_search_yield");
	g_exmdb_search_nice = pconfig->get_ll("exmdb_search_nice");
	g_exmdb_search_pacing_time = pconfig->get_ll("exmdb_search_pacing_time");
	auto s = pconfig->get_value("exmdb_schema_upgrades");
	if (strcmp(s, "auto") == 0)
		g_exmdb_schema_upgrades = EXMDB_UPGRADE_AUTO;
	else if (strcmp(s, "yes") == 0)
		g_exmdb_schema_upgrades = EXMDB_UPGRADE_YES;
	else
		g_exmdb_schema_upgrades = EXMDB_UPGRADE_NO;
	return true;
}

static BOOL svc_exmdb_provider(int reason, void **ppdata)
{
	switch(reason) {
	case PLUGIN_RELOAD:
		exmdb_provider_reload(nullptr);
		return TRUE;
	case PLUGIN_EARLY_INIT: {
		LINK_SVC_API(ppdata);
		textmaps_init();
		exmdb_rpc_alloc = common_util_alloc;
		exmdb_rpc_free = [](void *) {};
		auto pconfig = g_config_during_init = config_file_initd("exmdb_provider.cfg",
		               get_config_path(), exmdb_cfg_defaults);
		if (NULL == pconfig) {
			mlog(LV_ERR, "exmdb_provider: config_file_initd exmdb_provider.cfg: %s",
				strerror(errno));
			return FALSE;
		}
		if (!exmdb_provider_reload(pconfig))
			return false;

		auto listen_ip = pconfig->get_value("listen_ip");
		uint16_t listen_port = pconfig->get_ll("exmdb_listen_port");
		mlog(LV_NOTICE, "exmdb_provider: listen address is [%s]:%hu",
		       *listen_ip == '\0' ? "*" : listen_ip, listen_port);

		exmdb_listener_init(listen_ip, listen_port);
		if (exmdb_listener_run(get_config_path(),
		    pconfig->get_value("exmdb_hosts_allow")) != 0) {
			mlog(LV_ERR, "exmdb_provider: failed to run exmdb listener");
			return FALSE;
		}
		return TRUE;
	}
	case PLUGIN_INIT: {
		auto pconfig = std::move(g_config_during_init);
		auto org_name = pconfig->get_value("x500_org_name");
		int connection_num = pconfig->get_ll("rpc_proxy_connection_num");
		int threads_num = pconfig->get_ll("notify_stub_threads_num");
		size_t max_threads = pconfig->get_ll("max_rpc_stub_threads");
		size_t max_routers = pconfig->get_ll("max_router_connections");
		int table_size = pconfig->get_ll("table_size");
		char cache_int_s[64];
		int cache_interval = pconfig->get_ll("cache_interval");
		HX_unit_seconds(cache_int_s, std::size(cache_int_s), cache_interval, 0);
		int max_msg_count = pconfig->get_ll("max_store_message_count");
		int max_rule = pconfig->get_ll("max_rule_number");
		int max_ext_rule = pconfig->get_ll("max_ext_rule_number");
		int populating_num = pconfig->get_ll("populating_threads_num");
		mlog(LV_INFO, "exmdb_provider: x500=\"%s\", "
		        "rpc_proxyconn_num=%d, notify_stub_threads_num=%d, "
		        "db_hash_table_size=%d, cache_interval=%s, max_msgs_per_store=%d, "
		        "max_rule_per_folder=%d, max_ext_rule_per_folder=%d, popul_num=%d",
		        org_name, connection_num, threads_num, table_size,
		        cache_int_s, max_msg_count, max_rule, max_ext_rule,
		        populating_num);
		auto str = pconfig->get_value("exmdb_file_compression");
		if (str == nullptr || !parse_bool(str))
			g_cid_compression = 0;
		else if (strcasecmp(str, "yes") == 0 ||
		    strcasecmp(str, "zstd") == 0)
			g_cid_compression = 6;
		else if (strncasecmp(str, "zstd-", 5) == 0)
			g_cid_compression = strtoul(str + 5, nullptr, 0);
		else
			mlog(LV_WARN, "Compression scheme \"%s\" not understood, deactivating", str);
		if (g_cid_compression == 0)
			mlog(LV_INFO, "Content File Compression: off");
		else
			mlog(LV_INFO, "Content File Compression: zstd-%d", g_cid_compression);

		common_util_init(org_name, max_msg_count, max_rule, max_ext_rule);
		db_engine_init(table_size, cache_interval, populating_num);
		uint16_t listen_port = pconfig->get_ll("exmdb_listen_port");
		if (0 == listen_port) {
			exmdb_parser_init(0, 0);
		} else {
			exmdb_parser_init(max_threads, max_routers);
		}
		exmdb_client_init(connection_num, threads_num);
		
		if (bounce_gen_init(get_config_path(), get_data_path(),
		    "mail_bounce") != 0) {
			mlog(LV_ERR, "exmdb_provider: failed to start bounce producer");
			return FALSE;
		}
		if (0 != db_engine_run()) {
			mlog(LV_ERR, "exmdb_provider: failed to start db engine");
			db_engine_stop();
			return FALSE;
		}
		if (exmdb_parser_run(get_config_path()) != 0) {
			mlog(LV_ERR, "exmdb_provider: failed to start exmdb parser");
			db_engine_stop();
			return FALSE;
		}
		if (0 != exmdb_listener_trigger_accept()) {
			mlog(LV_ERR, "exmdb_provider: failed to start exmdb listener");
			exmdb_listener_stop();
			exmdb_parser_stop();
			db_engine_stop();
			return FALSE;
		}
		if (exmdb_client_run_front(get_config_path()) != 0) {
			mlog(LV_ERR, "exmdb_provider: failed to start exmdb client");
			exmdb_listener_stop();
			exmdb_parser_stop();
			db_engine_stop();
			return FALSE;
		}

#define EXMIDL(n, p) register_service("exmdb_client_" #n, exmdb_client_local::n);
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
		register_service("exmdb_client_register_proc", exmdb_server::register_proc);
		register_service("pass_service", common_util_pass_service);

#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "exmdb: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

		E(common_util_get_user_ids, "get_user_ids");
		E(common_util_get_domain_ids, "get_domain_ids");
		E(common_util_get_maildir, "get_maildir");
		E(common_util_get_homedir, "get_homedir");
		E(common_util_get_id_from_maildir, "get_id_from_maildir");
		E(common_util_get_id_from_homedir, "get_id_from_homedir");
		E(common_util_get_id_from_username, "get_id_from_username");
		E(common_util_get_username_from_id, "get_username_from_id");
		E(common_util_get_user_displayname, "get_user_displayname");
		E(common_util_check_mlist_include, "check_mlist_include");
		E(common_util_get_user_lang, "get_user_lang");
		E(common_util_get_timezone, "get_timezone");

#undef E
		return TRUE;
	}
	case PLUGIN_FREE:
		exmdb_client_stop();
		exmdb_listener_stop();
		exmdb_parser_stop();
		db_engine_stop();
		return TRUE;
	}
	return TRUE;
}

SVC_ENTRY(svc_exmdb_provider);
