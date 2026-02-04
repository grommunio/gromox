// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2026 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <libHX/string.h>
#include <vmime/utility/url.hpp>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/database.h>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_common_util.hpp>
#include <gromox/exmdb_provider_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/exmdb_server.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/svc_common.h>
#include <gromox/svc_loader.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "bounce_producer.hpp"
#include "db_engine.hpp"
#include "parser.hpp"

using namespace std::string_literals;
using namespace gromox;
DECLARE_SVC_API(exmdb, );
using namespace exmdb;

static std::shared_ptr<CONFIG_FILE> g_config_during_init, g_config_during_init2;

static constexpr cfg_directive exmdb_gromox_cfg_defaults[] = {
	{"exmdb_deep_backtrace", "0", CFG_BOOL},
	{"exmdb_force_write_txn", "0", CFG_BOOL},
	{"exmdb_ics_log_file", ""},
	{"outgoing_smtp_url", "sendmail://localhost"},
	CFG_TABLE_END,
};

static constexpr cfg_directive exmdb_cfg_defaults[] = {
	{"cache_interval", "15min", CFG_TIME, "1s"},
	{"dbg_synthesize_content", "0"},
	{"enable_dam", "1", CFG_BOOL},
	{"exmdb_body_autosynthesis", "1", CFG_BOOL},
	{"exmdb_eph_prefix", ""},
	{"exmdb_file_compression", "zstd-6"},
	{"exmdb_hosts_allow", ""}, /* ::1 default set later during startup */
	{"exmdb_max_sqlite_spares", "3", CFG_SIZE},
	{"exmdb_pf_read_per_user", "1"},
	{"exmdb_pf_read_states", "2"},
	{"exmdb_private_folder_softdelete", "1", CFG_BOOL},
	{"exmdb_schema_upgrades", "auto"},
	{"exmdb_search_nice", "0"},
	{"exmdb_search_pacing", "250", CFG_SIZE},
	{"exmdb_search_pacing_time", "0.5s", CFG_TIME_NS},
	{"exmdb_search_yield", "0", CFG_BOOL},
	{"exrpc_debug", "0"},
	{"listen_port", "exmdb_listen_port", CFG_ALIAS},
	{"max_ext_rule_number", "20", CFG_SIZE, "1", "100"},
	{"max_router_connections", "4095M", CFG_SIZE},
	{"max_rpc_stub_threads", "4095M", CFG_SIZE},
	{"max_rule_number", "1000", CFG_SIZE, "1", "2000"},
	{"max_store_message_count", "0", CFG_SIZE},
	{"notify_stub_threads_num", "4", CFG_SIZE, "0"},
	{"populating_threads_num", "4", CFG_SIZE, "1", "50"},
	{"rpc_proxy_connection_num", "10", CFG_SIZE, "0"},
	{"sqlite_debug", "0"},
	{"sqlite_busy_timeout", "60s", CFG_TIME_NS, "0s", "1h"},
	{"table_size", "5000", CFG_SIZE, "100"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

unsigned int g_dbg_synth_content;

static bool exmdb_provider_reload(std::shared_ptr<config_file> gxcfg = nullptr,
    std::shared_ptr<CONFIG_FILE> pconfig = nullptr)
{
	if (pconfig == nullptr)
		pconfig = config_file_initd("exmdb_provider.cfg", get_config_path(),
		          exmdb_cfg_defaults);
	if (pconfig == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd exmdb_provider.cfg: %s",
		       strerror(errno));
		return false;
	}
	if (gxcfg == nullptr)
		gxcfg = config_file_initd("gromox.cfg", get_config_path(),
		        exmdb_gromox_cfg_defaults);
	if (gxcfg == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd gromox.cfg: %s",
		       strerror(errno));
		return false;
	}
	g_exrpc_debug = pconfig->get_ll("exrpc_debug");
	gx_sqlite_debug = pconfig->get_ll("sqlite_debug");
	g_dbg_synth_content = pconfig->get_ll("dbg_synthesize_content");
	g_enable_dam = parse_bool(pconfig->get_value("enable_dam"));
	exmdb_body_autosynthesis = pconfig->get_ll("exmdb_body_autosynthesis");
	exmdb_pf_read_per_user = pconfig->get_ll("exmdb_pf_read_per_user");
	exmdb_pf_read_states = pconfig->get_ll("exmdb_pf_read_states");
	g_exmdb_pvt_folder_softdel = pconfig->get_ll("exmdb_private_folder_softdelete");
	g_exmdb_search_pacing = pconfig->get_ll("exmdb_search_pacing");
	g_exmdb_search_yield = pconfig->get_ll("exmdb_search_yield");
	g_exmdb_search_nice = pconfig->get_ll("exmdb_search_nice");
	g_exmdb_search_pacing_time = pconfig->get_ll("exmdb_search_pacing_time");
	g_exmdb_max_sqlite_spares = pconfig->get_ll("exmdb_max_sqlite_spares");
	g_sqlite_busy_timeout_ns = pconfig->get_ll("sqlite_busy_timeout");
	exmdb_eph_prefix = pconfig->get_value("exmdb_eph_prefix");
	gx_sql_deep_backtrace = gxcfg->get_ll("exmdb_deep_backtrace");
	gx_force_write_txn = gxcfg->get_ll("exmdb_force_write_txn");
	auto s = gxcfg->get_value("exmdb_ics_log_file");
	if (s != nullptr)
		g_exmdb_ics_log_file = s;
	s = pconfig->get_value("exmdb_schema_upgrades");
	if (strcmp(s, "auto") == 0)
		g_exmdb_schema_upgrades = EXMDB_UPGRADE_AUTO;
	else if (strcmp(s, "yes") == 0)
		g_exmdb_schema_upgrades = EXMDB_UPGRADE_YES;
	else
		g_exmdb_schema_upgrades = EXMDB_UPGRADE_NO;
	return true;
}

BOOL SVC_exmdb_provider(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	switch(reason) {
	case PLUGIN_RELOAD:
		exmdb_provider_reload();
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
		auto gxcfg = g_config_during_init2 = config_file_initd("gromox.cfg",
		             get_config_path(), exmdb_gromox_cfg_defaults);
		if (gxcfg == nullptr) {
			mlog(LV_ERR, "exmdb_provider: config_file_initd exmdb_provider.cfg: %s",
				strerror(errno));
			return FALSE;
		}
		if (!exmdb_provider_reload(gxcfg, pconfig))
			return false;
		g_exmdb_allow_lpc = strcasecmp(get_prog_id(), "istore") == 0;
		if (!g_exmdb_allow_lpc)
			return TRUE;
		if (exmdb_listener_init(*gxcfg, *pconfig) != 0)
			return FALSE;
		return TRUE;
	}
	case PLUGIN_INIT: {
		if (service_run_library({"libgxs_mysql_adaptor.so", SVC_mysql_adaptor}) != PLUGIN_LOAD_OK)
        		return false;
		auto pconfig = std::move(g_config_during_init);
		auto gxcfg = std::move(g_config_during_init2);
		if (gxcfg == nullptr) {
			mlog(LV_ERR, "emsmdb: config_file_initd gromox.cfg: %s",
			       strerror(errno));
			return false;
		}
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
		str = gxcfg->get_value("outgoing_smtp_url");
		std::string smtp_url;
		try {
			smtp_url = vmime::utility::url(str);
		} catch (const vmime::exceptions::malformed_url &e) {
			mlog(LV_ERR, "Malformed URL: outgoing_smtp_url=\"%s\": %s",
				str, e.what());
			return false;
		}

		mlog(LV_INFO, "exmdb_provider: x500=\"%s\", "
		        "rpc_proxyconn_num=%d, notify_stub_threads_num=%d, "
		        "db_hash_table_size=%d, cache_interval=%s, max_msgs_per_store=%d, "
		        "max_rule_per_folder=%d, max_ext_rule_per_folder=%d, popul_num=%d, smtp=%s",
		        org_name, connection_num, threads_num, table_size,
		        cache_int_s, max_msg_count, max_rule, max_ext_rule,
		        populating_num, smtp_url.c_str());

		common_util_init(org_name, max_msg_count, max_rule, max_ext_rule, std::move(smtp_url));
		db_engine_init(table_size, cache_interval, populating_num);
		if (!g_exmdb_allow_lpc)
			exmdb_parser_init(0, 0);
		else
			exmdb_parser_init(max_threads, max_routers);

		exmdb_client.emplace(connection_num, threads_num);
		
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
		if (g_exmdb_allow_lpc && exmdb_listener_run(get_config_path(), *pconfig) != 0) {
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
		return TRUE;
	}
	case PLUGIN_FREE:
		exmdb_listener_stop();
		exmdb_client.reset();
		exmdb_parser_stop();
		db_engine_stop();
		return TRUE;
	default:
		return TRUE;
	}
}
