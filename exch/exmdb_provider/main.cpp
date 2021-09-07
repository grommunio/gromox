// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <string>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/paths.h>
#include "bounce_producer.h"
#include <gromox/svc_common.h>
#include "exmdb_listener.h"
#include "exmdb_client.h"
#include "exmdb_server.h"
#include "exmdb_parser.h"
#include "common_util.h"
#include <gromox/config_file.hpp>
#include "db_engine.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>

using namespace std::string_literals;
using namespace gromox;

DECLARE_API();

/*
 *	console talk for exchange_emsmdb plugin
 *	@param
 *		argc					arguments number
 *		argv [in]				arguments array
 *		result [out]			buffer for retriving result
 *		length					result buffer length
 */
static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 exmdb provider help information:\r\n"
						 "\t%s unload <maildir>\r\n"
						 "\t    --unload the store\r\n"
						 "\t%s info\r\n"
						 "\t    --print the module information";

	if (1 == argc) {
		gx_strlcpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		snprintf(result, length,
			"250 exmdb provider information:\r\n"
			"\talive proxy connections    %d\r\n"
			"\tlost proxy connections     %d\r\n"
			"\talive router connections   %d",
			exmdb_client_get_param(ALIVE_PROXY_CONNECTIONS),
			exmdb_client_get_param(LOST_PROXY_CONNECTIONS),
			exmdb_parser_get_param(ALIVE_ROUTER_CONNECTIONS));
		return;
	}
	if (3 == argc && 0 == strcmp("unload", argv[1])) {
		if (TRUE == exmdb_server_unload_store(argv[2])) {
			gx_strlcpy(result, "250 unload store OK", length);
		} else {
			gx_strlcpy(result, "550 failed to unload store", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
    return;
}

static bool exmdb_provider_reload(std::shared_ptr<CONFIG_FILE> pconfig)
{
	if (pconfig == nullptr)
		pconfig = config_file_initd("exmdb_provider.cfg", get_config_path());
	if (pconfig == nullptr) {
		printf("[exmdb_provider]: config_file_initd exmdb_provider.cfg: %s\n",
		       strerror(errno));
		return false;
	}
	auto v = pconfig->get_value("exrpc_debug");
	g_exrpc_debug = v != nullptr ? strtoul(v, nullptr, 0) : 0;
	return true;
}

static BOOL svc_exmdb_provider(int reason, void **ppdata)
{
	BOOL b_wal;
	BOOL b_async;
	int max_rule;
	int table_size;
	int listen_port;
	int threads_num;
	int max_ext_rule;
	char separator[16];
	char temp_buff[64];
	int cache_interval;
	int connection_num;
	int populating_num;
	char listen_ip[40];
	char org_name[256];

	switch(reason) {
	case PLUGIN_RELOAD:
		exmdb_provider_reload(nullptr);
		return TRUE;
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		exmdb_rpc_alloc = common_util_alloc;
		exmdb_rpc_free = [](void *) {};
		exmdb_rpc_exec = exmdb_client_do_rpc;
		std::string cfg_path = get_plugin_name();
		auto pos = cfg_path.find_last_of('.');
		if (pos != cfg_path.npos)
			cfg_path.erase(pos);
		cfg_path += ".cfg";
		auto pconfig = config_file_initd(cfg_path.c_str(), get_config_path());
		if (NULL == pconfig) {
			printf("[exmdb_provider]: config_file_initd %s: %s\n",
			       cfg_path.c_str(), strerror(errno));
			return FALSE;
		}
		
		auto str_value = pconfig->get_value("SEPARATOR_FOR_BOUNCE");
		gx_strlcpy(separator, str_value == nullptr ? ";" : str_value, GX_ARRAY_SIZE(separator));
		str_value = pconfig->get_value("X500_ORG_NAME");
		gx_strlcpy(org_name, str_value == nullptr || *str_value == '\0' ?
			"Gromox default" : str_value, GX_ARRAY_SIZE(org_name));
		printf("[exmdb_provider]: x500 org name is \"%s\"\n", org_name);
		
		str_value = pconfig->get_value("LISTEN_IP");
		gx_strlcpy(listen_ip, str_value != nullptr ? str_value : "::1",
		           GX_ARRAY_SIZE(listen_ip));
		str_value = pconfig->get_value("LISTEN_PORT");
		listen_port = str_value != nullptr ? strtoul(str_value, nullptr, 0) : 5000;
		printf("[exmdb_provider]: listen address is [%s]:%d\n",
		       *listen_ip == '\0' ? "*" : listen_ip, listen_port);
		
		str_value = pconfig->get_value("RPC_PROXY_CONNECTION_NUM");
		if (NULL == str_value) {
			connection_num = 10;
		} else {
			connection_num = atoi(str_value);
			if (connection_num < 0) {
				connection_num = 0;
			}
		}
		printf("[exmdb_provider]: exmdb rpc proxy "
			"connection number is %d\n", connection_num);
			
		str_value = pconfig->get_value("NOTIFY_STUB_THREADS_NUM");
		if (NULL == str_value) {
			threads_num = 4;
		} else {
			threads_num = atoi(str_value);
			if (threads_num < 0) {
				threads_num = 0;
			}
		}
		printf("[exmdb_provider]: exmdb notify stub "
			"threads number is %d\n", threads_num);
		
		str_value = pconfig->get_value("MAX_RPC_STUB_THREADS");
		size_t max_threads = str_value != nullptr ? strtoull(str_value, nullptr, 0) : SIZE_MAX;
		str_value = pconfig->get_value("MAX_ROUTER_CONNECTIONS");
		size_t max_routers = str_value != nullptr ? strtoull(str_value, nullptr, 0) : SIZE_MAX;
		
		str_value = pconfig->get_value("TABLE_SIZE");
		table_size = str_value != nullptr ? strtol(str_value, nullptr, 0) : 5000;
		if (table_size < 100)
			table_size = 100;
		printf("[exmdb_provider]: db hash table size is %d\n", table_size);
		
		str_value = pconfig->get_value("CACHE_INTERVAL");
		if (NULL == str_value) {
			cache_interval = 7200;
		} else {
			cache_interval = atoitvl(str_value);
			if (cache_interval < 1)
				cache_interval = 1800;
		}
		itvltoa(cache_interval, temp_buff);
		printf("[exmdb_provider]: cache interval is %s\n", temp_buff);
		
		str_value = pconfig->get_value("MAX_STORE_MESSAGE_COUNT");
		int max_msg_count = str_value == nullptr ? 200000 : atoi(str_value);
		printf("[exmdb_provider]: maximum message "
			"count per store is %d\n", max_msg_count);
		
		str_value = pconfig->get_value("MAX_RULE_NUMBER");
		max_rule = str_value != nullptr ? strtol(str_value, nullptr, 0) : 1000;
		if (max_rule <= 0 || max_rule > 2000)
			max_rule = 1000;
		printf("[exmdb_provider]: maximum rule "
			"number per folder is %d\n", max_rule);
		
		str_value = pconfig->get_value("MAX_EXT_RULE_NUMBER");
		max_ext_rule = str_value != nullptr ? strtol(str_value, nullptr, 0) : 20;
		if (max_ext_rule <= 0 || max_ext_rule > 100)
			max_ext_rule = 20;
		printf("[exmdb_provider]: maximum ext rule "
			"number per folder is %d\n", max_ext_rule);
		
		str_value = pconfig->get_value("SQLITE_SYNCHRONOUS");
		b_async = str_value == nullptr || strcasecmp(str_value, "OFF") == 0 ||
		          strcasecmp(str_value, "FALSE") == 0 ? false : TRUE;
		printf("[exmdb_provider]: sqlite synchronous PRAGMA is %s\n", b_async ? "ON" : "OFF");
		
		str_value = pconfig->get_value("SQLITE_WAL_MODE");
		b_wal = str_value == nullptr ? TRUE :
		        strcasecmp(str_value, "OFF") == 0 ||
		        strcasecmp(str_value, "FALSE") == 0 ? false : TRUE;
		printf("[exmdb_provider]: sqlite journal mode is %s\n", b_wal ? "WAL" : "DELETE");
		
		str_value = pconfig->get_value("SQLITE_MMAP_SIZE");
		uint64_t mmap_size = str_value != nullptr ? atobyte(str_value) : 0;
		if (0 == mmap_size) {
			printf("[exmdb_provider]: sqlite mmap_size is disabled\n");
		} else {
			bytetoa(mmap_size, temp_buff);
			printf("[exmdb_provider]: sqlite mmap_size is %s\n", temp_buff);
		}
		
		str_value = pconfig->get_value("POPULATING_THREADS_NUM");
		populating_num = str_value != nullptr ? strtol(str_value, nullptr, 0) : 4;
		if (populating_num <= 0 || populating_num > 50)
			populating_num = 10;
		printf("[exmdb_provider]: populating threads"
				" number is %d\n", populating_num);
		if (!exmdb_provider_reload(pconfig))
			return false;
		
		common_util_init(org_name, max_msg_count, max_rule, max_ext_rule);
		bounce_producer_init(separator);
		db_engine_init(table_size, cache_interval,
			b_async, b_wal, mmap_size, populating_num);
		exmdb_server_init();
		if (0 == listen_port) {
			exmdb_parser_init(0, 0);
		} else {
			exmdb_parser_init(max_threads, max_routers);
		}
		exmdb_listener_init(listen_ip, listen_port);
		exmdb_client_init(connection_num, threads_num);
		
		if (bounce_producer_run(get_data_path()) != 0) {
			printf("[exmdb_provider]: failed to run bounce producer\n");
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}
		if (0 != db_engine_run()) {
			printf("[exmdb_provider]: failed to run db engine\n");
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}
		if (0 != exmdb_server_run()) {
			printf("[exmdb_provider]: failed to run exmdb server\n");
			db_engine_stop();
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}
		if (exmdb_parser_run(get_config_path()) != 0) {
			printf("[exmdb_provider]: failed to run exmdb parser\n");
			exmdb_server_stop();
			db_engine_stop();
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}
		if (exmdb_listener_run(get_config_path()) != 0) {
			printf("[exmdb_provider]: failed to run exmdb listener\n");
			exmdb_parser_stop();
			exmdb_server_stop();
			db_engine_stop();
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}
		if (0 != exmdb_listener_trigger_accept()) {
			printf("[exmdb_provider]: fail to trigger exmdb listener\n");
			exmdb_listener_stop();
			exmdb_parser_stop();
			exmdb_server_stop();
			db_engine_stop();
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}
		if (exmdb_client_run(get_config_path()) != 0) {
			printf("[exmdb_provider]: failed to run exmdb client\n");
			exmdb_listener_stop();
			exmdb_parser_stop();
			exmdb_server_stop();
			db_engine_stop();
			exmdb_server_free();
			db_engine_free();
			common_util_free();
			return FALSE;
		}

#define EXMIDL(n, p) register_service("exmdb_client_" #n, exmdb_client::n);
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
		register_service("exmdb_client_register_proc", exmdb_server_register_proc);
		register_service("pass_service", common_util_pass_service);
		if (FALSE == register_talk(console_talk)) {
			printf("[exmdb_provider]: failed to register console talk\n");
			return FALSE;
		}
		
		return TRUE;
	}
	case PLUGIN_FREE:
		exmdb_client_stop();
		exmdb_listener_stop();
		exmdb_parser_stop();
		exmdb_server_stop();
		db_engine_stop();
		exmdb_server_free();
		db_engine_free();
		common_util_free();
		return TRUE;
	}
	return TRUE;
}
SVC_ENTRY(svc_exmdb_provider);
