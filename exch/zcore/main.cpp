// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdint>
#include <memory>
#include <libHX/option.h>
#include <libHX/string.h>
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

BOOL g_notify_stop = FALSE;
std::shared_ptr<CONFIG_FILE> g_config_file;
static char *opt_config_file;
static unsigned int opt_show_version;

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
	g_notify_stop = TRUE;
}

int main(int argc, const char **argv)
{
	int max_mail;
	int stub_num;
	int mime_num;
	int max_rcpt;
	uint16_t smtp_port;
	int proxy_num;
	int max_length;
	int table_size, threads_num = 0;
	const char *str_value;
	char smtp_ip[40], console_ip[40];
	int max_item_num;
	int max_rule_len;
	int console_port;
	char charset[32];
	char timezone[64];
	int ping_interval;
	char separator[16];
	char org_name[256];
	int cache_interval;
	char temp_buff[45];
	char host_name[256];
	char data_path[256], state_dir[256];
	std::shared_ptr<CONFIG_FILE> pconfig;
	char config_path[256];
	char service_path[256];
	char submit_command[1024];
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	g_config_file = pconfig = config_file_prg(opt_config_file, "zcore.cfg");
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	str_value = config_file_get_value(pconfig, "HOST_ID");
	if (NULL == str_value) {
		gethostname(host_name, 256);
	} else {
		strcpy(host_name, str_value);
	}
	printf("[system]: hostname is %s\n", host_name);
	
	str_value = config_file_get_value(pconfig, "X500_ORG_NAME");
	if (NULL == str_value) {
		HX_strlcpy(org_name, "Gromox default", sizeof(org_name));
		config_file_set_value(pconfig, "X500_ORG_NAME", org_name);
	} else {
		strcpy(org_name, str_value);
	}
	printf("[system]: x500 org name is \"%s\"\n", org_name);
	
	str_value = config_file_get_value(pconfig, "DEFAULT_CHARSET");
	if (NULL == str_value) {
		strcpy(charset, "windows-1252");
		config_file_set_value(pconfig, "DEFAULT_CHARSET", charset);
	} else {
		strcpy(charset, str_value);
	}
	printf("[system]: default charset is \"%s\"\n", charset);

	str_value = config_file_get_value(pconfig, "DEFAULT_TIMEZONE");
	if (NULL == str_value) {
		strcpy(timezone, "Asia/Shanghai");
		config_file_set_value(pconfig, "DEFAULT_TIMEZONE", timezone);
	} else {
		strcpy(timezone, str_value);
	}
	printf("[system]: default timezone is \"%s\"\n", timezone);
	
	str_value = config_file_get_value(pconfig, "SERVICE_PLUGIN_PATH");
	if (NULL == str_value) {
		strcpy(service_path, PKGLIBDIR);
		config_file_set_value(pconfig, "SERVICE_PLUGIN_PATH", service_path);
	} else {
		strcpy(service_path, str_value);
	}
	printf("[system]: service plugin path is %s\n", service_path);
	str_value = config_file_get_value(pconfig, "SERVICE_PLUGIN_LIST");
	const char *const *service_plugin_list = NULL;
	if (str_value != NULL) {
		service_plugin_list = deconst(read_file_by_line(str_value));
		if (service_plugin_list == NULL) {
			printf("read_file_by_line %s: %s\n", str_value, strerror(errno));
			return 2;
		}
	}

	str_value = config_file_get_value(pconfig, "CONFIG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(config_path, PKGSYSCONFDIR "/zcore:" PKGSYSCONFDIR);
		config_file_set_value(pconfig, "config_file_path", config_path);
	} else {
		strcpy(config_path, str_value);
	}
	printf("[system]: config path is %s\n", config_path);
	
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, PKGDATADIR "/zcore:" PKGDATADIR);
	} else {
		strcpy(data_path, str_value);
	}
	printf("[system]: data path is %s\n", data_path);

	str_value = config_file_get_value(pconfig, "STATE_PATH");
	HX_strlcpy(state_dir, str_value != nullptr ? str_value : PKGSTATEDIR, sizeof(state_dir));
	
	msgchg_grouping_init(data_path);
	service_init({service_path, config_path, data_path, state_dir,
		service_plugin_list != NULL ? service_plugin_list : g_dfl_svc_plugins,
		parse_bool(config_file_get_value(g_config_file, "service_plugin_ignore_errors")),
		threads_num});
	
	str_value = config_file_get_value(pconfig, "ADDRESS_TABLE_SIZE");
	if (NULL == str_value) {
		table_size = 3000;
		config_file_set_value(pconfig, "ADDRESS_TABLE_SIZE", "3000");
	} else {
		table_size = atoi(str_value);
		if (table_size <= 0) {
			table_size = 3000;
			config_file_set_value(pconfig, "ADDRESS_TABLE_SIZE", "3000");
		}
	}
	printf("[system]: address table size is %d\n", table_size);
	str_value = config_file_get_value(pconfig, "ADDRESS_CACHE_INTERVAL");
	if (NULL == str_value) {
		cache_interval = 300;
		config_file_set_value(pconfig,
			"ADDRESS_CACHE_INTERVAL", "5minutes");
	} else {
		cache_interval = atoitvl(str_value);
		if (cache_interval > 24*3600 || cache_interval < 60) {
			cache_interval = 300;
			config_file_set_value(pconfig,
				"ADDRESS_CACHE_INTERVAL", "5minutes");
		}
	}
	itvltoa(cache_interval, temp_buff);
	printf("[system]: address book tree item"
		" cache interval is %s\n", temp_buff);
	str_value = config_file_get_value(pconfig, "ADDRESS_ITEM_NUM");
	if (NULL == str_value) {
		max_item_num = 100000;
		config_file_set_value(pconfig, "ADDRESS_ITEM_NUM", "100000");
	} else {
		max_item_num = atoi(str_value);
		if (max_item_num <= 0) {
			max_item_num = 100000;
			config_file_set_value(pconfig, "ADDRESS_ITEM_NUM", "100000");
		}
	}
	printf("[system]: maximum item number is %d\n", max_item_num);
	
	ab_tree_init(org_name, table_size, cache_interval, max_item_num);
	
	str_value = config_file_get_value(pconfig, "SEPARATOR_FOR_BOUNCE");
	if (NULL == str_value) {
		strcpy(separator, ";");
	} else {
		strcpy(separator, str_value);
	}
	
	bounce_producer_init(separator);
	str_value = config_file_get_value(pconfig, "ZARAFA_MIME_NUMBER");
	if (NULL == str_value) {
		mime_num = 4096;
		config_file_set_value(pconfig, "ZARAFA_MIME_NUMBER", "4096");
	} else {
		mime_num = atoi(str_value);
		if (mime_num < 1024) {
			mime_num = 4096;
			config_file_set_value(pconfig, "ZARAFA_MIME_NUMBER", "4096");
		}
	}
	printf("[system]: mime number is %d\n", mime_num);
	
	str_value = config_file_get_value(pconfig, "MAX_RCPT_NUM");
	if (str_value != NULL) {
		max_rcpt = atoi(str_value);
		if (max_rcpt <= 0) {
			max_rcpt = 256;
			config_file_set_value(pconfig, "MAX_RCPT_NUM", "256");
		}
	} else {
		max_rcpt = 256;
		config_file_set_value(pconfig, "MAX_RCPT_NUM", "256");
	}
	printf("[system]: maximum rcpt number is %d\n", max_rcpt);
	
	str_value = config_file_get_value(pconfig, "MAX_MAIL_NUM");
	if (NULL == str_value) {
		max_mail = 1000000;
		config_file_set_value(pconfig, "MAX_MAIL_NUM", "1000000");
	} else {
		max_mail = atoi(str_value);
		if (max_mail <= 0) {
			max_mail = 1000000;
			config_file_set_value(pconfig, "MAX_MAIL_NUM", "1000000");
		}
	}
	printf("[system]: maximum mail number is %d\n", max_mail);
	
	str_value = config_file_get_value(pconfig, "MAIL_MAX_LENGTH");
	if (NULL == str_value) {
		max_length = 64*1024*1024;
		config_file_set_value(pconfig, "MAIL_MAX_LENGTH", "64M");
	} else {
		max_length = atobyte(str_value);
		if (max_length <= 0) {
			max_length = 64*1024*1024;
			config_file_set_value(pconfig, "MAIL_MAX_LENGTH", "64M");
		}
	}
	bytetoa(max_length, temp_buff);
	printf("[system]: maximum mail length is %s\n", temp_buff);
	
	str_value = config_file_get_value(pconfig, "MAX_EXT_RULE_LENGTH");
	if (NULL == str_value) {
		max_rule_len = 510*1024;
		config_file_set_value(pconfig, "MAX_EXT_RULE_LENGTH", "510K");
	} else {
		max_rule_len = atobyte(str_value);
		if (max_rule_len <= 0) {
			max_rule_len = 510*1024;
			config_file_set_value(pconfig, "MAX_EXT_RULE_LENGTH", "510K");
		}
	}
	bytetoa(max_rule_len, temp_buff);
	printf("[system]: maximum extended rule length is %s\n", temp_buff);
	
	str_value = config_file_get_value(pconfig, "SMTP_SERVER_IP");
	HX_strlcpy(smtp_ip, str_value != nullptr ? str_value : "::1",
	           GX_ARRAY_SIZE(smtp_ip));
	str_value = config_file_get_value(pconfig, "SMTP_SERVER_PORT");
	if (NULL == str_value) {
		smtp_port = 25;
		config_file_set_value(pconfig, "SMTP_SERVER_PORT", "25");
	} else {
		smtp_port = atoi(str_value);
		if (smtp_port <= 0) {
			smtp_port = 25;
			config_file_set_value(pconfig, "SMTP_SERVER_PORT", "25");
		}
	}
	printf("[system]: smtp server is [%s]:%hu\n", smtp_ip, smtp_port);
	
	str_value = config_file_get_value(pconfig, "SUBMIT_COMMAND");
	if (str_value == nullptr)
		strcpy(submit_command, "/usr/bin/php " PKGDATADIR "/sa/submit.php");
	else
		strcpy(submit_command, str_value);
	
	str_value = config_file_get_value(pconfig, "FREEBUSY_TOOL_PATH");
	if (NULL == str_value) {
		str_value = PKGLIBEXECDIR "/freebusy";
	}
	common_util_init(org_name, host_name, charset, timezone, mime_num,
		max_rcpt, max_mail, max_length, max_rule_len, smtp_ip, smtp_port,
		str_value, submit_command);
	
	str_value = config_file_get_value(pconfig, "RPC_PROXY_CONNECTION_NUM");
	if (NULL == str_value) {
		proxy_num = 10;
		config_file_set_value(pconfig, "RPC_PROXY_CONNECTION_NUM", "10");
	} else {
		proxy_num = atoi(str_value);
		if (proxy_num <= 0 || proxy_num > 100) {
			config_file_set_value(pconfig, "RPC_PROXY_CONNECTION_NUM", "10");
			proxy_num = 10;
		}
	}
	printf("[system]: exmdb proxy connection number is %d\n", proxy_num);
	
	str_value = config_file_get_value(pconfig, "NOTIFY_STUB_THREADS_NUM");
	if (NULL == str_value) {
		stub_num = 10;
		config_file_set_value(pconfig, "NOTIFY_STUB_THREADS_NUM", "10");
	} else {
		stub_num = atoi(str_value);
		if (stub_num <= 0 || stub_num > 100) {
			stub_num = 10;
			config_file_set_value(pconfig, "NOTIFY_STUB_THREADS_NUM", "10");
		}
	}
	printf("[system]: exmdb notify stub threads number is %d\n", stub_num);
	
	exmdb_client_init(proxy_num, stub_num);
	str_value = config_file_get_value(pconfig, "ZARAFA_THREADS_NUM");
	if (NULL == str_value) {
		threads_num = 100;
		config_file_set_value(pconfig, "ZARAFA_THREADS_NUM", "100");
	} else {
		threads_num = atoi(str_value);
		if (threads_num < 20) {
			threads_num = 20;
			config_file_set_value(pconfig, "ZARAFA_THREADS_NUM", "20");
		} else if (threads_num > 1000) {
			threads_num = 1000;
			config_file_set_value(pconfig, "ZARAFA_THREADS_NUM", "1000");
		}
	}
	printf("[system]: connection threads number is %d\n", threads_num);
	
		
	rpc_parser_init(threads_num);
	auto cleanup_1 = make_scope_exit(rpc_parser_free);
	
	str_value = config_file_get_value(pconfig, "USER_TABLE_SIZE");
	if (NULL == str_value) {
		table_size = 5000;
		config_file_set_value(pconfig, "USER_TABLE_SIZE", "5000");
	} else {
		table_size = atoi(str_value);
		if (table_size < 100) {
			table_size = 100;
			config_file_set_value(pconfig, "USER_TABLE_SIZE", "100");
		} else if (table_size > 50000) {
			table_size = 50000;
			config_file_set_value(pconfig, "USER_TABLE_SIZE", "50000");
		}
	}
	printf("[system]: hash table size is %d\n", table_size);

	str_value = config_file_get_value(pconfig, "USER_CACHE_INTERVAL");
	if (NULL == str_value) {
		cache_interval = 3600;
		config_file_set_value(pconfig, "USER_CACHE_INTERVAL", "1hour");
	} else {
		cache_interval = atoitvl(str_value);
		if (cache_interval < 60 || cache_interval > 24*3600) {
			cache_interval = 3600;
			config_file_set_value(pconfig,
				"USER_CACHE_INTERVAL", "1hour");
		}
	}
	itvltoa(cache_interval, temp_buff);
	printf("[system]: cache interval is %s\n", temp_buff);
	
	str_value = config_file_get_value(pconfig, "MAILBOX_PING_INTERVAL");
	if (NULL == str_value) {
		ping_interval = 300;
		config_file_set_value(pconfig, "MAILBOX_PING_INTERVAL", "5minutes");
	} else {
		ping_interval = atoitvl(str_value);
		if (ping_interval > 3600 || ping_interval < 60) {
			ping_interval = 300;
			config_file_set_value(pconfig,
				"MAILBOX_PING_INTERVAL", "5minutes");
		}
	}
	itvltoa(ping_interval, temp_buff);
	printf("[system]: mailbox ping interval is %s\n", temp_buff);
	
	zarafa_server_init(table_size, cache_interval, ping_interval);
	auto cleanup_2 = make_scope_exit(zarafa_server_free);
	
	str_value = config_file_get_value(pconfig, "CONSOLE_SERVER_IP");
	HX_strlcpy(console_ip, str_value != nullptr ? str_value : "::1",
	           GX_ARRAY_SIZE(console_ip));
	str_value = config_file_get_value(pconfig, "CONSOLE_SERVER_PORT");
	if (NULL == str_value) {
		console_port = 3344;
		config_file_set_value(pconfig, "CONSOLE_SERVER_PORT", "3344");
	} else {
		console_port = atoi(str_value);
		if (console_port <= 0) {
			console_port = 3344;
			config_file_set_value(pconfig, "CONSOLE_SERVER_PORT", "3344");
		}
	}
	printf("[system]: console server address is [%s]:%d\n",
	       *console_ip == '\0' ? "*" : console_ip, console_port);
	console_server_init(console_ip, console_port);
	console_server_register_command("zcore", cmd_handler_zcore_control);
	console_server_register_command("system", cmd_handler_system_control);
	console_server_register_command("help", cmd_handler_help);
	console_server_register_command(nullptr, cmd_handler_service_plugins);

	char CS_PATH[256];
	str_value = config_file_get_value(pconfig, "zcore_listen");
	if (str_value == NULL) {
		HX_strlcpy(CS_PATH, PKGRUNDIR "/zcore.sock", sizeof(CS_PATH));
		config_file_set_value(pconfig, "zcore_listen", CS_PATH);
	} else {
		HX_strlcpy(CS_PATH, str_value, sizeof(CS_PATH));
	}
	listener_init();

	if (0 != service_run()) {
		printf("[system]: failed to run service\n");
		return 3;
	}
	
	if (0 != system_services_run()) {
		printf("[system]: failed to run system services\n");
		return 4;
	}
	if (common_util_run(data_path) != 0) {
		system_services_stop();
		service_stop();
		printf("[system]: failed to run common util\n");
		return 5;
	}
	if (bounce_producer_run(data_path) != 0) {
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run bounce producer\n");
		return 6;
	}
	
	if (0 != msgchg_grouping_run()) {
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run msgchg grouping\n");
		return 7;
	}
	
	if (0 != ab_tree_run()) {
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run address book tree\n");
		return 8;
	}
	
	if (0 != rpc_parser_run()) {
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run rpc parser\n");
		return 9;
	}

	if (0 != zarafa_server_run()) {
		rpc_parser_stop();
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run zarafa server\n");
		return 10;
	}
	if (exmdb_client_run(config_path) != 0) {
		zarafa_server_stop();
		rpc_parser_stop();
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run exmdb client\n");
		return 11;
	}
	
	if (0 != console_server_run()) {
		exmdb_client_stop();
		zarafa_server_stop();
		rpc_parser_stop();
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run console server\n");
		return 12;
	}
	
	if (listener_run(CS_PATH) != 0) {
		console_server_stop();
		exmdb_client_stop();
		zarafa_server_stop();
		rpc_parser_stop();
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: failed to run listener\n");
		return 13;
	}
	
	signal(SIGTERM, term_handler);
	printf("[system]: zcore is now running\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}
	listener_stop();
	console_server_stop();
	exmdb_client_stop();
	rpc_parser_stop();
	zarafa_server_stop();
	ab_tree_stop();
	msgchg_grouping_stop();
	bounce_producer_stop();
	common_util_stop();
	system_services_stop();
	service_stop();
	return 0;
}
