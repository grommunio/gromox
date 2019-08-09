#include "util.h"
#include "service.h"
#include "ab_tree.h"
#include "listener.h"
#include "mail_func.h"
#include "rpc_parser.h"
#include "common_util.h"
#include "config_file.h"
#include "exmdb_client.h"
#include "zarafa_server.h"
#include "console_server.h"
#include "msgchg_grouping.h"
#include "bounce_producer.h"
#include "system_services.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>

BOOL g_notify_stop = FALSE;

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

int main(int argc, char **argv)
{
	int max_mail;
	int stub_num;
	int mime_num;
	int max_rcpt;
	int smtp_port;
	int proxy_num;
	int max_length;
	int table_size;
	int threads_num;
	char *str_value;
	char smtp_ip[16];
	int max_item_num;
	int max_rule_len;
	int console_port;
	char charset[32];
	char timezone[64];
	int ping_interval;
	char separator[16];
	char org_name[256];
	int cache_interval;
	char temp_buff[32];
	char host_name[256];
	char console_ip[16];
	char data_path[256];
	char exmdb_path[256];
	CONFIG_FILE *pconfig;
	char config_path[256];
	char service_path[256];
	char resource_path[256];
	char grouping_path[256];
	
	
	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", ZCORE_VERSION);
		return 0;
	}
	umask(0);	
	signal(SIGPIPE, SIG_IGN);
	
	pconfig = config_file_init(argv[1]);
	if (NULL == pconfig) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return -2;
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
		strcpy(org_name, "gridware information");
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
		strcpy(service_path, "../service_plugins/zcore");
		config_file_set_value(pconfig, "SERVICE_PLUGIN_PATH",
			"../service_plugins/zcore");
	} else {
		strcpy(service_path, str_value);
	}
	printf("[system]: service plugin path is %s\n", service_path);

	str_value = config_file_get_value(pconfig, "CONFIG_FILE_PATH");
	if (NULL == str_value) {
		strcpy(config_path, "../config/zcore");	
	} else {
		strcpy(config_path, str_value);
	}
	printf("[system]: config path is %s\n", config_path);
	
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data/zcore");	
	} else {
		strcpy(data_path, str_value);
	}
	printf("[system]: data path is %s\n", data_path);
	
	sprintf(exmdb_path, "%s/exmdb_list.txt", data_path);
	printf("[system]: exmdb file path is %s\n", exmdb_path);
	sprintf(resource_path, "%s/notify_bounce", data_path);
	sprintf(grouping_path, "%s/msgchg_grouping", data_path);
	
	msgchg_grouping_init(grouping_path);
	service_init(threads_num, service_path, config_path, data_path);
	
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
		strcpy(separator, " ");
	} else {
		strcpy(separator, str_value);
	}
	
	bounce_producer_init(resource_path, separator);
	
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
	if (NULL == str_value) {
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
	if (NULL == str_value) {
		strcpy(smtp_ip, "127.0.0.1");
		config_file_set_value(pconfig, "SMTP_SERVER_IP", "127.0.0.1");
	} else {
		if (NULL == extract_ip(str_value, smtp_ip)) {
			strcpy(smtp_ip, "127.0.0.1");
			config_file_set_value(pconfig, "SMTP_SERVER_IP", "127.0.0.1");
		}
	}
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
	printf("[system]: smtp server is %s:%d\n", smtp_ip, smtp_port);
	
	common_util_init(org_name, host_name, charset, timezone, mime_num,
		max_rcpt, max_mail, max_length, max_rule_len, smtp_ip, smtp_port);
	
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
	
	exmdb_client_init(proxy_num, stub_num, exmdb_path);

	str_value = config_file_get_value(pconfig, "ZARAFA_THREADS_NUM");
	if (NULL == str_value) {
		threads_num = 50;
		config_file_set_value(pconfig, "ZARAFA_THREADS_NUM", "50");
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
	
	str_value = config_file_get_value(pconfig, "USER_TABLE_SIZE");
	if (NULL == str_value) {
		table_size = 3000;
		config_file_set_value(pconfig, "USER_TABLE_SIZE", "3000");
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
	
	str_value = config_file_get_value(pconfig, "CONSOLE_SERVER_IP");
	if (NULL == str_value || NULL == extract_ip(str_value, console_ip)) {
		strcpy(console_ip, "127.0.0.1");
		config_file_set_value(pconfig, "CONSOLE_SERVER_IP", "127.0.0.1");
	}
	printf("[system]: console server ip is %s\n", console_ip);
	str_value = config_file_get_value(pconfig, "CONSOLE_SERVER_PORT");
	if (NULL == str_value) {
		console_port = 9900;
		config_file_set_value(pconfig, "CONSOLE_SERVER_PORT", "9900");
	} else {
		console_port = atoi(str_value);
		if (console_port <= 0) {
			console_port = 9900;
			config_file_set_value(pconfig, "CONSOLE_SERVER_PORT", "9900");
		}
	}
	printf("[system]: console server port is %d\n", console_port);
	
	console_server_init(console_ip, console_port);
	
	config_file_save(pconfig);
	config_file_free(pconfig);
	
	system_services_init();
	
	listener_init();

	if (0 != service_run()) {
		printf("[system]: fail to run service\n");
		return -3;
	}
	
	if (0 != system_services_run()) {
		printf("[system]: fail to run system services\n");
		return -4;
	}
	
	if (0 != common_util_run()) {
		system_services_stop();
		service_stop();
		printf("[system]: fail to run common util\n");
		return -5;
	}
	
	if (0 != bounce_producer_run()) {
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to run bounce producer\n");
		return -6;
	}
	
	if (0 != msgchg_grouping_run()) {
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to run msgchg grouping\n");
		return -7;
	}
	
	if (0 != ab_tree_run()) {
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to run address book tree\n");
		return -8;
	}
	
	if (0 != rpc_parser_run()) {
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to run rpc parser\n");
		return -9;
	}

	if (0 != zarafa_server_run()) {
		rpc_parser_stop();
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to run zarafa server\n");
		return -10;
	}
	
	if (0 != exmdb_client_run()) {
		zarafa_server_stop();
		rpc_parser_stop();
		ab_tree_stop();
		msgchg_grouping_stop();
		bounce_producer_stop();
		common_util_stop();
		system_services_stop();
		service_stop();
		printf("[system]: fail to run exmdb client\n");
		return -11;
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
		printf("[system]: fail to run console server\n");
		return -12;
	}
	
	if (0 != listener_run()) {
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
		printf("[system]: fail to run listener\n");
		return -13;
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
