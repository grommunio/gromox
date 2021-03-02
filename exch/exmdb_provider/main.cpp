// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <libHX/string.h>
#include <gromox/defs.h>
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
		strncpy(result, "550 too few arguments", length);
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
			strncpy(result, "250 unload sotre OK", length);
		} else {
			strncpy(result, "550 fail to unload sotre", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
    return;
}

static BOOL svc_exmdb_provider(int reason, void **ppdata)
{
	BOOL b_wal;
	BOOL b_async;
	int max_rule;
	char *psearch;
	int table_size;
	int listen_port;
	int max_routers;
	int max_threads;
	int threads_num;
	int max_ext_rule;
	int max_msg_count;
	uint64_t mmap_size;
	char separator[16];
	char temp_buff[64];
	int cache_interval;
	int connection_num;
	int populating_num;
	char listen_ip[40];
	char org_name[256];
	char file_name[256];
	char config_path[256];

	switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		snprintf(config_path, GX_ARRAY_SIZE(config_path), "%s.cfg", file_name);
		auto pconfig = config_file_initd(config_path, get_config_path());
		if (NULL == pconfig) {
			printf("[exmdb_provider]: config_file_initd %s: %s\n",
			       config_path, strerror(errno));
			return FALSE;
		}
		
		auto str_value = config_file_get_value(pconfig, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_value) {
			strcpy(separator, ";");
		} else {
			strcpy(separator, str_value);
		}
		
		str_value = config_file_get_value(pconfig, "X500_ORG_NAME");
		if (NULL == str_value || '\0' == str_value[0]) {
			HX_strlcpy(org_name, "Gromox default", sizeof(org_name));
		} else {
			strcpy(org_name, str_value);
		}
		printf("[exmdb_provider]: x500 org name is \"%s\"\n", org_name);
		
		str_value = config_file_get_value(pconfig, "LISTEN_IP");
		HX_strlcpy(listen_ip, str_value != nullptr ? str_value : "::1",
		           GX_ARRAY_SIZE(listen_ip));
		str_value = config_file_get_value(pconfig, "LISTEN_PORT");
		listen_port = str_value != nullptr ? strtoul(str_value, nullptr, 0) : 5000;
		printf("[exmdb_provider]: listen address is [%s]:%d\n",
		       *listen_ip == '\0' ? "*" : listen_ip, listen_port);
		
		str_value = config_file_get_value(pconfig, "RPC_PROXY_CONNECTION_NUM");
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
			
		str_value = config_file_get_value(pconfig, "NOTIFY_STUB_THREADS_NUM");
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
		
		str_value = config_file_get_value(pconfig, "MAX_RPC_STUB_THREADS");
		if (NULL == str_value) {
			max_threads = 50;
		} else {
			max_threads = atoi(str_value);
			if (max_threads < 0) {
				max_threads = 0;
			}
		}
		if (0 != max_threads) {
			printf("[exmdb_provider]: exmdb maximum rpc "
				"stub threads number is %d\n", max_threads);
		}
		
		str_value = config_file_get_value(pconfig, "MAX_ROUTER_CONNECTIONS");
		if (NULL == str_value) {
			max_routers = 50;
		} else {
			max_routers = atoi(str_value);
			if (max_routers < 0) {
				max_routers = 0;
			}
		}
		if (0 != max_routers) {
			printf("[exmdb_provider]: exmdb maximum router "
				"connections number is %d\n", max_routers);
		}
		
		str_value = config_file_get_value(pconfig, "TABLE_SIZE");
		if (NULL == str_value) {
			table_size = 5000;
			config_file_set_value(pconfig, "TABLE_SIZE", "5000");
		} else {
			table_size = atoi(str_value);
			if (table_size < 100) {
				table_size = 100;
				config_file_set_value(pconfig, "TABLE_SIZE", "100");
			}
		}
		printf("[exmdb_provider]: db hash table size is %d\n", table_size);
		
		str_value = config_file_get_value(pconfig, "CACHE_INTERVAL");
		if (NULL == str_value) {
			cache_interval = 7200;
			config_file_set_value(pconfig, "CACHE_INTERVAL", "2 hours");
		} else {
			cache_interval = atoitvl(str_value);
			if (cache_interval < 600) {
				cache_interval = 1800;
				config_file_set_value(pconfig,
					"MIDB_CACHE_INTERVAL", "30minutes");
			}
		}
		itvltoa(cache_interval, temp_buff);
		printf("[exmdb_provider]: cache interval is %s\n", temp_buff);
		
		str_value = config_file_get_value(pconfig, "MAX_STORE_MESSAGE_COUNT");
		if (NULL == str_value) {
			max_msg_count = 200000;
		} else {
			max_msg_count = atoi(str_value);
		}
		printf("[exmdb_provider]: maximum message "
			"count per store is %d\n", max_msg_count);
		
		str_value = config_file_get_value(pconfig, "MAX_RULE_NUMBER");
		if (NULL == str_value) {
			max_rule = 1000;
			config_file_set_value(pconfig, "MAX_RULE_NUMBER", "1000");
		} else {
			max_rule = atoi(str_value);
			if (max_rule <= 0 || max_rule > 2000) {
				max_rule = 1000;
				config_file_set_value(pconfig, "MAX_RULE_NUMBER", "1000");
			}
		}
		printf("[exmdb_provider]: maximum rule "
			"number per folder is %d\n", max_rule);
		
		str_value = config_file_get_value(pconfig, "MAX_EXT_RULE_NUMBER");
		if (NULL == str_value) {
			max_ext_rule = 20;
			config_file_set_value(pconfig, "MAX_EXT_RULE_NUMBER", "20");
		} else {
			max_ext_rule = atoi(str_value);
			if (max_ext_rule <= 0 || max_ext_rule > 100) {
				max_ext_rule = 20;
				config_file_set_value(pconfig, "MAX_EXT_RULE_NUMBER", "20");
			}
		}
		printf("[exmdb_provider]: maximum ext rule "
			"number per folder is %d\n", max_ext_rule);
		
		str_value = config_file_get_value(pconfig, "SQLITE_SYNCHRONOUS");
		if (NULL == str_value) {
			b_async = FALSE;
			config_file_set_value(pconfig, "SQLITE_SYNCHRONOUS", "OFF");
		} else {
			if (0 == strcasecmp(str_value, "OFF") ||
				0 == strcasecmp(str_value, "FALSE")) {
				b_async = FALSE;	
			} else {
				b_async = TRUE;
			}
		}
		if (FALSE == b_async) {
			printf("[exmdb_provider]: sqlite synchronous PRAGMA is OFF\n");
		} else {
			printf("[exmdb_provider]: sqlite synchronous PRAGMA is ON\n");
		}
		
		str_value = config_file_get_value(pconfig, "SQLITE_WAL_MODE");
		if (NULL == str_value) {
			b_wal = TRUE;
			config_file_set_value(pconfig, "SQLITE_WAL_MODE", "ON");
		} else {
			if (0 == strcasecmp(str_value, "OFF") ||
				0 == strcasecmp(str_value, "FALSE")) {
				b_wal = FALSE;	
			} else {
				b_wal = TRUE;
			}
		}
		if (FALSE == b_wal) {
			printf("[exmdb_provider]: sqlite journal mode is DELETE\n");
		} else {
			printf("[exmdb_provider]: sqlite journal mode is WAL\n");
		}
		
		str_value = config_file_get_value(pconfig, "SQLITE_MMAP_SIZE");
		if (NULL != str_value) {
			mmap_size = atobyte(str_value);
		} else {
			mmap_size = 0;
		}
		if (0 == mmap_size) {
			printf("[exmdb_provider]: sqlite mmap_size is disabled\n");
		} else {
			bytetoa(mmap_size, temp_buff);
			printf("[exmdb_provider]: sqlite mmap_size is %s\n", temp_buff);
		}
		
		str_value = config_file_get_value(pconfig, "POPULATING_THREADS_NUM");
		if (NULL == str_value) {
			populating_num = 4;
			config_file_set_value(pconfig, "POPULATING_THREADS_NUM", "4");
		} else {
			populating_num = atoi(str_value);
			if (populating_num <= 0 || populating_num > 50) {
				populating_num = 10;
				config_file_set_value(pconfig, "POPULATING_THREADS_NUM", "10");
			}
		}
		printf("[exmdb_provider]: populating threads"
				" number is %d\n", populating_num);
		
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
		
		if (0 != common_util_run()) {
			printf("[exmdb_provider]: failed to run common util\n");
			return FALSE;
		}
		if (bounce_producer_run(get_data_path()) != 0) {
			printf("[exmdb_provider]: failed to run bounce producer\n");
			return FALSE;
		}
		if (0 != db_engine_run()) {
			printf("[exmdb_provider]: failed to run db engine\n");
			return FALSE;
		}
		if (0 != exmdb_server_run()) {
			printf("[exmdb_provider]: failed to run exmdb server\n");
			return FALSE;
		}
		if (exmdb_parser_run(get_config_path()) != 0) {
			printf("[exmdb_provider]: failed to run exmdb parser\n");
			return FALSE;
		}
		if (exmdb_listener_run(get_config_path()) != 0) {
			printf("[exmdb_provider]: failed to run exmdb listener\n");
			return FALSE;
		}
		if (0 != exmdb_listener_trigger_accept()) {
			printf("[exmdb_provider]: fail to trigger exmdb listener\n");
			return FALSE;
		}
		if (exmdb_client_run(get_config_path()) != 0) {
			printf("[exmdb_provider]: failed to run exmdb client\n");
			return FALSE;
		}

#define E(f) register_service(#f, f)
		E(exmdb_client_ping_store);
		E(exmdb_client_get_all_named_propids);
		E(exmdb_client_get_named_propids);
		E(exmdb_client_get_named_propnames);
		E(exmdb_client_get_mapping_guid);
		E(exmdb_client_get_mapping_replid);
		E(exmdb_client_get_store_all_proptags);
		E(exmdb_client_get_store_properties);
		E(exmdb_client_set_store_properties);
		E(exmdb_client_remove_store_properties);
		E(exmdb_client_check_mailbox_permission);
		E(exmdb_client_get_folder_by_class);
		E(exmdb_client_set_folder_by_class);
		E(exmdb_client_get_folder_class_table);
		E(exmdb_client_check_folder_id);
		E(exmdb_client_check_folder_deleted);
		E(exmdb_client_get_folder_by_name);
		E(exmdb_client_check_folder_permission);
		E(exmdb_client_create_folder_by_properties);
		E(exmdb_client_get_folder_all_proptags);
		E(exmdb_client_get_folder_properties);
		E(exmdb_client_set_folder_properties);
		E(exmdb_client_remove_folder_properties);
		E(exmdb_client_delete_folder);
		E(exmdb_client_empty_folder);
		E(exmdb_client_check_folder_cycle);
		E(exmdb_client_copy_folder_internal);
		E(exmdb_client_get_search_criteria);
		E(exmdb_client_set_search_criteria);
		E(exmdb_client_movecopy_message);
		E(exmdb_client_movecopy_messages);
		E(exmdb_client_movecopy_folder);
		E(exmdb_client_delete_messages);
		E(exmdb_client_get_message_brief);
		E(exmdb_client_sum_hierarchy);
		E(exmdb_client_load_hierarchy_table);
		E(exmdb_client_sum_content);
		E(exmdb_client_load_content_table);
		E(exmdb_client_reload_content_table);
		E(exmdb_client_load_permission_table);
		E(exmdb_client_load_rule_table);
		E(exmdb_client_unload_table);
		E(exmdb_client_sum_table);
		E(exmdb_client_query_table);
		E(exmdb_client_match_table);
		E(exmdb_client_locate_table);
		E(exmdb_client_read_table_row);
		E(exmdb_client_mark_table);
		E(exmdb_client_get_table_all_proptags);
		E(exmdb_client_expand_table);
		E(exmdb_client_collapse_table);
		E(exmdb_client_store_table_state);
		E(exmdb_client_restore_table_state);
		E(exmdb_client_check_message);
		E(exmdb_client_check_message_deleted);
		E(exmdb_client_load_message_instance);
		E(exmdb_client_load_embedded_instance);
		E(exmdb_client_get_embedded_cn);
		E(exmdb_client_reload_message_instance);
		E(exmdb_client_clear_message_instance);
		E(exmdb_client_read_message_instance);
		E(exmdb_client_write_message_instance);
		E(exmdb_client_load_attachment_instance);
		E(exmdb_client_create_attachment_instance);
		E(exmdb_client_read_attachment_instance);
		E(exmdb_client_write_attachment_instance);
		E(exmdb_client_delete_message_instance_attachment);
		E(exmdb_client_flush_instance);
		E(exmdb_client_unload_instance);
		E(exmdb_client_get_instance_all_proptags);
		E(exmdb_client_get_instance_properties);
		E(exmdb_client_set_instance_properties);
		E(exmdb_client_remove_instance_properties);
		E(exmdb_client_check_instance_cycle);
		E(exmdb_client_empty_message_instance_rcpts);
		E(exmdb_client_get_message_instance_rcpts_num);
		E(exmdb_client_get_message_instance_rcpts_all_proptags);
		E(exmdb_client_get_message_instance_rcpts);
		E(exmdb_client_update_message_instance_rcpts);
		E(exmdb_client_empty_message_instance_attachments);
		E(exmdb_client_get_message_instance_attachments_num);
		E(exmdb_client_get_message_instance_attachment_table_all_proptags);
		E(exmdb_client_query_message_instance_attachment_table);
		E(exmdb_client_set_message_instance_conflict);
		E(exmdb_client_get_message_rcpts);
		E(exmdb_client_get_message_properties);
		E(exmdb_client_set_message_properties);
		E(exmdb_client_set_message_read_state);
		E(exmdb_client_remove_message_properties);
		E(exmdb_client_allocate_message_id);
		E(exmdb_client_allocate_cn);
		E(exmdb_client_get_message_group_id);
		E(exmdb_client_set_message_group_id);
		E(exmdb_client_save_change_indices);
		E(exmdb_client_get_change_indices);
		E(exmdb_client_mark_modified);
		E(exmdb_client_try_mark_submit);
		E(exmdb_client_clear_submit);
		E(exmdb_client_link_message);
		E(exmdb_client_unlink_message);
		E(exmdb_client_rule_new_message);
		E(exmdb_client_set_message_timer);
		E(exmdb_client_get_message_timer);
		E(exmdb_client_empty_folder_permission);
		E(exmdb_client_update_folder_permission);
		E(exmdb_client_empty_folder_rule);
		E(exmdb_client_update_folder_rule);
		E(exmdb_client_write_message);
		E(exmdb_client_delivery_message);
		E(exmdb_client_read_message);
		E(exmdb_client_get_content_sync);
		E(exmdb_client_get_hierarchy_sync);
		E(exmdb_client_allocate_ids);
		E(exmdb_client_subscribe_notification);
		E(exmdb_client_unsubscribe_notification);
		E(exmdb_client_transport_new_mail);
		E(exmdb_client_copy_instance_rcpts);
		E(exmdb_client_copy_instance_attachments);
		E(exmdb_client_check_contact_address);
		E(exmdb_client_get_public_folder_unread_count);
#undef E
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
		bounce_producer_stop();
		common_util_stop();
		exmdb_parser_free();
		exmdb_server_free();
		db_engine_free();
		bounce_producer_free();
		common_util_free();
		return TRUE;
	}
	return false;
}
SVC_ENTRY(svc_exmdb_provider);
