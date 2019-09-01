#include "bounce_producer.h"
#include "service_common.h"
#include "exmdb_listener.h"
#include "exmdb_client.h"
#include "exmdb_server.h"
#include "exmdb_parser.h"
#include "common_util.h"
#include "config_file.h"
#include "db_engine.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

DECLARE_API;


/*
 *	console talk for exchange_emsmdb plugin
 *	@param
 *		argc					arguments number
 *		argv [in]				arguments array
 *		result [out]			buffer for retriving result
 *		length					result buffer length
 */
void console_talk(int argc, char **argv, char *result, int length)
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

BOOL SVC_LibMain(int reason, void **ppdata)
{
	BOOL b_wal;
	BOOL b_async;
	int max_rule;
	char *psearch;
	int table_size;
	char *str_value;
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
	char listen_ip[16];
	char acl_path[256];
	char org_name[256];
	char file_name[256];
	char list_path[256];
	CONFIG_FILE *pconfig;
	char config_path[256];
	char resource_path[256];
	

	switch(reason) {
	case PLUGIN_INIT:
		LINK_API(ppdata);
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(config_path, "%s/%s.cfg", get_config_path(), file_name);
		pconfig = config_file_init(config_path);
		if (NULL == pconfig) {
			printf("[exmdb_provider]: fail to open config file!!!\n");
			return FALSE;
		}
		
		sprintf(resource_path, "%s/mail_bounce", get_data_path());
		sprintf(list_path, "%s/exmdb_list.txt", get_data_path());
		sprintf(acl_path, "%s/exmdb_acl.txt", get_data_path());
		
		str_value = config_file_get_value(pconfig, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_value) {
			strcpy(separator, " ");
		} else {
			strcpy(separator, str_value);
		}
		
		str_value = config_file_get_value(pconfig, "X500_ORG_NAME");
		if (NULL == str_value || '\0' == str_value[0]) {
			strcpy(org_name, "gridware information");
		} else {
			strcpy(org_name, str_value);
		}
		printf("[exmdb_provider]: x500 org name is \"%s\"\n", org_name);
		
		str_value = config_file_get_value(pconfig, "LISTEN_IP");
		if (NULL == str_value) {
			listen_ip[0] = '\0';
			printf("[exmdb_provider]: listen ip is ANY\n");
		} else {
			strncpy(listen_ip, str_value, 16);
			printf("[exmdb_provider]: listen ip is %s\n", listen_ip);
		}
		
		str_value = config_file_get_value(pconfig, "LISTEN_PORT");
		if (NULL == str_value) {
			listen_port = 0;
			printf("[exmdb_provider]: do not listen, any "
				"proxy connection will not be accepted\n");
		} else {
			listen_port = atoi(str_value);
		}
		printf("[exmdb_provider]: listen port is %d\n", listen_port);
		
		str_value = config_file_get_value(pconfig, "RPC_PROXY_CONNECTION_NUM");
		if (NULL == str_value) {
			connection_num = 0;
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
			threads_num = 0;
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
			max_threads = 0;
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
			max_routers = 0;
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
			table_size = 3000;
			config_file_set_value(pconfig, "TABLE_SIZE", "3000");
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
			cache_interval = 1800;
			config_file_set_value(pconfig, "CACHE_INTERVAL", "30minutes");
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
			max_msg_count = 0;
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
				config_file_set_value(pconfig, "MAX_RULE_NUMBER", "20");
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
			populating_num = 10;
			config_file_set_value(pconfig, "POPULATING_THREADS_NUM", "10");
		} else {
			populating_num = atoi(str_value);
			if (populating_num <= 0 || populating_num > 50) {
				populating_num = 10;
				config_file_set_value(pconfig, "POPULATING_THREADS_NUM", "10");
			}
		}
		printf("[exmdb_provider]: populating threads"
				" number is %d\n", populating_num);
		
		config_file_save(pconfig);
		config_file_free(pconfig);
		
		common_util_init(org_name, max_msg_count, max_rule, max_ext_rule);
		bounce_producer_init(resource_path, separator);
		db_engine_init(table_size, cache_interval,
			b_async, b_wal, mmap_size, populating_num);
		exmdb_server_init();
		if (0 == listen_port) {
			exmdb_parser_init(0, 0, "");
		} else {
			exmdb_parser_init(max_threads, max_routers, list_path);
		}
		exmdb_listener_init(listen_ip, listen_port, acl_path);
		exmdb_client_init(connection_num, threads_num, list_path);
		
		if (0 != common_util_run()) {
			printf("[exmdb_provider]: fail to run common util\n");
			return FALSE;
		}
		if (0 != bounce_producer_run()) {
			printf("[exmdb_provider]: fail to run bounce producer\n");
			return FALSE;
		}
		if (0 != db_engine_run()) {
			printf("[exmdb_provider]: fail to run db engine\n");
			return FALSE;
		}
		if (0 != exmdb_server_run()) {
			printf("[exmdb_provider]: fail to run exmdb server\n");
			return FALSE;
		}
		if (0 != exmdb_parser_run()) {
			printf("[exmdb_provider]: fail to run exmdb parser\n");
			return FALSE;
		}
		if (0 != exmdb_listener_run()) {
			printf("[exmdb_provider]: fail to run exmdb listener\n");
			return FALSE;
		}
		if (0 != exmdb_listener_trigger_accept()) {
			printf("[exmdb_provider]: fail to trigger exmdb listener\n");
			return FALSE;
		}
		if (0 != exmdb_client_run()) {
			printf("[exmdb_provider]: fail to run exmdb client\n");
			return FALSE;
		}

		register_service("exmdb_client_ping_store",
			exmdb_client_ping_store);
		register_service("exmdb_client_get_all_named_propids",
			exmdb_client_get_all_named_propids);
		register_service("exmdb_client_get_named_propids",
			exmdb_client_get_named_propids);
		register_service("exmdb_client_get_named_propnames",
			exmdb_client_get_named_propnames);
		register_service("exmdb_client_get_mapping_guid",
			exmdb_client_get_mapping_guid);
		register_service("exmdb_client_get_mapping_replid",
			exmdb_client_get_mapping_replid);
		register_service("exmdb_client_get_store_all_proptags",
			exmdb_client_get_store_all_proptags);
		register_service("exmdb_client_get_store_properties",
			exmdb_client_get_store_properties);
		register_service("exmdb_client_set_store_properties",
			exmdb_client_set_store_properties);
		register_service("exmdb_client_remove_store_properties",
			exmdb_client_remove_store_properties);
		register_service("exmdb_client_check_mailbox_permission",
			exmdb_client_check_mailbox_permission);
		register_service("exmdb_client_get_folder_by_class",
			exmdb_client_get_folder_by_class);
		register_service("exmdb_client_set_folder_by_class",
			exmdb_client_set_folder_by_class);
		register_service("exmdb_client_get_folder_class_table",
			exmdb_client_get_folder_class_table);
		register_service("exmdb_client_check_folder_id",
			exmdb_client_check_folder_id);
		register_service("exmdb_client_check_folder_deleted",
			exmdb_client_check_folder_deleted);
		register_service("exmdb_client_get_folder_by_name",
			exmdb_client_get_folder_by_name);
		register_service("exmdb_client_check_folder_permission",
			exmdb_client_check_folder_permission);
		register_service("exmdb_client_create_folder_by_properties",
			exmdb_client_create_folder_by_properties);
		register_service("exmdb_client_get_folder_all_proptags",
			exmdb_client_get_folder_all_proptags);
		register_service("exmdb_client_get_folder_properties",
			exmdb_client_get_folder_properties);
		register_service("exmdb_client_set_folder_properties",
			exmdb_client_set_folder_properties);
		register_service("exmdb_client_remove_folder_properties",
			exmdb_client_remove_folder_properties);
		register_service("exmdb_client_delete_folder",
			exmdb_client_delete_folder);
		register_service("exmdb_client_empty_folder",
			exmdb_client_empty_folder);
		register_service("exmdb_client_check_folder_cycle",
			exmdb_client_check_folder_cycle);
		register_service("exmdb_client_copy_folder_internal",
			exmdb_client_copy_folder_internal);
		register_service("exmdb_client_get_search_criteria",
			exmdb_client_get_search_criteria);
		register_service("exmdb_client_set_search_criteria",
			exmdb_client_set_search_criteria);
		register_service("exmdb_client_movecopy_message",
			exmdb_client_movecopy_message);
		register_service("exmdb_client_movecopy_messages",
			exmdb_client_movecopy_messages);
		register_service("exmdb_client_movecopy_folder",
			exmdb_client_movecopy_folder);
		register_service("exmdb_client_delete_messages",
			exmdb_client_delete_messages);
		register_service("exmdb_client_get_message_brief",
			exmdb_client_get_message_brief);
		register_service("exmdb_client_sum_hierarchy",
			exmdb_client_sum_hierarchy);
		register_service("exmdb_client_load_hierarchy_table",
			exmdb_client_load_hierarchy_table);
		register_service("exmdb_client_sum_content",
			exmdb_client_sum_content);
		register_service("exmdb_client_load_content_table",
			exmdb_client_load_content_table);
		register_service("exmdb_client_reload_content_table",
			exmdb_client_reload_content_table);
		register_service("exmdb_client_load_permission_table",
			exmdb_client_load_permission_table);
		register_service("exmdb_client_load_rule_table",
			exmdb_client_load_rule_table);
		register_service("exmdb_client_unload_table",
			exmdb_client_unload_table);
		register_service("exmdb_client_sum_table",
			exmdb_client_sum_table);
		register_service("exmdb_client_query_table",
			exmdb_client_query_table);
		register_service("exmdb_client_match_table",
			exmdb_client_match_table);
		register_service("exmdb_client_locate_table",
			exmdb_client_locate_table);
		register_service("exmdb_client_read_table_row",
			exmdb_client_read_table_row);
		register_service("exmdb_client_mark_table",
			exmdb_client_mark_table);
		register_service("exmdb_client_get_table_all_proptags",
			exmdb_client_get_table_all_proptags);
		register_service("exmdb_client_expand_table",
			exmdb_client_expand_table);
		register_service("exmdb_client_collapse_table",
			exmdb_client_collapse_table);
		register_service("exmdb_client_store_table_state",
			exmdb_client_store_table_state);
		register_service("exmdb_client_restore_table_state",
			exmdb_client_restore_table_state);
		register_service("exmdb_client_check_message",
			exmdb_client_check_message);
		register_service("exmdb_client_check_message_deleted",
			exmdb_client_check_message_deleted);
		register_service("exmdb_client_load_message_instance",
			exmdb_client_load_message_instance);
		register_service("exmdb_client_load_embedded_instance",
			exmdb_client_load_embedded_instance);
		register_service("exmdb_client_get_embeded_cn",
			exmdb_client_get_embeded_cn);
		register_service("exmdb_client_reload_message_instance",
			exmdb_client_reload_message_instance);
		register_service("exmdb_client_clear_message_instance",
			exmdb_client_clear_message_instance);
		register_service("exmdb_client_read_message_instance",
			exmdb_client_read_message_instance);
		register_service("exmdb_client_write_message_instance",
			exmdb_client_write_message_instance);
		register_service("exmdb_client_load_attachment_instance",
			exmdb_client_load_attachment_instance);
		register_service("exmdb_client_create_attachment_instance",
			exmdb_client_create_attachment_instance);
		register_service("exmdb_client_read_attachment_instance",
			exmdb_client_read_attachment_instance);
		register_service("exmdb_client_write_attachment_instance",
			exmdb_client_write_attachment_instance);
		register_service("exmdb_client_delete_message_instance_attachment",
			exmdb_client_delete_message_instance_attachment);
		register_service("exmdb_client_flush_instance",
			exmdb_client_flush_instance);
		register_service("exmdb_client_unload_instance",
			exmdb_client_unload_instance);
		register_service("exmdb_client_get_instance_all_proptags",
			exmdb_client_get_instance_all_proptags);
		register_service("exmdb_client_get_instance_properties",
			exmdb_client_get_instance_properties);
		register_service("exmdb_client_set_instance_properties",
			exmdb_client_set_instance_properties);
		register_service("exmdb_client_remove_instance_properties",
			exmdb_client_remove_instance_properties);
		register_service("exmdb_client_check_instance_cycle",
			exmdb_client_check_instance_cycle);
		register_service("exmdb_client_empty_message_instance_rcpts",
			exmdb_client_empty_message_instance_rcpts);
		register_service("exmdb_client_get_message_instance_rcpts_num",
			exmdb_client_get_message_instance_rcpts_num);
		register_service("exmdb_client_get_message_instance_rcpts_all_proptags",
			exmdb_client_get_message_instance_rcpts_all_proptags);
		register_service("exmdb_client_get_message_instance_rcpts",
			exmdb_client_get_message_instance_rcpts);
		register_service("exmdb_client_update_message_instance_rcpts",
			exmdb_client_update_message_instance_rcpts);
		register_service("exmdb_client_empty_message_instance_attachments",
			exmdb_client_empty_message_instance_attachments);
		register_service("exmdb_client_get_message_instance_attachments_num",
			exmdb_client_get_message_instance_attachments_num);
		register_service("exmdb_client_get_message_instance_attachment_table_all_proptags",
			exmdb_client_get_message_instance_attachment_table_all_proptags);
		register_service("exmdb_client_query_message_instance_attachment_table",
			exmdb_client_query_message_instance_attachment_table);
		register_service("exmdb_client_set_message_instance_conflict",
			exmdb_client_set_message_instance_conflict);
		register_service("exmdb_client_get_message_rcpts",
			exmdb_client_get_message_rcpts);
		register_service("exmdb_client_get_message_properties",
			exmdb_client_get_message_properties);
		register_service("exmdb_client_set_message_properties",
			exmdb_client_set_message_properties);
		register_service("exmdb_client_set_message_read_state",
			exmdb_client_set_message_read_state);
		register_service("exmdb_client_remove_message_properties",
			exmdb_client_remove_message_properties);
		register_service("exmdb_client_allocate_message_id",
			exmdb_client_allocate_message_id);
		register_service("exmdb_client_allocate_cn",
			exmdb_client_allocate_cn);
		register_service("exmdb_client_get_message_group_id",
			exmdb_client_get_message_group_id);
		register_service("exmdb_client_set_message_group_id",
			exmdb_client_set_message_group_id);
		register_service("exmdb_client_save_change_indices",
			exmdb_client_save_change_indices);
		register_service("exmdb_client_get_change_indices",
			exmdb_client_get_change_indices);
		register_service("exmdb_client_mark_modified",
			exmdb_client_mark_modified);
		register_service("exmdb_client_try_mark_submit",
			exmdb_client_try_mark_submit);
		register_service("exmdb_client_clear_submit",
			exmdb_client_clear_submit);
		register_service("exmdb_client_link_message",
			exmdb_client_link_message);
		register_service("exmdb_client_unlink_message",
			exmdb_client_unlink_message);
		register_service("exmdb_client_rule_new_message",
			exmdb_client_rule_new_message);
		register_service("exmdb_client_set_message_timer",
			exmdb_client_set_message_timer);
		register_service("exmdb_client_get_message_timer",
			exmdb_client_get_message_timer);
		register_service("exmdb_client_empty_folder_permission",
			exmdb_client_empty_folder_permission);
		register_service("exmdb_client_update_folder_permission",
			exmdb_client_update_folder_permission);
		register_service("exmdb_client_empty_folder_rule",
			exmdb_client_empty_folder_rule);
		register_service("exmdb_client_update_folder_rule",
			exmdb_client_update_folder_rule);
		register_service("exmdb_client_write_message",
			exmdb_client_write_message);
		register_service("exmdb_client_delivery_message",
			exmdb_client_delivery_message);
		register_service("exmdb_client_read_message",
			exmdb_client_read_message);
		register_service("exmdb_client_get_content_sync",
			exmdb_client_get_content_sync);
		register_service("exmdb_client_get_hierarchy_sync",
			exmdb_client_get_hierarchy_sync);
		register_service("exmdb_client_allocate_ids",
			exmdb_client_allocate_ids);
		register_service("exmdb_client_subscribe_notification",
			exmdb_client_subscribe_notification);
		register_service("exmdb_client_unsubscribe_notification",
			exmdb_client_unsubscribe_notification);
		register_service("exmdb_client_transport_new_mail",
			exmdb_client_transport_new_mail);
		register_service("exmdb_client_copy_instance_rcpts",
			exmdb_client_copy_instance_rcpts);
		register_service("exmdb_client_copy_instance_attachments",
			exmdb_client_copy_instance_attachments);
		register_service("exmdb_client_check_contact_address",
			exmdb_client_check_contact_address);
		register_service("exmdb_client_get_public_folder_unread_count",
			exmdb_client_get_public_folder_unread_count);
		register_service("exmdb_client_register_proc",
			exmdb_server_register_proc);
		register_service("pass_service", common_util_pass_service);
		
		if (FALSE == register_talk(console_talk)) {
			printf("[exmdb_provider]: fail to register console talk\n");
			return FALSE;
		}
		
		return TRUE;
	case PLUGIN_FREE:
		exmdb_client_stop();
		exmdb_listener_stop();
		exmdb_parser_stop();
		exmdb_server_stop();
		db_engine_stop();
		bounce_producer_stop();
		common_util_stop();
		exmdb_client_free();
		exmdb_listener_free();
		exmdb_parser_free();
		exmdb_server_free();
		db_engine_free();
		bounce_producer_free();
		common_util_free();
		return TRUE;
	}
}
