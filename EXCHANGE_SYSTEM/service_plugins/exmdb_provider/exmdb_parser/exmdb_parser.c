#include "notification_agent.h"
#include "exmdb_parser.h"
#include "exmdb_server.h"
#include "common_util.h"
#include "mapi_types.h"
#include "exmdb_ext.h"
#include "list_file.h"
#include "idset.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <netdb.h>
#include <poll.h>


static int g_max_threads;
static int g_max_routers;
static char g_list_path[256];
static DOUBLE_LIST g_local_list;
static DOUBLE_LIST g_router_list;
static DOUBLE_LIST g_connection_list;
static pthread_mutex_t g_router_lock;
static pthread_mutex_t g_connection_lock;

int exmdb_parser_get_param(int param)
{
	switch (param) {
	case ALIVE_ROUTER_CONNECTIONS:
		return double_list_get_nodes_num(&g_router_list);
	}
	return -1;
}

void exmdb_parser_init(int max_threads,
	int max_routers, const char *list_path)
{
	g_max_threads = max_threads;
	g_max_routers = max_routers;
	strcpy(g_list_path, list_path);
	pthread_mutex_init(&g_router_lock, NULL);
	pthread_mutex_init(&g_connection_lock, NULL);
	double_list_init(&g_connection_list);
	double_list_init(&g_router_list);
	double_list_init(&g_local_list);
}

void exmdb_parser_free()
{
	double_list_free(&g_local_list);
	double_list_free(&g_router_list);
	double_list_free(&g_connection_list);
	pthread_mutex_destroy(&g_router_lock);
	pthread_mutex_destroy(&g_connection_lock);
}

EXMDB_CONNECTION* exmdb_parser_get_connection()
{
	EXMDB_CONNECTION *pconnection;

	if (0 != g_max_threads && double_list_get_nodes_num(
		&g_connection_list) >= g_max_threads) {
		return NULL;
	}
	pconnection = (EXMDB_CONNECTION*)malloc(sizeof(EXMDB_CONNECTION));
	if (NULL == pconnection) {
		return NULL;
	}
	pconnection->node.pdata = pconnection;
	pconnection->b_stop = FALSE;
	return pconnection;
}

static BOOL exmdb_parser_check_local(const char *prefix, BOOL *pb_private)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_local_list); NULL!=pnode;
		pnode=double_list_get_after(&g_local_list, pnode)) {
		if (0 == strcmp(((LOCAL_SVR*)pnode->pdata)->prefix, prefix)) {
			*pb_private = ((LOCAL_SVR*)pnode->pdata)->b_private;
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL exmdb_parser_dispatch(const EXMDB_REQUEST *prequest,
	EXMDB_RESPONSE *presponse)
{
	BOOL b_return;
	
	presponse->call_id = prequest->call_id;
	exmdb_server_set_dir(prequest->dir);
	switch (prequest->call_id) {
	case CALL_ID_PING_STORE:
		return exmdb_server_ping_store(prequest->dir);
	case CALL_ID_GET_ALL_NAMED_PROPIDS:
		return exmdb_server_get_all_named_propids(prequest->dir,
			&presponse->payload.get_all_named_propids.propids);
	case CALL_ID_GET_NAMED_PROPIDS:
		return exmdb_server_get_named_propids(prequest->dir,
			prequest->payload.get_named_propids.b_create,
			prequest->payload.get_named_propids.ppropnames,
			&presponse->payload.get_named_propids.propids);
	case CALL_ID_GET_NAMED_PROPNAMES:
		return exmdb_server_get_named_propnames(prequest->dir,
			prequest->payload.get_named_propnames.ppropids,
			&presponse->payload.get_named_propnames.propnames);
	case CALL_ID_GET_MAPPING_GUID:
		return exmdb_server_get_mapping_guid(prequest->dir,
			prequest->payload.get_mapping_guid.replid,
			&presponse->payload.get_mapping_guid.b_found,
			&presponse->payload.get_mapping_guid.guid);
	case CALL_ID_GET_MAPPING_REPLID:
		return exmdb_server_get_mapping_replid(prequest->dir,
			prequest->payload.get_mapping_replid.guid,
			&presponse->payload.get_mapping_replid.b_found,
			&presponse->payload.get_mapping_replid.replid);
	case CALL_ID_GET_STORE_ALL_PROPTAGS:
		return exmdb_server_get_store_all_proptags(prequest->dir,
			&presponse->payload.get_store_all_proptags.proptags);
	case CALL_ID_GET_STORE_PROPERTIES:
		return exmdb_server_get_store_properties(prequest->dir,
			prequest->payload.get_store_properties.cpid,
			prequest->payload.get_store_properties.pproptags,
			&presponse->payload.get_store_properties.propvals);
	case CALL_ID_SET_STORE_PROPERTIES:
		return exmdb_server_set_store_properties(prequest->dir,
			prequest->payload.set_store_properties.cpid,
			prequest->payload.set_store_properties.ppropvals,
			&presponse->payload.set_store_properties.problems);
	case CALL_ID_REMOVE_STORE_PROPERTIES:
		return exmdb_server_remove_store_properties(prequest->dir,
			prequest->payload.remove_store_properties.pproptags);
	case CALL_ID_CHECK_MAILBOX_PERMISSION:
		return exmdb_server_check_mailbox_permission(prequest->dir,
			prequest->payload.check_mailbox_permission.username,
			&presponse->payload.check_mailbox_permission.permission);
	case CALL_ID_GET_FOLDER_BY_CLASS:
		presponse->payload.get_folder_by_class.str_explicit =
										common_util_alloc(256);
		if (NULL == presponse->payload.get_folder_by_class.str_explicit) {
			return FALSE;
		}
		return exmdb_server_get_folder_by_class(prequest->dir,
			prequest->payload.get_folder_by_class.str_class,
			&presponse->payload.get_folder_by_class.id,
			presponse->payload.get_folder_by_class.str_explicit);
	case CALL_ID_SET_FOLDER_BY_CLASS:
		return exmdb_server_set_folder_by_class(prequest->dir,
			prequest->payload.set_folder_by_class.folder_id,
			prequest->payload.set_folder_by_class.str_class,
			&presponse->payload.set_folder_by_class.b_result);
	case CALL_ID_GET_FOLDER_CLASS_TABLE:
		return exmdb_server_get_folder_class_table(prequest->dir,
			&presponse->payload.get_folder_class_table.table);
	case CALL_ID_CHECK_FOLDER_ID:
		return exmdb_server_check_folder_id(prequest->dir,
			prequest->payload.check_folder_id.folder_id,
			&presponse->payload.check_folder_id.b_exist);
	case CALL_ID_QUERY_FOLDER_MESSAGES:
		return exmdb_server_query_folder_messages(prequest->dir,
			prequest->payload.query_folder_messages.folder_id,
			&presponse->payload.query_folder_messages.set);
	case CALL_ID_CHECK_FOLDER_DELETED:
		return exmdb_server_check_folder_deleted(prequest->dir,
			prequest->payload.check_folder_deleted.folder_id,
			&presponse->payload.check_folder_deleted.b_del);
	case CALL_ID_GET_FOLDER_BY_NAME:
		return exmdb_server_get_folder_by_name(prequest->dir,
			prequest->payload.get_folder_by_name.parent_id,
			prequest->payload.get_folder_by_name.str_name,
			&presponse->payload.get_folder_by_name.folder_id);
	case CALL_ID_CHECK_FOLDER_PERMISSION:
		return exmdb_server_check_folder_permission(prequest->dir,
			prequest->payload.check_folder_permission.folder_id,
			prequest->payload.check_folder_permission.username,
			&presponse->payload.check_folder_permission.permission);
	case CALL_ID_CREATE_FOLDER_BY_PROPERTIES:
		return exmdb_server_create_folder_by_properties(prequest->dir,
			prequest->payload.create_folder_by_properties.cpid,
			prequest->payload.create_folder_by_properties.pproperties,
			&presponse->payload.create_folder_by_properties.folder_id);
	case CALL_ID_GET_FOLDER_ALL_PROPTAGS:
		return exmdb_server_get_folder_all_proptags(prequest->dir,
			prequest->payload.get_folder_all_proptags.folder_id,
			&presponse->payload.get_folder_all_proptags.proptags);
	case CALL_ID_GET_FOLDER_PROPERTIES:
		return exmdb_server_get_folder_properties(prequest->dir,
			prequest->payload.get_folder_properties.cpid,
			prequest->payload.get_folder_properties.folder_id,
			prequest->payload.get_folder_properties.pproptags,
			&presponse->payload.get_folder_properties.propvals);
	case CALL_ID_SET_FOLDER_PROPERTIES:
		return exmdb_server_set_folder_properties(prequest->dir,
			prequest->payload.set_folder_properties.cpid,
			prequest->payload.set_folder_properties.folder_id,
			prequest->payload.set_folder_properties.pproperties,
			&presponse->payload.set_folder_properties.problems);
	case CALL_ID_REMOVE_FOLDER_PROPERTIES:
		return exmdb_server_remove_folder_properties(prequest->dir,
			prequest->payload.remove_folder_properties.folder_id,
			prequest->payload.remove_folder_properties.pproptags);
	case CALL_ID_DELETE_FOLDER:
		return exmdb_server_delete_folder(prequest->dir,
			prequest->payload.delete_folder.cpid,
			prequest->payload.delete_folder.folder_id,
			prequest->payload.delete_folder.b_hard,
			&presponse->payload.delete_folder.b_result);
	case CALL_ID_EMPTY_FOLDER:
		return exmdb_server_empty_folder(prequest->dir,
			prequest->payload.empty_folder.cpid,
			prequest->payload.empty_folder.username,
			prequest->payload.empty_folder.folder_id,
			prequest->payload.empty_folder.b_hard,
			prequest->payload.empty_folder.b_normal,
			prequest->payload.empty_folder.b_fai,
			prequest->payload.empty_folder.b_sub,
			&presponse->payload.empty_folder.b_partial);
	case CALL_ID_CHECK_FOLDER_CYCLE:
		return exmdb_server_check_folder_cycle(prequest->dir,
			prequest->payload.check_folder_cycle.src_fid,
			prequest->payload.check_folder_cycle.dst_fid,
			&presponse->payload.check_folder_cycle.b_cycle);
	case CALL_ID_COPY_FOLDER_INTERNAL:
		return exmdb_server_copy_folder_internal(prequest->dir,
			prequest->payload.copy_folder_internal.account_id,
			prequest->payload.copy_folder_internal.cpid,
			prequest->payload.copy_folder_internal.b_guest,
			prequest->payload.copy_folder_internal.username,
			prequest->payload.copy_folder_internal.src_fid,
			prequest->payload.copy_folder_internal.b_normal,
			prequest->payload.copy_folder_internal.b_fai,
			prequest->payload.copy_folder_internal.b_sub,
			prequest->payload.copy_folder_internal.dst_fid,
			&presponse->payload.copy_folder_internal.b_collid,
			&presponse->payload.copy_folder_internal.b_partial);
	case CALL_ID_GET_SEARCH_CRITERIA:
		return exmdb_server_get_search_criteria(prequest->dir,
			prequest->payload.get_search_criteria.folder_id,
			&presponse->payload.get_search_criteria.search_status,
			&presponse->payload.get_search_criteria.prestriction,
			&presponse->payload.get_search_criteria.folder_ids);
	case CALL_ID_SET_SEARCH_CRITERIA:
		return exmdb_server_set_search_criteria(prequest->dir,
			prequest->payload.set_search_criteria.cpid,
			prequest->payload.set_search_criteria.folder_id,
			prequest->payload.set_search_criteria.search_flags,
			prequest->payload.set_search_criteria.prestriction,
			prequest->payload.set_search_criteria.pfolder_ids,
			&presponse->payload.set_search_criteria.b_result);
	case CALL_ID_MOVECOPY_MESSAGE:
		return exmdb_server_movecopy_message(prequest->dir,
			prequest->payload.movecopy_message.account_id,
			prequest->payload.movecopy_message.cpid,
			prequest->payload.movecopy_message.message_id,
			prequest->payload.movecopy_message.dst_fid,
			prequest->payload.movecopy_message.dst_id,
			prequest->payload.movecopy_message.b_move,
			&presponse->payload.movecopy_message.b_result);
	case CALL_ID_MOVECOPY_MESSAGES:
		return exmdb_server_movecopy_messages(prequest->dir,
			prequest->payload.movecopy_messages.account_id,
			prequest->payload.movecopy_messages.cpid,
			prequest->payload.movecopy_messages.b_guest,
			prequest->payload.movecopy_messages.username,
			prequest->payload.movecopy_messages.src_fid,
			prequest->payload.movecopy_messages.dst_fid,
			prequest->payload.movecopy_messages.b_copy,
			prequest->payload.movecopy_messages.pmessage_ids,
			&presponse->payload.movecopy_messages.b_partial);
	case CALL_ID_MOVECOPY_FOLDER:
		return exmdb_server_movecopy_folder(prequest->dir,
			prequest->payload.movecopy_folder.account_id,
			prequest->payload.movecopy_folder.cpid,
			prequest->payload.movecopy_folder.b_guest,
			prequest->payload.movecopy_folder.username,
			prequest->payload.movecopy_folder.src_pid,
			prequest->payload.movecopy_folder.src_fid,
			prequest->payload.movecopy_folder.dst_fid,
			prequest->payload.movecopy_folder.str_new,
			prequest->payload.movecopy_folder.b_copy,
			&presponse->payload.movecopy_folder.b_exist,
			&presponse->payload.movecopy_folder.b_partial);
	case CALL_ID_DELETE_MESSAGES:
		return exmdb_server_delete_messages(prequest->dir,
			prequest->payload.delete_messages.account_id,
			prequest->payload.delete_messages.cpid,
			prequest->payload.delete_messages.username,
			prequest->payload.delete_messages.folder_id,
			prequest->payload.delete_messages.pmessage_ids,
			prequest->payload.delete_messages.b_hard,
			&presponse->payload.delete_messages.b_partial);
	case CALL_ID_GET_MESSAGE_BRIEF:
		return exmdb_server_get_message_brief(prequest->dir,
			prequest->payload.get_message_brief.cpid,
			prequest->payload.get_message_brief.message_id,
			&presponse->payload.get_message_brief.pbrief);
	case CALL_ID_SUM_HIERARCHY:
		return exmdb_server_sum_hierarchy(prequest->dir,
			prequest->payload.sum_hierarchy.folder_id,
			prequest->payload.sum_hierarchy.username,
			prequest->payload.sum_hierarchy.b_depth,
			&presponse->payload.sum_hierarchy.count);
	case CALL_ID_LOAD_HIERARCHY_TABLE:
		return exmdb_server_load_hierarchy_table(prequest->dir,
			prequest->payload.load_hierarchy_table.folder_id,
			prequest->payload.load_hierarchy_table.username,
			prequest->payload.load_hierarchy_table.table_flags,
			prequest->payload.load_hierarchy_table.prestriction,
			&presponse->payload.load_hierarchy_table.table_id,
			&presponse->payload.load_hierarchy_table.row_count);
	case CALL_ID_SUM_CONTENT:
		return exmdb_server_sum_content(prequest->dir,
			prequest->payload.sum_content.folder_id,
			prequest->payload.sum_content.b_fai,
			prequest->payload.sum_content.b_deleted,
			&presponse->payload.sum_content.count);
	case CALL_ID_LOAD_CONTENT_TABLE:
		return exmdb_server_load_content_table(prequest->dir,
			prequest->payload.load_content_table.cpid,
			prequest->payload.load_content_table.folder_id,
			prequest->payload.load_content_table.username,
			prequest->payload.load_content_table.table_flags,
			prequest->payload.load_content_table.prestriction,
			prequest->payload.load_content_table.psorts,
			&presponse->payload.load_content_table.table_id,
			&presponse->payload.load_content_table.row_count);
	case CALL_ID_LOAD_PERMISSION_TABLE:
		return exmdb_server_load_permission_table(prequest->dir,
			prequest->payload.load_permission_table.folder_id,
			prequest->payload.load_permission_table.table_flags,
			&presponse->payload.load_permission_table.table_id,
			&presponse->payload.load_permission_table.row_count);
	case CALL_ID_LOAD_RULE_TABLE:
		return exmdb_server_load_rule_table(prequest->dir,
			prequest->payload.load_rule_table.folder_id,
			prequest->payload.load_rule_table.table_flags,
			prequest->payload.load_rule_table.prestriction,
			&presponse->payload.load_rule_table.table_id,
			&presponse->payload.load_rule_table.row_count);
	case CALL_ID_UNLOAD_TABLE:
		return exmdb_server_unload_table(prequest->dir,
				prequest->payload.unload_table.table_id);
	case CALL_ID_SUM_TABLE:
		return exmdb_server_sum_table(prequest->dir,
			prequest->payload.sum_table.table_id,
			&presponse->payload.sum_table.rows);
	case CALL_ID_QUERY_TABLE:
		return exmdb_server_query_table(prequest->dir,
			prequest->payload.query_table.username,
			prequest->payload.query_table.cpid,
			prequest->payload.query_table.table_id,
			prequest->payload.query_table.pproptags,
			prequest->payload.query_table.start_pos,
			prequest->payload.query_table.row_needed,
			&presponse->payload.query_table.set);
	case CALL_ID_MATCH_TABLE:
		return exmdb_server_match_table(prequest->dir,
			prequest->payload.match_table.username,
			prequest->payload.match_table.cpid,
			prequest->payload.match_table.table_id,
			prequest->payload.match_table.b_forward,
			prequest->payload.match_table.start_pos,
			prequest->payload.match_table.pres,
			prequest->payload.match_table.pproptags,
			&presponse->payload.match_table.position,
			&presponse->payload.match_table.propvals);
	case CALL_ID_LOCATE_TABLE:
		return exmdb_server_locate_table(prequest->dir,
			prequest->payload.locate_table.table_id,
			prequest->payload.locate_table.inst_id,
			prequest->payload.locate_table.inst_num,
			&presponse->payload.locate_table.position,
			&presponse->payload.locate_table.row_type);
	case CALL_ID_READ_TABLE_ROW:
		return exmdb_server_read_table_row(prequest->dir,
			prequest->payload.read_table_row.username,
			prequest->payload.read_table_row.cpid,
			prequest->payload.read_table_row.table_id,
			prequest->payload.read_table_row.pproptags,
			prequest->payload.read_table_row.inst_id,
			prequest->payload.read_table_row.inst_num,
			&presponse->payload.read_table_row.propvals);
	case CALL_ID_MARK_TABLE:
		return exmdb_server_mark_table(prequest->dir,
			prequest->payload.mark_table.table_id,
			prequest->payload.mark_table.position,
			&presponse->payload.mark_table.inst_id,
			&presponse->payload.mark_table.inst_num,
			&presponse->payload.mark_table.row_type);
	case CALL_ID_GET_TABLE_ALL_PROPTAGS:
		return exmdb_server_get_table_all_proptags(prequest->dir,
			prequest->payload.get_table_all_proptags.table_id,
			&presponse->payload.get_table_all_proptags.proptags);
	case CALL_ID_EXPAND_TABLE:
		return exmdb_server_expand_table(prequest->dir,
			prequest->payload.expand_table.table_id,
			prequest->payload.expand_table.inst_id,
			&presponse->payload.expand_table.b_found,
			&presponse->payload.expand_table.position,
			&presponse->payload.expand_table.row_count);
	case CALL_ID_COLLAPSE_TABLE:
		return exmdb_server_collapse_table(prequest->dir,
			prequest->payload.collapse_table.table_id,
			prequest->payload.collapse_table.inst_id,
			&presponse->payload.collapse_table.b_found,
			&presponse->payload.collapse_table.position,
			&presponse->payload.collapse_table.row_count);
	case CALL_ID_STORE_TABLE_STATE:
		return exmdb_server_store_table_state(prequest->dir,
			prequest->payload.store_table_state.table_id,
			prequest->payload.store_table_state.inst_id,
			prequest->payload.store_table_state.inst_num,
			&presponse->payload.store_table_state.state_id);
	case CALL_ID_RESTORE_TABLE_STATE:
		return exmdb_server_restore_table_state(prequest->dir,
			prequest->payload.restore_table_state.table_id,
			prequest->payload.restore_table_state.state_id,
			&presponse->payload.restore_table_state.position);
	case CALL_ID_CHECK_MESSAGE:
		return exmdb_server_check_message(prequest->dir,
			prequest->payload.check_message.folder_id,
			prequest->payload.check_message.message_id,
			&presponse->payload.check_message.b_exist);
	case CALL_ID_CHECK_MESSAGE_DELETED:
		return exmdb_server_check_message_deleted(prequest->dir,
			prequest->payload.check_message_deleted.message_id,
			&presponse->payload.check_message_deleted.b_del);
	case CALL_ID_LOAD_MESSAGE_INSTANCE:
		return exmdb_server_load_message_instance(prequest->dir,
			prequest->payload.load_message_instance.username,
			prequest->payload.load_message_instance.cpid,
			prequest->payload.load_message_instance.b_new,
			prequest->payload.load_message_instance.folder_id,
			prequest->payload.load_message_instance.message_id,
			&presponse->payload.load_message_instance.instance_id);
	case CALL_ID_LOAD_EMBEDDED_INSTANCE:
		return exmdb_server_load_embedded_instance(prequest->dir,
			prequest->payload.load_embedded_instance.b_new,
			prequest->payload.load_embedded_instance.attachment_instance_id,
			&presponse->payload.load_embedded_instance.instance_id);
	case CALL_ID_GET_EMBEDED_CN:
		return exmdb_server_get_embeded_cn(prequest->dir,
			prequest->payload.get_embeded_cn.instance_id,
			&presponse->payload.get_embeded_cn.pcn);
	case CALL_ID_RELOAD_MESSAGE_INSTANCE:
		return exmdb_server_reload_message_instance(prequest->dir,
			prequest->payload.reload_message_instance.instance_id,
			&presponse->payload.reload_message_instance.b_result);
	case CALL_ID_CLEAR_MESSAGE_INSTANCE:
		return exmdb_server_clear_message_instance(prequest->dir,
			prequest->payload.clear_message_instance.instance_id);
	case CALL_ID_READ_MESSAGE_INSTANCE:
		return exmdb_server_read_message_instance(prequest->dir,
			prequest->payload.read_message_instance.instance_id,
			&presponse->payload.read_message_instance.msgctnt);
	case CALL_ID_WRITE_MESSAGE_INSTANCE:
		return exmdb_server_write_message_instance(prequest->dir,
			prequest->payload.write_message_instance.instance_id,
			prequest->payload.write_message_instance.pmsgctnt,
			prequest->payload.write_message_instance.b_force,
			&presponse->payload.write_message_instance.proptags,
			&presponse->payload.write_message_instance.problems);
	case CALL_ID_LOAD_ATTACHMENT_INSTANCE:
		return exmdb_server_load_attachment_instance(prequest->dir,
			prequest->payload.load_attachment_instance.message_instance_id,
			prequest->payload.load_attachment_instance.attachment_num,
			&presponse->payload.load_attachment_instance.instance_id);
	case CALL_ID_CREATE_ATTACHMENT_INSTANCE:
		return exmdb_server_create_attachment_instance(prequest->dir,
			prequest->payload.create_attachment_instance.message_instance_id,
			&presponse->payload.create_attachment_instance.instance_id,
			&presponse->payload.create_attachment_instance.attachment_num);
	case CALL_ID_READ_ATTACHMENT_INSTANCE:
		return exmdb_server_read_attachment_instance(prequest->dir,
			prequest->payload.read_attachment_instance.instance_id,
			&presponse->payload.read_attachment_instance.attctnt);
	case CALL_ID_WRITE_ATTACHMENT_INSTANCE:
		return exmdb_server_write_attachment_instance(prequest->dir,
			prequest->payload.write_attachment_instance.instance_id,
			prequest->payload.write_attachment_instance.pattctnt,
			prequest->payload.write_attachment_instance.b_force,
			&presponse->payload.write_attachment_instance.problems);
	case CALL_ID_DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		return exmdb_server_delete_message_instance_attachment(prequest->dir,
			prequest->payload.delete_message_instance_attachment.message_instance_id,
			prequest->payload.delete_message_instance_attachment.attachment_num);
	case CALL_ID_FLUSH_INSTANCE:
		return exmdb_server_flush_instance(prequest->dir,
			prequest->payload.flush_instance.instance_id,
			prequest->payload.flush_instance.account,
			&presponse->payload.flush_instance.b_result);
	case CALL_ID_UNLOAD_INSTANCE:
		return exmdb_server_unload_instance(prequest->dir,
			prequest->payload.unload_instance.instance_id);
	case CALL_ID_GET_INSTANCE_ALL_PROPTAGS:
		return exmdb_server_get_instance_all_proptags(prequest->dir,
			prequest->payload.get_instance_all_proptags.instance_id,
			&presponse->payload.get_instance_all_proptags.proptags);
	case CALL_ID_GET_INSTANCE_PROPERTIES:
		return exmdb_server_get_instance_properties(prequest->dir,
			prequest->payload.get_instance_properties.size_limit,
			prequest->payload.get_instance_properties.instance_id,
			prequest->payload.get_instance_properties.pproptags,
			&presponse->payload.get_instance_properties.propvals);
	case CALL_ID_SET_INSTANCE_PROPERTIES:
		return exmdb_server_set_instance_properties(prequest->dir,
			prequest->payload.set_instance_properties.instance_id,
			prequest->payload.set_instance_properties.pproperties,
			&presponse->payload.set_instance_properties.problems);
	case CALL_ID_REMOVE_INSTANCE_PROPERTIES:
		return exmdb_server_remove_instance_properties(prequest->dir,
			prequest->payload.remove_instance_properties.instance_id,
			prequest->payload.remove_instance_properties.pproptags,
			&presponse->payload.remove_instance_properties.problems);
	case CALL_ID_CHECK_INSTANCE_CYCLE:
		return exmdb_server_check_instance_cycle(prequest->dir,
			prequest->payload.check_instance_cycle.src_instance_id,
			prequest->payload.check_instance_cycle.dst_instance_id,
			&presponse->payload.check_instance_cycle.b_cycle);
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_RCPTS:
		return exmdb_server_empty_message_instance_rcpts(prequest->dir,
			prequest->payload.empty_message_instance_rcpts.instance_id);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_NUM:
		return exmdb_server_get_message_instance_rcpts_num(prequest->dir,
			prequest->payload.get_message_instance_rcpts_num.instance_id,
			&presponse->payload.get_message_instance_rcpts_num.num);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		return exmdb_server_get_message_instance_rcpts_all_proptags(prequest->dir,
			prequest->payload.get_message_instance_rcpts_all_proptags.instance_id,
			&presponse->payload.get_message_instance_rcpts_all_proptags.proptags);
	case CALL_ID_GET_MESSAGE_INSTANCE_RCPTS:
		return exmdb_server_get_message_instance_rcpts(prequest->dir,
			prequest->payload.get_message_instance_rcpts.instance_id,
			prequest->payload.get_message_instance_rcpts.row_id,
			prequest->payload.get_message_instance_rcpts.need_count,
			&presponse->payload.get_message_instance_rcpts.set);
	case CALL_ID_UPDATE_MESSAGE_INSTANCE_RCPTS:
		return exmdb_server_update_message_instance_rcpts(prequest->dir,
			prequest->payload.update_message_instance_rcpts.instance_id,
			prequest->payload.update_message_instance_rcpts.pset);
	case CALL_ID_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		return exmdb_server_empty_message_instance_attachments(prequest->dir,
			prequest->payload.empty_message_instance_attachments.instance_id);
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		return exmdb_server_get_message_instance_attachments_num(prequest->dir,
			prequest->payload.get_message_instance_attachments_num.instance_id,
			&presponse->payload.get_message_instance_attachments_num.num);
	case CALL_ID_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		return exmdb_server_get_message_instance_attachment_table_all_proptags(prequest->dir,
			prequest->payload.get_message_instance_attachment_table_all_proptags.instance_id,
			&presponse->payload.get_message_instance_attachment_table_all_proptags.proptags);
	case CALL_ID_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		return exmdb_server_query_message_instance_attachment_table(prequest->dir,
			prequest->payload.query_message_instance_attachment_table.instance_id,
			prequest->payload.query_message_instance_attachment_table.pproptags,
			prequest->payload.query_message_instance_attachment_table.start_pos,
			prequest->payload.query_message_instance_attachment_table.row_needed,
			&presponse->payload.query_message_instance_attachment_table.set);
	case CALL_ID_COPY_INSTANCE_ATTACHMENTS:
		return exmdb_server_copy_instance_attachments(prequest->dir,
			prequest->payload.copy_instance_attachments.b_force,
			prequest->payload.copy_instance_attachments.src_instance_id,
			prequest->payload.copy_instance_attachments.dst_instance_id,
			&presponse->payload.copy_instance_attachments.b_result);
	case CALL_ID_SET_MESSAGE_INSTANCE_CONFLICT:
		return exmdb_server_set_message_instance_conflict(prequest->dir,
			prequest->payload.set_message_instance_conflict.instance_id,
			prequest->payload.set_message_instance_conflict.pmsgctnt);
	case CALL_ID_GET_MESSAGE_RCPTS:
		return exmdb_server_get_message_rcpts(prequest->dir,
			prequest->payload.get_message_rcpts.message_id,
			&presponse->payload.get_message_rcpts.set);
	case CALL_ID_GET_MESSAGE_PROPERTIES:
		return exmdb_server_get_message_properties(prequest->dir,
			prequest->payload.get_message_properties.username,
			prequest->payload.get_message_properties.cpid,
			prequest->payload.get_message_properties.message_id,
			prequest->payload.get_message_properties.pproptags,
			&presponse->payload.get_message_properties.propvals);
	case CALL_ID_SET_MESSAGE_PROPERTIES:
		return exmdb_server_set_message_properties(prequest->dir,
			prequest->payload.set_message_properties.username,
			prequest->payload.set_message_properties.cpid,
			prequest->payload.set_message_properties.message_id,
			prequest->payload.set_message_properties.pproperties,
			&presponse->payload.set_message_properties.problems);
	case CALL_ID_SET_MESSAGE_READ_STATE:
		return exmdb_server_set_message_read_state(prequest->dir,
			prequest->payload.set_message_read_state.username,
			prequest->payload.set_message_read_state.message_id,
			prequest->payload.set_message_read_state.mark_as_read,
			&presponse->payload.set_message_read_state.read_cn);
	case CALL_ID_REMOVE_MESSAGE_PROPERTIES:
		return exmdb_server_remove_message_properties(prequest->dir,
			prequest->payload.remove_message_properties.cpid,
			prequest->payload.remove_message_properties.message_id,
			prequest->payload.remove_message_properties.pproptags);
	case CALL_ID_ALLOCATE_MESSAGE_ID:
		return exmdb_server_allocate_message_id(prequest->dir,
			prequest->payload.allocate_message_id.folder_id,
			&presponse->payload.allocate_message_id.message_id);
	case CALL_ID_ALLOCATE_CN:
		return exmdb_server_allocate_cn(prequest->dir,
			&presponse->payload.allocate_cn.cn);
	case CALL_ID_GET_MESSAGE_GROUP_ID:
		return exmdb_server_get_message_group_id(prequest->dir,
			prequest->payload.get_message_group_id.message_id,
			&presponse->payload.get_message_group_id.pgroup_id);
	case CALL_ID_SET_MESSAGE_GROUP_ID:
		return exmdb_server_set_message_group_id(prequest->dir,
			prequest->payload.set_message_group_id.message_id,
			prequest->payload.set_message_group_id.group_id);
	case CALL_ID_SAVE_CHANGE_INDICES:
		return exmdb_server_save_change_indices(prequest->dir,
			prequest->payload.save_change_indices.message_id,
			prequest->payload.save_change_indices.cn,
			prequest->payload.save_change_indices.pindices,
			prequest->payload.save_change_indices.pungroup_proptags);
	case CALL_ID_GET_CHANGE_INDICES:
		return exmdb_server_get_change_indices(prequest->dir,
			prequest->payload.get_change_indices.message_id,
			prequest->payload.get_change_indices.cn,
			&presponse->payload.get_change_indices.indices,
			&presponse->payload.get_change_indices.ungroup_proptags);
	case CALL_ID_MARK_MODIFIED:
		return exmdb_server_mark_modified(prequest->dir,
			prequest->payload.mark_modified.message_id);
	case CALL_ID_TRY_MARK_SUBMIT:
		return exmdb_server_try_mark_submit(prequest->dir,
			prequest->payload.try_mark_submit.message_id,
			&presponse->payload.try_mark_submit.b_marked);
	case CALL_ID_CLEAR_SUBMIT:
		return exmdb_server_clear_submit(prequest->dir,
			prequest->payload.clear_submit.message_id,
			prequest->payload.clear_submit.b_unsent);
	case CALL_ID_LINK_MESSAGE:
		return exmdb_server_link_message(prequest->dir,
			prequest->payload.link_message.cpid,
			prequest->payload.link_message.folder_id,
			prequest->payload.link_message.message_id,
			&presponse->payload.link_message.b_result);
	case CALL_ID_UNLINK_MESSAGE:
		return exmdb_server_unlink_message(prequest->dir,
			prequest->payload.unlink_message.cpid,
			prequest->payload.unlink_message.folder_id,
			prequest->payload.unlink_message.message_id);
	case CALL_ID_RULE_NEW_MESSAGE:
		return exmdb_server_rule_new_message(prequest->dir,
			prequest->payload.rule_new_message.username,
			prequest->payload.rule_new_message.account,
			prequest->payload.rule_new_message.cpid,
			prequest->payload.rule_new_message.folder_id,
			prequest->payload.rule_new_message.message_id);
	case CALL_ID_SET_MESSAGE_TIMER:
		return exmdb_server_set_message_timer(prequest->dir,
			prequest->payload.set_message_timer.message_id,
			prequest->payload.set_message_timer.timer_id);
	case CALL_ID_GET_MESSAGE_TIMER:
		return exmdb_server_get_message_timer(prequest->dir,
			prequest->payload.get_message_timer.message_id,
			&presponse->payload.get_message_timer.ptimer_id);
	case CALL_ID_EMPTY_FOLDER_PERMISSION:
		return exmdb_server_empty_folder_permission(prequest->dir,
			prequest->payload.empty_folder_permission.folder_id);
	case CALL_ID_UPDATE_FOLDER_PERMISSION:
		return exmdb_server_update_folder_permission(prequest->dir,
			prequest->payload.update_folder_permission.folder_id,
			prequest->payload.update_folder_permission.b_freebusy,
			prequest->payload.update_folder_permission.count,
			prequest->payload.update_folder_permission.prow);
	case CALL_ID_EMPTY_FOLDER_RULE:
		return exmdb_server_empty_folder_rule(prequest->dir,
			prequest->payload.empty_folder_rule.folder_id);
	case CALL_ID_UPDATE_FOLDER_RULE:
		return exmdb_server_update_folder_rule(prequest->dir,
			prequest->payload.update_folder_rule.folder_id,
			prequest->payload.update_folder_rule.count,
			prequest->payload.update_folder_rule.prow,
			&presponse->payload.update_folder_rule.b_exceed);
	case CALL_ID_DELIVERY_MESSAGE:
		return exmdb_server_delivery_message(prequest->dir,
			prequest->payload.delivery_message.from_address,
			prequest->payload.delivery_message.account,
			prequest->payload.delivery_message.cpid,
			prequest->payload.delivery_message.pmsg,
			prequest->payload.delivery_message.pdigest,
			&presponse->payload.delivery_message.result);
	case CALL_ID_WRITE_MESSAGE:
		return exmdb_server_write_message(prequest->dir,
			prequest->payload.write_message.account,
			prequest->payload.write_message.cpid,
			prequest->payload.write_message.folder_id,
			prequest->payload.write_message.pmsgctnt,
			&presponse->payload.write_message.b_result);
	case CALL_ID_READ_MESSAGE:
		return exmdb_server_read_message(prequest->dir,
			prequest->payload.read_message.username,
			prequest->payload.read_message.cpid,
			prequest->payload.read_message.message_id,
			&presponse->payload.read_message.pmsgctnt);
	case CALL_ID_GET_CONTENT_SYNC:
		b_return = exmdb_server_get_content_sync(prequest->dir,
			prequest->payload.get_content_sync.folder_id,
			prequest->payload.get_content_sync.username,
			prequest->payload.get_content_sync.pgiven,
			prequest->payload.get_content_sync.pseen,
			prequest->payload.get_content_sync.pseen_fai,
			prequest->payload.get_content_sync.pread,
			prequest->payload.get_content_sync.cpid,
			prequest->payload.get_content_sync.prestriction,
			prequest->payload.get_content_sync.b_ordered,
			&presponse->payload.get_content_sync.fai_count,
			&presponse->payload.get_content_sync.fai_total,
			&presponse->payload.get_content_sync.normal_count,
			&presponse->payload.get_content_sync.normal_total,
			&presponse->payload.get_content_sync.updated_mids,
			&presponse->payload.get_content_sync.chg_mids,
			&presponse->payload.get_content_sync.last_cn,
			&presponse->payload.get_content_sync.given_mids,
			&presponse->payload.get_content_sync.deleted_mids,
			&presponse->payload.get_content_sync.nolonger_mids,
			&presponse->payload.get_content_sync.read_mids,
			&presponse->payload.get_content_sync.unread_mids,
			&presponse->payload.get_content_sync.last_readcn);
		if (NULL != prequest->payload.get_content_sync.pgiven) {
			idset_free(prequest->payload.get_content_sync.pgiven);
		}
		if (NULL != prequest->payload.get_content_sync.pseen) {
			idset_free(prequest->payload.get_content_sync.pseen);
		}
		if (NULL != prequest->payload.get_content_sync.pseen_fai) {
			idset_free(prequest->payload.get_content_sync.pseen_fai);
		}
		if (NULL != prequest->payload.get_content_sync.pread) {
			idset_free(prequest->payload.get_content_sync.pread);
		}
		return b_return;
	case CALL_ID_GET_HIERARCHY_SYNC:
		b_return = exmdb_server_get_hierarchy_sync(prequest->dir,
			prequest->payload.get_hierarchy_sync.folder_id,
			prequest->payload.get_hierarchy_sync.username,
			prequest->payload.get_hierarchy_sync.pgiven,
			prequest->payload.get_hierarchy_sync.pseen,
			&presponse->payload.get_hierarchy_sync.fldchgs,
			&presponse->payload.get_hierarchy_sync.last_cn,
			&presponse->payload.get_hierarchy_sync.given_fids,
			&presponse->payload.get_hierarchy_sync.deleted_fids);
		if (NULL != prequest->payload.get_hierarchy_sync.pgiven) {
			idset_free(prequest->payload.get_hierarchy_sync.pgiven);
		}
		if (NULL != prequest->payload.get_hierarchy_sync.pseen) {
			idset_free(prequest->payload.get_hierarchy_sync.pseen);
		}
		return b_return;
	case CALL_ID_ALLOCATE_IDS:
		return exmdb_server_allocate_ids(prequest->dir,
			prequest->payload.allocate_ids.count,
			&presponse->payload.allocate_ids.begin_eid);
	case CALL_ID_SUBSCRIBE_NOTIFICATION:
		return exmdb_server_subscribe_notification(prequest->dir,
			prequest->payload.subscribe_notification.notificaton_type,
			prequest->payload.subscribe_notification.b_whole,
			prequest->payload.subscribe_notification.folder_id,
			prequest->payload.subscribe_notification.message_id,
			&presponse->payload.subscribe_notification.sub_id);
	case CALL_ID_UNSUBSCRIBE_NOTIFICATION:
		return exmdb_server_unsubscribe_notification(prequest->dir,
			prequest->payload.unsubscribe_notification.sub_id);
	case CALL_ID_TRANSPORT_NEW_MAIL:
		return exmdb_server_transport_new_mail(prequest->dir,
			prequest->payload.transport_new_mail.folder_id,
			prequest->payload.transport_new_mail.message_id,
			prequest->payload.transport_new_mail.message_flags,
			prequest->payload.transport_new_mail.pstr_class);
	case CALL_ID_RELOAD_CONTENT_TABLE:
		return exmdb_server_reload_content_table(prequest->dir,
			prequest->payload.reload_content_table.table_id);
	case CALL_ID_COPY_INSTANCE_RCPTS:
		return exmdb_server_copy_instance_rcpts(prequest->dir,
			prequest->payload.copy_instance_rcpts.b_force,
			prequest->payload.copy_instance_rcpts.src_instance_id,
			prequest->payload.copy_instance_rcpts.dst_instance_id,
			&presponse->payload.copy_instance_rcpts.b_result);
	case CALL_ID_CHECK_CONTACT_ADDRESS:
		return exmdb_server_check_contact_address(prequest->dir,
			prequest->payload.check_contact_address.paddress,
			&presponse->payload.check_contact_address.b_found);
	case CALL_ID_GET_PUBLIC_FOLDER_UNREAD_COUNT:
		return exmdb_server_get_public_folder_unread_count(prequest->dir,
				prequest->payload.get_public_folder_unread_count.username,
				prequest->payload.get_public_folder_unread_count.folder_id,
				&presponse->payload.get_public_folder_unread_count.count);
	case CALL_ID_UNLOAD_STORE:
		return exmdb_server_unload_store(prequest->dir);
	default:
		return FALSE;
	}
}

static void *thread_work_func(void *pparam)
{
	int status;
	int tv_msec;
	void *pbuff;
	int read_len;
	BOOL b_private;
	BINARY tmp_bin;
	uint32_t offset;
	int written_len;
	BOOL is_writing;
	uint8_t tmp_byte;
	BOOL is_connected;
	uint32_t buff_len;
	uint8_t resp_buff[5];
	EXMDB_REQUEST request;
	struct pollfd pfd_read;
	EXMDB_RESPONSE response;
	DOUBLE_LIST_NODE *pnode;
	ROUTER_CONNECTION *prouter;
	EXMDB_CONNECTION *pconnection;
	
	b_private = FALSE; /* whatever for connect request */
	memset(resp_buff, 0, 5);
	pconnection = (EXMDB_CONNECTION*)pparam;
	pbuff = NULL;
	offset = 0;
	buff_len = 0;
	is_writing = FALSE;
	is_connected = FALSE;
    while (FALSE == pconnection->b_stop) {
		if (TRUE == is_writing) {
			written_len = write(pconnection->sockd,
				pbuff + offset, buff_len - offset);
			if (written_len <= 0) {
				break;
			}
			offset += written_len;
			if (offset == buff_len) {
				free(pbuff);
				pbuff = NULL;
				buff_len = 0;
				offset = 0;
				is_writing = FALSE;
			}
			continue;
		}
		tv_msec = SOCKET_TIMEOUT * 1000;
		pfd_read.fd = pconnection->sockd;
		pfd_read.events = POLLIN|POLLPRI;
		if (1 != poll(&pfd_read, 1, tv_msec)) {
			break;
		}
		if (NULL == pbuff) {
			read_len = read(pconnection->sockd,
					&buff_len, sizeof(uint32_t));
			if (read_len != sizeof(uint32_t)) {
				break;
			}
			/* ping packet */
			if (0 == buff_len) {
				if (1 != write(pconnection->sockd, resp_buff, 1)) {
					break;
				}
				continue;
			}
			pbuff = malloc(buff_len);
			if (NULL == pbuff) {
				tmp_byte = RESPONSE_CODE_LACK_MEMORY;
				write(pconnection->sockd, &tmp_byte, 1);
				if (FALSE == is_connected) {
					break;
				}
				buff_len = 0;
			}
			offset = 0;
			continue;
		}
		read_len = read(pconnection->sockd,
				pbuff + offset, buff_len - offset);
		if (read_len <= 0) {
			break;
		}
		offset += read_len;
		if (offset < buff_len) {
			continue;
		}
		exmdb_server_build_environment(FALSE, b_private, NULL);
		tmp_bin.pb = pbuff;
		tmp_bin.cb = buff_len;
		status = exmdb_ext_pull_request(&tmp_bin, &request);
		free(pbuff);
		pbuff = NULL;
		if (EXT_ERR_SUCCESS != status) {
			tmp_byte = RESPONSE_CODE_PULL_ERROR;
		} else {
			if (FALSE == is_connected) {
				if (CALL_ID_CONNECT == request.call_id) {
					if (FALSE == exmdb_parser_check_local(
						request.payload.connect.prefix, &b_private)) {
						tmp_byte = RESPONSE_CODE_MISCONFIG_PREFIX;
					} else {
						if (b_private != request.payload.connect.b_private) {
							tmp_byte = RESPONSE_CODE_MISCONFIG_MODE;
						} else {
							strcpy(pconnection->remote_id,
								request.payload.connect.remote_id);
							exmdb_server_free_environment();
							exmdb_server_set_remote_id(pconnection->remote_id);
							is_connected = TRUE;
							if (5 != write(pconnection->sockd, resp_buff, 5)) {
								break;
							}
							offset = 0;
							buff_len = 0;
							continue;
						}
					}
				} else if (CALL_ID_LISTEN_NOTIFICATION == request.call_id) {
					prouter = malloc(sizeof(ROUTER_CONNECTION));
					if (NULL == prouter) {
						tmp_byte = RESPONSE_CODE_LACK_MEMORY;
					} else {
						if (0 != g_max_routers && double_list_get_nodes_num(
							&g_router_list) >= g_max_routers) {
							free(prouter);
							tmp_byte = RESPONSE_CODE_MAX_REACHED;
						} else {
							strcpy(prouter->remote_id,
								request.payload.listen_notification.remote_id);
							exmdb_server_free_environment();
							if (5 != write(pconnection->sockd, resp_buff, 5)) {
								free(prouter);
								break;
							} else {
								prouter->node.pdata = prouter;
								prouter->b_stop = FALSE;
								prouter->thr_id = pconnection->thr_id;
								prouter->sockd = pconnection->sockd;
								time(&prouter->last_time);
								pthread_mutex_init(&prouter->lock, NULL);
								pthread_mutex_init(&prouter->cond_mutex, NULL);
								pthread_cond_init(&prouter->waken_cond, NULL);
								double_list_init(&prouter->datagram_list);
								pthread_mutex_lock(&g_router_lock);
								double_list_append_as_tail(
									&g_router_list, &prouter->node);
								pthread_mutex_unlock(&g_router_lock);
								pthread_mutex_lock(&g_connection_lock);
								double_list_remove(&g_connection_list,
													&pconnection->node);
								pthread_mutex_unlock(&g_connection_lock);
								free(pconnection);
								notification_agent_thread_work(prouter);
							}
						}
					}
				} else {
					tmp_byte = RESPONSE_CODE_CONNECT_UNCOMPLETE;
				}
			} else {
				if (FALSE == exmdb_parser_dispatch(&request, &response)) {
					tmp_byte = RESPONSE_CODE_DISPATCH_ERROR;
				} else {
					if (EXT_ERR_SUCCESS != exmdb_ext_push_response(
						&response, &tmp_bin)) {
						tmp_byte = RESPONSE_CODE_PUSH_ERROR;
					} else {
						exmdb_server_free_environment();
						offset = 0;
						pbuff = tmp_bin.pb;
						buff_len = tmp_bin.cb;
						is_writing = TRUE;
						continue;
					}
				}
			}
		}
		exmdb_server_free_environment();
		write(pconnection->sockd, &tmp_byte, 1);
		break;
	}
	close(pconnection->sockd);
	if (NULL != pbuff) {
		free(pbuff);
	}
	pthread_mutex_lock(&g_connection_lock);
	double_list_remove(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_connection_lock);
	if (FALSE == pconnection->b_stop) {
		pthread_detach(pthread_self());
	}
	free(pconnection);
	pthread_exit(0);
}

void exmdb_parser_put_connection(EXMDB_CONNECTION *pconnection)
{
	pthread_mutex_lock(&g_connection_lock);
	double_list_append_as_tail(&g_connection_list, &pconnection->node);
	pthread_mutex_unlock(&g_connection_lock);
	if (0 != pthread_create(&pconnection->thr_id,
		NULL, thread_work_func, pconnection)) {
		pthread_mutex_lock(&g_connection_lock);
		double_list_remove(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_connection_lock);
		free(pconnection);
		return;
	}
}

ROUTER_CONNECTION* exmdb_parser_get_router(const char *remote_id)
{
	DOUBLE_LIST_NODE *pnode;
	ROUTER_CONNECTION *prouter;
	
	pthread_mutex_lock(&g_router_lock);
	for (pnode=double_list_get_head(&g_router_list); NULL!=pnode;
		pnode=double_list_get_after(&g_router_list, pnode)) {
		prouter = (ROUTER_CONNECTION*)pnode->pdata;
		if (0 == strcmp(prouter->remote_id, remote_id)) {
			double_list_remove(&g_router_list, pnode);
			pthread_mutex_unlock(&g_router_lock);
			return prouter;
		}
	}
	pthread_mutex_unlock(&g_router_lock);
	return NULL;
}

void exmdb_parser_put_router(ROUTER_CONNECTION *pconnection)
{
	pthread_mutex_lock(&g_router_lock);
	double_list_append_as_tail(&g_router_list, &pconnection->node);
	pthread_mutex_unlock(&g_router_lock);
}

BOOL exmdb_parser_remove_router(ROUTER_CONNECTION *pconnection)
{
	DOUBLE_LIST_NODE *pnode;
	ROUTER_CONNECTION *prouter;
	
	pthread_mutex_lock(&g_router_lock);
	for (pnode=double_list_get_head(&g_router_list); NULL!=pnode;
		pnode=double_list_get_after(&g_router_list, pnode)) {
		prouter = (ROUTER_CONNECTION*)pnode->pdata;
		if (pconnection == prouter) {
			double_list_remove(&g_router_list, pnode);
			pthread_mutex_unlock(&g_router_lock);
			return TRUE;
		}
	}
	pthread_mutex_unlock(&g_router_lock);
	return FALSE;
}

int exmdb_parser_run()
{
	int i;
	int list_num;
	BOOL b_private;
	LIST_FILE *plist;
	LOCAL_SVR *plocal;
	EXMDB_ITEM *pitem;
	
	if ('\0' == g_list_path[0]) {
		return 0;
	}
	plist = list_file_init(g_list_path, "%s:256%s:16%s:16%d");
	if (NULL == plist) {
		printf("[exmdb_provider]: fail to open exmdb list file\n");
		return 1;
	}
	list_num = list_file_get_item_num(plist);
	pitem = (EXMDB_ITEM*)list_file_get_list(plist);
	for (i=0; i<list_num; i++) {
		if (0 == strcasecmp(pitem[i].type, "private")) {
			b_private = TRUE;
		} else if (0 == strcasecmp(pitem[i].type, "public")) {
			b_private = FALSE;
		} else {
			printf("[exmdb_provider]: unknown type \"%s\", only"
				"can be \"private\" or \"public\"!");
			list_file_free(plist);
			return 2;
		}
		if (FALSE == common_util_check_local_ip(pitem[i].ip_addr)) {
			continue;
		}
		plocal = malloc(sizeof(LOCAL_SVR));
		if (NULL == plocal) {
			printf("[exmdb_provider]: fail to allocate memory\n");
			list_file_free(plist);
			return 3;
		}
		plocal->node.pdata = plocal;
		strcpy(plocal->prefix, pitem[i].prefix);
		plocal->prefix_len = strlen(plocal->prefix);
		plocal->b_private = b_private;
		double_list_append_as_tail(&g_local_list, &plocal->node);
	}
	list_file_free(plist);
	return 0;
}

int exmdb_parser_stop()
{
	int i, num;
	pthread_t *pthr_ids;
	DOUBLE_LIST_NODE *pnode;
	ROUTER_CONNECTION *prouter;
	EXMDB_CONNECTION *pconnection;
	
	if ('\0' == g_list_path[0]) {
		return 0;
	}
	pthr_ids = NULL;
	pthread_mutex_lock(&g_connection_lock);
	num = double_list_get_nodes_num(&g_connection_list);
	if (num > 0) {
		pthr_ids = malloc(sizeof(pthread_t)*num);
		if (NULL == pthr_ids) {
			return -1;
		}
	}
	for (i=0,pnode=double_list_get_head(&g_connection_list);
		NULL!=pnode; pnode=double_list_get_after(
		&g_connection_list, pnode),i++) {
		pconnection = (EXMDB_CONNECTION*)pnode->pdata;
		pthr_ids[i] = pconnection->thr_id;
		pconnection->b_stop = TRUE;
		shutdown(pconnection->sockd, SHUT_RDWR);
	}
	pthread_mutex_unlock(&g_connection_lock);
	for (i=0; i<num; i++) {
		pthread_join(pthr_ids[i], NULL);
	}
	if (NULL != pthr_ids) {
		free(pthr_ids);
		pthr_ids = NULL;
	}
	pthread_mutex_lock(&g_router_lock);
	num = double_list_get_nodes_num(&g_router_list);
	if (num > 0) {
		pthr_ids = malloc(sizeof(pthread_t)*num);
		if (NULL == pthr_ids) {
			return -2;
		}
	}
	for (i=0,pnode=double_list_get_head(&g_router_list);
		NULL!=pnode; pnode=double_list_get_after(
		&g_router_list, pnode),i++) {
		prouter = (ROUTER_CONNECTION*)pnode->pdata;
		pthr_ids[i] = prouter->thr_id;
		prouter->b_stop = TRUE;
		pthread_cond_signal(&prouter->waken_cond);
	}
	pthread_mutex_unlock(&g_router_lock);
	for (i=0; i<num; i++) {
		pthread_join(pthr_ids[i], NULL);
	}
	if (NULL != pthr_ids) {
		free(pthr_ids);
		pthr_ids = NULL;
	}
	while (pnode=double_list_get_from_head(&g_local_list)) {
		free(pnode->pdata);
	}
	return 0;
}
