// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/socket.h>
#include "notification_agent.h"
#include "exmdb_parser.h"
#include "exmdb_server.h"
#include "common_util.h"
#include <gromox/mapi_types.hpp>
#include "exmdb_ext.h"
#include <gromox/list_file.hpp>
#include <gromox/idset.hpp>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <cstdio>
#include <poll.h>

static size_t g_max_threads, g_max_routers;
static std::vector<EXMDB_ITEM> g_local_list;
static std::unordered_set<std::shared_ptr<ROUTER_CONNECTION>> g_router_list;
static std::unordered_set<std::shared_ptr<EXMDB_CONNECTION>> g_connection_list;
static std::mutex g_router_lock, g_connection_lock;
unsigned int g_exrpc_debug, g_enable_dam;

EXMDB_CONNECTION::~EXMDB_CONNECTION()
{
	if (sockd >= 0)
		close(sockd);
}

ROUTER_CONNECTION::~ROUTER_CONNECTION()
{
	if (sockd >= 0)
		close(sockd);
	for (auto &&bin : datagram_list)
		free(bin.pb);
}

int exmdb_parser_get_param(int param)
{
	switch (param) {
	case ALIVE_ROUTER_CONNECTIONS:
		return g_router_list.size();
	}
	return -1;
}

void exmdb_parser_init(size_t max_threads, size_t max_routers)
{
	g_max_threads = max_threads;
	g_max_routers = max_routers;
}

std::shared_ptr<EXMDB_CONNECTION> exmdb_parser_get_connection()
{
	if (g_max_threads != 0 && g_connection_list.size() >= g_max_threads)
		return nullptr;
	try {
		return std::make_shared<EXMDB_CONNECTION>();
	} catch (const std::bad_alloc &) {
	}
	return nullptr;
}

static BOOL exmdb_parser_check_local(const char *prefix, BOOL *pb_private)
{
	auto i = std::find_if(g_local_list.cbegin(), g_local_list.cend(),
	         [&](const EXMDB_ITEM &s) { return strncmp(s.prefix.c_str(), prefix, s.prefix.size()) == 0; });
	if (i == g_local_list.cend())
		return false;
	*pb_private = i->type == EXMDB_ITEM::EXMDB_PRIVATE ? TRUE : false;
	return TRUE;
}

static BOOL exmdb_parser_dispatch2(const EXMDB_REQUEST *prequest,
	EXMDB_RESPONSE *presponse)
{
	BOOL b_return;
	
	switch (prequest->call_id) {
	case exmdb_callid::PING_STORE:
		return exmdb_server_ping_store(prequest->dir);
	case exmdb_callid::GET_ALL_NAMED_PROPIDS:
		return exmdb_server_get_all_named_propids(prequest->dir,
			&presponse->payload.get_all_named_propids.propids);
	case exmdb_callid::GET_NAMED_PROPIDS:
		return exmdb_server_get_named_propids(prequest->dir,
			prequest->payload.get_named_propids.b_create,
			prequest->payload.get_named_propids.ppropnames,
			&presponse->payload.get_named_propids.propids);
	case exmdb_callid::GET_NAMED_PROPNAMES:
		return exmdb_server_get_named_propnames(prequest->dir,
			prequest->payload.get_named_propnames.ppropids,
			&presponse->payload.get_named_propnames.propnames);
	case exmdb_callid::GET_MAPPING_GUID:
		return exmdb_server_get_mapping_guid(prequest->dir,
			prequest->payload.get_mapping_guid.replid,
			&presponse->payload.get_mapping_guid.b_found,
			&presponse->payload.get_mapping_guid.guid);
	case exmdb_callid::GET_MAPPING_REPLID:
		return exmdb_server_get_mapping_replid(prequest->dir,
			prequest->payload.get_mapping_replid.guid,
			&presponse->payload.get_mapping_replid.b_found,
			&presponse->payload.get_mapping_replid.replid);
	case exmdb_callid::GET_STORE_ALL_PROPTAGS:
		return exmdb_server_get_store_all_proptags(prequest->dir,
			&presponse->payload.get_store_all_proptags.proptags);
	case exmdb_callid::GET_STORE_PROPERTIES:
		return exmdb_server_get_store_properties(prequest->dir,
			prequest->payload.get_store_properties.cpid,
			prequest->payload.get_store_properties.pproptags,
			&presponse->payload.get_store_properties.propvals);
	case exmdb_callid::SET_STORE_PROPERTIES:
		return exmdb_server_set_store_properties(prequest->dir,
			prequest->payload.set_store_properties.cpid,
			prequest->payload.set_store_properties.ppropvals,
			&presponse->payload.set_store_properties.problems);
	case exmdb_callid::REMOVE_STORE_PROPERTIES:
		return exmdb_server_remove_store_properties(prequest->dir,
			prequest->payload.remove_store_properties.pproptags);
	case exmdb_callid::CHECK_MAILBOX_PERMISSION:
		return exmdb_server_check_mailbox_permission(prequest->dir,
			prequest->payload.check_mailbox_permission.username,
			&presponse->payload.check_mailbox_permission.permission);
	case exmdb_callid::GET_FOLDER_BY_CLASS:
		presponse->payload.get_folder_by_class.str_explicit = cu_alloc<char>(256);
		if (NULL == presponse->payload.get_folder_by_class.str_explicit) {
			return FALSE;
		}
		return exmdb_server_get_folder_by_class(prequest->dir,
			prequest->payload.get_folder_by_class.str_class,
			&presponse->payload.get_folder_by_class.id,
			presponse->payload.get_folder_by_class.str_explicit);
	case exmdb_callid::SET_FOLDER_BY_CLASS:
		return exmdb_server_set_folder_by_class(prequest->dir,
			prequest->payload.set_folder_by_class.folder_id,
			prequest->payload.set_folder_by_class.str_class,
			&presponse->payload.set_folder_by_class.b_result);
	case exmdb_callid::GET_FOLDER_CLASS_TABLE:
		return exmdb_server_get_folder_class_table(prequest->dir,
			&presponse->payload.get_folder_class_table.table);
	case exmdb_callid::CHECK_FOLDER_ID:
		return exmdb_server_check_folder_id(prequest->dir,
			prequest->payload.check_folder_id.folder_id,
			&presponse->payload.check_folder_id.b_exist);
	case exmdb_callid::QUERY_FOLDER_MESSAGES:
		return exmdb_server_query_folder_messages(prequest->dir,
			prequest->payload.query_folder_messages.folder_id,
			&presponse->payload.query_folder_messages.set);
	case exmdb_callid::CHECK_FOLDER_DELETED:
		return exmdb_server_check_folder_deleted(prequest->dir,
			prequest->payload.check_folder_deleted.folder_id,
			&presponse->payload.check_folder_deleted.b_del);
	case exmdb_callid::GET_FOLDER_BY_NAME:
		return exmdb_server_get_folder_by_name(prequest->dir,
			prequest->payload.get_folder_by_name.parent_id,
			prequest->payload.get_folder_by_name.str_name,
			&presponse->payload.get_folder_by_name.folder_id);
	case exmdb_callid::CHECK_FOLDER_PERMISSION:
		return exmdb_server_check_folder_permission(prequest->dir,
			prequest->payload.check_folder_permission.folder_id,
			prequest->payload.check_folder_permission.username,
			&presponse->payload.check_folder_permission.permission);
	case exmdb_callid::CREATE_FOLDER_BY_PROPERTIES:
		return exmdb_server_create_folder_by_properties(prequest->dir,
			prequest->payload.create_folder_by_properties.cpid,
			prequest->payload.create_folder_by_properties.pproperties,
			&presponse->payload.create_folder_by_properties.folder_id);
	case exmdb_callid::GET_FOLDER_ALL_PROPTAGS:
		return exmdb_server_get_folder_all_proptags(prequest->dir,
			prequest->payload.get_folder_all_proptags.folder_id,
			&presponse->payload.get_folder_all_proptags.proptags);
	case exmdb_callid::GET_FOLDER_PROPERTIES: {
		const auto &q = prequest->payload.get_folder_properties;
		return exmdb_server_get_folder_properties(prequest->dir,
		       q.cpid, q.folder_id, q.pproptags,
			&presponse->payload.get_folder_properties.propvals);
	}
	case exmdb_callid::SET_FOLDER_PROPERTIES: {
		const auto &q = prequest->payload.set_folder_properties;
		return exmdb_server_set_folder_properties(prequest->dir,
		       q.cpid, q.folder_id, q.pproperties,
			&presponse->payload.set_folder_properties.problems);
	}
	case exmdb_callid::REMOVE_FOLDER_PROPERTIES:
		return exmdb_server_remove_folder_properties(prequest->dir,
			prequest->payload.remove_folder_properties.folder_id,
			prequest->payload.remove_folder_properties.pproptags);
	case exmdb_callid::DELETE_FOLDER: {
		const auto &q = prequest->payload.delete_folder;
		return exmdb_server_delete_folder(prequest->dir,
		       q.cpid, q.folder_id, q.b_hard,
			&presponse->payload.delete_folder.b_result);
	}
	case exmdb_callid::EMPTY_FOLDER: {
		const auto &q = prequest->payload.empty_folder;
		return exmdb_server_empty_folder(prequest->dir,
		       q.cpid, q.username, q.folder_id, q.b_hard,
		       q.b_normal, q.b_fai, q.b_sub,
			&presponse->payload.empty_folder.b_partial);
	}
	case exmdb_callid::CHECK_FOLDER_CYCLE:
		return exmdb_server_check_folder_cycle(prequest->dir,
			prequest->payload.check_folder_cycle.src_fid,
			prequest->payload.check_folder_cycle.dst_fid,
			&presponse->payload.check_folder_cycle.b_cycle);
	case exmdb_callid::COPY_FOLDER_INTERNAL: {
		const auto &q = prequest->payload.copy_folder_internal;
		return exmdb_server_copy_folder_internal(prequest->dir,
		       q.account_id, q.cpid, q.b_guest, q.username, q.src_fid,
		       q.b_normal, q.b_fai, q.b_sub, q.dst_fid,
			&presponse->payload.copy_folder_internal.b_collid,
			&presponse->payload.copy_folder_internal.b_partial);
	}
	case exmdb_callid::GET_SEARCH_CRITERIA: {
		auto &r = presponse->payload.get_search_criteria;
		return exmdb_server_get_search_criteria(prequest->dir,
			prequest->payload.get_search_criteria.folder_id,
		       &r.search_status, &r.prestriction, &r.folder_ids);
	}
	case exmdb_callid::SET_SEARCH_CRITERIA: {
		const auto &q = prequest->payload.set_search_criteria;
		return exmdb_server_set_search_criteria(prequest->dir,
		       q.cpid, q.folder_id, q.search_flags, q.prestriction,
		       q.pfolder_ids,
			&presponse->payload.set_search_criteria.b_result);
	}
	case exmdb_callid::MOVECOPY_MESSAGE: {
		const auto &q = prequest->payload.movecopy_message;
		return exmdb_server_movecopy_message(prequest->dir,
		       q.account_id, q.cpid, q.message_id, q.dst_fid,
		       q.dst_id, q.b_move,
			&presponse->payload.movecopy_message.b_result);
	}
	case exmdb_callid::MOVECOPY_MESSAGES: {
		const auto &q = prequest->payload.movecopy_messages;
		return exmdb_server_movecopy_messages(prequest->dir,
		       q.account_id, q.cpid, q.b_guest, q.username, q.src_fid,
		       q.dst_fid, q.b_copy, q.pmessage_ids,
			&presponse->payload.movecopy_messages.b_partial);
	}
	case exmdb_callid::MOVECOPY_FOLDER: {
		const auto &q = prequest->payload.movecopy_folder;
		return exmdb_server_movecopy_folder(prequest->dir,
		       q.account_id, q.cpid, q.b_guest, q.username, q.src_pid,
		       q.src_fid, q.dst_fid, q.str_new, q.b_copy,
			&presponse->payload.movecopy_folder.b_exist,
			&presponse->payload.movecopy_folder.b_partial);
	}
	case exmdb_callid::DELETE_MESSAGES: {
		const auto &q = prequest->payload.delete_messages;
		return exmdb_server_delete_messages(prequest->dir,
		       q.account_id, q.cpid, q.username, q.folder_id,
		       q.pmessage_ids, q.b_hard,
			&presponse->payload.delete_messages.b_partial);
	}
	case exmdb_callid::GET_MESSAGE_BRIEF:
		return exmdb_server_get_message_brief(prequest->dir,
			prequest->payload.get_message_brief.cpid,
			prequest->payload.get_message_brief.message_id,
			&presponse->payload.get_message_brief.pbrief);
	case exmdb_callid::SUM_HIERARCHY: {
		const auto &q = prequest->payload.sum_hierarchy;
		return exmdb_server_sum_hierarchy(prequest->dir,
		       q.folder_id, q.username, q.b_depth,
			&presponse->payload.sum_hierarchy.count);
	}
	case exmdb_callid::LOAD_HIERARCHY_TABLE: {
		const auto &q = prequest->payload.load_hierarchy_table;
		return exmdb_server_load_hierarchy_table(prequest->dir,
		       q.folder_id, q.username, q.table_flags, q.prestriction,
			&presponse->payload.load_hierarchy_table.table_id,
			&presponse->payload.load_hierarchy_table.row_count);
	}
	case exmdb_callid::SUM_CONTENT: {
		const auto &q = prequest->payload.sum_content;
		return exmdb_server_sum_content(prequest->dir,
		       q.folder_id, q.b_fai, q.b_deleted,
			&presponse->payload.sum_content.count);
	}
	case exmdb_callid::LOAD_CONTENT_TABLE: {
		const auto &q = prequest->payload.load_content_table;
		return exmdb_server_load_content_table(prequest->dir,
		       q.cpid, q.folder_id, q.username, q.table_flags,
		       q.prestriction, q.psorts,
			&presponse->payload.load_content_table.table_id,
			&presponse->payload.load_content_table.row_count);
	}
	case exmdb_callid::LOAD_PERMISSION_TABLE:
		return exmdb_server_load_permission_table(prequest->dir,
			prequest->payload.load_permission_table.folder_id,
			prequest->payload.load_permission_table.table_flags,
			&presponse->payload.load_permission_table.table_id,
			&presponse->payload.load_permission_table.row_count);
	case exmdb_callid::LOAD_RULE_TABLE: {
		const auto &q = prequest->payload.load_rule_table;
		return exmdb_server_load_rule_table(prequest->dir,
		       q.folder_id, q.table_flags, q.prestriction,
			&presponse->payload.load_rule_table.table_id,
			&presponse->payload.load_rule_table.row_count);
	}
	case exmdb_callid::UNLOAD_TABLE:
		return exmdb_server_unload_table(prequest->dir,
				prequest->payload.unload_table.table_id);
	case exmdb_callid::SUM_TABLE:
		return exmdb_server_sum_table(prequest->dir,
			prequest->payload.sum_table.table_id,
			&presponse->payload.sum_table.rows);
	case exmdb_callid::QUERY_TABLE: {
		const auto &q = prequest->payload.query_table;
		return exmdb_server_query_table(prequest->dir,
		       q.username, q.cpid, q.table_id, q.pproptags,
		       q.start_pos, q.row_needed,
			&presponse->payload.query_table.set);
	}
	case exmdb_callid::MATCH_TABLE: {
		const auto &q = prequest->payload.match_table;
		return exmdb_server_match_table(prequest->dir,
		       q.username, q.cpid, q.table_id, q.b_forward,
		       q.start_pos, q.pres, q.pproptags,
			&presponse->payload.match_table.position,
			&presponse->payload.match_table.propvals);
	}
	case exmdb_callid::LOCATE_TABLE: {
		const auto &q = prequest->payload.locate_table;
		return exmdb_server_locate_table(prequest->dir,
		       q.table_id, q.inst_id, q.inst_num,
			&presponse->payload.locate_table.position,
			&presponse->payload.locate_table.row_type);
	}
	case exmdb_callid::READ_TABLE_ROW: {
		const auto &q = prequest->payload.read_table_row;
		return exmdb_server_read_table_row(prequest->dir,
		       q.username, q.cpid, q.table_id, q.pproptags,
		       q.inst_id, q.inst_num,
			&presponse->payload.read_table_row.propvals);
	}
	case exmdb_callid::MARK_TABLE: {
		auto &r = presponse->payload.mark_table;
		return exmdb_server_mark_table(prequest->dir,
			prequest->payload.mark_table.table_id,
			prequest->payload.mark_table.position,
		       &r.inst_id, &r.inst_num, &r.row_type);
	}
	case exmdb_callid::GET_TABLE_ALL_PROPTAGS:
		return exmdb_server_get_table_all_proptags(prequest->dir,
			prequest->payload.get_table_all_proptags.table_id,
			&presponse->payload.get_table_all_proptags.proptags);
	case exmdb_callid::EXPAND_TABLE:
		return exmdb_server_expand_table(prequest->dir,
			prequest->payload.expand_table.table_id,
			prequest->payload.expand_table.inst_id,
			&presponse->payload.expand_table.b_found,
			&presponse->payload.expand_table.position,
			&presponse->payload.expand_table.row_count);
	case exmdb_callid::COLLAPSE_TABLE:
		return exmdb_server_collapse_table(prequest->dir,
			prequest->payload.collapse_table.table_id,
			prequest->payload.collapse_table.inst_id,
			&presponse->payload.collapse_table.b_found,
			&presponse->payload.collapse_table.position,
			&presponse->payload.collapse_table.row_count);
	case exmdb_callid::STORE_TABLE_STATE:
		return exmdb_server_store_table_state(prequest->dir,
			prequest->payload.store_table_state.table_id,
			prequest->payload.store_table_state.inst_id,
			prequest->payload.store_table_state.inst_num,
			&presponse->payload.store_table_state.state_id);
	case exmdb_callid::RESTORE_TABLE_STATE:
		return exmdb_server_restore_table_state(prequest->dir,
			prequest->payload.restore_table_state.table_id,
			prequest->payload.restore_table_state.state_id,
			&presponse->payload.restore_table_state.position);
	case exmdb_callid::CHECK_MESSAGE:
		return exmdb_server_check_message(prequest->dir,
			prequest->payload.check_message.folder_id,
			prequest->payload.check_message.message_id,
			&presponse->payload.check_message.b_exist);
	case exmdb_callid::CHECK_MESSAGE_DELETED:
		return exmdb_server_check_message_deleted(prequest->dir,
			prequest->payload.check_message_deleted.message_id,
			&presponse->payload.check_message_deleted.b_del);
	case exmdb_callid::LOAD_MESSAGE_INSTANCE: {
		const auto &q = prequest->payload.load_message_instance;
		return exmdb_server_load_message_instance(prequest->dir,
		       q.username, q.cpid, q.b_new, q.folder_id, q.message_id,
			&presponse->payload.load_message_instance.instance_id);
	}
	case exmdb_callid::LOAD_EMBEDDED_INSTANCE:
		return exmdb_server_load_embedded_instance(prequest->dir,
			prequest->payload.load_embedded_instance.b_new,
			prequest->payload.load_embedded_instance.attachment_instance_id,
			&presponse->payload.load_embedded_instance.instance_id);
	case exmdb_callid::GET_EMBEDDED_CN:
		return exmdb_server_get_embedded_cn(prequest->dir,
		       prequest->payload.get_embedded_cn.instance_id,
		       &presponse->payload.get_embedded_cn.pcn);
	case exmdb_callid::RELOAD_MESSAGE_INSTANCE:
		return exmdb_server_reload_message_instance(prequest->dir,
			prequest->payload.reload_message_instance.instance_id,
			&presponse->payload.reload_message_instance.b_result);
	case exmdb_callid::CLEAR_MESSAGE_INSTANCE:
		return exmdb_server_clear_message_instance(prequest->dir,
			prequest->payload.clear_message_instance.instance_id);
	case exmdb_callid::READ_MESSAGE_INSTANCE:
		return exmdb_server_read_message_instance(prequest->dir,
			prequest->payload.read_message_instance.instance_id,
			&presponse->payload.read_message_instance.msgctnt);
	case exmdb_callid::WRITE_MESSAGE_INSTANCE:
		return exmdb_server_write_message_instance(prequest->dir,
			prequest->payload.write_message_instance.instance_id,
			prequest->payload.write_message_instance.pmsgctnt,
			prequest->payload.write_message_instance.b_force,
			&presponse->payload.write_message_instance.proptags,
			&presponse->payload.write_message_instance.problems);
	case exmdb_callid::LOAD_ATTACHMENT_INSTANCE:
		return exmdb_server_load_attachment_instance(prequest->dir,
			prequest->payload.load_attachment_instance.message_instance_id,
			prequest->payload.load_attachment_instance.attachment_num,
			&presponse->payload.load_attachment_instance.instance_id);
	case exmdb_callid::CREATE_ATTACHMENT_INSTANCE:
		return exmdb_server_create_attachment_instance(prequest->dir,
			prequest->payload.create_attachment_instance.message_instance_id,
			&presponse->payload.create_attachment_instance.instance_id,
			&presponse->payload.create_attachment_instance.attachment_num);
	case exmdb_callid::READ_ATTACHMENT_INSTANCE:
		return exmdb_server_read_attachment_instance(prequest->dir,
			prequest->payload.read_attachment_instance.instance_id,
			&presponse->payload.read_attachment_instance.attctnt);
	case exmdb_callid::WRITE_ATTACHMENT_INSTANCE:
		return exmdb_server_write_attachment_instance(prequest->dir,
			prequest->payload.write_attachment_instance.instance_id,
			prequest->payload.write_attachment_instance.pattctnt,
			prequest->payload.write_attachment_instance.b_force,
			&presponse->payload.write_attachment_instance.problems);
	case exmdb_callid::DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		return exmdb_server_delete_message_instance_attachment(prequest->dir,
			prequest->payload.delete_message_instance_attachment.message_instance_id,
			prequest->payload.delete_message_instance_attachment.attachment_num);
	case exmdb_callid::FLUSH_INSTANCE:
		return exmdb_server_flush_instance(prequest->dir,
			prequest->payload.flush_instance.instance_id,
			prequest->payload.flush_instance.account,
			&presponse->payload.flush_instance.e_result);
	case exmdb_callid::UNLOAD_INSTANCE:
		return exmdb_server_unload_instance(prequest->dir,
			prequest->payload.unload_instance.instance_id);
	case exmdb_callid::GET_INSTANCE_ALL_PROPTAGS:
		return exmdb_server_get_instance_all_proptags(prequest->dir,
			prequest->payload.get_instance_all_proptags.instance_id,
			&presponse->payload.get_instance_all_proptags.proptags);
	case exmdb_callid::GET_INSTANCE_PROPERTIES: {
		const auto &q = prequest->payload.get_instance_properties;
		return exmdb_server_get_instance_properties(prequest->dir,
		       q.size_limit, q.instance_id, q.pproptags,
			&presponse->payload.get_instance_properties.propvals);
	}
	case exmdb_callid::SET_INSTANCE_PROPERTIES:
		return exmdb_server_set_instance_properties(prequest->dir,
			prequest->payload.set_instance_properties.instance_id,
			prequest->payload.set_instance_properties.pproperties,
			&presponse->payload.set_instance_properties.problems);
	case exmdb_callid::REMOVE_INSTANCE_PROPERTIES:
		return exmdb_server_remove_instance_properties(prequest->dir,
			prequest->payload.remove_instance_properties.instance_id,
			prequest->payload.remove_instance_properties.pproptags,
			&presponse->payload.remove_instance_properties.problems);
	case exmdb_callid::CHECK_INSTANCE_CYCLE:
		return exmdb_server_check_instance_cycle(prequest->dir,
			prequest->payload.check_instance_cycle.src_instance_id,
			prequest->payload.check_instance_cycle.dst_instance_id,
			&presponse->payload.check_instance_cycle.b_cycle);
	case exmdb_callid::EMPTY_MESSAGE_INSTANCE_RCPTS:
		return exmdb_server_empty_message_instance_rcpts(prequest->dir,
			prequest->payload.empty_message_instance_rcpts.instance_id);
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS_NUM:
		return exmdb_server_get_message_instance_rcpts_num(prequest->dir,
			prequest->payload.get_message_instance_rcpts_num.instance_id,
			&presponse->payload.get_message_instance_rcpts_num.num);
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		return exmdb_server_get_message_instance_rcpts_all_proptags(prequest->dir,
			prequest->payload.get_message_instance_rcpts_all_proptags.instance_id,
			&presponse->payload.get_message_instance_rcpts_all_proptags.proptags);
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS: {
		const auto &q = prequest->payload.get_message_instance_rcpts;
		return exmdb_server_get_message_instance_rcpts(prequest->dir,
		       q.instance_id, q.row_id, q.need_count,
			&presponse->payload.get_message_instance_rcpts.set);
	}
	case exmdb_callid::UPDATE_MESSAGE_INSTANCE_RCPTS:
		return exmdb_server_update_message_instance_rcpts(prequest->dir,
			prequest->payload.update_message_instance_rcpts.instance_id,
			prequest->payload.update_message_instance_rcpts.pset);
	case exmdb_callid::EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		return exmdb_server_empty_message_instance_attachments(prequest->dir,
			prequest->payload.empty_message_instance_attachments.instance_id);
	case exmdb_callid::GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		return exmdb_server_get_message_instance_attachments_num(prequest->dir,
			prequest->payload.get_message_instance_attachments_num.instance_id,
			&presponse->payload.get_message_instance_attachments_num.num);
	case exmdb_callid::GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		return exmdb_server_get_message_instance_attachment_table_all_proptags(prequest->dir,
			prequest->payload.get_message_instance_attachment_table_all_proptags.instance_id,
			&presponse->payload.get_message_instance_attachment_table_all_proptags.proptags);
	case exmdb_callid::QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE: {
		const auto &q = prequest->payload.query_message_instance_attachment_table;
		return exmdb_server_query_message_instance_attachment_table(prequest->dir,
		       q.instance_id, q.pproptags, q.start_pos, q.row_needed,
			&presponse->payload.query_message_instance_attachment_table.set);
	}
	case exmdb_callid::COPY_INSTANCE_ATTACHMENTS: {
		const auto &q = prequest->payload.copy_instance_attachments;
		return exmdb_server_copy_instance_attachments(prequest->dir,
		       q.b_force, q.src_instance_id, q.dst_instance_id,
			&presponse->payload.copy_instance_attachments.b_result);
	}
	case exmdb_callid::SET_MESSAGE_INSTANCE_CONFLICT:
		return exmdb_server_set_message_instance_conflict(prequest->dir,
			prequest->payload.set_message_instance_conflict.instance_id,
			prequest->payload.set_message_instance_conflict.pmsgctnt);
	case exmdb_callid::GET_MESSAGE_RCPTS:
		return exmdb_server_get_message_rcpts(prequest->dir,
			prequest->payload.get_message_rcpts.message_id,
			&presponse->payload.get_message_rcpts.set);
	case exmdb_callid::GET_MESSAGE_PROPERTIES: {
		const auto &q = prequest->payload.get_message_properties;
		return exmdb_server_get_message_properties(prequest->dir,
		       q.username, q.cpid, q.message_id, q.pproptags,
			&presponse->payload.get_message_properties.propvals);
	}
	case exmdb_callid::SET_MESSAGE_PROPERTIES: {
		const auto &q = prequest->payload.set_message_properties;
		return exmdb_server_set_message_properties(prequest->dir,
		       q.username, q.cpid, q.message_id, q.pproperties,
			&presponse->payload.set_message_properties.problems);
	}
	case exmdb_callid::SET_MESSAGE_READ_STATE: {
		const auto &q = prequest->payload.set_message_read_state;
		return exmdb_server_set_message_read_state(prequest->dir,
		       q.username, q.message_id, q.mark_as_read,
			&presponse->payload.set_message_read_state.read_cn);
	}
	case exmdb_callid::REMOVE_MESSAGE_PROPERTIES: {
		const auto &q = prequest->payload.remove_message_properties;
		return exmdb_server_remove_message_properties(prequest->dir,
		       q.cpid, q.message_id, q.pproptags);
	}
	case exmdb_callid::ALLOCATE_MESSAGE_ID:
		return exmdb_server_allocate_message_id(prequest->dir,
			prequest->payload.allocate_message_id.folder_id,
			&presponse->payload.allocate_message_id.message_id);
	case exmdb_callid::ALLOCATE_CN:
		return exmdb_server_allocate_cn(prequest->dir,
			&presponse->payload.allocate_cn.cn);
	case exmdb_callid::GET_MESSAGE_GROUP_ID:
		return exmdb_server_get_message_group_id(prequest->dir,
			prequest->payload.get_message_group_id.message_id,
			&presponse->payload.get_message_group_id.pgroup_id);
	case exmdb_callid::SET_MESSAGE_GROUP_ID:
		return exmdb_server_set_message_group_id(prequest->dir,
			prequest->payload.set_message_group_id.message_id,
			prequest->payload.set_message_group_id.group_id);
	case exmdb_callid::SAVE_CHANGE_INDICES: {
		const auto &q = prequest->payload.save_change_indices;
		return exmdb_server_save_change_indices(prequest->dir,
		       q.message_id, q.cn, q.pindices, q.pungroup_proptags);
	}
	case exmdb_callid::GET_CHANGE_INDICES:
		return exmdb_server_get_change_indices(prequest->dir,
			prequest->payload.get_change_indices.message_id,
			prequest->payload.get_change_indices.cn,
			&presponse->payload.get_change_indices.indices,
			&presponse->payload.get_change_indices.ungroup_proptags);
	case exmdb_callid::MARK_MODIFIED:
		return exmdb_server_mark_modified(prequest->dir,
			prequest->payload.mark_modified.message_id);
	case exmdb_callid::TRY_MARK_SUBMIT:
		return exmdb_server_try_mark_submit(prequest->dir,
			prequest->payload.try_mark_submit.message_id,
			&presponse->payload.try_mark_submit.b_marked);
	case exmdb_callid::CLEAR_SUBMIT:
		return exmdb_server_clear_submit(prequest->dir,
			prequest->payload.clear_submit.message_id,
			prequest->payload.clear_submit.b_unsent);
	case exmdb_callid::LINK_MESSAGE: {
		const auto &q = prequest->payload.link_message;
		return exmdb_server_link_message(prequest->dir,
		       q.cpid, q.folder_id, q.message_id,
			&presponse->payload.link_message.b_result);
	}
	case exmdb_callid::UNLINK_MESSAGE: {
		const auto &q = prequest->payload.unlink_message;
		return exmdb_server_unlink_message(prequest->dir,
		       q.cpid, q.folder_id, q.message_id);
	}
	case exmdb_callid::RULE_NEW_MESSAGE: {
		const auto &q = prequest->payload.rule_new_message;
		return exmdb_server_rule_new_message(prequest->dir,
		       q.username, q.account, q.cpid, q.folder_id,
		       q.message_id);
	}
	case exmdb_callid::SET_MESSAGE_TIMER:
		return exmdb_server_set_message_timer(prequest->dir,
			prequest->payload.set_message_timer.message_id,
			prequest->payload.set_message_timer.timer_id);
	case exmdb_callid::GET_MESSAGE_TIMER:
		return exmdb_server_get_message_timer(prequest->dir,
			prequest->payload.get_message_timer.message_id,
			&presponse->payload.get_message_timer.ptimer_id);
	case exmdb_callid::EMPTY_FOLDER_PERMISSION:
		return exmdb_server_empty_folder_permission(prequest->dir,
			prequest->payload.empty_folder_permission.folder_id);
	case exmdb_callid::UPDATE_FOLDER_PERMISSION: {
		const auto &q = prequest->payload.update_folder_permission;
		return exmdb_server_update_folder_permission(prequest->dir,
		       q.folder_id, q.b_freebusy, q.count, q.prow);
	}
	case exmdb_callid::EMPTY_FOLDER_RULE:
		return exmdb_server_empty_folder_rule(prequest->dir,
			prequest->payload.empty_folder_rule.folder_id);
	case exmdb_callid::UPDATE_FOLDER_RULE: {
		const auto &q = prequest->payload.update_folder_rule;
		return exmdb_server_update_folder_rule(prequest->dir,
		       q.folder_id, q.count, q.prow,
			&presponse->payload.update_folder_rule.b_exceed);
	}
	case exmdb_callid::DELIVERY_MESSAGE: {
		const auto &q = prequest->payload.delivery_message;
		return exmdb_server_delivery_message(prequest->dir,
		       q.from_address, q.account, q.cpid, q.pmsg, q.pdigest,
			&presponse->payload.delivery_message.result);
	}
	case exmdb_callid::WRITE_MESSAGE: {
		const auto &q = prequest->payload.write_message;
		return exmdb_server_write_message(prequest->dir,
		       q.account, q.cpid, q.folder_id, q.pmsgctnt,
			&presponse->payload.write_message.e_result);
	}
	case exmdb_callid::READ_MESSAGE: {
		const auto &q = prequest->payload.read_message;
		return exmdb_server_read_message(prequest->dir,
		       q.username, q.cpid, q.message_id,
			&presponse->payload.read_message.pmsgctnt);
	}
	case exmdb_callid::GET_CONTENT_SYNC: {
		auto &q = prequest->payload.get_content_sync;
		auto &r = presponse->payload.get_content_sync;
		b_return = exmdb_server_get_content_sync(prequest->dir,
		           q.folder_id, q.username, q.pgiven, q.pseen,
		           q.pseen_fai, q.pread, q.cpid, q.prestriction,
		           q.b_ordered, &r.fai_count, &r.fai_total,
		           &r.normal_count, &r.normal_total, &r.updated_mids,
		           &r.chg_mids, &r.last_cn, &r.given_mids,
		           &r.deleted_mids, &r.nolonger_mids, &r.read_mids,
		           &r.unread_mids, &r.last_readcn);
		if (q.pgiven != nullptr)
			idset_free(q.pgiven);
		if (q.pseen != nullptr)
			idset_free(q.pseen);
		if (q.pseen_fai != nullptr)
			idset_free(q.pseen_fai);
		if (q.pread != nullptr)
			idset_free(q.pread);
		return b_return;
	}
	case exmdb_callid::GET_HIERARCHY_SYNC: {
		auto &q = prequest->payload.get_hierarchy_sync;
		auto &r = presponse->payload.get_hierarchy_sync;
		b_return = exmdb_server_get_hierarchy_sync(prequest->dir,
		           q.folder_id, q.username, q.pgiven, q.pseen,
		           &r.fldchgs, &r.last_cn, &r.given_fids,
		           &r.deleted_fids);
		if (q.pgiven != nullptr)
			idset_free(q.pgiven);
		if (q.pseen != nullptr)
			idset_free(q.pseen);
		return b_return;
	}
	case exmdb_callid::ALLOCATE_IDS:
		return exmdb_server_allocate_ids(prequest->dir,
			prequest->payload.allocate_ids.count,
			&presponse->payload.allocate_ids.begin_eid);
	case exmdb_callid::SUBSCRIBE_NOTIFICATION: {
		const auto &q = prequest->payload.subscribe_notification;
		return exmdb_server_subscribe_notification(prequest->dir,
		       q.notificaton_type, q.b_whole, q.folder_id, q.message_id,
			&presponse->payload.subscribe_notification.sub_id);
	}
	case exmdb_callid::UNSUBSCRIBE_NOTIFICATION:
		return exmdb_server_unsubscribe_notification(prequest->dir,
			prequest->payload.unsubscribe_notification.sub_id);
	case exmdb_callid::TRANSPORT_NEW_MAIL: {
		const auto &q = prequest->payload.transport_new_mail;
		return exmdb_server_transport_new_mail(prequest->dir,
		       q.folder_id, q.message_id, q.message_flags,
		       q.pstr_class);
	}
	case exmdb_callid::RELOAD_CONTENT_TABLE:
		return exmdb_server_reload_content_table(prequest->dir,
			prequest->payload.reload_content_table.table_id);
	case exmdb_callid::COPY_INSTANCE_RCPTS: {
		const auto &q = prequest->payload.copy_instance_rcpts;
		return exmdb_server_copy_instance_rcpts(prequest->dir,
		       q.b_force, q.src_instance_id, q.dst_instance_id,
			&presponse->payload.copy_instance_rcpts.b_result);
	}
	case exmdb_callid::CHECK_CONTACT_ADDRESS:
		return exmdb_server_check_contact_address(prequest->dir,
			prequest->payload.check_contact_address.paddress,
			&presponse->payload.check_contact_address.b_found);
	case exmdb_callid::GET_PUBLIC_FOLDER_UNREAD_COUNT:
		return exmdb_server_get_public_folder_unread_count(prequest->dir,
				prequest->payload.get_public_folder_unread_count.username,
				prequest->payload.get_public_folder_unread_count.folder_id,
				&presponse->payload.get_public_folder_unread_count.count);
	case exmdb_callid::UNLOAD_STORE:
		return exmdb_server_unload_store(prequest->dir);
	default:
		return FALSE;
	}
}

static BOOL exmdb_parser_dispatch(const EXMDB_REQUEST *prequest,
	EXMDB_RESPONSE *presponse)
{
	presponse->call_id = prequest->call_id;
	if (access(prequest->dir, R_OK | X_OK) < 0)
		printf("exmdb rpc %s accessing %s: %s\n", exmdb_rpc_idtoname(prequest->call_id),
		       prequest->dir, strerror(errno));
	exmdb_server_set_dir(prequest->dir);
	auto ret = exmdb_parser_dispatch2(prequest, presponse);
	if (g_exrpc_debug == 0)
		return ret;
	if (!ret || g_exrpc_debug == 2)
		fprintf(stderr, "EXRPC %s %s\n",
		        ret == 0 ? "FAIL" : "ok  ",
		        exmdb_rpc_idtoname(prequest->call_id));
	return ret;
}

static void *mdpps_thrwork(void *pparam)
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
	uint8_t resp_buff[5]{};
	EXMDB_REQUEST request;
	struct pollfd pfd_read;
	EXMDB_RESPONSE response;
	
	b_private = FALSE; /* whatever for connect request */
	/* unordered_set currently owns it, now take another ref */
	auto pconnection = static_cast<EXMDB_CONNECTION *>(pparam)->shared_from_this();
	pthread_setname_np(pconnection->thr_id, "exmdb_parser");
	pbuff = NULL;
	offset = 0;
	buff_len = 0;
	is_writing = FALSE;
	is_connected = FALSE;
	while (!pconnection->b_stop) {
		if (TRUE == is_writing) {
			written_len = write(pconnection->sockd,
			              static_cast<char *>(pbuff) + offset, buff_len - offset);
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
				tmp_byte = exmdb_response::LACK_MEMORY;
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
		           static_cast<char *>(pbuff) + offset, buff_len - offset);
		if (read_len <= 0) {
			break;
		}
		offset += read_len;
		if (offset < buff_len) {
			continue;
		}
		exmdb_server_build_environment(FALSE, b_private, NULL);
		tmp_bin.pv = pbuff;
		tmp_bin.cb = buff_len;
		status = exmdb_ext_pull_request(&tmp_bin, &request);
		free(pbuff);
		pbuff = NULL;
		if (EXT_ERR_SUCCESS != status) {
			tmp_byte = exmdb_response::PULL_ERROR;
		} else if (!is_connected) {
			if (request.call_id == exmdb_callid::CONNECT) {
				if (FALSE == exmdb_parser_check_local(
					request.payload.connect.prefix, &b_private)) {
					tmp_byte = exmdb_response::MISCONFIG_PREFIX;
				} else if (b_private != request.payload.connect.b_private) {
					tmp_byte = exmdb_response::MISCONFIG_MODE;
				} else {
					pconnection->remote_id = request.payload.connect.remote_id;
					exmdb_server_free_environment();
					exmdb_server_set_remote_id(pconnection->remote_id.c_str());
					is_connected = TRUE;
					if (5 != write(pconnection->sockd, resp_buff, 5)) {
						break;
					}
					offset = 0;
					buff_len = 0;
					continue;
				}
			} else if (request.call_id == exmdb_callid::LISTEN_NOTIFICATION) {
				std::shared_ptr<ROUTER_CONNECTION> prouter;
				try {
					prouter = std::make_shared<ROUTER_CONNECTION>();
					prouter->remote_id.reserve(strlen(request.payload.listen_notification.remote_id));
				} catch (const std::bad_alloc &) {
				}
				if (NULL == prouter) {
					tmp_byte = exmdb_response::LACK_MEMORY;
				} else if (g_max_routers != 0 && g_router_list.size() >= g_max_routers) {
					tmp_byte = exmdb_response::MAX_REACHED;
				} else {
					prouter->remote_id = request.payload.listen_notification.remote_id;
					exmdb_server_free_environment();
					if (5 != write(pconnection->sockd, resp_buff, 5)) {
						break;
					} else {
						prouter->thr_id = pconnection->thr_id;
						prouter->sockd = pconnection->sockd;
						pconnection->thr_id = {};
						pconnection->sockd = -1;
						time(&prouter->last_time);
						std::unique_lock r_hold(g_router_lock);
						g_router_list.insert(prouter);
						r_hold.unlock();
						std::unique_lock chold(g_connection_lock);
						g_connection_list.erase(pconnection);
						chold.unlock();
						notification_agent_thread_work(std::move(prouter));
					}
				}
			} else {
				tmp_byte = exmdb_response::CONNECT_INCOMPLETE;
			}
		} else if (!exmdb_parser_dispatch(&request, &response)) {
			tmp_byte = exmdb_response::DISPATCH_ERROR;
		} else if (EXT_ERR_SUCCESS != exmdb_ext_push_response(&response, &tmp_bin)) {
			tmp_byte = exmdb_response::PUSH_ERROR;
		} else {
			exmdb_server_free_environment();
			offset = 0;
			pbuff = tmp_bin.pb;
			buff_len = tmp_bin.cb;
			is_writing = TRUE;
			continue;
		}
		exmdb_server_free_environment();
		write(pconnection->sockd, &tmp_byte, 1);
		break;
	}
	close(pconnection->sockd);
	pconnection->sockd = -1;
	if (NULL != pbuff) {
		free(pbuff);
	}
	return nullptr;
}

void exmdb_parser_put_connection(std::shared_ptr<EXMDB_CONNECTION> &&pconnection)
{
	std::unique_lock chold(g_connection_lock);
	auto stpair = g_connection_list.insert(pconnection);
	chold.unlock();
	auto ret = pthread_create(&pconnection->thr_id, nullptr, mdpps_thrwork, pconnection.get());
	if (ret == 0)
		return;
	fprintf(stderr, "W-1440: pthread_create: %s\n", strerror(ret));
	chold.lock();
	g_connection_list.erase(stpair.first);
}

std::shared_ptr<ROUTER_CONNECTION> exmdb_parser_get_router(const char *remote_id)
{
	std::lock_guard rhold(g_router_lock);
	auto it = std::find_if(g_router_list.begin(), g_router_list.end(),
	          [&](const auto &r) { return r->remote_id == remote_id; });
	if (it == g_router_list.end())
		return nullptr;
	auto rt = *it;
	g_router_list.erase(it);
	return rt;
}

void exmdb_parser_put_router(std::shared_ptr<ROUTER_CONNECTION> &&pconnection)
{
	std::lock_guard rhold(g_router_lock);
	try {
		g_router_list.insert(std::move(pconnection));
	} catch (const std::bad_alloc &) {
	}
}

BOOL exmdb_parser_remove_router(const std::shared_ptr<ROUTER_CONNECTION> &pconnection)
{
	std::lock_guard rhold(g_router_lock);
	auto it = g_router_list.find(pconnection);
	if (it == g_router_list.cend())
		return false;
	g_router_list.erase(it);
	return TRUE;
}

int exmdb_parser_run(const char *config_path)
{
	auto ret = list_file_read_exmdb("exmdb_list.txt", config_path, g_local_list);
	if (ret < 0) {
		printf("[exmdb_provider]: list_file_read_exmdb: %s\n", strerror(-ret));
		return 1;
	}
	g_local_list.erase(std::remove_if(g_local_list.begin(), g_local_list.end(),
		[&](const EXMDB_ITEM &s) { return !gx_peer_is_local(s.host.c_str()); }),
		g_local_list.end());
	return 0;
}

void exmdb_parser_stop()
{
	size_t i = 0;
	pthread_t *pthr_ids;
	
	pthr_ids = NULL;
	std::unique_lock chold(g_connection_lock);
	size_t num = g_connection_list.size();
	if (num > 0) {
		pthr_ids = me_alloc<pthread_t>(num);
		if (NULL == pthr_ids) {
			return;
		}
	for (auto &pconnection : g_connection_list) {
		pthr_ids[i++] = pconnection->thr_id;
		pconnection->b_stop = true;
		shutdown(pconnection->sockd, SHUT_RDWR);
		pthread_kill(pconnection->thr_id, SIGALRM);
	}
	chold.unlock();
	for (i=0; i<num; i++) {
		pthread_join(pthr_ids[i], NULL);
	}
	if (NULL != pthr_ids) {
		free(pthr_ids);
		pthr_ids = NULL;
	}
	}
	std::unique_lock rhold(g_router_lock);
	num = g_router_list.size();
	if (num > 0) {
		pthr_ids = me_alloc<pthread_t>(num);
		if (NULL == pthr_ids) {
			return;
		}
	i = 0;
	for (auto &rt : g_router_list) {
		pthr_ids[i++] = rt->thr_id;
		rt->b_stop = true;
		rt->waken_cond.notify_one();
		pthread_kill(rt->thr_id, SIGALRM);
	}
	rhold.unlock();
	for (i=0; i<num; i++) {
		pthread_join(pthr_ids[i], NULL);
	}
	if (NULL != pthr_ids) {
		free(pthr_ids);
		pthr_ids = NULL;
	}
	}
}
