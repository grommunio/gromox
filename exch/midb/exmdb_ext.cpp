// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/exmdb_rpc.hpp>
#include "exmdb_ext.h"
#include <gromox/rop_util.hpp>
#include <gromox/idset.hpp>
#define TRY(expr) do { int v = (expr); if (v != EXT_ERR_SUCCESS) return v; } while (false)

static int exmdb_ext_push_connect_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_string(pext, ppayload->connect.prefix));
	TRY(ext_buffer_push_string(pext, ppayload->connect.remote_id));
	return ext_buffer_push_bool(pext,
			ppayload->connect.b_private);
}

static int exmdb_ext_push_listen_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
			ppayload->listen_notification.remote_id);
}	

static int exmdb_ext_push_get_named_propids_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_bool(pext, ppayload->get_named_propids.b_create));
	return ext_buffer_push_propname_array(pext,
		ppayload->get_named_propids.ppropnames);
}

static int exmdb_ext_push_get_named_propnames_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_propid_array(pext,
		ppayload->get_named_propnames.ppropids);
}

static int exmdb_ext_push_get_mapping_guid_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint16(pext,
		ppayload->get_mapping_guid.replid);
}

static int exmdb_ext_push_get_mapping_replid_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_guid(pext,
		&ppayload->get_mapping_replid.guid);
}

static int exmdb_ext_push_get_store_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->get_store_properties.cpid));
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_store_properties.pproptags);
}

static int exmdb_ext_push_set_store_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->get_store_properties.cpid));
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_store_properties.ppropvals);
}

static int exmdb_ext_push_remove_store_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_store_properties.pproptags);
}

static int exmdb_ext_push_check_mailbox_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
		ppayload->check_mailbox_permission.username);
}

static int exmdb_ext_push_get_folder_by_class_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
		ppayload->get_folder_by_class.str_class);
}

static int exmdb_ext_push_set_folder_by_class_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->set_folder_by_class.folder_id));
	return ext_buffer_push_string(pext,
		ppayload->set_folder_by_class.str_class);
}

static int exmdb_ext_push_check_folder_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->check_folder_id.folder_id);
}

static int exmdb_ext_push_query_folder_messages_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->query_folder_messages.folder_id);
}

static int exmdb_ext_push_check_folder_deleted_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->check_folder_deleted.folder_id);
}

static int exmdb_ext_push_get_folder_by_name_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->get_folder_by_name.parent_id));
	return ext_buffer_push_string(pext,
		ppayload->get_folder_by_name.str_name);
}

static int exmdb_ext_push_check_folder_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->check_folder_permission.folder_id));
	return ext_buffer_push_string(pext,
		ppayload->check_folder_permission.username);
}

static int exmdb_ext_push_create_folder_by_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->create_folder_by_properties.cpid));
	return ext_buffer_push_tpropval_array(pext,
		ppayload->create_folder_by_properties.pproperties);
}

static int exmdb_ext_push_get_folder_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_folder_all_proptags.folder_id);
}

static int exmdb_ext_push_get_folder_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->get_folder_properties.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->get_folder_properties.folder_id));
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_folder_properties.pproptags);
}

static int exmdb_ext_push_set_folder_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->set_folder_properties.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->set_folder_properties.folder_id));
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_folder_properties.pproperties);
}

static int exmdb_ext_push_remove_folder_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->remove_folder_properties.folder_id));
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_folder_properties.pproptags);
}

static int exmdb_ext_push_delete_folder_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->delete_folder.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->delete_folder.folder_id));
	return ext_buffer_push_bool(pext,
		ppayload->delete_folder.b_hard);
}

static int exmdb_ext_push_empty_folder_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->empty_folder.cpid));
	if (NULL == ppayload->empty_folder.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->empty_folder.username));
	}
	TRY(ext_buffer_push_uint64(pext, ppayload->empty_folder.folder_id));
	TRY(ext_buffer_push_bool(pext, ppayload->empty_folder.b_hard));
	TRY(ext_buffer_push_bool(pext, ppayload->empty_folder.b_normal));
	TRY(ext_buffer_push_bool(pext, ppayload->empty_folder.b_fai));
	return ext_buffer_push_bool(pext,
		ppayload->empty_folder.b_sub);
}

static int exmdb_ext_push_check_folder_cycle_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->check_folder_cycle.src_fid));
	return ext_buffer_push_uint64(pext,
		ppayload->check_folder_cycle.dst_fid);
}

static int exmdb_ext_push_copy_folder_internal_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->copy_folder_internal.account_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->copy_folder_internal.cpid));
	TRY(ext_buffer_push_bool(pext, ppayload->copy_folder_internal.b_guest));
	if (NULL == ppayload->copy_folder_internal.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->copy_folder_internal.username));
	}
	TRY(ext_buffer_push_uint64(pext, ppayload->copy_folder_internal.src_fid));
	TRY(ext_buffer_push_bool(pext, ppayload->copy_folder_internal.b_normal));
	TRY(ext_buffer_push_bool(pext, ppayload->copy_folder_internal.b_fai));
	TRY(ext_buffer_push_bool(pext, ppayload->copy_folder_internal.b_sub));
	return ext_buffer_push_uint64(pext,
		ppayload->copy_folder_internal.dst_fid);
}

static int exmdb_ext_push_get_search_criteria_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_search_criteria.folder_id);
}

static int exmdb_ext_push_set_search_criteria_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->set_search_criteria.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->set_search_criteria.folder_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->set_search_criteria.search_flags));
	if (NULL == ppayload->set_search_criteria.prestriction) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_restriction(pext, ppayload->set_search_criteria.prestriction));
	}
	return ext_buffer_push_longlong_array(pext,
		ppayload->set_search_criteria.pfolder_ids);
}

static int exmdb_ext_push_movecopy_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->movecopy_message.account_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->movecopy_message.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_message.message_id));
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_message.dst_fid));
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_message.dst_id));
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_message.b_move);
}

static int exmdb_ext_push_movecopy_messages_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->movecopy_messages.account_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->movecopy_messages.cpid));
	TRY(ext_buffer_push_bool(pext, ppayload->movecopy_messages.b_guest));
	if (NULL == ppayload->movecopy_messages.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->movecopy_messages.username));
	}
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_messages.src_fid));
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_messages.dst_fid));
	TRY(ext_buffer_push_bool(pext, ppayload->movecopy_messages.b_copy));
	return ext_buffer_push_eid_array(pext,
		ppayload->movecopy_messages.pmessage_ids);
}

static int exmdb_ext_push_movecopy_folder_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->movecopy_folder.account_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->movecopy_folder.cpid));
	TRY(ext_buffer_push_bool(pext, ppayload->movecopy_folder.b_guest));
	if (NULL == ppayload->movecopy_folder.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->movecopy_folder.username));
	}
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_folder.src_pid));
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_folder.src_fid));
	TRY(ext_buffer_push_uint64(pext, ppayload->movecopy_folder.dst_fid));
	TRY(ext_buffer_push_string(pext, ppayload->movecopy_folder.str_new));
	return ext_buffer_push_bool(pext,
		ppayload->movecopy_folder.b_copy);
}

static int exmdb_ext_push_delete_messages_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->delete_messages.account_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->delete_messages.cpid));
	if (NULL == ppayload->delete_messages.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->delete_messages.username));
	}
	TRY(ext_buffer_push_uint64(pext, ppayload->delete_messages.folder_id));
	TRY(ext_buffer_push_eid_array(pext, ppayload->delete_messages.pmessage_ids));
	return ext_buffer_push_bool(pext,
		ppayload->delete_messages.b_hard);
}

static int exmdb_ext_push_get_message_brief_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->get_message_brief.cpid));
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_brief.message_id);
}

static int exmdb_ext_push_sum_hierarchy_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->sum_hierarchy.folder_id));
	if (NULL == ppayload->sum_hierarchy.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->sum_hierarchy.username));
	}
	return ext_buffer_push_bool(pext,
		ppayload->sum_hierarchy.b_depth);
}

static int exmdb_ext_push_load_hierarchy_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->load_hierarchy_table.folder_id));
	if (NULL == ppayload->load_hierarchy_table.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->load_hierarchy_table.username));
	}
	TRY(ext_buffer_push_uint8(pext, ppayload->load_hierarchy_table.table_flags));
	if (NULL == ppayload->load_hierarchy_table.prestriction) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		return ext_buffer_push_restriction(pext,
			ppayload->load_hierarchy_table.prestriction);
	}
}

static int exmdb_ext_push_sum_content_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->sum_content.folder_id));
	TRY(ext_buffer_push_bool(pext, ppayload->sum_content.b_fai));
	return ext_buffer_push_bool(pext,
		ppayload->sum_content.b_deleted);
}

static int exmdb_ext_push_load_content_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->load_content_table.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->load_content_table.folder_id));
	if (NULL == ppayload->load_content_table.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->load_content_table.username));
	}
	TRY(ext_buffer_push_uint8(pext, ppayload->load_content_table.table_flags));
	if (NULL == ppayload->load_content_table.prestriction) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_restriction(pext, ppayload->load_content_table.prestriction));
	}
	if (NULL == ppayload->load_content_table.psorts) {
		return ext_buffer_push_uint8(pext, 0);
	}
	TRY(ext_buffer_push_uint8(pext, 1));
	return ext_buffer_push_sortorder_set(pext,
		ppayload->load_content_table.psorts);
}

static int exmdb_ext_push_reload_content_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->reload_content_table.table_id);
}

static int exmdb_ext_push_load_permission_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint8(pext,
		ppayload->load_permission_table.table_flags);
}

static int exmdb_ext_push_load_rule_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->load_rule_table.folder_id));
	TRY(ext_buffer_push_uint8(pext, ppayload->load_rule_table.table_flags));
	if (NULL == ppayload->load_rule_table.prestriction) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		return ext_buffer_push_restriction(pext,
			ppayload->load_rule_table.prestriction);
	}
}

static int exmdb_ext_push_unload_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unload_table.table_id);
}

static int exmdb_ext_push_sum_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->sum_table.table_id);
}

static int exmdb_ext_push_query_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->query_table.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->query_table.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->query_table.cpid));
	TRY(ext_buffer_push_uint32(pext, ppayload->query_table.table_id));
	TRY(ext_buffer_push_proptag_array( pext, ppayload->query_table.pproptags));
	TRY(ext_buffer_push_uint32(pext, ppayload->query_table.start_pos));
	return ext_buffer_push_int32(pext, ppayload->query_table.row_needed);
}

static int exmdb_ext_push_match_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->match_table.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->match_table.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->match_table.cpid));
	TRY(ext_buffer_push_uint32(pext, ppayload->match_table.table_id));
	TRY(ext_buffer_push_bool(pext, ppayload->match_table.b_forward));
	TRY(ext_buffer_push_uint32(pext, ppayload->match_table.start_pos));
	TRY(ext_buffer_push_restriction( pext, ppayload->match_table.pres));
	return ext_buffer_push_proptag_array(pext,
			ppayload->match_table.pproptags);
}

static int exmdb_ext_push_locate_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->locate_table.table_id));
	TRY(ext_buffer_push_uint64(pext, ppayload->locate_table.inst_id));
	return ext_buffer_push_uint32(pext,
		ppayload->locate_table.inst_num);
}

static int exmdb_ext_push_read_table_row_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->read_table_row.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->read_table_row.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->read_table_row.cpid));
	TRY(ext_buffer_push_uint32(pext, ppayload->read_table_row.table_id));
	TRY(ext_buffer_push_proptag_array(pext, ppayload->read_table_row.pproptags));
	TRY(ext_buffer_push_uint64(pext, ppayload->read_table_row.inst_id));
	return ext_buffer_push_uint32(pext,
		ppayload->read_table_row.inst_num);
}

static int exmdb_ext_push_mark_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->mark_table.table_id));
	return ext_buffer_push_uint32(pext,
		ppayload->mark_table.position);
}

static int exmdb_ext_push_get_table_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_table_all_proptags.table_id);
}

static int exmdb_ext_push_expand_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->expand_table.table_id));
	return ext_buffer_push_uint64(pext,
		ppayload->expand_table.inst_id);
}

static int exmdb_ext_push_collapse_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->collapse_table.table_id));
	return ext_buffer_push_uint64(pext,
		ppayload->collapse_table.inst_id);
}

static int exmdb_ext_push_store_table_state_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->store_table_state.table_id));
	TRY(ext_buffer_push_uint64(pext, ppayload->store_table_state.inst_id));
	return ext_buffer_push_uint32(pext,
		ppayload->store_table_state.inst_num);
}

static int exmdb_ext_push_restore_table_state_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->restore_table_state.table_id));
	return ext_buffer_push_uint32(pext,
		ppayload->restore_table_state.state_id);
}

static int exmdb_ext_push_check_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->check_message.folder_id));
	return ext_buffer_push_uint64(pext,
		ppayload->check_message.message_id);
}

static int exmdb_ext_push_check_message_deleted_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->check_message_deleted.message_id);
}

static int exmdb_ext_push_load_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->load_message_instance.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->load_message_instance.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->load_message_instance.cpid));
	TRY(ext_buffer_push_bool(pext, ppayload->load_message_instance.b_new));
	TRY(ext_buffer_push_uint64(pext, ppayload->load_message_instance.folder_id));
	return ext_buffer_push_uint64(pext,
		ppayload->load_message_instance.message_id);
}

static int exmdb_ext_push_load_embedded_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_bool(pext, ppayload->load_embedded_instance.b_new));
	return ext_buffer_push_uint32(pext,
		ppayload->load_embedded_instance.attachment_instance_id);
}

static int exmdb_ext_push_get_embedded_cn_request(EXT_PUSH *pext,
    const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext, ppayload->get_embedded_cn.instance_id);
}

static int exmdb_ext_push_reload_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->reload_message_instance.instance_id);
}

static int exmdb_ext_push_clear_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->clear_message_instance.instance_id);
}

static int exmdb_ext_push_read_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->read_message_instance.instance_id);
}

static int exmdb_ext_push_write_message_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->write_message_instance.instance_id));
	TRY(ext_buffer_push_message_content(pext, ppayload->write_message_instance.pmsgctnt));
	return ext_buffer_push_bool(pext,
		ppayload->write_message_instance.b_force);
}

static int exmdb_ext_push_load_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->load_attachment_instance.message_instance_id));
	return ext_buffer_push_uint32(pext,
		ppayload->load_attachment_instance.attachment_num);
}

static int exmdb_ext_push_create_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->create_attachment_instance.message_instance_id);
}

static int exmdb_ext_push_read_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->read_attachment_instance.instance_id);
}

static int exmdb_ext_push_write_attachment_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->write_attachment_instance.instance_id));
	TRY(ext_buffer_push_tpropval_array(pext, &ppayload->write_attachment_instance.pattctnt->proplist));
	if (NULL == ppayload->write_attachment_instance.pattctnt->pembedded) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_message_content(pext, ppayload->write_attachment_instance.pattctnt->pembedded));
	}
	return ext_buffer_push_bool(pext,
		ppayload->write_attachment_instance.b_force);
}

static int exmdb_ext_push_delete_message_instance_attachment_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->delete_message_instance_attachment.message_instance_id));
	return ext_buffer_push_uint32(pext,
		ppayload->delete_message_instance_attachment.attachment_num);
}

static int exmdb_ext_push_flush_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->flush_instance.instance_id));
	if (NULL == ppayload->flush_instance.account) {
		return ext_buffer_push_uint8(pext, 0);
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		return ext_buffer_push_string(pext,
			ppayload->flush_instance.account);
	}
}

static int exmdb_ext_push_unload_instance_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unload_instance.instance_id);
}

static int exmdb_ext_push_get_instance_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_instance_all_proptags.instance_id);
}

static int exmdb_ext_push_get_instance_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->get_instance_properties.size_limit));
	TRY(ext_buffer_push_uint32(pext, ppayload->get_instance_properties.instance_id));
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_instance_properties.pproptags);
}

static int exmdb_ext_push_set_instance_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->set_instance_properties.instance_id));
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_instance_properties.pproperties);
}

static int exmdb_ext_push_remove_instance_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->remove_instance_properties.instance_id));
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_instance_properties.pproptags);
}

static int exmdb_ext_push_check_instance_cycle_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->check_instance_cycle.src_instance_id));
	return ext_buffer_push_uint32(pext,
		ppayload->check_instance_cycle.dst_instance_id);
}

static int exmdb_ext_push_empty_message_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->empty_message_instance_rcpts.instance_id);
}

static int exmdb_ext_push_get_message_instance_rcpts_num_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_rcpts_num.instance_id);	
}

static int exmdb_ext_push_get_message_instance_rcpts_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_rcpts_all_proptags.instance_id);	
}

static int exmdb_ext_push_get_message_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->get_message_instance_rcpts.instance_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->get_message_instance_rcpts.row_id));
	return ext_buffer_push_uint16(pext,
		ppayload->get_message_instance_rcpts.need_count);
}

static int exmdb_ext_push_update_message_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->update_message_instance_rcpts.instance_id));
	return ext_buffer_push_tarray_set(pext,
		ppayload->update_message_instance_rcpts.pset);
}

static int exmdb_ext_push_copy_instance_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_bool(pext, ppayload->copy_instance_rcpts.b_force));
	TRY(ext_buffer_push_uint32(pext, ppayload->copy_instance_rcpts.src_instance_id));
	return ext_buffer_push_uint32(pext,
		ppayload->copy_instance_rcpts.dst_instance_id);
}

static int exmdb_ext_push_empty_message_instance_attachments_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->empty_message_instance_attachments.instance_id);	
}

static int exmdb_ext_push_get_message_instance_attachments_num_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_attachments_num.instance_id);
}

static int exmdb_ext_push_get_message_instance_attachment_table_all_proptags_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->get_message_instance_attachment_table_all_proptags.instance_id);
}

static int exmdb_ext_push_query_message_instance_attachment_table_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->query_message_instance_attachment_table.instance_id));
	TRY(ext_buffer_push_proptag_array(pext, ppayload->query_message_instance_attachment_table.pproptags));
	TRY(ext_buffer_push_uint32(pext, ppayload->query_message_instance_attachment_table.start_pos));
	return ext_buffer_push_int32(pext,
		ppayload->query_message_instance_attachment_table.row_needed);
}

static int exmdb_ext_push_copy_instance_attachments_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_bool(pext, ppayload->copy_instance_attachments.b_force));
	TRY(ext_buffer_push_uint32(pext, ppayload->copy_instance_attachments.src_instance_id));
	return ext_buffer_push_uint32(pext,
		ppayload->copy_instance_attachments.dst_instance_id);
}

static int exmdb_ext_push_set_message_instance_conflict_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->set_message_instance_conflict.instance_id));
	return ext_buffer_push_message_content(pext,
		ppayload->set_message_instance_conflict.pmsgctnt);
}

static int exmdb_ext_push_get_message_rcpts_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_rcpts.message_id);
}

static int exmdb_ext_push_get_message_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->get_message_properties.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->get_message_properties.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->get_message_properties.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->get_message_properties.message_id));
	return ext_buffer_push_proptag_array(pext,
		ppayload->get_message_properties.pproptags);
}

static int exmdb_ext_push_set_message_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->set_message_properties.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->set_message_properties.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->set_message_properties.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->set_message_properties.message_id));
	return ext_buffer_push_tpropval_array(pext,
		ppayload->set_message_properties.pproperties);
}

static int exmdb_ext_push_set_message_read_state_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->set_message_read_state.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->set_message_read_state.username));
	}
	TRY(ext_buffer_push_uint64(pext, ppayload->set_message_read_state.message_id));
	return ext_buffer_push_uint8(pext,
		ppayload->set_message_read_state.mark_as_read);
}

static int exmdb_ext_push_remove_message_properties_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->remove_message_properties.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->remove_message_properties.message_id));
	return ext_buffer_push_proptag_array(pext,
		ppayload->remove_message_properties.pproptags);
}

static int exmdb_ext_push_allocate_message_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->allocate_message_id.folder_id);
}

static int exmdb_ext_push_get_message_group_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_group_id.message_id);
}

static int exmdb_ext_push_set_message_group_id_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->set_message_group_id.message_id));
	return ext_buffer_push_uint32(pext,
		ppayload->set_message_group_id.group_id);
}

static int exmdb_ext_push_save_change_indices_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->save_change_indices.message_id));
	TRY(ext_buffer_push_uint64(pext, ppayload->save_change_indices.cn));
	TRY(ext_buffer_push_proptag_array(pext, ppayload->save_change_indices.pindices));
	return ext_buffer_push_proptag_array(pext,
		ppayload->save_change_indices.pungroup_proptags);
}

static int exmdb_ext_push_get_change_indices_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->get_change_indices.message_id));
	return ext_buffer_push_uint64(pext,
		ppayload->get_change_indices.cn);
}

static int exmdb_ext_push_mark_modified_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->mark_modified.message_id);
}

static int exmdb_ext_push_try_mark_submit_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->try_mark_submit.message_id);
}

static int exmdb_ext_push_clear_submit_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->clear_submit.message_id));
	return ext_buffer_push_bool(pext,
		ppayload->clear_submit.b_unsent);
}

static int exmdb_ext_push_link_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->link_message.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->link_message.folder_id));
	return ext_buffer_push_uint64(pext,
		ppayload->link_message.message_id);
}

static int exmdb_ext_push_unlink_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint32(pext, ppayload->unlink_message.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->unlink_message.folder_id));
	return ext_buffer_push_uint64(pext,
		ppayload->unlink_message.message_id);
}

static int exmdb_ext_push_rule_new_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->rule_new_message.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->rule_new_message.username));
	}
	TRY(ext_buffer_push_string(pext, ppayload->rule_new_message.account));
	TRY(ext_buffer_push_uint32(pext, ppayload->rule_new_message.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->rule_new_message.folder_id));
	return ext_buffer_push_uint64(pext,
		ppayload->rule_new_message.message_id);
}

static int exmdb_ext_push_set_message_timer_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->set_message_timer.message_id));
	return ext_buffer_push_uint32(pext,
		ppayload->set_message_timer.timer_id);
}

static int exmdb_ext_push_get_message_timer_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->get_message_timer.message_id);
}

static int exmdb_ext_push_empty_folder_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->empty_folder_permission.folder_id);
}

static int exmdb_ext_push_update_folder_permission_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	TRY(ext_buffer_push_uint64(pext, ppayload->update_folder_permission.folder_id));
	TRY(ext_buffer_push_bool(pext, ppayload->update_folder_permission.b_freebusy));
	TRY(ext_buffer_push_uint16(pext, ppayload->update_folder_permission.count));
	for (i=0; i<ppayload->update_folder_permission.count; i++) {
		TRY(ext_buffer_push_permission_data(pext, ppayload->update_folder_permission.prow + i));
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_push_empty_folder_rule_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint64(pext,
		ppayload->empty_folder_rule.folder_id);
}

static int exmdb_ext_push_update_folder_rule_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int i;
	
	TRY(ext_buffer_push_uint64(pext, ppayload->update_folder_rule.folder_id));
	TRY(ext_buffer_push_uint16(pext, ppayload->update_folder_rule.count));
	for (i=0; i<ppayload->update_folder_rule.count; i++) {
		TRY(ext_buffer_push_rule_data(pext, ppayload->update_folder_rule.prow + i));
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_push_delivery_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_string(pext, ppayload->delivery_message.from_address));
	TRY(ext_buffer_push_string(pext, ppayload->delivery_message.account));
	TRY(ext_buffer_push_uint32(pext, ppayload->delivery_message.cpid));
	TRY(ext_buffer_push_message_content( pext, ppayload->delivery_message.pmsg));
	return ext_buffer_push_string(pext,
		ppayload->delivery_message.pdigest);
}

static int exmdb_ext_push_write_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_string(pext, ppayload->write_message.account));
	TRY(ext_buffer_push_uint32(pext, ppayload->write_message.cpid));
	TRY(ext_buffer_push_uint64(pext, ppayload->write_message.folder_id));
	return ext_buffer_push_message_content(pext,
		ppayload->write_message.pmsgctnt);
}

static int exmdb_ext_push_read_message_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	if (NULL == ppayload->read_message.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->read_message.username));
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->read_message.cpid));
	return ext_buffer_push_uint64(pext, ppayload->read_message.message_id);
}

static int exmdb_ext_push_get_content_sync_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	BINARY *pbin;
	
	TRY(ext_buffer_push_uint64(pext, ppayload->get_content_sync.folder_id));
	if (NULL == ppayload->get_content_sync.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->get_content_sync.username));
	}
	pbin = idset_serialize_replid(
		ppayload->get_content_sync.pgiven);
	if (NULL == pbin) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_exbinary(pext, pbin);
	if (EXT_ERR_SUCCESS != status) {
		rop_util_free_binary(pbin);
		return status;
	}
	rop_util_free_binary(pbin);
	if (NULL == ppayload->get_content_sync.pseen) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		pbin = idset_serialize_replid(
			ppayload->get_content_sync.pseen);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	if (NULL == ppayload->get_content_sync.pseen_fai) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		pbin = idset_serialize_replid(
			ppayload->get_content_sync.pseen_fai);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	if (NULL == ppayload->get_content_sync.pread) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		pbin = idset_serialize_replid(
			ppayload->get_content_sync.pread);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	TRY(ext_buffer_push_uint32(pext, ppayload->get_content_sync.cpid));
	if (NULL == ppayload->get_content_sync.prestriction) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_restriction(pext, ppayload->get_content_sync.prestriction));
	}
	return ext_buffer_push_bool(pext,
		ppayload->get_content_sync.b_ordered);
}

static int exmdb_ext_push_get_hierarchy_sync_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	int status;
	BINARY *pbin;
	
	TRY(ext_buffer_push_uint64(pext, ppayload->get_hierarchy_sync.folder_id));
	if (NULL == ppayload->get_hierarchy_sync.username) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		TRY(ext_buffer_push_string(pext, ppayload->get_hierarchy_sync.username));
	}
	pbin = idset_serialize_replid(
		ppayload->get_hierarchy_sync.pgiven);
	if (NULL == pbin) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_exbinary(pext, pbin);
	if (EXT_ERR_SUCCESS != status) {
		rop_util_free_binary(pbin);
		return status;
	}
	rop_util_free_binary(pbin);
	if (NULL == ppayload->get_hierarchy_sync.pseen) {
		TRY(ext_buffer_push_uint8(pext, 0));
	} else {
		TRY(ext_buffer_push_uint8(pext, 1));
		pbin = idset_serialize_replid(
			ppayload->get_hierarchy_sync.pseen);
		if (NULL == pbin) {
			return EXT_ERR_ALLOC;
		}
		status = ext_buffer_push_exbinary(pext, pbin);
		if (EXT_ERR_SUCCESS != status) {
			rop_util_free_binary(pbin);
			return status;
		}
		rop_util_free_binary(pbin);
	}
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_push_allocate_ids_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->allocate_ids.count);
}

static int exmdb_ext_push_subscribe_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint16(pext, ppayload->subscribe_notification.notificaton_type));
	TRY(ext_buffer_push_bool(pext, ppayload->subscribe_notification.b_whole));
	TRY(ext_buffer_push_uint64(pext, ppayload->subscribe_notification.folder_id));
	return ext_buffer_push_uint64(pext,
		ppayload->subscribe_notification.message_id);
}

static int exmdb_ext_push_unsubscribe_notification_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_uint32(pext,
		ppayload->unsubscribe_notification.sub_id);
}

static int exmdb_ext_push_transport_new_mail_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	TRY(ext_buffer_push_uint64(pext, ppayload->transport_new_mail.folder_id));
	TRY(ext_buffer_push_uint64(pext, ppayload->transport_new_mail.message_id));
	TRY(ext_buffer_push_uint32(pext, ppayload->transport_new_mail.message_flags));
	return ext_buffer_push_string(pext,
		ppayload->transport_new_mail.pstr_class);
}

static int exmdb_ext_push_check_contact_address_request(
	EXT_PUSH *pext, const REQUEST_PAYLOAD *ppayload)
{
	return ext_buffer_push_string(pext,
		ppayload->check_contact_address.paddress);
}

int exmdb_ext_push_request(const EXMDB_REQUEST *prequest,
	BINARY *pbin_out)
{
	int status;
	EXT_PUSH ext_push;
	
	if (FALSE == ext_buffer_push_init(
		&ext_push, NULL, 0, EXT_FLAG_WCOUNT)) {
		return EXT_ERR_ALLOC;
	}
	status = ext_buffer_push_advance(&ext_push, sizeof(uint32_t));
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	status = ext_buffer_push_uint8(&ext_push, prequest->call_id);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	if (prequest->call_id == exmdb_callid::CONNECT) {
		status = exmdb_ext_push_connect_request(
				&ext_push, &prequest->payload);
		goto END_PUSH_REQUEST;
	} else if (prequest->call_id == exmdb_callid::LISTEN_NOTIFICATION) {
		status = exmdb_ext_push_listen_notification_request(
							&ext_push, &prequest->payload);
		goto END_PUSH_REQUEST;
	}
	status = ext_buffer_push_string(&ext_push, prequest->dir);
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	switch (prequest->call_id) {
	case exmdb_callid::PING_STORE:
		status = EXT_ERR_SUCCESS;
		break;
	case exmdb_callid::GET_ALL_NAMED_PROPIDS:
		status = EXT_ERR_SUCCESS;
		break;
	case exmdb_callid::GET_NAMED_PROPIDS:
		status = exmdb_ext_push_get_named_propids_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_NAMED_PROPNAMES:
		status = exmdb_ext_push_get_named_propnames_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MAPPING_GUID:
		status = exmdb_ext_push_get_mapping_guid_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MAPPING_REPLID:
		status = exmdb_ext_push_get_mapping_replid_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_STORE_ALL_PROPTAGS:
		status = EXT_ERR_SUCCESS;
		break;
	case exmdb_callid::GET_STORE_PROPERTIES:
		status = exmdb_ext_push_get_store_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_STORE_PROPERTIES:
		status = exmdb_ext_push_set_store_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::REMOVE_STORE_PROPERTIES:
		status = exmdb_ext_push_remove_store_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_MAILBOX_PERMISSION:
		status = exmdb_ext_push_check_mailbox_permission_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_FOLDER_BY_CLASS:
		status = exmdb_ext_push_get_folder_by_class_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_FOLDER_BY_CLASS:
		status = exmdb_ext_push_set_folder_by_class_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_FOLDER_CLASS_TABLE:
		status = EXT_ERR_SUCCESS;
		break;
	case exmdb_callid::CHECK_FOLDER_ID:
		status = exmdb_ext_push_check_folder_id_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::QUERY_FOLDER_MESSAGES:
		status = exmdb_ext_push_query_folder_messages_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_FOLDER_DELETED:
		status = exmdb_ext_push_check_folder_deleted_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_FOLDER_BY_NAME:
		status = exmdb_ext_push_get_folder_by_name_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_FOLDER_PERMISSION:
		status = exmdb_ext_push_check_folder_permission_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CREATE_FOLDER_BY_PROPERTIES:
		status = exmdb_ext_push_create_folder_by_properties_request(
										&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_FOLDER_ALL_PROPTAGS:
		status = exmdb_ext_push_get_folder_all_proptags_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_FOLDER_PROPERTIES:
		status = exmdb_ext_push_get_folder_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_FOLDER_PROPERTIES:
		status = exmdb_ext_push_set_folder_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::REMOVE_FOLDER_PROPERTIES:
		status = exmdb_ext_push_remove_folder_properties_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::DELETE_FOLDER:
		status = exmdb_ext_push_delete_folder_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::EMPTY_FOLDER:
		status = exmdb_ext_push_empty_folder_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_FOLDER_CYCLE:
		status = exmdb_ext_push_check_folder_cycle_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::COPY_FOLDER_INTERNAL:
		status = exmdb_ext_push_copy_folder_internal_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_SEARCH_CRITERIA:
		status = exmdb_ext_push_get_search_criteria_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_SEARCH_CRITERIA:
		status = exmdb_ext_push_set_search_criteria_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::MOVECOPY_MESSAGE:
		status = exmdb_ext_push_movecopy_message_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::MOVECOPY_MESSAGES:
		status = exmdb_ext_push_movecopy_messages_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::MOVECOPY_FOLDER:
		status = exmdb_ext_push_movecopy_folder_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::DELETE_MESSAGES:
		status = exmdb_ext_push_delete_messages_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_BRIEF:
		status = exmdb_ext_push_get_message_brief_request(
							&ext_push,  &prequest->payload);
		break;
	case exmdb_callid::SUM_HIERARCHY:
		status = exmdb_ext_push_sum_hierarchy_request(
						&ext_push,  &prequest->payload);
		break;
	case exmdb_callid::LOAD_HIERARCHY_TABLE:
		status = exmdb_ext_push_load_hierarchy_table_request(
							&ext_push,  &prequest->payload);
		break;
	case exmdb_callid::SUM_CONTENT:
		status = exmdb_ext_push_sum_content_request(
					&ext_push,  &prequest->payload);
		break;
	case exmdb_callid::LOAD_CONTENT_TABLE:
		status = exmdb_ext_push_load_content_table_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::RELOAD_CONTENT_TABLE:
		status = exmdb_ext_push_reload_content_table_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LOAD_PERMISSION_TABLE:
		status = exmdb_ext_push_load_permission_table_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LOAD_RULE_TABLE:
		status = exmdb_ext_push_load_rule_table_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UNLOAD_TABLE:
		status = exmdb_ext_push_unload_table_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SUM_TABLE:
		status = exmdb_ext_push_sum_table_request(
					&ext_push, &prequest->payload);
		break;
	case exmdb_callid::QUERY_TABLE:
		status = exmdb_ext_push_query_table_request(
					&ext_push, &prequest->payload);
		break;
	case exmdb_callid::MATCH_TABLE:
		status = exmdb_ext_push_match_table_request(
					&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LOCATE_TABLE:
		status = exmdb_ext_push_locate_table_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::READ_TABLE_ROW:
		status = exmdb_ext_push_read_table_row_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::MARK_TABLE:
		status = exmdb_ext_push_mark_table_request(
					&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_TABLE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_table_all_proptags_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::EXPAND_TABLE:
		status = exmdb_ext_push_expand_table_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::COLLAPSE_TABLE:
		status = exmdb_ext_push_collapse_table_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::STORE_TABLE_STATE:
		status = exmdb_ext_push_store_table_state_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::RESTORE_TABLE_STATE:
		status = exmdb_ext_push_restore_table_state_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_MESSAGE:
		status = exmdb_ext_push_check_message_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_MESSAGE_DELETED:
		status = exmdb_ext_push_check_message_deleted_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LOAD_MESSAGE_INSTANCE:
		status = exmdb_ext_push_load_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LOAD_EMBEDDED_INSTANCE:
		status = exmdb_ext_push_load_embedded_instance_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_EMBEDDED_CN:
		status = exmdb_ext_push_get_embedded_cn_request(&ext_push, &prequest->payload);
		break;
	case exmdb_callid::RELOAD_MESSAGE_INSTANCE:
		status = exmdb_ext_push_reload_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CLEAR_MESSAGE_INSTANCE:
		status = exmdb_ext_push_clear_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::READ_MESSAGE_INSTANCE:
		status = exmdb_ext_push_read_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::WRITE_MESSAGE_INSTANCE:
		status = exmdb_ext_push_write_message_instance_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LOAD_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_load_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CREATE_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_create_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::READ_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_read_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::WRITE_ATTACHMENT_INSTANCE:
		status = exmdb_ext_push_write_attachment_instance_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		status = exmdb_ext_push_delete_message_instance_attachment_request(
											&ext_push, &prequest->payload);
		break;
	case exmdb_callid::FLUSH_INSTANCE:
		status = exmdb_ext_push_flush_instance_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UNLOAD_INSTANCE:
		status = exmdb_ext_push_unload_instance_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_INSTANCE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_instance_all_proptags_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_get_instance_properties_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_set_instance_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::REMOVE_INSTANCE_PROPERTIES:
		status = exmdb_ext_push_remove_instance_properties_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_INSTANCE_CYCLE:
		status = exmdb_ext_push_check_instance_cycle_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::EMPTY_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_empty_message_instance_rcpts_request(
										&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS_NUM:
		status = exmdb_ext_push_get_message_instance_rcpts_num_request(
										&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		status = exmdb_ext_push_get_message_instance_rcpts_all_proptags_request(
												&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_get_message_instance_rcpts_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UPDATE_MESSAGE_INSTANCE_RCPTS:
		status = exmdb_ext_push_update_message_instance_rcpts_request(
										&ext_push, &prequest->payload);
		break;
	case exmdb_callid::COPY_INSTANCE_RCPTS:
		status = exmdb_ext_push_copy_instance_rcpts_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		status = exmdb_ext_push_empty_message_instance_attachments_request(
											&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		status = exmdb_ext_push_get_message_instance_attachments_num_request(
												&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		status = exmdb_ext_push_get_message_instance_attachment_table_all_proptags_request(
															&ext_push, &prequest->payload);
		break;
	case exmdb_callid::QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		status = exmdb_ext_push_query_message_instance_attachment_table_request(
												&ext_push, &prequest->payload);
		break;
	case exmdb_callid::COPY_INSTANCE_ATTACHMENTS:
		status = exmdb_ext_push_copy_instance_attachments_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_MESSAGE_INSTANCE_CONFLICT:
		status = exmdb_ext_push_set_message_instance_conflict_request(
										&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_RCPTS:
		status = exmdb_ext_push_get_message_rcpts_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_get_message_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_set_message_properties_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_MESSAGE_READ_STATE:
		status = exmdb_ext_push_set_message_read_state_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::REMOVE_MESSAGE_PROPERTIES:
		status = exmdb_ext_push_remove_message_properties_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::ALLOCATE_MESSAGE_ID:
		status = exmdb_ext_push_allocate_message_id_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::ALLOCATE_CN:
		status = EXT_ERR_SUCCESS;
		break;
	case exmdb_callid::GET_MESSAGE_GROUP_ID:
		status = exmdb_ext_push_get_message_group_id_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_MESSAGE_GROUP_ID:
		status = exmdb_ext_push_set_message_group_id_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SAVE_CHANGE_INDICES:
		status = exmdb_ext_push_save_change_indices_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_CHANGE_INDICES:
		status = exmdb_ext_push_get_change_indices_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::MARK_MODIFIED:
		status = exmdb_ext_push_mark_modified_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::TRY_MARK_SUBMIT:
		status = exmdb_ext_push_try_mark_submit_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CLEAR_SUBMIT:
		status = exmdb_ext_push_clear_submit_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::LINK_MESSAGE:
		status = exmdb_ext_push_link_message_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UNLINK_MESSAGE:
		status = exmdb_ext_push_unlink_message_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::RULE_NEW_MESSAGE:
		status = exmdb_ext_push_rule_new_message_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SET_MESSAGE_TIMER:
		status = exmdb_ext_push_set_message_timer_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_MESSAGE_TIMER:
		status = exmdb_ext_push_get_message_timer_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::EMPTY_FOLDER_PERMISSION:
		status = exmdb_ext_push_empty_folder_permission_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UPDATE_FOLDER_PERMISSION:
		status = exmdb_ext_push_update_folder_permission_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::EMPTY_FOLDER_RULE:
		status = exmdb_ext_push_empty_folder_rule_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UPDATE_FOLDER_RULE:
		status = exmdb_ext_push_update_folder_rule_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::DELIVERY_MESSAGE:
		status = exmdb_ext_push_delivery_message_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::WRITE_MESSAGE:
		status = exmdb_ext_push_write_message_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::READ_MESSAGE:
		status = exmdb_ext_push_read_message_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_CONTENT_SYNC:
		status = exmdb_ext_push_get_content_sync_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::GET_HIERARCHY_SYNC:
		status = exmdb_ext_push_get_hierarchy_sync_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::ALLOCATE_IDS:
		status = exmdb_ext_push_allocate_ids_request(
						&ext_push, &prequest->payload);
		break;
	case exmdb_callid::SUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_subscribe_notification_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UNSUBSCRIBE_NOTIFICATION:
		status = exmdb_ext_push_unsubscribe_notification_request(
									&ext_push, &prequest->payload);
		break;
	case exmdb_callid::TRANSPORT_NEW_MAIL:
		status = exmdb_ext_push_transport_new_mail_request(
							&ext_push, &prequest->payload);
		break;
	case exmdb_callid::CHECK_CONTACT_ADDRESS:
		status = exmdb_ext_push_check_contact_address_request(
								&ext_push, &prequest->payload);
		break;
	case exmdb_callid::UNLOAD_STORE:
		status = EXT_ERR_SUCCESS;
		break;
	default:
		ext_buffer_push_free(&ext_push);
		return EXT_ERR_BAD_SWITCH;
	}
 END_PUSH_REQUEST:
	if (EXT_ERR_SUCCESS != status) {
		ext_buffer_push_free(&ext_push);
		return status;
	}
	pbin_out->cb = ext_push.offset;
	ext_push.offset = 0;
	ext_buffer_push_uint32(&ext_push,
		pbin_out->cb - sizeof(uint32_t));
	/* memory referenced by ext_push.data will be freed outside */
	pbin_out->pb = ext_buffer_push_release(&ext_push);
	return EXT_ERR_SUCCESS;
}

static int exmdb_ext_pull_get_all_named_propids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_propid_array(pext,
		&ppayload->get_all_named_propids.propids);
}

static int exmdb_ext_pull_get_named_propids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_propid_array(pext,
		&ppayload->get_named_propids.propids);
}

static int exmdb_ext_pull_get_named_propnames_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_propname_array(pext,
		&ppayload->get_named_propnames.propnames);
}

static int exmdb_ext_pull_get_mapping_guid_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_bool(pext, &ppayload->get_mapping_guid.b_found));
	return ext_buffer_pull_guid(pext,
		&ppayload->get_mapping_guid.guid);
}

static int exmdb_ext_pull_get_mapping_replid_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_bool(pext, &ppayload->get_mapping_replid.b_found));
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_mapping_replid.replid);
}

static int exmdb_ext_pull_get_store_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_store_all_proptags.proptags);
}

static int exmdb_ext_pull_get_store_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_store_properties.propvals);
}

static int exmdb_ext_pull_set_store_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_store_properties.problems);
}

static int exmdb_ext_pull_check_mailbox_permission_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->check_mailbox_permission.permission);
}

static int exmdb_ext_pull_get_folder_by_class_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint64(pext, &ppayload->get_folder_by_class.id));
	return ext_buffer_pull_string(pext,
		&ppayload->get_folder_by_class.str_explicit);
}

static int exmdb_ext_pull_set_folder_by_class_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->set_folder_by_class.b_result);
}

static int exmdb_ext_pull_get_folder_class_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->get_folder_class_table.table);
}

static int exmdb_ext_pull_check_folder_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_folder_id.b_exist);
}

static int exmdb_ext_pull_query_folder_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->query_folder_messages.set);
}

static int exmdb_ext_pull_check_folder_deleted_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_folder_deleted.b_del);
}

static int exmdb_ext_pull_get_folder_by_name_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_folder_by_name.folder_id);
}

static int exmdb_ext_pull_check_folder_permission_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->check_folder_permission.permission);
}

static int exmdb_ext_pull_create_folder_by_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->create_folder_by_properties.folder_id);
}

static int exmdb_ext_pull_get_folder_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_folder_all_proptags.proptags);
}

static int exmdb_ext_pull_get_folder_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_folder_properties.propvals);
}

static int exmdb_ext_pull_set_folder_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_folder_properties.problems);
}

static int exmdb_ext_pull_delete_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->delete_folder.b_result);
}

static int exmdb_ext_pull_empty_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->empty_folder.b_partial);
}

static int exmdb_ext_pull_check_folder_cycle_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_folder_cycle.b_cycle);
}

static int exmdb_ext_pull_copy_folder_internal_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_bool(pext, &ppayload->copy_folder_internal.b_collid));
	return ext_buffer_pull_bool(pext,
		&ppayload->copy_folder_internal.b_partial);
}

static int exmdb_ext_pull_get_search_criteria_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_uint32(pext, &ppayload->get_search_criteria.search_status));
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_search_criteria.prestriction = NULL;
	} else {
		ppayload->get_search_criteria.prestriction = cu_alloc<RESTRICTION>();
		if (NULL == ppayload->get_search_criteria.prestriction) {
			return EXT_ERR_ALLOC;
		}
		TRY(ext_buffer_pull_restriction(pext, ppayload->get_search_criteria.prestriction));
	}
	return ext_buffer_pull_longlong_array(pext,
		&ppayload->get_search_criteria.folder_ids);
}

static int exmdb_ext_pull_set_search_criteria_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->set_search_criteria.b_result);
}

static int exmdb_ext_pull_movecopy_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_message.b_result);
}

static int exmdb_ext_pull_movecopy_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_messages.b_partial);
}

static int exmdb_ext_pull_movecopy_folder_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_bool(pext, &ppayload->movecopy_folder.b_exist));
	return ext_buffer_pull_bool(pext,
		&ppayload->movecopy_folder.b_partial);
}

static int exmdb_ext_pull_delete_messages_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->delete_messages.b_partial);
}

static int exmdb_ext_pull_get_message_brief_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	int status;
	uint8_t tmp_byte;
	
	status = ext_buffer_pull_uint8(pext, &tmp_byte);
	if (status != EXT_ERR_SUCCESS || tmp_byte == 0) {
		ppayload->get_message_brief.pbrief = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_message_brief.pbrief = cu_alloc<MESSAGE_CONTENT>();
		if (NULL == ppayload->get_message_brief.pbrief) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_message_content(pext,
				ppayload->get_message_brief.pbrief);
	}
}

static int exmdb_ext_pull_sum_hierarchy_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->sum_hierarchy.count);
}

static int exmdb_ext_pull_load_hierarchy_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->load_hierarchy_table.table_id));
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_hierarchy_table.row_count);
}

static int exmdb_ext_pull_sum_content_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->sum_content.count);
}

static int exmdb_ext_pull_load_content_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->load_content_table.table_id));
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_content_table.row_count);
}

static int exmdb_ext_pull_load_permission_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->load_permission_table.table_id));
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_permission_table.row_count);
}

static int exmdb_ext_pull_load_rule_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->load_rule_table.table_id));
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_rule_table.row_count);
}

static int exmdb_ext_pull_sum_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
			&ppayload->sum_table.rows);
}

static int exmdb_ext_pull_query_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(
		pext, &ppayload->query_table.set);
}

static int exmdb_ext_pull_match_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_int32(pext, &ppayload->match_table.position));
	return ext_buffer_pull_tpropval_array(pext,
			&ppayload->match_table.propvals);	
}

static int exmdb_ext_pull_locate_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_int32(pext, &ppayload->locate_table.position));
	return ext_buffer_pull_uint32(pext,
		&ppayload->locate_table.row_type);
}

static int exmdb_ext_pull_read_table_row_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->read_table_row.propvals);
}

static int exmdb_ext_pull_mark_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint64(pext, &ppayload->mark_table.inst_id));
	TRY(ext_buffer_pull_uint32(pext, &ppayload->mark_table.inst_num));
	return ext_buffer_pull_uint32(pext,
		&ppayload->mark_table.row_type);
}

static int exmdb_ext_pull_get_table_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_table_all_proptags.proptags);
}

static int exmdb_ext_pull_expand_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_bool(pext, &ppayload->expand_table.b_found));
	TRY(ext_buffer_pull_int32(pext, &ppayload->expand_table.position));
	return ext_buffer_pull_uint32(pext,
		&ppayload->expand_table.row_count);
}

static int exmdb_ext_pull_collapse_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_bool(pext, &ppayload->collapse_table.b_found));
	TRY(ext_buffer_pull_int32(pext, &ppayload->collapse_table.position));
	return ext_buffer_pull_uint32(pext,
		&ppayload->collapse_table.row_count);
}

static int exmdb_ext_pull_store_table_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->store_table_state.state_id);
}

static int exmdb_ext_pull_restore_table_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_int32(pext,
		&ppayload->restore_table_state.position);
}

static int exmdb_ext_pull_check_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_message.b_exist);
}

static int exmdb_ext_pull_check_message_deleted_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_message_deleted.b_del);
}

static int exmdb_ext_pull_load_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_message_instance.instance_id);
}

static int exmdb_ext_pull_load_embedded_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_embedded_instance.instance_id);
}

static int exmdb_ext_pull_get_embedded_cn_response(EXT_PULL *pext,
    RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_embedded_cn.pcn = nullptr;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_embedded_cn.pcn = cu_alloc<uint64_t>();
		if (ppayload->get_embedded_cn.pcn == nullptr)
			return EXT_ERR_ALLOC;
		return ext_buffer_pull_uint64(pext, ppayload->get_embedded_cn.pcn);
	}
}

static int exmdb_ext_pull_reload_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->reload_message_instance.b_result);
}

static int exmdb_ext_pull_read_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_message_content(pext,
		&ppayload->read_message_instance.msgctnt);
}

static int exmdb_ext_pull_write_message_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_proptag_array(pext, &ppayload->write_message_instance.proptags));
	return ext_buffer_pull_problem_array(pext,
		&ppayload->write_message_instance.problems);
}

static int exmdb_ext_pull_load_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->load_attachment_instance.instance_id);
}

static int exmdb_ext_pull_create_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->create_attachment_instance.instance_id));
	return ext_buffer_pull_uint32(pext,
		&ppayload->create_attachment_instance.attachment_num);
}

static int exmdb_ext_pull_read_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_tpropval_array(pext, &ppayload->read_attachment_instance.attctnt.proplist));
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 != tmp_byte) {
		ppayload->read_attachment_instance.attctnt.pembedded = cu_alloc<MESSAGE_CONTENT>();
		if (NULL == ppayload->read_attachment_instance.attctnt.pembedded) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_message_content(pext,
			ppayload->read_attachment_instance.attctnt.pembedded);
	} else {
		ppayload->read_attachment_instance.attctnt.pembedded = NULL;
		return EXT_ERR_SUCCESS;
	}
}

static int exmdb_ext_pull_write_attachment_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->write_attachment_instance.problems);
}

static int exmdb_ext_pull_flush_instance_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext, reinterpret_cast<uint32_t *>(&ppayload->flush_instance.e_result));
}

static int exmdb_ext_pull_get_instance_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_instance_all_proptags.proptags);
}

static int exmdb_ext_pull_get_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_instance_properties.propvals);
}

static int exmdb_ext_pull_set_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_instance_properties.problems);
}

static int exmdb_ext_pull_remove_instance_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->remove_instance_properties.problems);
}

static int exmdb_ext_pull_check_instance_cycle_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_instance_cycle.b_cycle);
}

static int exmdb_ext_pull_get_message_instance_rcpts_num_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_message_instance_rcpts_num.num);
}

static int exmdb_ext_pull_get_message_instance_rcpts_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_message_instance_rcpts_all_proptags.proptags);
}

static int exmdb_ext_pull_get_message_instance_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->get_message_instance_rcpts.set);
}

static int exmdb_ext_pull_copy_instance_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->copy_instance_rcpts.b_result);
}

static int exmdb_ext_pull_get_message_instance_attachments_num_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint16(pext,
		&ppayload->get_message_instance_attachments_num.num);
}

static int exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_message_instance_attachment_table_all_proptags.proptags);
}

static int exmdb_ext_pull_query_message_instance_attachment_table_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->query_message_instance_attachment_table.set);
}

static int exmdb_ext_pull_copy_instance_attachments_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->copy_instance_attachments.b_result);
}

static int exmdb_ext_pull_get_message_rcpts_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tarray_set(pext,
		&ppayload->get_message_rcpts.set);
}

static int exmdb_ext_pull_get_message_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_tpropval_array(pext,
		&ppayload->get_message_properties.propvals);
}

static int exmdb_ext_pull_set_message_properties_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_problem_array(pext,
		&ppayload->set_message_properties.problems);
}

static int exmdb_ext_pull_set_message_read_state_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->set_message_read_state.read_cn);
}

static int exmdb_ext_pull_allocate_message_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->allocate_message_id.message_id);
}

static int exmdb_ext_pull_allocate_cn_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
			&ppayload->allocate_cn.cn);
}

static int exmdb_ext_pull_get_message_group_id_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_message_group_id.pgroup_id = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_message_group_id.pgroup_id = cu_alloc<uint32_t>();
		if (NULL == ppayload->get_message_group_id.pgroup_id) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext,
			ppayload->get_message_group_id.pgroup_id);
	}
}

static int exmdb_ext_pull_get_change_indices_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_proptag_array(pext, &ppayload->get_change_indices.indices));
	return ext_buffer_pull_proptag_array(pext,
		&ppayload->get_change_indices.ungroup_proptags);
}

static int exmdb_ext_pull_try_mark_submit_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->try_mark_submit.b_marked);
}

static int exmdb_ext_pull_link_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->link_message.b_result);
}

static int exmdb_ext_pull_get_message_timer_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->get_message_timer.ptimer_id = NULL;
		return EXT_ERR_SUCCESS;
	} else {
		ppayload->get_message_timer.ptimer_id = cu_alloc<uint32_t>();
		if (NULL == ppayload->get_message_timer.ptimer_id) {
			return EXT_ERR_ALLOC;
		}
		return ext_buffer_pull_uint32(pext,
			ppayload->get_message_timer.ptimer_id);
	}
}

static int exmdb_ext_pull_update_folder_rule_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->update_folder_rule.b_exceed);
}

static int exmdb_ext_pull_delivery_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->delivery_message.result);
}

static int exmdb_ext_pull_write_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext, reinterpret_cast<uint32_t *>(&ppayload->write_message.e_result));
}

static int exmdb_ext_pull_read_message_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	uint8_t tmp_byte;
	
	TRY(ext_buffer_pull_uint8(pext, &tmp_byte));
	if (0 == tmp_byte) {
		ppayload->read_message.pmsgctnt = NULL;
		return EXT_ERR_SUCCESS;
	}
	ppayload->read_message.pmsgctnt = cu_alloc<MESSAGE_CONTENT>();
	if (NULL == ppayload->read_message.pmsgctnt) {
		return EXT_ERR_ALLOC;
	}
	return ext_buffer_pull_message_content(
		pext, ppayload->read_message.pmsgctnt);
}

static int exmdb_ext_pull_get_content_sync_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->get_content_sync.fai_count));
	TRY(ext_buffer_pull_uint64(pext, &ppayload->get_content_sync.fai_total));
	TRY(ext_buffer_pull_uint32(pext, &ppayload->get_content_sync.normal_count));
	TRY(ext_buffer_pull_uint64(pext, &ppayload->get_content_sync.normal_total));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.updated_mids));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.chg_mids));
	TRY(ext_buffer_pull_uint64(pext, &ppayload->get_content_sync.last_cn));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.given_mids));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.deleted_mids));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.nolonger_mids));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.read_mids));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_content_sync.unread_mids));
	return ext_buffer_pull_uint64(pext,
		&ppayload->get_content_sync.last_readcn);
}

static int exmdb_ext_pull_get_hierarchy_sync_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	TRY(ext_buffer_pull_uint32(pext, &ppayload->get_hierarchy_sync.fldchgs.count));
	if (0 == ppayload->get_hierarchy_sync.fldchgs.count) {
		ppayload->get_hierarchy_sync.fldchgs.pfldchgs = NULL;
	} else {
		ppayload->get_hierarchy_sync.fldchgs.pfldchgs = cu_alloc<TPROPVAL_ARRAY>(ppayload->get_hierarchy_sync.fldchgs.count);
		if (NULL == ppayload->get_hierarchy_sync.fldchgs.pfldchgs) {
			return EXT_ERR_ALLOC;
		}
		for (size_t i = 0; i < ppayload->get_hierarchy_sync.fldchgs.count; ++i)
			TRY(ext_buffer_pull_tpropval_array(pext, ppayload->get_hierarchy_sync.fldchgs.pfldchgs + i));
	}
	TRY(ext_buffer_pull_uint64(pext, &ppayload->get_hierarchy_sync.last_cn));
	TRY(ext_buffer_pull_eid_array(pext, &ppayload->get_hierarchy_sync.given_fids));
	return ext_buffer_pull_eid_array(pext,
		&ppayload->get_hierarchy_sync.deleted_fids);
}

static int exmdb_ext_pull_allocate_ids_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint64(pext,
		&ppayload->allocate_ids.begin_eid);
}

static int exmdb_ext_pull_subscribe_notification_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_uint32(pext,
		&ppayload->subscribe_notification.sub_id);
}

static int exmdb_ext_pull_check_contact_address_response(
	EXT_PULL *pext, RESPONSE_PAYLOAD *ppayload)
{
	return ext_buffer_pull_bool(pext,
		&ppayload->check_contact_address.b_found);
}

/* exmdb_callid::CONNECT, exmdb_callid::LISTEN_NOTIFICATION not included */
int exmdb_ext_pull_response(const BINARY *pbin_in,
	EXMDB_RESPONSE *presponse)
{
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
	switch (presponse->call_id) {
	case exmdb_callid::PING_STORE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_ALL_NAMED_PROPIDS:
		return exmdb_ext_pull_get_all_named_propids_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::GET_NAMED_PROPIDS:
		return exmdb_ext_pull_get_named_propids_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::GET_NAMED_PROPNAMES:
		return exmdb_ext_pull_get_named_propnames_response(
							&ext_pull,  &presponse->payload);
	case exmdb_callid::GET_MAPPING_GUID:
		return exmdb_ext_pull_get_mapping_guid_response(
						&ext_pull,  &presponse->payload);
	case exmdb_callid::GET_MAPPING_REPLID:
		return exmdb_ext_pull_get_mapping_replid_response(
						&ext_pull,  &presponse->payload);
	case exmdb_callid::GET_STORE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_store_all_proptags_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::GET_STORE_PROPERTIES:
		return exmdb_ext_pull_get_store_properties_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::SET_STORE_PROPERTIES:
		return exmdb_ext_pull_set_store_properties_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::REMOVE_STORE_PROPERTIES:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::CHECK_MAILBOX_PERMISSION:
		return exmdb_ext_pull_check_mailbox_permission_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::GET_FOLDER_BY_CLASS:
		return exmdb_ext_pull_get_folder_by_class_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::SET_FOLDER_BY_CLASS:
		return exmdb_ext_pull_set_folder_by_class_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::GET_FOLDER_CLASS_TABLE:
		return exmdb_ext_pull_get_folder_class_table_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_FOLDER_ID:
		return exmdb_ext_pull_check_folder_id_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::QUERY_FOLDER_MESSAGES:
		return exmdb_ext_pull_query_folder_messages_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_FOLDER_DELETED:
		return exmdb_ext_pull_check_folder_deleted_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::GET_FOLDER_BY_NAME:
		return exmdb_ext_pull_get_folder_by_name_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_FOLDER_PERMISSION:
		return exmdb_ext_pull_check_folder_permission_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::CREATE_FOLDER_BY_PROPERTIES:
		return exmdb_ext_pull_create_folder_by_properties_response(
									&ext_pull, &presponse->payload);
	case exmdb_callid::GET_FOLDER_ALL_PROPTAGS:
		return exmdb_ext_pull_get_folder_all_proptags_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::GET_FOLDER_PROPERTIES:
		return exmdb_ext_pull_get_folder_properties_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::SET_FOLDER_PROPERTIES:
		return exmdb_ext_pull_set_folder_properties_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::REMOVE_FOLDER_PROPERTIES:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::DELETE_FOLDER:
		return exmdb_ext_pull_delete_folder_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::EMPTY_FOLDER:
		return exmdb_ext_pull_empty_folder_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_FOLDER_CYCLE:
		return exmdb_ext_pull_check_folder_cycle_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::COPY_FOLDER_INTERNAL:
		return exmdb_ext_pull_copy_folder_internal_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::GET_SEARCH_CRITERIA:
		return exmdb_ext_pull_get_search_criteria_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::SET_SEARCH_CRITERIA:
		return exmdb_ext_pull_set_search_criteria_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::MOVECOPY_MESSAGE:
		return exmdb_ext_pull_movecopy_message_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::MOVECOPY_MESSAGES:
		return exmdb_ext_pull_movecopy_messages_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::MOVECOPY_FOLDER:
		return exmdb_ext_pull_movecopy_folder_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::DELETE_MESSAGES:
		return exmdb_ext_pull_delete_messages_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::GET_MESSAGE_BRIEF:
		return exmdb_ext_pull_get_message_brief_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::SUM_HIERARCHY:
		return exmdb_ext_pull_sum_hierarchy_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::LOAD_HIERARCHY_TABLE:
		return exmdb_ext_pull_load_hierarchy_table_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::SUM_CONTENT:
		return exmdb_ext_pull_sum_content_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::LOAD_CONTENT_TABLE:
		return exmdb_ext_pull_load_content_table_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::RELOAD_CONTENT_TABLE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::LOAD_PERMISSION_TABLE:
		return exmdb_ext_pull_load_permission_table_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::LOAD_RULE_TABLE:
		return exmdb_ext_pull_load_rule_table_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::UNLOAD_TABLE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::SUM_TABLE:
		return exmdb_ext_pull_sum_table_response(
				&ext_pull, &presponse->payload);
	case exmdb_callid::QUERY_TABLE:
		return exmdb_ext_pull_query_table_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::MATCH_TABLE:
		return exmdb_ext_pull_match_table_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::LOCATE_TABLE:
		return exmdb_ext_pull_locate_table_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::READ_TABLE_ROW:
		return exmdb_ext_pull_read_table_row_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::MARK_TABLE:
		return exmdb_ext_pull_mark_table_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::GET_TABLE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_table_all_proptags_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::EXPAND_TABLE:
		return exmdb_ext_pull_expand_table_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::COLLAPSE_TABLE:
		return exmdb_ext_pull_collapse_table_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::STORE_TABLE_STATE:
		return exmdb_ext_pull_store_table_state_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::RESTORE_TABLE_STATE:
		return exmdb_ext_pull_restore_table_state_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_MESSAGE:
		return exmdb_ext_pull_check_message_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_MESSAGE_DELETED:
		return exmdb_ext_pull_check_message_deleted_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::LOAD_MESSAGE_INSTANCE:
		return exmdb_ext_pull_load_message_instance_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::LOAD_EMBEDDED_INSTANCE:
		return exmdb_ext_pull_load_embedded_instance_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::GET_EMBEDDED_CN:
		return exmdb_ext_pull_get_embedded_cn_response(&ext_pull, &presponse->payload);
	case exmdb_callid::RELOAD_MESSAGE_INSTANCE:
		return exmdb_ext_pull_reload_message_instance_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::CLEAR_MESSAGE_INSTANCE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::READ_MESSAGE_INSTANCE:
		return exmdb_ext_pull_read_message_instance_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::WRITE_MESSAGE_INSTANCE:
		return exmdb_ext_pull_write_message_instance_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::LOAD_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_load_attachment_instance_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::CREATE_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_create_attachment_instance_response(
									&ext_pull, &presponse->payload);
	case exmdb_callid::READ_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_read_attachment_instance_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::WRITE_ATTACHMENT_INSTANCE:
		return exmdb_ext_pull_write_attachment_instance_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::DELETE_MESSAGE_INSTANCE_ATTACHMENT:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::FLUSH_INSTANCE:
		return exmdb_ext_pull_flush_instance_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::UNLOAD_INSTANCE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_INSTANCE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_instance_all_proptags_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::GET_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_get_instance_properties_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::SET_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_set_instance_properties_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::REMOVE_INSTANCE_PROPERTIES:
		return exmdb_ext_pull_remove_instance_properties_response(
									&ext_pull, &presponse->payload);
	case exmdb_callid::CHECK_INSTANCE_CYCLE:
		return exmdb_ext_pull_check_instance_cycle_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::EMPTY_MESSAGE_INSTANCE_RCPTS:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS_NUM:
		return exmdb_ext_pull_get_message_instance_rcpts_num_response(
										&ext_pull, &presponse->payload);
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS:
		return exmdb_ext_pull_get_message_instance_rcpts_all_proptags_response(
												&ext_pull, &presponse->payload);
	case exmdb_callid::GET_MESSAGE_INSTANCE_RCPTS:
		return exmdb_ext_pull_get_message_instance_rcpts_response(
									&ext_pull, &presponse->payload);
	case exmdb_callid::UPDATE_MESSAGE_INSTANCE_RCPTS:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::COPY_INSTANCE_RCPTS:
		return exmdb_ext_pull_copy_instance_rcpts_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::EMPTY_MESSAGE_INSTANCE_ATTACHMENTS:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM:
		return exmdb_ext_pull_get_message_instance_attachments_num_response(
											&ext_pull, &presponse->payload);
	case exmdb_callid::GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS:
		return exmdb_ext_pull_get_message_instance_attachment_table_all_proptags_response(
															&ext_pull, &presponse->payload);
	case exmdb_callid::QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE:
		return exmdb_ext_pull_query_message_instance_attachment_table_response(
												&ext_pull, &presponse->payload);
	case exmdb_callid::COPY_INSTANCE_ATTACHMENTS:
		return exmdb_ext_pull_copy_instance_attachments_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::SET_MESSAGE_INSTANCE_CONFLICT:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_MESSAGE_RCPTS:
		return exmdb_ext_pull_get_message_rcpts_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::GET_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_get_message_properties_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::SET_MESSAGE_PROPERTIES:
		return exmdb_ext_pull_set_message_properties_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::SET_MESSAGE_READ_STATE:
		return exmdb_ext_pull_set_message_read_state_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::REMOVE_MESSAGE_PROPERTIES:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::ALLOCATE_MESSAGE_ID:
		return exmdb_ext_pull_allocate_message_id_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::ALLOCATE_CN:
		return exmdb_ext_pull_allocate_cn_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::GET_MESSAGE_GROUP_ID:
		return exmdb_ext_pull_get_message_group_id_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::SET_MESSAGE_GROUP_ID:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::SAVE_CHANGE_INDICES:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_CHANGE_INDICES:
		return exmdb_ext_pull_get_change_indices_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::MARK_MODIFIED:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::TRY_MARK_SUBMIT:
		return exmdb_ext_pull_try_mark_submit_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::CLEAR_SUBMIT:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::LINK_MESSAGE:
		return exmdb_ext_pull_link_message_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::UNLINK_MESSAGE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::RULE_NEW_MESSAGE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::SET_MESSAGE_TIMER:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::GET_MESSAGE_TIMER:
		return exmdb_ext_pull_get_message_timer_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::EMPTY_FOLDER_PERMISSION:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::UPDATE_FOLDER_PERMISSION:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::EMPTY_FOLDER_RULE:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::UPDATE_FOLDER_RULE:
		return exmdb_ext_pull_update_folder_rule_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::DELIVERY_MESSAGE:
		return exmdb_ext_pull_delivery_message_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::WRITE_MESSAGE:
		return exmdb_ext_pull_write_message_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::READ_MESSAGE:
		return exmdb_ext_pull_read_message_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::GET_CONTENT_SYNC:
		return exmdb_ext_pull_get_content_sync_response(
						&ext_pull, &presponse->payload);
	case exmdb_callid::GET_HIERARCHY_SYNC:
		return exmdb_ext_pull_get_hierarchy_sync_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::ALLOCATE_IDS:
		return exmdb_ext_pull_allocate_ids_response(
					&ext_pull, &presponse->payload);
	case exmdb_callid::SUBSCRIBE_NOTIFICATION:
		return exmdb_ext_pull_subscribe_notification_response(
								&ext_pull, &presponse->payload);
	case exmdb_callid::UNSUBSCRIBE_NOTIFICATION:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::TRANSPORT_NEW_MAIL:
		return EXT_ERR_SUCCESS;
	case exmdb_callid::CHECK_CONTACT_ADDRESS:
		return exmdb_ext_pull_check_contact_address_response(
							&ext_pull, &presponse->payload);
	case exmdb_callid::UNLOAD_STORE:
		return EXT_ERR_SUCCESS;
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}

int exmdb_ext_pull_db_notify(const BINARY *pbin_in,
	DB_NOTIFY_DATAGRAM *pnotify)
{
	uint8_t tmp_byte;
	EXT_PULL ext_pull;
	
	ext_buffer_pull_init(&ext_pull, pbin_in->pb,
		pbin_in->cb, common_util_alloc, EXT_FLAG_WCOUNT);
	TRY(ext_buffer_pull_string(&ext_pull, &pnotify->dir));
	TRY(ext_buffer_pull_bool(&ext_pull, &pnotify->b_table));
	TRY(ext_buffer_pull_long_array(&ext_pull, &pnotify->id_array));
	TRY(ext_buffer_pull_uint8(&ext_pull, &pnotify->db_notify.type));
	switch (pnotify->db_notify.type) {
	case DB_NOTIFY_TYPE_NEW_MAIL: {
		auto n = cu_alloc<DB_NOTIFY_NEW_MAIL>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->message_id));
		TRY(ext_buffer_pull_uint32(&ext_pull, &n->message_flags));
		return ext_buffer_pull_string(&ext_pull, const_cast<char **>(&n->pmessage_class));
	}
	case DB_NOTIFY_TYPE_FOLDER_CREATED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->parent_id));
		return ext_buffer_pull_proptag_array(&ext_pull, &n->proptags);
	}
	case DB_NOTIFY_TYPE_MESSAGE_CREATED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->message_id));
		return ext_buffer_pull_proptag_array(&ext_pull, &n->proptags);
	}
	case DB_NOTIFY_TYPE_LINK_CREATED: {
		auto n = cu_alloc<DB_NOTIFY_LINK_CREATED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->message_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->parent_id));
		return ext_buffer_pull_proptag_array(&ext_pull, &n->proptags);
	}
	case DB_NOTIFY_TYPE_FOLDER_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->parent_id);
	}
	case DB_NOTIFY_TYPE_MESSAGE_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->message_id);
	}
	case DB_NOTIFY_TYPE_LINK_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_LINK_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->message_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->parent_id);
	}
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint8(&ext_pull, &tmp_byte));
		if (0 == tmp_byte) {
			n->ptotal = nullptr;
		} else {
			n->ptotal = cu_alloc<uint32_t>();
			if (n->ptotal == nullptr)
				return EXT_ERR_ALLOC;	
			TRY(ext_buffer_pull_uint32(&ext_pull, n->ptotal));
		}
		TRY(ext_buffer_pull_uint8(&ext_pull, &tmp_byte));
		if (0 == tmp_byte) {
			n->punread = nullptr;
		} else {
			n->punread = cu_alloc<uint32_t>();
			if (n->punread == nullptr)
				return EXT_ERR_ALLOC;	
			TRY(ext_buffer_pull_uint32(&ext_pull, n->punread));
		}
		return ext_buffer_pull_proptag_array(&ext_pull, &n->proptags);
	}
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->message_id));
		return ext_buffer_pull_proptag_array(&ext_pull, &n->proptags);
	}
	case DB_NOTIFY_TYPE_FOLDER_MOVED:
	case DB_NOTIFY_TYPE_FOLDER_COPIED: {
		auto n = cu_alloc<DB_NOTIFY_FOLDER_MVCP>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->parent_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->old_folder_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->old_parent_id);
	}
	case DB_NOTIFY_TYPE_MESSAGE_MOVED:
	case DB_NOTIFY_TYPE_MESSAGE_COPIED: {
		auto n = cu_alloc<DB_NOTIFY_MESSAGE_MVCP>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->message_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->old_folder_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->old_message_id);
	}
	case DB_NOTIFY_TYPE_SEARCH_COMPLETED: {
		auto n = cu_alloc<DB_NOTIFY_SEARCH_COMPLETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		return ext_buffer_pull_uint64(&ext_pull, &n->folder_id);
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_CHANGED:
	case DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED:
		return EXT_ERR_SUCCESS;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_folder_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->after_folder_id);
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_ADDED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_message_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_instance));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->after_folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->after_row_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->after_instance);
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		return ext_buffer_pull_uint64(&ext_pull, &n->row_folder_id);
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_DELETED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_message_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->row_instance);
	}
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED: {
		auto n = cu_alloc<DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_folder_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->after_folder_id);
	}
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED: {
		auto n = cu_alloc<DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED>();
		if (n == nullptr)
			return EXT_ERR_ALLOC;
		pnotify->db_notify.pdata = n;
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_message_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->row_instance));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->after_folder_id));
		TRY(ext_buffer_pull_uint64(&ext_pull, &n->after_row_id));
		return ext_buffer_pull_uint64(&ext_pull, &n->after_instance);
	}
	default:
		return EXT_ERR_BAD_SWITCH;
	}
}
