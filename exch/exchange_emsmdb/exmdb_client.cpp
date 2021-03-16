// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include <gromox/ext_buffer.hpp>
#include <cstdio>

#define SERVICE_ID_LANG_TO_CHARSET							1
#define SERVICE_ID_CPID_TO_CHARSET							2
#define SERVICE_ID_GET_USER_DISPLAYNAME						3
#define SERVICE_ID_CHECK_MLIST_INCLUDE						4
#define SERVICE_ID_GET_USER_LANG							5
#define SERVICE_ID_GET_TIMEZONE								6
#define SERVICE_ID_GET_MAILDIR								7
#define SERVICE_ID_GET_ID_FFROM_USERNAME					8
#define SERVICE_ID_GET_USERNAME_FROM_ID						9
#define SERVICE_ID_GET_USER_IDS								10
#define SERVICE_ID_GET_DOMAIN_IDS							11
#define SERVICE_ID_GET_ID_FROM_MAILDIR						12
#define SERVICE_ID_GET_ID_FROM_HOMEDIR						13
#define SERVICE_ID_SEND_MAIL								14
#define SERVICE_ID_GET_MIME_POOL							15
#define SERVICE_ID_LOG_INFO									16
#define SERVICE_ID_GET_HANDLE								17

#define E(s) decltype(exmdb_client_ ## s) exmdb_client_ ## s;
E(ping_store)
E(get_all_named_propids)
E(get_named_propids)
E(get_named_propnames)
E(get_mapping_guid)
E(get_mapping_replid)
E(get_store_all_proptags)
E(get_store_properties)
E(set_store_properties)
E(remove_store_properties)
E(check_mailbox_permission)
E(get_folder_by_class)
E(set_folder_by_class)
E(get_folder_class_table)
E(check_folder_id)
E(check_folder_deleted)
E(get_folder_by_name)
E(check_folder_permission)
E(create_folder_by_properties)
E(get_folder_all_proptags)
E(get_folder_properties)
E(set_folder_properties)
E(remove_folder_properties)
E(delete_folder)
E(empty_folder)
E(check_folder_cycle)
E(copy_folder_internal)
E(get_search_criteria)
E(set_search_criteria)
E(movecopy_message)
E(movecopy_messages)
E(movecopy_folder)
E(delete_messages)
E(get_message_brief)
E(sum_hierarchy)
E(load_hierarchy_table)
E(sum_content)
E(load_content_table)
E(reload_content_table)
E(load_permission_table)
E(load_rule_table)
E(unload_table)
E(sum_table)
E(query_table)
E(match_table)
E(locate_table)
E(read_table_row)
E(mark_table)
E(get_table_all_proptags)
E(expand_table)
E(collapse_table)
E(store_table_state)
E(restore_table_state)
E(check_message)
E(check_message_deleted)
E(load_message_instance)
E(load_embedded_instance)
E(get_embedded_cn)
E(reload_message_instance)
E(clear_message_instance)
E(read_message_instance)
E(write_message_instance)
E(load_attachment_instance)
E(create_attachment_instance)
E(read_attachment_instance)
E(write_attachment_instance)
E(delete_message_instance_attachment)
E(flush_instance)
E(unload_instance)
E(get_instance_all_proptags)
E(get_instance_properties)
E(set_instance_properties)
E(remove_instance_properties)
E(check_instance_cycle)
E(empty_message_instance_rcpts)
E(get_message_instance_rcpts_num)
E(get_message_instance_rcpts_all_proptags)
E(get_message_instance_rcpts)
E(update_message_instance_rcpts)
E(copy_instance_rcpts)
E(empty_message_instance_attachments)
E(get_message_instance_attachments_num)
E(get_message_instance_attachment_table_all_proptags)
E(query_message_instance_attachment_table)
E(copy_instance_attachments)
E(set_message_instance_conflict)
E(get_message_rcpts)
E(get_message_properties)
E(set_message_properties)
E(set_message_read_state)
E(remove_message_properties)
E(allocate_message_id)
E(allocate_cn)
E(get_message_group_id)
E(set_message_group_id)
E(save_change_indices)
E(get_change_indices)
E(mark_modified)
E(try_mark_submit)
E(clear_submit)
E(link_message)
E(unlink_message)
E(rule_new_message)
E(set_message_timer)
E(get_message_timer)
E(empty_folder_permission)
E(update_folder_permission)
E(empty_folder_rule)
E(update_folder_rule)
E(delivery_message)
E(write_message)
E(read_message)
E(get_content_sync)
E(get_hierarchy_sync)
E(allocate_ids)
E(subscribe_notification)
E(unsubscribe_notification)
E(transport_new_mail)
E(check_contact_address)
E(get_public_folder_unread_count)
#undef E

int exmdb_client_run()
{
	void (*register_proc)(void*);
	void (*pass_service)(int, void*);
	
#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "exchange_emsmdb", (s)); \
		return -1; \
	} \
} while (false)

	E(exmdb_client_ping_store, "exmdb_client_ping_store");
	E(exmdb_client_get_all_named_propids, "exmdb_client_get_all_named_propids");
	E(exmdb_client_get_named_propids, "exmdb_client_get_named_propids");
	E(exmdb_client_get_named_propnames, "exmdb_client_get_named_propnames");
	E(exmdb_client_get_mapping_guid, "exmdb_client_get_mapping_guid");
	E(exmdb_client_get_mapping_replid, "exmdb_client_get_mapping_replid");
	E(exmdb_client_get_store_all_proptags, "exmdb_client_get_store_all_proptags");
	E(exmdb_client_get_store_properties, "exmdb_client_get_store_properties");
	E(exmdb_client_set_store_properties, "exmdb_client_set_store_properties");
	E(exmdb_client_remove_store_properties, "exmdb_client_remove_store_properties");
	E(exmdb_client_check_mailbox_permission, "exmdb_client_check_mailbox_permission");
	E(exmdb_client_get_folder_by_class, "exmdb_client_get_folder_by_class");
	E(exmdb_client_set_folder_by_class, "exmdb_client_set_folder_by_class");
	E(exmdb_client_get_folder_class_table, "exmdb_client_get_folder_class_table");
	E(exmdb_client_check_folder_id, "exmdb_client_check_folder_id");
	E(exmdb_client_check_folder_deleted, "exmdb_client_check_folder_deleted");
	E(exmdb_client_get_folder_by_name, "exmdb_client_get_folder_by_name");
	E(exmdb_client_check_folder_permission, "exmdb_client_check_folder_permission");
	E(exmdb_client_create_folder_by_properties, "exmdb_client_create_folder_by_properties");
	E(exmdb_client_get_folder_all_proptags, "exmdb_client_get_folder_all_proptags");
	E(exmdb_client_get_folder_properties, "exmdb_client_get_folder_properties");
	E(exmdb_client_set_folder_properties, "exmdb_client_set_folder_properties");
	E(exmdb_client_remove_folder_properties, "exmdb_client_remove_folder_properties");
	E(exmdb_client_delete_folder, "exmdb_client_delete_folder");
	E(exmdb_client_empty_folder, "exmdb_client_empty_folder");
	E(exmdb_client_check_folder_cycle, "exmdb_client_check_folder_cycle");
	E(exmdb_client_copy_folder_internal, "exmdb_client_copy_folder_internal");
	E(exmdb_client_get_search_criteria, "exmdb_client_get_search_criteria");
	E(exmdb_client_set_search_criteria, "exmdb_client_set_search_criteria");
	E(exmdb_client_movecopy_message, "exmdb_client_movecopy_message");
	E(exmdb_client_movecopy_messages, "exmdb_client_movecopy_messages");
	E(exmdb_client_movecopy_folder, "exmdb_client_movecopy_folder");
	E(exmdb_client_delete_messages, "exmdb_client_delete_messages");
	E(exmdb_client_get_message_brief, "exmdb_client_get_message_brief");
	E(exmdb_client_sum_hierarchy, "exmdb_client_sum_hierarchy");
	E(exmdb_client_load_hierarchy_table, "exmdb_client_load_hierarchy_table");
	E(exmdb_client_sum_content, "exmdb_client_sum_content");
	E(exmdb_client_load_content_table, "exmdb_client_load_content_table");
	E(exmdb_client_reload_content_table, "exmdb_client_reload_content_table");
	E(exmdb_client_load_permission_table, "exmdb_client_load_permission_table");
	E(exmdb_client_load_rule_table, "exmdb_client_load_rule_table");
	E(exmdb_client_unload_table, "exmdb_client_unload_table");
	E(exmdb_client_sum_table, "exmdb_client_sum_table");
	E(exmdb_client_query_table, "exmdb_client_query_table");
	E(exmdb_client_match_table, "exmdb_client_match_table");
	E(exmdb_client_locate_table, "exmdb_client_locate_table");
	E(exmdb_client_read_table_row, "exmdb_client_read_table_row");
	E(exmdb_client_mark_table, "exmdb_client_mark_table");
	E(exmdb_client_get_table_all_proptags, "exmdb_client_get_table_all_proptags");
	E(exmdb_client_expand_table, "exmdb_client_expand_table");
	E(exmdb_client_collapse_table, "exmdb_client_collapse_table");
	E(exmdb_client_store_table_state, "exmdb_client_store_table_state");
	E(exmdb_client_restore_table_state, "exmdb_client_restore_table_state");
	E(exmdb_client_check_message, "exmdb_client_check_message");
	E(exmdb_client_check_message_deleted, "exmdb_client_check_message_deleted");
	E(exmdb_client_load_message_instance, "exmdb_client_load_message_instance");
	E(exmdb_client_load_embedded_instance, "exmdb_client_load_embedded_instance");
	E(exmdb_client_get_embedded_cn, "exmdb_client_get_embedded_cn");
	E(exmdb_client_reload_message_instance, "exmdb_client_reload_message_instance");
	E(exmdb_client_clear_message_instance, "exmdb_client_clear_message_instance");
	E(exmdb_client_read_message_instance, "exmdb_client_read_message_instance");
	E(exmdb_client_write_message_instance, "exmdb_client_write_message_instance");
	E(exmdb_client_load_attachment_instance, "exmdb_client_load_attachment_instance");
	E(exmdb_client_create_attachment_instance, "exmdb_client_create_attachment_instance");
	E(exmdb_client_read_attachment_instance, "exmdb_client_read_attachment_instance");
	E(exmdb_client_write_attachment_instance, "exmdb_client_write_attachment_instance");
	E(exmdb_client_delete_message_instance_attachment, "exmdb_client_delete_message_instance_attachment");
	E(exmdb_client_flush_instance, "exmdb_client_flush_instance");
	E(exmdb_client_unload_instance, "exmdb_client_unload_instance");
	E(exmdb_client_get_instance_all_proptags, "exmdb_client_get_instance_all_proptags");
	E(exmdb_client_get_instance_properties, "exmdb_client_get_instance_properties");
	E(exmdb_client_set_instance_properties, "exmdb_client_set_instance_properties");
	E(exmdb_client_remove_instance_properties, "exmdb_client_remove_instance_properties");
	E(exmdb_client_check_instance_cycle, "exmdb_client_check_instance_cycle");
	E(exmdb_client_empty_message_instance_rcpts, "exmdb_client_empty_message_instance_rcpts");
	E(exmdb_client_get_message_instance_rcpts_num, "exmdb_client_get_message_instance_rcpts_num");
	E(exmdb_client_get_message_instance_rcpts_all_proptags, "exmdb_client_get_message_instance_rcpts_all_proptags");
	E(exmdb_client_get_message_instance_rcpts, "exmdb_client_get_message_instance_rcpts");
	E(exmdb_client_update_message_instance_rcpts, "exmdb_client_update_message_instance_rcpts");
	E(exmdb_client_copy_instance_rcpts, "exmdb_client_copy_instance_rcpts");
	E(exmdb_client_empty_message_instance_attachments, "exmdb_client_empty_message_instance_attachments");
	E(exmdb_client_get_message_instance_attachments_num, "exmdb_client_get_message_instance_attachments_num");
	E(exmdb_client_get_message_instance_attachment_table_all_proptags, "exmdb_client_get_message_instance_attachment_table_all_proptags");
	E(exmdb_client_query_message_instance_attachment_table, "exmdb_client_query_message_instance_attachment_table");
	E(exmdb_client_copy_instance_attachments, "exmdb_client_copy_instance_attachments");
	E(exmdb_client_set_message_instance_conflict, "exmdb_client_set_message_instance_conflict");
	E(exmdb_client_get_message_rcpts, "exmdb_client_get_message_rcpts");
	E(exmdb_client_get_message_properties, "exmdb_client_get_message_properties");
	E(exmdb_client_set_message_properties, "exmdb_client_set_message_properties");
	E(exmdb_client_set_message_read_state, "exmdb_client_set_message_read_state");
	E(exmdb_client_remove_message_properties, "exmdb_client_remove_message_properties");
	E(exmdb_client_allocate_message_id, "exmdb_client_allocate_message_id");
	E(exmdb_client_allocate_cn, "exmdb_client_allocate_cn");
	E(exmdb_client_get_message_group_id, "exmdb_client_get_message_group_id");
	E(exmdb_client_set_message_group_id, "exmdb_client_set_message_group_id");
	E(exmdb_client_save_change_indices, "exmdb_client_save_change_indices");
	E(exmdb_client_get_change_indices, "exmdb_client_get_change_indices");
	E(exmdb_client_mark_modified, "exmdb_client_mark_modified");
	E(exmdb_client_try_mark_submit, "exmdb_client_try_mark_submit");
	E(exmdb_client_clear_submit, "exmdb_client_clear_submit");
	E(exmdb_client_link_message, "exmdb_client_link_message");
	E(exmdb_client_unlink_message, "exmdb_client_unlink_message");
	E(exmdb_client_rule_new_message, "exmdb_client_rule_new_message");
	E(exmdb_client_set_message_timer, "exmdb_client_set_message_timer");
	E(exmdb_client_get_message_timer, "exmdb_client_get_message_timer");
	E(exmdb_client_empty_folder_permission, "exmdb_client_empty_folder_permission");
	E(exmdb_client_update_folder_permission, "exmdb_client_update_folder_permission");
	E(exmdb_client_empty_folder_rule, "exmdb_client_empty_folder_rule");
	E(exmdb_client_update_folder_rule, "exmdb_client_update_folder_rule");
	E(exmdb_client_delivery_message, "exmdb_client_delivery_message");
	E(exmdb_client_write_message, "exmdb_client_write_message");
	E(exmdb_client_read_message, "exmdb_client_read_message");
	E(exmdb_client_get_content_sync, "exmdb_client_get_content_sync");
	E(exmdb_client_get_hierarchy_sync, "exmdb_client_get_hierarchy_sync");
	E(exmdb_client_allocate_ids, "exmdb_client_allocate_ids");
	E(exmdb_client_subscribe_notification, "exmdb_client_subscribe_notification");
	E(exmdb_client_unsubscribe_notification, "exmdb_client_unsubscribe_notification");
	E(exmdb_client_transport_new_mail, "exmdb_client_transport_new_mail");
	E(exmdb_client_check_contact_address, "exmdb_client_check_contact_address");
	E(exmdb_client_get_public_folder_unread_count, "exmdb_client_get_public_folder_unread_count");

	E(register_proc, "exmdb_client_register_proc");
	register_proc(reinterpret_cast<void *>(emsmdb_interface_event_proc));

	E(pass_service, "pass_service");
#undef E
	/* pass the service functions to exmdb_provider */
#define E(s) reinterpret_cast<void *>(s)
	pass_service(SERVICE_ID_LANG_TO_CHARSET, E(common_util_lang_to_charset));
	pass_service(SERVICE_ID_CPID_TO_CHARSET, E(common_util_cpid_to_charset));
	pass_service(SERVICE_ID_GET_USER_DISPLAYNAME, E(common_util_get_user_displayname));
	pass_service(SERVICE_ID_CHECK_MLIST_INCLUDE, E(common_util_check_mlist_include));
	pass_service(SERVICE_ID_GET_USER_LANG, E(common_util_get_user_lang));
	pass_service(SERVICE_ID_GET_TIMEZONE, E(common_util_get_timezone));
	pass_service(SERVICE_ID_GET_MAILDIR, E(common_util_get_maildir));
	pass_service(SERVICE_ID_GET_ID_FFROM_USERNAME, E(common_util_get_id_from_username));
	pass_service(SERVICE_ID_GET_USERNAME_FROM_ID, E(common_util_get_username_from_id));
	pass_service(SERVICE_ID_GET_USER_IDS, E(common_util_get_user_ids));
	pass_service(SERVICE_ID_GET_DOMAIN_IDS, E(common_util_get_domain_ids));
	pass_service(SERVICE_ID_GET_ID_FROM_MAILDIR, E(common_util_get_id_from_maildir));
	pass_service(SERVICE_ID_GET_ID_FROM_HOMEDIR, E(common_util_get_id_from_homedir));
	pass_service(SERVICE_ID_SEND_MAIL, E(common_util_send_mail));
	pass_service(SERVICE_ID_GET_MIME_POOL, E(common_util_get_mime_pool));
	pass_service(SERVICE_ID_LOG_INFO, E(log_info));
	pass_service(SERVICE_ID_GET_HANDLE, E(emsmdb_interface_get_handle));
#undef E
	return 0;
}

BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid)
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	tmp_propnames.count = 1;
	tmp_propnames.ppropname = (PROPERTY_NAME*)ppropname;
	if (FALSE == exmdb_client_get_named_propids(dir,
		b_create, &tmp_propnames, &tmp_propids)) {
		return FALSE;	
	}
	*ppropid = *tmp_propids.ppropid;
	return TRUE;
}

BOOL exmdb_client_get_named_propname(const char *dir,
	uint16_t propid, PROPERTY_NAME *ppropname)
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	tmp_propids.count = 1;
	tmp_propids.ppropid = &propid;
	if (FALSE == exmdb_client_get_named_propnames(dir,
		&tmp_propids, &tmp_propnames)) {
		return FALSE;	
	}
	*ppropname = *tmp_propnames.ppropname;
	return TRUE;
}

BOOL exmdb_client_get_store_property(const char *dir,
	uint32_t cpid, uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (FALSE == exmdb_client_get_store_properties(
		dir, cpid, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_get_folder_property(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (FALSE == exmdb_client_get_folder_properties(
		dir, cpid, folder_id, &tmp_proptags,
		&tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_delete_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t folder_id,
	uint64_t message_id, BOOL b_hard, BOOL *pb_done)
{
	BOOL b_partial;
	EID_ARRAY message_ids;
	
	message_ids.count = 1;
	message_ids.pids = &message_id;
	if (FALSE == exmdb_client_delete_messages(dir, account_id,
		cpid, NULL, folder_id, &message_ids, b_hard, &b_partial)) {
		return FALSE;	
	}
	*pb_done = !b_partial;
	return TRUE;
}

BOOL exmdb_client_get_instance_property(
	const char *dir, uint32_t instance_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (FALSE == exmdb_client_get_instance_properties(dir,
		0, instance_id, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_set_instance_property(
	const char *dir, uint32_t instance_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (FALSE == exmdb_client_set_instance_properties(dir,
		instance_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_instance_property(const char *dir,
	uint32_t instance_id, uint32_t proptag, uint32_t *presult)
{
	PROPTAG_ARRAY tmp_proptags;
	PROBLEM_ARRAY tmp_problems;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (FALSE == exmdb_client_remove_instance_properties(
		dir, instance_id, &tmp_proptags, &tmp_problems)) {
		return FALSE;	
	}
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_get_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (FALSE == exmdb_client_get_message_properties(dir,
		username, cpid, message_id, &tmp_proptags, &tmp_propvals)) {
		return FALSE;	
	}
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_set_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (FALSE == exmdb_client_set_message_properties(dir,
		username, cpid, message_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_message_property(const char *dir,
	uint32_t cpid, uint64_t message_id, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (FALSE == exmdb_client_remove_message_properties(
		dir, cpid, message_id, &tmp_proptags)) {
		return FALSE;	
	}
	return TRUE;
}

BOOL exmdb_client_check_message_owner(const char *dir,
	uint64_t message_id, const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	char tmp_name[256];
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	if (FALSE == exmdb_client_get_message_property(dir, NULL,
		0, message_id, PROP_TAG_CREATORENTRYID, (void**)&pbin)) {
		return FALSE;
	}
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb,
		pbin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_addressbook_entryid(
		&ext_pull, &ab_entryid)) {
		*pb_owner = false;
		return TRUE;
	}
	if (FALSE == common_util_essdn_to_username(
		ab_entryid.px500dn, tmp_name)) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(username, tmp_name) == 0 ? TRUE : false;
	return TRUE;
}
