#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "common_util.h"
#include "proc_common.h"
#include "ext_buffer.h"
#include <stdio.h>

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


BOOL (*exmdb_client_ping_store)(const char *dir);

BOOL (*exmdb_client_get_all_named_propids)(
	const char *dir, PROPID_ARRAY *ppropids);

BOOL (*exmdb_client_get_named_propids)(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);

BOOL (*exmdb_client_get_named_propnames)(const char *dir,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);

BOOL (*exmdb_client_get_mapping_guid)(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid);

BOOL (*exmdb_client_get_mapping_replid)(const char *dir,
	GUID guid, BOOL *pb_found, uint16_t *preplid);

BOOL (*exmdb_client_get_store_all_proptags)(
	const char *dir, PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_get_store_properties)(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

BOOL (*exmdb_client_set_store_properties)(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropval,
	PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_remove_store_properties)(
	const char *dir, const PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_check_mailbox_permission)(const char *dir,
	const char *username, uint32_t *ppermission);

BOOL (*exmdb_client_get_folder_by_class)(const char *dir,
	const char *str_class, uint64_t *pid, char *str_explicit);

BOOL (*exmdb_client_set_folder_by_class)(const char *dir,
	uint64_t folder_id, const char *str_class, BOOL *pb_result);

BOOL (*exmdb_client_get_folder_class_table)(
	const char *dir, TARRAY_SET *ptable);

BOOL (*exmdb_client_check_folder_id)(const char *dir,
	uint64_t folder_id, BOOL *pb_exist);

BOOL (*exmdb_client_check_folder_deleted)(const char *dir,
	uint64_t folder_id, BOOL *pb_del);

BOOL (*exmdb_client_get_folder_by_name)(const char *dir,
	uint64_t parent_id, const char *str_name,
	uint64_t *pfolder_id);

BOOL (*exmdb_client_check_folder_permission)(const char *dir,
	uint64_t folder_id, const char *username,
	uint32_t *ppermission);

BOOL (*exmdb_client_create_folder_by_properties)(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *pproperties,
	uint64_t *pfolder_id);

BOOL (*exmdb_client_get_folder_all_proptags)(const char *dir,
	uint64_t folder_id, PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_get_folder_properties)(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

BOOL (*exmdb_client_set_folder_properties)(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_remove_folder_properties)(const char *dir,
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_delete_folder)(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result);

BOOL (*exmdb_client_empty_folder)(const char *dir, uint32_t cpid,
	const char *username, uint64_t folder_id, BOOL b_hard,
	BOOL b_normal, BOOL b_fai, BOOL b_sub, BOOL *pb_partial);

BOOL (*exmdb_client_check_folder_cycle)(const char *dir,
	uint64_t src_fid, uint64_t dst_fid, BOOL *pb_cycle);

BOOL (*exmdb_client_copy_folder_internal)(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, BOOL b_normal, BOOL b_fai, BOOL b_sub,
	uint64_t dst_fid, BOOL *pb_collid, BOOL *pb_partial);

BOOL (*exmdb_client_get_search_criteria)(const char *dir,
	uint64_t folder_id, uint32_t *psearch_status,
	RESTRICTION **pprestriction, LONGLONG_ARRAY *pfolder_ids);

BOOL (*exmdb_client_set_search_criteria)(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint32_t search_flags,
	const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids,
	BOOL *pb_result);

BOOL (*exmdb_client_movecopy_message)(const char *dir,
	int account_id, uint32_t cpid, uint64_t message_id,
	uint64_t dst_fid, uint64_t dst_id, BOOL b_move,
	BOOL *pb_result);

BOOL (*exmdb_client_movecopy_messages)(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, uint64_t dst_fid,
	BOOL b_copy, const EID_ARRAY *pmessage_ids, BOOL *pb_partial);

BOOL (*exmdb_client_movecopy_folder)(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_pid, uint64_t src_fid, uint64_t dst_fid,
	const char *str_new, BOOL b_copy, BOOL *pb_exist,
	BOOL *pb_partial);

BOOL (*exmdb_client_delete_messages)(const char *dir,
	int account_id, uint32_t cpid, const char *username,
	uint64_t folder_id, const EID_ARRAY *pmessage_ids,
	BOOL b_hard, BOOL *pb_partial);

BOOL (*exmdb_client_get_message_brief)(const char *dir,
	uint32_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppbrief);

BOOL (*exmdb_client_sum_hierarchy)(const char *dir,
	uint64_t folder_id, const char *username,
	BOOL b_depth, uint32_t *pcount);
	
BOOL (*exmdb_client_load_hierarchy_table)(const char *dir,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, uint32_t *ptable_id,
	uint32_t *prow_count);

BOOL (*exmdb_client_sum_content)(const char *dir, uint64_t folder_id,
	BOOL b_fai, BOOL b_deleted, uint32_t *pcount);

BOOL (*exmdb_client_load_content_table)(const char *dir, uint32_t cpid,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL (*exmdb_client_reload_content_table)(
	const char *dir, uint32_t table_id);

BOOL (*exmdb_client_load_permission_table)(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL (*exmdb_client_load_rule_table)(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	const RESTRICTION *prestriction,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL (*exmdb_client_unload_table)(const char *dir, uint32_t table_id);

BOOL (*exmdb_client_sum_table)(const char *dir,
	uint32_t table_id, uint32_t *prows);

BOOL (*exmdb_client_query_table)(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset);

BOOL (*exmdb_client_match_table)(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, BOOL b_forward, uint32_t start_pos,
	const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals);

BOOL (*exmdb_client_locate_table)(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	int32_t *pposition, uint32_t *prow_type);

BOOL (*exmdb_client_read_table_row)(const char *dir,
	const char *username, uint32_t cpid, uint32_t table_id,
	const PROPTAG_ARRAY *pproptags, uint64_t inst_id,
	uint32_t inst_num, TPROPVAL_ARRAY *ppropvals);
	
BOOL (*exmdb_client_mark_table)(const char *dir,
	uint32_t table_id, uint32_t position, uint64_t *pinst_id,
	uint32_t *pinst_num, uint32_t *prow_type);

BOOL (*exmdb_client_get_table_all_proptags)(const char *dir,
	uint32_t table_id, PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_expand_table)(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count);

BOOL (*exmdb_client_collapse_table)(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count);

BOOL (*exmdb_client_store_table_state)(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	uint32_t *pstate_id);

BOOL (*exmdb_client_restore_table_state)(const char *dir,
	uint32_t table_id, uint32_t state_id, int32_t *pposition);

BOOL (*exmdb_client_check_message)(const char *dir,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist);

BOOL (*exmdb_client_check_message_deleted)(const char *dir,
	uint64_t message_id, BOOL *pb_del);

BOOL (*exmdb_client_load_message_instance)(const char *dir,
	const char *username, uint32_t cpid, BOOL b_new,
	uint64_t folder_id, uint64_t message_id,
	uint32_t *pinstance_id);

BOOL (*exmdb_client_load_embedded_instance)(const char *dir,
	BOOL b_new, uint32_t attachment_instance_id,
	uint32_t *pinstance_id);

BOOL (*exmdb_client_get_embeded_cn)(const char *dir,
	uint32_t instance_id, uint64_t **ppcn);

BOOL (*exmdb_client_reload_message_instance)(const char *dir,
	uint32_t instance_id, BOOL *pb_result);

BOOL (*exmdb_client_clear_message_instance)(
	const char *dir, uint32_t instance_id);

BOOL (*exmdb_client_read_message_instance)(const char *dir,
	uint32_t instance_id, MESSAGE_CONTENT *pmsgctnt);

BOOL (*exmdb_client_write_message_instance)(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt,
	BOOL b_force, PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_load_attachment_instance)(const char *dir,
	uint32_t message_instance_id, uint32_t attachment_num,
	uint32_t *pinstance_id);

BOOL (*exmdb_client_create_attachment_instance)(const char *dir,
	uint32_t message_instance_id, uint32_t *pinstance_id,
	uint32_t *pattachment_num);

BOOL (*exmdb_client_read_attachment_instance)(const char *dir,
	uint32_t instance_id, ATTACHMENT_CONTENT *pattctnt);

BOOL (*exmdb_client_write_attachment_instance)(const char *dir,
	uint32_t instance_id, const ATTACHMENT_CONTENT *pattctnt,
	BOOL b_force, PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_delete_message_instance_attachment)(
	const char *dir, uint32_t message_instance_id,
	uint32_t attachment_num);

BOOL (*exmdb_client_flush_instance)(const char *dir,
	uint32_t instance_id, const char *account, BOOL *pb_result);
	
BOOL (*exmdb_client_unload_instance)(
	const char *dir, uint32_t instance_id);

BOOL (*exmdb_client_get_instance_all_proptags)(
	const char *dir, uint32_t instance_id,
	PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_get_instance_properties)(
	const char *dir, uint32_t size_limit, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL (*exmdb_client_set_instance_properties)(const char *dir,
	uint32_t instance_id, const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_remove_instance_properties)(const char *dir,
	uint32_t instance_id, const PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_check_instance_cycle)(const char *dir,
	uint32_t src_instance_id, uint32_t dst_instance_id,
	BOOL *pb_cycle);

BOOL (*exmdb_client_empty_message_instance_rcpts)(
	const char *dir, uint32_t instance_id);

BOOL (*exmdb_client_get_message_instance_rcpts_num)(
	const char *dir, uint32_t instance_id, uint16_t *pnum);

BOOL (*exmdb_client_get_message_instance_rcpts_all_proptags)(
	const char *dir, uint32_t instance_id,
	PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_get_message_instance_rcpts)(
	const char *dir, uint32_t instance_id, uint32_t row_id,
	uint16_t need_count, TARRAY_SET *pset);

BOOL (*exmdb_client_update_message_instance_rcpts)(
	const char *dir, uint32_t instance_id, const TARRAY_SET *pset);

BOOL (*exmdb_client_copy_instance_rcpts)(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result);

BOOL (*exmdb_client_empty_message_instance_attachments)(
	const char *dir, uint32_t instance_id);

BOOL (*exmdb_client_get_message_instance_attachments_num)(
	const char *dir, uint32_t instance_id, uint16_t *pnum);

BOOL (*exmdb_client_get_message_instance_attachment_table_all_proptags)(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_query_message_instance_attachment_table)(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
	int32_t row_needed, TARRAY_SET *pset);

BOOL (*exmdb_client_copy_instance_attachments)(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result);

BOOL (*exmdb_client_set_message_instance_conflict)(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt);

BOOL (*exmdb_client_get_message_rcpts)(const char *dir,
	uint64_t message_id, TARRAY_SET *pset);

BOOL (*exmdb_client_get_message_properties)(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL (*exmdb_client_set_message_properties)(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems);

BOOL (*exmdb_client_set_message_read_state)(const char *dir,
	const char *username, uint64_t message_id,
	uint8_t mark_as_read, uint64_t *pread_cn);

BOOL (*exmdb_client_remove_message_properties)(const char *dir,
	uint32_t cpid, uint64_t message_id, const PROPTAG_ARRAY *pproptags);

BOOL (*exmdb_client_allocate_message_id)(const char *dir,
	uint64_t folder_id, uint64_t *pmessage_id);

BOOL (*exmdb_client_allocate_cn)(
	const char *dir, uint64_t *pcn);

BOOL (*exmdb_client_get_message_group_id)(const char *dir,
	uint64_t message_id, uint32_t **ppgroup_id);

BOOL (*exmdb_client_set_message_group_id)(const char *dir,
	uint64_t message_id, uint32_t group_id);

BOOL (*exmdb_client_save_change_indices)(const char *dir,
	uint64_t message_id, uint64_t cn, const INDEX_ARRAY *pindices,
	const PROPTAG_ARRAY *pungroup_proptags);

BOOL (*exmdb_client_get_change_indices)(const char *dir,
	uint64_t message_id, uint64_t cn, INDEX_ARRAY *pindices,
	PROPTAG_ARRAY *pungroup_proptags);

BOOL (*exmdb_client_mark_modified)(
	const char *dir, uint64_t message_id);

BOOL (*exmdb_client_try_mark_submit)(const char *dir,
	uint64_t message_id, BOOL *pb_marked);

BOOL (*exmdb_client_clear_submit)(const char *dir,
	uint64_t message_id, BOOL b_unsent);

BOOL (*exmdb_client_link_message)(const char *dir, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_result);

BOOL (*exmdb_client_unlink_message)(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint64_t message_id);

BOOL (*exmdb_client_rule_new_message)(const char *dir,
	const char *username, const char *account, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id);

BOOL (*exmdb_client_set_message_timer)(const char *dir,
	uint64_t message_id, uint32_t timer_id);

BOOL (*exmdb_client_get_message_timer)(const char *dir,
	uint64_t message_id, uint32_t **pptimer_id);

BOOL (*exmdb_client_empty_folder_permission)(
	const char *dir, uint64_t folder_id);

BOOL (*exmdb_client_update_folder_permission)(const char *dir,
	uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow);

BOOL (*exmdb_client_empty_folder_rule)(
	const char *dir, uint64_t folder_id);

BOOL (*exmdb_client_update_folder_rule)(const char *dir,
	uint64_t folder_id, uint16_t count,
	const RULE_DATA *prow, BOOL *pb_exceed);

BOOL (*exmdb_client_delivery_message)(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult);

BOOL (*exmdb_client_write_message)(const char *dir,
	const char *account, uint32_t cpid, uint64_t folder_id,
	const MESSAGE_CONTENT *pmsgctnt, BOOL *pb_result);

BOOL (*exmdb_client_read_message)(const char *dir,
	const char *username, uint32_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt);

BOOL (*exmdb_client_get_content_sync)(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, const IDSET *pseen_fai, const IDSET *pread,
	uint32_t cpid, const RESTRICTION *prestriction, BOOL b_ordered,
	uint32_t *pfai_count, uint64_t *pfai_total, uint32_t *pnormal_count,
	uint64_t *pnormal_total, EID_ARRAY *pupdated_mids, EID_ARRAY *pchg_mids,
	uint64_t *plast_cn, EID_ARRAY *pgiven_mids, EID_ARRAY *pdeleted_mids,
	EID_ARRAY *pnolonger_mids, EID_ARRAY *pread_mids,
	EID_ARRAY *punread_mids, uint64_t *plast_readcn);

BOOL (*exmdb_client_get_hierarchy_sync)(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, FOLDER_CHANGES *pfldchgs, uint64_t *plast_cn,
	EID_ARRAY *pgiven_fids, EID_ARRAY *pdeleted_fids);

BOOL (*exmdb_client_allocate_ids)(const char *dir,
	uint32_t count, uint64_t *pbegin_eid);

BOOL (*exmdb_client_subscribe_notification)(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id);

BOOL (*exmdb_client_unsubscribe_notification)(
	const char *dir, uint32_t sub_id);

BOOL (*exmdb_client_transport_new_mail)(const char *dir,
	uint64_t folder_id, uint64_t message_id,
	uint32_t message_flags, const char *pstr_class);

BOOL (*exmdb_client_check_contact_address)(const char *dir,
	const char *paddress, BOOL *pb_found);

BOOL (*exmdb_client_get_public_folder_unread_count)(const char *dir,
	const char *username, uint64_t folder_id, uint32_t *pcount);

void exmdb_client_init()
{
	/* do nothing */
}

int exmdb_client_run()
{
	void (*register_proc)(void*);
	void (*pass_service)(int, void*);
	
	exmdb_client_ping_store =
		query_service("exmdb_client_ping_store");
	if (NULL == exmdb_client_ping_store) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_ping_store\" service\n");
		return -1;
	}
	exmdb_client_get_all_named_propids =
		query_service("exmdb_client_get_all_named_propids");
	if (NULL == exmdb_client_get_all_named_propids) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_all_named_propids\" service\n");
		return -2;
	}
	exmdb_client_get_named_propids =
		query_service("exmdb_client_get_named_propids");
	if (NULL == exmdb_client_get_named_propids) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_named_propids\" service\n");
		return -2;
	}
	exmdb_client_get_named_propnames =
		query_service("exmdb_client_get_named_propnames");
	if (NULL == exmdb_client_get_named_propnames) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_named_propnames\" service\n");
		return -2;
	}
	exmdb_client_get_mapping_guid =
		query_service("exmdb_client_get_mapping_guid");
	if (NULL == exmdb_client_get_mapping_guid) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_mapping_guid\" service\n");
		return -2;
	}
	exmdb_client_get_mapping_replid =
		query_service("exmdb_client_get_mapping_replid");
	if (NULL == exmdb_client_get_mapping_replid) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_mapping_replid\" service\n");
		return -2;
	}
	exmdb_client_get_store_all_proptags =
		query_service("exmdb_client_get_store_all_proptags");
	if (NULL == exmdb_client_get_store_all_proptags) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_store_all_proptags\" service\n");
		return -2;
	}
	exmdb_client_get_store_properties =
		query_service("exmdb_client_get_store_properties");
	if (NULL == exmdb_client_get_store_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_store_properties\" service\n");
		return -2;
	}
	exmdb_client_set_store_properties =
		query_service("exmdb_client_set_store_properties");
	if (NULL == exmdb_client_set_store_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_store_properties\" service\n");
		return -2;
	}
	exmdb_client_remove_store_properties =
		query_service("exmdb_client_remove_store_properties");
	if (NULL == exmdb_client_remove_store_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_remove_store_properties\" service\n");
		return -2;
	}
	exmdb_client_check_mailbox_permission =
		query_service("exmdb_client_check_mailbox_permission");
	if (NULL == exmdb_client_check_mailbox_permission) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_mailbox_permission\" service\n");
		return -2;
	}
	exmdb_client_get_folder_by_class =
		query_service("exmdb_client_get_folder_by_class");
	if (NULL == exmdb_client_get_folder_by_class) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_folder_by_class\" service\n");
		return -2;
	}
	exmdb_client_set_folder_by_class =
		query_service("exmdb_client_set_folder_by_class");
	if (NULL == exmdb_client_set_folder_by_class) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_folder_by_class\" service\n");
		return -2;
	}
	exmdb_client_get_folder_class_table =
		query_service("exmdb_client_get_folder_class_table");
	if (NULL == exmdb_client_get_folder_class_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_folder_class_table\" service\n");
		return -2;
	}
	exmdb_client_check_folder_id =
		query_service("exmdb_client_check_folder_id");
	if (NULL == exmdb_client_check_folder_id) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_folder_id\" service\n");
		return -2;
	}
	exmdb_client_check_folder_deleted =
		query_service("exmdb_client_check_folder_deleted");
	if (NULL == exmdb_client_check_folder_deleted) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_folder_deleted\" service\n");
		return -2;
	}
	exmdb_client_get_folder_by_name =
		query_service("exmdb_client_get_folder_by_name");
	if (NULL == exmdb_client_get_folder_by_name) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_folder_by_name\" service\n");
		return -2;
	}
	exmdb_client_check_folder_permission =
		query_service("exmdb_client_check_folder_permission");
	if (NULL == exmdb_client_check_folder_permission) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_folder_permission\" service\n");
		return -2;
	}
	exmdb_client_create_folder_by_properties =
		query_service("exmdb_client_create_folder_by_properties");
	if (NULL == exmdb_client_create_folder_by_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_create_folder_by_properties\" service\n");
		return -2;
	}
	exmdb_client_get_folder_all_proptags =
		query_service("exmdb_client_get_folder_all_proptags");
	if (NULL == exmdb_client_get_folder_all_proptags) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_folder_all_proptags\" service\n");
		return -2;
	}
	exmdb_client_get_folder_properties =
		query_service("exmdb_client_get_folder_properties");
	if (NULL == exmdb_client_get_folder_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_folder_properties\" service\n");
		return -2;
	}
	exmdb_client_set_folder_properties =
		query_service("exmdb_client_set_folder_properties");
	if (NULL == exmdb_client_set_folder_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_folder_properties\" service\n");
		return -2;
	}
	exmdb_client_remove_folder_properties =
		query_service("exmdb_client_remove_folder_properties");
	if (NULL == exmdb_client_remove_folder_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_remove_folder_properties\" service\n");
		return -2;
	}
	exmdb_client_delete_folder =
		query_service("exmdb_client_delete_folder");
	if (NULL == exmdb_client_delete_folder) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_delete_folder\" service\n");
		return -2;
	}
	exmdb_client_empty_folder =
		query_service("exmdb_client_empty_folder");
	if (NULL == exmdb_client_empty_folder) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_empty_folder\" service\n");
		return -2;
	}
	exmdb_client_check_folder_cycle =
		query_service("exmdb_client_check_folder_cycle");
	if (NULL == exmdb_client_check_folder_cycle) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_folder_cycle\" service\n");
		return -2;
	}
	exmdb_client_copy_folder_internal =
		query_service("exmdb_client_copy_folder_internal");
	if (NULL == exmdb_client_copy_folder_internal) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_copy_folder_internal\" service\n");
		return -2;
	}
	exmdb_client_get_search_criteria =
		query_service("exmdb_client_get_search_criteria");
	if (NULL == exmdb_client_get_search_criteria) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_search_criteria\" service\n");
		return -2;
	}
	exmdb_client_set_search_criteria =
		query_service("exmdb_client_set_search_criteria");
	if (NULL == exmdb_client_set_search_criteria) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_search_criteria\" service\n");
		return -2;
	}
	exmdb_client_movecopy_message =
		query_service("exmdb_client_movecopy_message");
	if (NULL == exmdb_client_movecopy_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_movecopy_message\" service\n");
		return -2;
	}
	exmdb_client_movecopy_messages =
		query_service("exmdb_client_movecopy_messages");
	if (NULL == exmdb_client_movecopy_messages) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_movecopy_messages\" service\n");
		return -2;
	}
	exmdb_client_movecopy_folder =
		query_service("exmdb_client_movecopy_folder");
	if (NULL == exmdb_client_movecopy_folder) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_movecopy_folder\" service\n");
		return -2;
	}
	exmdb_client_delete_messages =
		query_service("exmdb_client_delete_messages");
	if (NULL == exmdb_client_delete_messages) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_delete_messages\" service\n");
		return -2;
	}
	exmdb_client_get_message_brief =
		query_service("exmdb_client_get_message_brief");
	if (NULL == exmdb_client_get_message_brief) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_brief\" service\n");
		return -2;
	}
	exmdb_client_sum_hierarchy =
		query_service("exmdb_client_sum_hierarchy");
	if (NULL == exmdb_client_sum_hierarchy) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_sum_hierarchy\" service\n");
		return -2;
	}
	exmdb_client_load_hierarchy_table =
		query_service("exmdb_client_load_hierarchy_table");
	if (NULL == exmdb_client_load_hierarchy_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_hierarchy_table\" service\n");
		return -2;
	}
	exmdb_client_sum_content =
		query_service("exmdb_client_sum_content");
	if (NULL == exmdb_client_sum_content) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_sum_content\" service\n");
		return -2;
	}
	exmdb_client_load_content_table =
		query_service("exmdb_client_load_content_table");
	if (NULL == exmdb_client_load_content_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_content_table\" service\n");
		return -2;
	}
	exmdb_client_reload_content_table =
		query_service("exmdb_client_reload_content_table");
	if (NULL == exmdb_client_reload_content_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_reload_content_table\" service\n");
		return -2;
	}
	exmdb_client_load_permission_table =
		query_service("exmdb_client_load_permission_table");
	if (NULL == exmdb_client_load_permission_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_permission_table\" service\n");
		return -2;
	}
	exmdb_client_load_rule_table =
		query_service("exmdb_client_load_rule_table");
	if (NULL == exmdb_client_load_rule_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_rule_table\" service\n");
		return -2;
	}
	exmdb_client_unload_table =
		query_service("exmdb_client_unload_table");
	if (NULL == exmdb_client_unload_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_unload_table\" service\n");
		return -2;
	}
	exmdb_client_sum_table =
		query_service("exmdb_client_sum_table");
	if (NULL == exmdb_client_sum_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_sum_table\" service\n");
		return -2;
	}
	exmdb_client_query_table =
		query_service("exmdb_client_query_table");
	if (NULL == exmdb_client_query_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_query_table\" service\n");
		return -2;
	}
	exmdb_client_match_table =
		query_service("exmdb_client_match_table");
	if (NULL == exmdb_client_match_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_match_table\" service\n");
		return -2;
	}
	exmdb_client_locate_table =
		query_service("exmdb_client_locate_table");
	if (NULL == exmdb_client_locate_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_locate_table\" service\n");
		return -2;
	}
	exmdb_client_read_table_row =
		query_service("exmdb_client_read_table_row");
	if (NULL == exmdb_client_read_table_row) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_read_table_row\" service\n");
		return -2;
	}
	exmdb_client_mark_table =
		query_service("exmdb_client_mark_table");
	if (NULL == exmdb_client_mark_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_mark_table\" service\n");
		return -2;
	}
	exmdb_client_get_table_all_proptags =
		query_service("exmdb_client_get_table_all_proptags");
	if (NULL == exmdb_client_get_table_all_proptags) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_table_all_proptags\" service\n");
		return -2;
	}
	exmdb_client_expand_table =
		query_service("exmdb_client_expand_table");
	if (NULL == exmdb_client_expand_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_expand_table\" service\n");
		return -2;
	}
	exmdb_client_collapse_table =
		query_service("exmdb_client_collapse_table");
	if (NULL == exmdb_client_collapse_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_collapse_table\" service\n");
		return -2;
	}
	exmdb_client_store_table_state =
		query_service("exmdb_client_store_table_state");
	if (NULL == exmdb_client_store_table_state) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_store_table_state\" service\n");
		return -2;
	}
	exmdb_client_restore_table_state =
		query_service("exmdb_client_restore_table_state");
	if (NULL == exmdb_client_restore_table_state) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_restore_table_state\" service\n");
		return -2;
	}
	exmdb_client_check_message =
		query_service("exmdb_client_check_message");
	if (NULL == exmdb_client_check_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_message\" service\n");
		return -2;
	}
	exmdb_client_check_message_deleted =
		query_service("exmdb_client_check_message_deleted");
	if (NULL == exmdb_client_check_message_deleted) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_message_deleted\" service\n");
		return -2;
	}
	exmdb_client_load_message_instance =
		query_service("exmdb_client_load_message_instance");
	if (NULL == exmdb_client_load_message_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_message_instance\" service\n");
		return -2;
	}
	exmdb_client_load_embedded_instance =
		query_service("exmdb_client_load_embedded_instance");
	if (NULL == exmdb_client_load_embedded_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_embedded_instance\" service\n");
		return -2;
	}
	exmdb_client_get_embeded_cn =
		query_service("exmdb_client_get_embeded_cn");
	if (NULL == exmdb_client_get_embeded_cn) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_embeded_cn\" service\n");
		return -2;
	}
	exmdb_client_reload_message_instance =
		query_service("exmdb_client_reload_message_instance");
	if (NULL == exmdb_client_reload_message_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_reload_message_instance\" service\n");
		return -2;
	}
	exmdb_client_clear_message_instance =
		query_service("exmdb_client_clear_message_instance");
	if (NULL == exmdb_client_clear_message_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_clear_message_instance\" service\n");
		return -2;
	}
	exmdb_client_read_message_instance =
		query_service("exmdb_client_read_message_instance");
	if (NULL == exmdb_client_read_message_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_read_message_instance\" service\n");
		return -2;
	}
	exmdb_client_write_message_instance =
		query_service("exmdb_client_write_message_instance");
	if (NULL == exmdb_client_write_message_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_write_message_instance\" service\n");
		return -2;
	}
	exmdb_client_load_attachment_instance =
		query_service("exmdb_client_load_attachment_instance");
	if (NULL == exmdb_client_load_attachment_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_load_attachment_instance\" service\n");
		return -2;
	}
	exmdb_client_create_attachment_instance =
		query_service("exmdb_client_create_attachment_instance");
	if (NULL == exmdb_client_create_attachment_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_create_attachment_instance\" service\n");
		return -2;
	}
	exmdb_client_read_attachment_instance =
		query_service("exmdb_client_read_attachment_instance");
	if (NULL == exmdb_client_read_attachment_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_read_attachment_instance\" service\n");
		return -2;
	}
	exmdb_client_write_attachment_instance =
		query_service("exmdb_client_write_attachment_instance");
	if (NULL == exmdb_client_write_attachment_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_write_attachment_instance\" service\n");
		return -2;
	}
	exmdb_client_delete_message_instance_attachment =
		query_service("exmdb_client_delete_message_instance_attachment");
	if (NULL == exmdb_client_delete_message_instance_attachment) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_delete_message_instance_attachment\" service\n");
		return -2;
	}
	exmdb_client_flush_instance =
		query_service("exmdb_client_flush_instance");
	if (NULL == exmdb_client_flush_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_flush_instance\" service\n");
		return -2;
	}
	exmdb_client_unload_instance =
		query_service("exmdb_client_unload_instance");
	if (NULL == exmdb_client_unload_instance) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_unload_instance\" service\n");
		return -2;
	}
	exmdb_client_get_instance_all_proptags =
		query_service("exmdb_client_get_instance_all_proptags");
	if (NULL == exmdb_client_get_instance_all_proptags) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_instance_all_proptags\" service\n");
		return -2;
	}
	exmdb_client_get_instance_properties =
		query_service("exmdb_client_get_instance_properties");
	if (NULL == exmdb_client_get_instance_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_instance_properties\" service\n");
		return -2;
	}
	exmdb_client_set_instance_properties =
		query_service("exmdb_client_set_instance_properties");
	if (NULL == exmdb_client_set_instance_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_instance_properties\" service\n");
		return -2;
	}
	exmdb_client_remove_instance_properties =
		query_service("exmdb_client_remove_instance_properties");
	if (NULL == exmdb_client_remove_instance_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_remove_instance_properties\" service\n");
		return -2;
	}
	exmdb_client_check_instance_cycle =
		query_service("exmdb_client_check_instance_cycle");
	if (NULL == exmdb_client_check_instance_cycle) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_instance_cycle\" service\n");
		return -2;
	}
	exmdb_client_empty_message_instance_rcpts =
		query_service("exmdb_client_empty_message_instance_rcpts");
	if (NULL == exmdb_client_empty_message_instance_rcpts) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_empty_message_instance_rcpts\" service\n");
		return -2;
	}
	exmdb_client_get_message_instance_rcpts_num =
		query_service("exmdb_client_get_message_instance_rcpts_num");
	if (NULL == exmdb_client_get_message_instance_rcpts_num) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_instance_rcpts_num\" service\n");
		return -2;
	}
	exmdb_client_get_message_instance_rcpts_all_proptags =
		query_service("exmdb_client_get_message_instance_rcpts_all_proptags");
	if (NULL == exmdb_client_get_message_instance_rcpts_all_proptags) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_instance_rcpts_all_proptags\" service\n");
		return -2;
	}
	exmdb_client_get_message_instance_rcpts =
		query_service("exmdb_client_get_message_instance_rcpts");
	if (NULL == exmdb_client_get_message_instance_rcpts) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_instance_rcpts\" service\n");
		return -2;
	}
	exmdb_client_update_message_instance_rcpts =
		query_service("exmdb_client_update_message_instance_rcpts");
	if (NULL == exmdb_client_update_message_instance_rcpts) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_update_message_instance_rcpts\" service\n");
		return -2;
	}
	exmdb_client_copy_instance_rcpts =
		query_service("exmdb_client_copy_instance_rcpts");
	if (NULL == exmdb_client_copy_instance_rcpts) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_copy_instance_rcpts\" service\n");
		return -2;
	}
	exmdb_client_empty_message_instance_attachments =
		query_service("exmdb_client_empty_message_instance_attachments");
	if (NULL == exmdb_client_empty_message_instance_attachments) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_empty_message_instance_attachments\" service\n");
		return -2;
	}
	exmdb_client_get_message_instance_attachments_num =
		query_service("exmdb_client_get_message_instance_attachments_num");
	if (NULL == exmdb_client_get_message_instance_attachments_num) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_instance_attachments_num\" service\n");
		return -2;
	}
	exmdb_client_get_message_instance_attachment_table_all_proptags =
		query_service("exmdb_client_get_message_instance_attachment_table_all_proptags");
	if (NULL == exmdb_client_get_message_instance_attachment_table_all_proptags) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_instance_attachment_table_all_proptags\" service\n");
		return -2;
	}
	exmdb_client_query_message_instance_attachment_table =
		query_service("exmdb_client_query_message_instance_attachment_table");
	if (NULL == exmdb_client_query_message_instance_attachment_table) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_query_message_instance_attachment_table\" service\n");
		return -2;
	}
	exmdb_client_copy_instance_attachments =
		query_service("exmdb_client_copy_instance_attachments");
	if (NULL == exmdb_client_copy_instance_attachments) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_copy_instance_attachments\" service\n");
		return -2;
	}
	exmdb_client_set_message_instance_conflict =
		query_service("exmdb_client_set_message_instance_conflict");
	if (NULL == exmdb_client_set_message_instance_conflict) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_message_instance_conflict\" service\n");
		return -2;
	}
	exmdb_client_get_message_rcpts =
		query_service("exmdb_client_get_message_rcpts");
	if (NULL == exmdb_client_get_message_rcpts) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_rcpts\" service\n");
		return -2;
	}
	exmdb_client_get_message_properties =
		query_service("exmdb_client_get_message_properties");
	if (NULL == exmdb_client_get_message_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_properties\" service\n");
		return -2;
	}
	exmdb_client_set_message_properties =
		query_service("exmdb_client_set_message_properties");
	if (NULL == exmdb_client_set_message_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_message_properties\" service\n");
		return -2;
	}
	exmdb_client_set_message_read_state =
		query_service("exmdb_client_set_message_read_state");
	if (NULL == exmdb_client_set_message_read_state) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_message_read_state\" service\n");
		return -2;
	}
	exmdb_client_remove_message_properties =
		query_service("exmdb_client_remove_message_properties");
	if (NULL == exmdb_client_remove_message_properties) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_remove_message_properties\" service\n");
		return -2;
	}
	exmdb_client_allocate_message_id =
		query_service("exmdb_client_allocate_message_id");
	if (NULL == exmdb_client_allocate_message_id) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_allocate_message_id\" service\n");
		return -2;
	}
	exmdb_client_allocate_cn =
		query_service("exmdb_client_allocate_cn");
	if (NULL == exmdb_client_allocate_cn) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_allocate_cn\" service\n");
		return -2;
	}
	exmdb_client_get_message_group_id =
		query_service("exmdb_client_get_message_group_id");
	if (NULL == exmdb_client_get_message_group_id) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_group_id\" service\n");
		return -2;
	}
	exmdb_client_set_message_group_id =
		query_service("exmdb_client_set_message_group_id");
	if (NULL == exmdb_client_set_message_group_id) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_message_group_id\" service\n");
		return -2;
	}
	exmdb_client_save_change_indices =
		query_service("exmdb_client_save_change_indices");
	if (NULL == exmdb_client_save_change_indices) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_save_change_indices\" service\n");
		return -2;
	}
	exmdb_client_get_change_indices =
		query_service("exmdb_client_get_change_indices");
	if (NULL == exmdb_client_get_change_indices) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_change_indices\" service\n");
		return -2;
	}
	exmdb_client_mark_modified =
		query_service("exmdb_client_mark_modified");
	if (NULL == exmdb_client_mark_modified) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_mark_modified\" service\n");
		return -2;
	}
	exmdb_client_try_mark_submit =
		query_service("exmdb_client_try_mark_submit");
	if (NULL == exmdb_client_try_mark_submit) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_try_mark_submit\" service\n");
		return -2;
	}
	exmdb_client_clear_submit =
		query_service("exmdb_client_clear_submit");
	if (NULL == exmdb_client_clear_submit) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_clear_submit\" service\n");
		return -2;
	}
	exmdb_client_link_message =
		query_service("exmdb_client_link_message");
	if (NULL == exmdb_client_link_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_link_message\" service\n");
		return -2;
	}
	exmdb_client_unlink_message =
		query_service("exmdb_client_unlink_message");
	if (NULL == exmdb_client_unlink_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_unlink_message\" service\n");
		return -2;
	}
	exmdb_client_rule_new_message =
		query_service("exmdb_client_rule_new_message");
	if (NULL == exmdb_client_rule_new_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_rule_new_message\" service\n");
		return -2;
	}
	exmdb_client_set_message_timer =
		query_service("exmdb_client_set_message_timer");
	if (NULL == exmdb_client_set_message_timer) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_set_message_timer\" service\n");
		return -2;
	}
	exmdb_client_get_message_timer =
		query_service("exmdb_client_get_message_timer");
	if (NULL == exmdb_client_get_message_timer) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_message_timer\" service\n");
		return -2;
	}
	exmdb_client_empty_folder_permission =
		query_service("exmdb_client_empty_folder_permission");
	if (NULL == exmdb_client_empty_folder_permission) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_empty_folder_permission\" service\n");
		return -2;
	}
	exmdb_client_update_folder_permission =
		query_service("exmdb_client_update_folder_permission");
	if (NULL == exmdb_client_update_folder_permission) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_update_folder_permission\" service\n");
		return -2;
	}
	exmdb_client_empty_folder_rule =
		query_service("exmdb_client_empty_folder_rule");
	if (NULL == exmdb_client_empty_folder_rule) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_empty_folder_rule\" service\n");
		return -2;
	}
	exmdb_client_update_folder_rule =
		query_service("exmdb_client_update_folder_rule");
	if (NULL == exmdb_client_update_folder_rule) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_update_folder_rule\" service\n");
		return -2;
	}
	exmdb_client_delivery_message =
		query_service("exmdb_client_delivery_message");
	if (NULL == exmdb_client_delivery_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_delivery_message\" service\n");
		return -2;
	}
	exmdb_client_write_message =
		query_service("exmdb_client_write_message");
	if (NULL == exmdb_client_write_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_write_message\" service\n");
		return -2;
	}
	exmdb_client_read_message =
		query_service("exmdb_client_read_message");
	if (NULL == exmdb_client_read_message) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_read_message\" service\n");
		return -2;
	}
	exmdb_client_get_content_sync =
		query_service("exmdb_client_get_content_sync");
	if (NULL == exmdb_client_get_content_sync) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_content_sync\" service\n");
		return -2;
	}
	exmdb_client_get_hierarchy_sync =
		query_service("exmdb_client_get_hierarchy_sync");
	if (NULL == exmdb_client_get_hierarchy_sync) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_hierarchy_sync\" service\n");
		return -2;
	}
	exmdb_client_allocate_ids =
		query_service("exmdb_client_allocate_ids");
	if (NULL == exmdb_client_allocate_ids) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_allocate_ids\" service\n");
		return -2;
	}
	exmdb_client_subscribe_notification =
		query_service("exmdb_client_subscribe_notification");
	if (NULL == exmdb_client_subscribe_notification) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_subscribe_notification\" service\n");
		return -2;
	}
	exmdb_client_unsubscribe_notification =
		query_service("exmdb_client_unsubscribe_notification");
	if (NULL == exmdb_client_unsubscribe_notification) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_unsubscribe_notification\" service\n");
		return -2;
	}
	exmdb_client_transport_new_mail =
		query_service("exmdb_client_transport_new_mail");
	if (NULL == exmdb_client_transport_new_mail) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_transport_new_mail\" service\n");
		return -2;
	}
	exmdb_client_check_contact_address =
		query_service("exmdb_client_check_contact_address");
	if (NULL == exmdb_client_check_contact_address) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_check_contact_address\" service\n");
		return -2;
	}
	exmdb_client_get_public_folder_unread_count =
		query_service("exmdb_client_get_public_folder_unread_count");
	if (NULL == exmdb_client_get_public_folder_unread_count) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_get_public_folder_unread_count\" service\n");
		return -2;
	}
	register_proc = query_service("exmdb_client_register_proc");
	if (NULL == register_proc) {
		printf("[exchange_emsmdb]: fail to query "
			"\"exmdb_client_register_proc\" service\n");
		return -2;
	}
	register_proc(emsmdb_interface_event_proc);
	pass_service = query_service("pass_service");
	if (NULL == pass_service) {
		printf("[exchange_emsmdb]: fail to query "
			"\"pass_service\" service\n");
		return -2;
	}
	/* pass the service functions to exmdb_provider */
	pass_service(SERVICE_ID_LANG_TO_CHARSET,
		common_util_lang_to_charset);
	pass_service(SERVICE_ID_CPID_TO_CHARSET,
		common_util_cpid_to_charset);
	pass_service(SERVICE_ID_GET_USER_DISPLAYNAME,
		common_util_get_user_displayname);
	pass_service(SERVICE_ID_CHECK_MLIST_INCLUDE,
		common_util_check_mlist_include);
	pass_service(SERVICE_ID_GET_USER_LANG,
		common_util_get_user_lang);
	pass_service(SERVICE_ID_GET_TIMEZONE,
		common_util_get_timezone);
	pass_service(SERVICE_ID_GET_MAILDIR,
		common_util_get_maildir);
	pass_service(SERVICE_ID_GET_ID_FFROM_USERNAME,
		common_util_get_id_from_username);
	pass_service(SERVICE_ID_GET_USERNAME_FROM_ID,
		common_util_get_username_from_id);
	pass_service(SERVICE_ID_GET_USER_IDS,
		common_util_get_user_ids);
	pass_service(SERVICE_ID_GET_DOMAIN_IDS,
		common_util_get_domain_ids);
	pass_service(SERVICE_ID_GET_ID_FROM_MAILDIR,
		common_util_get_id_from_maildir);
	pass_service(SERVICE_ID_GET_ID_FROM_HOMEDIR,
		common_util_get_id_from_homedir);
	pass_service(SERVICE_ID_SEND_MAIL,
		common_util_send_mail);
	pass_service(SERVICE_ID_GET_MIME_POOL,
		common_util_get_mime_pool);
	pass_service(SERVICE_ID_LOG_INFO, log_info);
	pass_service(SERVICE_ID_GET_HANDLE,
		emsmdb_interface_get_handle);
	return 0;
}

int exmdb_client_stop()
{
	return 0;
}

void exmdb_client_free()
{
	/* do nothing */
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
	if (0 == tmp_propvals.count) {
		*ppval = NULL;
	} else {
		*ppval = tmp_propvals.ppropval->pvalue;
	}
	return TRUE;
}

BOOL exmdb_client_set_store_property(const char *dir,
	uint32_t cpid, const TAGGED_PROPVAL *ppropval,
	uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (FALSE == exmdb_client_set_store_properties(
		dir, cpid, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	if (0 == tmp_problems.count) {
		*presult = 0;
	} else {
		*presult = tmp_problems.pproblem->err;
	}
	return TRUE;
}

BOOL exmdb_client_remove_store_property(
	const char *dir, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	return exmdb_client_remove_store_properties(
							dir, &tmp_proptags);
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
	if (0 == tmp_propvals.count) {
		*ppval = NULL;
	} else {
		*ppval = tmp_propvals.ppropval->pvalue;
	}
	return TRUE;
}

BOOL exmdb_client_set_folder_property(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (FALSE == exmdb_client_set_folder_properties(
		dir, cpid, folder_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	if (0 == tmp_problems.count) {
		*presult = 0;
	} else {
		*presult = tmp_problems.pproblem->err;
	}
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
	if (FALSE == b_partial) {
		*pb_done = TRUE;
	} else {
		*pb_done = FALSE;
	}
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
	if (0 == tmp_propvals.count) {
		*ppval = NULL;
	} else {
		*ppval = tmp_propvals.ppropval->pvalue;
	}
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
	if (0 == tmp_problems.count) {
		*presult = 0;
	} else {
		*presult = tmp_problems.pproblem->err;
	}
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
	if (0 == tmp_problems.count) {
		*presult = 0;
	} else {
		*presult = tmp_problems.pproblem->err;
	}
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
	if (0 == tmp_propvals.count) {
		*ppval = NULL;
	} else {
		*ppval = tmp_propvals.ppropval->pvalue;
	}
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
	if (0 == tmp_problems.count) {
		*presult = 0;
	} else {
		*presult = tmp_problems.pproblem->err;
	}
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
		return FALSE;	
	}
	if (FALSE == common_util_essdn_to_username(
		ab_entryid.px500dn, tmp_name)) {
		return FALSE;	
	}
	if (0 == strcasecmp(username, tmp_name)) {
		*pb_owner = TRUE;
	} else {
		*pb_owner = FALSE;
	}
	return TRUE;
}
