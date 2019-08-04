#ifndef _H_EXMDB_SERVER_
#define _H_EXMDB_SERVER_
#include "mapi_types.h"
#include "element_data.h"
#include "alloc_context.h"

extern void (*exmdb_server_event_proc)(const char *dir,
	BOOL b_table, uint32_t notify_id, const DB_NOTIFY *pdb_notify);

void exmdb_server_init();

int exmdb_server_run();

int exmdb_server_stop();

void exmdb_server_free();

void exmdb_server_build_environment(BOOL b_local,
	BOOL b_private, const char *dir);

void exmdb_server_free_environment();

void exmdb_server_set_remote_id(const char *remote_id);

const char* exmdb_server_get_remote_id();

void exmdb_server_set_public_username(const char *username);

const char* exmdb_server_get_public_username();

ALLOC_CONTEXT* exmdb_server_get_alloc_context();

BOOL exmdb_server_check_private();

const char* exmdb_server_get_dir();

void exmdb_server_set_dir(const char *dir);

int exmdb_server_get_account_id();

const GUID* exmdb_server_get_handle();

BOOL exmdb_server_ping_store(const char *dir);

BOOL exmdb_server_get_all_named_propids(
	const char *dir, PROPID_ARRAY *ppropids);

BOOL exmdb_server_get_named_propids(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);

BOOL exmdb_server_get_named_propnames(const char *dir,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);

BOOL exmdb_server_get_mapping_guid(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid);

BOOL exmdb_server_get_mapping_replid(const char *dir,
	GUID guid, BOOL *pb_found, uint16_t *preplid);

BOOL exmdb_server_get_store_all_proptags(
	const char *dir, PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_get_store_properties(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_server_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_remove_store_properties(
	const char *dir, const PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_check_mailbox_permission(const char *dir,
	const char *username, uint32_t *ppermission);

BOOL exmdb_server_get_folder_by_class(const char *dir,
	const char *str_class, uint64_t *pid, char *str_explicit);

BOOL exmdb_server_set_folder_by_class(const char *dir,
	uint64_t folder_id, const char *str_class, BOOL *pb_result);

BOOL exmdb_server_get_folder_class_table(
	const char *dir, TARRAY_SET *ptable);

BOOL exmdb_server_check_folder_id(const char *dir,
	uint64_t folder_id, BOOL *pb_exist);

BOOL exmdb_server_query_folder_messages(const char *dir,
	uint64_t folder_id, TARRAY_SET *pset);

BOOL exmdb_server_check_folder_deleted(const char *dir,
	uint64_t folder_id, BOOL *pb_del);

BOOL exmdb_server_get_folder_by_name(const char *dir,
	uint64_t parent_id, const char *str_name,
	uint64_t *pfolder_id);

BOOL exmdb_server_check_folder_permission(const char *dir,
	uint64_t folder_id, const char *username,
	uint32_t *ppermission);

BOOL exmdb_server_create_folder_by_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *pproperties,
	uint64_t *pfolder_id);

BOOL exmdb_server_get_folder_all_proptags(const char *dir,
	uint64_t folder_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_get_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_server_set_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_remove_folder_properties(const char *dir,
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_delete_folder(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result);

BOOL exmdb_server_empty_folder(const char *dir, uint32_t cpid,
	const char *username, uint64_t folder_id, BOOL b_hard,
	BOOL b_normal, BOOL b_fai, BOOL b_sub, BOOL *pb_partial);

BOOL exmdb_server_check_folder_cycle(const char *dir,
	uint64_t src_fid, uint64_t dst_fid, BOOL *pb_cycle);

BOOL exmdb_server_copy_folder_internal(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, BOOL b_normal, BOOL b_fai, BOOL b_sub,
	uint64_t dst_fid, BOOL *pb_collid, BOOL *pb_partial);

BOOL exmdb_server_get_search_criteria(
	const char *dir, uint64_t folder_id, uint32_t *psearch_status,
	RESTRICTION **pprestriction, LONGLONG_ARRAY *pfolder_ids);

BOOL exmdb_server_set_search_criteria(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint32_t search_flags,
	const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids,
	BOOL *pb_result);

BOOL exmdb_server_movecopy_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t message_id,
	uint64_t dst_fid, uint64_t dst_id, BOOL b_move,
	BOOL *pb_result);

BOOL exmdb_server_movecopy_messages(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, uint64_t dst_fid,
	BOOL b_copy, const EID_ARRAY *pmessage_ids, BOOL *pb_partial);

BOOL exmdb_server_movecopy_folder(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_pid, uint64_t src_fid, uint64_t dst_fid,
	const char *str_new, BOOL b_copy, BOOL *pb_exist,
	BOOL *pb_partial);

BOOL exmdb_server_delete_messages(const char *dir,
	int account_id, uint32_t cpid, const char *username,
	uint64_t folder_id, const EID_ARRAY *pmessage_ids,
	BOOL b_hard, BOOL *pb_partial);

BOOL exmdb_server_get_message_brief(const char *dir, uint32_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppbrief);

BOOL exmdb_server_sum_hierarchy(const char *dir,
	uint64_t folder_id, const char *username,
	BOOL b_depth, uint32_t *pcount);
	
BOOL exmdb_server_load_hierarchy_table(const char *dir,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, uint32_t *ptable_id,
	uint32_t *prow_count);

BOOL exmdb_server_sum_content(const char *dir, uint64_t folder_id,
	BOOL b_fai, BOOL b_deleted, uint32_t *pcount);

BOOL exmdb_server_load_content_table(const char *dir, uint32_t cpid,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL exmdb_server_reload_content_table(const char *dir, uint32_t table_id);

BOOL exmdb_server_load_permission_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL exmdb_server_load_rule_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	const RESTRICTION *prestriction,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL exmdb_server_unload_table(const char *dir, uint32_t table_id);

BOOL exmdb_server_sum_table(const char *dir,
	uint32_t table_id, uint32_t *prows);

BOOL exmdb_server_query_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset);

BOOL exmdb_server_match_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, BOOL b_forward, uint32_t start_pos,
	const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_server_locate_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	int32_t *pposition, uint32_t *prow_type);

BOOL exmdb_server_read_table_row(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint64_t inst_id, uint32_t inst_num, TPROPVAL_ARRAY *ppropvals);
	
BOOL exmdb_server_mark_table(const char *dir,
	uint32_t table_id, uint32_t position, uint64_t *pinst_id,
	uint32_t *pinst_num, uint32_t *prow_type);

BOOL exmdb_server_get_table_all_proptags(const char *dir,
	uint32_t table_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_expand_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count);

BOOL exmdb_server_collapse_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count);

BOOL exmdb_server_store_table_state(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	uint32_t *pstate_id);

BOOL exmdb_server_restore_table_state(const char *dir,
	uint32_t table_id, uint32_t state_id, int32_t *pposition);

BOOL exmdb_server_check_message(const char *dir,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist);

BOOL exmdb_server_check_message_deleted(const char *dir,
	uint64_t message_id, BOOL *pb_del);

BOOL exmdb_server_load_message_instance(const char *dir,
	const char *username, uint32_t cpid, BOOL b_new,
	uint64_t folder_id, uint64_t message_id,
	uint32_t *pinstance_id);

BOOL exmdb_server_load_embedded_instance(const char *dir,
	BOOL b_new, uint32_t attachment_instance_id,
	uint32_t *pinstance_id);

BOOL exmdb_server_get_embeded_cn(const char *dir,
	uint32_t instance_id, uint64_t **ppcn);

BOOL exmdb_server_reload_message_instance(
	const char *dir, uint32_t instance_id, BOOL *pb_result);

BOOL exmdb_server_clear_message_instance(
	const char *dir, uint32_t instance_id);

BOOL exmdb_server_read_message_instance(const char *dir,
	uint32_t instance_id, MESSAGE_CONTENT *pmsgctnt);

BOOL exmdb_server_write_message_instance(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt,
	BOOL b_force, PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_load_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t attachment_num,
	uint32_t *pinstance_id);

BOOL exmdb_server_create_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t *pinstance_id,
	uint32_t *pattachment_num);

BOOL exmdb_server_read_attachment_instance(const char *dir,
	uint32_t instance_id, ATTACHMENT_CONTENT *pattctnt);

BOOL exmdb_server_write_attachment_instance(const char *dir,
	uint32_t instance_id, const ATTACHMENT_CONTENT *pattctnt,
	BOOL b_force, PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_delete_message_instance_attachment(
	const char *dir, uint32_t message_instance_id,
	uint32_t attachment_num);

BOOL exmdb_server_flush_instance(const char *dir,
	uint32_t instance_id, const char *account, BOOL *pb_result);
	
BOOL exmdb_server_unload_instance(
	const char *dir, uint32_t instance_id);

BOOL exmdb_server_get_instance_all_proptags(
	const char *dir, uint32_t instance_id,
	PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_get_instance_properties(
	const char *dir, uint32_t size_limit, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_server_set_instance_properties(const char *dir,
	uint32_t instance_id, const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_remove_instance_properties(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_check_instance_cycle(const char *dir,
	uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_cycle);

BOOL exmdb_server_empty_message_instance_rcpts(
	const char *dir, uint32_t instance_id);

BOOL exmdb_server_get_message_instance_rcpts_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum);

BOOL exmdb_server_get_message_instance_rcpts_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_get_message_instance_rcpts(
	const char *dir, uint32_t instance_id,
	uint32_t row_id, uint16_t need_count, TARRAY_SET *pset);

BOOL exmdb_server_update_message_instance_rcpts(
	const char *dir, uint32_t instance_id, const TARRAY_SET *pset);

BOOL exmdb_server_copy_instance_rcpts(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result);

BOOL exmdb_server_empty_message_instance_attachments(
	const char *dir, uint32_t instance_id);

BOOL exmdb_server_get_message_instance_attachments_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum);

BOOL exmdb_server_get_message_instance_attachment_table_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_query_message_instance_attachment_table(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
	int32_t row_needed, TARRAY_SET *pset);

BOOL exmdb_server_copy_instance_attachments(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result);

BOOL exmdb_server_set_message_instance_conflict(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt);

BOOL exmdb_server_get_message_rcpts(const char *dir,
	uint64_t message_id, TARRAY_SET *pset);

BOOL exmdb_server_get_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_server_set_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems);

BOOL exmdb_server_set_message_read_state(const char *dir,
	const char *username, uint64_t message_id,
	uint8_t mark_as_read, uint64_t *pread_cn);

BOOL exmdb_server_remove_message_properties(
	const char *dir, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags);

BOOL exmdb_server_allocate_message_id(const char *dir,
	uint64_t folder_id, uint64_t *pmessage_id);

BOOL exmdb_server_allocate_cn(const char *dir, uint64_t *pcn);

BOOL exmdb_server_get_message_group_id(const char *dir,
	uint64_t message_id, uint32_t **ppgroup_id);

BOOL exmdb_server_set_message_group_id(const char *dir,
	uint64_t message_id, uint32_t group_id);

BOOL exmdb_server_save_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, const INDEX_ARRAY *pindices,
	const PROPTAG_ARRAY *pungroup_proptags);

BOOL exmdb_server_get_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, INDEX_ARRAY *pindices,
	PROPTAG_ARRAY *pungroup_proptags);

BOOL exmdb_server_mark_modified(const char *dir, uint64_t message_id);

BOOL exmdb_server_try_mark_submit(const char *dir,
	uint64_t message_id, BOOL *pb_marked);

BOOL exmdb_server_clear_submit(const char *dir,
	uint64_t message_id, BOOL b_unsent);

BOOL exmdb_server_link_message(const char *dir, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_result);

BOOL exmdb_server_unlink_message(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint64_t message_id);

BOOL exmdb_server_rule_new_message(const char *dir,
	const char *username, const char *account, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id);

BOOL exmdb_server_set_message_timer(const char *dir,
	uint64_t message_id, uint32_t timer_id);

BOOL exmdb_server_get_message_timer(const char *dir,
	uint64_t message_id, uint32_t **pptimer_id);

BOOL exmdb_server_empty_folder_permission(
	const char *dir, uint64_t folder_id);

BOOL exmdb_server_update_folder_permission(const char *dir,
	uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow);

BOOL exmdb_server_empty_folder_rule(
	const char *dir, uint64_t folder_id);

BOOL exmdb_server_update_folder_rule(const char *dir,
	uint64_t folder_id, uint16_t count,
	const RULE_DATA *prow, BOOL *pb_exceed);

BOOL exmdb_server_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult);

BOOL exmdb_server_write_message(const char *dir,
	const char *account, uint32_t cpid, uint64_t folder_id,
	const MESSAGE_CONTENT *pmsgctnt, BOOL *pb_result);

BOOL exmdb_server_read_message(const char *dir, const char *username,
	uint32_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt);

BOOL exmdb_server_get_content_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, const IDSET *pseen_fai, const IDSET *pread,
	uint32_t cpid, const RESTRICTION *prestriction, BOOL b_ordered,
	uint32_t *pfai_count, uint64_t *pfai_total, uint32_t *pnormal_count,
	uint64_t *pnormal_total, EID_ARRAY *pupdated_mids, EID_ARRAY *pchg_mids,
	uint64_t *plast_cn, EID_ARRAY *pgiven_mids, EID_ARRAY *pdeleted_mids,
	EID_ARRAY *pnolonger_mids, EID_ARRAY *pread_mids,
	EID_ARRAY *punread_mids, uint64_t *plast_readcn);

BOOL exmdb_server_get_hierarchy_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, FOLDER_CHANGES *pfldchgs, uint64_t *plast_cn,
	EID_ARRAY *pgiven_fids, EID_ARRAY *pdeleted_fids);

BOOL exmdb_server_allocate_ids(const char *dir,
	uint32_t count, uint64_t *pbegin_eid);

BOOL exmdb_server_subscribe_notification(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id);

BOOL exmdb_server_unsubscribe_notification(
	const char *dir, uint32_t sub_id);

BOOL exmdb_server_notify_new_mail(const char *dir,
	uint64_t folder_id, uint64_t message_id);

BOOL exmdb_server_transport_new_mail(const char *dir, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class);

BOOL exmdb_server_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found);

void exmdb_server_register_proc(void *pproc);

BOOL exmdb_server_unload_store(const char *dir);

#endif /* _H_EXMDB_SERVER_ */
