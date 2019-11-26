#ifndef _H_EXMDB_CLIENT_
#define _H_EXMDB_CLIENT_
#include "mapi_types.h"
#include "element_data.h"

enum {
	ALIVE_PROXY_CONNECTIONS,
	LOST_PROXY_CONNECTIONS
};

int exmdb_client_get_param(int param);

void exmdb_client_init(int conn_num,
	int threads_num, const char *list_path);

int exmdb_client_run();

int exmdb_client_stop();

void exmdb_client_free();

BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid);

BOOL exmdb_client_get_named_propname(const char *dir,
	uint16_t propid, PROPERTY_NAME *ppropname);

BOOL exmdb_client_get_folder_property(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	uint32_t proptag, void **ppval);

BOOL exmdb_client_get_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppval);

BOOL exmdb_client_delete_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t folder_id,
	uint64_t message_id, BOOL b_hard, BOOL *pb_done);

BOOL exmdb_client_get_instance_property(
	const char *dir, uint32_t instance_id,
	uint32_t proptag, void **ppval);

BOOL exmdb_client_set_instance_property(
	const char *dir, uint32_t instance_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult);

BOOL exmdb_client_remove_instance_property(const char *dir,
	uint32_t instance_id, uint32_t proptag, uint32_t *presult);

BOOL exmdb_client_check_message_owner(const char *dir,
	uint64_t message_id, const char *username, BOOL *pb_owner);

BOOL exmdb_client_remove_message_property(const char *dir,
	uint32_t cpid, uint64_t message_id, uint32_t proptag);

BOOL exmdb_client_ping_store(const char *dir);

BOOL exmdb_client_get_all_named_propids(
	const char *dir, PROPID_ARRAY *ppropids);

BOOL exmdb_client_get_named_propids(const char *dir,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);

BOOL exmdb_client_get_named_propnames(const char *dir,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);

BOOL exmdb_client_get_mapping_guid(const char *dir,
	uint16_t replid, BOOL *pb_found, GUID *pguid);

BOOL exmdb_client_get_mapping_replid(const char *dir,
	GUID guid, BOOL *pb_found, uint16_t *preplid);

BOOL exmdb_client_get_store_all_proptags(
	const char *dir, PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_get_store_properties(const char *dir,
	uint32_t cpid, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_client_set_store_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_remove_store_properties(
	const char *dir, const PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_check_mailbox_permission(const char *dir,
	const char *username, uint32_t *ppermission);

BOOL exmdb_client_get_folder_by_class(const char *dir,
	const char *str_class, uint64_t *pid, char *str_explicit);

BOOL exmdb_client_set_folder_by_class(const char *dir,
	uint64_t folder_id, const char *str_class, BOOL *pb_result);

BOOL exmdb_client_get_folder_class_table(
	const char *dir, TARRAY_SET *ptable);

BOOL exmdb_client_check_folder_id(const char *dir,
	uint64_t folder_id, BOOL *pb_exist);

BOOL exmdb_client_check_folder_deleted(const char *dir,
	uint64_t folder_id, BOOL *pb_del);

BOOL exmdb_client_get_folder_by_name(const char *dir,
	uint64_t parent_id, const char *str_name,
	uint64_t *pfolder_id);

BOOL exmdb_client_check_folder_permission(const char *dir,
	uint64_t folder_id, const char *username,
	uint32_t *ppermission);

BOOL exmdb_client_create_folder_by_properties(const char *dir,
	uint32_t cpid, const TPROPVAL_ARRAY *pproperties,
	uint64_t *pfolder_id);

BOOL exmdb_client_get_folder_all_proptags(const char *dir,
	uint64_t folder_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_get_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_client_set_folder_properties(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_remove_folder_properties(const char *dir,
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_delete_folder(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result);

BOOL exmdb_client_empty_folder(const char *dir, uint32_t cpid,
	const char *username, uint64_t folder_id, BOOL b_hard,
	BOOL b_normal, BOOL b_fai, BOOL b_sub, BOOL *pb_partial);

BOOL exmdb_client_check_folder_cycle(const char *dir,
	uint64_t src_fid, uint64_t dst_fid, BOOL *pb_cycle);

BOOL exmdb_client_copy_folder_internal(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_fid, BOOL b_normal, BOOL b_fai, BOOL b_sub,
	uint64_t dst_fid, BOOL *pb_collid, BOOL *pb_partial);

BOOL exmdb_client_get_search_criteria(
	const char *dir, uint64_t folder_id, uint32_t *psearch_status,
	RESTRICTION **pprestriction, LONGLONG_ARRAY *pfolder_ids);

BOOL exmdb_client_set_search_criteria(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint32_t search_flags,
	const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids,
	BOOL *pb_result);

BOOL exmdb_client_movecopy_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t message_id,
	uint64_t dst_fid, uint64_t dst_id, BOOL b_move,
	BOOL *pb_result);

BOOL exmdb_client_movecopy_messages(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest,
	const char *username, uint64_t src_fid, uint64_t dst_fid,
	BOOL b_copy, const EID_ARRAY *pmessage_ids, BOOL *pb_partial);

BOOL exmdb_client_movecopy_folder(const char *dir,
	int account_id, uint32_t cpid, BOOL b_guest, const char *username,
	uint64_t src_pid, uint64_t src_fid, uint64_t dst_fid,
	const char *str_new, BOOL b_copy, BOOL *pb_exist,
	BOOL *pb_partial);

BOOL exmdb_client_delete_messages(const char *dir,
	int account_id, uint32_t cpid, const char *username,
	uint64_t folder_id, const EID_ARRAY *pmessage_ids,
	BOOL b_hard, BOOL *pb_partial);

BOOL exmdb_client_get_message_brief(const char *dir, uint32_t cpid,
	uint64_t message_id, MESSAGE_CONTENT **ppbrief);

BOOL exmdb_client_sum_hierarchy(const char *dir,
	uint64_t folder_id, const char *username,
	BOOL b_depth, uint32_t *pcount);
	
BOOL exmdb_client_load_hierarchy_table(const char *dir,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, uint32_t *ptable_id,
	uint32_t *prow_count);

BOOL exmdb_client_sum_content(const char *dir, uint64_t folder_id,
	BOOL b_fai, BOOL b_deleted, uint32_t *pcount);

BOOL exmdb_client_load_content_table(const char *dir, uint32_t cpid,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL exmdb_client_reload_content_table(const char *dir, uint32_t table_id);

BOOL exmdb_client_load_permission_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL exmdb_client_load_rule_table(const char *dir,
	uint64_t folder_id,  uint8_t table_flags,
	const RESTRICTION *prestriction,
	uint32_t *ptable_id, uint32_t *prow_count);

BOOL exmdb_client_unload_table(const char *dir, uint32_t table_id);

BOOL exmdb_client_sum_table(const char *dir,
	uint32_t table_id, uint32_t *prows);

BOOL exmdb_client_query_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset);

BOOL exmdb_client_match_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, BOOL b_forward, uint32_t start_pos,
	const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_client_locate_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	int32_t *pposition, uint32_t *prow_type);

BOOL exmdb_client_read_table_row(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint64_t inst_id, uint32_t inst_num, TPROPVAL_ARRAY *ppropvals);
	
BOOL exmdb_client_mark_table(const char *dir,
	uint32_t table_id, uint32_t position, uint64_t *pinst_id,
	uint32_t *pinst_num, uint32_t *prow_type);

BOOL exmdb_client_get_table_all_proptags(const char *dir,
	uint32_t table_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_expand_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count);

BOOL exmdb_client_collapse_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count);

BOOL exmdb_client_store_table_state(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	uint32_t *pstate_id);

BOOL exmdb_client_restore_table_state(const char *dir,
	uint32_t table_id, uint32_t state_id, int32_t *pposition);

BOOL exmdb_client_check_message(const char *dir,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_exist);

BOOL exmdb_client_check_message_deleted(const char *dir,
	uint64_t message_id, BOOL *pb_del);

BOOL exmdb_client_load_message_instance(const char *dir,
	const char *username, uint32_t cpid, BOOL b_new,
	uint64_t folder_id, uint64_t message_id,
	uint32_t *pinstance_id);

BOOL exmdb_client_load_embedded_instance(
	const char *dir, BOOL b_new, uint32_t attachment_instance_id,
	uint32_t *pinstance_id);

BOOL exmdb_client_get_embeded_cn(const char *dir,
	uint32_t instance_id, uint64_t **ppcn);

BOOL exmdb_client_reload_message_instance(
	const char *dir, uint32_t instance_id, BOOL *pb_result);

BOOL exmdb_client_clear_message_instance(
	const char *dir, uint32_t instance_id);

BOOL exmdb_client_read_message_instance(const char *dir,
	uint32_t instance_id, MESSAGE_CONTENT *pmsgctnt);

BOOL exmdb_client_write_message_instance(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt,
	BOOL b_force, PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_load_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t attachment_num,
	uint32_t *pinstance_id);

BOOL exmdb_client_create_attachment_instance(const char *dir,
	uint32_t message_instance_id, uint32_t *pinstance_id,
	uint32_t *pattachment_num);

BOOL exmdb_client_read_attachment_instance(const char *dir,
	uint32_t instance_id, ATTACHMENT_CONTENT *pattctnt);

BOOL exmdb_client_write_attachment_instance(const char *dir,
	uint32_t instance_id, const ATTACHMENT_CONTENT *pattctnt,
	BOOL b_force, PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_delete_message_instance_attachment(
	const char *dir, uint32_t message_instance_id,
	uint32_t attachment_num);

BOOL exmdb_client_flush_instance(const char *dir,
	uint32_t instance_id, const char *account, BOOL *pb_result);
	
BOOL exmdb_client_unload_instance(
	const char *dir, uint32_t instance_id);

BOOL exmdb_client_get_instance_all_proptags(
	const char *dir, uint32_t instance_id,
	PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_get_instance_properties(
	const char *dir, uint32_t size_limit, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_client_set_instance_properties(const char *dir,
	uint32_t instance_id, const TPROPVAL_ARRAY *pproperties,
	PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_remove_instance_properties(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_check_instance_cycle(const char *dir,
	uint32_t src_instance_id, uint32_t dst_instance_id, BOOL *pb_cycle);

BOOL exmdb_client_empty_message_instance_rcpts(
	const char *dir, uint32_t instance_id);

BOOL exmdb_client_get_message_instance_rcpts_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum);

BOOL exmdb_client_get_message_instance_rcpts_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_get_message_instance_rcpts(
	const char *dir, uint32_t instance_id, uint32_t row_id,
	uint16_t need_count, TARRAY_SET *pset);

BOOL exmdb_client_update_message_instance_rcpts(
	const char *dir, uint32_t instance_id, const TARRAY_SET *pset);

BOOL exmdb_client_copy_instance_rcpts(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result);

BOOL exmdb_client_empty_message_instance_attachments(
	const char *dir, uint32_t instance_id);

BOOL exmdb_client_get_message_instance_attachments_num(
	const char *dir, uint32_t instance_id, uint16_t *pnum);

BOOL exmdb_client_get_message_instance_attachment_table_all_proptags(
	const char *dir, uint32_t instance_id, PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_query_message_instance_attachment_table(
	const char *dir, uint32_t instance_id,
	const PROPTAG_ARRAY *pproptags, uint32_t start_pos,
	int32_t row_needed, TARRAY_SET *pset);

BOOL exmdb_client_copy_instance_attachments(
	const char *dir, BOOL b_force, uint32_t src_instance_id,
	uint32_t dst_instance_id, BOOL *pb_result);

BOOL exmdb_client_set_message_instance_conflict(const char *dir,
	uint32_t instance_id, const MESSAGE_CONTENT *pmsgctnt);

BOOL exmdb_client_get_message_rcpts(const char *dir,
	uint64_t message_id, TARRAY_SET *pset);

BOOL exmdb_client_get_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL exmdb_client_set_message_properties(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	const TPROPVAL_ARRAY *pproperties, PROBLEM_ARRAY *pproblems);

BOOL exmdb_client_set_message_read_state(const char *dir,
	const char *username, uint64_t message_id,
	uint8_t mark_as_read, uint64_t *pread_cn);

BOOL exmdb_client_remove_message_properties(
	const char *dir, uint32_t cpid, uint64_t message_id,
	const PROPTAG_ARRAY *pproptags);

BOOL exmdb_client_allocate_message_id(const char *dir,
	uint64_t folder_id, uint64_t *pmessage_id);

BOOL exmdb_client_allocate_cn(const char *dir, uint64_t *pcn);

BOOL exmdb_client_get_message_group_id(const char *dir,
	uint64_t message_id, uint32_t **ppgroup_id);

BOOL exmdb_client_set_message_group_id(const char *dir,
	uint64_t message_id, uint32_t group_id);

BOOL exmdb_client_save_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, const INDEX_ARRAY *pindices,
	const PROPTAG_ARRAY *pungroup_proptags);

BOOL exmdb_client_get_change_indices(const char *dir,
	uint64_t message_id, uint64_t cn, INDEX_ARRAY *pindices,
	PROPTAG_ARRAY *pungroup_proptags);

BOOL exmdb_client_mark_modified(const char *dir, uint64_t message_id);

BOOL exmdb_client_try_mark_submit(const char *dir,
	uint64_t message_id, BOOL *pb_marked);

BOOL exmdb_client_clear_submit(const char *dir,
	uint64_t message_id, BOOL b_unsent);

BOOL exmdb_client_link_message(const char *dir, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id, BOOL *pb_result);

BOOL exmdb_client_unlink_message(const char *dir,
	uint32_t cpid, uint64_t folder_id, uint64_t message_id);

BOOL exmdb_client_rule_new_message(const char *dir,
	const char *username, const char *account, uint32_t cpid,
	uint64_t folder_id, uint64_t message_id);

BOOL exmdb_client_set_message_timer(const char *dir,
	uint64_t message_id, uint32_t timer_id);

BOOL exmdb_client_get_message_timer(const char *dir,
	uint64_t message_id, uint32_t **pptimer_id);

BOOL exmdb_client_empty_folder_permission(
	const char *dir, uint64_t folder_id);

BOOL exmdb_client_update_folder_permission(const char *dir,
	uint64_t folder_id, BOOL b_freebusy,
	uint16_t count, const PERMISSION_DATA *prow);

BOOL exmdb_client_empty_folder_rule(
	const char *dir, uint64_t folder_id);

BOOL exmdb_client_update_folder_rule(const char *dir,
	uint64_t folder_id, uint16_t count,
	const RULE_DATA *prow, BOOL *pb_exceed);

BOOL exmdb_client_delivery_message(const char *dir,
	const char *from_address, const char *account,
	uint32_t cpid, const MESSAGE_CONTENT *pmsg,
	const char *pdigest, uint32_t *presult);

BOOL exmdb_client_write_message(const char *dir,
	const char *account, uint32_t cpid, uint64_t folder_id,
	const MESSAGE_CONTENT *pmsgctnt, BOOL *pb_result);

BOOL exmdb_client_read_message(const char *dir, const char *username,
	uint32_t cpid, uint64_t message_id, MESSAGE_CONTENT **ppmsgctnt);

BOOL exmdb_client_get_content_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, const IDSET *pseen_fai, const IDSET *pread,
	uint32_t cpid, const RESTRICTION *prestriction, BOOL b_ordered,
	uint32_t *pfai_count, uint64_t *pfai_total, uint32_t *pnormal_count,
	uint64_t *pnormal_total, EID_ARRAY *pupdated_mids, EID_ARRAY *pchg_mids,
	uint64_t *plast_cn, EID_ARRAY *pgiven_mids, EID_ARRAY *pdeleted_mids,
	EID_ARRAY *pnolonger_mids, EID_ARRAY *pread_mids,
	EID_ARRAY *punread_mids, uint64_t *plast_readcn);

BOOL exmdb_client_get_hierarchy_sync(const char *dir,
	uint64_t folder_id, const char *username, const IDSET *pgiven,
	const IDSET *pseen, FOLDER_CHANGES *pfldchgs, uint64_t *plast_cn,
	EID_ARRAY *pgiven_fids, EID_ARRAY *pdeleted_fids);


BOOL exmdb_client_allocate_ids(const char *dir,
	uint32_t count, uint64_t *pbegin_eid);

BOOL exmdb_client_subscribe_notification(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id);

BOOL exmdb_client_unsubscribe_notification(
	const char *dir, uint32_t sub_id);

BOOL exmdb_client_transport_new_mail(const char *dir,
	uint64_t folder_id, uint64_t message_id, uint32_t message_flags,
	const char *pstr_class);

BOOL exmdb_client_check_contact_address(const char *dir,
	const char *paddress, BOOL *pb_found);

BOOL exmdb_client_get_public_folder_unread_count(const char *dir,
	const char *username, uint64_t folder_id, uint32_t *pcount);

BOOL exmdb_client_unload_store(const char *dir);

void exmdb_client_register_proc(void *pproc);

#endif /* _H_EXMDB_CLIENT_ */
