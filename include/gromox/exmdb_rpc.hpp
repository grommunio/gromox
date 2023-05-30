#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/mapi_types.hpp>

enum class exmdb_response : uint8_t {
	success = 0x00,
	access_deny = 0x01,
	max_reached = 0x02,
	lack_memory = 0x03,
	misconfig_prefix = 0x04,
	misconfig_mode = 0x05,
	connect_incomplete = 0x06,
	pull_error = 0x07,
	dispatch_error = 0x08,
	push_error = 0x09,
	invalid = 0xff,
};

enum class exmdb_callid : uint8_t {
	connect = 0x00,
	listen_notification = 0x01,
	ping_store = 0x02,
	get_all_named_propids = 0x03,
	get_named_propids = 0x04,
	get_named_propnames = 0x05,
	get_mapping_guid = 0x06,
	get_mapping_replid = 0x07,
	get_store_all_proptags = 0x08,
	get_store_properties = 0x09,
	set_store_properties = 0x0a,
	remove_store_properties = 0x0b,
	get_mbox_perm = 0x0c,
	// get_folder_by_class (v1) = 0x0d,
	set_folder_by_class = 0x0e,
	get_folder_class_table = 0x0f,
	check_folder_id = 0x10,
	// query_folder_messages = 0x11,
	check_folder_deleted = 0x12,
	get_folder_by_name = 0x13,
	get_folder_perm = 0x14,
	create_folder_by_properties = 0x15,
	get_folder_all_proptags = 0x16,
	get_folder_properties = 0x17,
	set_folder_properties = 0x18,
	remove_folder_properties = 0x19,
	delete_folder = 0x1a,
	// empty_folder_v1 = 0x1b,
	check_folder_cycle = 0x1c,
	copy_folder_internal = 0x1d,
	get_search_criteria = 0x1e,
	set_search_criteria = 0x1f,
	movecopy_message = 0x20,
	movecopy_messages = 0x21,
	movecopy_folder = 0x22,
	delete_messages = 0x23,
	get_message_brief = 0x24,
	sum_hierarchy = 0x25,
	load_hierarchy_table = 0x26,
	sum_content = 0x27,
	load_content_table = 0x28,
	load_perm_table_v1 = 0x29, // still used by libexmdbpp
	load_rule_table = 0x2a,
	unload_table = 0x2b,
	sum_table = 0x2c,
	query_table = 0x2d,
	match_table = 0x2e,
	locate_table = 0x2f,
	read_table_row = 0x30,
	mark_table = 0x31,
	get_table_all_proptags = 0x32,
	expand_table = 0x33,
	collapse_table = 0x34,
	store_table_state = 0x35,
	restore_table_state = 0x36,
	check_message = 0x37,
	check_message_deleted = 0x38,
	load_message_instance = 0x39,
	load_embedded_instance = 0x3a,
	get_embedded_cn = 0x3b,
	reload_message_instance = 0x3c,
	clear_message_instance = 0x3d,
	read_message_instance = 0x3e,
	// write_message_instance_v1 = 0x3f,
	load_attachment_instance = 0x40,
	create_attachment_instance = 0x41,
	read_attachment_instance = 0x42,
	write_attachment_instance = 0x43,
	delete_message_instance_attachment = 0x44,
	// flush_instance_v1 = 0x45,
	unload_instance = 0x46,
	get_instance_all_proptags = 0x47,
	get_instance_properties = 0x48,
	set_instance_properties = 0x49,
	remove_instance_properties = 0x4a,
	check_instance_cycle = 0x4b,
	empty_message_instance_rcpts = 0x4c,
	get_message_instance_rcpts_num = 0x4d,
	get_message_instance_rcpts_all_proptags = 0x4e,
	get_message_instance_rcpts = 0x4f,
	update_message_instance_rcpts = 0x50,
	empty_message_instance_attachments = 0x51,
	get_message_instance_attachments_num = 0x52,
	get_message_instance_attachment_table_all_proptags = 0x53,
	query_message_instance_attachment_table = 0x54,
	set_message_instance_conflict = 0x55,
	get_message_rcpts = 0x56,
	get_message_properties = 0x57,
	set_message_properties = 0x58,
	set_message_read_state = 0x59,
	remove_message_properties = 0x5a,
	allocate_message_id = 0x5b,
	allocate_cn = 0x5c,
	mark_modified = 0x5d,
	get_message_group_id = 0x5e,
	set_message_group_id = 0x5f,
	save_change_indices = 0x60,
	get_change_indices = 0x61,
	try_mark_submit = 0x62,
	clear_submit = 0x63,
	link_message = 0x64,
	unlink_message = 0x65,
	rule_new_message = 0x66,
	set_message_timer = 0x67,
	get_message_timer = 0x68,
	empty_folder_permission = 0x69,
	update_folder_permission = 0x6a,
	empty_folder_rule = 0x6b,
	update_folder_rule = 0x6c,
	// deliver_message_v1 = 0x6d,
	write_message = 0x6e,
	read_message = 0x6f,
	get_content_sync = 0x70,
	get_hierarchy_sync = 0x71,
	allocate_ids = 0x72,
	subscribe_notification = 0x73,
	unsubscribe_notification = 0x74,
	transport_new_mail = 0x75,
	reload_content_table = 0x76,
	copy_instance_rcpts = 0x77,
	copy_instance_attachments = 0x78,
	check_contact_address = 0x79,
	get_public_folder_unread_count = 0x7a,
	vacuum = 0x7b,
	get_folder_by_class /* v2 */ = 0x7c,
	load_permission_table /* v2 */ = 0x7d,
	write_message_instance /* v2 */ = 0x7e,
	flush_instance /* v2 */ = 0x7f,
	unload_store = 0x80,
	deliver_message = 0x81,
	notify_new_mail = 0x82,
	store_eid_to_user = 0x83,
	empty_folder = 0x84,
	purge_softdelete = 0x85,
	/* update exch/exmdb_provider/names.cpp! */
};

struct exreq {
	exmdb_callid call_id;
	char *dir;
};

struct exreq_connect : public exreq {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct exreq_listen_notification : public exreq {
	char *remote_id;
};

struct exreq_get_named_propids : public exreq {
	BOOL b_create;
	PROPNAME_ARRAY *ppropnames;
};

struct exreq_get_named_propnames : public exreq {
	PROPID_ARRAY *ppropids;
};

struct exreq_get_mapping_guid : public exreq {
	uint16_t replid;
};

struct exreq_get_mapping_replid : public exreq {
	GUID guid;
};

struct exreq_get_store_properties : public exreq {
	cpid_t cpid;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_store_properties : public exreq {
	cpid_t cpid;
	TPROPVAL_ARRAY *ppropvals;
};

struct exreq_remove_store_properties : public exreq {
	PROPTAG_ARRAY *pproptags;
};

struct exreq_get_mbox_perm : public exreq {
	char *username;
};

struct exreq_get_folder_by_class : public exreq {
	char *str_class;
};

struct exreq_set_folder_by_class : public exreq {
	uint64_t folder_id;
	char *str_class;
};

struct exreq_check_folder_id : public exreq {
	uint64_t folder_id;
};

struct exreq_check_folder_deleted : public exreq {
	uint64_t folder_id;
};

struct exreq_get_folder_by_name : public exreq {
	uint64_t parent_id;
	char *str_name;
};

struct exreq_get_folder_perm : public exreq {
	uint64_t folder_id;
	char *username;
};

struct exreq_create_folder_by_properties : public exreq {
	cpid_t cpid;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_delete_folder : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	BOOL b_hard;
};

struct exreq_get_folder_all_proptags : public exreq {
	uint64_t folder_id;
};

struct exreq_get_folder_properties : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_folder_properties : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_remove_folder_properties : public exreq {
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_empty_folder : public exreq {
	cpid_t cpid;
	char *username;
	uint64_t folder_id;
	uint32_t flags;
};

struct exreq_check_folder_cycle : public exreq {
	uint64_t src_fid;
	uint64_t dst_fid;
};

struct exreq_copy_folder_internal : public exreq {
	uint32_t account_id;
	cpid_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_fid;
	BOOL b_normal;
	BOOL b_fai;
	BOOL b_sub;
	uint64_t dst_fid;
};

struct exreq_get_search_criteria : public exreq {
	uint64_t folder_id;
};

struct exreq_set_search_criteria : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	uint32_t search_flags;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY *pfolder_ids;
};

struct exreq_movecopy_message : public exreq {
	uint32_t account_id;
	cpid_t cpid;
	uint64_t message_id;
	uint64_t dst_fid;
	uint64_t dst_id;
	BOOL b_move;
};

struct exreq_movecopy_messages : public exreq {
	uint32_t account_id;
	cpid_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_fid;
	uint64_t dst_fid;
	BOOL b_copy;
	EID_ARRAY *pmessage_ids;
};

struct exreq_movecopy_folder : public exreq {
	uint32_t account_id;
	cpid_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_pid;
	uint64_t src_fid;
	uint64_t dst_fid;
	char *str_new;
	BOOL b_copy;
};

struct exreq_delete_messages : public exreq {
	uint32_t account_id;
	cpid_t cpid;
	char *username;
	uint64_t folder_id;
	EID_ARRAY *pmessage_ids;
	BOOL b_hard;
};

struct exreq_get_message_brief : public exreq {
	cpid_t cpid;
	uint64_t message_id;
};

struct exreq_sum_hierarchy : public exreq {
	uint64_t folder_id;
	char *username;
	BOOL b_depth;
};

struct exreq_sum_content : public exreq {
	uint64_t folder_id;
	BOOL b_fai;
	BOOL b_deleted;
};

struct exreq_load_hierarchy_table : public exreq {
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct exreq_load_content_table : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
	SORTORDER_SET *psorts;
};

struct exreq_reload_content_table : public exreq {
	uint32_t table_id;
};

struct exreq_load_perm_table_v1 : public exreq {
	uint64_t folder_id;
	uint8_t table_flags;
};

struct exreq_load_permission_table : public exreq {
	uint64_t folder_id;
	uint32_t table_flags;
};

struct exreq_load_rule_table : public exreq {
	uint64_t folder_id;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct exreq_unload_table : public exreq {
	uint32_t table_id;
};

struct exreq_sum_table : public exreq {
	uint32_t table_id;
};

struct exreq_query_table : public exreq {
	char *username;
	cpid_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct exreq_match_table : public exreq {
	char *username;
	cpid_t cpid;
	uint32_t table_id;
	BOOL b_forward;
	uint32_t start_pos;
	RESTRICTION *pres;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_locate_table : public exreq {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct exreq_read_table_row : public exreq {
	char *username;
	cpid_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct exreq_mark_table : public exreq {
	uint32_t table_id;
	uint32_t position;
};

struct exreq_get_table_all_proptags : public exreq {
	uint32_t table_id;
};

struct exreq_expand_table : public exreq {
	uint32_t table_id;
	uint64_t inst_id;
};

struct exreq_collapse_table : public exreq {
	uint32_t table_id;
	uint64_t inst_id;
};

struct exreq_store_table_state : public exreq {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct exreq_restore_table_state : public exreq {
	uint32_t table_id;
	uint32_t state_id;
};

struct exreq_check_message : public exreq {
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_check_message_deleted : public exreq {
	uint64_t message_id;
};

struct exreq_load_message_instance : public exreq {
	char *username;
	cpid_t cpid;
	BOOL b_new;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_load_embedded_instance : public exreq {
	BOOL b_new;
	uint32_t attachment_instance_id;
};

struct exreq_get_embedded_cn : public exreq {
	uint32_t instance_id;
};

struct exreq_reload_message_instance : public exreq {
	uint32_t instance_id;
};

struct exreq_clear_message_instance : public exreq {
	uint32_t instance_id;
};

struct exreq_read_message_instance : public exreq {
	uint32_t instance_id;
};

struct exreq_write_message_instance : public exreq {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
	BOOL b_force;
};

struct exreq_load_attachment_instance : public exreq {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct exreq_create_attachment_instance : public exreq {
	uint32_t message_instance_id;
};

struct exreq_read_attachment_instance : public exreq {
	uint32_t instance_id;
};

struct exreq_write_attachment_instance : public exreq {
	uint32_t instance_id;
	ATTACHMENT_CONTENT *pattctnt;
	BOOL b_force;
};

struct exreq_delete_message_instance_attachment : public exreq {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct exreq_flush_instance : public exreq {
	uint32_t instance_id;
	char *account;
};

struct exreq_unload_instance : public exreq {
	uint32_t instance_id;
};

struct exreq_get_instance_all_proptags : public exreq {
	uint32_t instance_id;
};

struct exreq_get_instance_properties : public exreq {
	uint32_t size_limit;
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_instance_properties : public exreq {
	uint32_t instance_id;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_remove_instance_properties : public exreq {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_check_instance_cycle : public exreq {
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct exreq_empty_message_instance_rcpts : public exreq {
	uint32_t instance_id;
};

struct exreq_get_message_instance_rcpts_num : public exreq {
	uint32_t instance_id;
};

struct exreq_get_message_instance_rcpts_all_proptags : public exreq {
	uint32_t instance_id;
};

struct exreq_get_message_instance_rcpts : public exreq {
	uint32_t instance_id;
	uint32_t row_id;
	uint16_t need_count;
};

struct exreq_update_message_instance_rcpts : public exreq {
	uint32_t instance_id;
	TARRAY_SET *pset;
};

struct exreq_copy_instance_rcpts : public exreq {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct exreq_empty_message_instance_attachments : public exreq {
	uint32_t instance_id;
};

struct exreq_get_message_instance_attachments_num : public exreq {
	uint32_t instance_id;
};

struct exreq_get_message_instance_attachment_table_all_proptags : public exreq {
	uint32_t instance_id;
};

struct exreq_query_message_instance_attachment_table : public exreq {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct exreq_copy_instance_attachments : public exreq {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct exreq_set_message_instance_conflict : public exreq {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct exreq_get_message_rcpts : public exreq {
	uint64_t message_id;
};

struct exreq_get_message_properties : public exreq {
	char *username;
	cpid_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_message_properties : public exreq {
	char *username;
	cpid_t cpid;
	uint64_t message_id;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_set_message_read_state : public exreq {
	char *username;
	uint64_t message_id;
	uint8_t mark_as_read;
};

struct exreq_remove_message_properties : public exreq {
	cpid_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_allocate_message_id : public exreq {
	uint64_t folder_id;
};

struct exreq_get_message_group_id : public exreq {
	uint64_t message_id;
};

struct exreq_set_message_group_id : public exreq {
	uint64_t message_id;
	uint32_t group_id;
};

struct exreq_save_change_indices : public exreq {
	uint64_t message_id;
	uint64_t cn;
	INDEX_ARRAY *pindices;
	PROPTAG_ARRAY *pungroup_proptags;
};

struct exreq_get_change_indices : public exreq {
	uint64_t message_id;
	uint64_t cn;
};

struct exreq_mark_modified : public exreq {
	uint64_t message_id;
};

struct exreq_try_mark_submit : public exreq {
	uint64_t message_id;
};

struct exreq_clear_submit : public exreq {
	uint64_t message_id;
	BOOL b_unsent;
};

struct exreq_link_message : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_unlink_message : public exreq {
	cpid_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_rule_new_message : public exreq {
	char *username;
	char *account;
	cpid_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_set_message_timer : public exreq {
	uint64_t message_id;
	uint32_t timer_id;
};

struct exreq_get_message_timer : public exreq {
	uint64_t message_id;
};

struct exreq_empty_folder_permission : public exreq {
	uint64_t folder_id;
};

struct exreq_update_folder_permission : public exreq {
	uint64_t folder_id;
	BOOL b_freebusy;
	uint16_t count;
	PERMISSION_DATA *prow;
};

struct exreq_empty_folder_rule : public exreq {
	uint64_t folder_id;
};

struct exreq_update_folder_rule : public exreq {
	uint64_t folder_id;
	uint16_t count;
	RULE_DATA *prow;
};

enum delivery_flags {
	DELIVERY_DO_RULES = 0x1U,
	DELIVERY_DO_NOTIF = 0x2U,
};

struct exreq_deliver_message : public exreq {
	char *from_address;
	char *account;
	cpid_t cpid;
	uint32_t dlflags;
	MESSAGE_CONTENT *pmsg;
	char *pdigest;
};

struct exreq_write_message : public exreq {
	char *account;
	cpid_t cpid;
	uint64_t folder_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct exreq_read_message : public exreq {
	char *username;
	cpid_t cpid;
	uint64_t message_id;
};

struct exreq_get_content_sync : public exreq {
	uint64_t folder_id;
	char *username;
	IDSET *pgiven;
	IDSET *pseen;
	IDSET *pseen_fai;
	IDSET *pread;
	cpid_t cpid;
	RESTRICTION *prestriction;
	BOOL b_ordered;
};

struct exreq_get_hierarchy_sync : public exreq {
	uint64_t folder_id;
	char *username;
	IDSET *pgiven;
	IDSET *pseen;
};

struct exreq_allocate_ids : public exreq {
	uint32_t count;
};

struct exreq_subscribe_notification : public exreq {
	uint16_t notification_type;
	BOOL b_whole;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_unsubscribe_notification : public exreq {
	uint32_t sub_id;
};

struct exreq_transport_new_mail : public exreq {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	char *pstr_class;
};

struct exreq_check_contact_address : public exreq {
	char *paddress;
};

struct exreq_get_public_folder_unread_count : public exreq {
	char *username;
	uint64_t folder_id;
};

struct exreq_notify_new_mail : public exreq {
	uint64_t folder_id, message_id;
};

struct exreq_store_eid_to_user : public exreq {
	STORE_ENTRYID *store_eid;
};

struct exreq_purge_softdelete : public exreq {
	char *username;
	uint64_t folder_id = 0;
	uint32_t del_flags = 0;
	mapitime_t cutoff = 0;
};

struct exresp {
	exmdb_callid call_id;
};

struct exresp_get_all_named_propids : public exresp {
	PROPID_ARRAY propids;
};

struct exresp_get_named_propids : public exresp {
	PROPID_ARRAY propids;
};

struct exresp_get_named_propnames : public exresp {
	PROPNAME_ARRAY propnames;
};

struct exresp_get_mapping_guid : public exresp {
	BOOL b_found;
	GUID guid;
};

struct exresp_get_mapping_replid : public exresp {
	BOOL b_found;
	uint16_t replid;
};

struct exresp_get_store_all_proptags : public exresp {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_store_properties : public exresp {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_store_properties : public exresp {
	PROBLEM_ARRAY problems;
};

struct exresp_get_mbox_perm : public exresp {
	uint32_t permission;
};

struct exresp_get_folder_by_class : public exresp {
	uint64_t id;
	char *str_explicit;
};

struct exresp_set_folder_by_class : public exresp {
	BOOL b_result;
};

struct exresp_get_folder_class_table : public exresp {
	TARRAY_SET table;
};

struct exresp_check_folder_id : public exresp {
	BOOL b_exist;
};

struct exresp_check_folder_deleted : public exresp {
	BOOL b_del;
};

struct exresp_get_folder_by_name : public exresp {
	uint64_t folder_id;
};

struct exresp_get_folder_perm : public exresp {
	uint32_t permission;
};

struct exresp_create_folder_by_properties : public exresp {
	uint64_t folder_id;
};

struct exresp_get_folder_all_proptags : public exresp {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_folder_properties : public exresp {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_folder_properties : public exresp {
	PROBLEM_ARRAY problems;
};

struct exresp_delete_folder : public exresp {
	BOOL b_result;
};

struct exresp_empty_folder : public exresp {
	BOOL b_partial;
};

struct exresp_check_folder_cycle : public exresp {
	BOOL b_cycle;
};

struct exresp_copy_folder_internal : public exresp {
	BOOL b_collid;
	BOOL b_partial;
};

struct exresp_get_search_criteria : public exresp {
	uint32_t search_status;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
};

struct exresp_set_search_criteria : public exresp {
	BOOL b_result;
};

struct exresp_movecopy_message : public exresp {
	BOOL b_result;
};

struct exresp_movecopy_messages : public exresp {
	BOOL b_partial;
};

struct exresp_movecopy_folder : public exresp {
	BOOL b_exist;
	BOOL b_partial;
};

struct exresp_delete_messages : public exresp {
	BOOL b_partial;
};

struct exresp_get_message_brief : public exresp {
	MESSAGE_CONTENT *pbrief;
};

struct exresp_sum_hierarchy : public exresp {
	uint32_t count;
};

struct exresp_load_hierarchy_table : public exresp {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_sum_content : public exresp {
	uint32_t count;
};

struct exresp_load_content_table : public exresp {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_load_permission_table : public exresp {
	uint32_t table_id;
	uint32_t row_count;
};
using exresp_load_perm_table_v1 = exresp_load_permission_table;

struct exresp_load_rule_table : public exresp {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_sum_table : public exresp {
	uint32_t rows;
};

struct exresp_query_table : public exresp {
	TARRAY_SET set;
};

struct exresp_match_table : public exresp {
	int32_t position;
	TPROPVAL_ARRAY propvals;
};

struct exresp_locate_table : public exresp {
	int32_t position;
	uint32_t row_type;
};

struct exresp_read_table_row : public exresp {
	TPROPVAL_ARRAY propvals;
};

struct exresp_mark_table : public exresp {
	uint64_t inst_id;
	uint32_t inst_num;
	uint32_t row_type;
};

struct exresp_get_table_all_proptags : public exresp {
	PROPTAG_ARRAY proptags;
};

struct exresp_expand_table : public exresp {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct exresp_collapse_table : public exresp {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct exresp_store_table_state : public exresp {
	uint32_t state_id;
};

struct exresp_restore_table_state : public exresp {
	int32_t position;
};

struct exresp_check_message : public exresp {
	BOOL b_exist;
};

struct exresp_check_message_deleted : public exresp {
	BOOL b_del;
};

struct exresp_load_message_instance : public exresp {
	uint32_t instance_id;
};

struct exresp_load_embedded_instance : public exresp {
	uint32_t instance_id;
};

struct exresp_get_embedded_cn : public exresp {
	uint64_t *pcn;
};

struct exresp_reload_message_instance : public exresp {
	BOOL b_result;
};

struct exresp_read_message_instance : public exresp {
	MESSAGE_CONTENT msgctnt;
};

struct exresp_write_message_instance : public exresp {
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
};

struct exresp_load_attachment_instance : public exresp {
	uint32_t instance_id;
};

struct exresp_create_attachment_instance : public exresp {
	uint32_t instance_id;
	uint32_t attachment_num;
};

struct exresp_read_attachment_instance : public exresp {
	ATTACHMENT_CONTENT attctnt;
};

struct exresp_write_attachment_instance : public exresp {
	PROBLEM_ARRAY problems;
};

struct exresp_flush_instance : public exresp {
	ec_error_t e_result;
};

struct exresp_get_instance_all_proptags : public exresp {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_instance_properties : public exresp {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_instance_properties : public exresp {
	PROBLEM_ARRAY problems;
};

struct exresp_remove_instance_properties : public exresp {
	PROBLEM_ARRAY problems;
};

struct exresp_check_instance_cycle : public exresp {
	BOOL b_cycle;
};

struct exresp_get_message_instance_rcpts_num : public exresp {
	uint16_t num;
};

struct exresp_get_message_instance_rcpts_all_proptags : public exresp {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_message_instance_rcpts : public exresp {
	TARRAY_SET set;
};

struct exresp_copy_instance_rcpts : public exresp {
	BOOL b_result;
};

struct exresp_get_message_instance_attachments_num : public exresp {
	uint16_t num;
};

struct exresp_get_message_instance_attachment_table_all_proptags : public exresp {
	PROPTAG_ARRAY proptags;
};

struct exresp_query_message_instance_attachment_table : public exresp {
	TARRAY_SET set;
};

struct exresp_copy_instance_attachments : public exresp {
	BOOL b_result;
};

struct exresp_get_message_rcpts : public exresp {
	TARRAY_SET set;
};

struct exresp_get_message_properties : public exresp {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_message_properties : public exresp {
	PROBLEM_ARRAY problems;
};

struct exresp_set_message_read_state : public exresp {
	uint64_t read_cn;
};

struct exresp_allocate_message_id : public exresp {
	uint64_t message_id;
};

struct exresp_allocate_cn : public exresp {
	uint64_t cn;
};

struct exresp_get_message_group_id : public exresp {
	uint32_t *pgroup_id;
};

struct exresp_get_change_indices : public exresp {
	INDEX_ARRAY indices;
	PROPTAG_ARRAY ungroup_proptags;
};

struct exresp_try_mark_submit : public exresp {
	BOOL b_marked;
};

struct exresp_link_message : public exresp {
	BOOL b_result;
};

struct exresp_get_message_timer : public exresp {
	uint32_t *ptimer_id;
};

struct exresp_update_folder_rule : public exresp {
	BOOL b_exceed;
};

enum deliver_message_result {
	result_ok = 0,
	/* mailbox_full (unused) = 1, */
	result_error = 2,
	mailbox_full_bysize = 3,
	mailbox_full_bymsg = 4,
};

struct exresp_deliver_message : public exresp {
	uint64_t folder_id, message_id;
	uint32_t result;
};

struct exresp_write_message : public exresp {
	ec_error_t e_result;
};

struct exresp_read_message : public exresp {
	MESSAGE_CONTENT *pmsgctnt;
};

struct exresp_get_content_sync : public exresp {
	uint32_t fai_count;
	uint64_t fai_total;
	uint32_t normal_count;
	uint64_t normal_total;
	EID_ARRAY updated_mids;
	EID_ARRAY chg_mids;
	uint64_t last_cn;
	EID_ARRAY given_mids;
	EID_ARRAY deleted_mids;
	EID_ARRAY nolonger_mids;
	EID_ARRAY read_mids;
	EID_ARRAY unread_mids;
	uint64_t last_readcn;
};

struct exresp_get_hierarchy_sync : public exresp {
	FOLDER_CHANGES fldchgs;
	uint64_t last_cn;
	EID_ARRAY given_fids;
	EID_ARRAY deleted_fids;
};

struct exresp_allocate_ids : public exresp {
	uint64_t begin_eid;
};

struct exresp_subscribe_notification : public exresp {
	uint32_t sub_id;
};

struct exresp_check_contact_address : public exresp {
	BOOL b_found;
};

struct exresp_get_public_folder_unread_count : public exresp {
	uint32_t count;
};

struct exresp_store_eid_to_user : public exresp {
	char *maildir = nullptr;
	unsigned int user_id = 0, domain_id = 0;
};

using exreq_ping_store = exreq;
using exreq_get_all_named_propids = exreq;
using exreq_get_store_all_proptags = exreq;
using exreq_get_folder_class_table = exreq;
using exreq_allocate_cn = exreq;
using exreq_vacuum = exreq;
using exreq_unload_store = exreq;
using exresp_remove_folder_properties = exresp;
using exresp_reload_content_table = exresp;
using exresp_unload_table = exresp;
using exresp_clear_message_instance = exresp;
using exresp_delete_message_instance_attachment = exresp;
using exresp_unload_instance = exresp;
using exresp_empty_message_instance_rcpts = exresp;
using exresp_update_message_instance_rcpts = exresp;
using exresp_empty_message_instance_attachments = exresp;
using exresp_set_message_instance_conflict = exresp;
using exresp_remove_message_properties = exresp;
using exresp_set_message_group_id = exresp;
using exresp_save_change_indices = exresp;
using exresp_remove_store_properties = exresp;
using exresp_mark_modified = exresp;
using exresp_clear_submit = exresp;
using exresp_unlink_message = exresp;
using exresp_rule_new_message = exresp;
using exresp_set_message_timer = exresp;
using exresp_empty_folder_permission = exresp;
using exresp_update_folder_permission = exresp;
using exresp_empty_folder_rule = exresp;
using exresp_unsubscribe_notification = exresp;
using exresp_transport_new_mail = exresp;
using exresp_vacuum = exresp;
using exresp_unload_store = exresp;
using exresp_ping_store = exresp;
using exresp_notify_new_mail = exresp;
using exresp_purge_softdelete = exresp;

struct DB_NOTIFY_DATAGRAM {
	char *dir = nullptr;
	BOOL b_table = false;
	LONG_ARRAY id_array{};
	DB_NOTIFY db_notify{};
};

extern GX_EXPORT pack_result exmdb_ext_pull_request(const BINARY *, exreq *&);
extern GX_EXPORT pack_result exmdb_ext_push_request(const exreq *, BINARY *);
extern GX_EXPORT pack_result exmdb_ext_pull_response(const BINARY *, exresp *);
extern GX_EXPORT pack_result exmdb_ext_push_response(const exresp *presponse, BINARY *);
extern GX_EXPORT pack_result exmdb_ext_pull_db_notify(const BINARY *, DB_NOTIFY_DATAGRAM *);
extern GX_EXPORT pack_result exmdb_ext_push_db_notify(const DB_NOTIFY_DATAGRAM *, BINARY *);
extern GX_EXPORT const char *exmdb_rpc_strerror(exmdb_response);
extern GX_EXPORT BOOL exmdb_client_read_socket(int, BINARY &, long timeout = -1);
extern GX_EXPORT BOOL exmdb_client_write_socket(int, const BINARY &, long timeout = -1);
extern GX_EXPORT ec_error_t exmdb_local_rules_execute(const char *dir, const char *from, const char *to, eid_t fid, eid_t mid);

extern GX_EXPORT void *(*exmdb_rpc_alloc)(size_t);
extern GX_EXPORT void (*exmdb_rpc_free)(void *);

namespace exmdb_client_remote {
#define IDLOUT
#define EXMIDL(n, p) extern GX_EXPORT BOOL n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
}
