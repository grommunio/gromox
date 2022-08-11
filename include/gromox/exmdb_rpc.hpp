#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
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
	check_mailbox_permission = 0x0c,
	// get_folder_by_class (v1) = 0x0d,
	set_folder_by_class = 0x0e,
	get_folder_class_table = 0x0f,
	check_folder_id = 0x10,
	query_folder_messages = 0x11,
	check_folder_deleted = 0x12,
	get_folder_by_name = 0x13,
	check_folder_permission = 0x14,
	create_folder_by_properties = 0x15,
	get_folder_all_proptags = 0x16,
	get_folder_properties = 0x17,
	set_folder_properties = 0x18,
	remove_folder_properties = 0x19,
	delete_folder = 0x1a,
	empty_folder = 0x1b,
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
	load_permission_table = 0x29,
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
	write_message_instance = 0x3f,
	load_attachment_instance = 0x40,
	create_attachment_instance = 0x41,
	read_attachment_instance = 0x42,
	write_attachment_instance = 0x43,
	delete_message_instance_attachment = 0x44,
	flush_instance = 0x45,
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
	delivery_message = 0x6d,
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
	unload_store = 0x80,
};

struct exreq_connect {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct exreq_listen_notification {
	char *remote_id;
};

struct exreq_get_named_propids {
	BOOL b_create;
	PROPNAME_ARRAY *ppropnames;
};

struct exreq_get_named_propnames {
	PROPID_ARRAY *ppropids;
};

struct exreq_get_mapping_guid {
	uint16_t replid;
};

struct exreq_get_mapping_replid {
	GUID guid;
};

struct exreq_get_store_properties {
	uint32_t cpid;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_store_properties {
	uint32_t cpid;
	TPROPVAL_ARRAY *ppropvals;
};

struct exreq_remove_store_properties {
	PROPTAG_ARRAY *pproptags;
};

struct exreq_check_mailbox_permission {
	char *username;
};

struct exreq_get_folder_by_class {
	char *str_class;
};

struct exreq_set_folder_by_class {
	uint64_t folder_id;
	char *str_class;
};

struct exreq_check_folder_id {
	uint64_t folder_id;
};

struct exreq_query_folder_messages {
	uint64_t folder_id;
};

struct exreq_check_folder_deleted {
	uint64_t folder_id;
};

struct exreq_get_folder_by_name {
	uint64_t parent_id;
	char *str_name;
};

struct exreq_check_folder_permission {
	uint64_t folder_id;
	char *username;
};

struct exreq_create_folder_by_properties {
	uint32_t cpid;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_delete_folder {
	uint32_t cpid;
	uint64_t folder_id;
	BOOL b_hard;
};

struct exreq_get_folder_all_proptags {
	uint64_t folder_id;
};

struct exreq_get_folder_properties {
	uint32_t cpid;
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_folder_properties {
	uint32_t cpid;
	uint64_t folder_id;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_remove_folder_properties {
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_empty_folder {
	uint32_t cpid;
	char *username;
	uint64_t folder_id;
	BOOL b_hard;
	BOOL b_normal;
	BOOL b_fai;
	BOOL b_sub;
};

struct exreq_check_folder_cycle {
	uint64_t src_fid;
	uint64_t dst_fid;
};

struct exreq_copy_folder_internal {
	uint32_t account_id;
	uint32_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_fid;
	BOOL b_normal;
	BOOL b_fai;
	BOOL b_sub;
	uint64_t dst_fid;
};

struct exreq_get_search_criteria {
	uint64_t folder_id;
};

struct exreq_set_search_criteria {
	uint32_t cpid;
	uint64_t folder_id;
	uint32_t search_flags;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY *pfolder_ids;
};

struct exreq_movecopy_message {
	uint32_t account_id;
	uint32_t cpid;
	uint64_t message_id;
	uint64_t dst_fid;
	uint64_t dst_id;
	BOOL b_move;
};

struct exreq_movecopy_messages {
	uint32_t account_id;
	uint32_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_fid;
	uint64_t dst_fid;
	BOOL b_copy;
	EID_ARRAY *pmessage_ids;
};

struct exreq_movecopy_folder {
	uint32_t account_id;
	uint32_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_pid;
	uint64_t src_fid;
	uint64_t dst_fid;
	char *str_new;
	BOOL b_copy;
};

struct exreq_delete_messages {
	uint32_t account_id;
	uint32_t cpid;
	char *username;
	uint64_t folder_id;
	EID_ARRAY *pmessage_ids;
	BOOL b_hard;
};

struct exreq_get_message_brief {
	uint32_t cpid;
	uint64_t message_id;
};

struct exreq_sum_hierarchy {
	uint64_t folder_id;
	char *username;
	BOOL b_depth;
};

struct exreq_sum_content {
	uint64_t folder_id;
	BOOL b_fai;
	BOOL b_deleted;
};

struct exreq_load_hierarchy_table {
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct exreq_load_content_table {
	uint32_t cpid;
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
	SORTORDER_SET *psorts;
};

struct exreq_reload_content_table {
	uint32_t table_id;
};

struct exreq_load_permission_table {
	uint64_t folder_id;
	uint8_t table_flags;
};

struct exreq_load_rule_table {
	uint64_t folder_id;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct exreq_unload_table {
	uint32_t table_id;
};

struct exreq_sum_table {
	uint32_t table_id;
};

struct exreq_query_table {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct exreq_match_table {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	BOOL b_forward;
	uint32_t start_pos;
	RESTRICTION *pres;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_locate_table {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct exreq_read_table_row {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct exreq_mark_table {
	uint32_t table_id;
	uint32_t position;
};

struct exreq_get_table_all_proptags {
	uint32_t table_id;
};

struct exreq_expand_table {
	uint32_t table_id;
	uint64_t inst_id;
};

struct exreq_collapse_table {
	uint32_t table_id;
	uint64_t inst_id;
};

struct exreq_store_table_state {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct exreq_restore_table_state {
	uint32_t table_id;
	uint32_t state_id;
};

struct exreq_check_message {
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_check_message_deleted {
	uint64_t message_id;
};

struct exreq_load_message_instance {
	char *username;
	uint32_t cpid;
	BOOL b_new;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_load_embedded_instance {
	BOOL b_new;
	uint32_t attachment_instance_id;
};

struct exreq_get_embedded_cn {
	uint32_t instance_id;
};

struct exreq_reload_message_instance {
	uint32_t instance_id;
};

struct exreq_clear_message_instance {
	uint32_t instance_id;
};

struct exreq_read_message_instance {
	uint32_t instance_id;
};

struct exreq_write_message_instance {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
	BOOL b_force;
};

struct exreq_load_attachment_instance {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct exreq_create_attachment_instance {
	uint32_t message_instance_id;
};

struct exreq_read_attachment_instance {
	uint32_t instance_id;
};

struct exreq_write_attachment_instance {
	uint32_t instance_id;
	ATTACHMENT_CONTENT *pattctnt;
	BOOL b_force;
};

struct exreq_delete_message_instance_attachment {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct exreq_flush_instance {
	uint32_t instance_id;
	char *account;
};

struct exreq_unload_instance {
	uint32_t instance_id;
};

struct exreq_get_instance_all_proptags {
	uint32_t instance_id;
};

struct exreq_get_instance_properties {
	uint32_t size_limit;
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_instance_properties {
	uint32_t instance_id;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_remove_instance_properties {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_check_instance_cycle {
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct exreq_empty_message_instance_rcpts {
	uint32_t instance_id;
};

struct exreq_get_message_instance_rcpts_num {
	uint32_t instance_id;
};

struct exreq_get_message_instance_rcpts_all_proptags {
	uint32_t instance_id;
};

struct exreq_get_message_instance_rcpts {
	uint32_t instance_id;
	uint32_t row_id;
	uint16_t need_count;
};

struct exreq_update_message_instance_rcpts {
	uint32_t instance_id;
	TARRAY_SET *pset;
};

struct exreq_copy_instance_rcpts {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct exreq_empty_message_instance_attachments {
	uint32_t instance_id;
};

struct exreq_get_message_instance_attachments_num {
	uint32_t instance_id;
};

struct exreq_get_message_instance_attachment_table_all_proptags {
	uint32_t instance_id;
};

struct exreq_query_message_instance_attachment_table {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct exreq_copy_instance_attachments {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct exreq_set_message_instance_conflict {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct exreq_get_message_rcpts {
	uint64_t message_id;
};

struct exreq_get_message_properties {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_set_message_properties {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
	TPROPVAL_ARRAY *pproperties;
};

struct exreq_set_message_read_state {
	char *username;
	uint64_t message_id;
	uint8_t mark_as_read;
};

struct exreq_remove_message_properties {
	uint32_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct exreq_allocate_message_id {
	uint64_t folder_id;
};

struct exreq_get_message_group_id {
	uint64_t message_id;
};

struct exreq_set_message_group_id {
	uint64_t message_id;
	uint32_t group_id;
};

struct exreq_save_change_indices {
	uint64_t message_id;
	uint64_t cn;
	INDEX_ARRAY *pindices;
	PROPTAG_ARRAY *pungroup_proptags;
};

struct exreq_get_change_indices {
	uint64_t message_id;
	uint64_t cn;
};

struct exreq_mark_modified {
	uint64_t message_id;
};

struct exreq_try_mark_submit {
	uint64_t message_id;
};

struct exreq_clear_submit {
	uint64_t message_id;
	BOOL b_unsent;
};

struct exreq_link_message {
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_unlink_message {
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_rule_new_message {
	char *username;
	char *account;
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_set_message_timer {
	uint64_t message_id;
	uint32_t timer_id;
};

struct exreq_get_message_timer {
	uint64_t message_id;
};

struct exreq_empty_folder_permission {
	uint64_t folder_id;
};

struct exreq_update_folder_permission {
	uint64_t folder_id;
	BOOL b_freebusy;
	uint16_t count;
	PERMISSION_DATA *prow;
};

struct exreq_empty_folder_rule {
	uint64_t folder_id;
};

struct exreq_update_folder_rule {
	uint64_t folder_id;
	uint16_t count;
	RULE_DATA *prow;
};

struct exreq_delivery_message {
	char *from_address;
	char *account;
	uint32_t cpid;
	MESSAGE_CONTENT *pmsg;
	char *pdigest;
};

struct exreq_write_message {
	char *account;
	uint32_t cpid;
	uint64_t folder_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct exreq_read_message {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
};

struct exreq_get_content_sync {
	uint64_t folder_id;
	char *username;
	IDSET *pgiven;
	IDSET *pseen;
	IDSET *pseen_fai;
	IDSET *pread;
	uint32_t cpid;
	RESTRICTION *prestriction;
	BOOL b_ordered;
};

struct exreq_get_hierarchy_sync {
	uint64_t folder_id;
	char *username;
	IDSET *pgiven;
	IDSET *pseen;
};

struct exreq_allocate_ids {
	uint32_t count;
};

struct exreq_subscribe_notification {
	uint16_t notificaton_type;
	BOOL b_whole;
	uint64_t folder_id;
	uint64_t message_id;
};

struct exreq_unsubscribe_notification {
	uint32_t sub_id;
};

struct exreq_transport_new_mail {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	char *pstr_class;
};

struct exreq_check_contact_address {
	char *paddress;
};

struct exreq_get_public_folder_unread_count {
	char *username;
	uint64_t folder_id;
};

union EXMDB_REQUEST_PAYLOAD {
	exreq_connect connect;
	exreq_get_named_propids get_named_propids;
	exreq_get_named_propnames get_named_propnames;
	exreq_get_mapping_guid get_mapping_guid;
	exreq_get_mapping_replid get_mapping_replid;
	exreq_listen_notification	listen_notification;
	exreq_get_store_properties get_store_properties;
	exreq_set_store_properties set_store_properties;
	exreq_remove_store_properties remove_store_properties;
	exreq_check_mailbox_permission check_mailbox_permission;
	exreq_get_folder_by_class get_folder_by_class;
	exreq_set_folder_by_class set_folder_by_class;
	exreq_check_folder_id check_folder_id;
	exreq_query_folder_messages query_folder_messages;
	exreq_check_folder_deleted check_folder_deleted;
	exreq_get_folder_by_name get_folder_by_name;
	exreq_check_folder_permission check_folder_permission;
	exreq_create_folder_by_properties create_folder_by_properties;
	exreq_get_folder_all_proptags get_folder_all_proptags;
	exreq_get_folder_properties get_folder_properties;
	exreq_set_folder_properties set_folder_properties;
	exreq_remove_folder_properties remove_folder_properties;
	exreq_delete_folder delete_folder;
	exreq_empty_folder empty_folder;
	exreq_check_folder_cycle check_folder_cycle;
	exreq_copy_folder_internal copy_folder_internal;
	exreq_get_search_criteria get_search_criteria;
	exreq_set_search_criteria set_search_criteria;
	exreq_movecopy_message movecopy_message;
	exreq_movecopy_messages movecopy_messages;
	exreq_movecopy_folder movecopy_folder;
	exreq_delete_messages delete_messages;
	exreq_get_message_brief get_message_brief;
	exreq_sum_hierarchy sum_hierarchy;
	exreq_load_hierarchy_table load_hierarchy_table;
	exreq_sum_content sum_content;
	exreq_load_content_table load_content_table;
	exreq_reload_content_table reload_content_table;
	exreq_load_permission_table load_permission_table;
	exreq_load_rule_table load_rule_table;
	exreq_unload_table unload_table;
	exreq_sum_table sum_table;
	exreq_query_table query_table;
	exreq_match_table match_table;
	exreq_locate_table locate_table;
	exreq_read_table_row read_table_row;
	exreq_mark_table mark_table;
	exreq_get_table_all_proptags get_table_all_proptags;
	exreq_expand_table expand_table;
	exreq_collapse_table collapse_table;
	exreq_store_table_state store_table_state;
	exreq_restore_table_state restore_table_state;
	exreq_check_message check_message;
	exreq_check_message_deleted check_message_deleted;
	exreq_load_message_instance load_message_instance;
	exreq_load_embedded_instance load_embedded_instance;
	exreq_get_embedded_cn get_embedded_cn;
	exreq_reload_message_instance reload_message_instance;
	exreq_clear_message_instance clear_message_instance;
	exreq_read_message_instance read_message_instance;
	exreq_write_message_instance write_message_instance;
	exreq_load_attachment_instance load_attachment_instance;
	exreq_create_attachment_instance create_attachment_instance;
	exreq_read_attachment_instance read_attachment_instance;
	exreq_write_attachment_instance write_attachment_instance;
	exreq_delete_message_instance_attachment delete_message_instance_attachment;
	exreq_flush_instance flush_instance;
	exreq_unload_instance unload_instance;
	exreq_get_instance_all_proptags get_instance_all_proptags;
	exreq_get_instance_properties get_instance_properties;
	exreq_set_instance_properties set_instance_properties;
	exreq_remove_instance_properties remove_instance_properties;
	exreq_check_instance_cycle check_instance_cycle;
	exreq_empty_message_instance_rcpts empty_message_instance_rcpts;
	exreq_get_message_instance_rcpts_num get_message_instance_rcpts_num;
	exreq_get_message_instance_rcpts_all_proptags get_message_instance_rcpts_all_proptags;
	exreq_get_message_instance_rcpts get_message_instance_rcpts;
	exreq_update_message_instance_rcpts update_message_instance_rcpts;
	exreq_copy_instance_rcpts copy_instance_rcpts;
	exreq_empty_message_instance_attachments empty_message_instance_attachments;
	exreq_get_message_instance_attachments_num get_message_instance_attachments_num;
	exreq_get_message_instance_attachment_table_all_proptags get_message_instance_attachment_table_all_proptags;
	exreq_query_message_instance_attachment_table query_message_instance_attachment_table;
	exreq_copy_instance_attachments copy_instance_attachments;
	exreq_set_message_instance_conflict set_message_instance_conflict;
	exreq_get_message_rcpts get_message_rcpts;
	exreq_get_message_properties get_message_properties;
	exreq_set_message_properties set_message_properties;
	exreq_set_message_read_state set_message_read_state;
	exreq_remove_message_properties remove_message_properties;
	exreq_allocate_message_id allocate_message_id;
	exreq_get_message_group_id get_message_group_id;
	exreq_set_message_group_id set_message_group_id;
	exreq_save_change_indices save_change_indices;
	exreq_get_change_indices get_change_indices;
	exreq_mark_modified mark_modified;
	exreq_try_mark_submit try_mark_submit;
	exreq_clear_submit clear_submit;
	exreq_link_message link_message;
	exreq_unlink_message unlink_message;
	exreq_rule_new_message rule_new_message;
	exreq_set_message_timer set_message_timer;
	exreq_get_message_timer get_message_timer;
	exreq_empty_folder_permission empty_folder_permission;
	exreq_update_folder_permission update_folder_permission;
	exreq_empty_folder_rule empty_folder_rule;
	exreq_update_folder_rule update_folder_rule;
	exreq_delivery_message delivery_message;
	exreq_write_message write_message;
	exreq_read_message read_message;
	exreq_get_content_sync get_content_sync;
	exreq_get_hierarchy_sync get_hierarchy_sync;
	exreq_allocate_ids allocate_ids;
	exreq_subscribe_notification subscribe_notification;
	exreq_unsubscribe_notification unsubscribe_notification;
	exreq_check_contact_address check_contact_address;
	exreq_transport_new_mail transport_new_mail;
	exreq_get_public_folder_unread_count get_public_folder_unread_count;
};

struct EXMDB_REQUEST {
	exmdb_callid call_id;
	char *dir;
	EXMDB_REQUEST_PAYLOAD payload;
};

struct exresp_get_all_named_propids {
	PROPID_ARRAY propids;
};

struct exresp_get_named_propids {
	PROPID_ARRAY propids;
};

struct exresp_get_named_propnames {
	PROPNAME_ARRAY propnames;
};

struct exresp_get_mapping_guid {
	BOOL b_found;
	GUID guid;
};

struct exresp_get_mapping_replid {
	BOOL b_found;
	uint16_t replid;
};

struct exresp_get_store_all_proptags {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_store_properties {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_store_properties {
	PROBLEM_ARRAY problems;
};

struct exresp_check_mailbox_permission {
	uint32_t permission;
};

struct exresp_get_folder_by_class {
	uint64_t id;
	char *str_explicit;
};

struct exresp_set_folder_by_class {
	BOOL b_result;
};

struct exresp_get_folder_class_table {
	TARRAY_SET table;
};

struct exresp_check_folder_id {
	BOOL b_exist;
};

struct exresp_query_folder_messages {
	TARRAY_SET set;
};

struct exresp_check_folder_deleted {
	BOOL b_del;
};

struct exresp_get_folder_by_name {
	uint64_t folder_id;
};

struct exresp_check_folder_permission {
	uint32_t permission;
};

struct exresp_create_folder_by_properties {
	uint64_t folder_id;
};

struct exresp_get_folder_all_proptags {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_folder_properties {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_folder_properties {
	PROBLEM_ARRAY problems;
};

struct exresp_delete_folder {
	BOOL b_result;
};

struct exresp_empty_folder {
	BOOL b_partial;
};

struct exresp_check_folder_cycle {
	BOOL b_cycle;
};

struct exresp_copy_folder_internal {
	BOOL b_collid;
	BOOL b_partial;
};

struct exresp_get_search_criteria {
	uint32_t search_status;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
};

struct exresp_set_search_criteria {
	BOOL b_result;
};

struct exresp_movecopy_message {
	BOOL b_result;
};

struct exresp_movecopy_messages {
	BOOL b_partial;
};

struct exresp_movecopy_folder {
	BOOL b_exist;
	BOOL b_partial;
};

struct exresp_delete_messages {
	BOOL b_partial;
};

struct exresp_get_message_brief {
	MESSAGE_CONTENT *pbrief;
};

struct exresp_sum_hierarchy {
	uint32_t count;
};

struct exresp_load_hierarchy_table {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_sum_content {
	uint32_t count;
};

struct exresp_load_content_table {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_load_permission_table {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_load_rule_table {
	uint32_t table_id;
	uint32_t row_count;
};

struct exresp_sum_table {
	uint32_t rows;
};

struct exresp_query_table {
	TARRAY_SET set;
};

struct exresp_match_table {
	int32_t position;
	TPROPVAL_ARRAY propvals;
};

struct exresp_locate_table {
	int32_t position;
	uint32_t row_type;
};

struct exresp_read_table_row {
	TPROPVAL_ARRAY propvals;
};

struct exresp_mark_table {
	uint64_t inst_id;
	uint32_t inst_num;
	uint32_t row_type;
};

struct exresp_get_table_all_proptags {
	PROPTAG_ARRAY proptags;
};

struct exresp_expand_table {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct exresp_collapse_table {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct exresp_store_table_state {
	uint32_t state_id;
};

struct exresp_restore_table_state {
	int32_t position;
};

struct exresp_check_message {
	BOOL b_exist;
};

struct exresp_check_message_deleted {
	BOOL b_del;
};

struct exresp_load_message_instance {
	uint32_t instance_id;
};

struct exresp_load_embedded_instance {
	uint32_t instance_id;
};

struct exresp_get_embedded_cn {
	uint64_t *pcn;
};

struct exresp_reload_message_instance {
	BOOL b_result;
};

struct exresp_read_message_instance {
	MESSAGE_CONTENT msgctnt;
};

struct exresp_write_message_instance {
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
};

struct exresp_load_attachment_instance {
	uint32_t instance_id;
};

struct exresp_create_attachment_instance {
	uint32_t instance_id;
	uint32_t attachment_num;
};

struct exresp_read_attachment_instance {
	ATTACHMENT_CONTENT attctnt;
};

struct exresp_write_attachment_instance {
	PROBLEM_ARRAY problems;
};

struct exresp_flush_instance {
	gxerr_t e_result;
};

struct exresp_get_instance_all_proptags {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_instance_properties {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_instance_properties {
	PROBLEM_ARRAY problems;
};

struct exresp_remove_instance_properties {
	PROBLEM_ARRAY problems;
};

struct exresp_check_instance_cycle {
	BOOL b_cycle;
};

struct exresp_get_message_instance_rcpts_num {
	uint16_t num;
};

struct exresp_get_message_instance_rcpts_all_proptags {
	PROPTAG_ARRAY proptags;
};

struct exresp_get_message_instance_rcpts {
	TARRAY_SET set;
};

struct exresp_copy_instance_rcpts {
	BOOL b_result;
};

struct exresp_get_message_instance_attachments_num {
	uint16_t num;
};

struct exresp_get_message_instance_attachment_table_all_proptags {
	PROPTAG_ARRAY proptags;
};

struct exresp_query_message_instance_attachment_table {
	TARRAY_SET set;
};

struct exresp_copy_instance_attachments {
	BOOL b_result;
};

struct exresp_get_message_rcpts {
	TARRAY_SET set;
};

struct exresp_get_message_properties {
	TPROPVAL_ARRAY propvals;
};

struct exresp_set_message_properties {
	PROBLEM_ARRAY problems;
};

struct exresp_set_message_read_state {
	uint64_t read_cn;
};

struct exresp_allocate_message_id {
	uint64_t message_id;
};

struct exresp_allocate_cn {
	uint64_t cn;
};

struct exresp_get_message_group_id {
	uint32_t *pgroup_id;
};

struct exresp_get_change_indices {
	INDEX_ARRAY indices;
	PROPTAG_ARRAY ungroup_proptags;
};

struct exresp_try_mark_submit {
	BOOL b_marked;
};

struct exresp_link_message {
	BOOL b_result;
};

struct exresp_get_message_timer {
	uint32_t *ptimer_id;
};

struct exresp_update_folder_rule {
	BOOL b_exceed;
};

enum delivery_message_result {
	result_ok = 0,
	mailbox_full = 1,
	result_error = 2,
};

struct exresp_delivery_message {
	uint32_t result;
};

struct exresp_write_message {
	gxerr_t e_result;
};

struct exresp_read_message {
	MESSAGE_CONTENT *pmsgctnt;
};

struct exresp_get_content_sync {
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

struct exresp_get_hierarchy_sync {
	FOLDER_CHANGES fldchgs;
	uint64_t last_cn;
	EID_ARRAY given_fids;
	EID_ARRAY deleted_fids;
};

struct exresp_allocate_ids {
	uint64_t begin_eid;
};

struct exresp_subscribe_notification {
	uint32_t sub_id;
};

struct exresp_check_contact_address {
	BOOL b_found;
};

struct exresp_get_public_folder_unread_count {
	uint32_t count;
};

union EXMDB_RESPONSE_PAYLOAD {
	exresp_get_all_named_propids get_all_named_propids;
	exresp_get_named_propids get_named_propids;
	exresp_get_named_propnames get_named_propnames;
	exresp_get_mapping_guid get_mapping_guid;
	exresp_get_mapping_replid get_mapping_replid;
	exresp_get_store_all_proptags get_store_all_proptags;
	exresp_get_store_properties get_store_properties;
	exresp_set_store_properties set_store_properties;
	exresp_check_mailbox_permission check_mailbox_permission;
	exresp_get_folder_by_class get_folder_by_class;
	exresp_set_folder_by_class set_folder_by_class;
	exresp_get_folder_class_table get_folder_class_table;
	exresp_check_folder_id check_folder_id;
	exresp_query_folder_messages query_folder_messages;
	exresp_check_folder_deleted check_folder_deleted;
	exresp_get_folder_by_name get_folder_by_name;
	exresp_check_folder_permission check_folder_permission;
	exresp_create_folder_by_properties create_folder_by_properties;
	exresp_get_folder_all_proptags get_folder_all_proptags;
	exresp_get_folder_properties get_folder_properties;
	exresp_set_folder_properties set_folder_properties;
	exresp_delete_folder delete_folder;
	exresp_empty_folder empty_folder;
	exresp_check_folder_cycle check_folder_cycle;
	exresp_copy_folder_internal copy_folder_internal;
	exresp_get_search_criteria get_search_criteria;
	exresp_set_search_criteria set_search_criteria;
	exresp_movecopy_message movecopy_message;
	exresp_movecopy_messages movecopy_messages;
	exresp_movecopy_folder movecopy_folder;
	exresp_delete_messages delete_messages;
	exresp_get_message_brief get_message_brief;
	exresp_sum_hierarchy sum_hierarchy;
	exresp_load_hierarchy_table load_hierarchy_table;
	exresp_sum_content sum_content;
	exresp_load_content_table load_content_table;
	exresp_load_permission_table load_permission_table;
	exresp_load_rule_table load_rule_table;
	exresp_sum_table sum_table;
	exresp_query_table query_table;
	exresp_match_table match_table;
	exresp_locate_table locate_table;
	exresp_read_table_row read_table_row;
	exresp_mark_table mark_table;
	exresp_get_table_all_proptags get_table_all_proptags;
	exresp_expand_table expand_table;
	exresp_collapse_table collapse_table;
	exresp_store_table_state store_table_state;
	exresp_restore_table_state restore_table_state;
	exresp_check_message check_message;
	exresp_check_message_deleted check_message_deleted;
	exresp_load_message_instance load_message_instance;
	exresp_load_embedded_instance load_embedded_instance;
	exresp_get_embedded_cn get_embedded_cn;
	exresp_reload_message_instance reload_message_instance;
	exresp_read_message_instance read_message_instance;
	exresp_write_message_instance write_message_instance;
	exresp_load_attachment_instance load_attachment_instance;
	exresp_create_attachment_instance create_attachment_instance;
	exresp_read_attachment_instance read_attachment_instance;
	exresp_write_attachment_instance write_attachment_instance;
	exresp_flush_instance flush_instance;
	exresp_get_instance_all_proptags get_instance_all_proptags;
	exresp_get_instance_properties get_instance_properties;
	exresp_set_instance_properties set_instance_properties;
	exresp_remove_instance_properties remove_instance_properties;
	exresp_check_instance_cycle check_instance_cycle;
	exresp_get_message_instance_rcpts_num get_message_instance_rcpts_num;
	exresp_get_message_instance_rcpts_all_proptags get_message_instance_rcpts_all_proptags;
	exresp_get_message_instance_rcpts get_message_instance_rcpts;
	exresp_copy_instance_rcpts copy_instance_rcpts;
	exresp_get_message_instance_attachments_num get_message_instance_attachments_num;
	exresp_get_message_instance_attachment_table_all_proptags get_message_instance_attachment_table_all_proptags;
	exresp_query_message_instance_attachment_table query_message_instance_attachment_table;
	exresp_copy_instance_attachments copy_instance_attachments;
	exresp_get_message_rcpts get_message_rcpts;
	exresp_get_message_properties get_message_properties;
	exresp_set_message_properties set_message_properties;
	exresp_set_message_read_state set_message_read_state;
	exresp_allocate_message_id allocate_message_id;
	exresp_allocate_cn allocate_cn;
	exresp_get_message_group_id get_message_group_id;
	exresp_get_change_indices get_change_indices;
	exresp_try_mark_submit try_mark_submit;
	exresp_link_message link_message;
	exresp_get_message_timer get_message_timer;
	exresp_update_folder_rule update_folder_rule;
	exresp_delivery_message delivery_message;
	exresp_write_message write_message;
	exresp_read_message read_message;
	exresp_get_content_sync get_content_sync;
	exresp_get_hierarchy_sync get_hierarchy_sync;
	exresp_allocate_ids allocate_ids;
	exresp_subscribe_notification subscribe_notification;
	exresp_check_contact_address check_contact_address;
	exresp_get_public_folder_unread_count get_public_folder_unread_count;
};

struct EXMDB_RESPONSE {
	exmdb_callid call_id;
	EXMDB_RESPONSE_PAYLOAD payload;
};

struct DB_NOTIFY_DATAGRAM {
	char *dir;
	BOOL b_table;
	LONG_ARRAY id_array;
	DB_NOTIFY db_notify;
};

extern GX_EXPORT int exmdb_ext_pull_request(const BINARY *, EXMDB_REQUEST *);
extern GX_EXPORT int exmdb_ext_push_request(const EXMDB_REQUEST *, BINARY *);
extern GX_EXPORT int exmdb_ext_pull_response(const BINARY *, EXMDB_RESPONSE *);
extern GX_EXPORT int exmdb_ext_push_response(const EXMDB_RESPONSE *presponse, BINARY *);
extern GX_EXPORT int exmdb_ext_pull_db_notify(const BINARY *, DB_NOTIFY_DATAGRAM *);
extern GX_EXPORT int exmdb_ext_push_db_notify(const DB_NOTIFY_DATAGRAM *, BINARY *);
extern GX_EXPORT const char *exmdb_rpc_strerror(exmdb_response);
extern GX_EXPORT BOOL exmdb_client_read_socket(int, BINARY &, long timeout = -1);
extern GX_EXPORT BOOL exmdb_client_write_socket(int, const BINARY &, long timeout = -1);

extern GX_EXPORT void *(*exmdb_rpc_alloc)(size_t);
extern GX_EXPORT void (*exmdb_rpc_free)(void *);

namespace exmdb_client_remote {
#define IDLOUT
#define EXMIDL(n, p) extern GX_EXPORT BOOL n p;
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
}
