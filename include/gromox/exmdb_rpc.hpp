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
	get_folder_by_class = 0x0d,
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
	unload_store = 0x80,
};

struct EXREQ_CONNECT {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};

struct EXREQ_LISTEN_NOTIFICATION {
	char *remote_id;
};

struct EXREQ_GET_NAMED_PROPIDS {
	BOOL b_create;
	PROPNAME_ARRAY *ppropnames;
};

struct EXREQ_GET_NAMED_PROPNAMES {
	PROPID_ARRAY *ppropids;
};

struct EXREQ_GET_MAPPING_GUID {
	uint16_t replid;
};

struct EXREQ_GET_MAPPING_REPLID {
	GUID guid;
};

struct EXREQ_GET_STORE_PROPERTIES {
	uint32_t cpid;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_SET_STORE_PROPERTIES {
	uint32_t cpid;
	TPROPVAL_ARRAY *ppropvals;
};

struct EXREQ_REMOVE_STORE_PROPERTIES {
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_CHECK_MAILBOX_PERMISSION {
	char *username;
};

struct EXREQ_GET_FOLDER_BY_CLASS {
	char *str_class;
};

struct EXREQ_SET_FOLDER_BY_CLASS {
	uint64_t folder_id;
	char *str_class;
};

struct EXREQ_CHECK_FOLDER_ID {
	uint64_t folder_id;
};

struct EXREQ_QUERY_FOLDER_MESSAGES {
	uint64_t folder_id;
};

struct EXREQ_CHECK_FOLDER_DELETED {
	uint64_t folder_id;
};

struct EXREQ_GET_FOLDER_BY_NAME {
	uint64_t parent_id;
	char *str_name;
};

struct EXREQ_CHECK_FOLDER_PERMISSION {
	uint64_t folder_id;
	char *username;
};

struct EXREQ_CREATE_FOLDER_BY_PROPERTIES {
	uint32_t cpid;
	TPROPVAL_ARRAY *pproperties;
};

struct EXREQ_DELETE_FOLDER {
	uint32_t cpid;
	uint64_t folder_id;
	BOOL b_hard;
};

struct EXREQ_GET_FOLDER_ALL_PROPTAGS {
	uint64_t folder_id;
};

struct EXREQ_GET_FOLDER_PROPERTIES {
	uint32_t cpid;
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_SET_FOLDER_PROPERTIES {
	uint32_t cpid;
	uint64_t folder_id;
	TPROPVAL_ARRAY *pproperties;
};

struct EXREQ_REMOVE_FOLDER_PROPERTIES {
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_EMPTY_FOLDER {
	uint32_t cpid;
	char *username;
	uint64_t folder_id;
	BOOL b_hard;
	BOOL b_normal;
	BOOL b_fai;
	BOOL b_sub;
};

struct EXREQ_CHECK_FOLDER_CYCLE {
	uint64_t src_fid;
	uint64_t dst_fid;
};

struct EXREQ_COPY_FOLDER_INTERNAL {
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

struct EXREQ_GET_SEARCH_CRITERIA {
	uint64_t folder_id;
};

struct EXREQ_SET_SEARCH_CRITERIA {
	uint32_t cpid;
	uint64_t folder_id;
	uint32_t search_flags;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY *pfolder_ids;
};

struct EXREQ_MOVECOPY_MESSAGE {
	uint32_t account_id;
	uint32_t cpid;
	uint64_t message_id;
	uint64_t dst_fid;
	uint64_t dst_id;
	BOOL b_move;
};

struct EXREQ_MOVECOPY_MESSAGES {
	uint32_t account_id;
	uint32_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_fid;
	uint64_t dst_fid;
	BOOL b_copy;
	EID_ARRAY *pmessage_ids;
};

struct EXREQ_MOVECOPY_FOLDER {
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

struct EXREQ_DELETE_MESSAGES {
	uint32_t account_id;
	uint32_t cpid;
	char *username;
	uint64_t folder_id;
	EID_ARRAY *pmessage_ids;
	BOOL b_hard;
};

struct EXREQ_GET_MESSAGE_BRIEF {
	uint32_t cpid;
	uint64_t message_id;
};

struct EXREQ_SUM_HIERARCHY {
	uint64_t folder_id;
	char *username;
	BOOL b_depth;
};

struct EXREQ_SUM_CONTENT {
	uint64_t folder_id;
	BOOL b_fai;
	BOOL b_deleted;
};

struct EXREQ_LOAD_HIERARCHY_TABLE {
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct EXREQ_LOAD_CONTENT_TABLE {
	uint32_t cpid;
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
	SORTORDER_SET *psorts;
};

struct EXREQ_RELOAD_CONTENT_TABLE {
	uint32_t table_id;
};

struct EXREQ_LOAD_PERMISSION_TABLE {
	uint64_t folder_id;
	uint8_t table_flags;
};

struct EXREQ_LOAD_RULE_TABLE {
	uint64_t folder_id;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct EXREQ_UNLOAD_TABLE {
	uint32_t table_id;
};

struct EXREQ_SUM_TABLE {
	uint32_t table_id;
};

struct EXREQ_QUERY_TABLE {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct EXREQ_MATCH_TABLE {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	BOOL b_forward;
	uint32_t start_pos;
	RESTRICTION *pres;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_LOCATE_TABLE {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct EXREQ_READ_TABLE_ROW {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct EXREQ_MARK_TABLE {
	uint32_t table_id;
	uint32_t position;
};

struct EXREQ_GET_TABLE_ALL_PROPTAGS {
	uint32_t table_id;
};

struct EXREQ_EXPAND_TABLE {
	uint32_t table_id;
	uint64_t inst_id;
};

struct EXREQ_COLLAPSE_TABLE {
	uint32_t table_id;
	uint64_t inst_id;
};

struct EXREQ_STORE_TABLE_STATE {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct EXREQ_RESTORE_TABLE_STATE {
	uint32_t table_id;
	uint32_t state_id;
};

struct EXREQ_CHECK_MESSAGE {
	uint64_t folder_id;
	uint64_t message_id;
};

struct EXREQ_CHECK_MESSAGE_DELETED {
	uint64_t message_id;
};

struct EXREQ_LOAD_MESSAGE_INSTANCE {
	char *username;
	uint32_t cpid;
	BOOL b_new;
	uint64_t folder_id;
	uint64_t message_id;
};

struct EXREQ_LOAD_EMBEDDED_INSTANCE {
	BOOL b_new;
	uint32_t attachment_instance_id;
};

struct EXREQ_GET_EMBEDDED_CN {
	uint32_t instance_id;
};

struct EXREQ_RELOAD_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct EXREQ_CLEAR_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct EXREQ_READ_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct EXREQ_WRITE_MESSAGE_INSTANCE {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
	BOOL b_force;
};

struct EXREQ_LOAD_ATTACHMENT_INSTANCE {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct EXREQ_CREATE_ATTACHMENT_INSTANCE {
	uint32_t message_instance_id;
};

struct EXREQ_READ_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
};

struct EXREQ_WRITE_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
	ATTACHMENT_CONTENT *pattctnt;
	BOOL b_force;
};

struct EXREQ_DELETE_MESSAGE_INSTANCE_ATTACHMENT {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct EXREQ_FLUSH_INSTANCE {
	uint32_t instance_id;
	char *account;
};

struct EXREQ_UNLOAD_INSTANCE {
	uint32_t instance_id;
};

struct EXREQ_GET_INSTANCE_ALL_PROPTAGS {
	uint32_t instance_id;
};

struct EXREQ_GET_INSTANCE_PROPERTIES {
	uint32_t size_limit;
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_SET_INSTANCE_PROPERTIES {
	uint32_t instance_id;
	TPROPVAL_ARRAY *pproperties;
};

struct EXREQ_REMOVE_INSTANCE_PROPERTIES {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_CHECK_INSTANCE_CYCLE {
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct EXREQ_EMPTY_MESSAGE_INSTANCE_RCPTS {
	uint32_t instance_id;
};

struct EXREQ_GET_MESSAGE_INSTANCE_RCPTS_NUM {
	uint32_t instance_id;
};

struct EXREQ_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS {
	uint32_t instance_id;
};

struct EXREQ_GET_MESSAGE_INSTANCE_RCPTS {
	uint32_t instance_id;
	uint32_t row_id;
	uint16_t need_count;
};

struct EXREQ_UPDATE_MESSAGE_INSTANCE_RCPTS {
	uint32_t instance_id;
	TARRAY_SET *pset;
};

struct EXREQ_COPY_INSTANCE_RCPTS {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct EXREQ_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS {
	uint32_t instance_id;
};

struct EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM {
	uint32_t instance_id;
};

struct EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS {
	uint32_t instance_id;
};

struct EXREQ_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct EXREQ_COPY_INSTANCE_ATTACHMENTS {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct EXREQ_SET_MESSAGE_INSTANCE_CONFLICT {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct EXREQ_GET_MESSAGE_RCPTS {
	uint64_t message_id;
};

struct EXREQ_GET_MESSAGE_PROPERTIES {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_SET_MESSAGE_PROPERTIES {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
	TPROPVAL_ARRAY *pproperties;
};

struct EXREQ_SET_MESSAGE_READ_STATE {
	char *username;
	uint64_t message_id;
	uint8_t mark_as_read;
};

struct EXREQ_REMOVE_MESSAGE_PROPERTIES {
	uint32_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct EXREQ_ALLOCATE_MESSAGE_ID {
	uint64_t folder_id;
};

struct EXREQ_GET_MESSAGE_GROUP_ID {
	uint64_t message_id;
};

struct EXREQ_SET_MESSAGE_GROUP_ID {
	uint64_t message_id;
	uint32_t group_id;
};

struct EXREQ_SAVE_CHANGE_INDICES {
	uint64_t message_id;
	uint64_t cn;
	INDEX_ARRAY *pindices;
	PROPTAG_ARRAY *pungroup_proptags;
};

struct EXREQ_GET_CHANGE_INDICES {
	uint64_t message_id;
	uint64_t cn;
};

struct EXREQ_MARK_MODIFIED {
	uint64_t message_id;
};

struct EXREQ_TRY_MARK_SUBMIT {
	uint64_t message_id;
};

struct EXREQ_CLEAR_SUBMIT {
	uint64_t message_id;
	BOOL b_unsent;
};

struct EXREQ_LINK_MESSAGE {
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct EXREQ_UNLINK_MESSAGE {
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct EXREQ_RULE_NEW_MESSAGE {
	char *username;
	char *account;
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct EXREQ_SET_MESSAGE_TIMER {
	uint64_t message_id;
	uint32_t timer_id;
};

struct EXREQ_GET_MESSAGE_TIMER {
	uint64_t message_id;
};

struct EXREQ_EMPTY_FOLDER_PERMISSION {
	uint64_t folder_id;
};

struct EXREQ_UPDATE_FOLDER_PERMISSION {
	uint64_t folder_id;
	BOOL b_freebusy;
	uint16_t count;
	PERMISSION_DATA *prow;
};

struct EXREQ_EMPTY_FOLDER_RULE {
	uint64_t folder_id;
};

struct EXREQ_UPDATE_FOLDER_RULE {
	uint64_t folder_id;
	uint16_t count;
	RULE_DATA *prow;
};

struct EXREQ_DELIVERY_MESSAGE {
	char *from_address;
	char *account;
	uint32_t cpid;
	MESSAGE_CONTENT *pmsg;
	char *pdigest;
};

struct EXREQ_WRITE_MESSAGE {
	char *account;
	uint32_t cpid;
	uint64_t folder_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct EXREQ_READ_MESSAGE {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
};

struct EXREQ_GET_CONTENT_SYNC {
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

struct EXREQ_GET_HIERARCHY_SYNC {
	uint64_t folder_id;
	char *username;
	IDSET *pgiven;
	IDSET *pseen;
};

struct EXREQ_ALLOCATE_IDS {
	uint32_t count;
};

struct EXREQ_SUBSCRIBE_NOTIFICATION {
	uint16_t notificaton_type;
	BOOL b_whole;
	uint64_t folder_id;
	uint64_t message_id;
};

struct EXREQ_UNSUBSCRIBE_NOTIFICATION {
	uint32_t sub_id;
};

struct EXREQ_TRANSPORT_NEW_MAIL {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	char *pstr_class;
};

struct EXREQ_CHECK_CONTACT_ADDRESS {
	char *paddress;
};

struct EXREQ_GET_PUBLIC_FOLDER_UNREAD_COUNT {
	char *username;
	uint64_t folder_id;
};

union EXMDB_REQUEST_PAYLOAD {
	EXREQ_CONNECT connect;
	EXREQ_GET_NAMED_PROPIDS get_named_propids;
	EXREQ_GET_NAMED_PROPNAMES get_named_propnames;
	EXREQ_GET_MAPPING_GUID get_mapping_guid;
	EXREQ_GET_MAPPING_REPLID get_mapping_replid;
	EXREQ_LISTEN_NOTIFICATION	listen_notification;
	EXREQ_GET_STORE_PROPERTIES get_store_properties;
	EXREQ_SET_STORE_PROPERTIES set_store_properties;
	EXREQ_REMOVE_STORE_PROPERTIES remove_store_properties;
	EXREQ_CHECK_MAILBOX_PERMISSION check_mailbox_permission;
	EXREQ_GET_FOLDER_BY_CLASS get_folder_by_class;
	EXREQ_SET_FOLDER_BY_CLASS set_folder_by_class;
	EXREQ_CHECK_FOLDER_ID check_folder_id;
	EXREQ_QUERY_FOLDER_MESSAGES query_folder_messages;
	EXREQ_CHECK_FOLDER_DELETED check_folder_deleted;
	EXREQ_GET_FOLDER_BY_NAME get_folder_by_name;
	EXREQ_CHECK_FOLDER_PERMISSION check_folder_permission;
	EXREQ_CREATE_FOLDER_BY_PROPERTIES create_folder_by_properties;
	EXREQ_GET_FOLDER_ALL_PROPTAGS get_folder_all_proptags;
	EXREQ_GET_FOLDER_PROPERTIES get_folder_properties;
	EXREQ_SET_FOLDER_PROPERTIES set_folder_properties;
	EXREQ_REMOVE_FOLDER_PROPERTIES remove_folder_properties;
	EXREQ_DELETE_FOLDER delete_folder;
	EXREQ_EMPTY_FOLDER empty_folder;
	EXREQ_CHECK_FOLDER_CYCLE check_folder_cycle;
	EXREQ_COPY_FOLDER_INTERNAL copy_folder_internal;
	EXREQ_GET_SEARCH_CRITERIA get_search_criteria;
	EXREQ_SET_SEARCH_CRITERIA set_search_criteria;
	EXREQ_MOVECOPY_MESSAGE movecopy_message;
	EXREQ_MOVECOPY_MESSAGES movecopy_messages;
	EXREQ_MOVECOPY_FOLDER movecopy_folder;
	EXREQ_DELETE_MESSAGES delete_messages;
	EXREQ_GET_MESSAGE_BRIEF get_message_brief;
	EXREQ_SUM_HIERARCHY sum_hierarchy;
	EXREQ_LOAD_HIERARCHY_TABLE load_hierarchy_table;
	EXREQ_SUM_CONTENT sum_content;
	EXREQ_LOAD_CONTENT_TABLE load_content_table;
	EXREQ_RELOAD_CONTENT_TABLE reload_content_table;
	EXREQ_LOAD_PERMISSION_TABLE load_permission_table;
	EXREQ_LOAD_RULE_TABLE load_rule_table;
	EXREQ_UNLOAD_TABLE unload_table;
	EXREQ_SUM_TABLE sum_table;
	EXREQ_QUERY_TABLE query_table;
	EXREQ_MATCH_TABLE match_table;
	EXREQ_LOCATE_TABLE locate_table;
	EXREQ_READ_TABLE_ROW read_table_row;
	EXREQ_MARK_TABLE mark_table;
	EXREQ_GET_TABLE_ALL_PROPTAGS get_table_all_proptags;
	EXREQ_EXPAND_TABLE expand_table;
	EXREQ_COLLAPSE_TABLE collapse_table;
	EXREQ_STORE_TABLE_STATE store_table_state;
	EXREQ_RESTORE_TABLE_STATE restore_table_state;
	EXREQ_CHECK_MESSAGE check_message;
	EXREQ_CHECK_MESSAGE_DELETED check_message_deleted;
	EXREQ_LOAD_MESSAGE_INSTANCE load_message_instance;
	EXREQ_LOAD_EMBEDDED_INSTANCE load_embedded_instance;
	EXREQ_GET_EMBEDDED_CN get_embedded_cn;
	EXREQ_RELOAD_MESSAGE_INSTANCE reload_message_instance;
	EXREQ_CLEAR_MESSAGE_INSTANCE clear_message_instance;
	EXREQ_READ_MESSAGE_INSTANCE read_message_instance;
	EXREQ_WRITE_MESSAGE_INSTANCE write_message_instance;
	EXREQ_LOAD_ATTACHMENT_INSTANCE load_attachment_instance;
	EXREQ_CREATE_ATTACHMENT_INSTANCE create_attachment_instance;
	EXREQ_READ_ATTACHMENT_INSTANCE read_attachment_instance;
	EXREQ_WRITE_ATTACHMENT_INSTANCE write_attachment_instance;
	EXREQ_DELETE_MESSAGE_INSTANCE_ATTACHMENT delete_message_instance_attachment;
	EXREQ_FLUSH_INSTANCE flush_instance;
	EXREQ_UNLOAD_INSTANCE unload_instance;
	EXREQ_GET_INSTANCE_ALL_PROPTAGS get_instance_all_proptags;
	EXREQ_GET_INSTANCE_PROPERTIES get_instance_properties;
	EXREQ_SET_INSTANCE_PROPERTIES set_instance_properties;
	EXREQ_REMOVE_INSTANCE_PROPERTIES remove_instance_properties;
	EXREQ_CHECK_INSTANCE_CYCLE check_instance_cycle;
	EXREQ_EMPTY_MESSAGE_INSTANCE_RCPTS empty_message_instance_rcpts;
	EXREQ_GET_MESSAGE_INSTANCE_RCPTS_NUM get_message_instance_rcpts_num;
	EXREQ_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS get_message_instance_rcpts_all_proptags;
	EXREQ_GET_MESSAGE_INSTANCE_RCPTS get_message_instance_rcpts;
	EXREQ_UPDATE_MESSAGE_INSTANCE_RCPTS update_message_instance_rcpts;
	EXREQ_COPY_INSTANCE_RCPTS copy_instance_rcpts;
	EXREQ_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS empty_message_instance_attachments;
	EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM get_message_instance_attachments_num;
	EXREQ_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS get_message_instance_attachment_table_all_proptags;
	EXREQ_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE query_message_instance_attachment_table;
	EXREQ_COPY_INSTANCE_ATTACHMENTS copy_instance_attachments;
	EXREQ_SET_MESSAGE_INSTANCE_CONFLICT set_message_instance_conflict;
	EXREQ_GET_MESSAGE_RCPTS get_message_rcpts;
	EXREQ_GET_MESSAGE_PROPERTIES get_message_properties;
	EXREQ_SET_MESSAGE_PROPERTIES set_message_properties;
	EXREQ_SET_MESSAGE_READ_STATE set_message_read_state;
	EXREQ_REMOVE_MESSAGE_PROPERTIES remove_message_properties;
	EXREQ_ALLOCATE_MESSAGE_ID allocate_message_id;
	EXREQ_GET_MESSAGE_GROUP_ID get_message_group_id;
	EXREQ_SET_MESSAGE_GROUP_ID set_message_group_id;
	EXREQ_SAVE_CHANGE_INDICES save_change_indices;
	EXREQ_GET_CHANGE_INDICES get_change_indices;
	EXREQ_MARK_MODIFIED mark_modified;
	EXREQ_TRY_MARK_SUBMIT try_mark_submit;
	EXREQ_CLEAR_SUBMIT clear_submit;
	EXREQ_LINK_MESSAGE link_message;
	EXREQ_UNLINK_MESSAGE unlink_message;
	EXREQ_RULE_NEW_MESSAGE rule_new_message;
	EXREQ_SET_MESSAGE_TIMER set_message_timer;
	EXREQ_GET_MESSAGE_TIMER get_message_timer;
	EXREQ_EMPTY_FOLDER_PERMISSION empty_folder_permission;
	EXREQ_UPDATE_FOLDER_PERMISSION update_folder_permission;
	EXREQ_EMPTY_FOLDER_RULE empty_folder_rule;
	EXREQ_UPDATE_FOLDER_RULE update_folder_rule;
	EXREQ_DELIVERY_MESSAGE delivery_message;
	EXREQ_WRITE_MESSAGE write_message;
	EXREQ_READ_MESSAGE read_message;
	EXREQ_GET_CONTENT_SYNC get_content_sync;
	EXREQ_GET_HIERARCHY_SYNC get_hierarchy_sync;
	EXREQ_ALLOCATE_IDS allocate_ids;
	EXREQ_SUBSCRIBE_NOTIFICATION subscribe_notification;
	EXREQ_UNSUBSCRIBE_NOTIFICATION unsubscribe_notification;
	EXREQ_CHECK_CONTACT_ADDRESS check_contact_address;
	EXREQ_TRANSPORT_NEW_MAIL transport_new_mail;
	EXREQ_GET_PUBLIC_FOLDER_UNREAD_COUNT get_public_folder_unread_count;
};

struct EXMDB_REQUEST {
	exmdb_callid call_id;
	char *dir;
	EXMDB_REQUEST_PAYLOAD payload;
};

struct EXRESP_GET_ALL_NAMED_PROPIDS {
	PROPID_ARRAY propids;
};

struct EXRESP_GET_NAMED_PROPIDS {
	PROPID_ARRAY propids;
};

struct EXRESP_GET_NAMED_PROPNAMES {
	PROPNAME_ARRAY propnames;
};

struct EXRESP_GET_MAPPING_GUID {
	BOOL b_found;
	GUID guid;
};

struct EXRESP_GET_MAPPING_REPLID {
	BOOL b_found;
	uint16_t replid;
};

struct EXRESP_GET_STORE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct EXRESP_GET_STORE_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct EXRESP_SET_STORE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct EXRESP_CHECK_MAILBOX_PERMISSION {
	uint32_t permission;
};

struct EXRESP_GET_FOLDER_BY_CLASS {
	uint64_t id;
	char *str_explicit;
};

struct EXRESP_SET_FOLDER_BY_CLASS {
	BOOL b_result;
};

struct EXRESP_GET_FOLDER_CLASS_TABLE {
	TARRAY_SET table;
};

struct EXRESP_CHECK_FOLDER_ID {
	BOOL b_exist;
};

struct EXRESP_QUERY_FOLDER_MESSAGES {
	TARRAY_SET set;
};

struct EXRESP_CHECK_FOLDER_DELETED {
	BOOL b_del;
};

struct EXRESP_GET_FOLDER_BY_NAME {
	uint64_t folder_id;
};

struct EXRESP_CHECK_FOLDER_PERMISSION {
	uint32_t permission;
};

struct EXRESP_CREATE_FOLDER_BY_PROPERTIES {
	uint64_t folder_id;
};

struct EXRESP_GET_FOLDER_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct EXRESP_GET_FOLDER_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct EXRESP_SET_FOLDER_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct EXRESP_DELETE_FOLDER {
	BOOL b_result;
};

struct EXRESP_EMPTY_FOLDER {
	BOOL b_partial;
};

struct EXRESP_CHECK_FOLDER_CYCLE {
	BOOL b_cycle;
};

struct EXRESP_COPY_FOLDER_INTERNAL {
	BOOL b_collid;
	BOOL b_partial;
};

struct EXRESP_GET_SEARCH_CRITERIA {
	uint32_t search_status;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
};

struct EXRESP_SET_SEARCH_CRITERIA {
	BOOL b_result;
};

struct EXRESP_MOVECOPY_MESSAGE {
	BOOL b_result;
};

struct EXRESP_MOVECOPY_MESSAGES {
	BOOL b_partial;
};

struct EXRESP_MOVECOPY_FOLDER {
	BOOL b_exist;
	BOOL b_partial;
};

struct EXRESP_DELETE_MESSAGES {
	BOOL b_partial;
};

struct EXRESP_GET_MESSAGE_BRIEF {
	MESSAGE_CONTENT *pbrief;
};

struct EXRESP_SUM_HIERARCHY {
	uint32_t count;
};

struct EXRESP_LOAD_HIERARCHY_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct EXRESP_SUM_CONTENT {
	uint32_t count;
};

struct EXRESP_LOAD_CONTENT_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct EXRESP_LOAD_PERMISSION_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct EXRESP_LOAD_RULE_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct EXRESP_SUM_TABLE {
	uint32_t rows;
};

struct EXRESP_QUERY_TABLE {
	TARRAY_SET set;
};

struct EXRESP_MATCH_TABLE {
	int32_t position;
	TPROPVAL_ARRAY propvals;
};

struct EXRESP_LOCATE_TABLE {
	int32_t position;
	uint32_t row_type;
};

struct EXRESP_READ_TABLE_ROW {
	TPROPVAL_ARRAY propvals;
};

struct EXRESP_MARK_TABLE {
	uint64_t inst_id;
	uint32_t inst_num;
	uint32_t row_type;
};

struct EXRESP_GET_TABLE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct EXRESP_EXPAND_TABLE {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct EXRESP_COLLAPSE_TABLE {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct EXRESP_STORE_TABLE_STATE {
	uint32_t state_id;
};

struct EXRESP_RESTORE_TABLE_STATE {
	int32_t position;
};

struct EXRESP_CHECK_MESSAGE {
	BOOL b_exist;
};

struct EXRESP_CHECK_MESSAGE_DELETED {
	BOOL b_del;
};

struct EXRESP_LOAD_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct EXRESP_LOAD_EMBEDDED_INSTANCE {
	uint32_t instance_id;
};

struct EXRESP_GET_EMBEDDED_CN {
	uint64_t *pcn;
};

struct EXRESP_RELOAD_MESSAGE_INSTANCE {
	BOOL b_result;
};

struct EXRESP_READ_MESSAGE_INSTANCE {
	MESSAGE_CONTENT msgctnt;
};

struct EXRESP_WRITE_MESSAGE_INSTANCE {
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
};

struct EXRESP_LOAD_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
};

struct EXRESP_CREATE_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
	uint32_t attachment_num;
};

struct EXRESP_READ_ATTACHMENT_INSTANCE {
	ATTACHMENT_CONTENT attctnt;
};

struct EXRESP_WRITE_ATTACHMENT_INSTANCE {
	PROBLEM_ARRAY problems;
};

struct EXRESP_FLUSH_INSTANCE {
	gxerr_t e_result;
};

struct EXRESP_GET_INSTANCE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct EXRESP_GET_INSTANCE_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct EXRESP_SET_INSTANCE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct EXRESP_REMOVE_INSTANCE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct EXRESP_CHECK_INSTANCE_CYCLE {
	BOOL b_cycle;
};

struct EXRESP_GET_MESSAGE_INSTANCE_RCPTS_NUM {
	uint16_t num;
};

struct EXRESP_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct EXRESP_GET_MESSAGE_INSTANCE_RCPTS {
	TARRAY_SET set;
};

struct EXRESP_COPY_INSTANCE_RCPTS {
	BOOL b_result;
};

struct EXRESP_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM {
	uint16_t num;
};

struct EXRESP_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct EXRESP_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE {
	TARRAY_SET set;
};

struct EXRESP_COPY_INSTANCE_ATTACHMENTS {
	BOOL b_result;
};

struct EXRESP_GET_MESSAGE_RCPTS {
	TARRAY_SET set;
};

struct EXRESP_GET_MESSAGE_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct EXRESP_SET_MESSAGE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct EXRESP_SET_MESSAGE_READ_STATE {
	uint64_t read_cn;
};

struct EXRESP_ALLOCATE_MESSAGE_ID {
	uint64_t message_id;
};

struct EXRESP_ALLOCATE_CN {
	uint64_t cn;
};

struct EXRESP_GET_MESSAGE_GROUP_ID {
	uint32_t *pgroup_id;
};

struct EXRESP_GET_CHANGE_INDICES {
	INDEX_ARRAY indices;
	PROPTAG_ARRAY ungroup_proptags;
};

struct EXRESP_TRY_MARK_SUBMIT {
	BOOL b_marked;
};

struct EXRESP_LINK_MESSAGE {
	BOOL b_result;
};

struct EXRESP_GET_MESSAGE_TIMER {
	uint32_t *ptimer_id;
};

struct EXRESP_UPDATE_FOLDER_RULE {
	BOOL b_exceed;
};

enum delivery_message_result {
	result_ok = 0,
	mailbox_full = 1,
	result_error = 2,
};

struct EXRESP_DELIVERY_MESSAGE {
	uint32_t result;
};

struct EXRESP_WRITE_MESSAGE {
	gxerr_t e_result;
};

struct EXRESP_READ_MESSAGE {
	MESSAGE_CONTENT *pmsgctnt;
};

struct EXRESP_GET_CONTENT_SYNC {
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

struct EXRESP_GET_HIERARCHY_SYNC {
	FOLDER_CHANGES fldchgs;
	uint64_t last_cn;
	EID_ARRAY given_fids;
	EID_ARRAY deleted_fids;
};

struct EXRESP_ALLOCATE_IDS {
	uint64_t begin_eid;
};

struct EXRESP_SUBSCRIBE_NOTIFICATION {
	uint32_t sub_id;
};

struct EXRESP_CHECK_CONTACT_ADDRESS {
	BOOL b_found;
};

struct EXRESP_GET_PUBLIC_FOLDER_UNREAD_COUNT {
	uint32_t count;
};

union EXMDB_RESPONSE_PAYLOAD {
	EXRESP_GET_ALL_NAMED_PROPIDS get_all_named_propids;
	EXRESP_GET_NAMED_PROPIDS get_named_propids;
	EXRESP_GET_NAMED_PROPNAMES get_named_propnames;
	EXRESP_GET_MAPPING_GUID get_mapping_guid;
	EXRESP_GET_MAPPING_REPLID get_mapping_replid;
	EXRESP_GET_STORE_ALL_PROPTAGS get_store_all_proptags;
	EXRESP_GET_STORE_PROPERTIES get_store_properties;
	EXRESP_SET_STORE_PROPERTIES set_store_properties;
	EXRESP_CHECK_MAILBOX_PERMISSION check_mailbox_permission;
	EXRESP_GET_FOLDER_BY_CLASS get_folder_by_class;
	EXRESP_SET_FOLDER_BY_CLASS set_folder_by_class;
	EXRESP_GET_FOLDER_CLASS_TABLE get_folder_class_table;
	EXRESP_CHECK_FOLDER_ID check_folder_id;
	EXRESP_QUERY_FOLDER_MESSAGES query_folder_messages;
	EXRESP_CHECK_FOLDER_DELETED check_folder_deleted;
	EXRESP_GET_FOLDER_BY_NAME get_folder_by_name;
	EXRESP_CHECK_FOLDER_PERMISSION check_folder_permission;
	EXRESP_CREATE_FOLDER_BY_PROPERTIES create_folder_by_properties;
	EXRESP_GET_FOLDER_ALL_PROPTAGS get_folder_all_proptags;
	EXRESP_GET_FOLDER_PROPERTIES get_folder_properties;
	EXRESP_SET_FOLDER_PROPERTIES set_folder_properties;
	EXRESP_DELETE_FOLDER delete_folder;
	EXRESP_EMPTY_FOLDER empty_folder;
	EXRESP_CHECK_FOLDER_CYCLE check_folder_cycle;
	EXRESP_COPY_FOLDER_INTERNAL copy_folder_internal;
	EXRESP_GET_SEARCH_CRITERIA get_search_criteria;
	EXRESP_SET_SEARCH_CRITERIA set_search_criteria;
	EXRESP_MOVECOPY_MESSAGE movecopy_message;
	EXRESP_MOVECOPY_MESSAGES movecopy_messages;
	EXRESP_MOVECOPY_FOLDER movecopy_folder;
	EXRESP_DELETE_MESSAGES delete_messages;
	EXRESP_GET_MESSAGE_BRIEF get_message_brief;
	EXRESP_SUM_HIERARCHY sum_hierarchy;
	EXRESP_LOAD_HIERARCHY_TABLE load_hierarchy_table;
	EXRESP_SUM_CONTENT sum_content;
	EXRESP_LOAD_CONTENT_TABLE load_content_table;
	EXRESP_LOAD_PERMISSION_TABLE load_permission_table;
	EXRESP_LOAD_RULE_TABLE load_rule_table;
	EXRESP_SUM_TABLE sum_table;
	EXRESP_QUERY_TABLE query_table;
	EXRESP_MATCH_TABLE match_table;
	EXRESP_LOCATE_TABLE locate_table;
	EXRESP_READ_TABLE_ROW read_table_row;
	EXRESP_MARK_TABLE mark_table;
	EXRESP_GET_TABLE_ALL_PROPTAGS get_table_all_proptags;
	EXRESP_EXPAND_TABLE expand_table;
	EXRESP_COLLAPSE_TABLE collapse_table;
	EXRESP_STORE_TABLE_STATE store_table_state;
	EXRESP_RESTORE_TABLE_STATE restore_table_state;
	EXRESP_CHECK_MESSAGE check_message;
	EXRESP_CHECK_MESSAGE_DELETED check_message_deleted;
	EXRESP_LOAD_MESSAGE_INSTANCE load_message_instance;
	EXRESP_LOAD_EMBEDDED_INSTANCE load_embedded_instance;
	EXRESP_GET_EMBEDDED_CN get_embedded_cn;
	EXRESP_RELOAD_MESSAGE_INSTANCE reload_message_instance;
	EXRESP_READ_MESSAGE_INSTANCE read_message_instance;
	EXRESP_WRITE_MESSAGE_INSTANCE write_message_instance;
	EXRESP_LOAD_ATTACHMENT_INSTANCE load_attachment_instance;
	EXRESP_CREATE_ATTACHMENT_INSTANCE create_attachment_instance;
	EXRESP_READ_ATTACHMENT_INSTANCE read_attachment_instance;
	EXRESP_WRITE_ATTACHMENT_INSTANCE write_attachment_instance;
	EXRESP_FLUSH_INSTANCE flush_instance;
	EXRESP_GET_INSTANCE_ALL_PROPTAGS get_instance_all_proptags;
	EXRESP_GET_INSTANCE_PROPERTIES get_instance_properties;
	EXRESP_SET_INSTANCE_PROPERTIES set_instance_properties;
	EXRESP_REMOVE_INSTANCE_PROPERTIES remove_instance_properties;
	EXRESP_CHECK_INSTANCE_CYCLE check_instance_cycle;
	EXRESP_GET_MESSAGE_INSTANCE_RCPTS_NUM get_message_instance_rcpts_num;
	EXRESP_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS get_message_instance_rcpts_all_proptags;
	EXRESP_GET_MESSAGE_INSTANCE_RCPTS get_message_instance_rcpts;
	EXRESP_COPY_INSTANCE_RCPTS copy_instance_rcpts;
	EXRESP_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM get_message_instance_attachments_num;
	EXRESP_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS get_message_instance_attachment_table_all_proptags;
	EXRESP_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE query_message_instance_attachment_table;
	EXRESP_COPY_INSTANCE_ATTACHMENTS copy_instance_attachments;
	EXRESP_GET_MESSAGE_RCPTS get_message_rcpts;
	EXRESP_GET_MESSAGE_PROPERTIES get_message_properties;
	EXRESP_SET_MESSAGE_PROPERTIES set_message_properties;
	EXRESP_SET_MESSAGE_READ_STATE set_message_read_state;
	EXRESP_ALLOCATE_MESSAGE_ID allocate_message_id;
	EXRESP_ALLOCATE_CN allocate_cn;
	EXRESP_GET_MESSAGE_GROUP_ID get_message_group_id;
	EXRESP_GET_CHANGE_INDICES get_change_indices;
	EXRESP_TRY_MARK_SUBMIT try_mark_submit;
	EXRESP_LINK_MESSAGE link_message;
	EXRESP_GET_MESSAGE_TIMER get_message_timer;
	EXRESP_UPDATE_FOLDER_RULE update_folder_rule;
	EXRESP_DELIVERY_MESSAGE delivery_message;
	EXRESP_WRITE_MESSAGE write_message;
	EXRESP_READ_MESSAGE read_message;
	EXRESP_GET_CONTENT_SYNC get_content_sync;
	EXRESP_GET_HIERARCHY_SYNC get_hierarchy_sync;
	EXRESP_ALLOCATE_IDS allocate_ids;
	EXRESP_SUBSCRIBE_NOTIFICATION subscribe_notification;
	EXRESP_CHECK_CONTACT_ADDRESS check_contact_address;
	EXRESP_GET_PUBLIC_FOLDER_UNREAD_COUNT get_public_folder_unread_count;
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

struct exmdb_hell {
	BOOL rdsock(int, BINARY *, long timeout_ms = -1);
	BOOL wrsock(int, const BINARY *, long timeout_ms = -1);

	void *(*alloc)(size_t);
	BOOL (*exec)(const char *, const EXMDB_REQUEST *, EXMDB_RESPONSE *);
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
