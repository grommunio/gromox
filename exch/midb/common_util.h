#pragma once
#include <cstdint>
#include <cstdlib>
#include <gromox/defs.h>
#include <gromox/common_types.hpp>
#include <gromox/element_data.hpp>
#define SOCKET_TIMEOUT										60
#define MAX_DIGLEN											256*1024

struct REQ_CONNECT {
	char *prefix;
	char *remote_id;
	BOOL b_private;
};


struct REQ_LISTEN_NOTIFICATION {
	char *remote_id;
};

struct REQ_GET_NAMED_PROPIDS {
	BOOL b_create;
	PROPNAME_ARRAY *ppropnames;
};

struct REQ_GET_NAMED_PROPNAMES {
	PROPID_ARRAY *ppropids;
};

struct REQ_GET_MAPPING_GUID {
	uint16_t replid;
};

struct REQ_GET_MAPPING_REPLID {
	GUID guid;
};

struct REQ_GET_STORE_PROPERTIES {
	uint32_t cpid;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_SET_STORE_PROPERTIES {
	uint32_t cpid;
	TPROPVAL_ARRAY *ppropvals;
};

struct REQ_REMOVE_STORE_PROPERTIES {
	PROPTAG_ARRAY *pproptags;
};

struct REQ_CHECK_MAILBOX_PERMISSION {
	char *username;
};

struct REQ_GET_FOLDER_BY_CLASS {
	char *str_class;
};

struct REQ_SET_FOLDER_BY_CLASS {
	uint64_t folder_id;
	char *str_class;
};

struct REQ_CHECK_FOLDER_ID {
	uint64_t folder_id;
};

struct REQ_QUERY_FOLDER_MESSAGES {
	uint64_t folder_id;
};

struct REQ_CHECK_FOLDER_DELETED {
	uint64_t folder_id;
};

struct REQ_GET_FOLDER_BY_NAME {
	uint64_t parent_id;
	char *str_name;
};

struct REQ_CHECK_FOLDER_PERMISSION {
	uint64_t folder_id;
	char *username;
};

struct REQ_CREATE_FOLDER_BY_PROPERTIES {
	uint32_t cpid;
	TPROPVAL_ARRAY *pproperties;
};

struct REQ_DELETE_FOLDER {
	uint32_t cpid;
	uint64_t folder_id;
	BOOL b_hard;
};

struct REQ_GET_FOLDER_ALL_PROPTAGS {
	uint64_t folder_id;
};

struct REQ_GET_FOLDER_PROPERTIES {
	uint32_t cpid;
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_SET_FOLDER_PROPERTIES {
	uint32_t cpid;
	uint64_t folder_id;
	TPROPVAL_ARRAY *pproperties;
};

struct REQ_REMOVE_FOLDER_PROPERTIES {
	uint64_t folder_id;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_EMPTY_FOLDER {
	uint32_t cpid;
	char *username;
	uint64_t folder_id;
	BOOL b_hard;
	BOOL b_normal;
	BOOL b_fai;
	BOOL b_sub;
};

struct REQ_CHECK_FOLDER_CYCLE {
	uint64_t src_fid;
	uint64_t dst_fid;
};

struct REQ_COPY_FOLDER_INTERNAL {
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

struct REQ_GET_SEARCH_CRITERIA {
	uint64_t folder_id;
};

struct REQ_SET_SEARCH_CRITERIA {
	uint32_t cpid;
	uint64_t folder_id;
	uint32_t search_flags;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY *pfolder_ids;
};

struct REQ_MOVECOPY_MESSAGE {
	uint32_t account_id;
	uint32_t cpid;
	uint64_t message_id;
	uint64_t dst_fid;
	uint64_t dst_id;
	BOOL b_move;
};

struct REQ_MOVECOPY_MESSAGES {
	uint32_t account_id;
	uint32_t cpid;
	BOOL b_guest;
	char *username;
	uint64_t src_fid;
	uint64_t dst_fid;
	BOOL b_copy;
	EID_ARRAY *pmessage_ids;
};

struct REQ_MOVECOPY_FOLDER {
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

struct REQ_DELETE_MESSAGES {
	uint32_t account_id;
	uint32_t cpid;
	char *username;
	uint64_t folder_id;
	EID_ARRAY *pmessage_ids;
	BOOL b_hard;
};

struct REQ_GET_MESSAGE_BRIEF {
	uint32_t cpid;
	uint64_t message_id;
};

struct REQ_SUM_HIERARCHY {
	uint64_t folder_id;
	char *username;
	BOOL b_depth;
};

struct REQ_SUM_CONTENT {
	uint64_t folder_id;
	BOOL b_fai;
	BOOL b_deleted;
};

struct REQ_LOAD_HIERARCHY_TABLE {
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct REQ_LOAD_CONTENT_TABLE {
	uint32_t cpid;
	uint64_t folder_id;
	char *username;
	uint8_t table_flags;
	RESTRICTION *prestriction;
	SORTORDER_SET *psorts;
};

struct REQ_RELOAD_CONTENT_TABLE {
	uint32_t table_id;
};

struct REQ_LOAD_PERMISSION_TABLE {
	uint64_t folder_id;
	uint8_t table_flags;
};

struct REQ_LOAD_RULE_TABLE {
	uint64_t folder_id;
	uint8_t table_flags;
	RESTRICTION *prestriction;
};

struct REQ_UNLOAD_TABLE {
	uint32_t table_id;
};

struct REQ_SUM_TABLE {
	uint32_t table_id;
};

struct REQ_QUERY_TABLE {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct REQ_MATCH_TABLE {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	BOOL b_forward;
	uint32_t start_pos;
	RESTRICTION *pres;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_LOCATE_TABLE {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct REQ_READ_TABLE_ROW {
	char *username;
	uint32_t cpid;
	uint32_t table_id;
	PROPTAG_ARRAY *pproptags;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct REQ_MARK_TABLE {
	uint32_t table_id;
	uint32_t position;
};

struct REQ_GET_TABLE_ALL_PROPTAGS {
	uint32_t table_id;
};

struct REQ_EXPAND_TABLE {
	uint32_t table_id;
	uint64_t inst_id;
};

struct REQ_COLLAPSE_TABLE {
	uint32_t table_id;
	uint64_t inst_id;
};

struct REQ_STORE_TABLE_STATE {
	uint32_t table_id;
	uint64_t inst_id;
	uint32_t inst_num;
};

struct REQ_RESTORE_TABLE_STATE {
	uint32_t table_id;
	uint32_t state_id;
};

struct REQ_CHECK_MESSAGE {
	uint64_t folder_id;
	uint64_t message_id;
};

struct REQ_CHECK_MESSAGE_DELETED {
	uint64_t message_id;
};

struct REQ_LOAD_MESSAGE_INSTANCE {
	char *username;
	uint32_t cpid;
	BOOL b_new;
	uint64_t folder_id;
	uint64_t message_id;
};

struct REQ_LOAD_EMBEDDED_INSTANCE {
	BOOL b_new;
	uint32_t attachment_instance_id;
};

struct REQ_GET_EMBEDDED_CN {
	uint32_t instance_id;
};

struct REQ_RELOAD_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct REQ_CLEAR_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct REQ_READ_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct REQ_WRITE_MESSAGE_INSTANCE {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
	BOOL b_force;
};

struct REQ_LOAD_ATTACHMENT_INSTANCE {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct REQ_CREATE_ATTACHMENT_INSTANCE {
	uint32_t message_instance_id;
};

struct REQ_READ_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
};

struct REQ_WRITE_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
	ATTACHMENT_CONTENT *pattctnt;
	BOOL b_force;
};

struct REQ_DELETE_MESSAGE_INSTANCE_ATTACHMENT {
	uint32_t message_instance_id;
	uint32_t attachment_num;
};

struct REQ_FLUSH_INSTANCE {
	uint32_t instance_id;
	char *account;
};

struct REQ_UNLOAD_INSTANCE {
	uint32_t instance_id;
};

struct REQ_GET_INSTANCE_ALL_PROPTAGS {
	uint32_t instance_id;
};

struct REQ_GET_INSTANCE_PROPERTIES {
	uint32_t size_limit;
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_SET_INSTANCE_PROPERTIES {
	uint32_t instance_id;
	TPROPVAL_ARRAY *pproperties;
};

struct REQ_REMOVE_INSTANCE_PROPERTIES {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_CHECK_INSTANCE_CYCLE {
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct REQ_EMPTY_MESSAGE_INSTANCE_RCPTS {
	uint32_t instance_id;
};

struct REQ_GET_MESSAGE_INSTANCE_RCPTS_NUM {
	uint32_t instance_id;
};

struct REQ_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS {
	uint32_t instance_id;
};

struct REQ_GET_MESSAGE_INSTANCE_RCPTS {
	uint32_t instance_id;
	uint32_t row_id;
	uint16_t need_count;
};

struct REQ_UPDATE_MESSAGE_INSTANCE_RCPTS {
	uint32_t instance_id;
	TARRAY_SET *pset;
};

struct REQ_COPY_INSTANCE_RCPTS {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct REQ_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS {
	uint32_t instance_id;
};

struct REQ_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM {
	uint32_t instance_id;
};

struct REQ_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS {
	uint32_t instance_id;
};

struct REQ_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE {
	uint32_t instance_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t start_pos;
	int32_t row_needed;
};

struct REQ_COPY_INSTANCE_ATTACHMENTS {
	BOOL b_force;
	uint32_t src_instance_id;
	uint32_t dst_instance_id;
};

struct REQ_SET_MESSAGE_INSTANCE_CONFLICT {
	uint32_t instance_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct REQ_GET_MESSAGE_RCPTS {
	uint64_t message_id;
};

struct REQ_GET_MESSAGE_PROPERTIES {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_SET_MESSAGE_PROPERTIES {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
	TPROPVAL_ARRAY *pproperties;
};

struct REQ_SET_MESSAGE_READ_STATE {
	char *username;
	uint64_t message_id;
	uint8_t mark_as_read;
};

struct REQ_REMOVE_MESSAGE_PROPERTIES {
	uint32_t cpid;
	uint64_t message_id;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_ALLOCATE_MESSAGE_ID {
	uint64_t folder_id;
};

struct REQ_GET_MESSAGE_GROUP_ID {
	uint64_t message_id;
};

struct REQ_SET_MESSAGE_GROUP_ID {
	uint64_t message_id;
	uint32_t group_id;
};

struct REQ_SAVE_CHANGE_INDICES {
	uint64_t message_id;
	uint64_t cn;
	INDEX_ARRAY *pindices;
	PROPTAG_ARRAY *pungroup_proptags;
};

struct REQ_GET_CHANGE_INDICES {
	uint64_t message_id;
	uint64_t cn;
};

struct REQ_MARK_MODIFIED {
	uint64_t message_id;
};

struct REQ_TRY_MARK_SUBMIT {
	uint64_t message_id;
};

struct REQ_CLEAR_SUBMIT {
	uint64_t message_id;
	BOOL b_unsent;
};

struct REQ_LINK_MESSAGE {
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct REQ_UNLINK_MESSAGE {
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct REQ_RULE_NEW_MESSAGE {
	char *username;
	char *account;
	uint32_t cpid;
	uint64_t folder_id;
	uint64_t message_id;
};

struct REQ_SET_MESSAGE_TIMER {
	uint64_t message_id;
	uint32_t timer_id;
};

struct REQ_GET_MESSAGE_TIMER {
	uint64_t message_id;
};

struct REQ_EMPTY_FOLDER_PERMISSION {
	uint64_t folder_id;
};

struct REQ_UPDATE_FOLDER_PERMISSION {
	uint64_t folder_id;
	BOOL b_freebusy;
	uint16_t count;
	PERMISSION_DATA *prow;
};

struct REQ_EMPTY_FOLDER_RULE {
	uint64_t folder_id;
};

struct REQ_UPDATE_FOLDER_RULE {
	uint64_t folder_id;
	uint16_t count;
	RULE_DATA *prow;
};

struct REQ_DELIVERY_MESSAGE {
	char *from_address;
	char *account;
	uint32_t cpid;
	MESSAGE_CONTENT *pmsg;
	char *pdigest;
};

struct REQ_WRITE_MESSAGE {
	char *account;
	uint32_t cpid;
	uint64_t folder_id;
	MESSAGE_CONTENT *pmsgctnt;
};

struct REQ_READ_MESSAGE {
	char *username;
	uint32_t cpid;
	uint64_t message_id;
};

struct REQ_GET_CONTENT_SYNC {
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

struct REQ_GET_HIERARCHY_SYNC {
	uint64_t folder_id;
	char *username;
	IDSET *pgiven;
	IDSET *pseen;
};

struct REQ_ALLOCATE_IDS {
	uint32_t count;
};

struct REQ_SUBSCRIBE_NOTIFICATION {
	uint16_t notificaton_type;
	BOOL b_whole;
	uint64_t folder_id;
	uint64_t message_id;
};

struct REQ_UNSUBSCRIBE_NOTIFICATION {
	uint32_t sub_id;
};

struct REQ_TRANSPORT_NEW_MAIL {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	char *pstr_class;
};

struct REQ_CHECK_CONTACT_ADDRESS {
	char *paddress;
};

union REQUEST_PAYLOAD {
	REQ_CONNECT connect;
	REQ_GET_NAMED_PROPIDS get_named_propids;
	REQ_GET_NAMED_PROPNAMES get_named_propnames;
	REQ_GET_MAPPING_GUID get_mapping_guid;
	REQ_GET_MAPPING_REPLID get_mapping_replid;
	REQ_LISTEN_NOTIFICATION	listen_notification;
	REQ_GET_STORE_PROPERTIES get_store_properties;
	REQ_SET_STORE_PROPERTIES set_store_properties;
	REQ_REMOVE_STORE_PROPERTIES remove_store_properties;
	REQ_CHECK_MAILBOX_PERMISSION check_mailbox_permission;
	REQ_GET_FOLDER_BY_CLASS get_folder_by_class;
	REQ_SET_FOLDER_BY_CLASS set_folder_by_class;
	REQ_CHECK_FOLDER_ID check_folder_id;
	REQ_QUERY_FOLDER_MESSAGES query_folder_messages;
	REQ_CHECK_FOLDER_DELETED check_folder_deleted;
	REQ_GET_FOLDER_BY_NAME get_folder_by_name;
	REQ_CHECK_FOLDER_PERMISSION check_folder_permission;
	REQ_CREATE_FOLDER_BY_PROPERTIES create_folder_by_properties;
	REQ_GET_FOLDER_ALL_PROPTAGS get_folder_all_proptags;
	REQ_GET_FOLDER_PROPERTIES get_folder_properties;
	REQ_SET_FOLDER_PROPERTIES set_folder_properties;
	REQ_REMOVE_FOLDER_PROPERTIES remove_folder_properties;
	REQ_DELETE_FOLDER delete_folder;
	REQ_EMPTY_FOLDER empty_folder;
	REQ_CHECK_FOLDER_CYCLE check_folder_cycle;
	REQ_COPY_FOLDER_INTERNAL copy_folder_internal;
	REQ_GET_SEARCH_CRITERIA get_search_criteria;
	REQ_SET_SEARCH_CRITERIA set_search_criteria;
	REQ_MOVECOPY_MESSAGE movecopy_message;
	REQ_MOVECOPY_MESSAGES movecopy_messages;
	REQ_MOVECOPY_FOLDER movecopy_folder;
	REQ_DELETE_MESSAGES delete_messages;
	REQ_GET_MESSAGE_BRIEF get_message_brief;
	REQ_SUM_HIERARCHY sum_hierarchy;
	REQ_LOAD_HIERARCHY_TABLE load_hierarchy_table;
	REQ_SUM_CONTENT sum_content;
	REQ_LOAD_CONTENT_TABLE load_content_table;
	REQ_RELOAD_CONTENT_TABLE reload_content_table;
	REQ_LOAD_PERMISSION_TABLE load_permission_table;
	REQ_LOAD_RULE_TABLE load_rule_table;
	REQ_UNLOAD_TABLE unload_table;
	REQ_SUM_TABLE sum_table;
	REQ_QUERY_TABLE query_table;
	REQ_MATCH_TABLE match_table;
	REQ_LOCATE_TABLE locate_table;
	REQ_READ_TABLE_ROW read_table_row;
	REQ_MARK_TABLE mark_table;
	REQ_GET_TABLE_ALL_PROPTAGS get_table_all_proptags;
	REQ_EXPAND_TABLE expand_table;
	REQ_COLLAPSE_TABLE collapse_table;
	REQ_STORE_TABLE_STATE store_table_state;
	REQ_RESTORE_TABLE_STATE restore_table_state;
	REQ_CHECK_MESSAGE check_message;
	REQ_CHECK_MESSAGE_DELETED check_message_deleted;
	REQ_LOAD_MESSAGE_INSTANCE load_message_instance;
	REQ_LOAD_EMBEDDED_INSTANCE load_embedded_instance;
	REQ_GET_EMBEDDED_CN get_embedded_cn;
	REQ_RELOAD_MESSAGE_INSTANCE reload_message_instance;
	REQ_CLEAR_MESSAGE_INSTANCE clear_message_instance;
	REQ_READ_MESSAGE_INSTANCE read_message_instance;
	REQ_WRITE_MESSAGE_INSTANCE write_message_instance;
	REQ_LOAD_ATTACHMENT_INSTANCE load_attachment_instance;
	REQ_CREATE_ATTACHMENT_INSTANCE create_attachment_instance;
	REQ_READ_ATTACHMENT_INSTANCE read_attachment_instance;
	REQ_WRITE_ATTACHMENT_INSTANCE write_attachment_instance;
	REQ_DELETE_MESSAGE_INSTANCE_ATTACHMENT delete_message_instance_attachment;
	REQ_FLUSH_INSTANCE flush_instance;
	REQ_UNLOAD_INSTANCE unload_instance;
	REQ_GET_INSTANCE_ALL_PROPTAGS get_instance_all_proptags;
	REQ_GET_INSTANCE_PROPERTIES get_instance_properties;
	REQ_SET_INSTANCE_PROPERTIES set_instance_properties;
	REQ_REMOVE_INSTANCE_PROPERTIES remove_instance_properties;
	REQ_CHECK_INSTANCE_CYCLE check_instance_cycle;
	REQ_EMPTY_MESSAGE_INSTANCE_RCPTS empty_message_instance_rcpts;
	REQ_GET_MESSAGE_INSTANCE_RCPTS_NUM get_message_instance_rcpts_num;
	REQ_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS get_message_instance_rcpts_all_proptags;
	REQ_GET_MESSAGE_INSTANCE_RCPTS get_message_instance_rcpts;
	REQ_UPDATE_MESSAGE_INSTANCE_RCPTS update_message_instance_rcpts;
	REQ_COPY_INSTANCE_RCPTS copy_instance_rcpts;
	REQ_EMPTY_MESSAGE_INSTANCE_ATTACHMENTS empty_message_instance_attachments;
	REQ_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM get_message_instance_attachments_num;
	REQ_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS get_message_instance_attachment_table_all_proptags;
	REQ_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE query_message_instance_attachment_table;
	REQ_COPY_INSTANCE_ATTACHMENTS copy_instance_attachments;
	REQ_SET_MESSAGE_INSTANCE_CONFLICT set_message_instance_conflict;
	REQ_GET_MESSAGE_RCPTS get_message_rcpts;
	REQ_GET_MESSAGE_PROPERTIES get_message_properties;
	REQ_SET_MESSAGE_PROPERTIES set_message_properties;
	REQ_SET_MESSAGE_READ_STATE set_message_read_state;
	REQ_REMOVE_MESSAGE_PROPERTIES remove_message_properties;
	REQ_ALLOCATE_MESSAGE_ID allocate_message_id;
	REQ_GET_MESSAGE_GROUP_ID get_message_group_id;
	REQ_SET_MESSAGE_GROUP_ID set_message_group_id;
	REQ_SAVE_CHANGE_INDICES save_change_indices;
	REQ_GET_CHANGE_INDICES get_change_indices;
	REQ_MARK_MODIFIED mark_modified;
	REQ_TRY_MARK_SUBMIT try_mark_submit;
	REQ_CLEAR_SUBMIT clear_submit;
	REQ_LINK_MESSAGE link_message;
	REQ_UNLINK_MESSAGE unlink_message;
	REQ_RULE_NEW_MESSAGE rule_new_message;
	REQ_SET_MESSAGE_TIMER set_message_timer;
	REQ_GET_MESSAGE_TIMER get_message_timer;
	REQ_EMPTY_FOLDER_PERMISSION empty_folder_permission;
	REQ_UPDATE_FOLDER_PERMISSION update_folder_permission;
	REQ_EMPTY_FOLDER_RULE empty_folder_rule;
	REQ_UPDATE_FOLDER_RULE update_folder_rule;
	REQ_DELIVERY_MESSAGE delivery_message;
	REQ_WRITE_MESSAGE write_message;
	REQ_READ_MESSAGE read_message;
	REQ_GET_CONTENT_SYNC get_content_sync;
	REQ_GET_HIERARCHY_SYNC get_hierarchy_sync;
	REQ_ALLOCATE_IDS allocate_ids;
	REQ_SUBSCRIBE_NOTIFICATION subscribe_notification;
	REQ_UNSUBSCRIBE_NOTIFICATION unsubscribe_notification;
	REQ_CHECK_CONTACT_ADDRESS check_contact_address;
	REQ_TRANSPORT_NEW_MAIL transport_new_mail;
};

struct EXMDB_REQUEST {
	uint8_t call_id;
	char *dir;
	REQUEST_PAYLOAD payload;
};

struct RESP_GET_ALL_NAMED_PROPIDS {
	PROPID_ARRAY propids;
};

struct RESP_GET_NAMED_PROPIDS {
	PROPID_ARRAY propids;
};

struct RESP_GET_NAMED_PROPNAMES {
	PROPNAME_ARRAY propnames;
};

struct RESP_GET_MAPPING_GUID {
	BOOL b_found;
	GUID guid;
};

struct RESP_GET_MAPPING_REPLID {
	BOOL b_found;
	uint16_t replid;
};

struct RESP_GET_STORE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct RESP_GET_STORE_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct RESP_SET_STORE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct RESP_CHECK_MAILBOX_PERMISSION {
	uint32_t permission;
};

struct RESP_GET_FOLDER_BY_CLASS {
	uint64_t id;
	char *str_explicit;
};

struct RESP_SET_FOLDER_BY_CLASS {
	BOOL b_result;
};

struct RESP_GET_FOLDER_CLASS_TABLE {
	TARRAY_SET table;
};

struct RESP_CHECK_FOLDER_ID {
	BOOL b_exist;
};

struct RESP_QUERY_FOLDER_MESSAGES {
	TARRAY_SET set;
};

struct RESP_CHECK_FOLDER_DELETED {
	BOOL b_del;
};

struct RESP_GET_FOLDER_BY_NAME {
	uint64_t folder_id;
};

struct RESP_CHECK_FOLDER_PERMISSION {
	uint32_t permission;
};

struct RESP_CREATE_FOLDER_BY_PROPERTIES {
	uint64_t folder_id;
};

struct RESP_GET_FOLDER_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct RESP_GET_FOLDER_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct RESP_SET_FOLDER_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct RESP_DELETE_FOLDER {
	BOOL b_result;
};

struct RESP_EMPTY_FOLDER {
	BOOL b_partial;
};

struct RESP_CHECK_FOLDER_CYCLE {
	BOOL b_cycle;
};

struct RESP_COPY_FOLDER_INTERNAL {
	BOOL b_collid;
	BOOL b_partial;
};

struct RESP_GET_SEARCH_CRITERIA {
	uint32_t search_status;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
};

struct RESP_SET_SEARCH_CRITERIA {
	BOOL b_result;
};

struct RESP_MOVECOPY_MESSAGE {
	BOOL b_result;
};

struct RESP_MOVECOPY_MESSAGES {
	BOOL b_partial;
};

struct RESP_MOVECOPY_FOLDER {
	BOOL b_exist;
	BOOL b_partial;
};

struct RESP_DELETE_MESSAGES {
	BOOL b_partial;
};

struct RESP_GET_MESSAGE_BRIEF {
	MESSAGE_CONTENT *pbrief;
};

struct RESP_SUM_HIERARCHY {
	uint32_t count;
};

struct RESP_LOAD_HIERARCHY_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct RESP_SUM_CONTENT {
	uint32_t count;
};

struct RESP_LOAD_CONTENT_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct RESP_LOAD_PERMISSION_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct RESP_LOAD_RULE_TABLE {
	uint32_t table_id;
	uint32_t row_count;
};

struct RESP_SUM_TABLE {
	uint32_t rows;
};

struct RESP_QUERY_TABLE {
	TARRAY_SET set;
};

struct RESP_MATCH_TABLE {
	int32_t position;
	TPROPVAL_ARRAY propvals;
};

struct RESP_LOCATE_TABLE {
	int32_t position;
	uint32_t row_type;
};

struct RESP_READ_TABLE_ROW {
	TPROPVAL_ARRAY propvals;
};

struct RESP_MARK_TABLE {
	uint64_t inst_id;
	uint32_t inst_num;
	uint32_t row_type;
};

struct RESP_GET_TABLE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct RESP_EXPAND_TABLE {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct RESP_COLLAPSE_TABLE {
	BOOL b_found;
	int32_t position;
	uint32_t row_count;
};

struct RESP_STORE_TABLE_STATE {
	uint32_t state_id;
};

struct RESP_RESTORE_TABLE_STATE {
	int32_t position;
};

struct RESP_CHECK_MESSAGE {
	BOOL b_exist;
};

struct RESP_CHECK_MESSAGE_DELETED {
	BOOL b_del;
};

struct RESP_LOAD_MESSAGE_INSTANCE {
	uint32_t instance_id;
};

struct RESP_LOAD_EMBEDDED_INSTANCE {
	uint32_t instance_id;
};

struct RESP_GET_EMBEDDED_CN {
	uint64_t *pcn;
};

struct RESP_RELOAD_MESSAGE_INSTANCE {
	BOOL b_result;
};

struct RESP_READ_MESSAGE_INSTANCE {
	MESSAGE_CONTENT msgctnt;
};

struct RESP_WRITE_MESSAGE_INSTANCE {
	PROPTAG_ARRAY proptags;
	PROBLEM_ARRAY problems;
};

struct RESP_LOAD_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
};

struct RESP_CREATE_ATTACHMENT_INSTANCE {
	uint32_t instance_id;
	uint32_t attachment_num;
};

struct RESP_READ_ATTACHMENT_INSTANCE {
	ATTACHMENT_CONTENT attctnt;
};

struct RESP_WRITE_ATTACHMENT_INSTANCE {
	PROBLEM_ARRAY problems;
};

struct RESP_FLUSH_INSTANCE {
	gxerr_t e_result;
};

struct RESP_GET_INSTANCE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct RESP_GET_INSTANCE_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct RESP_SET_INSTANCE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct RESP_REMOVE_INSTANCE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct RESP_CHECK_INSTANCE_CYCLE {
	BOOL b_cycle;
};

struct RESP_GET_MESSAGE_INSTANCE_RCPTS_NUM {
	uint16_t num;
};

struct RESP_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct RESP_GET_MESSAGE_INSTANCE_RCPTS {
	TARRAY_SET set;
};

struct RESP_COPY_INSTANCE_RCPTS {
	BOOL b_result;
};

struct RESP_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM {
	uint16_t num;
};

struct RESP_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS {
	PROPTAG_ARRAY proptags;
};

struct RESP_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE {
	TARRAY_SET set;
};

struct RESP_COPY_INSTANCE_ATTACHMENTS {
	BOOL b_result;
};

struct RESP_GET_MESSAGE_RCPTS {
	TARRAY_SET set;
};

struct RESP_GET_MESSAGE_PROPERTIES {
	TPROPVAL_ARRAY propvals;
};

struct RESP_SET_MESSAGE_PROPERTIES {
	PROBLEM_ARRAY problems;
};

struct RESP_SET_MESSAGE_READ_STATE {
	uint64_t read_cn;
};

struct RESP_ALLOCATE_MESSAGE_ID {
	uint64_t message_id;
};

struct RESP_ALLOCATE_CN {
	uint64_t cn;
};

struct RESP_GET_MESSAGE_GROUP_ID {
	uint32_t *pgroup_id;
};

struct RESP_GET_CHANGE_INDICES {
	INDEX_ARRAY indices;
	PROPTAG_ARRAY ungroup_proptags;
};

struct RESP_TRY_MARK_SUBMIT {
	BOOL b_marked;
};

struct RESP_LINK_MESSAGE {
	BOOL b_result;
};

struct RESP_GET_MESSAGE_TIMER {
	uint32_t *ptimer_id;
};

struct RESP_UPDATE_FOLDER_RULE {
	BOOL b_exceed;
};

struct RESP_DELIVERY_MESSAGE {
	uint32_t result;
};

struct RESP_WRITE_MESSAGE {
	gxerr_t e_result;
};

struct RESP_READ_MESSAGE {
	MESSAGE_CONTENT *pmsgctnt;
};

struct RESP_GET_CONTENT_SYNC {
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

struct RESP_GET_HIERARCHY_SYNC {
	FOLDER_CHANGES fldchgs;
	uint64_t last_cn;
	EID_ARRAY given_fids;
	EID_ARRAY deleted_fids;
};

struct RESP_ALLOCATE_IDS {
	uint64_t begin_eid;
};

struct RESP_SUBSCRIBE_NOTIFICATION {
	uint32_t sub_id;
};

struct RESP_CHECK_CONTACT_ADDRESS {
	BOOL b_found;
};

union RESPONSE_PAYLOAD {
	RESP_GET_ALL_NAMED_PROPIDS get_all_named_propids;
	RESP_GET_NAMED_PROPIDS get_named_propids;
	RESP_GET_NAMED_PROPNAMES get_named_propnames;
	RESP_GET_MAPPING_GUID get_mapping_guid;
	RESP_GET_MAPPING_REPLID get_mapping_replid;
	RESP_GET_STORE_ALL_PROPTAGS get_store_all_proptags;
	RESP_GET_STORE_PROPERTIES get_store_properties;
	RESP_SET_STORE_PROPERTIES set_store_properties;
	RESP_CHECK_MAILBOX_PERMISSION check_mailbox_permission;
	RESP_GET_FOLDER_BY_CLASS get_folder_by_class;
	RESP_SET_FOLDER_BY_CLASS set_folder_by_class;
	RESP_GET_FOLDER_CLASS_TABLE get_folder_class_table;
	RESP_CHECK_FOLDER_ID check_folder_id;
	RESP_QUERY_FOLDER_MESSAGES query_folder_messages;
	RESP_CHECK_FOLDER_DELETED check_folder_deleted;
	RESP_GET_FOLDER_BY_NAME get_folder_by_name;
	RESP_CHECK_FOLDER_PERMISSION check_folder_permission;
	RESP_CREATE_FOLDER_BY_PROPERTIES create_folder_by_properties;
	RESP_GET_FOLDER_ALL_PROPTAGS get_folder_all_proptags;
	RESP_GET_FOLDER_PROPERTIES get_folder_properties;
	RESP_SET_FOLDER_PROPERTIES set_folder_properties;
	RESP_DELETE_FOLDER delete_folder;
	RESP_EMPTY_FOLDER empty_folder;
	RESP_CHECK_FOLDER_CYCLE check_folder_cycle;
	RESP_COPY_FOLDER_INTERNAL copy_folder_internal;
	RESP_GET_SEARCH_CRITERIA get_search_criteria;
	RESP_SET_SEARCH_CRITERIA set_search_criteria;
	RESP_MOVECOPY_MESSAGE movecopy_message;
	RESP_MOVECOPY_MESSAGES movecopy_messages;
	RESP_MOVECOPY_FOLDER movecopy_folder;
	RESP_DELETE_MESSAGES delete_messages;
	RESP_GET_MESSAGE_BRIEF get_message_brief;
	RESP_SUM_HIERARCHY sum_hierarchy;
	RESP_LOAD_HIERARCHY_TABLE load_hierarchy_table;
	RESP_SUM_CONTENT sum_content;
	RESP_LOAD_CONTENT_TABLE load_content_table;
	RESP_LOAD_PERMISSION_TABLE load_permission_table;
	RESP_LOAD_RULE_TABLE load_rule_table;
	RESP_SUM_TABLE sum_table;
	RESP_QUERY_TABLE query_table;
	RESP_MATCH_TABLE match_table;
	RESP_LOCATE_TABLE locate_table;
	RESP_READ_TABLE_ROW read_table_row;
	RESP_MARK_TABLE mark_table;
	RESP_GET_TABLE_ALL_PROPTAGS get_table_all_proptags;
	RESP_EXPAND_TABLE expand_table;
	RESP_COLLAPSE_TABLE collapse_table;
	RESP_STORE_TABLE_STATE store_table_state;
	RESP_RESTORE_TABLE_STATE restore_table_state;
	RESP_CHECK_MESSAGE check_message;
	RESP_CHECK_MESSAGE_DELETED check_message_deleted;
	RESP_LOAD_MESSAGE_INSTANCE load_message_instance;
	RESP_LOAD_EMBEDDED_INSTANCE load_embedded_instance;
	RESP_GET_EMBEDDED_CN get_embedded_cn;
	RESP_RELOAD_MESSAGE_INSTANCE reload_message_instance;
	RESP_READ_MESSAGE_INSTANCE read_message_instance;
	RESP_WRITE_MESSAGE_INSTANCE write_message_instance;
	RESP_LOAD_ATTACHMENT_INSTANCE load_attachment_instance;
	RESP_CREATE_ATTACHMENT_INSTANCE create_attachment_instance;
	RESP_READ_ATTACHMENT_INSTANCE read_attachment_instance;
	RESP_WRITE_ATTACHMENT_INSTANCE write_attachment_instance;
	RESP_FLUSH_INSTANCE flush_instance;
	RESP_GET_INSTANCE_ALL_PROPTAGS get_instance_all_proptags;
	RESP_GET_INSTANCE_PROPERTIES get_instance_properties;
	RESP_SET_INSTANCE_PROPERTIES set_instance_properties;
	RESP_REMOVE_INSTANCE_PROPERTIES remove_instance_properties;
	RESP_CHECK_INSTANCE_CYCLE check_instance_cycle;
	RESP_GET_MESSAGE_INSTANCE_RCPTS_NUM get_message_instance_rcpts_num;
	RESP_GET_MESSAGE_INSTANCE_RCPTS_ALL_PROPTAGS get_message_instance_rcpts_all_proptags;
	RESP_GET_MESSAGE_INSTANCE_RCPTS get_message_instance_rcpts;
	RESP_COPY_INSTANCE_RCPTS copy_instance_rcpts;
	RESP_GET_MESSAGE_INSTANCE_ATTACHMENTS_NUM get_message_instance_attachments_num;
	RESP_GET_MESSAGE_INSTANCE_ATTACHMENT_TABLE_ALL_PROPTAGS get_message_instance_attachment_table_all_proptags;
	RESP_QUERY_MESSAGE_INSTANCE_ATTACHMENT_TABLE query_message_instance_attachment_table;
	RESP_COPY_INSTANCE_ATTACHMENTS copy_instance_attachments;
	RESP_GET_MESSAGE_RCPTS get_message_rcpts;
	RESP_GET_MESSAGE_PROPERTIES get_message_properties;
	RESP_SET_MESSAGE_PROPERTIES set_message_properties;
	RESP_SET_MESSAGE_READ_STATE set_message_read_state;
	RESP_ALLOCATE_MESSAGE_ID allocate_message_id;
	RESP_ALLOCATE_CN allocate_cn;
	RESP_GET_MESSAGE_GROUP_ID get_message_group_id;
	RESP_GET_CHANGE_INDICES get_change_indices;
	RESP_TRY_MARK_SUBMIT try_mark_submit;
	RESP_LINK_MESSAGE link_message;
	RESP_GET_MESSAGE_TIMER get_message_timer;
	RESP_UPDATE_FOLDER_RULE update_folder_rule;
	RESP_DELIVERY_MESSAGE delivery_message;
	RESP_WRITE_MESSAGE write_message;
	RESP_READ_MESSAGE read_message;
	RESP_GET_CONTENT_SYNC get_content_sync;
	RESP_GET_HIERARCHY_SYNC get_hierarchy_sync;
	RESP_ALLOCATE_IDS allocate_ids;
	RESP_SUBSCRIBE_NOTIFICATION subscribe_notification;
	RESP_CHECK_CONTACT_ADDRESS check_contact_address;
};

struct EXMDB_RESPONSE {
	uint8_t call_id;
	RESPONSE_PAYLOAD payload;
};

struct DB_NOTIFY_DATAGRAM {
	char *dir;
	BOOL b_table;
	LONG_ARRAY id_array;
	DB_NOTIFY db_notify;
};

extern void common_util_init();
extern int common_util_run();
extern int common_util_stop();
extern void common_util_free();
BOOL common_util_build_environment(const char *maildir);
extern void common_util_free_environment();
void* common_util_alloc(size_t size);
template<typename T> T *cu_alloc() { return static_cast<T *>(common_util_alloc(sizeof(T))); }
template<typename T> T *cu_alloc(size_t elem) { return static_cast<T *>(common_util_alloc(sizeof(T) * elem)); }
template<typename T> T *me_alloc() { return static_cast<T *>(malloc(sizeof(T))); }
template<typename T> T *me_alloc(size_t elem) { return static_cast<T *>(malloc(sizeof(T) * elem)); }
extern BOOL common_util_switch_allocator();
void common_util_set_maildir(const char *maildir);
extern const char* common_util_get_maildir();
char* common_util_dup(const char *pstr);
void* common_util_get_propvals(
	const TPROPVAL_ARRAY *parray, uint32_t proptag);

BINARY* common_util_xid_to_binary(uint8_t size, const XID *pxid);

BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid);

BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key);
	
BOOL common_util_create_folder(const char *dir, int user_id,
	uint64_t parent_id, const char *folder_name, uint64_t *pfolder_id);

BOOL common_util_get_propids(const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);
extern BOOL common_util_get_propids_create(const PROPNAME_ARRAY *, PROPID_ARRAY *);
BOOL common_util_get_propname(
	uint16_t propid, PROPERTY_NAME **pppropname);
