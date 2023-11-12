#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

struct rop_request {
	uint8_t rop_id;
	uint8_t logon_id;
	// meaning dependent on rop_id (OutputHandleIndex, InputHandleIndex,
	// SourceHandleIndex, ResposneHandleIndex)
	uint8_t hindex;
	BINARY rq_bookmark;
};
using ROP_REQUEST = rop_request;

struct rop_response {
	uint8_t rop_id;
	// meaning dependent on rop_id (OutputHandleIndex, InputHandleIndex, ..)
	uint8_t hindex;
	uint32_t result;
};
using ROP_RESPONSE = rop_response;

struct PARTIAL_COMPLETION_RESPONSE final : public rop_response {
	uint8_t partial_completion;
};

struct TABLE_STATUS_RESPONSE final : public rop_response {
	uint8_t table_status;
};

struct PROBLEM_RESPONSE final : public rop_response {
	PROBLEM_ARRAY problems;
};

struct LOGON_REQUEST final : public rop_request {
	uint8_t logon_flags;
	uint32_t open_flags;
	uint32_t store_stat;
	char *pessdn;
};

struct LOGON_PMB_RESPONSE final : public rop_response {
	uint8_t logon_flags;
	uint64_t folder_ids[13];
	uint8_t response_flags;
	GUID mailbox_guid;
	uint16_t replid;
	GUID replguid;
	LOGON_TIME logon_time;
	uint64_t gwart_time;
	uint32_t store_stat;
};

struct LOGON_PF_RESPONSE final : public rop_response {
	uint8_t logon_flags;
	uint64_t folder_ids[13];
	uint16_t replid;
	GUID replguid;
	GUID per_user_guid;
};

struct LOGON_REDIRECT_RESPONSE final : public rop_response {
	uint8_t logon_flags;
	char pserver_name[1024];
};

struct GETRECEIVEFOLDER_REQUEST final : public rop_request {
	char *pstr_class;
};

struct GETRECEIVEFOLDER_RESPONSE final : public rop_response {
	uint64_t folder_id;
	char *pstr_class;
};

struct SETRECEIVEFOLDER_REQUEST final : public rop_request {
	uint64_t folder_id;
	char * pstr_class;
};

struct GETRECEIVEFOLDERTABLE_RESPONSE final : public rop_response {
	PROPROW_SET rows;
};

struct GETSTORESTAT_RESPONSE final : public rop_response {
	uint32_t stat;
};

struct GETOWNINGSERVERS_REQUEST final : public rop_request {
	uint64_t folder_id;
};

struct GETOWNINGSERVERS_RESPONSE final : public rop_response {
	GHOST_SERVER ghost;
};

struct PUBLICFOLDERISGHOSTED_REQUEST final : public rop_request {
	uint64_t folder_id;
};

struct PUBLICFOLDERISGHOSTED_RESPONSE final : public rop_response {
	GHOST_SERVER *pghost;
};

struct LONGTERMIDFROMID_REQUEST final : public rop_request {
	uint64_t id;
};

struct LONGTERMIDFROMID_RESPONSE final : public rop_response {
	LONG_TERM_ID long_term_id;
};

struct IDFROMLONGTERMID_REQUEST final : public rop_request {
	LONG_TERM_ID long_term_id;
};

struct IDFROMLONGTERMID_RESPONSE final : public rop_response {
	uint64_t id;
};

struct GETPERUSERLONGTERMIDS_REQUEST final : public rop_request {
	GUID guid;
};

struct GETPERUSERLONGTERMIDS_RESPONSE final : public rop_response {
	LONG_TERM_ID_ARRAY ids;
};

struct GETPERUSERGUID_REQUEST final : public rop_request {
	LONG_TERM_ID long_term_id;
};

struct GETPERUSERGUID_RESPONSE final : public rop_response {
	GUID guid;
};

struct READPERUSERINFORMATION_REQUEST final : public rop_request {
	LONG_TERM_ID long_folder_id;
	uint8_t reserved;
	uint32_t data_offset;
	uint16_t max_data_size;
};

struct READPERUSERINFORMATION_RESPONSE final : public rop_response {
	uint8_t has_finished;
	BINARY data;
};

struct WRITEPERUSERINFORMATION_REQUEST final : public rop_request {
	LONG_TERM_ID long_folder_id;
	uint8_t has_finished;
	uint32_t offset;
	BINARY data;
	GUID *pguid;
};

struct OPENFOLDER_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint64_t folder_id;
	uint8_t open_flags;
};

struct OPENFOLDER_RESPONSE final : public rop_response {
	uint8_t has_rules;
	GHOST_SERVER *pghost;
};

struct CREATEFOLDER_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t folder_type;
	uint8_t use_unicode;
	uint8_t open_existing;
	uint8_t reserved;
	char *pfolder_name;
	char *pfolder_comment;
};

struct CREATEFOLDER_RESPONSE final : public rop_response {
	uint64_t folder_id;
	uint8_t is_existing;
	uint8_t has_rules;
	GHOST_SERVER *pghost;
};

struct DELETEFOLDER_REQUEST final : public rop_request {
	uint8_t flags;
	uint64_t folder_id;
};

struct SETSEARCHCRITERIA_REQUEST final : public rop_request {
	RESTRICTION *pres;
	LONGLONG_ARRAY folder_ids;
	uint32_t search_flags;
};

struct GETSEARCHCRITERIA_REQUEST final : public rop_request {
	uint8_t use_unicode;
	uint8_t include_restriction;
	uint8_t include_folders;
};

struct GETSEARCHCRITERIA_RESPONSE final : public rop_response {
	RESTRICTION *pres;
	uint8_t logon_id;
	LONGLONG_ARRAY folder_ids;
	uint32_t search_status;
};

struct MOVECOPYMESSAGES_REQUEST final : public rop_request {
	uint8_t dhindex;
	LONGLONG_ARRAY message_ids;
	uint8_t want_asynchronous;
	uint8_t want_copy;
};

/**
 * Alternate response for ropMoveCopyMessages, ropMoveFolder, ropCopyFolder.
 */
struct NULL_DST_RESPONSE final : public rop_response {
	uint32_t dhindex;
	uint8_t partial_completion;
};

/**
 * Alternate response for ropCopyProperties, ropCopyTo.
 */
struct NULL_DST1_RESPONSE final : public rop_response {
	uint32_t dhindex;
};

struct MOVEFOLDER_REQUEST final : public rop_request {
	uint8_t dhindex;
	uint8_t want_asynchronous;
	uint8_t use_unicode;
	uint64_t folder_id;
	char *pnew_name;
};

struct COPYFOLDER_REQUEST final : public rop_request {
	uint8_t dhindex;
	uint8_t want_asynchronous;
	uint8_t want_recursive;
	uint8_t use_unicode;
	uint64_t folder_id;
	char *pnew_name;
};

struct EMPTYFOLDER_REQUEST final : public rop_request {
	uint8_t want_asynchronous;
	uint8_t want_delete_associated;
};

struct HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST final : public rop_request {
	uint8_t want_asynchronous;
	uint8_t want_delete_associated;
};

struct DELETEMESSAGES_REQUEST final : public rop_request {
	uint8_t want_asynchronous;
	uint8_t notify_non_read;
	LONGLONG_ARRAY message_ids;
};

struct HARDDELETEMESSAGES_REQUEST final : public rop_request {
	uint8_t want_asynchronous;
	uint8_t notify_non_read;
	LONGLONG_ARRAY message_ids;
};

struct GETHIERARCHYTABLE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t table_flags;
};

struct GETHIERARCHYTABLE_RESPONSE final : public rop_response {
	uint32_t row_count;
};

struct GETCONTENTSTABLE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t table_flags;
};

struct GETCONTENTSTABLE_RESPONSE final : public rop_response {
	uint32_t row_count;
};

struct SETCOLUMNS_REQUEST final : public rop_request {
	uint8_t table_flags;
	PROPTAG_ARRAY proptags;
};

struct SORTTABLE_REQUEST final : public rop_request {
	uint8_t table_flags;
	SORTORDER_SET sort_criteria;
};

struct RESTRICT_REQUEST final : public rop_request {
	uint8_t res_flags;
	RESTRICTION *pres;
};

struct QUERYROWS_REQUEST final : public rop_request {
	uint8_t flags;
	uint8_t forward_read;
	uint16_t row_count;
};

struct QUERYROWS_RESPONSE final : public rop_response {
	uint8_t seek_pos;
	uint16_t count;
	BINARY bin_rows;
};

struct QUERYPOSITION_RESPONSE final : public rop_response {
	uint32_t numerator;
	uint32_t denominator;
};

struct SEEKROW_REQUEST final : public rop_request {
	uint8_t seek_pos;
	int32_t offset;
	uint8_t want_moved_count;
};

struct SEEKROW_RESPONSE final : public rop_response {
	uint8_t has_soughtless;
	int32_t offset_sought;
};

struct SEEKROWBOOKMARK_REQUEST final : public rop_request {
	BINARY bookmark;
	int32_t offset;
	uint8_t want_moved_count;
};

struct SEEKROWBOOKMARK_RESPONSE final : public rop_response {
	uint8_t row_invisible;
	uint8_t has_soughtless;
	uint32_t offset_sought;
};

struct SEEKROWFRACTIONAL_REQUEST final : public rop_request {
	uint32_t numerator;
	uint32_t denominator;
};

struct CREATEBOOKMARK_RESPONSE final : public rop_response {
	BINARY bookmark;
};

struct QUERYCOLUMNSALL_RESPONSE final : public rop_response {
	PROPTAG_ARRAY proptags;
};

struct FINDROW_REQUEST final : public rop_request {
	uint8_t flags;
	RESTRICTION *pres;
	uint8_t seek_pos;
	BINARY bookmark;
};

struct FINDROW_RESPONSE final : public rop_response {
	uint8_t bookmark_invisible;
	PROPERTY_ROW *prow;
	PROPTAG_ARRAY *pcolumns;
};

struct FREEBOOKMARK_REQUEST final : public rop_request {
	BINARY bookmark;
};

struct EXPANDROW_REQUEST final : public rop_request {
	uint16_t max_count;
	uint64_t category_id;
};

struct EXPANDROW_RESPONSE final : public rop_response {
	uint32_t expanded_count;
	uint16_t count;
	BINARY bin_rows;
};

struct COLLAPSEROW_REQUEST final : public rop_request {
	uint64_t category_id;
};

struct COLLAPSEROW_RESPONSE final : public rop_response {
	uint32_t collapsed_count;
};

struct GETCOLLAPSESTATE_REQUEST final : public rop_request {
	uint64_t row_id;
	uint32_t row_instance;
};

struct GETCOLLAPSESTATE_RESPONSE final : public rop_response {
	BINARY collapse_state;
};

struct SETCOLLAPSESTATE_REQUEST final : public rop_request {
	BINARY collapse_state;
};

struct SETCOLLAPSESTATE_RESPONSE final : public rop_response {
	BINARY bookmark;
};

struct OPENMESSAGE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint16_t cpid;
	uint64_t folder_id;
	uint8_t open_mode_flags;
	uint64_t message_id;
};

struct OPENMESSAGE_RESPONSE final : public rop_response {
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
};

struct CREATEMESSAGE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint16_t cpid;
	uint64_t folder_id;
	uint8_t associated_flag;
};

struct CREATEMESSAGE_RESPONSE final : public rop_response {
	uint64_t *pmessage_id;
};

struct SAVECHANGESMESSAGE_REQUEST final : public rop_request {
	uint8_t ihindex2;
	uint8_t save_flags;
};

struct SAVECHANGESMESSAGE_RESPONSE final : public rop_response {
	uint8_t ihindex2;
	uint64_t message_id;
};

struct REMOVEALLRECIPIENTS_REQUEST final : public rop_request {
	uint32_t reserved;
};

struct MODIFYRECIPIENTS_REQUEST final : public rop_request {
	PROPTAG_ARRAY proptags;
	uint16_t count;
	MODIFYRECIPIENT_ROW *prow;
};

struct READRECIPIENTS_REQUEST final : public rop_request {
	uint32_t row_id;
	uint16_t reserved;
};

struct READRECIPIENTS_RESPONSE final : public rop_response {
	uint8_t count;
	BINARY bin_recipients;
};

struct RELOADCACHEDINFORMATION_REQUEST final : public rop_request {
	uint16_t reserved;
};

struct RELOADCACHEDINFORMATION_RESPONSE final : public rop_response {
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
};

struct SETREADFLAGS_REQUEST final : public rop_request {
	uint8_t want_asynchronous;
	uint8_t read_flags;
	LONGLONG_ARRAY message_ids;
};

struct SETMESSAGESTATUS_REQUEST final : public rop_request {
	uint64_t message_id;
	uint32_t message_status;
	uint32_t status_mask;
};

struct SETMESSAGESTATUS_RESPONSE final : public rop_response {
	uint32_t message_status;
};

struct GETMESSAGESTATUS_REQUEST final : public rop_request {
	uint64_t message_id;
};

struct GETMESSAGESTATUS_RESPONSE final : public rop_response {
	uint32_t message_status;
};

struct SETMESSAGEREADFLAG_REQUEST final : public rop_request {
	uint8_t ihindex2;
	uint8_t flags;
	LONG_TERM_ID *pclient_data;
};

struct SETMESSAGEREADFLAG_RESPONSE final : public rop_response {
	uint8_t read_changed;
	uint8_t logon_id;
	LONG_TERM_ID *pclient_data;
};

struct OPENATTACHMENT_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t flags;
	uint32_t attachment_id;
};

struct CREATEATTACHMENT_REQUEST final : public rop_request {
	uint8_t ohindex;
};

struct CREATEATTACHMENT_RESPONSE final : public rop_response {
	uint32_t attachment_id;
};

struct DELETEATTACHMENT_REQUEST final : public rop_request {
	uint32_t attachment_id;
};

struct SAVECHANGESATTACHMENT_REQUEST final : public rop_request {
	uint8_t ihindex2;
	uint8_t save_flags;
};

struct OPENEMBEDDEDMESSAGE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint16_t cpid;
	uint8_t open_embedded_flags;
};

struct OPENEMBEDDEDMESSAGE_RESPONSE final : public rop_response {
	uint8_t reserved;
	uint64_t message_id;
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
};

struct GETATTACHMENTTABLE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t table_flags;
};

struct GETVALIDATTACHMENTS_RESPONSE final : public rop_response {
	LONG_ARRAY attachment_ids;
};

struct SUBMITMESSAGE_REQUEST final : public rop_request {
	uint8_t submit_flags;
};

struct ABORTSUBMIT_REQUEST final : public rop_request {
	uint64_t folder_id;
	uint64_t message_id;
};

struct GETADDRESSTYPES_RESPONSE final : public rop_response {
	STRING_ARRAY address_types;
};

struct SPOOLERLOCKMESSAGE_REQUEST final : public rop_request {
	uint64_t message_id;
	uint8_t lock_stat;
};

struct TRANSPORTSEND_RESPONSE final : public rop_response {
	TPROPVAL_ARRAY *ppropvals;
};

struct TRANSPORTNEWMAIL_REQUEST final : public rop_request {
	uint64_t message_id;
	uint64_t folder_id;
	char *pstr_class;
	uint32_t message_flags;
};

struct GETTRANSPORTFOLDER_RESPONSE final : public rop_response {
	uint64_t folder_id;
};

struct OPTIONSDATA_REQUEST final : public rop_request {
	char *paddress_type;
	uint8_t want_win32;
};

struct OPTIONSDATA_RESPONSE final : public rop_response {
	uint8_t reserved;
	BINARY options_info;
	BINARY help_file;
	char *pfile_name;
};

struct GETPROPERTYIDSFROMNAMES_REQUEST final : public rop_request {
	uint8_t flags;
	PROPNAME_ARRAY propnames;
};

struct GETPROPERTYIDSFROMNAMES_RESPONSE final : public rop_response {
	PROPID_ARRAY propids;
};

struct GETNAMESFROMPROPERTYIDS_REQUEST final : public rop_request {
	PROPID_ARRAY propids;
};

struct GETNAMESFROMPROPERTYIDS_RESPONSE final : public rop_response {
	PROPNAME_ARRAY propnames;
};

struct GETPROPERTIESSPECIFIC_REQUEST final : public rop_request {
	uint16_t size_limit;
	uint16_t want_unicode;
	PROPTAG_ARRAY proptags;
};

struct GETPROPERTIESSPECIFIC_RESPONSE final : public rop_response {
	PROPTAG_ARRAY *pproptags;    /* only for pushing row data into stream */
	PROPERTY_ROW row;
};

struct GETPROPERTIESALL_REQUEST final : public rop_request {
	uint16_t size_limit;
	uint16_t want_unicode;
};

struct GETPROPERTIESALL_RESPONSE final : public rop_response {
	TPROPVAL_ARRAY propvals;
};

struct GETPROPERTIESLIST_RESPONSE final : public rop_response {
	PROPTAG_ARRAY proptags;
};

struct SETPROPERTIES_REQUEST final : public rop_request {
	TPROPVAL_ARRAY propvals;
};

struct SETPROPERTIESNOREPLICATE_REQUEST final : public rop_request {
	TPROPVAL_ARRAY propvals;
};

struct DELETEPROPERTIES_REQUEST final : public rop_request {
	PROPTAG_ARRAY proptags;
};

struct DELETEPROPERTIESNOREPLICATE_REQUEST final : public rop_request {
	PROPTAG_ARRAY proptags;
};

struct QUERYNAMEDPROPERTIES_REQUEST final : public rop_request {
	uint8_t query_flags;
	GUID *pguid;
};

struct QUERYNAMEDPROPERTIES_RESPONSE final : public rop_response {
	PROPIDNAME_ARRAY propidnames;
};

struct COPYPROPERTIES_REQUEST final : public rop_request {
	uint8_t dhindex;
	uint8_t want_asynchronous;
	uint8_t copy_flags;
	PROPTAG_ARRAY proptags;
};

struct COPYTO_REQUEST final : public rop_request {
	uint8_t dhindex;
	uint8_t want_asynchronous;
	uint8_t want_subobjects;
	uint8_t copy_flags;
	PROPTAG_ARRAY excluded_proptags;
};

struct PROGRESS_REQUEST final : public rop_request {
	uint8_t want_cancel;
};

struct PROGRESS_RESPONSE final : public rop_response {
	uint8_t logon_id;
	uint32_t completed_count;
	uint32_t total_count;
};

struct OPENSTREAM_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint32_t proptag;
	uint8_t flags;
};

struct OPENSTREAM_RESPONSE final : public rop_response {
	uint32_t stream_size;
};

struct READSTREAM_REQUEST final : public rop_request {
	uint16_t byte_count;
	uint32_t max_byte_count;
};

struct READSTREAM_RESPONSE final : public rop_response {
	BINARY data;
};

struct WRITESTREAM_REQUEST final : public rop_request {
	BINARY data;
};

struct WRITESTREAM_RESPONSE final : public rop_response {
	uint16_t written_size;
};

struct GETSTREAMSIZE_RESPONSE final : public rop_response {
	uint32_t stream_size;
};

struct SETSTREAMSIZE_REQUEST final : public rop_request {
	uint64_t stream_size;
};

struct SEEKSTREAM_REQUEST final : public rop_request {
	uint8_t seek_pos;
	int64_t offset;
};

struct SEEKSTREAM_RESPONSE final : public rop_response {
	uint64_t new_pos;
};

struct COPYTOSTREAM_REQUEST final : public rop_request {
	uint8_t dhindex;
	uint64_t byte_count;
};

struct COPYTOSTREAM_RESPONSE final : public rop_response {
	uint64_t read_bytes;
	uint64_t written_bytes;
};

/**
 * Alternate response for ropCopyToStream.
 */
struct COPYTOSTREAM_NULL_DEST_RESPONSE final : public rop_response {
	uint32_t dhindex;
	uint64_t read_bytes;
	uint64_t written_bytes;
};

struct LOCKREGIONSTREAM_REQUEST final : public rop_request {
	uint64_t region_offset;
	uint64_t region_size;
	uint32_t lock_flags;
};

struct UNLOCKREGIONSTREAM_REQUEST final : public rop_request {
	uint64_t region_offset;
	uint64_t region_size;
	uint32_t lock_flags;
};

struct WRITEANDCOMMITSTREAM_REQUEST final : public rop_request {
	BINARY data;
};

struct WRITEANDCOMMITSTREAM_RESPONSE final : public rop_response {
	uint16_t written_size;
};

struct CLONESTREAM_REQUEST final : public rop_request {
	uint8_t ohindex;
};

struct MODIFYPERMISSIONS_REQUEST final : public rop_request {
	uint8_t flags;
	uint16_t count;
	PERMISSION_DATA *prow;
};

struct GETPERMISSIONSTABLE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t flags;
};

struct MODIFYRULES_REQUEST final : public rop_request {
	uint8_t flags;
	uint16_t count;
	RULE_DATA *prow;
};

struct GETRULESTABLE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t flags;
};

struct UPDATEDEFERREDACTIONMESSAGES_REQUEST final : public rop_request {
	BINARY server_entry_id;
	BINARY client_entry_id;
};

struct FASTTRANSFERDESTCONFIGURE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t source_operation;
	uint8_t flags;
};

struct FASTTRANSFERDESTPUTBUFFER_REQUEST final : public rop_request {
	BINARY transfer_data;
};

struct FASTTRANSFERDESTPUTBUFFER_RESPONSE final : public rop_response {
	uint16_t transfer_status;
	uint16_t in_progress_count;
	uint16_t total_step_count;
	uint8_t reserved;
	uint16_t used_size;
};

struct FASTTRANSFERSOURCEGETBUFFER_REQUEST final : public rop_request {
	uint16_t buffer_size;
	uint16_t max_buffer_size;
};

struct FASTTRANSFERSOURCEGETBUFFER_RESPONSE final : public rop_response {
	uint16_t transfer_status;
	uint16_t in_progress_count;
	uint16_t total_step_count;
	uint8_t reserved;
	BINARY transfer_data;
};

struct FASTTRANSFERSOURCECOPYFOLDER_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t flags;
	uint8_t send_options;
};

struct FASTTRANSFERSOURCECOPYMESSAGES_REQUEST final : public rop_request {
	uint8_t ohindex;
	LONGLONG_ARRAY message_ids;
	uint8_t flags;
	uint8_t send_options;
};

struct FASTTRANSFERSOURCECOPYTO_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t level;
	uint32_t flags;
	uint8_t send_options;
	PROPTAG_ARRAY proptags;
};

struct FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t level;
	uint8_t flags;
	uint8_t send_options;
	PROPTAG_ARRAY proptags;
};

struct TELLVERSION_REQUEST final : public rop_request {
	uint16_t version[3];
};

struct SYNCCONFIGURE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t sync_type;
	uint8_t send_options;
	uint16_t sync_flags;
	RESTRICTION *pres;
	uint32_t extra_flags;
	PROPTAG_ARRAY proptags;
};

struct SYNCIMPORTMESSAGECHANGE_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t import_flags;
	TPROPVAL_ARRAY propvals;
};

struct SYNCIMPORTMESSAGECHANGE_RESPONSE final : public rop_response {
	uint64_t message_id;
};

struct SYNCIMPORTREADSTATECHANGES_REQUEST final : public rop_request {
	uint16_t count;
	MESSAGE_READ_STAT *pread_stat;
};

struct SYNCIMPORTHIERARCHYCHANGE_REQUEST final : public rop_request {
	TPROPVAL_ARRAY hichyvals;
	TPROPVAL_ARRAY propvals;
};

struct SYNCIMPORTHIERARCHYCHANGE_RESPONSE final : public rop_response {
	uint64_t folder_id;
};

struct SYNCIMPORTDELETES_REQUEST final : public rop_request {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
};

struct SYNCIMPORTMESSAGEMOVE_REQUEST final : public rop_request {
	BINARY src_folder_id;
	BINARY src_message_id;
	BINARY change_list;
	BINARY dst_message_id;
	BINARY change_number;
};

struct SYNCIMPORTMESSAGEMOVE_RESPONSE final : public rop_response {
	uint64_t message_id;
};

struct SYNCOPENCOLLECTOR_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t is_content_collector;
};

struct SYNCGETTRANSFERSTATE_REQUEST final : public rop_request {
	uint8_t ohindex;
};

struct SYNCUPLOADSTATESTREAMBEGIN_REQUEST final : public rop_request {
	uint32_t proptag_stat;
	uint32_t buffer_size;
};

struct SYNCUPLOADSTATESTREAMCONTINUE_REQUEST final : public rop_request {
	BINARY stream_data;
};

struct SETLOCALREPLICAMIDSETDELETED_REQUEST final : public rop_request {
	uint32_t count;
	LONG_TERM_ID_RANGE *prange;
};

struct GETLOCALREPLICAIDS_REQUEST final : public rop_request {
	uint32_t count;
};

struct GETLOCALREPLICAIDS_RESPONSE final : public rop_response {
	GUID replguid;
	GLOBCNT global_count;
};

struct REGISTERNOTIFICATION_REQUEST final : public rop_request {
	uint8_t ohindex;
	uint8_t notification_types;
	uint8_t reserved;
	uint8_t want_whole_store;
	uint64_t *pfolder_id;
	uint64_t *pmessage_id;
};

struct PENDING_RESPONSE final : public rop_response {
	uint16_t session_index;
};

struct BACKOFF_RESPONSE /* nobase */ {
	uint8_t rop_id;
	uint8_t logon_id;
	uint32_t duration;
	uint8_t rop_count;
	struct BACKOFF_ROP *prop_data;
	BINARY additional_data;
};

struct BUFFERTOOSMALL_RESPONSE final : public rop_response {
	uint16_t size_needed;
	BINARY buffer;
};

using DELETEFOLDER_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using MOVECOPYMESSAGES_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using MOVEFOLDER_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using COPYFOLDER_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using EMPTYFOLDER_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using DELETEMESSAGES_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using HARDDELETEMESSAGES_RESPONSE = PARTIAL_COMPLETION_RESPONSE;
using SETREADFLAGS_RESPONSE = PARTIAL_COMPLETION_RESPONSE;

using SETCOLUMNS_RESPONSE = TABLE_STATUS_RESPONSE;
using SORTTABLE_RESPONSE = TABLE_STATUS_RESPONSE;
using RESTRICT_RESPONSE = TABLE_STATUS_RESPONSE;
using ABORT_RESPONSE = TABLE_STATUS_RESPONSE;
using GETSTATUS_RESPONSE = TABLE_STATUS_RESPONSE;

using SETPROPERTIES_RESPONSE = PROBLEM_RESPONSE;
using SETPROPERTIESNOREPLICATE_RESPONSE = PROBLEM_RESPONSE;
using DELETEPROPERTIES_RESPONSE = PROBLEM_RESPONSE;
using DELETEPROPERTIESNOREPLICATE_RESPONSE = PROBLEM_RESPONSE;
using COPYPROPERTIES_RESPONSE = PROBLEM_RESPONSE;
using COPYTO_RESPONSE = PROBLEM_RESPONSE;

/* end of rop request and response structure */

/**
 * @hnum:	amount of room in the phandles array in this
 *              request/response pair
 * @phandles:	a list of server object handles (akin to file descriptors)
 *              used for ROPs
 */
struct ROP_BUFFER {
	uint16_t rhe_version;
	uint16_t rhe_flags;
	DOUBLE_LIST rop_list;
	uint8_t hnum;
	uint32_t *phandles;
};
