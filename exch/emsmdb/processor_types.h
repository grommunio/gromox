#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>

struct LOGON_REQUEST {
	uint8_t logon_flags;
	uint32_t open_flags;
	uint32_t store_stat;
	char *pessdn;
};

struct LOGON_PMB_RESPONSE {
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

struct LOGON_PF_RESPONSE {
	uint8_t logon_flags;
	uint64_t folder_ids[13];
	uint16_t replid;
	GUID replguid;
	GUID per_user_guid;
};

struct LOGON_REDIRECT_RESPONSE {
	uint8_t logon_flags;
	char pserver_name[1024];
};

struct GETRECEIVEFOLDER_REQUEST {
	char *pstr_class;
};

struct GETRECEIVEFOLDER_RESPONSE {
	uint64_t folder_id;
	char *pstr_class;
};

struct SETRECEIVEFOLDER_REQUEST {
	uint64_t folder_id;
	char * pstr_class;
};

struct GETRECEIVEFOLDERTABLE_RESPONSE {
	PROPROW_SET rows;
};

struct GETSTORESTAT_RESPONSE {
	uint32_t stat;
};

struct GETOWNINGSERVERS_REQUEST {
	uint64_t folder_id;
};

struct GETOWNINGSERVERS_RESPONSE {
	GHOST_SERVER ghost;
};

struct PUBLICFOLDERISGHOSTED_REQUEST {
	uint64_t folder_id;
};

struct PUBLICFOLDERISGHOSTED_RESPONSE {
	GHOST_SERVER *pghost;
};

struct LONGTERMIDFROMID_REQUEST {
	uint64_t id;
};

struct LONGTERMIDFROMID_RESPONSE {
	LONG_TERM_ID long_term_id;
};

struct IDFROMLONGTERMID_REQUEST {
	LONG_TERM_ID long_term_id;
};

struct IDFROMLONGTERMID_RESPONSE {
	uint64_t id;
};

struct GETPERUSERLONGTERMIDS_REQUEST {
	GUID guid;
};

struct GETPERUSERLONGTERMIDS_RESPONSE {
	LONG_TERM_ID_ARRAY ids;
};

struct GETPERUSERGUID_REQUEST {
	LONG_TERM_ID long_term_id;
};

struct GETPERUSERGUID_RESPONSE {
	GUID guid;
};

struct READPERUSERINFORMATION_REQUEST {
	LONG_TERM_ID long_folder_id;
	uint8_t reserved;
	uint32_t data_offset;
	uint16_t max_data_size;
};

struct READPERUSERINFORMATION_RESPONSE {
	uint8_t has_finished;
	BINARY data;
};

struct WRITEPERUSERINFORMATION_REQUEST {
	LONG_TERM_ID long_folder_id;
	uint8_t has_finished;
	uint32_t offset;
	BINARY data;
	GUID *pguid;
};

struct OPENFOLDER_REQUEST {
	uint8_t hindex;
	uint64_t folder_id;
	uint8_t open_flags;
};

struct OPENFOLDER_RESPONSE {
	uint8_t has_rules;
	GHOST_SERVER *pghost;
};

struct CREATEFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t folder_type;
	uint8_t use_unicode;
	uint8_t open_existing;
	uint8_t reserved;
	char *pfolder_name;
	char *pfolder_comment;
};

struct CREATEFOLDER_RESPONSE {
	uint64_t folder_id;
	uint8_t is_existing;
	uint8_t has_rules;
	GHOST_SERVER *pghost;
};

struct DELETEFOLDER_REQUEST {
	uint8_t flags;
	uint64_t folder_id;
};

struct DELETEFOLDER_RESPONSE {
	uint8_t partial_completion;
};


struct SETSEARCHCRITERIA_REQUEST {
	RESTRICTION *pres;
	LONGLONG_ARRAY folder_ids;
	uint32_t search_flags;
};

struct GETSEARCHCRITERIA_REQUEST {
	uint8_t use_unicode;
	uint8_t include_restriction;
	uint8_t include_folders;
};

struct GETSEARCHCRITERIA_RESPONSE {
	RESTRICTION *pres;
	uint8_t logon_id;
	LONGLONG_ARRAY folder_ids;
	uint32_t search_status;
};

struct MOVECOPYMESSAGES_REQUEST {
	uint8_t hindex;
	LONGLONG_ARRAY message_ids;
	uint8_t want_asynchronous;
	uint8_t want_copy;
};

struct MOVECOPYMESSAGES_RESPONSE {
	uint8_t partial_completion;
};

struct NULL_DST_RESPONSE {
	uint32_t hindex;
	uint8_t partial_completion;
};

struct MOVEFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t use_unicode;
	uint64_t folder_id;
	char *pnew_name;
};

struct MOVEFOLDER_RESPONSE {
	uint8_t partial_completion;
};

struct COPYFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t want_recursive;
	uint8_t use_unicode;
	uint64_t folder_id;
	char *pnew_name;
};

struct COPYFOLDER_RESPONSE {
	uint8_t partial_completion;
};

struct EMPTYFOLDER_REQUEST {
	uint8_t want_asynchronous;
	uint8_t want_delete_associated;
};

struct EMPTYFOLDER_RESPONSE {
	uint8_t partial_completion;
};

struct HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST {
	uint8_t want_asynchronous;
	uint8_t want_delete_associated;
};

struct HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE {
	uint8_t partial_completion;
};

struct DELETEMESSAGES_REQUEST {
	uint8_t want_asynchronous;
	uint8_t notify_non_read;
	LONGLONG_ARRAY message_ids;
};

struct DELETEMESSAGES_RESPONSE {
	uint8_t partial_completion;
};

struct HARDDELETEMESSAGES_REQUEST {
	uint8_t want_asynchronous;
	uint8_t notify_non_read;
	LONGLONG_ARRAY message_ids;
};

struct HARDDELETEMESSAGES_RESPONSE {
	uint8_t partial_completion;
};

struct GETHIERARCHYTABLE_REQUEST {
	uint8_t hindex;
	uint8_t table_flags;
};

struct GETHIERARCHYTABLE_RESPONSE {
	uint32_t row_count;
};

struct GETCONTENTSTABLE_REQUEST {
	uint8_t hindex;
	uint8_t table_flags;
};

struct GETCONTENTSTABLE_RESPONSE {
	uint32_t row_count;
};


struct SETCOLUMNS_REQUEST {
	uint8_t table_flags;
	PROPTAG_ARRAY proptags;
};

struct SETCOLUMNS_RESPONSE {
	uint8_t table_status;
};

struct SORTTABLE_REQUEST {
	uint8_t table_flags;
	SORTORDER_SET sort_criteria;
};

struct SORTTABLE_RESPONSE {
	uint8_t table_status;
};

struct RESTRICT_REQUEST {
	uint8_t res_flags;
	RESTRICTION *pres;
};

struct RESTRICT_RESPONSE {
	uint8_t table_status;
};

struct QUERYROWS_REQUEST {
	uint8_t flags;
	uint8_t forward_read;
	uint16_t row_count;
};

struct QUERYROWS_RESPONSE {
	uint8_t seek_pos;
	uint16_t count;
	BINARY bin_rows;
};

struct ABORT_RESPONSE {
	uint8_t table_status;
};

struct GETSTATUS_RESPONSE {
	uint8_t table_status;
};

struct QUERYPOSITION_RESPONSE {
	uint32_t numerator;
	uint32_t denominator;
};

struct SEEKROW_REQUEST {
	uint8_t seek_pos;
	int32_t offset;
	uint8_t want_moved_count;
};

struct SEEKROW_RESPONSE {
	uint8_t has_soughtless;
	int32_t offset_sought;
};

struct SEEKROWBOOKMARK_REQUEST {
	BINARY bookmark;
	int32_t offset;
	uint8_t want_moved_count;
};

struct SEEKROWBOOKMARK_RESPONSE {
	uint8_t row_invisible;
	uint8_t has_soughtless;
	uint32_t offset_sought;
};

struct SEEKROWFRACTIONAL_REQUEST {
	uint32_t numerator;
	uint32_t denominator;
};

struct CREATEBOOKMARK_RESPONSE {
	BINARY bookmark;
};

struct QUERYCOLUMNSALL_RESPONSE {
	PROPTAG_ARRAY proptags;
};

struct FINDROW_REQUEST {
	uint8_t flags;
	RESTRICTION *pres;
	uint8_t seek_pos;
	BINARY bookmark;
};

struct FINDROW_RESPONSE {
	uint8_t bookmark_invisible;
	PROPERTY_ROW *prow;
	PROPTAG_ARRAY *pcolumns;
};

struct FREEBOOKMARK_REQUEST {
	BINARY bookmark;
};

struct EXPANDROW_REQUEST {
	uint16_t max_count;
	uint64_t category_id;
};

struct EXPANDROW_RESPONSE {
	uint32_t expanded_count;
	uint16_t count;
	BINARY bin_rows;
};

struct COLLAPSEROW_REQUEST {
	uint64_t category_id;
};

struct COLLAPSEROW_RESPONSE {
	uint32_t collapsed_count;
};

struct GETCOLLAPSESTATE_REQUEST {
	uint64_t row_id;
	uint32_t row_instance;
};

struct GETCOLLAPSESTATE_RESPONSE {
	BINARY collapse_state;
};

struct SETCOLLAPSESTATE_REQUEST {
	BINARY collapse_state;
};

struct SETCOLLAPSESTATE_RESPONSE {
	BINARY bookmark;
};

struct OPENMESSAGE_REQUEST {
	uint8_t hindex;
	uint16_t cpid;
	uint64_t folder_id;
	uint8_t open_mode_flags;
	uint64_t message_id;
};


struct OPENMESSAGE_RESPONSE {
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
};


struct CREATEMESSAGE_REQUEST {
	uint8_t hindex;
	uint16_t cpid;
	uint64_t folder_id;
	uint8_t associated_flag;
};

struct CREATEMESSAGE_RESPONSE {
	uint64_t *pmessage_id;
};

struct SAVECHANGESMESSAGE_REQUEST {
	uint8_t hindex;
	uint8_t save_flags;
};

struct SAVECHANGESMESSAGE_RESPONSE {
	uint8_t hindex;
	uint64_t message_id;
};

struct REMOVEALLRECIPIENTS_REQUEST {
	uint32_t reserved;
};

struct MODIFYRECIPIENTS_REQUEST {
	PROPTAG_ARRAY proptags;
	uint16_t count;
	MODIFYRECIPIENT_ROW *prow;
};

struct READRECIPIENTS_REQUEST {
	uint32_t row_id;
	uint16_t reserved;
};

struct READRECIPIENTS_RESPONSE {
	uint8_t count;
	BINARY bin_recipients;
};

struct RELOADCACHEDINFORMATION_REQUEST {
	uint16_t reserved;
};

struct RELOADCACHEDINFORMATION_RESPONSE {
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
};

struct SETREADFLAGS_REQUEST {
	uint8_t want_asynchronous;
	uint8_t read_flags;
	LONGLONG_ARRAY message_ids;
};

struct SETMESSAGESTATUS_REQUEST {
	uint64_t message_id;
	uint32_t message_status;
	uint32_t status_mask;
};

struct SETMESSAGESTATUS_RESPONSE {
	uint32_t message_status;
};

struct GETMESSAGESTATUS_REQUEST {
	uint64_t message_id;
};

struct GETMESSAGESTATUS_RESPONSE {
	uint32_t message_status;
};

struct SETREADFLAGS_RESPONSE {
	uint8_t partial_completion;
};

struct SETMESSAGEREADFLAG_REQUEST {
	uint8_t hindex;
	uint8_t flags;
	LONG_TERM_ID *pclient_data;
};

struct SETMESSAGEREADFLAG_RESPONSE {
	uint8_t read_changed;
	uint8_t logon_id;
	LONG_TERM_ID *pclient_data;
};

struct OPENATTACHMENT_REQUEST {
	uint8_t hindex;
	uint8_t flags;
	uint32_t attachment_id;
};

struct CREATEATTACHMENT_REQUEST {
	uint8_t hindex;
};

struct CREATEATTACHMENT_RESPONSE {
	uint32_t attachment_id;
};

struct DELETEATTACHMENT_REQUEST {
	uint32_t attachment_id;
};

struct SAVECHANGESATTACHMENT_REQUEST {
	uint8_t hindex;
	uint8_t save_flags;
};

struct OPENEMBEDDEDMESSAGE_REQUEST {
	uint8_t hindex;
	uint16_t cpid;
	uint8_t open_embedded_flags;
};

struct OPENEMBEDDEDMESSAGE_RESPONSE {
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

struct GETATTACHMENTTABLE_REQUEST {
	uint8_t hindex;
	uint8_t table_flags;
};

struct GETVALIDATTACHMENTS_RESPONSE {
	LONG_ARRAY attachment_ids;
};

struct SUBMITMESSAGE_REQUEST {
	uint8_t submit_flags;
};

struct ABORTSUBMIT_REQUEST {
	uint64_t folder_id;
	uint64_t message_id;
};

struct GETADDRESSTYPES_RESPONSE {
	STRING_ARRAY address_types;
};

struct SPOOLERLOCKMESSAGE_REQUEST {
	uint64_t message_id;
	uint8_t lock_stat;
};

struct TRANSPORTSEND_RESPONSE {
	TPROPVAL_ARRAY *ppropvals;
};

struct TRANSPORTNEWMAIL_REQUEST {
	uint64_t message_id;
	uint64_t folder_id;
	char *pstr_class;
	uint32_t message_flags;
};

struct GETTRANSPORTFOLDER_RESPONSE {
	uint64_t folder_id;
};

struct OPTIONSDATA_REQUEST {
	char *paddress_type;
	uint8_t want_win32;
};

struct OPTIONSDATA_RESPONSE {
	uint8_t reserved;
	BINARY options_info;
	BINARY help_file;
	char *pfile_name;
};

struct GETPROPERTYIDSFROMNAMES_REQUEST {
	uint8_t flags;
	PROPNAME_ARRAY propnames;
};

struct GETPROPERTYIDSFROMNAMES_RESPONSE {
	PROPID_ARRAY propids;
};

struct GETNAMESFROMPROPERTYIDS_REQUEST {
	PROPID_ARRAY propids;
};

struct GETNAMESFROMPROPERTYIDS_RESPONSE {
	PROPNAME_ARRAY propnames;
};

struct GETPROPERTIESSPECIFIC_REQUEST {
	uint16_t size_limit;
	uint16_t want_unicode;
	PROPTAG_ARRAY proptags;
};

struct GETPROPERTIESSPECIFIC_RESPONSE {
	PROPTAG_ARRAY *pproptags;    /* only for pushing row data into stream */
	PROPERTY_ROW row;
};

struct GETPROPERTIESALL_REQUEST {
	uint16_t size_limit;
	uint16_t want_unicode;
};

struct GETPROPERTIESALL_RESPONSE {
	TPROPVAL_ARRAY propvals;
};

struct GETPROPERTIESLIST_RESPONSE {
	PROPTAG_ARRAY proptags;
};

struct SETPROPERTIES_REQUEST {
	TPROPVAL_ARRAY propvals;
};

struct SETPROPERTIES_RESPONSE {
	PROBLEM_ARRAY problems;
};

struct SETPROPERTIESNOREPLICATE_REQUEST {
	TPROPVAL_ARRAY propvals;
};

struct SETPROPERTIESNOREPLICATE_RESPONSE {
	PROBLEM_ARRAY problems;
};

struct DELETEPROPERTIES_REQUEST {
	PROPTAG_ARRAY proptags;
};

struct DELETEPROPERTIES_RESPONSE {
	PROBLEM_ARRAY problems;
};

struct DELETEPROPERTIESNOREPLICATE_REQUEST {
	PROPTAG_ARRAY proptags;
};

struct DELETEPROPERTIESNOREPLICATE_RESPONSE {
	PROBLEM_ARRAY problems;
};

struct QUERYNAMEDPROPERTIES_REQUEST {
	uint8_t query_flags;
	GUID *pguid;
};

struct QUERYNAMEDPROPERTIES_RESPONSE {
	PROPIDNAME_ARRAY propidnames;
};

struct COPYPROPERTIES_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t copy_flags;
	PROPTAG_ARRAY proptags;
};

struct COPYPROPERTIES_RESPONSE {
	PROBLEM_ARRAY problems;
};

struct COPYTO_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t want_subobjects;
	uint8_t copy_flags;
	PROPTAG_ARRAY excluded_proptags;
};

struct COPYTO_RESPONSE {
	PROBLEM_ARRAY problems;
};

struct PROGRESS_REQUEST {
	uint8_t want_cancel;
};

struct PROGRESS_RESPONSE {
	uint8_t logon_id;
	uint32_t completed_count;
	uint32_t total_count;
};

struct OPENSTREAM_REQUEST {
	uint8_t hindex;
	uint32_t proptag;
	uint8_t flags;
};

struct OPENSTREAM_RESPONSE {
	uint32_t stream_size;
};

struct READSTREAM_REQUEST {
	uint16_t byte_count;
	uint32_t max_byte_count;
};

struct READSTREAM_RESPONSE {
	BINARY data;
};

struct WRITESTREAM_REQUEST {
	BINARY data;
};

struct WRITESTREAM_RESPONSE {
	uint16_t written_size;
};

struct GETSTREAMSIZE_RESPONSE {
	uint32_t stream_size;
};

struct SETSTREAMSIZE_REQUEST {
	uint64_t stream_size;
};

struct SEEKSTREAM_REQUEST {
	uint8_t seek_pos;
	int64_t offset;
};

struct SEEKSTREAM_RESPONSE {
	uint64_t new_pos;
};

struct COPYTOSTREAM_REQUEST {
	uint8_t hindex;
	uint64_t byte_count;
};

struct COPYTOSTREAM_RESPONSE {
	uint64_t read_bytes;
	uint64_t written_bytes;
};

struct COPYTOSTREAM_NULL_DEST_RESPONSE {
	uint32_t hindex;
	uint64_t read_bytes;
	uint64_t written_bytes;
};

struct LOCKREGIONSTREAM_REQUEST {
	uint64_t region_offset;
	uint64_t region_size;
	uint32_t lock_flags;
};

struct UNLOCKREGIONSTREAM_REQUEST {
	uint64_t region_offset;
	uint64_t region_size;
	uint32_t lock_flags;
};

struct WRITEANDCOMMITSTREAM_REQUEST {
	BINARY data;
};

struct WRITEANDCOMMITSTREAM_RESPONSE {
	uint16_t written_size;
};

struct CLONESTREAM_REQUEST {
	uint8_t hindex;
};

struct MODIFYPERMISSIONS_REQUEST {
	uint8_t flags;
	uint16_t count;
	PERMISSION_DATA *prow;
};


struct GETPERMISSIONSTABLE_REQUEST {
	uint8_t hindex;
	uint8_t flags;
};


struct MODIFYRULES_REQUEST {
	uint8_t flags;
	uint16_t count;
	RULE_DATA *prow;
};

struct GETRULESTABLE_REQUEST {
	uint8_t hindex;
	uint8_t flags;
};

struct UPDATEDEFERREDACTIONMESSAGES_REQUEST {
	BINARY server_entry_id;
	BINARY client_entry_id;
};

struct FASTTRANSFERDESTCONFIGURE_REQUEST {
	uint8_t hindex;
	uint8_t source_operation;
	uint8_t flags;
};

struct FASTTRANSFERDESTPUTBUFFER_REQUEST {
	BINARY transfer_data;
};

struct FASTTRANSFERDESTPUTBUFFER_RESPONSE {
	uint16_t transfer_status;
	uint16_t in_progress_count;
	uint16_t total_step_count;
	uint8_t reserved;
	uint16_t used_size;
};

struct FASTTRANSFERSOURCEGETBUFFER_REQUEST {
	uint16_t buffer_size;
	uint16_t max_buffer_size;
};

struct FASTTRANSFERSOURCEGETBUFFER_RESPONSE {
	uint16_t transfer_status;
	uint16_t in_progress_count;
	uint16_t total_step_count;
	uint8_t reserved;
	BINARY transfer_data;
};

struct FASTTRANSFERSOURCECOPYFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t flags;
	uint8_t send_options;
};

struct FASTTRANSFERSOURCECOPYMESSAGES_REQUEST {
	uint8_t hindex;
	LONGLONG_ARRAY message_ids;
	uint8_t flags;
	uint8_t send_options;
};

struct FASTTRANSFERSOURCECOPYTO_REQUEST {
	uint8_t hindex;
	uint8_t level;
	uint32_t flags;
	uint8_t send_options;
	PROPTAG_ARRAY proptags;
};

struct FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST {
	uint8_t hindex;
	uint8_t level;
	uint8_t flags;
	uint8_t send_options;
	PROPTAG_ARRAY proptags;
};

struct TELLVERSION_REQUEST {
	uint16_t version[3];
};

struct SYNCCONFIGURE_REQUEST {
	uint8_t hindex;
	uint8_t sync_type;
	uint8_t send_options;
	uint16_t sync_flags;
	RESTRICTION *pres;
	uint32_t extra_flags;
	PROPTAG_ARRAY proptags;
};

struct SYNCIMPORTMESSAGECHANGE_REQUEST {
	uint8_t hindex;
	uint8_t import_flags;
	TPROPVAL_ARRAY propvals;
};

struct SYNCIMPORTMESSAGECHANGE_RESPONSE {
	uint64_t message_id;
};

struct SYNCIMPORTREADSTATECHANGES_REQUEST {
	uint16_t count;
	MESSAGE_READ_STAT *pread_stat;
};

struct SYNCIMPORTHIERARCHYCHANGE_REQUEST {
	TPROPVAL_ARRAY hichyvals;
	TPROPVAL_ARRAY propvals;
};

struct SYNCIMPORTHIERARCHYCHANGE_RESPONSE {
	uint64_t folder_id;
};

struct SYNCIMPORTDELETES_REQUEST {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
};

struct SYNCIMPORTMESSAGEMOVE_REQUEST {
	BINARY src_folder_id;
	BINARY src_message_id;
	BINARY change_list;
	BINARY dst_message_id;
	BINARY change_number;
};

struct SYNCIMPORTMESSAGEMOVE_RESPONSE {
	uint64_t message_id;
};

struct SYNCOPENCOLLECTOR_REQUEST {
	uint8_t hindex;
	uint8_t is_content_collector;
};

struct SYNCGETTRANSFERSTATE_REQUEST {
	uint8_t hindex;
};

struct SYNCUPLOADSTATESTREAMBEGIN_REQUEST {
	uint32_t proptag_stat;
	uint32_t buffer_size;
};

struct SYNCUPLOADSTATESTREAMCONTINUE_REQUEST {
	BINARY stream_data;
};

struct SETLOCALREPLICAMIDSETDELETED_REQUEST {
	uint32_t count;
	LONG_TERM_ID_RANGE *prange;
};

struct GETLOCALREPLICAIDS_REQUEST {
	uint32_t count;
};

struct GETLOCALREPLICAIDS_RESPONSE {
	GUID replguid;
	GLOBCNT global_count;
};

struct REGISTERNOTIFICATION_REQUEST {
	uint8_t hindex;
	uint8_t notification_types;
	uint8_t reserved;
	uint8_t want_whole_store;
	uint64_t *pfolder_id;
	uint64_t *pmessage_id;
};

struct PENDING_RESPONSE {
	uint16_t session_index;
};

struct BACKOFF_ROP {
	uint8_t rop_id;
	uint32_t duration;
};

struct BACKOFF_RESPONSE {
	uint8_t logon_id;
	uint32_t duration;
	uint8_t rop_count;
	struct BACKOFF_ROP *prop_data;
	BINARY additional_data;
};

struct BUFFERTOOSMALL_RESPONSE {
	uint16_t size_needed;
	BINARY buffer;
};

/* end of rop request and response structure */

struct ROP_REQUEST {
	uint8_t rop_id;
	uint8_t logon_id;
	uint8_t hindex;
	void *ppayload;
	BINARY bookmark;
};

struct ROP_RESPONSE {
	uint8_t rop_id;
	uint8_t hindex;
	uint32_t result;
	void *ppayload;
};

struct ROP_BUFFER {
	uint16_t rhe_version;
	uint16_t rhe_flags;
	DOUBLE_LIST rop_list;
	uint8_t hnum;
	uint32_t *phandles;
};
