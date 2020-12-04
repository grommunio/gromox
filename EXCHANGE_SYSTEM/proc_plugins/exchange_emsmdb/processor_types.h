#pragma once
#include "mapi_types.h"

typedef struct _LOGON_REQUEST {
	uint8_t logon_flags;
	uint32_t open_flags;
	uint32_t store_stat;
	char *pessdn;
} LOGON_REQUEST;

typedef struct _LOGON_PMB_RESPONSE {
	uint8_t logon_flags;
	uint64_t folder_ids[13];
	uint8_t response_flags;
	GUID mailbox_guid;
	uint16_t replica_id;
	GUID replica_guid;
	LOGON_TIME logon_time;
	uint64_t gwart_time;
	uint32_t store_stat;
} LOGON_PMB_RESPONSE;

typedef struct _LOGON_PF_RESPONSE {
	uint8_t logon_flags;
	uint64_t folder_ids[13];
	uint16_t replica_id;
	GUID replica_guid;
	GUID per_user_guid;
} LOGON_PF_RESPONSE;

typedef struct _LOGON_REDIRECT_RESPONSE {
	uint8_t logon_flags;
	char pserver_name[1024];
} LOGON_REDIRECT_RESPONSE;

typedef struct _GETRECEIVEFOLDER_REQUEST {
	char *pstr_class;
} GETRECEIVEFOLDER_REQUEST;

typedef struct _GETRECEIVEFOLDER_RESPONSE {
	uint64_t folder_id;
	char *pstr_class;
} GETRECEIVEFOLDER_RESPONSE;

typedef struct _SETRECEIVEFOLDER_REQUEST {
	uint64_t folder_id;
	char * pstr_class;
} SETRECEIVEFOLDER_REQUEST;

typedef struct _GETRECEIVEFOLDERTABLE_RESPONSE {
	PROPROW_SET rows;
} GETRECEIVEFOLDERTABLE_RESPONSE;

typedef struct _GETSTORESTAT_RESPONSE {
	uint32_t stat;
} GETSTORESTAT_RESPONSE;

typedef struct _GETOWNINGSERVERS_REQUEST {
	uint64_t folder_id;
} GETOWNINGSERVERS_REQUEST;

typedef struct _GETOWNINGSERVERS_RESPONSE {
	GHOST_SERVER ghost;
} GETOWNINGSERVERS_RESPONSE;

typedef struct _PUBLICFOLDERISGHOSTED_REQUEST {
	uint64_t folder_id;
} PUBLICFOLDERISGHOSTED_REQUEST;

typedef struct _PUBLICFOLDERISGHOSTED_RESPONSE {
	GHOST_SERVER *pghost;
} PUBLICFOLDERISGHOSTED_RESPONSE;

typedef struct _LONGTERMIDFROMID_REQUEST {
	uint64_t id;
} LONGTERMIDFROMID_REQUEST;

typedef struct _LONGTERMIDFROMID_RESPONSE {
	LONG_TERM_ID long_term_id;
} LONGTERMIDFROMID_RESPONSE;

typedef struct _IDFROMLONGTERMID_REQUEST {
	LONG_TERM_ID long_term_id;
} IDFROMLONGTERMID_REQUEST;

typedef struct _IDFROMLONGTERMID_RESPONSE {
	uint64_t id;
} IDFROMLONGTERMID_RESPONSE;

typedef struct _GETPERUSERLONGTERMIDS_REQUEST {
	GUID guid;
} GETPERUSERLONGTERMIDS_REQUEST;

typedef struct _GETPERUSERLONGTERMIDS_RESPONSE {
	LONG_TERM_ID_ARRAY ids;
} GETPERUSERLONGTERMIDS_RESPONSE;

typedef struct _GETPERUSERGUID_REQUEST {
	LONG_TERM_ID long_term_id;
} GETPERUSERGUID_REQUEST;

typedef struct _GETPERUSERGUID_RESPONSE {
	GUID guid;
} GETPERUSERGUID_RESPONSE;

typedef struct _READPERUSERINFORMATION_REQUEST {
	LONG_TERM_ID long_folder_id;
	uint8_t reserved;
	uint32_t data_offset;
	uint16_t max_data_size;
} READPERUSERINFORMATION_REQUEST;

typedef struct _READPERUSERINFORMATION_RESPONSE {
	uint8_t has_finished;
	BINARY data;
} READPERUSERINFORMATION_RESPONSE;

typedef struct _WRITEPERUSERINFORMATION_REQUEST {
	LONG_TERM_ID long_folder_id;
	uint8_t has_finished;
	uint32_t offset;
	BINARY data;
	GUID *pguid;
} WRITEPERUSERINFORMATION_REQUEST;

typedef struct _OPENFOLDER_REQUEST {
	uint8_t hindex;
	uint64_t folder_id;
	uint8_t open_flags;
} OPENFOLDER_REQUEST;

typedef struct _OPENFOLDER_RESPONSE {
	uint8_t has_rules;
	GHOST_SERVER *pghost;
} OPENFOLDER_RESPONSE;

typedef struct _CREATEFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t folder_type;
	uint8_t use_unicode;
	uint8_t open_existing;
	uint8_t reserved;
	char *pfolder_name;
	char *pfolder_comment;
} CREATEFOLDER_REQUEST;

typedef struct _CREATEFOLDER_RESPONSE {
	uint64_t folder_id;
	uint8_t is_existing;
	uint8_t has_rules;
	GHOST_SERVER *pghost;
} CREATEFOLDER_RESPONSE;

typedef struct _DELETEFOLDER_REQUEST {
	uint8_t flags;
	uint64_t folder_id;
} DELETEFOLDER_REQUEST;

typedef struct _DELETEFOLDER_RESPONSE {
	uint8_t partial_completion;
} DELETEFOLDER_RESPONSE;


typedef struct _SETSEARCHCRITERIA_REQUEST {
	RESTRICTION *pres;
	LONGLONG_ARRAY folder_ids;
	uint32_t search_flags;
} SETSEARCHCRITERIA_REQUEST;

typedef struct _GETSEARCHCRITERIA_REQUEST {
	uint8_t use_unicode;
	uint8_t include_restriction;
	uint8_t include_folders;
} GETSEARCHCRITERIA_REQUEST;

typedef struct _GETSEARCHCRITERIA_RESPONSE {
	RESTRICTION *pres;
	uint8_t logon_id;
	LONGLONG_ARRAY folder_ids;
	uint32_t search_status;
} GETSEARCHCRITERIA_RESPONSE;

typedef struct _MOVECOPYMESSAGES_REQUEST {
	uint8_t hindex;
	LONGLONG_ARRAY message_ids;
	uint8_t want_asynchronous;
	uint8_t want_copy;
} MOVECOPYMESSAGES_REQUEST;

typedef struct _MOVECOPYMESSAGES_RESPONSE {
	uint8_t partial_completion;
} MOVECOPYMESSAGES_RESPONSE;

typedef struct _NULL_DST_RESPONSE {
	uint32_t hindex;
	uint8_t partial_completion;
} NULL_DST_RESPONSE;

typedef struct _MOVEFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t use_unicode;
	uint64_t folder_id;
	char *pnew_name;
} MOVEFOLDER_REQUEST;

typedef struct _MOVEFOLDER_RESPONSE {
	uint8_t partial_completion;
} MOVEFOLDER_RESPONSE;

typedef struct _COPYFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t want_recursive;
	uint8_t use_unicode;
	uint64_t folder_id;
	char *pnew_name;
} COPYFOLDER_REQUEST;

typedef struct _COPYFOLDER_RESPONSE {
	uint8_t partial_completion;
} COPYFOLDER_RESPONSE;

typedef struct _EMPTYFOLDER_REQUEST {
	uint8_t want_asynchronous;
	uint8_t want_delete_associated;
} EMPTYFOLDER_REQUEST;

typedef struct _EMPTYFOLDER_RESPONSE {
	uint8_t partial_completion;
} EMPTYFOLDER_RESPONSE;

typedef struct _HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST {
	uint8_t want_asynchronous;
	uint8_t want_delete_associated;
} HARDDELETEMESSAGESANDSUBFOLDERS_REQUEST;

typedef struct _HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE {
	uint8_t partial_completion;
} HARDDELETEMESSAGESANDSUBFOLDERS_RESPONSE;

typedef struct _DELETEMESSAGES_REQUEST {
	uint8_t want_asynchronous;
	uint8_t notify_non_read;
	LONGLONG_ARRAY message_ids;
} DELETEMESSAGES_REQUEST;

typedef struct _DELETEMESSAGES_RESPONSE {
	uint8_t partial_completion;
} DELETEMESSAGES_RESPONSE;

typedef struct _HARDDELETEMESSAGES_REQUEST {
	uint8_t want_asynchronous;
	uint8_t notify_non_read;
	LONGLONG_ARRAY message_ids;
} HARDDELETEMESSAGES_REQUEST;

typedef struct _HARDDELETEMESSAGES_RESPONSE {
	uint8_t partial_completion;
} HARDDELETEMESSAGES_RESPONSE;

typedef struct _GETHIERARCHYTABLE_REQUEST {
	uint8_t hindex;
	uint8_t table_flags;
} GETHIERARCHYTABLE_REQUEST;

typedef struct _GETHIERARCHYTABLE_RESPONSE {
	uint32_t row_count;
} GETHIERARCHYTABLE_RESPONSE;

typedef struct _GETCONTENTSTABLE_REQUEST {
	uint8_t hindex;
	uint8_t table_flags;
} GETCONTENTSTABLE_REQUEST;

typedef struct _GETCONTENTSTABLE_RESPONSE {
	uint32_t row_count;
} GETCONTENTSTABLE_RESPONSE;


typedef struct _SETCOLUMNS_REQUEST {
	uint8_t table_flags;
	PROPTAG_ARRAY proptags;
} SETCOLUMNS_REQUEST;

typedef struct _SETCOLUMNS_RESPONSE {
	uint8_t table_status;
} SETCOLUMNS_RESPONSE;

typedef struct _SORTTABLE_REQUEST {
	uint8_t table_flags;
	SORTORDER_SET sort_criteria;
} SORTTABLE_REQUEST;

typedef struct _SORTTABLE_RESPONSE {
	uint8_t table_status;
} SORTTABLE_RESPONSE;

typedef struct _RESTRICT_REQUEST {
	uint8_t res_flags;
	RESTRICTION *pres;
} RESTRICT_REQUEST;

typedef struct _RESTRICT_RESPONSE {
	uint8_t table_status;
} RESTRICT_RESPONSE;

typedef struct _QUERYROWS_REQUEST {
	uint8_t flags;
	uint8_t forward_read;
	uint16_t row_count;
} QUERYROWS_REQUEST;

typedef struct _QUERYROWS_RESPONSE {
	uint8_t seek_pos;
	uint16_t count;
	BINARY bin_rows;
} QUERYROWS_RESPONSE;

typedef struct _ABORT_RESPONSE {
	uint8_t table_status;
} ABORT_RESPONSE;

typedef struct _GETSTATUS_RESPONSE {
	uint8_t table_status;
} GETSTATUS_RESPONSE;

typedef struct _QUERYPOSITION_RESPONSE {
	uint32_t numerator;
	uint32_t denominator;
} QUERYPOSITION_RESPONSE;

typedef struct _SEEKROW_REQUEST {
	uint8_t seek_pos;
	int32_t offset;
	uint8_t want_moved_count;
} SEEKROW_REQUEST;

typedef struct _SEEKROW_RESPONSE {
	uint8_t has_soughtless;
	int32_t offset_sought;
} SEEKROW_RESPONSE;

typedef struct _SEEKROWBOOKMARK_REQUEST {
	BINARY bookmark;
	int32_t offset;
	uint8_t want_moved_count;
} SEEKROWBOOKMARK_REQUEST;

typedef struct _SEEKROWBOOKMARK_RESPONSE {
	uint8_t row_invisible;
	uint8_t has_soughtless;
	uint32_t offset_sought;
} SEEKROWBOOKMARK_RESPONSE;

typedef struct _SEEKROWFRACTIONAL_REQUEST {
	uint32_t numerator;
	uint32_t denominator;
} SEEKROWFRACTIONAL_REQUEST;

typedef struct _CREATEBOOKMARK_RESPONSE {
	BINARY bookmark;
} CREATEBOOKMARK_RESPONSE;

typedef struct _QUERYCOLUMNSALL_RESPONSE {
	PROPTAG_ARRAY proptags;
} QUERYCOLUMNSALL_RESPONSE;

typedef struct _FINDROW_REQUEST {
	uint8_t flags;
	RESTRICTION *pres;
	uint8_t seek_pos;
	BINARY bookmark;
} FINDROW_REQUEST;

typedef struct _FINDROW_RESPONSE {
	uint8_t bookmark_invisible;
	PROPERTY_ROW *prow;
	PROPTAG_ARRAY *pcolumns;
} FINDROW_RESPONSE;

typedef struct _FREEBOOKMARK_REQUEST {
	BINARY bookmark;
} FREEBOOKMARK_REQUEST;

typedef struct _EXPANDROW_REQUEST {
	uint16_t max_count;
	uint64_t category_id;
} EXPANDROW_REQUEST;

typedef struct _EXPANDROW_RESPONSE {
	uint32_t expanded_count;
	uint16_t count;
	BINARY bin_rows;
} EXPANDROW_RESPONSE;

typedef struct _COLLAPSEROW_REQUEST {
	uint64_t category_id;
} COLLAPSEROW_REQUEST;

typedef struct _COLLAPSEROW_RESPONSE {
	uint32_t collapsed_count;
} COLLAPSEROW_RESPONSE;

typedef struct _GETCOLLAPSESTATE_REQUEST {
	uint64_t row_id;
	uint32_t row_instance;
} GETCOLLAPSESTATE_REQUEST;

typedef struct _GETCOLLAPSESTATE_RESPONSE {
	BINARY collapse_state;
} GETCOLLAPSESTATE_RESPONSE;

typedef struct _SETCOLLAPSESTATE_REQUEST {
	BINARY collapse_state;
} SETCOLLAPSESTATE_REQUEST;

typedef struct _SETCOLLAPSESTATE_RESPONSE {
	BINARY bookmark;
} SETCOLLAPSESTATE_RESPONSE;

typedef struct _OPENMESSAGE_REQUEST {
	uint8_t hindex;
	uint16_t cpid;
	uint64_t folder_id;
	uint8_t open_mode_flags;
	uint64_t message_id;
} OPENMESSAGE_REQUEST;


typedef struct _OPENMESSAGE_RESPONSE {
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
} OPENMESSAGE_RESPONSE;


typedef struct _CREATEMESSAGE_REQUEST {
	uint8_t hindex;
	uint16_t cpid;
	uint64_t folder_id;
	uint8_t associated_flag;
} CREATEMESSAGE_REQUEST;

typedef struct _CREATEMESSAGE_RESPONSE {
	uint64_t *pmessage_id;
} CREATEMESSAGE_RESPONSE;

typedef struct _SAVECHANGESMESSAGE_REQUEST {
	uint8_t hindex;
	uint8_t save_flags;
} SAVECHANGESMESSAGE_REQUEST;

typedef struct _SAVECHANGESMESSAGE_RESPONSE {
	uint8_t hindex;
	uint64_t message_id;
} SAVECHANGESMESSAGE_RESPONSE;

typedef struct _REMOVEALLRECIPIENTS_REQUEST {
	uint32_t reserved;
} REMOVEALLRECIPIENTS_REQUEST;

typedef struct _MODIFYRECIPIENTS_REQUEST {
	PROPTAG_ARRAY proptags;
	uint16_t count;
	MODIFYRECIPIENT_ROW *prow;
} MODIFYRECIPIENTS_REQUEST;

typedef struct _READRECIPIENTS_REQUEST {
	uint32_t row_id;
	uint16_t reserved;
} READRECIPIENTS_REQUEST;

typedef struct _READRECIPIENTS_RESPONSE {
	uint8_t count;
	BINARY bin_recipients;
} READRECIPIENTS_RESPONSE;

typedef struct _RELOADCACHEDINFORMATION_REQUEST {
	uint16_t reserved;
} RELOADCACHEDINFORMATION_REQUEST;

typedef struct _RELOADCACHEDINFORMATION_RESPONSE {
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
} RELOADCACHEDINFORMATION_RESPONSE;

typedef struct _SETREADFLAGS_REQUEST {
	uint8_t want_asynchronous;
	uint8_t read_flags;
	LONGLONG_ARRAY message_ids;
} SETREADFLAGS_REQUEST;

typedef struct _SETMESSAGESTATUS_REQUEST {
	uint64_t message_id;
	uint32_t message_status;
	uint32_t status_mask;
} SETMESSAGESTATUS_REQUEST;

typedef struct _SETMESSAGESTATUS_RESPONSE {
	uint32_t message_status;
} SETMESSAGESTATUS_RESPONSE;

typedef struct _GETMESSAGESTATUS_REQUEST {
	uint64_t message_id;
} GETMESSAGESTATUS_REQUEST;

typedef struct _GETMESSAGESTATUS_RESPONSE {
	uint32_t message_status;
} GETMESSAGESTATUS_RESPONSE;

typedef struct _SETREADFLAGS_RESPONSE {
	uint8_t partial_completion;
} SETREADFLAGS_RESPONSE;

typedef struct _SETMESSAGEREADFLAG_REQUEST {
	uint8_t hindex;
	uint8_t flags;
	LONG_TERM_ID *pclient_data;
} SETMESSAGEREADFLAG_REQUEST;

typedef struct _SETMESSAGEREADFLAG_RESPONSE {
	uint8_t read_changed;
	uint8_t logon_id;
	LONG_TERM_ID *pclient_data;
} SETMESSAGEREADFLAG_RESPONSE;

typedef struct _OPENATTACHMENT_REQUEST {
	uint8_t hindex;
	uint8_t flags;
	uint32_t attachment_id;
} OPENATTACHMENT_REQUEST;

typedef struct _CREATEATTACHMENT_REQUEST {
	uint8_t hindex;
} CREATEATTACHMENT_REQUEST;

typedef struct _CREATEATTACHMENT_RESPONSE {
	uint32_t attachment_id;
} CREATEATTACHMENT_RESPONSE;

typedef struct _DELETEATTACHMENT_REQUEST {
	uint32_t attachment_id;
} DELETEATTACHMENT_REQUEST;

typedef struct _SAVECHANGESATTACHMENT_REQUEST {
	uint8_t hindex;
	uint8_t save_flags;
} SAVECHANGESATTACHMENT_REQUEST;

typedef struct _OPENEMBEDDEDMESSAGE_REQUEST {
	uint8_t hindex;
	uint16_t cpid;
	uint8_t open_embedded_flags;
} OPENEMBEDDEDMESSAGE_REQUEST;

typedef struct _OPENEMBEDDEDMESSAGE_RESPONSE {
	uint8_t reserved;
	uint64_t message_id;
	uint8_t has_named_properties;
	TYPED_STRING subject_prefix;
	TYPED_STRING normalized_subject;
	uint16_t recipient_count;
	PROPTAG_ARRAY recipient_columns;
	uint8_t row_count;
	OPENRECIPIENT_ROW *precipient_row;
} OPENEMBEDDEDMESSAGE_RESPONSE;

typedef struct _GETATTACHMENTTABLE_REQUEST {
	uint8_t hindex;
	uint8_t table_flags;
} GETATTACHMENTTABLE_REQUEST;

typedef struct _GETVALIDATTACHMENTS_RESPONSE {
	LONG_ARRAY attachment_ids;
} GETVALIDATTACHMENTS_RESPONSE;

typedef struct _SUBMITMESSAGE_REQUEST {
	uint8_t submit_flags;
} SUBMITMESSAGE_REQUEST;

typedef struct _ABORTSUBMIT_REQUEST {
	uint64_t folder_id;
	uint64_t message_id;
} ABORTSUBMIT_REQUEST;

typedef struct _GETADDRESSTYPES_RESPONSE {
	STRING_ARRAY address_types;
} GETADDRESSTYPES_RESPONSE;

typedef struct _SPOOLERLOCKMESSAGE_REQUEST {
	uint64_t message_id;
	uint8_t lock_stat;
} SPOOLERLOCKMESSAGE_REQUEST;

typedef struct _TRANSPORTSEND_RESPONSE {
	TPROPVAL_ARRAY *ppropvals;
} TRANSPORTSEND_RESPONSE;

typedef struct _TRANSPORTNEWMAIL_REQUEST {
	uint64_t message_id;
	uint64_t folder_id;
	char *pstr_class;
	uint32_t message_flags;
} TRANSPORTNEWMAIL_REQUEST;

typedef struct _GETTRANSPORTFOLDER_RESPONSE {
	uint64_t folder_id;
} GETTRANSPORTFOLDER_RESPONSE;

typedef struct _OPTIONSDATA_REQUEST {
	char *paddress_type;
	uint8_t want_win32;
} OPTIONSDATA_REQUEST;

typedef struct _OPTIONSDATA_RESPONSE {
	uint8_t reserved;
	BINARY options_info;
	BINARY help_file;
	char *pfile_name;
} OPTIONSDATA_RESPONSE;

typedef struct _GETPROPERTYIDSFROMNAMES_REQUEST {
	uint8_t flags;
	PROPNAME_ARRAY propnames;
} GETPROPERTYIDSFROMNAMES_REQUEST;

typedef struct _GETPROPERTYIDSFROMNAMES_RESPONSE {
	PROPID_ARRAY propids;
} GETPROPERTYIDSFROMNAMES_RESPONSE;

typedef struct _GETNAMESFROMPROPERTYIDS_REQUEST {
	PROPID_ARRAY propids;
} GETNAMESFROMPROPERTYIDS_REQUEST;

typedef struct _GETNAMESFROMPROPERTYIDS_RESPONSE {
	PROPNAME_ARRAY propnames;
} GETNAMESFROMPROPERTYIDS_RESPONSE;

typedef struct _GETPROPERTIESSPECIFIC_REQUEST {
	uint16_t size_limit;
	uint16_t want_unicode;
	PROPTAG_ARRAY proptags;
} GETPROPERTIESSPECIFIC_REQUEST;

typedef struct _GETPROPERTIESSPECIFIC_RESPONSE {
	PROPTAG_ARRAY *pproptags;    /* only for pushing row data into stream */
	PROPERTY_ROW row;
} GETPROPERTIESSPECIFIC_RESPONSE;

typedef struct _GETPROPERTIESALL_REQUEST {
	uint16_t size_limit;
	uint16_t want_unicode;
} GETPROPERTIESALL_REQUEST;

typedef struct _GETPROPERTIESALL_RESPONSE {
	TPROPVAL_ARRAY propvals;
} GETPROPERTIESALL_RESPONSE;

typedef struct _GETPROPERTIESLIST_RESPONSE {
	PROPTAG_ARRAY proptags;
} GETPROPERTIESLIST_RESPONSE;

typedef struct _SETPROPERTIES_REQUEST {
	TPROPVAL_ARRAY propvals;
} SETPROPERTIES_REQUEST;

typedef struct _SETPROPERTIES_RESPONSE {
	PROBLEM_ARRAY problems;
} SETPROPERTIES_RESPONSE;

typedef struct _SETPROPERTIESNOREPLICATE_REQUEST {
	TPROPVAL_ARRAY propvals;
} SETPROPERTIESNOREPLICATE_REQUEST;

typedef struct _SETPROPERTIESNOREPLICATE_RESPONSE {
	PROBLEM_ARRAY problems;
} SETPROPERTIESNOREPLICATE_RESPONSE;

typedef struct _DELETEPROPERTIES_REQUEST {
	PROPTAG_ARRAY proptags;
} DELETEPROPERTIES_REQUEST;

typedef struct _DELETEPROPERTIES_RESPONSE {
	PROBLEM_ARRAY problems;
} DELETEPROPERTIES_RESPONSE;

typedef struct _DELETEPROPERTIESNOREPLICATE_REQUEST {
	PROPTAG_ARRAY proptags;
} DELETEPROPERTIESNOREPLICATE_REQUEST;

typedef struct _DELETEPROPERTIESNOREPLICATE_RESPONSE {
	PROBLEM_ARRAY problems;
} DELETEPROPERTIESNOREPLICATE_RESPONSE;

typedef struct _QUERYNAMEDPROPERTIES_REQUEST {
	uint8_t query_flags;
	GUID *pguid;
} QUERYNAMEDPROPERTIES_REQUEST;

typedef struct _QUERYNAMEDPROPERTIES_RESPONSE {
	PROPIDNAME_ARRAY propidnames;
} QUERYNAMEDPROPERTIES_RESPONSE;

typedef struct _COPYPROPERTIES_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t copy_flags;
	PROPTAG_ARRAY proptags;
} COPYPROPERTIES_REQUEST;

typedef struct _COPYPROPERTIES_RESPONSE {
	PROBLEM_ARRAY problems;
} COPYPROPERTIES_RESPONSE;

typedef struct _COPYTO_REQUEST {
	uint8_t hindex;
	uint8_t want_asynchronous;
	uint8_t want_subobjects;
	uint8_t copy_flags;
	PROPTAG_ARRAY excluded_proptags;
} COPYTO_REQUEST;

typedef struct _COPYTO_RESPONSE {
	PROBLEM_ARRAY problems;
} COPYTO_RESPONSE;

typedef struct _PROGRESS_REQUEST {
	uint8_t want_cancel;
} PROGRESS_REQUEST;

typedef struct _PROGRESS_RESPONSE {
	uint8_t logon_id;
	uint32_t completed_count;
	uint32_t total_count;
} PROGRESS_RESPONSE;

typedef struct _OPENSTREAM_REQUEST {
	uint8_t hindex;
	uint32_t proptag;
	uint8_t flags;
} OPENSTREAM_REQUEST;

typedef struct _OPENSTREAM_RESPONSE {
	uint32_t stream_size;
} OPENSTREAM_RESPONSE;

typedef struct _READSTREAM_REQUEST {
	uint16_t byte_count;
	uint32_t max_byte_count;
} READSTREAM_REQUEST;

typedef struct _READSTREAM_RESPONSE {
	BINARY data;
} READSTREAM_RESPONSE;

typedef struct _WRITESTREAM_REQUEST {
	BINARY data;
} WRITESTREAM_REQUEST;

typedef struct _WRITESTREAM_RESPONSE {
	uint16_t written_size;
} WRITESTREAM_RESPONSE;

typedef struct _GETSTREAMSIZE_RESPONSE {
	uint32_t stream_size;
} GETSTREAMSIZE_RESPONSE;

typedef struct _SETSTREAMSIZE_REQUEST {
	uint64_t stream_size;
} SETSTREAMSIZE_REQUEST;

typedef struct _SEEKSTREAM_REQUEST {
	uint8_t seek_pos;
	int64_t offset;
} SEEKSTREAM_REQUEST;

typedef struct _SEEKSTREAM_RESPONSE {
	uint64_t new_pos;
} SEEKSTREAM_RESPONSE;

typedef struct _COPYTOSTREAM_REQUEST {
	uint8_t hindex;
	uint64_t byte_count;
} COPYTOSTREAM_REQUEST;

typedef struct _COPYTOSTREAM_RESPONSE {
	uint64_t read_bytes;
	uint64_t written_bytes;
} COPYTOSTREAM_RESPONSE;

typedef struct _COPYTOSTREAM_NULL_DEST_RESPONSE {
	uint32_t hindex;
	uint64_t read_bytes;
	uint64_t written_bytes;
} COPYTOSTREAM_NULL_DEST_RESPONSE;

typedef struct _LOCKREGIONSTREAM_REQUEST {
	uint64_t region_offset;
	uint64_t region_size;
	uint32_t lock_flags;
} LOCKREGIONSTREAM_REQUEST;

typedef struct _UNLOCKREGIONSTREAM_REQUEST {
	uint64_t region_offset;
	uint64_t region_size;
	uint32_t lock_flags;
} UNLOCKREGIONSTREAM_REQUEST;

typedef struct _WRITEANDCOMMITSTREAM_REQUEST {
	BINARY data;
} WRITEANDCOMMITSTREAM_REQUEST;

typedef struct _WRITEANDCOMMITSTREAM_RESPONSE {
	uint16_t written_size;
} WRITEANDCOMMITSTREAM_RESPONSE;

typedef struct _CLONESTREAM_REQUEST {
	uint8_t hindex;
} CLONESTREAM_REQUEST;

typedef struct _MODIFYPERMISSIONS_REQUEST {
	uint8_t flags;
	uint16_t count;
	PERMISSION_DATA *prow;
} MODIFYPERMISSIONS_REQUEST;


typedef struct _GETPERMISSIONSTABLE_REQUEST {
	uint8_t hindex;
	uint8_t flags;
} GETPERMISSIONSTABLE_REQUEST;


typedef struct _MODIFYRULES_REQUEST {
	uint8_t flags;
	uint16_t count;
	RULE_DATA *prow;
} MODIFYRULES_REQUEST;

typedef struct _GETRULESTABLE_REQUEST {
	uint8_t hindex;
	uint8_t flags;
} GETRULESTABLE_REQUEST;

typedef struct _UPDATEDEFERREDACTIONMESSAGES_REQUEST {
	BINARY server_entry_id;
	BINARY client_entry_id;
} UPDATEDEFERREDACTIONMESSAGES_REQUEST;

typedef struct _FASTTRANSFERDESTCONFIGURE_REQUEST {
	uint8_t hindex;
	uint8_t source_operation;
	uint8_t flags;
} FASTTRANSFERDESTCONFIGURE_REQUEST;

typedef struct _FASTTRANSFERDESTPUTBUFFER_REQUEST {
	BINARY transfer_data;
} FASTTRANSFERDESTPUTBUFFER_REQUEST;

typedef struct _FASTTRANSFERDESTPUTBUFFER_RESPONSE {
	uint16_t transfer_status;
	uint16_t in_progress_count;
	uint16_t total_step_count;
	uint8_t reserved;
	uint16_t used_size;
} FASTTRANSFERDESTPUTBUFFER_RESPONSE;

typedef struct _FASTTRANSFERSOURCEGETBUFFER_REQUEST {
	uint16_t buffer_size;
	uint16_t max_buffer_size;
} FASTTRANSFERSOURCEGETBUFFER_REQUEST;

typedef struct _FASTTRANSFERSOURCEGETBUFFER_RESPONSE {
	uint16_t transfer_status;
	uint16_t in_progress_count;
	uint16_t total_step_count;
	uint8_t reserved;
	BINARY transfer_data;
} FASTTRANSFERSOURCEGETBUFFER_RESPONSE;

typedef struct _FASTTRANSFERSOURCECOPYFOLDER_REQUEST {
	uint8_t hindex;
	uint8_t flags;
	uint8_t send_options;
} FASTTRANSFERSOURCECOPYFOLDER_REQUEST;

typedef struct _FASTTRANSFERSOURCECOPYMESSAGES_REQUEST {
	uint8_t hindex;
	LONGLONG_ARRAY message_ids;
	uint8_t flags;
	uint8_t send_options;
} FASTTRANSFERSOURCECOPYMESSAGES_REQUEST;

typedef struct _FASTTRANSFERSOURCECOPYTO_REQUEST {
	uint8_t hindex;
	uint8_t level;
	uint32_t flags;
	uint8_t send_options;
	PROPTAG_ARRAY proptags;
} FASTTRANSFERSOURCECOPYTO_REQUEST;

typedef struct _FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST {
	uint8_t hindex;
	uint8_t level;
	uint8_t flags;
	uint8_t send_options;
	PROPTAG_ARRAY proptags;
} FASTTRANSFERSOURCECOPYPROPERTIES_REQUEST;

typedef struct _TELLVERSION_REQUEST {
	uint16_t version[3];
} TELLVERSION_REQUEST;

typedef struct _SYNCCONFIGURE_REQUEST {
	uint8_t hindex;
	uint8_t sync_type;
	uint8_t send_options;
	uint16_t sync_flags;
	RESTRICTION *pres;
	uint32_t extra_flags;
	PROPTAG_ARRAY proptags;
} SYNCCONFIGURE_REQUEST;

typedef struct _SYNCIMPORTMESSAGECHANGE_REQUEST {
	uint8_t hindex;
	uint8_t import_flags;
	TPROPVAL_ARRAY propvals;
} SYNCIMPORTMESSAGECHANGE_REQUEST;

typedef struct _SYNCIMPORTMESSAGECHANGE_RESPONSE {
	uint64_t message_id;
} SYNCIMPORTMESSAGECHANGE_RESPONSE;

typedef struct _SYNCIMPORTREADSTATECHANGES_REQUEST {
	uint16_t count;
	MESSAGE_READ_STAT *pread_stat;
} SYNCIMPORTREADSTATECHANGES_REQUEST;

typedef struct _SYNCIMPORTHIERARCHYCHANGE_REQUEST {
	TPROPVAL_ARRAY hichyvals;
	TPROPVAL_ARRAY propvals;
} SYNCIMPORTHIERARCHYCHANGE_REQUEST;

typedef struct _SYNCIMPORTHIERARCHYCHANGE_RESPONSE {
	uint64_t folder_id;
} SYNCIMPORTHIERARCHYCHANGE_RESPONSE;

typedef struct _SYNCIMPORTDELETES_REQUEST {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
} SYNCIMPORTDELETES_REQUEST;

typedef struct _SYNCIMPORTMESSAGEMOVE_REQUEST {
	BINARY src_folder_id;
	BINARY src_message_id;
	BINARY change_list;
	BINARY dst_message_id;
	BINARY change_number;
} SYNCIMPORTMESSAGEMOVE_REQUEST;

typedef struct _SYNCIMPORTMESSAGEMOVE_RESPONSE {
	uint64_t message_id;
} SYNCIMPORTMESSAGEMOVE_RESPONSE;

typedef struct _SYNCOPENCOLLECTOR_REQUEST {
	uint8_t hindex;
	uint8_t is_content_collector;
} SYNCOPENCOLLECTOR_REQUEST;

typedef struct _SYNCGETTRANSFERSTATE_REQUEST {
	uint8_t hindex;
} SYNCGETTRANSFERSTATE_REQUEST;

typedef struct _SYNCUPLOADSTATESTREAMBEGIN_REQUEST {
	uint32_t proptag_stat;
	uint32_t buffer_size;
} SYNCUPLOADSTATESTREAMBEGIN_REQUEST;

typedef struct _SYNCUPLOADSTATESTREAMCONTINUE_REQUEST {
	BINARY stream_data;
} SYNCUPLOADSTATESTREAMCONTINUE_REQUEST;

typedef struct _SETLOCALREPLICAMIDSETDELETED_REQUEST {
	uint32_t count;
	LONG_TERM_ID_RANGE *prange;
} SETLOCALREPLICAMIDSETDELETED_REQUEST;

typedef struct _GETLOCALREPLICAIDS_REQUEST {
	uint32_t count;
} GETLOCALREPLICAIDS_REQUEST;

typedef struct _GETLOCALREPLICAIDS_RESPONSE {
	GUID guid;
	uint8_t global_count[6];
} GETLOCALREPLICAIDS_RESPONSE;

typedef struct _REGISTERNOTIFICATION_REQUEST {
	uint8_t hindex;
	uint8_t notification_types;
	uint8_t reserved;
	uint8_t want_whole_store;
	uint64_t *pfolder_id;
	uint64_t *pmessage_id;
} REGISTERNOTIFICATION_REQUEST;

typedef struct _NOTIFY_RESPONSE {
	uint32_t handle;
	uint8_t logon_id;
	NOTIFICATION_DATA notification_data;
} NOTIFY_RESPONSE;

typedef struct _PENDING_RESPONSE {
	uint16_t session_index;
} PENDING_RESPONSE;

typedef struct _BACKOFF_ROP {
	uint8_t rop_id;
	uint32_t duration;
} BACKOFF_ROP;

typedef struct _BACKOFF_RESPONSE {
	uint8_t logon_id;
	uint32_t duration;
	uint8_t rop_count;
	BACKOFF_ROP *prop_data;
	BINARY additional_data;
} BACKOFF_RESPONSE;

typedef struct _BUFFERTOOSMALL_RESPONSE {
	uint16_t size_needed;
	BINARY buffer;
} BUFFERTOOSMALL_RESPONSE;

/* end of rop request and response structure */

enum {
	ropRelease = 0x01,
	ropOpenFolder = 0x02,
	ropOpenMessage = 0x03,
	ropGetHierarchyTable = 0x04,
	ropGetContentsTable = 0x05,
	ropCreateMessage = 0x06,
	ropGetPropertiesSpecific = 0x07,
	ropGetPropertiesAll = 0x08,
	ropGetPropertiesLIst = 0x09,
	ropSetProperties = 0x0A,
	ropDeleteProperties = 0x0B,
	ropSaveChangesMessage = 0x0C,
	ropRemoveAllRecipients = 0x0D,
	ropModifyRecipients = 0x0E,
	ropReadRecipients = 0x0F,
	ropReloadCachedInformation = 0x10,
	ropSetMessageReadFlag = 0x11,
	ropSetColumns = 0x12,
	ropSortTable = 0x13,
	ropRestrict = 0x14,
	ropQueryRows = 0x15,
	ropGetStatus = 0x16,
	ropQueryPosition = 0x17,
	ropSeekRow = 0x18,
	ropSeekRowBookmark = 0x19,
	ropSeekRowFractional = 0x1A,
	ropCreateBookmark = 0x1B,
	ropCreateFolder = 0x1C,
	ropDeleteFolder = 0x1D,
	ropDeleteMessages = 0x1E,
	ropGetMessageStatus = 0x1F,
	ropSetMessageStatus = 0x20,
	ropGetAttachmentTable = 0x21,
	ropOpenAttachment = 0x22,
	ropCreateAttachment = 0x23,
	ropDeleteAttachment = 0x24,
	ropSaveChangesAttachment = 0x25,
	ropSetReceiveFolder = 0x26,
	ropGetReceiveFolder = 0x27,
	ropRegisterNotification = 0x29,
	ropRegisterNotify = 0x2A,
	ropOpenStream = 0x2B,
	ropReadStream = 0x2C,
	ropWriteStream = 0x2D,
	ropSeekStream = 0x2E,
	ropSetStreamSize = 0x2F,
	ropSetSearchCriteria = 0x30,
	ropGetSearchCriteria = 0x31,
	ropSubmitMessage = 0x32,
	ropMoveCopyMessages = 0x33,
	ropAbortSubmit = 0x34,
	ropMoveFolder = 0x35,
	ropCopyFolder = 0x36,
	ropQueryColumnsAll = 0x37,
	ropAbort = 0x38,
	ropCopyTo = 0x39,
	ropCopyToStream = 0x3A,
	ropCloneStream = 0x3B,
	ropGetPermissionsTable = 0x3E,
	ropGetRulesTable = 0x3F,
	ropModifyPermissions = 0x40,
	ropModifyRules = 0x41,
	ropGetOwningServers = 0x42,
	ropLongTermIdFromId = 0x43,
	ropIdFromLongTermId = 0x44,
	ropPublicFolderIsGhosted = 0x45,
	ropOpenEmbeddedMessage = 0x46,
	ropSetSpooler = 0x47,
	ropSpoolerLockMessage = 0x48,
	ropGetAddressTypes = 0x49,
	ropTransportSend = 0x4A,
	ropFastTransferSourceCopyMessages = 0x4B,
	ropFastTransferSourceCopyFolder = 0x4C,
	ropFastTransferSourceCopyTo = 0x4D,
	ropFastTransferSourceGetBuffer = 0x4E,
	ropFindRow = 0x4F,
	ropProgress = 0x50,
	ropTransportNewMail = 0x51,
	ropGetValidAttachments = 0x52,
	ropFastTransferDestinationConfigure = 0x53,
	ropFastTransferDestinationPutBuffer = 0x54,
	ropGetNamesFromPropertyIds = 0x55,
	ropGetPropertyIdsFromNames = 0x56,
	ropUpdateDeferredActionMessages = 0x57,
	ropEmptyFolder = 0x58,
	ropExpandRow = 0x59,
	ropCollapseRow = 0x5A,
	ropLockRegionStream = 0x5B,
	ropUnlockRegionStream = 0x5C,
	ropCommitStream = 0x5D,
	ropGetStreamSize = 0x5E,
	ropQueryNamedProperties = 0x5F,
	ropGetPerUserLongTermIds = 0x60,
	ropGetPerUserGuid = 0x61,
	ropReadPerUserInformation = 0x63,
	ropWritePerUserInformation = 0x64,
	ropSetReadFlags = 0x66,
	ropCopyProperties = 0x67,
	ropGetReceiveFolderTable = 0x68,
	ropFastTransferSourceCopyProperties = 0x69,
	ropGetCollapseState = 0x6B,
	ropSetCollapseState = 0x6C,
	ropGetTransportFolder = 0x6D,
	ropPending = 0x6E,
	ropOptionsData = 0x6F,
	ropSynchronizationConfigure = 0x70,
	ropSynchronizationImportMessageChange = 0x72,
	ropSynchronizationImportHierarchyChange = 0x73,
	ropSynchronizationImportDeletes = 0x74,
	ropSynchronizationUploadStateStreamBegin = 0x75,
	ropSynchronizationUploadStateStreamContinue = 0x76,
	ropSynchronizationUploadStateStreamEnd = 0x77,
	ropSynchronizationImportMessageMove = 0x78,
	ropSetPropertiesNoReplicate = 0x79,
	ropDeletePropertiesNoReplicate = 0x7A,
	ropGetStoreState = 0x7B,
	ropSynchronizationOpenCollector = 0x7E,
	ropGetLocalReplicaIds = 0x7F,
	ropSynchronizationImportReadStateChanges = 0x80,
	ropResetTable = 0x81,
	ropSynchronizationGetTransferState = 0x82,
	ropTellVersion = 0x86,
	ropFreeBookmark = 0x89,
	ropWriteAndCommitStream = 0x90,
	ropHardDeleteMessages = 0x91,
	ropHardDeleteMessagesAndSubfolders = 0x92,
	ropSetLocalReplicaMidsetDeleted = 0x93,
	ropBackoff = 0xF9,
	ropLogon = 0xFE,
	ropBufferTooSmall = 0xFF,
};

typedef struct _ROP_REQUEST {
	uint8_t rop_id;
	uint8_t logon_id;
	uint8_t hindex;
	void *ppayload;
	BINARY bookmark;
} ROP_REQUEST;

typedef struct _ROP_RESPONSE {
	uint8_t rop_id;
	uint8_t hindex;
	uint32_t result;
	void *ppayload;
} ROP_RESPONSE;

typedef struct _ROP_BUFFER {
	uint16_t rhe_version;
	uint16_t rhe_flags;
	DOUBLE_LIST rop_list;
	uint8_t hnum;
	uint32_t *phandles;
} ROP_BUFFER;

#ifdef __cplusplus
extern "C" {
#endif

extern const char *rop_idtoname(unsigned int i);

#ifdef __cplusplus
}
#endif
