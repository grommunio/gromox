#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>
#include <gromox/ext_buffer.hpp>

extern uint32_t rop_logon_pmb(uint8_t logon_flags, uint32_t open_flags, uint32_t store_stat, char *essdn, size_t dnmax, uint64_t *folder_id, uint8_t *response_flags, GUID *mailbox_guid, uint16_t *replica_id, GUID *preplica_guid, LOGON_TIME *logon_time, uint64_t *pgwart_time, uint32_t *store_stat_out, void *plogmap, uint8_t logon_id, uint32_t *hout);
uint32_t rop_logon_pf(uint8_t logon_flags, uint32_t open_flags,
	uint32_t store_stat, char *pessdn, uint64_t *pfolder_id,
	uint16_t *preplica_id, GUID *preplica_guid, GUID *pper_user_guid,
	void *plogmap, uint8_t logon_id, uint32_t *phout);
uint32_t rop_getreceivefolder(const char *pstr_class,
	uint64_t *pfolder_id, char **ppstr_explicit,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_setreceivefolder(uint64_t folder_id,
	const char *pstr_class, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_getreceivefoldertable(PROPROW_SET *prows,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getstorestat(uint32_t *pstat,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getowningservers(
	uint64_t folder_id, GHOST_SERVER *pghost,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_publicfolderisghosted(
	uint64_t folder_id, GHOST_SERVER **ppghost,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_longtermidfromid(uint64_t id,
	LONG_TERM_ID *plong_term_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_idfromlongtermid(
	const LONG_TERM_ID *plong_term_id, uint64_t *pid,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getperuserlongtermids(const GUID *pguid,
	LONG_TERM_ID_ARRAY *plong_term_ids,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getperuserguid(
	const LONG_TERM_ID *plong_term_id, GUID *pguid,
	void *plogmap,uint8_t logon_id,  uint32_t hin);
uint32_t rop_readperuserinformation(
	const LONG_TERM_ID *plong_folder_id,
	uint8_t reserved, uint32_t data_offset,
	uint16_t max_data_size, uint8_t *phas_finished,
	BINARY *pdata, void *plogmap, uint8_t logon_id,
	uint32_t hin);
uint32_t rop_writeperuserinformation(
	const LONG_TERM_ID *plong_folder_id,
	uint8_t has_finished, uint32_t offset,
	const BINARY *pdata, const GUID *pguid,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_openfolder(uint64_t folder_id,
	uint8_t open_flags, uint8_t *phas_rules,
	GHOST_SERVER **ppghost, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_createfolder(uint8_t folder_type,
	uint8_t use_unicode, uint8_t open_existing,
	uint8_t reserved, const char *pfolder_name,
	const char *pfolder_comment, uint64_t *pfolder_id,
	uint8_t *pis_existing, uint8_t *phas_rules,
	GHOST_SERVER **ppghost, void *plogmap,
	uint8_t logon_id,  uint32_t hin, uint32_t *phout);
uint32_t rop_deletefolder(uint8_t flags,
	uint64_t folder_id, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_setsearchcriteria(const RESTRICTION *pres,
	const LONGLONG_ARRAY *pfolder_ids, uint32_t search_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getsearchcriteria(uint8_t use_unicode,
	uint8_t include_restriction, uint8_t include_folders,
	RESTRICTION **ppres, LONGLONG_ARRAY *pfolder_ids,
	uint32_t *psearch_flags, void *plogmap, uint8_t logon_id,
	uint32_t hin);
uint32_t rop_movecopymessages(const LONGLONG_ARRAY *pmessage_ids,
	uint8_t want_asynchronous, uint8_t want_copy,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst);
uint32_t rop_movefolder(uint8_t want_asynchronous,
	uint8_t use_unicode, uint64_t folder_id, const char *pnew_name,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst);
uint32_t rop_copyfolder(uint8_t want_asynchronous,
	uint8_t want_recursive, uint8_t use_unicode, uint64_t folder_id,
	const char *pnew_name, uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst);
uint32_t rop_emptyfolder(uint8_t want_asynchronous,
	uint8_t want_delete_associated, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_harddeletemessagesandsubfolders(
	uint8_t want_asynchronous, uint8_t want_delete_associated,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_deletemessages(uint8_t want_asynchronous,
	uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
	uint8_t *ppartial_completion, void *plogmap, uint8_t logon_id,
	uint32_t hin);
uint32_t rop_harddeletemessages(uint8_t want_asynchronous,
	uint8_t notify_non_read, const LONGLONG_ARRAY *pmessage_ids,
	uint8_t *ppartial_completion, void *plogmap, uint8_t logon_id,
	uint32_t hin);
uint32_t rop_gethierarchytable(uint8_t table_flags,
	uint32_t *prow_count, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_getcontentstable(uint8_t table_flags,
	uint32_t *prow_count, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_setcolumns(uint8_t table_flags,
	const PROPTAG_ARRAY *pproptags, uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_sorttable(uint8_t table_flags,
	const SORTORDER_SET *psort_criteria, uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_restrict(uint8_t res_flags,
	const RESTRICTION *pres, uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_queryrows(uint8_t flags,
	uint8_t forward_read, uint16_t row_count,
	uint8_t *pseek_pos, uint16_t *pcount, EXT_PUSH *pext,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_abort(uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getstatus(uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_queryposition(uint32_t *pnumerator,
	uint32_t *pdenominator, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_seekrow(uint8_t seek_pos,
	int32_t offset, uint8_t want_moved_count,
	uint8_t *phas_soughtless, int32_t *poffset_sought,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_seekrowbookmark(const BINARY *pbookmark, 
	int32_t offset, uint8_t want_moved_count,
	uint8_t *prow_invisible, uint8_t *phas_soughtless,
	uint32_t *poffset_sought, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_seekrowfractional(uint32_t numerator,
	uint32_t denominator, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_createbookmark(BINARY *pbookmark,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_querycolumnsall(PROPTAG_ARRAY *pproptags,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_findrow(uint8_t flags, const RESTRICTION *pres,
	uint8_t seek_pos, const BINARY *pbookmark,
	uint8_t *pbookmark_invisible, PROPERTY_ROW **pprow,
	PROPTAG_ARRAY **ppcolumns, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_freebookmark(const BINARY *pbookmark,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_resettable(void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_expandrow(uint16_t max_count,
	uint64_t category_id, uint32_t *pexpanded_count,
	uint16_t *pcount, EXT_PUSH *pext, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_collapserow(uint64_t category_id,
	uint32_t *pcollapsed_count, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_getcollapsestate(uint64_t row_id,
	uint32_t row_instance, BINARY *pcollapse_state,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_setcollapsestate(
	const BINARY *pcollapse_state, BINARY *pbookmark,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_openmessage(uint16_t cpid,
	uint64_t folder_id, uint8_t open_mode_flags,
	uint64_t message_id, uint8_t *phas_named_properties,
	TYPED_STRING *psubject_prefix, TYPED_STRING *pnormalized_subject,
	uint16_t *precipient_count, PROPTAG_ARRAY *precipient_columns,
	uint8_t *prow_count, OPENRECIPIENT_ROW **pprecipient_row,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_createmessage(uint16_t cpid,
	uint64_t folder_id, uint8_t associated_flag,
	uint64_t **ppmessage_id, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_savechangesmessage(uint8_t save_flags,
	uint64_t *pmessage_id, void *plogmap, uint8_t logon_id,
	uint32_t hresponse, uint32_t hin);
uint32_t rop_removeallrecipients(uint32_t reserved,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_modifyrecipients(const PROPTAG_ARRAY *pproptags,
	uint16_t count, const MODIFYRECIPIENT_ROW *prow,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_readrecipients(uint32_t row_id,
	uint16_t reserved, uint8_t *pcount, EXT_PUSH *pext,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_reloadcachedinformation(uint16_t reserved,
	uint8_t *phas_named_properties, TYPED_STRING *psubject_prefix,
	TYPED_STRING *pnormalized_subject, uint16_t *precipient_count,
	PROPTAG_ARRAY *precipient_columns, uint8_t *prow_count,
	OPENRECIPIENT_ROW **pprecipient_row, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_setmessagestatus(uint64_t message_id,
	uint32_t message_status, uint32_t status_mask,
	uint32_t *pmessage_status, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_getmessagestatus(uint64_t message_id,
	uint32_t *pmessage_status, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_setreadflags(uint8_t want_asynchronous,
	uint8_t read_flags,	const LONGLONG_ARRAY *pmessage_ids,
	uint8_t *ppartial_completion, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_setmessagereadflag(uint8_t read_flags,
	const LONG_TERM_ID *pclient_data, uint8_t *pread_change,
	void *plogmap, uint8_t logon_id, uint32_t hresponse, uint32_t hin);
uint32_t rop_openattachment(uint8_t flags, uint32_t attachment_id,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_createattachment(uint32_t *pattachment_id,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_deleteattachment(uint32_t attachment_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_savechangesattachment(uint8_t save_flags,
	void *plogmap, uint8_t logon_id, uint32_t hresponse, uint32_t hin);
uint32_t rop_openembeddedmessage(uint16_t cpid,
	uint8_t open_embedded_flags, uint8_t *preserved,
	uint64_t *pmessage_id, uint8_t *phas_named_properties,
	TYPED_STRING *psubject_prefix, TYPED_STRING *pnormalized_subject,
	uint16_t *precipient_count, PROPTAG_ARRAY *precipient_columns,
	uint8_t *prow_count, OPENRECIPIENT_ROW **pprecipient_row,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_getattachmenttable(uint8_t table_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_getvalidattachments(LONG_ARRAY *pattachment_ids,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_submitmessage(uint8_t submit_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_abortsubmit(uint64_t folder_id, uint64_t message_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getaddresstypes(STRING_ARRAY *paddress_types,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_setspooler(void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_spoolerlockmessage(uint64_t message_id,
	uint8_t lock_stat, void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_transportsend(TPROPVAL_ARRAY **pppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_transportnewmail(uint64_t message_id,
	uint64_t folder_id, const char *pstr_class,
	uint32_t message_flags, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_gettransportfolder(uint64_t *pfolder_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_optionsdata(const char *paddress_type,
	uint8_t want_win32, uint8_t *preserved,
	BINARY *poptions_info, BINARY *phelp_file,
	char **ppfile_name, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_getpropertyidsfromnames(uint8_t flags,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getnamesfrompropertyids(
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getpropertiesspecific(uint16_t size_limit,
	uint16_t want_unicode, const PROPTAG_ARRAY *pproptags,
	PROPERTY_ROW *prow, void *plogmap, uint8_t logon_id,
	uint32_t hin);
uint32_t rop_getpropertiesall(uint16_t size_limit,
	uint16_t want_unicode, TPROPVAL_ARRAY *ppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getpropertieslist(PROPTAG_ARRAY *pproptags,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_setproperties(const TPROPVAL_ARRAY *ppropvals,
	PROBLEM_ARRAY *pproblems, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_setpropertiesnoreplicate(
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_deleteproperties(
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_deletepropertiesnoreplicate(
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_querynamedproperties(uint8_t query_flags,
	const GUID *pguid, PROPIDNAME_ARRAY *ppropidnames,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_copyproperties(uint8_t want_asynchronous,
	uint8_t copy_flags, const PROPTAG_ARRAY *pproptags,
	PROBLEM_ARRAY *pproblems, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst);
uint32_t rop_copyto(uint8_t want_asynchronous,
	uint8_t want_subobjects, uint8_t copy_flags,
	const PROPTAG_ARRAY *pexcluded_proptags,
	PROBLEM_ARRAY *pproblems, void *plogmap,
	uint8_t logon_id, uint32_t hsrc, uint32_t hdst);
uint32_t rop_progress(uint8_t want_cancel,
	uint32_t *pcompleted_count, uint32_t *ptotal_count,
	uint8_t *prop_id, uint8_t *ppartial_completion,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_openstream(uint32_t proptag, uint8_t flags,
	uint32_t *pstream_size, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_readstream(uint16_t byte_count,
	uint32_t max_byte_count, BINARY *pdata_bin,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_writestream(const BINARY *pdata_bin,
	uint16_t *pwritten_size, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_commitstream(void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_getstreamsize(uint32_t *pstream_size,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_setstreamsize(uint64_t stream_size,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_seekstream(uint8_t seek_pos,
	int64_t offset, uint64_t *pnew_pos,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_copytostream(uint64_t byte_count,
	uint64_t *pread_bytes, uint64_t *pwritten_bytes,
	void *plogmap, uint8_t logon_id, uint32_t hsrc,
	uint32_t hdst);
uint32_t rop_lockregionstream(uint64_t region_offset,
	uint64_t region_size, uint32_t lock_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_unlockregionstream(uint64_t region_offset,
	uint64_t region_size, uint32_t lock_flags,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_writeandcommitstream(
	const BINARY *pdata, uint16_t *pwritten_size,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_clonestream(void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_modifypermissions(uint8_t flags,
	uint16_t count, const PERMISSION_DATA *prow,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getpermissionstable(uint8_t flags,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_modifyrules(uint8_t flags,
	uint16_t count, const RULE_DATA *prow,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_getrulestable(uint8_t flags,
	void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout);
uint32_t rop_updatedeferredactionmessages(
	const BINARY *pserver_entry_id,
	const BINARY *pclient_entry_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_fasttransferdestconfigure(
	uint8_t source_operation, uint8_t flags,
	void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout);
uint32_t rop_fasttransferdestputbuffer(
	const BINARY *ptransfer_data, uint16_t *ptransfer_status,
	uint16_t *pin_progress_count, uint16_t *ptotal_step_count,
	uint8_t *preserved, uint16_t *pused_size, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_fasttransfersourcegetbuffer(uint16_t buffer_size,
	uint16_t max_buffer_size, uint16_t *ptransfer_status,
	uint16_t *pin_progress_count, uint16_t *ptotal_step_count,
	uint8_t *preserved, BINARY *ptransfer_data,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_fasttransfersourcecopyfolder(uint8_t flags,
	uint8_t send_options, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout);
uint32_t rop_fasttransfersourcecopymessages(
	const LONGLONG_ARRAY *pmessage_ids, uint8_t flags,
	uint8_t send_options, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout);
uint32_t rop_fasttransfersourcecopyto(uint8_t level, uint32_t flags,
	uint8_t send_options, const PROPTAG_ARRAY *pproptags,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_fasttransfersourcecopyproperties(uint8_t level, uint8_t flags,
	uint8_t send_options, const PROPTAG_ARRAY *pproptags, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_tellversion(const uint16_t *pversion,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncconfigure(uint8_t sync_type, uint8_t send_options,
	uint16_t sync_flags, const RESTRICTION *pres, uint32_t extra_flags,
	const PROPTAG_ARRAY *pproptags, void *plogmap, uint8_t logon_id,
	uint32_t hin, uint32_t *phout);
uint32_t rop_syncimportmessagechange(uint8_t import_flags,
	const TPROPVAL_ARRAY *ppropvals, uint64_t *pmessage_id,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_syncimportreadstatechanges(uint16_t count,
	const MESSAGE_READ_STAT *pread_stat,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncimporthierarchychange(const TPROPVAL_ARRAY *phichyvals,
	const TPROPVAL_ARRAY *ppropvals, uint64_t *pfolder_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncimportdeletes(
	uint8_t flags, const TPROPVAL_ARRAY *ppropvals,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncimportmessagemove(
	const BINARY *psrc_folder_id, const BINARY *psrc_message_id,
	const BINARY *pchange_list, const BINARY *pdst_message_id,
	const BINARY *pchange_number, uint64_t *pmessage_id,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncopencollector(uint8_t is_content_collector,
	void *plogmap, uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_syncgettransferstate(void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
uint32_t rop_syncuploadstatestreambegin(uint32_t proptag_state,
	uint32_t buffer_size, void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncuploadstatestreamcontinue(const BINARY *pstream_data,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_syncuploadstatestreamend(void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_setlocalreplicamidsetdeleted(uint32_t count,
	const LONG_TERM_ID_RANGE *prange, void *plogmap,
	uint8_t logon_id, uint32_t hin);
uint32_t rop_getlocalreplicaids(uint32_t count,
	GUID *pguid, uint8_t *pglobal_count,
	void *plogmap, uint8_t logon_id, uint32_t hin);
uint32_t rop_registernotification(
	uint8_t notification_types, uint8_t reserved,
	uint8_t want_whole_store, const uint64_t *pfolder_id,
	const uint64_t *pmessage_id, void *plogmap,
	uint8_t logon_id, uint32_t hin, uint32_t *phout);
void rop_release(void *plogmap, uint8_t logon_id, uint32_t hin);
