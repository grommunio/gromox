#ifndef _H_ZARAFA_CLIENT_
#define _H_ZARAFA_CLIENT_
#include "php.h"
#include "types.h"

uint32_t zarafa_client_logon(const char *username,
	const char *password, uint32_t flags, GUID *phsession);

uint32_t zarafa_client_uinfo(const char *username, BINARY *pentryid,
	char **ppdisplay_name, char **ppx500dn, uint32_t *pprivilege_bits);

uint32_t zarafa_client_unloadobject(GUID hsession, uint32_t hobject);

uint32_t zarafa_client_openentry(GUID hsession, BINARY entryid,
	uint32_t flags, uint8_t *pmapi_type, uint32_t *phobject);

uint32_t zarafa_client_openstoreentry(GUID hsession, uint32_t hobject,
	BINARY entryid, uint32_t flags, uint8_t *pmapi_type, uint32_t *phobject);

uint32_t zarafa_client_openabentry(GUID hsession,
	BINARY entryid, uint8_t *pmapi_type, uint32_t *phobject);

uint32_t zarafa_client_resolvename(GUID hsession,
	const TARRAY_SET *pcond_set, TARRAY_SET *presult_set);

uint32_t zarafa_client_getpermissions(GUID hsession,
	uint32_t hobject, PERMISSION_SET *pperm_set);

uint32_t zarafa_client_modifypermissions(GUID hsession,
	uint32_t hfolder, const PERMISSION_SET *pset);

uint32_t zarafa_client_modifyrules(GUID hsession,
	uint32_t hfolder, uint32_t flags, const RULE_LIST *plist);

uint32_t zarafa_client_getabgal(GUID hsession, BINARY *pentryid);

uint32_t zarafa_client_loadstoretable(
	GUID hsession, uint32_t *phobject);

uint32_t zarafa_client_openstore(GUID hsession,
	BINARY entryid, uint32_t *phobject);

uint32_t zarafa_client_openpropfilesec(GUID hsession,
	const FLATUID *puid, uint32_t *phobject);

uint32_t zarafa_client_loadhierarchytable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject);

uint32_t zarafa_client_loadcontenttable(GUID hsession,
	uint32_t hfolder, uint32_t flags, uint32_t *phobject);

uint32_t zarafa_client_loadrecipienttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);

uint32_t zarafa_client_loadruletable(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);

uint32_t zarafa_client_createmessage(GUID hsession,
	uint32_t hfolder,  uint32_t flags, uint32_t *phobject);

uint32_t zarafa_client_deletemessages(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags);

uint32_t zarafa_client_copymessages(GUID hsession,
	uint32_t hsrcfolder, uint32_t hdstfolder,
	const BINARY_ARRAY *pentryids, uint32_t flags);

uint32_t zarafa_client_setreadflags(GUID hsession,
	uint32_t hfolder, const BINARY_ARRAY *pentryids,
	uint32_t flags);

uint32_t zarafa_client_createfolder(GUID hsession,
	uint32_t hparent_folder, uint32_t folder_type,
	const char *folder_name, const char *folder_comment,
	uint32_t flags, uint32_t *phobject);

uint32_t zarafa_client_deletefolder(GUID hsession,
	uint32_t hparent_folder, BINARY entryid, uint32_t flags);

uint32_t zarafa_client_emptyfolder(GUID hsession,
	uint32_t hfolder, uint32_t flags);

uint32_t zarafa_client_copyfolder(GUID hsession,
	uint32_t hsrc_folder, BINARY entryid, uint32_t hdst_folder,
	const char *new_name, uint32_t flags);

uint32_t zarafa_client_getstoreentryid(
	const char *mailbox_dn, BINARY *pentryid);

uint32_t zarafa_client_entryidfromsourcekey(
	GUID hsession, uint32_t hstore, BINARY folder_key,
	const BINARY *pmessage_key, BINARY *pentryid);

uint32_t zarafa_client_storeadvise(GUID hsession,
	uint32_t hstore, const BINARY *pentryid,
	uint32_t event_mask, uint32_t *psub_id);

uint32_t zarafa_client_unadvise(GUID hsession,
	uint32_t hstore, uint32_t sub_id);

uint32_t zarafa_client_notifdequeue(const NOTIF_SINK *psink,
	uint32_t timeval, ZNOTIFICATION_ARRAY *pnotifications);

uint32_t zarafa_client_queryrows(
	GUID hsession, uint32_t htable, uint32_t start,
	uint32_t count, const RESTRICTION *prestriction,
	const PROPTAG_ARRAY *pproptags, TARRAY_SET *prowset);
	
uint32_t zarafa_client_setcolumns(GUID hsession, uint32_t htable,
	const PROPTAG_ARRAY *pproptags, uint32_t flags);

uint32_t zarafa_client_seekrow(GUID hsession,
	uint32_t htable, uint32_t bookmark, int32_t seek_rows,
	int32_t *psought_rows);

uint32_t zarafa_client_sorttable(GUID hsession,
	uint32_t htable, const SORTORDER_SET *psortset);

uint32_t zarafa_client_getrowcount(GUID hsession,
	uint32_t htable, uint32_t *pcount);

uint32_t zarafa_client_restricttable(GUID hsession, uint32_t htable,
	const RESTRICTION *prestriction, uint32_t flags);

uint32_t zarafa_client_findrow(GUID hsession, uint32_t htable,
	uint32_t bookmark, const RESTRICTION *prestriction,
	uint32_t flags, uint32_t *prow_idx);

uint32_t zarafa_client_createbookmark(GUID hsession,
	uint32_t htable, uint32_t *pbookmark);

uint32_t zarafa_client_freebookmark(GUID hsession,
	uint32_t htable, uint32_t bookmark);

uint32_t zarafa_client_getreceivefolder(GUID hsession,
	uint32_t hstore, const char *pstrclass, BINARY *pentryid);

uint32_t zarafa_client_modifyrecipients(GUID hsession,
	uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list);

uint32_t zarafa_client_submitmessage(GUID hsession, uint32_t hmessage);

uint32_t zarafa_client_loadattachmenttable(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);

uint32_t zarafa_client_openattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id, uint32_t *phobject);

uint32_t zarafa_client_createattachment(GUID hsession,
	uint32_t hmessage, uint32_t *phobject);
	
uint32_t zarafa_client_deleteattachment(GUID hsession,
	uint32_t hmessage, uint32_t attach_id);

uint32_t zarafa_client_setpropval(GUID hsession,
	uint32_t hobject, uint32_t proptag, const void *pvalue);

uint32_t zarafa_client_setpropvals(GUID hsession,
	uint32_t hobject, const TPROPVAL_ARRAY *ppropvals);

uint32_t zarafa_client_getpropval(GUID hsession,
	uint32_t hobject, uint32_t proptag, void **ppvalue);

uint32_t zarafa_client_getpropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

uint32_t zarafa_client_deletepropvals(GUID hsession,
	uint32_t hobject, const PROPTAG_ARRAY *pproptags);

uint32_t zarafa_client_setmessagereadflag(
	GUID hsession, uint32_t hmessage, uint32_t flags);

uint32_t zarafa_client_openembedded(GUID hsession,
	uint32_t hattachment, uint32_t flags, uint32_t *phobject);

uint32_t zarafa_client_getnamedpropids(GUID hsession, uint32_t hstore,
	const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids);

uint32_t zarafa_client_getpropnames(GUID hsession, uint32_t hstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);

uint32_t zarafa_client_copyto(GUID hsession, uint32_t hsrcobject,
	const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject,
	uint32_t flags);

uint32_t zarafa_client_savechanges(GUID hsession, uint32_t hobject);

uint32_t zarafa_client_hierarchysync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);

uint32_t zarafa_client_contentsync(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);

uint32_t zarafa_client_configsync(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY *pstate,
	const RESTRICTION *prestriction, zend_bool *pb_changed,
	uint32_t *pcount);

uint32_t zarafa_client_statesync(GUID hsession,
	uint32_t hctx, BINARY *pstate);

uint32_t zarafa_client_syncmessagechange(GUID hsession,
	uint32_t hctx, zend_bool *pb_new, TPROPVAL_ARRAY *pproplist);

uint32_t zarafa_client_syncfolderchange(GUID hsession,
	uint32_t hctx, TPROPVAL_ARRAY *pproplist);

uint32_t zarafa_client_syncreadstatechanges(
	GUID hsession, uint32_t hctx, STATE_ARRAY *pstates);

uint32_t zarafa_client_syncdeletions(GUID hsession,
	uint32_t hctx, uint32_t flags, BINARY_ARRAY *pbins);

uint32_t zarafa_client_hierarchyimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);

uint32_t zarafa_client_contentimport(GUID hsession,
	uint32_t hfolder, uint32_t *phobject);
	
uint32_t zarafa_client_configimport(GUID hsession,
	uint32_t hctx, uint8_t sync_type, const BINARY *pstate);

uint32_t zarafa_client_stateimport(GUID hsession,
	uint32_t hctx, BINARY *pstate);

uint32_t zarafa_client_importmessage(GUID hsession, uint32_t hctx,
	uint32_t flags, const TPROPVAL_ARRAY *pproplist, uint32_t *phobject);

uint32_t zarafa_client_importfolder(GUID hsession,
	uint32_t hctx, const TPROPVAL_ARRAY *pproplist);

uint32_t zarafa_client_importdeletion(GUID hsession,
	uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins);

uint32_t zarafa_client_importreadstates(GUID hsession,
	uint32_t hctx, const STATE_ARRAY *pstates);

uint32_t zarafa_client_getsearchcriteria(GUID hsession,
	uint32_t hfolder, BINARY_ARRAY *pfolder_array,
	RESTRICTION **pprestriction, uint32_t *psearch_stat);

uint32_t zarafa_client_setsearchcriteria(
	GUID hsession, uint32_t hfolder, uint32_t flags,
	const BINARY_ARRAY *pfolder_array,
	const RESTRICTION *prestriction);

uint32_t zarafa_client_messagetorfc822(GUID hsession,
	uint32_t hmessage, BINARY *peml_bin);

uint32_t zarafa_client_rfc822tomessage(GUID hsession,
	uint32_t hmessage, const BINARY *peml_bin);

uint32_t zarafa_client_messagetoical(GUID hsession,
	uint32_t hmessage, BINARY *pical_bin);

uint32_t zarafa_client_icaltomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pical_bin);

uint32_t zarafa_client_messagetovcf(GUID hsession,
	uint32_t hmessage, BINARY *pvcf_bin);

uint32_t zarafa_client_vcftomessage(GUID hsession,
	uint32_t hmessage, const BINARY *pvcf_bin);

uint32_t zarafa_client_getuseravailability(GUID hsession,
	BINARY entryid, uint64_t starttime, uint64_t endtime,
	char **ppresult_string);

uint32_t zarafa_client_setpasswd(const char *username,
	const char *passwd, const char *new_passwd);

uint32_t zarafa_client_linkmessage(GUID hsession,
	BINARY search_entryid, BINARY message_entryid);

#endif /* _H_ZARAFA_CLIENT_ */
