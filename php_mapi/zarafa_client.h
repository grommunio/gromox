#pragma once
#include "php.h"
#undef slprintf
#undef vslprintf
#undef snprintf
#undef vsnprintf
#undef vasprintf
#undef asprintf
#include <cstdint>

struct zcreq;
struct zcresp;
extern zend_bool zarafa_client_do_rpc(const zcreq *, zcresp *);
extern uint32_t zarafa_client_setpropval(GUID hsession, uint32_t hobject, uint32_t proptag, const void *pvalue);
extern uint32_t zarafa_client_getpropval(GUID hsession, uint32_t hobject, uint32_t proptag, void **ppvalue);

#define IDLOUT
#define ZCIDL(n, p) extern uint32_t zarafa_client_ ## n p;
/* When calling these functions, none of the IDLOUT parameters may be NULL */
ZCIDL(logon, (const char *username, const char *password, uint32_t flags, IDLOUT GUID *hsession))
ZCIDL(uinfo, (const char *username, IDLOUT BINARY *entryid, char **pdisplay_name, char **px500dn, uint32_t *privilege_bits))
ZCIDL(unloadobject, (GUID hsession, uint32_t hobject))
ZCIDL(openentry, (GUID hsession, BINARY entryid, uint32_t flags, IDLOUT uint8_t *mapi_type, uint32_t *hobject))
ZCIDL(openstoreentry, (GUID hsession, uint32_t hobject, BINARY entryid, uint32_t flags, IDLOUT uint8_t *mapi_type, uint32_t *hxobject))
ZCIDL(openabentry, (GUID hsession, BINARY entryid, IDLOUT uint8_t *mapi_type, uint32_t *hobject))
ZCIDL(resolvename, (GUID hsession, const TARRAY_SET *pcond_set, IDLOUT TARRAY_SET *result_set))
ZCIDL(getpermissions, (GUID hsession, uint32_t hobject, IDLOUT PERMISSION_SET *perm_set))
ZCIDL(modifypermissions, (GUID hsession, uint32_t hfolder, const PERMISSION_SET *pset))
ZCIDL(modifyrules, (GUID hsession, uint32_t hfolder, uint32_t flags, const RULE_LIST *plist))
ZCIDL(getabgal, (GUID hsession, IDLOUT BINARY *entryid))
ZCIDL(loadstoretable, (GUID hsession, IDLOUT uint32_t *hobject))
ZCIDL(openstore, (GUID hsession, BINARY entryid, IDLOUT uint32_t *hobject))
ZCIDL(openprofilesec, (GUID hsession, const FLATUID *puid, IDLOUT uint32_t *hobject))
ZCIDL(loadhierarchytable, (GUID hsession, uint32_t hfolder, uint32_t flags, IDLOUT uint32_t *hobject))
ZCIDL(loadcontenttable, (GUID hsession, uint32_t hfolder, uint32_t flags, IDLOUT uint32_t *hobject))
ZCIDL(loadrecipienttable, (GUID hsession, uint32_t hmessage, IDLOUT uint32_t *hobject))
ZCIDL(loadruletable, (GUID hsession, uint32_t hfolder, IDLOUT uint32_t *hobject))
ZCIDL(createmessage, (GUID hsession, uint32_t hfolder,  uint32_t flags, IDLOUT uint32_t *hobject))
ZCIDL(deletemessages, (GUID hsession, uint32_t hfolder, const BINARY_ARRAY *pentryids, uint32_t flags))
ZCIDL(copymessages, (GUID hsession, uint32_t hsrcfolder, uint32_t hdstfolder, const BINARY_ARRAY *pentryids, uint32_t flags))
ZCIDL(setreadflags, (GUID hsession, uint32_t hfolder, const BINARY_ARRAY *pentryids, uint32_t flags))
ZCIDL(createfolder, (GUID hsession, uint32_t hparent_folder, uint32_t folder_type, const char *folder_name, const char *folder_comment, uint32_t flags, IDLOUT uint32_t *hobject))
ZCIDL(deletefolder, (GUID hsession, uint32_t hparent_folder, BINARY entryid, uint32_t flags))
ZCIDL(emptyfolder, (GUID hsession, uint32_t hfolder, uint32_t flags))
ZCIDL(copyfolder, (GUID hsession, uint32_t hsrc_folder, BINARY entryid, uint32_t hdst_folder, const char *new_name, uint32_t flags))
ZCIDL(getstoreentryid, (const char *mailbox_dn, IDLOUT BINARY *entryid))
ZCIDL(entryidfromsourcekey, (GUID hsession, uint32_t hstore, BINARY folder_key, const BINARY *pmessage_key, IDLOUT BINARY *entryid))
ZCIDL(storeadvise, (GUID hsession, uint32_t hstore, const BINARY *pentryid, uint32_t event_mask, IDLOUT uint32_t *sub_id))
ZCIDL(unadvise, (GUID hsession, uint32_t hstore, uint32_t sub_id))
ZCIDL(notifdequeue, (const NOTIF_SINK *psink, uint32_t timeval, IDLOUT ZNOTIFICATION_ARRAY *notifications))
ZCIDL(queryrows, (GUID hsession, uint32_t htable, uint32_t start, uint32_t count, const RESTRICTION *prestriction, const PROPTAG_ARRAY *pproptags, IDLOUT TARRAY_SET *rowset))
ZCIDL(setcolumns, (GUID hsession, uint32_t htable, const PROPTAG_ARRAY *pproptags, uint32_t flags))
ZCIDL(seekrow, (GUID hsession, uint32_t htable, uint32_t bookmark, int32_t seek_rows, IDLOUT int32_t *sought_rows))
ZCIDL(sorttable, (GUID hsession, uint32_t htable, const SORTORDER_SET *psortset))
ZCIDL(getrowcount, (GUID hsession, uint32_t htable, IDLOUT uint32_t *count))
ZCIDL(restricttable, (GUID hsession, uint32_t htable, const RESTRICTION *prestriction, uint32_t flags))
ZCIDL(findrow, (GUID hsession, uint32_t htable, uint32_t bookmark, const RESTRICTION *prestriction, uint32_t flags, IDLOUT uint32_t *row_idx))
ZCIDL(createbookmark, (GUID hsession, uint32_t htable, IDLOUT uint32_t *bookmark))
ZCIDL(freebookmark, (GUID hsession, uint32_t htable, uint32_t bookmark))
ZCIDL(getreceivefolder, (GUID hsession, uint32_t hstore, const char *pstrclass, IDLOUT BINARY *entryid))
ZCIDL(modifyrecipients, (GUID hsession, uint32_t hmessage, uint32_t flags, const TARRAY_SET *prcpt_list))
ZCIDL(submitmessage, (GUID hsession, uint32_t hmessage))
ZCIDL(loadattachmenttable, (GUID hsession, uint32_t hmessage, IDLOUT uint32_t *hobject))
ZCIDL(openattachment, (GUID hsession, uint32_t hmessage, uint32_t attach_id, IDLOUT uint32_t *hobject))
ZCIDL(createattachment, (GUID hsession, uint32_t hmessage, IDLOUT uint32_t *hobject))
ZCIDL(deleteattachment, (GUID hsession, uint32_t hmessage, uint32_t attach_id))
ZCIDL(setpropvals, (GUID hsession, uint32_t hobject, const TPROPVAL_ARRAY *ppropvals))
ZCIDL(getpropvals, (GUID hsession, uint32_t hobject, const PROPTAG_ARRAY *pproptags, IDLOUT TPROPVAL_ARRAY *propvals))
ZCIDL(deletepropvals, (GUID hsession, uint32_t hobject, const PROPTAG_ARRAY *pproptags))
ZCIDL(setmessagereadflag, (GUID hsession, uint32_t hmessage, uint32_t flags))
ZCIDL(openembedded, (GUID hsession, uint32_t hattachment, uint32_t flags, IDLOUT uint32_t *hobject))
ZCIDL(getnamedpropids, (GUID hsession, uint32_t hstore, const PROPNAME_ARRAY *ppropnames, IDLOUT PROPID_ARRAY *propids))
ZCIDL(getpropnames, (GUID hsession, uint32_t hstore, const PROPID_ARRAY *ppropids, IDLOUT PROPNAME_ARRAY *propnames))
ZCIDL(copyto, (GUID hsession, uint32_t hsrcobject, const PROPTAG_ARRAY *pexclude_proptags, uint32_t hdstobject, uint32_t flags))
ZCIDL(savechanges, (GUID hsession, uint32_t hobject))
ZCIDL(hierarchysync, (GUID hsession, uint32_t hfolder, IDLOUT uint32_t *hobject))
ZCIDL(contentsync, (GUID hsession, uint32_t hfolder, IDLOUT uint32_t *hobject))
ZCIDL(configsync, (GUID hsession, uint32_t hctx, uint32_t flags, const BINARY *pstate, const RESTRICTION *prestriction, IDLOUT zend_bool *b_changed, uint32_t *count))
ZCIDL(statesync, (GUID hsession, uint32_t hctx, IDLOUT BINARY *state))
ZCIDL(syncmessagechange, (GUID hsession, uint32_t hctx, IDLOUT zend_bool *b_new, TPROPVAL_ARRAY *proplist))
ZCIDL(syncfolderchange, (GUID hsession, uint32_t hctx, IDLOUT TPROPVAL_ARRAY *proplist))
ZCIDL(syncreadstatechanges, (GUID hsession, uint32_t hctx, IDLOUT STATE_ARRAY *states))
ZCIDL(syncdeletions, (GUID hsession, uint32_t hctx, uint32_t flags, IDLOUT BINARY_ARRAY *bins))
ZCIDL(hierarchyimport, (GUID hsession, uint32_t hfolder, IDLOUT uint32_t *hobject))
ZCIDL(contentimport, (GUID hsession, uint32_t hfolder, IDLOUT uint32_t *hobject))
ZCIDL(configimport, (GUID hsession, uint32_t hctx, uint8_t sync_type, const BINARY *pstate))
ZCIDL(stateimport, (GUID hsession, uint32_t hctx, IDLOUT BINARY *state))
ZCIDL(importmessage, (GUID hsession, uint32_t hctx, uint32_t flags, const TPROPVAL_ARRAY *pproplist, IDLOUT uint32_t *hobject))
ZCIDL(importfolder, (GUID hsession, uint32_t hctx, const TPROPVAL_ARRAY *pproplist))
ZCIDL(importdeletion, (GUID hsession, uint32_t hctx, uint32_t flags, const BINARY_ARRAY *pbins))
ZCIDL(importreadstates, (GUID hsession, uint32_t hctx, const STATE_ARRAY *pstates))
ZCIDL(getsearchcriteria, (GUID hsession, uint32_t hfolder, IDLOUT BINARY_ARRAY *folder_array, RESTRICTION **prestriction, uint32_t *search_stat))
ZCIDL(setsearchcriteria, (GUID hsession, uint32_t hfolder, uint32_t flags, const BINARY_ARRAY *pfolder_array, const RESTRICTION *prestriction))
ZCIDL(messagetorfc822, (GUID hsession, uint32_t hmessage, IDLOUT BINARY *eml_bin))
ZCIDL(rfc822tomessage, (GUID hsession, uint32_t hmessage, uint32_t mxf_flags, const BINARY *peml_bin))
ZCIDL(messagetoical, (GUID hsession, uint32_t hmessage, IDLOUT BINARY *ical_bin))
ZCIDL(icaltomessage, (GUID hsession, uint32_t hmessage, const BINARY *pical_bin))
ZCIDL(messagetovcf, (GUID hsession, uint32_t hmessage, IDLOUT BINARY *vcf_bin))
ZCIDL(vcftomessage, (GUID hsession, uint32_t hmessage, const BINARY *pvcf_bin))
ZCIDL(getuseravailability, (GUID hsession, BINARY entryid, uint64_t starttime, uint64_t endtime, IDLOUT char **result_string))
ZCIDL(setpasswd, (const char *username, const char *passwd, const char *new_passwd))
ZCIDL(linkmessage, (GUID hsession, BINARY search_entryid, BINARY message_entryid))
ZCIDL(checksession, (GUID hsession))
ZCIDL(imtomessage2, (GUID session, uint32_t folder, uint32_t data_type, const char *im_data, IDLOUT LONG_ARRAY *msg_handles))
#undef ZCIDL
#undef IDLOUT
