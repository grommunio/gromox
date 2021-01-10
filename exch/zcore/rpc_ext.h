#pragma once
#include <cstdint>
#include <gromox/mapi_types.hpp>
#include "common_util.h"

struct REQ_LOGON {
	char *username;
	char *password;
	uint32_t flags;
};

struct REQ_CHECKSESSION {
	GUID hsession;
};

struct REQ_UINFO {
	char *username;
};

struct REQ_UNLOADOBJECT {
	GUID hsession;
	uint32_t hobject;
};

struct REQ_OPENENTRY {
	GUID hsession;
	BINARY entryid;
	uint32_t flags;
};

struct REQ_OPENSTOREENTRY {
	GUID hsession;
	uint32_t hobject;
	BINARY entryid;
	uint32_t flags;
};

struct REQ_OPENABENTRY {
	GUID hsession;
	BINARY entryid;
};

struct REQ_RESOLVENAME {
	GUID hsession;
	TARRAY_SET *pcond_set;
};

struct REQ_GETPERMISSIONS {
	GUID hsession;
	uint32_t hobject;
};

struct REQ_MODIFYPERMISSIONS {
	GUID hsession;
	uint32_t hfolder;
	PERMISSION_SET *pset;
};

struct REQ_MODIFYRULES {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	RULE_LIST *plist;
};

struct REQ_GETABGAL {
	GUID hsession;
};

struct REQ_LOADSTORETABLE {
	GUID hsession;
};

struct REQ_OPENSTORE {
	GUID hsession;
	BINARY entryid;
};

struct REQ_OPENPROPFILESEC {
	GUID hsession;
	const FLATUID *puid;
};

struct REQ_LOADHIERARCHYTABLE {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct REQ_LOADCONTENTTABLE {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct REQ_LOADRECIPIENTTABLE {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_LOADRULETABLE {
	GUID hsession;
	uint32_t hfolder;
};
	
struct REQ_CREATEMESSAGE {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct REQ_DELETEMESSAGES {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct REQ_COPYMESSAGES {
	GUID hsession;
	uint32_t hsrcfolder;
	uint32_t hdstfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct REQ_SETREADFLAGS {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct REQ_CREATEFOLDER {
	GUID hsession;
	uint32_t hparent_folder;
	uint32_t folder_type;
	char *folder_name;
	char *folder_comment;
	uint32_t flags;
};

struct REQ_DELETEFOLDER {
	GUID hsession;
	uint32_t hparent_folder;
	BINARY entryid;
	uint32_t flags;
};

struct REQ_EMPTYFOLDER {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct REQ_COPYFOLDER {
	GUID hsession;
	uint32_t hsrc_folder;
	BINARY entryid;
	uint32_t hdst_folder;
	char *new_name;
	uint32_t flags;
};

struct REQ_GETSTOREENTRYID {
	char *mailbox_dn;
};

struct REQ_ENTRYIDFROMSOURCEKEY {
	GUID hsession;
	uint32_t hstore;
	BINARY folder_key;
	BINARY *pmessage_key;
};

struct REQ_STOREADVISE {
	GUID hsession;
	uint32_t hstore;
	BINARY *pentryid;
	uint32_t event_mask;
};

struct REQ_UNADVISE {
	GUID hsession;
	uint32_t hstore;
	uint32_t sub_id;
};

struct REQ_NOTIFDEQUEUE {
	NOTIF_SINK *psink;
	uint32_t timeval;
};

struct REQ_QUERYROWS {
	GUID hsession;
	uint32_t htable;
	uint32_t start;
	uint32_t count;
	RESTRICTION *prestriction;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_SETCOLUMNS {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct REQ_SEEKROW {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	int32_t seek_rows;
};

struct REQ_SORTTABLE {
	GUID hsession;
	uint32_t htable;
	SORTORDER_SET *psortset;
};

struct REQ_GETROWCOUNT {
	GUID hsession;
	uint32_t htable;
};

struct REQ_RESTRICTTABLE {
	GUID hsession;
	uint32_t htable;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct REQ_FINDROW {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct REQ_CREATEBOOKMARK {
	GUID hsession;
	uint32_t htable;
};

struct REQ_FREEBOOKMARK {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
};

struct REQ_GETRECEIVEFOLDER {
	GUID hsession;
	uint32_t hstore;
	char *pstrclass;
};

struct REQ_MODIFYRECIPIENTS {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
	TARRAY_SET *prcpt_list;
};

struct REQ_SUBMITMESSAGE {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_LOADATTACHMENTTABLE {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_OPENATTACHMENT {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct REQ_CREATEATTACHMENT {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_DELETEATTACHMENT {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct REQ_SETPROPVALS {
	GUID hsession;
	uint32_t hobject;
	TPROPVAL_ARRAY *ppropvals;
};

struct REQ_GETPROPVALS {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_DELETEPROPVALS {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct REQ_SETMESSAGEREADFLAG {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
};

struct REQ_OPENEMBEDDED {
	GUID hsession;
	uint32_t hattachment;
	uint32_t flags;
};

struct REQ_GETNAMEDPROPIDS {
	GUID hsession;
	uint32_t hstore;
	PROPNAME_ARRAY *ppropnames;
};

struct REQ_GETPROPNAMES {
	GUID hsession;
	uint32_t hstore;
	PROPID_ARRAY *ppropids;
};

struct REQ_COPYTO {
	GUID hsession;
	uint32_t hsrcobject;
	PROPTAG_ARRAY *pexclude_proptags;
	uint32_t hdstobject;
	uint32_t flags;
};

struct REQ_SAVECHANGES {
	GUID hsession;
	uint32_t hobject;
};

struct REQ_HIERARCHYSYNC {
	GUID hsession;
	uint32_t hfolder;
};

struct REQ_CONTENTSYNC {
	GUID hsession;
	uint32_t hfolder;
};

struct REQ_CONFIGSYNC {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY *pstate;
	RESTRICTION *prestriction;
};

struct REQ_STATESYNC {
	GUID hsession;
	uint32_t hctx;
};

struct REQ_SYNCMESSAGECHANGE {
	GUID hsession;
	uint32_t hctx;
};

struct REQ_SYNCFOLDERCHANGE {
	GUID hsession;
	uint32_t hctx;
};

struct REQ_SYNCREADSTATECHANGES {
	GUID hsession;
	uint32_t hctx;
};

struct REQ_SYNCDELETIONS {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
};

struct REQ_HIERARCHYIMPORT {
	GUID hsession;
	uint32_t hfolder;
};

struct REQ_CONTENTIMPORT {
	GUID hsession;
	uint32_t hfolder;
};

struct REQ_CONFIGIMPORT {
	GUID hsession;
	uint32_t hctx;
	uint8_t sync_type;
	BINARY *pstate;
};
	
struct REQ_STATEIMPORT {
	GUID hsession;
	uint32_t hctx;
};

struct REQ_IMPORTMESSAGE {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	TPROPVAL_ARRAY *pproplist;
};
	
struct REQ_IMPORTFOLDER {
	GUID hsession;
	uint32_t hctx;
	TPROPVAL_ARRAY *pproplist;
};

struct REQ_IMPORTDELETION {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY_ARRAY *pbins;
};

struct REQ_IMPORTREADSTATES {
	GUID hsession;
	uint32_t hctx;
	STATE_ARRAY *pstates;
};

struct REQ_GETSEARCHCRITERIA {
	GUID hsession;
	uint32_t hfolder;
};
	
struct REQ_SETSEARCHCRITERIA {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	BINARY_ARRAY *pfolder_array;
	RESTRICTION *prestriction;
};

struct REQ_MESSAGETORFC822 {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_RFC822TOMESSAGE {
	GUID hsession;
	uint32_t hmessage;
	BINARY *peml_bin;
};

struct REQ_MESSAGETOICAL {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_ICALTOMESSAGE {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pical_bin;
};

struct REQ_MESSAGETOVCF {
	GUID hsession;
	uint32_t hmessage;
};

struct REQ_VCFTOMESSAGE {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pvcf_bin;
};

struct REQ_GETUSERAVAILABILITY {
	GUID hsession;
	BINARY entryid;
	uint64_t starttime;
	uint64_t endtime;
};

struct REQ_SETPASSWD {
	char *username;
	char *passwd;
	char *new_passwd;
};

struct REQ_LINKMESSAGE {
	GUID hsession;
	BINARY search_entryid;
	BINARY message_entryid;
};

union REQUEST_PAYLOAD {
	REQ_LOGON logon;
	REQ_CHECKSESSION checksession;
	REQ_UINFO uinfo;
	REQ_UNLOADOBJECT unloadobject;
	REQ_OPENENTRY openentry;
	REQ_OPENSTOREENTRY openstoreentry;
	REQ_OPENABENTRY openabentry;
	REQ_RESOLVENAME resolvename;
	REQ_GETPERMISSIONS getpermissions;
	REQ_MODIFYPERMISSIONS modifypermissions;
	REQ_MODIFYRULES modifyrules;
	REQ_GETABGAL getabgal;
	REQ_LOADSTORETABLE loadstoretable;
	REQ_OPENSTORE openstore;
	REQ_OPENPROPFILESEC openpropfilesec;
	REQ_LOADHIERARCHYTABLE loadhierarchytable;
	REQ_LOADCONTENTTABLE loadcontenttable;
	REQ_LOADRECIPIENTTABLE loadrecipienttable;
	REQ_LOADRULETABLE loadruletable;
	REQ_CREATEMESSAGE createmessage;
	REQ_DELETEMESSAGES deletemessages;
	REQ_COPYMESSAGES copymessages;
	REQ_SETREADFLAGS setreadflags;
	REQ_CREATEFOLDER createfolder;
	REQ_DELETEFOLDER deletefolder;
	REQ_EMPTYFOLDER emptyfolder;
	REQ_COPYFOLDER copyfolder;
	REQ_GETSTOREENTRYID getstoreentryid;
	REQ_ENTRYIDFROMSOURCEKEY entryidfromsourcekey;
	REQ_STOREADVISE storeadvise;
	REQ_UNADVISE unadvise;
	REQ_NOTIFDEQUEUE notifdequeue;
	REQ_QUERYROWS queryrows;
	REQ_SETCOLUMNS setcolumns;
	REQ_SEEKROW seekrow;
	REQ_SORTTABLE sorttable;
	REQ_GETROWCOUNT getrowcount;
	REQ_RESTRICTTABLE restricttable;
	REQ_FINDROW findrow;
	REQ_CREATEBOOKMARK createbookmark;
	REQ_FREEBOOKMARK freebookmark;
	REQ_GETRECEIVEFOLDER getreceivefolder;
	REQ_MODIFYRECIPIENTS modifyrecipients;
	REQ_SUBMITMESSAGE submitmessage;
	REQ_LOADATTACHMENTTABLE loadattachmenttable;
	REQ_OPENATTACHMENT openattachment;
	REQ_CREATEATTACHMENT createattachment;
	REQ_DELETEATTACHMENT deleteattachment;
	REQ_SETPROPVALS setpropvals;
	REQ_GETPROPVALS getpropvals;
	REQ_DELETEPROPVALS deletepropvals;
	REQ_SETMESSAGEREADFLAG setmessagereadflag;
	REQ_OPENEMBEDDED openembedded;
	REQ_GETNAMEDPROPIDS getnamedpropids;
	REQ_GETPROPNAMES getpropnames;
	REQ_COPYTO copyto;
	REQ_SAVECHANGES savechanges;
	REQ_HIERARCHYSYNC hierarchysync;
	REQ_CONTENTSYNC contentsync;
	REQ_CONFIGSYNC configsync;
	REQ_STATESYNC statesync;
	REQ_SYNCMESSAGECHANGE syncmessagechange;
	REQ_SYNCFOLDERCHANGE syncfolderchange;
	REQ_SYNCREADSTATECHANGES syncreadstatechanges;
	REQ_SYNCDELETIONS syncdeletions;
	REQ_HIERARCHYIMPORT hierarchyimport;
	REQ_CONTENTIMPORT contentimport;
	REQ_CONFIGIMPORT configimport;
	REQ_STATEIMPORT stateimport;
	REQ_IMPORTMESSAGE importmessage;
	REQ_IMPORTFOLDER importfolder;
	REQ_IMPORTDELETION importdeletion;
	REQ_IMPORTREADSTATES importreadstates;
	REQ_GETSEARCHCRITERIA getsearchcriteria;
	REQ_SETSEARCHCRITERIA setsearchcriteria;
	REQ_MESSAGETORFC822 messagetorfc822;
	REQ_RFC822TOMESSAGE rfc822tomessage;
	REQ_MESSAGETOICAL messagetoical;
	REQ_ICALTOMESSAGE icaltomessage;
	REQ_MESSAGETOVCF messagetovcf;
	REQ_VCFTOMESSAGE vcftomessage;
	REQ_GETUSERAVAILABILITY getuseravailability;
	REQ_SETPASSWD setpasswd;
	REQ_LINKMESSAGE linkmessage;
};

struct RPC_REQUEST {
	uint8_t call_id;
	REQUEST_PAYLOAD payload;
};

struct RESP_LOGON {
	GUID hsession;
};

struct RESP_UINFO {
	BINARY entryid;
	char *pdisplay_name;
	char *px500dn;
	uint32_t privilege_bits;
};

struct RESP_OPENENTRY {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct RESP_OPENSTOREENTRY {
	uint8_t mapi_type;
	uint32_t hxobject;
};

struct RESP_OPENABENTRY {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct RESP_RESOLVENAME {
	TARRAY_SET result_set;
};

struct RESP_GETPERMISSIONS {
	PERMISSION_SET perm_set;
};

struct RESP_GETABGAL {
	BINARY entryid;
};

struct RESP_LOADSTORETABLE {
	uint32_t hobject;
};

struct RESP_OPENSTORE {
	uint32_t hobject;
};

struct RESP_OPENPROPFILESEC {
	uint32_t hobject;
};

struct RESP_LOADHIERARCHYTABLE {
	uint32_t hobject;
};

struct RESP_LOADCONTENTTABLE {
	uint32_t hobject;
};

struct RESP_LOADRECIPIENTTABLE {
	uint32_t hobject;
};

struct RESP_LOADRULETABLE {
	uint32_t hobject;
};
	
struct RESP_CREATEMESSAGE {
	uint32_t hobject;
};

struct RESP_CREATEFOLDER {
	uint32_t hobject;
};

struct RESP_GETSTOREENTRYID {
	BINARY entryid;
};

struct RESP_ENTRYIDFROMSOURCEKEY {
	BINARY entryid;
};

struct RESP_STOREADVISE {
	uint32_t sub_id;
};

struct RESP_NOTIFDEQUEUE {
	ZNOTIFICATION_ARRAY notifications;
};

struct RESP_QUERYROWS {
	TARRAY_SET rowset;
};

struct RESP_SETCOLUMNS {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct RESP_SEEKROW {
	int32_t sought_rows;
};

struct RESP_GETROWCOUNT {
	uint32_t count;
};

struct RESP_FINDROW {
	uint32_t row_idx;
};

struct RESP_CREATEBOOKMARK {
	uint32_t bookmark;
};

struct RESP_GETRECEIVEFOLDER {
	BINARY entryid;
};

struct RESP_LOADATTACHMENTTABLE {
	uint32_t hobject;
};

struct RESP_OPENATTACHMENT {
	uint32_t hobject;
};

struct RESP_CREATEATTACHMENT {
	uint32_t hobject;
};

struct RESP_GETPROPVALS {
	TPROPVAL_ARRAY propvals;
};

struct RESP_OPENEMBEDDED {
	uint32_t hobject;
};

struct RESP_GETNAMEDPROPIDS {
	PROPID_ARRAY propids;
};

struct RESP_GETPROPNAMES {
	PROPNAME_ARRAY propnames;
};

struct RESP_HIERARCHYSYNC {
	uint32_t hobject;
};

struct RESP_CONTENTSYNC {
	uint32_t hobject;
};

struct RESP_CONFIGSYNC {
	BOOL b_changed;
	uint32_t count;
};

struct RESP_STATESYNC {
	BINARY state;
};

struct RESP_SYNCMESSAGECHANGE {
	BOOL b_new;
	TPROPVAL_ARRAY proplist;
};

struct RESP_SYNCFOLDERCHANGE {
	TPROPVAL_ARRAY proplist;
};

struct RESP_SYNCREADSTATECHANGES {
	STATE_ARRAY states;
};

struct RESP_SYNCDELETIONS {
	BINARY_ARRAY bins;
};

struct RESP_HIERARCHYIMPORT {
	uint32_t hobject;
};

struct RESP_CONTENTIMPORT {
	uint32_t hobject;
};
	
struct RESP_STATEIMPORT {
	BINARY state;
};

struct RESP_IMPORTMESSAGE {
	uint32_t hobject;
};

struct RESP_GETSEARCHCRITERIA {
	BINARY_ARRAY folder_array;
	RESTRICTION *prestriction;
	uint32_t search_stat;
};

struct RESP_MESSAGETORFC822 {
	BINARY eml_bin;
};

struct RESP_MESSAGETOICAL {
	BINARY ical_bin;
};

struct RESP_MESSAGETOVCF {
	BINARY vcf_bin;
};

struct RESP_GETUSERAVAILABILITY {
	char *result_string;
};

union RESPONSE_PAYLOAD {
	RESP_LOGON logon;
	RESP_UINFO uinfo;
	RESP_OPENENTRY openentry;
	RESP_OPENSTOREENTRY openstoreentry;
	RESP_OPENABENTRY openabentry;
	RESP_RESOLVENAME resolvename;
	RESP_GETPERMISSIONS getpermissions;
	RESP_GETABGAL getabgal;
	RESP_LOADSTORETABLE loadstoretable;
	RESP_OPENSTORE openstore;
	RESP_OPENPROPFILESEC openpropfilesec;
	RESP_LOADHIERARCHYTABLE loadhierarchytable;
	RESP_LOADCONTENTTABLE loadcontenttable;
	RESP_LOADRECIPIENTTABLE loadrecipienttable;
	RESP_LOADRULETABLE loadruletable;
	RESP_CREATEMESSAGE createmessage;
	RESP_CREATEFOLDER createfolder;
	RESP_GETSTOREENTRYID getstoreentryid;
	RESP_ENTRYIDFROMSOURCEKEY entryidfromsourcekey;
	RESP_STOREADVISE storeadvise;
	RESP_NOTIFDEQUEUE notifdequeue;
	RESP_QUERYROWS queryrows;
	RESP_SEEKROW seekrow;
	RESP_GETROWCOUNT getrowcount;
	RESP_FINDROW findrow;
	RESP_CREATEBOOKMARK createbookmark;
	RESP_GETRECEIVEFOLDER getreceivefolder;
	RESP_LOADATTACHMENTTABLE loadattachmenttable;
	RESP_OPENATTACHMENT openattachment;
	RESP_CREATEATTACHMENT createattachment;
	RESP_GETPROPVALS getpropvals;
	RESP_OPENEMBEDDED openembedded;
	RESP_GETNAMEDPROPIDS getnamedpropids;
	RESP_GETPROPNAMES getpropnames;
	RESP_HIERARCHYSYNC hierarchysync;
	RESP_CONTENTSYNC contentsync;
	RESP_CONFIGSYNC configsync;
	RESP_STATESYNC statesync;
	RESP_SYNCMESSAGECHANGE syncmessagechange;
	RESP_SYNCFOLDERCHANGE syncfolderchange;
	RESP_SYNCREADSTATECHANGES syncreadstatechanges;
	RESP_SYNCDELETIONS syncdeletions;
	RESP_HIERARCHYIMPORT hierarchyimport;
	RESP_CONTENTIMPORT contentimport;
	RESP_STATEIMPORT stateimport;
	RESP_IMPORTMESSAGE importmessage;
	RESP_GETSEARCHCRITERIA getsearchcriteria;
	RESP_MESSAGETORFC822 messagetorfc822;
	RESP_MESSAGETOICAL messagetoical;
	RESP_MESSAGETOVCF messagetovcf;
	RESP_GETUSERAVAILABILITY getuseravailability;
};

struct RPC_RESPONSE {
	uint8_t call_id;
	uint32_t result;
	RESPONSE_PAYLOAD payload;
};

BOOL rpc_ext_pull_request(const BINARY *pbin_in,
	RPC_REQUEST *prequest);

BOOL rpc_ext_push_response(const RPC_RESPONSE *presponse,
	BINARY *pbin_out);
