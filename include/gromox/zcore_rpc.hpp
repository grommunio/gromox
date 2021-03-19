#pragma once
#include <gromox/mapidefs.h>

namespace zcore_response {
enum {
	SUCCESS = 0x00,
	LACK_MEMORY = 0x01,
	PULL_ERROR = 0x02,
	DISPATCH_ERROR = 0x03,
	PUSH_ERROR = 0x04,
};
}

namespace zcore_callid {
enum {
	LOGON = 0x00,
	UNLOADOBJECT = 0x01,
	OPENENTRY = 0x02,
	OPENSTOREENTRY = 0x03,
	OPENABENTRY = 0x04,
	RESOLVENAME = 0x05,
	GETPERMISSIONS = 0x07,
	MODIFYPERMISSIONS = 0x08,
	MODIFYRULES = 0x09,
	GETABGAL = 0x0a,
	LOADSTORETABLE = 0x0b,
	OPENSTORE = 0x0c,
	OPENPROPFILESEC = 0x0d,
	LOADHIERARCHYTABLE = 0x0e,
	LOADCONTENTTABLE = 0x0f,
	LOADRECIPIENTTABLE = 0x10,
	LOADRULETABLE = 0x12,
	CREATEMESSAGE = 0x13,
	DELETEMESSAGES = 0x14,
	COPYMESSAGES = 0x15,
	SETREADFLAGS = 0x16,
	CREATEFOLDER = 0x17,
	DELETEFOLDER = 0x18,
	EMPTYFOLDER = 0x19,
	COPYFOLDER = 0x1a,
	GETSTOREENTRYID = 0x1b,
	ENTRYIDFROMSOURCEKEY = 0x1c,
	STOREADVISE = 0x1d,
	UNADVISE = 0x1e,
	NOTIFDEQUEUE = 0x1f,
	QUERYROWS = 0x20,
	SETCOLUMNS = 0x21,
	SEEKROW = 0x22,
	SORTTABLE = 0x23,
	GETROWCOUNT = 0x24,
	RESTRICTTABLE = 0x25,
	FINDROW = 0x26,
	CREATEBOOKMARK = 0x27,
	FREEBOOKMARK = 0x28,
	GETRECEIVEFOLDER = 0x29,
	MODIFYRECIPIENTS = 0x2a,
	SUBMITMESSAGE = 0x2b,
	LOADATTACHMENTTABLE = 0x2c,
	OPENATTACHMENT = 0x2d,
	CREATEATTACHMENT = 0x2e,
	DELETEATTACHMENT = 0x2f,
	SETPROPVALS = 0x30,
	GETPROPVALS = 0x31,
	DELETEPROPVALS = 0x32,
	SETMESSAGEREADFLAG = 0x33,
	OPENEMBEDDED = 0x34,
	GETNAMEDPROPIDS = 0x35,
	GETPROPNAMES = 0x36,
	COPYTO = 0x37,
	SAVECHANGES = 0x38,
	HIERARCHYSYNC = 0x39,
	CONTENTSYNC = 0x3a,
	CONFIGSYNC = 0x3b,
	STATESYNC = 0x3c,
	SYNCMESSAGECHANGE = 0x3d,
	SYNCFOLDERCHANGE = 0x3e,
	SYNCREADSTATECHANGES = 0x3f,
	SYNCDELETIONS = 0x40,
	HIERARCHYIMPORT = 0x41,
	CONTENTIMPORT = 0x42,
	CONFIGIMPORT = 0x43,
	STATEIMPORT = 0x44,
	IMPORTMESSAGE = 0x45,
	IMPORTFOLDER = 0x46,
	IMPORTDELETION = 0x47,
	IMPORTREADSTATES = 0x48,
	GETSEARCHCRITERIA = 0x49,
	SETSEARCHCRITERIA = 0x4a,
	MESSAGETORFC822 = 0x4b,
	RFC822TOMESSAGE = 0x4c,
	MESSAGETOICAL = 0x4d,
	ICALTOMESSAGE = 0x4e,
	MESSAGETOVCF = 0x4f,
	VCFTOMESSAGE = 0x50,
	UINFO = 0x51,
	CHECKSESSION = 0x52,
	GETUSERAVAILABILITY = 0x53,
	SETPASSWD = 0x54,
	LINKMESSAGE = 0x55,
};
}

struct ZCREQ_LOGON {
	char *username;
	char *password;
	uint32_t flags;
};

struct ZCREQ_CHECKSESSION {
	GUID hsession;
};

struct ZCREQ_UINFO {
	char *username;
};

struct ZCREQ_UNLOADOBJECT {
	GUID hsession;
	uint32_t hobject;
};

struct ZCREQ_OPENENTRY {
	GUID hsession;
	BINARY entryid;
	uint32_t flags;
};

struct ZCREQ_OPENSTOREENTRY {
	GUID hsession;
	uint32_t hobject;
	BINARY entryid;
	uint32_t flags;
};

struct ZCREQ_OPENABENTRY {
	GUID hsession;
	BINARY entryid;
};

struct ZCREQ_RESOLVENAME {
	GUID hsession;
	TARRAY_SET *pcond_set;
};

struct ZCREQ_GETPERMISSIONS {
	GUID hsession;
	uint32_t hobject;
};

struct ZCREQ_MODIFYPERMISSIONS {
	GUID hsession;
	uint32_t hfolder;
	PERMISSION_SET *pset;
};

struct ZCREQ_MODIFYRULES {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	RULE_LIST *plist;
};

struct ZCREQ_GETABGAL {
	GUID hsession;
};

struct ZCREQ_LOADSTORETABLE {
	GUID hsession;
};

struct ZCREQ_OPENSTORE {
	GUID hsession;
	BINARY entryid;
};

struct ZCREQ_OPENPROPFILESEC {
	GUID hsession;
	const FLATUID *puid;
};

struct ZCREQ_LOADHIERARCHYTABLE {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct ZCREQ_LOADCONTENTTABLE {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct ZCREQ_LOADRECIPIENTTABLE {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_LOADRULETABLE {
	GUID hsession;
	uint32_t hfolder;
};
	
struct ZCREQ_CREATEMESSAGE {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct ZCREQ_DELETEMESSAGES {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct ZCREQ_COPYMESSAGES {
	GUID hsession;
	uint32_t hsrcfolder;
	uint32_t hdstfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct ZCREQ_SETREADFLAGS {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct ZCREQ_CREATEFOLDER {
	GUID hsession;
	uint32_t hparent_folder;
	uint32_t folder_type;
	char *folder_name;
	char *folder_comment;
	uint32_t flags;
};

struct ZCREQ_DELETEFOLDER {
	GUID hsession;
	uint32_t hparent_folder;
	BINARY entryid;
	uint32_t flags;
};

struct ZCREQ_EMPTYFOLDER {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct ZCREQ_COPYFOLDER {
	GUID hsession;
	uint32_t hsrc_folder;
	BINARY entryid;
	uint32_t hdst_folder;
	char *new_name;
	uint32_t flags;
};

struct ZCREQ_GETSTOREENTRYID {
	char *mailbox_dn;
};

struct ZCREQ_ENTRYIDFROMSOURCEKEY {
	GUID hsession;
	uint32_t hstore;
	BINARY folder_key;
	BINARY *pmessage_key;
};

struct ZCREQ_STOREADVISE {
	GUID hsession;
	uint32_t hstore;
	BINARY *pentryid;
	uint32_t event_mask;
};

struct ZCREQ_UNADVISE {
	GUID hsession;
	uint32_t hstore;
	uint32_t sub_id;
};

struct ZCREQ_NOTIFDEQUEUE {
	NOTIF_SINK *psink;
	uint32_t timeval;
};

struct ZCREQ_QUERYROWS {
	GUID hsession;
	uint32_t htable;
	uint32_t start;
	uint32_t count;
	RESTRICTION *prestriction;
	PROPTAG_ARRAY *pproptags;
};

struct ZCREQ_SETCOLUMNS {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct ZCREQ_SEEKROW {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	int32_t seek_rows;
};

struct ZCREQ_SORTTABLE {
	GUID hsession;
	uint32_t htable;
	SORTORDER_SET *psortset;
};

struct ZCREQ_GETROWCOUNT {
	GUID hsession;
	uint32_t htable;
};

struct ZCREQ_RESTRICTTABLE {
	GUID hsession;
	uint32_t htable;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct ZCREQ_FINDROW {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct ZCREQ_CREATEBOOKMARK {
	GUID hsession;
	uint32_t htable;
};

struct ZCREQ_FREEBOOKMARK {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
};

struct ZCREQ_GETRECEIVEFOLDER {
	GUID hsession;
	uint32_t hstore;
	char *pstrclass;
};

struct ZCREQ_MODIFYRECIPIENTS {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
	TARRAY_SET *prcpt_list;
};

struct ZCREQ_SUBMITMESSAGE {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_LOADATTACHMENTTABLE {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_OPENATTACHMENT {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct ZCREQ_CREATEATTACHMENT {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_DELETEATTACHMENT {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct ZCREQ_SETPROPVALS {
	GUID hsession;
	uint32_t hobject;
	TPROPVAL_ARRAY *ppropvals;
};

struct ZCREQ_GETPROPVALS {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct ZCREQ_DELETEPROPVALS {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct ZCREQ_SETMESSAGEREADFLAG {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
};

struct ZCREQ_OPENEMBEDDED {
	GUID hsession;
	uint32_t hattachment;
	uint32_t flags;
};

struct ZCREQ_GETNAMEDPROPIDS {
	GUID hsession;
	uint32_t hstore;
	PROPNAME_ARRAY *ppropnames;
};

struct ZCREQ_GETPROPNAMES {
	GUID hsession;
	uint32_t hstore;
	PROPID_ARRAY *ppropids;
};

struct ZCREQ_COPYTO {
	GUID hsession;
	uint32_t hsrcobject;
	PROPTAG_ARRAY *pexclude_proptags;
	uint32_t hdstobject;
	uint32_t flags;
};

struct ZCREQ_SAVECHANGES {
	GUID hsession;
	uint32_t hobject;
};

struct ZCREQ_HIERARCHYSYNC {
	GUID hsession;
	uint32_t hfolder;
};

struct ZCREQ_CONTENTSYNC {
	GUID hsession;
	uint32_t hfolder;
};

struct ZCREQ_CONFIGSYNC {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY *pstate;
	RESTRICTION *prestriction;
};

struct ZCREQ_STATESYNC {
	GUID hsession;
	uint32_t hctx;
};

struct ZCREQ_SYNCMESSAGECHANGE {
	GUID hsession;
	uint32_t hctx;
};

struct ZCREQ_SYNCFOLDERCHANGE {
	GUID hsession;
	uint32_t hctx;
};

struct ZCREQ_SYNCREADSTATECHANGES {
	GUID hsession;
	uint32_t hctx;
};

struct ZCREQ_SYNCDELETIONS {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
};

struct ZCREQ_HIERARCHYIMPORT {
	GUID hsession;
	uint32_t hfolder;
};

struct ZCREQ_CONTENTIMPORT {
	GUID hsession;
	uint32_t hfolder;
};

struct ZCREQ_CONFIGIMPORT {
	GUID hsession;
	uint32_t hctx;
	uint8_t sync_type;
	BINARY *pstate;
};
	
struct ZCREQ_STATEIMPORT {
	GUID hsession;
	uint32_t hctx;
};

struct ZCREQ_IMPORTMESSAGE {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	TPROPVAL_ARRAY *pproplist;
};
	
struct ZCREQ_IMPORTFOLDER {
	GUID hsession;
	uint32_t hctx;
	TPROPVAL_ARRAY *pproplist;
};

struct ZCREQ_IMPORTDELETION {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY_ARRAY *pbins;
};

struct ZCREQ_IMPORTREADSTATES {
	GUID hsession;
	uint32_t hctx;
	STATE_ARRAY *pstates;
};

struct ZCREQ_GETSEARCHCRITERIA {
	GUID hsession;
	uint32_t hfolder;
};
	
struct ZCREQ_SETSEARCHCRITERIA {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	BINARY_ARRAY *pfolder_array;
	RESTRICTION *prestriction;
};

struct ZCREQ_MESSAGETORFC822 {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_RFC822TOMESSAGE {
	GUID hsession;
	uint32_t hmessage;
	BINARY *peml_bin;
};

struct ZCREQ_MESSAGETOICAL {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_ICALTOMESSAGE {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pical_bin;
};

struct ZCREQ_MESSAGETOVCF {
	GUID hsession;
	uint32_t hmessage;
};

struct ZCREQ_VCFTOMESSAGE {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pvcf_bin;
};

struct ZCREQ_GETUSERAVAILABILITY {
	GUID hsession;
	BINARY entryid;
	uint64_t starttime;
	uint64_t endtime;
};

struct ZCREQ_SETPASSWD {
	char *username;
	char *passwd;
	char *new_passwd;
};

struct ZCREQ_LINKMESSAGE {
	GUID hsession;
	BINARY search_entryid;
	BINARY message_entryid;
};

struct ZCREQ_SAVESESSION {
	GUID hsession;
};

struct ZCREQ_RESTORESESSION {
	BINARY *pdata_bin;
};

union ZCORE_REQUEST_PAYLOAD {
	ZCREQ_LOGON logon;
	ZCREQ_CHECKSESSION checksession;
	ZCREQ_UINFO uinfo;
	ZCREQ_UNLOADOBJECT unloadobject;
	ZCREQ_OPENENTRY openentry;
	ZCREQ_OPENSTOREENTRY openstoreentry;
	ZCREQ_OPENABENTRY openabentry;
	ZCREQ_RESOLVENAME resolvename;
	ZCREQ_GETPERMISSIONS getpermissions;
	ZCREQ_MODIFYPERMISSIONS modifypermissions;
	ZCREQ_MODIFYRULES modifyrules;
	ZCREQ_GETABGAL getabgal;
	ZCREQ_LOADSTORETABLE loadstoretable;
	ZCREQ_OPENSTORE openstore;
	ZCREQ_OPENPROPFILESEC openpropfilesec;
	ZCREQ_LOADHIERARCHYTABLE loadhierarchytable;
	ZCREQ_LOADCONTENTTABLE loadcontenttable;
	ZCREQ_LOADRECIPIENTTABLE loadrecipienttable;
	ZCREQ_LOADRULETABLE loadruletable;
	ZCREQ_CREATEMESSAGE createmessage;
	ZCREQ_DELETEMESSAGES deletemessages;
	ZCREQ_COPYMESSAGES copymessages;
	ZCREQ_SETREADFLAGS setreadflags;
	ZCREQ_CREATEFOLDER createfolder;
	ZCREQ_DELETEFOLDER deletefolder;
	ZCREQ_EMPTYFOLDER emptyfolder;
	ZCREQ_COPYFOLDER copyfolder;
	ZCREQ_GETSTOREENTRYID getstoreentryid;
	ZCREQ_ENTRYIDFROMSOURCEKEY entryidfromsourcekey;
	ZCREQ_STOREADVISE storeadvise;
	ZCREQ_UNADVISE unadvise;
	ZCREQ_NOTIFDEQUEUE notifdequeue;
	ZCREQ_QUERYROWS queryrows;
	ZCREQ_SETCOLUMNS setcolumns;
	ZCREQ_SEEKROW seekrow;
	ZCREQ_SORTTABLE sorttable;
	ZCREQ_GETROWCOUNT getrowcount;
	ZCREQ_RESTRICTTABLE restricttable;
	ZCREQ_FINDROW findrow;
	ZCREQ_CREATEBOOKMARK createbookmark;
	ZCREQ_FREEBOOKMARK freebookmark;
	ZCREQ_GETRECEIVEFOLDER getreceivefolder;
	ZCREQ_MODIFYRECIPIENTS modifyrecipients;
	ZCREQ_SUBMITMESSAGE submitmessage;
	ZCREQ_LOADATTACHMENTTABLE loadattachmenttable;
	ZCREQ_OPENATTACHMENT openattachment;
	ZCREQ_CREATEATTACHMENT createattachment;
	ZCREQ_DELETEATTACHMENT deleteattachment;
	ZCREQ_SETPROPVALS setpropvals;
	ZCREQ_GETPROPVALS getpropvals;
	ZCREQ_DELETEPROPVALS deletepropvals;
	ZCREQ_SETMESSAGEREADFLAG setmessagereadflag;
	ZCREQ_OPENEMBEDDED openembedded;
	ZCREQ_GETNAMEDPROPIDS getnamedpropids;
	ZCREQ_GETPROPNAMES getpropnames;
	ZCREQ_COPYTO copyto;
	ZCREQ_SAVECHANGES savechanges;
	ZCREQ_HIERARCHYSYNC hierarchysync;
	ZCREQ_CONTENTSYNC contentsync;
	ZCREQ_CONFIGSYNC configsync;
	ZCREQ_STATESYNC statesync;
	ZCREQ_SYNCMESSAGECHANGE syncmessagechange;
	ZCREQ_SYNCFOLDERCHANGE syncfolderchange;
	ZCREQ_SYNCREADSTATECHANGES syncreadstatechanges;
	ZCREQ_SYNCDELETIONS syncdeletions;
	ZCREQ_HIERARCHYIMPORT hierarchyimport;
	ZCREQ_CONTENTIMPORT contentimport;
	ZCREQ_CONFIGIMPORT configimport;
	ZCREQ_STATEIMPORT stateimport;
	ZCREQ_IMPORTMESSAGE importmessage;
	ZCREQ_IMPORTFOLDER importfolder;
	ZCREQ_IMPORTDELETION importdeletion;
	ZCREQ_IMPORTREADSTATES importreadstates;
	ZCREQ_GETSEARCHCRITERIA getsearchcriteria;
	ZCREQ_SETSEARCHCRITERIA setsearchcriteria;
	ZCREQ_MESSAGETORFC822 messagetorfc822;
	ZCREQ_RFC822TOMESSAGE rfc822tomessage;
	ZCREQ_MESSAGETOICAL messagetoical;
	ZCREQ_ICALTOMESSAGE icaltomessage;
	ZCREQ_MESSAGETOVCF messagetovcf;
	ZCREQ_VCFTOMESSAGE vcftomessage;
	ZCREQ_GETUSERAVAILABILITY getuseravailability;
	ZCREQ_SETPASSWD setpasswd;
	ZCREQ_LINKMESSAGE linkmessage;
};

struct ZCORE_RPC_REQUEST {
	uint8_t call_id;
	ZCORE_REQUEST_PAYLOAD payload;
};
