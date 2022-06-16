#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>

enum class zcore_response : uint8_t {
	success = 0x00,
	lack_memory = 0x01,
	pull_error = 0x02,
	dispatch_error = 0x03,
	push_error = 0x04,
};

enum class zcore_callid : uint8_t {
	logon = 0x00,
	unloadobject = 0x01,
	openentry = 0x02,
	openstoreentry = 0x03,
	openabentry = 0x04,
	resolvename = 0x05,
	getpermissions = 0x07,
	modifypermissions = 0x08,
	modifyrules = 0x09,
	getabgal = 0x0a,
	loadstoretable = 0x0b,
	openstore = 0x0c,
	openprofilesec = 0x0d,
	loadhierarchytable = 0x0e,
	loadcontenttable = 0x0f,
	loadrecipienttable = 0x10,
	loadruletable = 0x12,
	createmessage = 0x13,
	deletemessages = 0x14,
	copymessages = 0x15,
	setreadflags = 0x16,
	createfolder = 0x17,
	deletefolder = 0x18,
	emptyfolder = 0x19,
	copyfolder = 0x1a,
	getstoreentryid = 0x1b,
	entryidfromsourcekey = 0x1c,
	storeadvise = 0x1d,
	unadvise = 0x1e,
	notifdequeue = 0x1f,
	queryrows = 0x20,
	setcolumns = 0x21,
	seekrow = 0x22,
	sorttable = 0x23,
	getrowcount = 0x24,
	restricttable = 0x25,
	findrow = 0x26,
	createbookmark = 0x27,
	freebookmark = 0x28,
	getreceivefolder = 0x29,
	modifyrecipients = 0x2a,
	submitmessage = 0x2b,
	loadattachmenttable = 0x2c,
	openattachment = 0x2d,
	createattachment = 0x2e,
	deleteattachment = 0x2f,
	setpropvals = 0x30,
	getpropvals = 0x31,
	deletepropvals = 0x32,
	setmessagereadflag = 0x33,
	openembedded = 0x34,
	getnamedpropids = 0x35,
	getpropnames = 0x36,
	copyto = 0x37,
	savechanges = 0x38,
	hierarchysync = 0x39,
	contentsync = 0x3a,
	configsync = 0x3b,
	statesync = 0x3c,
	syncmessagechange = 0x3d,
	syncfolderchange = 0x3e,
	syncreadstatechanges = 0x3f,
	syncdeletions = 0x40,
	hierarchyimport = 0x41,
	contentimport = 0x42,
	configimport = 0x43,
	stateimport = 0x44,
	importmessage = 0x45,
	importfolder = 0x46,
	importdeletion = 0x47,
	importreadstates = 0x48,
	getsearchcriteria = 0x49,
	setsearchcriteria = 0x4a,
	messagetorfc822 = 0x4b,
	// rfc822tomessagev1 = 0x4c,
	messagetoical = 0x4d,
	icaltomessage = 0x4e,
	messagetovcf = 0x4f,
	vcftomessage = 0x50,
	uinfo = 0x51,
	checksession = 0x52,
	getuseravailability = 0x53,
	setpasswd = 0x54,
	linkmessage = 0x55,
	rfc822tomessage = 0x56,
};

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

struct ZCREQ_OPENPROFILESEC {
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
	uint32_t hmessage, mxf_flags;
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
	ZCREQ_OPENPROFILESEC openprofilesec;
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
	zcore_callid call_id;
	ZCORE_REQUEST_PAYLOAD payload;
};

struct ZCRESP_LOGON {
	GUID hsession;
};

struct ZCRESP_UINFO {
	BINARY entryid;
	char *pdisplay_name;
	char *px500dn;
	uint32_t privilege_bits;
};

struct ZCRESP_OPENENTRY {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct ZCRESP_OPENSTOREENTRY {
	uint8_t mapi_type;
	uint32_t hxobject;
};

struct ZCRESP_OPENABENTRY {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct ZCRESP_RESOLVENAME {
	TARRAY_SET result_set;
};

struct ZCRESP_GETPERMISSIONS {
	PERMISSION_SET perm_set;
};

struct ZCRESP_GETABGAL {
	BINARY entryid;
};

struct ZCRESP_LOADSTORETABLE {
	uint32_t hobject;
};

struct ZCRESP_OPENSTORE {
	uint32_t hobject;
};

struct ZCRESP_OPENPROFILESEC {
	uint32_t hobject;
};

struct ZCRESP_LOADHIERARCHYTABLE {
	uint32_t hobject;
};

struct ZCRESP_LOADCONTENTTABLE {
	uint32_t hobject;
};

struct ZCRESP_LOADRECIPIENTTABLE {
	uint32_t hobject;
};

struct ZCRESP_LOADRULETABLE {
	uint32_t hobject;
};
	
struct ZCRESP_CREATEMESSAGE {
	uint32_t hobject;
};

struct ZCRESP_CREATEFOLDER {
	uint32_t hobject;
};

struct ZCRESP_GETSTOREENTRYID {
	BINARY entryid;
};

struct ZCRESP_ENTRYIDFROMSOURCEKEY {
	BINARY entryid;
};

struct ZCRESP_STOREADVISE {
	uint32_t sub_id;
};

struct ZCRESP_NOTIFDEQUEUE {
	ZNOTIFICATION_ARRAY notifications;
};

struct ZCRESP_QUERYROWS {
	TARRAY_SET rowset;
};

struct ZCRESP_SETCOLUMNS {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct ZCRESP_SEEKROW {
	int32_t sought_rows;
};

struct ZCRESP_GETROWCOUNT {
	uint32_t count;
};

struct ZCRESP_FINDROW {
	uint32_t row_idx;
};

struct ZCRESP_CREATEBOOKMARK {
	uint32_t bookmark;
};

struct ZCRESP_GETRECEIVEFOLDER {
	BINARY entryid;
};

struct ZCRESP_LOADATTACHMENTTABLE {
	uint32_t hobject;
};

struct ZCRESP_OPENATTACHMENT {
	uint32_t hobject;
};

struct ZCRESP_CREATEATTACHMENT {
	uint32_t hobject;
};

struct ZCRESP_GETPROPVALS {
	TPROPVAL_ARRAY propvals;
};

struct ZCRESP_OPENEMBEDDED {
	uint32_t hobject;
};

struct ZCRESP_GETNAMEDPROPIDS {
	PROPID_ARRAY propids;
};

struct ZCRESP_GETPROPNAMES {
	PROPNAME_ARRAY propnames;
};

struct ZCRESP_HIERARCHYSYNC {
	uint32_t hobject;
};

struct ZCRESP_CONTENTSYNC {
	uint32_t hobject;
};

struct ZCRESP_CONFIGSYNC {
	uint8_t b_changed;
	uint32_t count;
};

struct ZCRESP_STATESYNC {
	BINARY state;
};

struct ZCRESP_SYNCMESSAGECHANGE {
	uint8_t b_new;
	TPROPVAL_ARRAY proplist;
};

struct ZCRESP_SYNCFOLDERCHANGE {
	TPROPVAL_ARRAY proplist;
};

struct ZCRESP_SYNCREADSTATECHANGES {
	STATE_ARRAY states;
};

struct ZCRESP_SYNCDELETIONS {
	BINARY_ARRAY bins;
};

struct ZCRESP_HIERARCHYIMPORT {
	uint32_t hobject;
};

struct ZCRESP_CONTENTIMPORT {
	uint32_t hobject;
};
	
struct ZCRESP_STATEIMPORT {
	BINARY state;
};

struct ZCRESP_IMPORTMESSAGE {
	uint32_t hobject;
};

struct ZCRESP_GETSEARCHCRITERIA {
	BINARY_ARRAY folder_array;
	RESTRICTION *prestriction;
	uint32_t search_stat;
};

struct ZCRESP_MESSAGETORFC822 {
	BINARY eml_bin;
};

struct ZCRESP_MESSAGETOICAL {
	BINARY ical_bin;
};

struct ZCRESP_MESSAGETOVCF {
	BINARY vcf_bin;
};

struct ZCRESP_GETUSERAVAILABILITY {
	char *result_string;
};

union ZCORE_RESPONSE_PAYLOAD {
	ZCRESP_LOGON logon;
	ZCRESP_UINFO uinfo;
	ZCRESP_OPENENTRY openentry;
	ZCRESP_OPENSTOREENTRY openstoreentry;
	ZCRESP_OPENABENTRY openabentry;
	ZCRESP_RESOLVENAME resolvename;
	ZCRESP_GETPERMISSIONS getpermissions;
	ZCRESP_GETABGAL getabgal;
	ZCRESP_LOADSTORETABLE loadstoretable;
	ZCRESP_OPENSTORE openstore;
	ZCRESP_OPENPROFILESEC openprofilesec;
	ZCRESP_LOADHIERARCHYTABLE loadhierarchytable;
	ZCRESP_LOADCONTENTTABLE loadcontenttable;
	ZCRESP_LOADRECIPIENTTABLE loadrecipienttable;
	ZCRESP_LOADRULETABLE loadruletable;
	ZCRESP_CREATEMESSAGE createmessage;
	ZCRESP_CREATEFOLDER createfolder;
	ZCRESP_GETSTOREENTRYID getstoreentryid;
	ZCRESP_ENTRYIDFROMSOURCEKEY entryidfromsourcekey;
	ZCRESP_STOREADVISE storeadvise;
	ZCRESP_NOTIFDEQUEUE notifdequeue;
	ZCRESP_QUERYROWS queryrows;
	ZCRESP_SEEKROW seekrow;
	ZCRESP_GETROWCOUNT getrowcount;
	ZCRESP_FINDROW findrow;
	ZCRESP_CREATEBOOKMARK createbookmark;
	ZCRESP_GETRECEIVEFOLDER getreceivefolder;
	ZCRESP_LOADATTACHMENTTABLE loadattachmenttable;
	ZCRESP_OPENATTACHMENT openattachment;
	ZCRESP_CREATEATTACHMENT createattachment;
	ZCRESP_GETPROPVALS getpropvals;
	ZCRESP_OPENEMBEDDED openembedded;
	ZCRESP_GETNAMEDPROPIDS getnamedpropids;
	ZCRESP_GETPROPNAMES getpropnames;
	ZCRESP_HIERARCHYSYNC hierarchysync;
	ZCRESP_CONTENTSYNC contentsync;
	ZCRESP_CONFIGSYNC configsync;
	ZCRESP_STATESYNC statesync;
	ZCRESP_SYNCMESSAGECHANGE syncmessagechange;
	ZCRESP_SYNCFOLDERCHANGE syncfolderchange;
	ZCRESP_SYNCREADSTATECHANGES syncreadstatechanges;
	ZCRESP_SYNCDELETIONS syncdeletions;
	ZCRESP_HIERARCHYIMPORT hierarchyimport;
	ZCRESP_CONTENTIMPORT contentimport;
	ZCRESP_STATEIMPORT stateimport;
	ZCRESP_IMPORTMESSAGE importmessage;
	ZCRESP_GETSEARCHCRITERIA getsearchcriteria;
	ZCRESP_MESSAGETORFC822 messagetorfc822;
	ZCRESP_MESSAGETOICAL messagetoical;
	ZCRESP_MESSAGETOVCF messagetovcf;
	ZCRESP_GETUSERAVAILABILITY getuseravailability;
};

struct ZCORE_RPC_RESPONSE {
	zcore_callid call_id;
	uint32_t result;
	ZCORE_RESPONSE_PAYLOAD payload;
};
