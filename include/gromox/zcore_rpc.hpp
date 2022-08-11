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
	// icaltomessage2 = 0x57,
	imtomessage2 = 0x58,
};

struct zcreq_logon {
	char *username;
	char *password;
	uint32_t flags;
};

struct zcreq_checksession {
	GUID hsession;
};

struct zcreq_uinfo {
	char *username;
};

struct zcreq_unloadobject {
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_openentry {
	GUID hsession;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_openstoreentry {
	GUID hsession;
	uint32_t hobject;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_openabentry {
	GUID hsession;
	BINARY entryid;
};

struct zcreq_resolvename {
	GUID hsession;
	TARRAY_SET *pcond_set;
};

struct zcreq_getpermissions {
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_modifypermissions {
	GUID hsession;
	uint32_t hfolder;
	PERMISSION_SET *pset;
};

struct zcreq_modifyrules {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	RULE_LIST *plist;
};

struct zcreq_getabgal {
	GUID hsession;
};

struct zcreq_loadstoretable {
	GUID hsession;
};

struct zcreq_openstore {
	GUID hsession;
	BINARY entryid;
};

struct zcreq_openprofilesec {
	GUID hsession;
	const FLATUID *puid;
};

struct zcreq_loadhierarchytable {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_loadcontenttable {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_loadrecipienttable {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_loadruletable {
	GUID hsession;
	uint32_t hfolder;
};
	
struct zcreq_createmessage {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_deletemessages {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_copymessages {
	GUID hsession;
	uint32_t hsrcfolder;
	uint32_t hdstfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_setreadflags {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_createfolder {
	GUID hsession;
	uint32_t hparent_folder;
	uint32_t folder_type;
	char *folder_name;
	char *folder_comment;
	uint32_t flags;
};

struct zcreq_deletefolder {
	GUID hsession;
	uint32_t hparent_folder;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_emptyfolder {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_copyfolder {
	GUID hsession;
	uint32_t hsrc_folder;
	BINARY entryid;
	uint32_t hdst_folder;
	char *new_name;
	uint32_t flags;
};

struct zcreq_getstoreentryid {
	char *mailbox_dn;
};

struct zcreq_entryidfromsourcekey {
	GUID hsession;
	uint32_t hstore;
	BINARY folder_key;
	BINARY *pmessage_key;
};

struct zcreq_storeadvise {
	GUID hsession;
	uint32_t hstore;
	BINARY *pentryid;
	uint32_t event_mask;
};

struct zcreq_unadvise {
	GUID hsession;
	uint32_t hstore;
	uint32_t sub_id;
};

struct zcreq_notifdequeue {
	NOTIF_SINK *psink;
	uint32_t timeval;
};

struct zcreq_queryrows {
	GUID hsession;
	uint32_t htable;
	uint32_t start;
	uint32_t count;
	RESTRICTION *prestriction;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_setcolumns {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct zcreq_seekrow {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	int32_t seek_rows;
};

struct zcreq_sorttable {
	GUID hsession;
	uint32_t htable;
	SORTORDER_SET *psortset;
};

struct zcreq_getrowcount {
	GUID hsession;
	uint32_t htable;
};

struct zcreq_restricttable {
	GUID hsession;
	uint32_t htable;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct zcreq_findrow {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct zcreq_createbookmark {
	GUID hsession;
	uint32_t htable;
};

struct zcreq_freebookmark {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
};

struct zcreq_getreceivefolder {
	GUID hsession;
	uint32_t hstore;
	char *pstrclass;
};

struct zcreq_modifyrecipients {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
	TARRAY_SET *prcpt_list;
};

struct zcreq_submitmessage {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_loadattachmenttable {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_openattachment {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct zcreq_createattachment {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_deleteattachment {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct zcreq_setpropvals {
	GUID hsession;
	uint32_t hobject;
	TPROPVAL_ARRAY *ppropvals;
};

struct zcreq_getpropvals {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_deletepropvals {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_setmessagereadflag {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
};

struct zcreq_openembedded {
	GUID hsession;
	uint32_t hattachment;
	uint32_t flags;
};

struct zcreq_getnamedpropids {
	GUID hsession;
	uint32_t hstore;
	PROPNAME_ARRAY *ppropnames;
};

struct zcreq_getpropnames {
	GUID hsession;
	uint32_t hstore;
	PROPID_ARRAY *ppropids;
};

struct zcreq_copyto {
	GUID hsession;
	uint32_t hsrcobject;
	PROPTAG_ARRAY *pexclude_proptags;
	uint32_t hdstobject;
	uint32_t flags;
};

struct zcreq_savechanges {
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_hierarchysync {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_contentsync {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_configsync {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY *pstate;
	RESTRICTION *prestriction;
};

struct zcreq_statesync {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncmessagechange {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncfolderchange {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncreadstatechanges {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncdeletions {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
};

struct zcreq_hierarchyimport {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_contentimport {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_configimport {
	GUID hsession;
	uint32_t hctx;
	uint8_t sync_type;
	BINARY *pstate;
};
	
struct zcreq_stateimport {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_importmessage {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	TPROPVAL_ARRAY *pproplist;
};
	
struct zcreq_importfolder {
	GUID hsession;
	uint32_t hctx;
	TPROPVAL_ARRAY *pproplist;
};

struct zcreq_importdeletion {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY_ARRAY *pbins;
};

struct zcreq_importreadstates {
	GUID hsession;
	uint32_t hctx;
	STATE_ARRAY *pstates;
};

struct zcreq_getsearchcriteria {
	GUID hsession;
	uint32_t hfolder;
};
	
struct zcreq_setsearchcriteria {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	BINARY_ARRAY *pfolder_array;
	RESTRICTION *prestriction;
};

struct zcreq_messagetorfc822 {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_rfc822tomessage {
	GUID hsession;
	uint32_t hmessage, mxf_flags;
	BINARY *peml_bin;
};

struct zcreq_messagetoical {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_icaltomessage {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pical_bin;
};

enum imtomessage2_type {
	IMTOMESSAGE_ICAL = 0,
	IMTOMESSAGE_VCARD,
};

struct zcreq_imtomessage2 {
	GUID session;
	uint32_t folder;
	uint32_t data_type;
	char *im_data;
};

struct zcreq_messagetovcf {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_vcftomessage {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pvcf_bin;
};

struct zcreq_getuseravailability {
	GUID hsession;
	BINARY entryid;
	uint64_t starttime;
	uint64_t endtime;
};

struct zcreq_setpasswd {
	char *username;
	char *passwd;
	char *new_passwd;
};

struct zcreq_linkmessage {
	GUID hsession;
	BINARY search_entryid;
	BINARY message_entryid;
};

struct zcreq_savesession {
	GUID hsession;
};

struct zcreq_restoresession {
	BINARY *pdata_bin;
};

union ZCORE_REQUEST_PAYLOAD {
	zcreq_logon logon;
	zcreq_checksession checksession;
	zcreq_uinfo uinfo;
	zcreq_unloadobject unloadobject;
	zcreq_openentry openentry;
	zcreq_openstoreentry openstoreentry;
	zcreq_openabentry openabentry;
	zcreq_resolvename resolvename;
	zcreq_getpermissions getpermissions;
	zcreq_modifypermissions modifypermissions;
	zcreq_modifyrules modifyrules;
	zcreq_getabgal getabgal;
	zcreq_loadstoretable loadstoretable;
	zcreq_openstore openstore;
	zcreq_openprofilesec openprofilesec;
	zcreq_loadhierarchytable loadhierarchytable;
	zcreq_loadcontenttable loadcontenttable;
	zcreq_loadrecipienttable loadrecipienttable;
	zcreq_loadruletable loadruletable;
	zcreq_createmessage createmessage;
	zcreq_deletemessages deletemessages;
	zcreq_copymessages copymessages;
	zcreq_setreadflags setreadflags;
	zcreq_createfolder createfolder;
	zcreq_deletefolder deletefolder;
	zcreq_emptyfolder emptyfolder;
	zcreq_copyfolder copyfolder;
	zcreq_getstoreentryid getstoreentryid;
	zcreq_entryidfromsourcekey entryidfromsourcekey;
	zcreq_storeadvise storeadvise;
	zcreq_unadvise unadvise;
	zcreq_notifdequeue notifdequeue;
	zcreq_queryrows queryrows;
	zcreq_setcolumns setcolumns;
	zcreq_seekrow seekrow;
	zcreq_sorttable sorttable;
	zcreq_getrowcount getrowcount;
	zcreq_restricttable restricttable;
	zcreq_findrow findrow;
	zcreq_createbookmark createbookmark;
	zcreq_freebookmark freebookmark;
	zcreq_getreceivefolder getreceivefolder;
	zcreq_modifyrecipients modifyrecipients;
	zcreq_submitmessage submitmessage;
	zcreq_loadattachmenttable loadattachmenttable;
	zcreq_openattachment openattachment;
	zcreq_createattachment createattachment;
	zcreq_deleteattachment deleteattachment;
	zcreq_setpropvals setpropvals;
	zcreq_getpropvals getpropvals;
	zcreq_deletepropvals deletepropvals;
	zcreq_setmessagereadflag setmessagereadflag;
	zcreq_openembedded openembedded;
	zcreq_getnamedpropids getnamedpropids;
	zcreq_getpropnames getpropnames;
	zcreq_copyto copyto;
	zcreq_savechanges savechanges;
	zcreq_hierarchysync hierarchysync;
	zcreq_contentsync contentsync;
	zcreq_configsync configsync;
	zcreq_statesync statesync;
	zcreq_syncmessagechange syncmessagechange;
	zcreq_syncfolderchange syncfolderchange;
	zcreq_syncreadstatechanges syncreadstatechanges;
	zcreq_syncdeletions syncdeletions;
	zcreq_hierarchyimport hierarchyimport;
	zcreq_contentimport contentimport;
	zcreq_configimport configimport;
	zcreq_stateimport stateimport;
	zcreq_importmessage importmessage;
	zcreq_importfolder importfolder;
	zcreq_importdeletion importdeletion;
	zcreq_importreadstates importreadstates;
	zcreq_getsearchcriteria getsearchcriteria;
	zcreq_setsearchcriteria setsearchcriteria;
	zcreq_messagetorfc822 messagetorfc822;
	zcreq_rfc822tomessage rfc822tomessage;
	zcreq_messagetoical messagetoical;
	zcreq_icaltomessage icaltomessage;
	zcreq_messagetovcf messagetovcf;
	zcreq_vcftomessage vcftomessage;
	zcreq_getuseravailability getuseravailability;
	zcreq_setpasswd setpasswd;
	zcreq_linkmessage linkmessage;
	zcreq_imtomessage2 imtomessage2;
};

struct ZCORE_RPC_REQUEST {
	zcore_callid call_id;
	ZCORE_REQUEST_PAYLOAD payload;
};

struct zcresp_logon {
	GUID hsession;
};

struct zcresp_uinfo {
	BINARY entryid;
	char *pdisplay_name;
	char *px500dn;
	uint32_t privilege_bits;
};

struct zcresp_openentry {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct zcresp_openstoreentry {
	uint8_t mapi_type;
	uint32_t hxobject;
};

struct zcresp_openabentry {
	uint8_t mapi_type;
	uint32_t hobject;
};

struct zcresp_resolvename {
	TARRAY_SET result_set;
};

struct zcresp_getpermissions {
	PERMISSION_SET perm_set;
};

struct zcresp_getabgal {
	BINARY entryid;
};

struct zcresp_loadstoretable {
	uint32_t hobject;
};

struct zcresp_openstore {
	uint32_t hobject;
};

struct zcresp_openprofilesec {
	uint32_t hobject;
};

struct zcresp_loadhierarchytable {
	uint32_t hobject;
};

struct zcresp_loadcontenttable {
	uint32_t hobject;
};

struct zcresp_loadrecipienttable {
	uint32_t hobject;
};

struct zcresp_loadruletable {
	uint32_t hobject;
};
	
struct zcresp_createmessage {
	uint32_t hobject;
};

struct zcresp_createfolder {
	uint32_t hobject;
};

struct zcresp_getstoreentryid {
	BINARY entryid;
};

struct zcresp_entryidfromsourcekey {
	BINARY entryid;
};

struct zcresp_storeadvise {
	uint32_t sub_id;
};

struct zcresp_notifdequeue {
	ZNOTIFICATION_ARRAY notifications;
};

struct zcresp_queryrows {
	TARRAY_SET rowset;
};

struct zcresp_setcolumns {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct zcresp_seekrow {
	int32_t sought_rows;
};

struct zcresp_getrowcount {
	uint32_t count;
};

struct zcresp_findrow {
	uint32_t row_idx;
};

struct zcresp_createbookmark {
	uint32_t bookmark;
};

struct zcresp_getreceivefolder {
	BINARY entryid;
};

struct zcresp_loadattachmenttable {
	uint32_t hobject;
};

struct zcresp_openattachment {
	uint32_t hobject;
};

struct zcresp_createattachment {
	uint32_t hobject;
};

struct zcresp_getpropvals {
	TPROPVAL_ARRAY propvals;
};

struct zcresp_openembedded {
	uint32_t hobject;
};

struct zcresp_getnamedpropids {
	PROPID_ARRAY propids;
};

struct zcresp_getpropnames {
	PROPNAME_ARRAY propnames;
};

struct zcresp_hierarchysync {
	uint32_t hobject;
};

struct zcresp_contentsync {
	uint32_t hobject;
};

struct zcresp_configsync {
	uint8_t b_changed;
	uint32_t count;
};

struct zcresp_statesync {
	BINARY state;
};

struct zcresp_syncmessagechange {
	uint8_t b_new;
	TPROPVAL_ARRAY proplist;
};

struct zcresp_syncfolderchange {
	TPROPVAL_ARRAY proplist;
};

struct zcresp_syncreadstatechanges {
	STATE_ARRAY states;
};

struct zcresp_syncdeletions {
	BINARY_ARRAY bins;
};

struct zcresp_hierarchyimport {
	uint32_t hobject;
};

struct zcresp_contentimport {
	uint32_t hobject;
};
	
struct zcresp_stateimport {
	BINARY state;
};

struct zcresp_importmessage {
	uint32_t hobject;
};

struct zcresp_getsearchcriteria {
	BINARY_ARRAY folder_array;
	RESTRICTION *prestriction;
	uint32_t search_stat;
};

struct zcresp_messagetorfc822 {
	BINARY eml_bin;
};

struct zcresp_messagetoical {
	BINARY ical_bin;
};

struct zcresp_messagetovcf {
	BINARY vcf_bin;
};

struct zcresp_getuseravailability {
	char *result_string;
};

struct zcresp_imtomessage2 {
	LONG_ARRAY msg_handles;
};

union ZCORE_RESPONSE_PAYLOAD {
	zcresp_logon logon;
	zcresp_uinfo uinfo;
	zcresp_openentry openentry;
	zcresp_openstoreentry openstoreentry;
	zcresp_openabentry openabentry;
	zcresp_resolvename resolvename;
	zcresp_getpermissions getpermissions;
	zcresp_getabgal getabgal;
	zcresp_loadstoretable loadstoretable;
	zcresp_openstore openstore;
	zcresp_openprofilesec openprofilesec;
	zcresp_loadhierarchytable loadhierarchytable;
	zcresp_loadcontenttable loadcontenttable;
	zcresp_loadrecipienttable loadrecipienttable;
	zcresp_loadruletable loadruletable;
	zcresp_createmessage createmessage;
	zcresp_createfolder createfolder;
	zcresp_getstoreentryid getstoreentryid;
	zcresp_entryidfromsourcekey entryidfromsourcekey;
	zcresp_storeadvise storeadvise;
	zcresp_notifdequeue notifdequeue;
	zcresp_queryrows queryrows;
	zcresp_seekrow seekrow;
	zcresp_getrowcount getrowcount;
	zcresp_findrow findrow;
	zcresp_createbookmark createbookmark;
	zcresp_getreceivefolder getreceivefolder;
	zcresp_loadattachmenttable loadattachmenttable;
	zcresp_openattachment openattachment;
	zcresp_createattachment createattachment;
	zcresp_getpropvals getpropvals;
	zcresp_openembedded openembedded;
	zcresp_getnamedpropids getnamedpropids;
	zcresp_getpropnames getpropnames;
	zcresp_hierarchysync hierarchysync;
	zcresp_contentsync contentsync;
	zcresp_configsync configsync;
	zcresp_statesync statesync;
	zcresp_syncmessagechange syncmessagechange;
	zcresp_syncfolderchange syncfolderchange;
	zcresp_syncreadstatechanges syncreadstatechanges;
	zcresp_syncdeletions syncdeletions;
	zcresp_hierarchyimport hierarchyimport;
	zcresp_contentimport contentimport;
	zcresp_stateimport stateimport;
	zcresp_importmessage importmessage;
	zcresp_getsearchcriteria getsearchcriteria;
	zcresp_messagetorfc822 messagetorfc822;
	zcresp_messagetoical messagetoical;
	zcresp_messagetovcf messagetovcf;
	zcresp_getuseravailability getuseravailability;
	zcresp_imtomessage2 imtomessage2;
};

struct ZCORE_RPC_RESPONSE {
	zcore_callid call_id;
	uint32_t result;
	ZCORE_RESPONSE_PAYLOAD payload;
};

enum {
	MXF_UNWRAP_SMIME_CLEARSIGNED = 0x1U,
};
