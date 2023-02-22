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
	essdn_to_username = 0x59,
	/* update exch/zcore/names.cpp! */
};

struct zcreq {
	zcore_callid call_id;
};

struct zcreq_logon : public zcreq {
	char *username;
	char *password;
	uint32_t flags;
};

struct zcreq_checksession : public zcreq {
	GUID hsession;
};

struct zcreq_uinfo : public zcreq {
	char *username;
};

struct zcreq_unloadobject : public zcreq {
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_openentry : public zcreq {
	GUID hsession;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_openstoreentry : public zcreq {
	GUID hsession;
	uint32_t hobject;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_openabentry : public zcreq {
	GUID hsession;
	BINARY entryid;
};

struct zcreq_resolvename : public zcreq {
	GUID hsession;
	TARRAY_SET *pcond_set;
};

struct zcreq_getpermissions : public zcreq {
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_modifypermissions : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	PERMISSION_SET *pset;
};

struct zcreq_modifyrules : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	RULE_LIST *plist;
};

struct zcreq_getabgal : public zcreq {
	GUID hsession;
};

struct zcreq_loadstoretable : public zcreq {
	GUID hsession;
};

struct zcreq_openstore : public zcreq {
	GUID hsession;
	BINARY entryid;
};

struct zcreq_openprofilesec : public zcreq {
	GUID hsession;
	const FLATUID *puid;
};

struct zcreq_loadhierarchytable : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_loadcontenttable : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_loadrecipienttable : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_loadruletable : public zcreq {
	GUID hsession;
	uint32_t hfolder;
};
	
struct zcreq_createmessage : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_deletemessages : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_copymessages : public zcreq {
	GUID hsession;
	uint32_t hsrcfolder;
	uint32_t hdstfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_setreadflags : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_createfolder : public zcreq {
	GUID hsession;
	uint32_t hparent_folder;
	uint32_t folder_type;
	char *folder_name;
	char *folder_comment;
	uint32_t flags;
};

struct zcreq_deletefolder : public zcreq {
	GUID hsession;
	uint32_t hparent_folder;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_emptyfolder : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_copyfolder : public zcreq {
	GUID hsession;
	uint32_t hsrc_folder;
	BINARY entryid;
	uint32_t hdst_folder;
	char *new_name;
	uint32_t flags;
};

struct zcreq_getstoreentryid : public zcreq {
	char *mailbox_dn;
};

struct zcreq_entryidfromsourcekey : public zcreq {
	GUID hsession;
	uint32_t hstore;
	BINARY folder_key;
	BINARY *pmessage_key;
};

struct zcreq_storeadvise : public zcreq {
	GUID hsession;
	uint32_t hstore;
	BINARY *pentryid;
	uint32_t event_mask;
};

struct zcreq_unadvise : public zcreq {
	GUID hsession;
	uint32_t hstore;
	uint32_t sub_id;
};

struct zcreq_notifdequeue : public zcreq {
	NOTIF_SINK *psink;
	uint32_t timeval;
};

struct zcreq_queryrows : public zcreq {
	GUID hsession;
	uint32_t htable;
	uint32_t start;
	uint32_t count;
	RESTRICTION *prestriction;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_setcolumns : public zcreq {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct zcreq_seekrow : public zcreq {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	int32_t seek_rows;
};

struct zcreq_sorttable : public zcreq {
	GUID hsession;
	uint32_t htable;
	SORTORDER_SET *psortset;
};

struct zcreq_getrowcount : public zcreq {
	GUID hsession;
	uint32_t htable;
};

struct zcreq_restricttable : public zcreq {
	GUID hsession;
	uint32_t htable;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct zcreq_findrow : public zcreq {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct zcreq_createbookmark : public zcreq {
	GUID hsession;
	uint32_t htable;
};

struct zcreq_freebookmark : public zcreq {
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
};

struct zcreq_getreceivefolder : public zcreq {
	GUID hsession;
	uint32_t hstore;
	char *pstrclass;
};

struct zcreq_modifyrecipients : public zcreq {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
	TARRAY_SET *prcpt_list;
};

struct zcreq_submitmessage : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_loadattachmenttable : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_openattachment : public zcreq {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct zcreq_createattachment : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_deleteattachment : public zcreq {
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct zcreq_setpropvals : public zcreq {
	GUID hsession;
	uint32_t hobject;
	TPROPVAL_ARRAY *ppropvals;
};

struct zcreq_getpropvals : public zcreq {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_deletepropvals : public zcreq {
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_setmessagereadflag : public zcreq {
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
};

struct zcreq_openembedded : public zcreq {
	GUID hsession;
	uint32_t hattachment;
	uint32_t flags;
};

struct zcreq_getnamedpropids : public zcreq {
	GUID hsession;
	uint32_t hstore;
	PROPNAME_ARRAY *ppropnames;
};

struct zcreq_getpropnames : public zcreq {
	GUID hsession;
	uint32_t hstore;
	PROPID_ARRAY *ppropids;
};

struct zcreq_copyto : public zcreq {
	GUID hsession;
	uint32_t hsrcobject;
	PROPTAG_ARRAY *pexclude_proptags;
	uint32_t hdstobject;
	uint32_t flags;
};

struct zcreq_savechanges : public zcreq {
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_hierarchysync : public zcreq {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_contentsync : public zcreq {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_configsync : public zcreq {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY *pstate;
	RESTRICTION *prestriction;
};

struct zcreq_statesync : public zcreq {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncmessagechange : public zcreq {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncfolderchange : public zcreq {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncreadstatechanges : public zcreq {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncdeletions : public zcreq {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
};

struct zcreq_hierarchyimport : public zcreq {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_contentimport : public zcreq {
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_configimport : public zcreq {
	GUID hsession;
	uint32_t hctx;
	uint8_t sync_type;
	BINARY *pstate;
};
	
struct zcreq_stateimport : public zcreq {
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_importmessage : public zcreq {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	TPROPVAL_ARRAY *pproplist;
};
	
struct zcreq_importfolder : public zcreq {
	GUID hsession;
	uint32_t hctx;
	TPROPVAL_ARRAY *pproplist;
};

struct zcreq_importdeletion : public zcreq {
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY_ARRAY *pbins;
};

struct zcreq_importreadstates : public zcreq {
	GUID hsession;
	uint32_t hctx;
	STATE_ARRAY *pstates;
};

struct zcreq_getsearchcriteria : public zcreq {
	GUID hsession;
	uint32_t hfolder;
};
	
struct zcreq_setsearchcriteria : public zcreq {
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	BINARY_ARRAY *pfolder_array;
	RESTRICTION *prestriction;
};

struct zcreq_messagetorfc822 : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_rfc822tomessage : public zcreq {
	GUID hsession;
	uint32_t hmessage, mxf_flags;
	BINARY *peml_bin;
};

struct zcreq_messagetoical : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_icaltomessage : public zcreq {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pical_bin;
};

enum imtomessage2_type {
	IMTOMESSAGE_ICAL = 0,
	IMTOMESSAGE_VCARD,
};

struct zcreq_imtomessage2 : public zcreq {
	GUID session;
	uint32_t folder;
	uint32_t data_type;
	char *im_data;
};

struct zcreq_messagetovcf : public zcreq {
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_vcftomessage : public zcreq {
	GUID hsession;
	uint32_t hmessage;
	BINARY *pvcf_bin;
};

struct zcreq_getuseravailability : public zcreq {
	GUID hsession;
	BINARY entryid;
	uint64_t starttime;
	uint64_t endtime;
};

struct zcreq_setpasswd : public zcreq {
	char *username;
	char *passwd;
	char *new_passwd;
};

struct zcreq_linkmessage : public zcreq {
	GUID hsession;
	BINARY search_entryid;
	BINARY message_entryid;
};

struct zcreq_savesession : public zcreq {
	GUID hsession;
};

struct zcreq_restoresession : public zcreq {
	BINARY *pdata_bin;
};

struct zcreq_essdn_to_username : public zcreq {
	char *essdn;
};

struct zcresp {
	zcore_callid call_id;
	ec_error_t result;
};

struct zcresp_logon : public zcresp {
	GUID hsession;
};

struct zcresp_uinfo : public zcresp {
	BINARY entryid;
	char *pdisplay_name;
	char *px500dn;
	uint32_t privilege_bits;
};

struct zcresp_openentry : public zcresp {
	zs_objtype mapi_type;
	uint32_t hobject;
};

struct zcresp_openstoreentry : public zcresp {
	zs_objtype mapi_type;
	uint32_t hxobject;
};

struct zcresp_openabentry : public zcresp {
	zs_objtype mapi_type;
	uint32_t hobject;
};

struct zcresp_resolvename : public zcresp {
	TARRAY_SET result_set;
};

struct zcresp_getpermissions : public zcresp {
	PERMISSION_SET perm_set;
};

struct zcresp_getabgal : public zcresp {
	BINARY entryid;
};

struct zcresp_loadstoretable : public zcresp {
	uint32_t hobject;
};

struct zcresp_openstore : public zcresp {
	uint32_t hobject;
};

struct zcresp_openprofilesec : public zcresp {
	uint32_t hobject;
};

struct zcresp_loadhierarchytable : public zcresp {
	uint32_t hobject;
};

struct zcresp_loadcontenttable : public zcresp {
	uint32_t hobject;
};

struct zcresp_loadrecipienttable : public zcresp {
	uint32_t hobject;
};

struct zcresp_loadruletable : public zcresp {
	uint32_t hobject;
};
	
struct zcresp_createmessage : public zcresp {
	uint32_t hobject;
};

struct zcresp_createfolder : public zcresp {
	uint32_t hobject;
};

struct zcresp_getstoreentryid : public zcresp {
	BINARY entryid;
};

struct zcresp_entryidfromsourcekey : public zcresp {
	BINARY entryid;
};

struct zcresp_storeadvise : public zcresp {
	uint32_t sub_id;
};

struct zcresp_notifdequeue : public zcresp {
	ZNOTIFICATION_ARRAY notifications;
};

struct zcresp_queryrows : public zcresp {
	TARRAY_SET rowset;
};

struct zcresp_setcolumns : public zcresp {
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct zcresp_seekrow : public zcresp {
	int32_t sought_rows;
};

struct zcresp_getrowcount : public zcresp {
	uint32_t count;
};

struct zcresp_findrow : public zcresp {
	uint32_t row_idx;
};

struct zcresp_createbookmark : public zcresp {
	uint32_t bookmark;
};

struct zcresp_getreceivefolder : public zcresp {
	BINARY entryid;
};

struct zcresp_loadattachmenttable : public zcresp {
	uint32_t hobject;
};

struct zcresp_openattachment : public zcresp {
	uint32_t hobject;
};

struct zcresp_createattachment : public zcresp {
	uint32_t hobject;
};

struct zcresp_getpropvals : public zcresp {
	TPROPVAL_ARRAY propvals;
};

struct zcresp_openembedded : public zcresp {
	uint32_t hobject;
};

struct zcresp_getnamedpropids : public zcresp {
	PROPID_ARRAY propids;
};

struct zcresp_getpropnames : public zcresp {
	PROPNAME_ARRAY propnames;
};

struct zcresp_hierarchysync : public zcresp {
	uint32_t hobject;
};

struct zcresp_contentsync : public zcresp {
	uint32_t hobject;
};

struct zcresp_configsync : public zcresp {
	uint8_t b_changed;
	uint32_t count;
};

struct zcresp_statesync : public zcresp {
	BINARY state;
};

struct zcresp_syncmessagechange : public zcresp {
	uint8_t b_new;
	TPROPVAL_ARRAY proplist;
};

struct zcresp_syncfolderchange : public zcresp {
	TPROPVAL_ARRAY proplist;
};

struct zcresp_syncreadstatechanges : public zcresp {
	STATE_ARRAY states;
};

struct zcresp_syncdeletions : public zcresp {
	BINARY_ARRAY bins;
};

struct zcresp_hierarchyimport : public zcresp {
	uint32_t hobject;
};

struct zcresp_contentimport : public zcresp {
	uint32_t hobject;
};
	
struct zcresp_stateimport : public zcresp {
	BINARY state;
};

struct zcresp_importmessage : public zcresp {
	uint32_t hobject;
};

struct zcresp_getsearchcriteria : public zcresp {
	BINARY_ARRAY folder_array;
	RESTRICTION *prestriction;
	uint32_t search_stat;
};

struct zcresp_messagetorfc822 : public zcresp {
	BINARY eml_bin;
};

struct zcresp_messagetoical : public zcresp {
	BINARY ical_bin;
};

struct zcresp_messagetovcf : public zcresp {
	BINARY vcf_bin;
};

struct zcresp_getuseravailability : public zcresp {
	char *result_string;
};

struct zcresp_imtomessage2 : public zcresp {
	LONG_ARRAY msg_handles;
};

struct zcresp_essdn_to_username : public zcresp {
	char *username;
};

using zcresp_checksession = zcresp;
using zcresp_configimport = zcresp;
using zcresp_copyfolder = zcresp;
using zcresp_copymessages = zcresp;
using zcresp_copyto = zcresp;
using zcresp_deleteattachment = zcresp;
using zcresp_deletefolder = zcresp;
using zcresp_deletemessages = zcresp;
using zcresp_deletepropvals = zcresp;
using zcresp_emptyfolder = zcresp;
using zcresp_freebookmark = zcresp;
using zcresp_icaltomessage = zcresp;
using zcresp_importdeletion = zcresp;
using zcresp_importfolder = zcresp;
using zcresp_importreadstates = zcresp;
using zcresp_linkmessage = zcresp;
using zcresp_modifypermissions = zcresp;
using zcresp_modifyrecipients = zcresp;
using zcresp_modifyrules = zcresp;
using zcresp_restricttable = zcresp;
using zcresp_rfc822tomessage = zcresp;
using zcresp_savechanges = zcresp;
using zcresp_setmessagereadflag = zcresp;
using zcresp_setpasswd = zcresp;
using zcresp_setpropvals = zcresp;
using zcresp_setreadflags = zcresp;
using zcresp_setsearchcriteria = zcresp;
using zcresp_sorttable = zcresp;
using zcresp_submitmessage = zcresp;
using zcresp_unadvise = zcresp;
using zcresp_unloadobject = zcresp;
using zcresp_vcftomessage = zcresp;

enum {
	MXF_UNWRAP_SMIME_CLEARSIGNED = 0x1U,
};
