#pragma once
#include <cstdint>
#include <vector>
#include <gromox/mapidefs.h>
#include <gromox/zcore_types.hpp>

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
	// getuseravailability = 0x53,
	setpasswd = 0x54,
	linkmessage = 0x55,
	rfc822tomessage = 0x56,
	// icaltomessage2 = 0x57,
	imtomessage2 = 0x58,
	essdn_to_username = 0x59,
	logon_token = 0x5a,
	getuserfreebusy = 0x5b,
	getuserfreebusyical = 0x5c,
	logon_np = 0x5d,
	/* update exch/zcore/names.cpp! */
};

struct zcreq {
	using view_t = zcreq;
	zcreq() = default; /* Prevent use of direct-init-list */
	virtual ~zcreq() = default;
	zcore_callid call_id;
};

struct zcreq_logon_token final : public zcreq {
	using view_t = zcreq_logon_token;
	char *token;
	char *rhost;
};

struct zcreq_logon final : public zcreq {
	using view_t = zcreq_logon;
	char *username;
	char *password;
	char *rhost;
	uint32_t flags;
};
using zcreq_logon_np = zcreq_logon;

struct zcreq_checksession final : public zcreq {
	using view_t = zcreq_checksession;
	GUID hsession;
};

struct zcreq_uinfo final : public zcreq {
	using view_t = zcreq_uinfo;
	char *username;
};

struct zcreq_unloadobject final : public zcreq {
	using view_t = zcreq_unloadobject;
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_openentry final : public zcreq {
	using view_t = zcreq_openentry;
	GUID hsession;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_openstoreentry final : public zcreq {
	using view_t = zcreq_openstoreentry;
	GUID hsession;
	uint32_t hobject;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_openabentry final : public zcreq {
	using view_t = zcreq_openabentry;
	GUID hsession;
	BINARY entryid;
};

struct zcreq_resolvename final : public zcreq {
	using view_t = zcreq_resolvename;
	GUID hsession;
	TARRAY_SET *pcond_set;
};

struct zcreq_getpermissions final : public zcreq {
	using view_t = zcreq_getpermissions;
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_modifypermissions final : public zcreq {
	using view_t = zcreq_modifypermissions;
	GUID hsession;
	uint32_t hfolder;
	PERMISSION_SET *pset;
};

struct zcreq_modifyrules final : public zcreq {
	using view_t = zcreq_modifyrules;
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	RULE_LIST *plist;
};

struct zcreq_getabgal final : public zcreq {
	using view_t = zcreq_getabgal;
	GUID hsession;
};

struct zcreq_loadstoretable final : public zcreq {
	using view_t = zcreq_loadstoretable;
	GUID hsession;
};

struct zcreq_openstore final : public zcreq {
	using view_t = zcreq_openstore;
	GUID hsession;
	BINARY entryid;
};

struct zcreq_openprofilesec final : public zcreq {
	using view_t = zcreq_openprofilesec;
	GUID hsession;
	const FLATUID *puid;
};

struct zcreq_loadhierarchytable final : public zcreq {
	using view_t = zcreq_loadhierarchytable;
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_loadcontenttable final : public zcreq {
	using view_t = zcreq_loadcontenttable;
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_loadrecipienttable final : public zcreq {
	using view_t = zcreq_loadrecipienttable;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_loadruletable final : public zcreq {
	using view_t = zcreq_loadruletable;
	GUID hsession;
	uint32_t hfolder;
};
	
struct zcreq_createmessage final : public zcreq {
	using view_t = zcreq_createmessage;
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_deletemessages final : public zcreq {
	using view_t = zcreq_deletemessages;
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_copymessages final : public zcreq {
	using view_t = zcreq_copymessages;
	GUID hsession;
	uint32_t hsrcfolder;
	uint32_t hdstfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_setreadflags final : public zcreq {
	using view_t = zcreq_setreadflags;
	GUID hsession;
	uint32_t hfolder;
	BINARY_ARRAY *pentryids;
	uint32_t flags;
};

struct zcreq_createfolder final : public zcreq {
	using view_t = zcreq_createfolder;
	GUID hsession;
	uint32_t hparent_folder;
	uint32_t folder_type;
	char *folder_name;
	char *folder_comment;
	uint32_t flags;
};

struct zcreq_deletefolder final : public zcreq {
	using view_t = zcreq_deletefolder;
	GUID hsession;
	uint32_t hparent_folder;
	BINARY entryid;
	uint32_t flags;
};

struct zcreq_emptyfolder final : public zcreq {
	using view_t = zcreq_emptyfolder;
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
};

struct zcreq_copyfolder final : public zcreq {
	using view_t = zcreq_copyfolder;
	GUID hsession;
	uint32_t hsrc_folder;
	BINARY entryid;
	uint32_t hdst_folder;
	char *new_name;
	uint32_t flags;
};

struct zcreq_getstoreentryid final : public zcreq {
	using view_t = zcreq_getstoreentryid;
	char *mailbox_dn;
};

struct zcreq_entryidfromsourcekey final : public zcreq {
	using view_t = zcreq_entryidfromsourcekey;
	GUID hsession;
	uint32_t hstore;
	BINARY folder_key;
	BINARY *pmessage_key;
};

struct zcreq_storeadvise final : public zcreq {
	using view_t = zcreq_storeadvise;
	GUID hsession;
	uint32_t hstore;
	BINARY *pentryid;
	uint32_t event_mask;
};

struct zcreq_unadvise final : public zcreq {
	using view_t = zcreq_unadvise;
	GUID hsession;
	uint32_t hstore;
	uint32_t sub_id;
};

struct zcreq_notifdequeue final : public zcreq {
	using view_t = zcreq_notifdequeue;
	NOTIF_SINK *psink;
	uint32_t timeval;
};

struct zcreq_queryrows_v final : public zcreq {
	GUID hsession;
	uint32_t htable;
	uint32_t start;
	uint32_t count;
	RESTRICTION *prestriction;
	std::optional<proptag_cspan> pproptags;
};

struct zcreq_queryrows final : public zcreq {
	using view_t = zcreq_queryrows_v;
	GUID hsession;
	uint32_t htable;
	uint32_t start;
	uint32_t count;
	RESTRICTION *prestriction;
	std::optional<proptag_vector> pproptags;
	operator view_t() const {
		view_t v;
		v.hsession = hsession;
		v.htable = htable;
		v.start = start;
		v.count = count;
		v.prestriction = prestriction;
		if (pproptags.has_value())
			v.pproptags = *pproptags;
		return v;
	}
};

struct zcreq_setcolumns_v final : public zcreq {
	GUID hsession;
	uint32_t htable, flags;
	proptag_cspan pproptags;
};

struct zcreq_setcolumns final : public zcreq {
	using view_t = zcreq_setcolumns_v;
	GUID hsession;
	uint32_t htable, flags;
	proptag_vector pproptags;
	operator view_t() const {
		view_t v;
		v.hsession = hsession;
		v.htable = htable;
		v.flags = flags;
		v.pproptags = pproptags;
		return v;
	}
};

struct zcreq_seekrow final : public zcreq {
	using view_t = zcreq_seekrow;
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	int32_t seek_rows;
};

struct zcreq_sorttable final : public zcreq {
	using view_t = zcreq_sorttable;
	GUID hsession;
	uint32_t htable;
	SORTORDER_SET *psortset;
};

struct zcreq_getrowcount final : public zcreq {
	using view_t = zcreq_getrowcount;
	GUID hsession;
	uint32_t htable;
};

struct zcreq_restricttable final : public zcreq {
	using view_t = zcreq_restricttable;
	GUID hsession;
	uint32_t htable;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct zcreq_findrow final : public zcreq {
	using view_t = zcreq_findrow;
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
	RESTRICTION *prestriction;
	uint32_t flags;
};

struct zcreq_createbookmark final : public zcreq {
	using view_t = zcreq_createbookmark;
	GUID hsession;
	uint32_t htable;
};

struct zcreq_freebookmark final : public zcreq {
	using view_t = zcreq_freebookmark;
	GUID hsession;
	uint32_t htable;
	uint32_t bookmark;
};

struct zcreq_getreceivefolder final : public zcreq {
	using view_t = zcreq_getreceivefolder;
	GUID hsession;
	uint32_t hstore;
	char *pstrclass;
};

struct zcreq_modifyrecipients final : public zcreq {
	using view_t = zcreq_modifyrecipients;
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
	TARRAY_SET *prcpt_list;
};

struct zcreq_submitmessage final : public zcreq {
	using view_t = zcreq_submitmessage;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_loadattachmenttable final : public zcreq {
	using view_t = zcreq_loadattachmenttable;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_openattachment final : public zcreq {
	using view_t = zcreq_openattachment;
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct zcreq_createattachment final : public zcreq {
	using view_t = zcreq_createattachment;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_deleteattachment final : public zcreq {
	using view_t = zcreq_deleteattachment;
	GUID hsession;
	uint32_t hmessage;
	uint32_t attach_id;
};

struct zcreq_setpropvals final : public zcreq {
	using view_t = zcreq_setpropvals;
	GUID hsession;
	uint32_t hobject;
	TPROPVAL_ARRAY *ppropvals;
};

struct zcreq_getpropvals final : public zcreq {
	using view_t = zcreq_getpropvals;
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_deletepropvals final : public zcreq {
	using view_t = zcreq_deletepropvals;
	GUID hsession;
	uint32_t hobject;
	PROPTAG_ARRAY *pproptags;
};

struct zcreq_setmessagereadflag final : public zcreq {
	using view_t = zcreq_setmessagereadflag;
	GUID hsession;
	uint32_t hmessage;
	uint32_t flags;
};

struct zcreq_openembedded final : public zcreq {
	using view_t = zcreq_openembedded;
	GUID hsession;
	uint32_t hattachment;
	uint32_t flags;
};

struct zcreq_getnamedpropids final : public zcreq {
	using view_t = zcreq_getnamedpropids;
	GUID hsession;
	uint32_t hstore;
	PROPNAME_ARRAY *ppropnames;
};

struct zcreq_getpropnames final : public zcreq {
	using view_t = zcreq_getpropnames;
	GUID hsession;
	uint32_t hstore;
	PROPID_ARRAY ppropids;
};

struct zcreq_copyto final : public zcreq {
	using view_t = zcreq_copyto;
	GUID hsession;
	uint32_t hsrcobject;
	PROPTAG_ARRAY *pexclude_proptags;
	uint32_t hdstobject;
	uint32_t flags;
};

struct zcreq_savechanges final : public zcreq {
	using view_t = zcreq_savechanges;
	GUID hsession;
	uint32_t hobject;
};

struct zcreq_hierarchysync final : public zcreq {
	using view_t = zcreq_hierarchysync;
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_contentsync final : public zcreq {
	using view_t = zcreq_contentsync;
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_configsync final : public zcreq {
	using view_t = zcreq_configsync;
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY *pstate;
	RESTRICTION *prestriction;
};

struct zcreq_statesync final : public zcreq {
	using view_t = zcreq_statesync;
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncmessagechange final : public zcreq {
	using view_t = zcreq_syncmessagechange;
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncfolderchange final : public zcreq {
	using view_t = zcreq_syncfolderchange;
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncreadstatechanges final : public zcreq {
	using view_t = zcreq_syncreadstatechanges;
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_syncdeletions final : public zcreq {
	using view_t = zcreq_syncdeletions;
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
};

struct zcreq_hierarchyimport final : public zcreq {
	using view_t = zcreq_hierarchyimport;
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_contentimport final : public zcreq {
	using view_t = zcreq_contentimport;
	GUID hsession;
	uint32_t hfolder;
};

struct zcreq_configimport final : public zcreq {
	using view_t = zcreq_configimport;
	GUID hsession;
	uint32_t hctx;
	uint8_t sync_type;
	BINARY *pstate;
};
	
struct zcreq_stateimport final : public zcreq {
	using view_t = zcreq_stateimport;
	GUID hsession;
	uint32_t hctx;
};

struct zcreq_importmessage final : public zcreq {
	using view_t = zcreq_importmessage;
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	TPROPVAL_ARRAY *pproplist;
};
	
struct zcreq_importfolder final : public zcreq {
	using view_t = zcreq_importfolder;
	GUID hsession;
	uint32_t hctx;
	TPROPVAL_ARRAY *pproplist;
};

struct zcreq_importdeletion final : public zcreq {
	using view_t = zcreq_importdeletion;
	GUID hsession;
	uint32_t hctx;
	uint32_t flags;
	BINARY_ARRAY *pbins;
};

struct zcreq_importreadstates final : public zcreq {
	using view_t = zcreq_importreadstates;
	GUID hsession;
	uint32_t hctx;
	STATE_ARRAY *pstates;
};

struct zcreq_getsearchcriteria final : public zcreq {
	using view_t = zcreq_getsearchcriteria;
	GUID hsession;
	uint32_t hfolder;
};
	
struct zcreq_setsearchcriteria final : public zcreq {
	using view_t = zcreq_setsearchcriteria;
	GUID hsession;
	uint32_t hfolder;
	uint32_t flags;
	BINARY_ARRAY *pfolder_array;
	RESTRICTION *prestriction;
};

struct zcreq_messagetorfc822 final : public zcreq {
	using view_t = zcreq_messagetorfc822;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_rfc822tomessage final : public zcreq {
	using view_t = zcreq_rfc822tomessage;
	GUID hsession;
	uint32_t hmessage, mxf_flags;
	BINARY *peml_bin;
};

struct zcreq_messagetoical final : public zcreq {
	using view_t = zcreq_messagetoical;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_icaltomessage final : public zcreq {
	using view_t = zcreq_icaltomessage;
	GUID hsession;
	uint32_t hmessage;
	BINARY *pical_bin;
};

enum imtomessage2_type {
	IMTOMESSAGE_ICAL = 0,
	IMTOMESSAGE_VCARD,
};

struct zcreq_imtomessage2 final : public zcreq {
	using view_t = zcreq_imtomessage2;
	GUID session;
	uint32_t folder;
	uint32_t data_type;
	char *im_data;
};

struct zcreq_messagetovcf final : public zcreq {
	using view_t = zcreq_messagetovcf;
	GUID hsession;
	uint32_t hmessage;
};

struct zcreq_vcftomessage final : public zcreq {
	using view_t = zcreq_vcftomessage;
	GUID hsession;
	uint32_t hmessage;
	BINARY *pvcf_bin;
};

struct zcreq_setpasswd final : public zcreq {
	using view_t = zcreq_setpasswd;
	char *username;
	char *passwd;
	char *new_passwd;
};

struct zcreq_linkmessage final : public zcreq {
	using view_t = zcreq_linkmessage;
	GUID hsession;
	BINARY search_entryid;
	BINARY message_entryid;
};

struct zcreq_savesession final : public zcreq {
	using view_t = zcreq_savesession;
	GUID hsession;
};

struct zcreq_restoresession final : public zcreq {
	using view_t = zcreq_restoresession;
	BINARY *pdata_bin;
};

struct zcreq_essdn_to_username final : public zcreq {
	using view_t = zcreq_essdn_to_username;
	char *essdn;
};

struct zcreq_getuserfreebusy final : public zcreq {
	using view_t = zcreq_getuserfreebusy;
	GUID hsession;
	BINARY entryid;
	int64_t starttime;
	int64_t endtime;
};

struct zcreq_getuserfreebusyical final : public zcreq {
	using view_t = zcreq_getuserfreebusyical;
	GUID hsession;
	BINARY entryid;
	int64_t starttime;
	int64_t endtime;
};

struct zcresp {
	zcresp() = default; /* Prevent use of direct-init-list */
	virtual ~zcresp() = default;
	zcore_callid call_id;
	ec_error_t result;
};

struct zcresp_logon final : public zcresp {
	using view_t = zcresp_logon;
	GUID hsession;
};

struct zcresp_logon_token final : public zcresp {
	using view_t = zcresp_logon_token;
	GUID hsession;
};

struct zcresp_uinfo final : public zcresp {
	using view_t = zcresp_uinfo;
	BINARY entryid{};
	std::string pdisplay_name, px500dn;
	uint32_t privilege_bits = 0;
};

struct zcresp_openentry final : public zcresp {
	using view_t = zcresp_openentry;
	zs_objtype mapi_type;
	uint32_t hobject;
};

struct zcresp_openstoreentry final : public zcresp {
	using view_t = zcresp_openstoreentry;
	zs_objtype mapi_type;
	uint32_t hxobject;
};

struct zcresp_openabentry final : public zcresp {
	using view_t = zcresp_openabentry;
	zs_objtype mapi_type;
	uint32_t hobject;
};

struct zcresp_resolvename final : public zcresp {
	using view_t = zcresp_resolvename;
	TARRAY_SET result_set;
};

struct zcresp_getpermissions final : public zcresp {
	using view_t = zcresp_getpermissions;
	PERMISSION_SET perm_set;
};

struct zcresp_getabgal final : public zcresp {
	using view_t = zcresp_getabgal;
	BINARY entryid;
};

struct zcresp_loadstoretable final : public zcresp {
	using view_t = zcresp_loadstoretable;
	uint32_t hobject;
};

struct zcresp_openstore final : public zcresp {
	using view_t = zcresp_openstore;
	uint32_t hobject;
};

struct zcresp_openprofilesec final : public zcresp {
	using view_t = zcresp_openprofilesec;
	uint32_t hobject;
};

struct zcresp_loadhierarchytable final : public zcresp {
	using view_t = zcresp_loadhierarchytable;
	uint32_t hobject;
};

struct zcresp_loadcontenttable final : public zcresp {
	using view_t = zcresp_loadcontenttable;
	uint32_t hobject;
};

struct zcresp_loadrecipienttable final : public zcresp {
	using view_t = zcresp_loadrecipienttable;
	uint32_t hobject;
};

struct zcresp_loadruletable final : public zcresp {
	using view_t = zcresp_loadruletable;
	uint32_t hobject;
};
	
struct zcresp_createmessage final : public zcresp {
	using view_t = zcresp_createmessage;
	uint32_t hobject;
};

struct zcresp_createfolder final : public zcresp {
	using view_t = zcresp_createfolder;
	uint32_t hobject;
};

struct zcresp_getstoreentryid final : public zcresp {
	using view_t = zcresp_getstoreentryid;
	BINARY entryid;
};

struct zcresp_entryidfromsourcekey final : public zcresp {
	using view_t = zcresp_entryidfromsourcekey;
	BINARY entryid;
};

struct zcresp_storeadvise final : public zcresp {
	using view_t = zcresp_storeadvise;
	uint32_t sub_id;
};

struct zcresp_notifdequeue final : public zcresp {
	using view_t = zcresp_notifdequeue;
	ZNOTIFICATION_ARRAY notifications;
};

struct zcresp_queryrows final : public zcresp {
	using view_t = zcresp_queryrows;
	TARRAY_SET rowset;
};

struct zcresp_setcolumns final : public zcresp {
	using view_t = zcresp_setcolumns;
	GUID hsession;
	uint32_t htable;
	PROPTAG_ARRAY *pproptags;
	uint32_t flags;
};

struct zcresp_seekrow final : public zcresp {
	using view_t = zcresp_seekrow;
	int32_t sought_rows;
};

struct zcresp_getrowcount final : public zcresp {
	using view_t = zcresp_getrowcount;
	uint32_t count;
};

struct zcresp_findrow final : public zcresp {
	using view_t = zcresp_findrow;
	uint32_t row_idx;
};

struct zcresp_createbookmark final : public zcresp {
	using view_t = zcresp_createbookmark;
	uint32_t bookmark;
};

struct zcresp_getreceivefolder final : public zcresp {
	using view_t = zcresp_getreceivefolder;
	BINARY entryid;
};

struct zcresp_loadattachmenttable final : public zcresp {
	using view_t = zcresp_loadattachmenttable;
	uint32_t hobject;
};

struct zcresp_openattachment final : public zcresp {
	using view_t = zcresp_openattachment;
	uint32_t hobject;
};

struct zcresp_createattachment final : public zcresp {
	using view_t = zcresp_createattachment;
	uint32_t hobject;
};

struct zcresp_getpropvals final : public zcresp {
	using view_t = zcresp_getpropvals;
	TPROPVAL_ARRAY propvals;
};

struct zcresp_openembedded final : public zcresp {
	using view_t = zcresp_openembedded;
	uint32_t hobject;
};

struct zcresp_getnamedpropids final : public zcresp {
	using view_t = zcresp_getnamedpropids;
	PROPID_ARRAY propids;
};

struct zcresp_getpropnames final : public zcresp {
	using view_t = zcresp_getpropnames;
	PROPNAME_ARRAY propnames;
};

struct zcresp_hierarchysync final : public zcresp {
	using view_t = zcresp_hierarchysync;
	uint32_t hobject;
};

struct zcresp_contentsync final : public zcresp {
	using view_t = zcresp_contentsync;
	uint32_t hobject;
};

struct zcresp_configsync final : public zcresp {
	using view_t = zcresp_configsync;
	uint8_t b_changed;
	uint32_t count;
};

struct zcresp_statesync final : public zcresp {
	using view_t = zcresp_statesync;
	BINARY state;
};

struct zcresp_syncmessagechange final : public zcresp {
	using view_t = zcresp_syncmessagechange;
	uint8_t b_new;
	TPROPVAL_ARRAY proplist;
};

struct zcresp_syncfolderchange final : public zcresp {
	using view_t = zcresp_syncfolderchange;
	TPROPVAL_ARRAY proplist;
};

struct zcresp_syncreadstatechanges final : public zcresp {
	using view_t = zcresp_syncreadstatechanges;
	STATE_ARRAY states;
};

struct zcresp_syncdeletions final : public zcresp {
	using view_t = zcresp_syncdeletions;
	BINARY_ARRAY bins;
};

struct zcresp_hierarchyimport final : public zcresp {
	using view_t = zcresp_hierarchyimport;
	uint32_t hobject;
};

struct zcresp_contentimport final : public zcresp {
	using view_t = zcresp_contentimport;
	uint32_t hobject;
};
	
struct zcresp_stateimport final : public zcresp {
	using view_t = zcresp_stateimport;
	BINARY state;
};

struct zcresp_importmessage final : public zcresp {
	using view_t = zcresp_importmessage;
	uint32_t hobject;
};

struct zcresp_getsearchcriteria final : public zcresp {
	using view_t = zcresp_getsearchcriteria;
	BINARY_ARRAY folder_array;
	RESTRICTION *prestriction;
	uint32_t search_stat;
};

struct zcresp_messagetorfc822 final : public zcresp {
	using view_t = zcresp_messagetorfc822;
	BINARY eml_bin;
};

struct zcresp_messagetoical final : public zcresp {
	using view_t = zcresp_messagetoical;
	BINARY ical_bin;
};

struct zcresp_messagetovcf final : public zcresp {
	using view_t = zcresp_messagetovcf;
	BINARY vcf_bin;
};

struct zcresp_imtomessage2 final : public zcresp {
	using view_t = zcresp_imtomessage2;
	LONG_ARRAY msg_handles;
};

struct zcresp_essdn_to_username final : public zcresp {
	using view_t = zcresp_essdn_to_username;
	char *username;
};

struct zcresp_getuserfreebusy final : public zcresp {
	using view_t = zcresp_getuserfreebusy;
	std::vector<freebusy_event> fb_events;
};

struct zcresp_getuserfreebusyical final : public zcresp {
	using view_t = zcresp_getuserfreebusyical;
	BINARY ical_bin;
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
using zcresp_logon_np = zcresp_logon;

enum {
	MXF_UNWRAP_SMIME_CLEARSIGNED = 0x1U,
};
