#pragma once
#include <cstdint>

#define PROP_ID(x) ((x) >> 16)
#define PROP_TYPE(x) ((x) & 0xFFFF)
#define CHANGE_PROP_TYPE(tag, newtype) (((tag) & ~0xFFFF) | (newtype))
/*
 * x|y yields an unsigned result if either x or y are unsigned.
 * x<<y yields unsigned only if x is unsigned.
 * All the while | and << only make *sense* in an unsigned _context_ anyway
 * (i.e. the operator should have returned unsigned all the time)
 */
#define PROP_TAG(type, tag) ((((unsigned int)tag) << 16) | (type))
enum { /* MS-OAUT */
	PT_UNSPECIFIED = 0x0000, /* VT_EMPTY */
	PT_NULL = 0x0001, /* VT_NULL */
	PT_SHORT = 0x0002, /* VT_I2, PT_I2 */
	PT_LONG = 0x0003, /* VT_I4, PT_I4 */
	PT_FLOAT = 0x0004, /* VT_R4, PT_R4 */
	PT_DOUBLE = 0x0005, /* VT_R8, PT_R8 */
	PT_CURRENCY = 0x0006, /* VT_CY */
	PT_APPTIME = 0x0007, /* VT_DATE */
	PT_ERROR = 0x000A, /* VT_ERROR */
	PT_BOOLEAN = 0x000B, /* VT_BOOL */
	PT_OBJECT = 0x000D, /* VT_UNKNOWN */
	PT_I8 = 0x0014, /* VT_I8 */
	PT_STRING8 = 0x001E, /* VT_LPSTR */
	PT_UNICODE = 0x001F, /* VT_LPWSTR */
	PT_SYSTIME = 0x0040, /* VT_FILETIME */
	PT_CLSID = 0x0048, /* VT_CLSID */
	PT_SVREID = 0x00FB, /* MS-OXCDATA extension */
	PT_SRESTRICT = 0x00FD, /* edkmdb.h extension */
	PT_ACTIONS = 0x00FE, /* edkmdb.h extension */
	PT_BINARY = 0x0102,
	PT_MV_SHORT = 0x1002, /* PT_MV_I2 */
	PT_MV_LONG = 0x1003, /* PT_MV_I4 */
	PT_MV_FLOAT = 0x1004, /* PT_MV_R4 */
	PT_MV_DOUBLE = 0x1005, /* PT_MV_R8 */
	PT_MV_CURRENCY = 0x1006, /* PT_MV_CURRENCY */
	PT_MV_APPTIME = 0x1007, /* PT_MV_APPTIME */
	PT_MV_I8 = 0x1014,
	PT_MV_STRING8 = 0x101E,
	PT_MV_UNICODE = 0x101F,
	PT_MV_SYSTIME = 0x1040,
	PT_MV_CLSID = 0x1048,
	PT_MV_BINARY = 0x1102,
};

enum {
	MV_FLAG = 0x1000,
	MV_INSTANCE = 0x2000,
	MVI_FLAG = MV_FLAG | MV_INSTANCE,
};

enum {
	PR_PARENT_KEY = PROP_TAG(PT_BINARY, 0x0025), /* PidTagParentKey */
	PR_DISPLAY_BCC_A = PROP_TAG(PT_STRING8, 0x0E02),
	PR_DISPLAY_BCC = PROP_TAG(PT_UNICODE, 0x0E02), /* PidTagDisplayBcc */
	PR_DISPLAY_CC_A = PROP_TAG(PT_STRING8, 0x0E03),
	PR_DISPLAY_CC = PROP_TAG(PT_UNICODE, 0x0E03), /* PidTagDisplayCc */
	PR_DISPLAY_TO_A = PROP_TAG(PT_STRING8, 0x0E04),
	PR_DISPLAY_TO = PROP_TAG(PT_UNICODE, 0x0E04), /* PidTagDisplayTo */
	PR_PARENT_DISPLAY_A = PROP_TAG(PT_STRING8, 0x0E05),
	PR_PARENT_DISPLAY = PROP_TAG(PT_UNICODE, 0x0E05), /* PidTagParentDisplay */
	PR_MESSAGE_FLAGS = PROP_TAG(PT_LONG, 0x0E07), /* pidTagMessageFlags */
	PR_MESSAGE_SIZE = PROP_TAG(PT_LONG, 0x0E08), /* pidTagMessageSize */
	PR_MESSAGE_SIZE_EXTENDED = PROP_TAG(PT_I8, 0x0E08), /* pidTagMessageSizeExtended */
	PR_PARENT_ENTRYID = PROP_TAG(PT_BINARY, 0x0E09), /* PidTagParentEntryId */
	PR_PARENT_SVREID = PROP_TAG(PT_SVREID, 0x0E09),
	PR_REPL_ITEMID = PROP_TAG(PT_LONG, 0x0E30), /* pidTagReplItemId */
	PR_REPL_CHANGENUM = PROP_TAG(PT_I8, 0x0E33), /* pidTagReplChangenum */
	PR_REPL_VERSIONHISTORY = PROP_TAG(PT_BINARY, 0x0E34), /* pidTagReplVersionhistory */
	PR_REPL_FLAGS = PROP_TAG(PT_LONG, 0x0E38), /* pidTagReplFlags */
	PR_REPL_COPIEDFROM_VERSIONHISTORY = PROP_TAG(PT_BINARY, 0x0E3C), /* pidTagReplCopiedfromVersionhistory */
	PR_REPL_COPIEDFROM_ITEMID = PROP_TAG(PT_BINARY, 0x0E3D), /* pidTagReplCopiedfromItemid */
	PR_READ = PROP_TAG(PT_BOOLEAN, 0x0E69), /* pidTagRead */
	PR_ACCESS = PROP_TAG(PT_LONG, 0x0FF4), /* PidTagAccess */
	PR_ACCESS_LEVEL = PROP_TAG(PT_LONG, 0x0FF7), /* PidTagAccessLevel */
	PR_STORE_RECORD_KEY = PROP_TAG(PT_BINARY, 0x0FFA), /* PidTagStoreRecordKey */
	PR_STORE_ENTRYID = PROP_TAG(PT_BINARY, 0x0FFB), /* PidTagStoreEntryId */
	PR_RECORD_KEY = PROP_TAG(PT_BINARY, 0x0FF9), /* pidTagRecordKey */
	PR_OBJECT_TYPE = PROP_TAG(PT_LONG, 0x0FFE), /* pidTagObjectType */
	PR_ENTRYID = PROP_TAG(PT_BINARY, 0x0FFF), /* pidTagEntryId */
	PR_BODY_A = PROP_TAG(PT_STRING8, 0x1000),
	PR_BODY_W = PROP_TAG(PT_UNICODE, 0x1000),
	PR_BODY = PR_BODY_W, /* pidTagBody */
	PR_HTML = PROP_TAG(PT_BINARY, 0x1013), /* pidTagHtml */
	PR_RTF_COMPRESSED = PROP_TAG(PT_BINARY, 0x1009), /* pidTagRtfCompressed */
	PR_DISPLAY_NAME_A = PROP_TAG(PT_STRING8, 0x3001),
	PR_DISPLAY_NAME = PROP_TAG(PT_UNICODE, 0x3001), /* pidTagDisplayName */
	PR_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x3003),
	PR_EMAIL_ADDRESS = PROP_TAG(PT_UNICODE, 0x3003), /* pidTagEmailAddress */
	PR_CREATION_TIME = PROP_TAG(PT_SYSTIME, 0x3007), /* pidTagCreationTime */
	PR_LAST_MODIFICATION_TIME = PROP_TAG(PT_SYSTIME, 0x3008), /* pidTagLastModificationTime */
	PR_STORE_STATE = PROP_TAG(PT_LONG, 0x340E), /* PidTagStoreState */
	PR_STORE_SUPPORT_MASK = PROP_TAG(PT_LONG, 0x340D), /* PidTagStoreSupportMask */
	PR_MDB_PROVIDER = PROP_TAG(PT_BINARY, 0x3414), /* PidTagStoreProvider */
	PR_DISPLAY_NAME_PREFIX_A = PROP_TAG(PT_STRING8, 0x3A45),
	PR_DISPLAY_NAME_PREFIX = PROP_TAG(PT_UNICODE, 0x3A45), /* PidTagDisplayNamePrefix */
	PR_IPM_SUBTREE_ENTRYID = PROP_TAG(PT_BINARY, 0x35E0), /* PidTagIpmSubtreeEntryId */
	PR_IPM_OUTBOX_ENTRYID = PROP_TAG(PT_BINARY, 0x35E2), /* PidTagIpmOutboxEntryId */
	PR_IPM_WASTEBASKET_ENTRYID = PROP_TAG(PT_BINARY, 0x35E3), /* PidTagIpmWastebasketEntryId */
	PR_IPM_SENTMAIL_ENTRYID = PROP_TAG(PT_BINARY, 0x35E4), /* PidTagIpmSentMailEntryId */
	PR_IPM_APPOINTMENT_ENTRYID = PROP_TAG(PT_BINARY, 0x36D0), /* PidTagIpmAppointmentEntryId */
	PR_IPM_CONTACT_ENTRYID = PROP_TAG(PT_BINARY, 0x36D1), /* PidTagIpmContactEntryId */
	PR_IPM_JOURNAL_ENTRYID = PROP_TAG(PT_BINARY, 0x36D2), /* PidTagIpmJournalEntryId */
	PR_IPM_NOTE_ENTRYID = PROP_TAG(PT_BINARY, 0x36D3), /* PidTagIpmNoteEntryId */
	PR_IPM_TASK_ENTRYID = PROP_TAG(PT_BINARY, 0x36D4), /* PidTagIpmTaskEntryId */
	PR_IPM_DRAFTS_ENTRYID = PROP_TAG(PT_BINARY, 0x36D7), /* PidTagIpmDraftsEntryId */
	PR_ATTACH_DATA_BIN = PROP_TAG(PT_BINARY, 0x3701), /* pidTagAttachDataBinary */
	PR_ATTACH_DATA_OBJ = PROP_TAG(PT_OBJECT, 0x3701), /* pidTagAttachDataObject */
	PR_DISPLAY_TYPE = PROP_TAG(PT_LONG, 0x3900), /* PidTagDisplayType */
	PR_DISPLAY_TYPE_EX = PROP_TAG(PT_LONG, 0x3905), /* PidTagDisplayTypeEx */
	PR_SMTP_ADDRESS = PROP_TAG(PT_UNICODE, 0x39FE), /* pidTagSmtpAddress */
	PR_SOURCE_KEY = PROP_TAG(PT_BINARY, 0x65E0), /* pidTagSourceKey */
	PR_PARENT_SOURCE_KEY = PROP_TAG(PT_BINARY, 0x65E1), /* PidTagParentSourceKey */
	PR_CHANGE_KEY = PROP_TAG(PT_BINARY, 0x65E2), /* pidTagChangeKey */
	PR_PREDECESSOR_CHANGE_LIST = PROP_TAG(PT_BINARY, 0x65E3), /* pidTagPredecessorChangeList */
	PR_IPM_PUBLIC_FOLDERS_ENTRYID = PROP_TAG(PT_BINARY, 0x65E1),
	PR_IPM_FAVORITES_ENTRYID = PROP_TAG(PT_BINARY, 0x6630),
	PR_STORE_OFFLINE = PROP_TAG(PT_BOOLEAN, 0x6632),
	PR_PST_LRNORESTRICTIONS = PROP_TAG(PT_BOOLEAN, 0x6633), /* pidTagPstLrNoRestrictions */
	PR_HIERARCHY_SERVER_A = PROP_TAG(PT_STRING8, 0x6633),
	PR_HIERARCHY_SERVER_W = PROP_TAG(PT_UNICODE, 0x6633),
	PR_PROFILE_OAB_COUNT_ATTEMPTED_FULLDN = PROP_TAG(PT_LONG, 0x6635), /* pidTagProfileOabCountAttemptedFulldn */
	PR_PST_HIDDEN_COUNT = PROP_TAG(PT_LONG, 0x6635), /* pidTagPstHiddenCount */
	PR_FAVORITES_DEFAULT_NAME_A = PROP_TAG(PT_STRING8, 0x6635),
	PR_FAVORITES_DEFAULT_NAME_W = PROP_TAG(PT_UNICODE, 0x6635),
	PR_PST_HIDDEN_UNREAD = PROP_TAG(PT_LONG, 0x6636), /* pidTagPstHiddenUnread */
	PR_PROFILE_OAB_COUNT_ATTEMPTED_INCRDN = PROP_TAG(PT_LONG, 0x6636), /* pidTagProfileOabCountAttemptedIncrdn */
	PR_LATEST_PST_ENSURE = PROP_TAG(PT_LONG, 0x66FA), /* pidTagLatestPstEnsure */
	PR_LTP_ROW_ID = PROP_TAG(PT_LONG, 0x67F2), /* pidTagLtpRowId */
	PR_LTP_ROW_VER = PROP_TAG(PT_LONG, 0x67F3), /* pidTagLtpRowVer */
	PR_PST_PASSWORD = PROP_TAG(PT_LONG, 0x67FF), /* pidTagPstPassword */
};

enum ACTTYPE {
	OP_MOVE = 0x1U,
	OP_COPY = 0x2U,
	OP_REPLY = 0x3U,
	OP_OOF_REPLY = 0x4U,
	OP_DEFER_ACTION = 0x5U,
	OP_BOUNCE = 0x6U,
	OP_FORWARD = 0x7U,
	OP_DELEGATE = 0x8U,
	OP_TAG = 0x9U,
	OP_DELETE = 0xaU,
	OP_MARK_AS_READ = 0xbU,
};

enum bm_relop {
	BMR_EQZ = 0,
	BMR_NEZ,
};

enum {
	CTRL_FLAG_BINHEX = 0x00,
	CTRL_FLAG_UUENCODE = 0x20,
	CTRL_FLAG_APPLESINGLE = 0x40,
	CTRL_FLAG_APPLEDOUBLE = 0x60,
	CTRL_FLAG_TEXTONLY = 0x06,
	CTRL_FLAG_HTMLONLY = 0x0E,
	CTRL_FLAG_TEXTANDHTML = 0x16,
	CTRL_FLAG_NORICH = 0x01,
	CTRL_FLAG_UNICODE = 0x8000,
	CTRL_FLAG_DONTLOOKUP = 0x1000,
};

enum {
	EVENT_TYPE_NEWMAIL = 1U << 1,
	EVENT_TYPE_OBJECTCREATED = 1U << 2,
	EVENT_TYPE_OBJECTDELETED = 1U << 3,
	EVENT_TYPE_OBJECTMODIFIED = 1U << 4,
	EVENT_TYPE_OBJECTMOVED = 1U << 5,
	EVENT_TYPE_OBJECTCOPIED = 1U << 6,
	EVENT_TYPE_SEARCHCOMPLETE = 1U << 7,
};

enum {
	MNID_ID = 0,
	MNID_STRING = 1,
	KIND_NONE = 0xff,
};

enum {
	MODRECIP_ADD = 1U << 1,
	MODRECIP_MODIFY = 1U << 2,
	MODRECIP_REMOVE = 1U << 3,
};

enum relop {
	RELOP_LT = 0x00,
	RELOP_LE,
	RELOP_GT,
	RELOP_GE,
	RELOP_EQ,
	RELOP_NE,
	RELOP_RE,
	RELOP_MEMBER_OF_DL = 0x64,
};

enum res_type {
	RES_AND = 0x00,
	RES_OR = 0x01,
	RES_NOT = 0x02,
	RES_CONTENT = 0x03,
	RES_PROPERTY = 0x04,
	RES_PROPCOMPARE = 0x05,
	RES_BITMASK = 0x06,
	RES_SIZE = 0x07,
	RES_EXIST = 0x08,
	RES_SUBRESTRICTION = 0x09,
	RES_COMMENT = 0x0a,
	RES_COUNT = 0x0b,
	RES_NULL = 0xff,
};

enum zics_type {
	ICS_TYPE_CONTENTS = 1,
	ICS_TYPE_HIERARCHY = 2,
};

enum zmapi_group {
	MAPI_ROOT = 0,
	MAPI_TABLE = 1,
	MAPI_MESSAGE = 2,
	MAPI_ATTACHMENT = 3,
	MAPI_ABCONT = 4,
	MAPI_FOLDER = 5,
	MAPI_SESSION = 6,
	MAPI_ADDRESSBOOK = 7,
	MAPI_STORE = 8,
	MAPI_MAILUSER = 9,
	MAPI_DISTLIST = 10,
	MAPI_PROFPROPERTY = 11,
	MAPI_ADVISESINK = 12,
	MAPI_ICSDOWNCTX = 13,
	MAPI_ICSUPCTX = 14,
	MAPI_INVALID = 255,
};

enum STREAM_SEEK {
	STREAM_SEEK_SET = 0,
	STREAM_SEEK_CUR = 1,
	STREAM_SEEK_END = 2,
};

enum BOOKMARK {
	BOOKMARK_BEGINNING = STREAM_SEEK_SET,
	BOOKMARK_CURRENT = STREAM_SEEK_CUR,
	BOOKMARK_END = STREAM_SEEK_END,
	BOOKMARK_CUSTOM = 3,
};

enum {
	FL_FULLSTRING = 0,
	FL_SUBSTRING,
	FL_PREFIX,

	FL_IGNORECASE = 1 << 16,
	FL_IGNORENONSPACE = 1 << 17,
	FL_LOOSE = 1 << 18,
};

enum {
	MAXIMUM_SORT_COUNT = 8,
};

enum {
	RULE_DATA_FLAG_ADD_ROW = 1U << 0,
	RULE_DATA_FLAG_MODIFY_ROW = 1U << 1,
	RULE_DATA_FLAG_REMOVE_ROW = 1U << 2,
};

enum zaccess_type {
	ACCESS_TYPE_DENIED = 1,
	ACCESS_TYPE_GRANT = 2,
	ACCESS_TYPE_BOTH = 3,
};

enum {
	RIGHT_NORMAL = 0,
	RIGHT_NEW = 1U << 0,
	RIGHT_MODIFY = 1U << 1,
	RIGHT_DELETED = 1U << 2,
	RIGHT_AUTOUPDATE_DENIED = 1U << 3,
};

struct ACTION_BLOCK {
	uint16_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
};

struct ADVISE_INFO {
	uint32_t hstore;
	uint32_t sub_id;
};

struct BINARY {
	uint32_t cb;
	union {
		uint8_t *pb;
		char *pc;
		void *pv;
	};
};

struct BINARY_ARRAY {
	uint32_t count;
	BINARY *pbin;
};

struct FLATUID {
	uint8_t ab[16];
};

struct FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
};

struct GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
};

struct GUID_ARRAY {
	uint32_t count;
	GUID *pguid;
};

struct LONG_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	uint32_t *pl;
};

struct LONGLONG_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	uint64_t *pll;
};

struct LPROPTAG_ARRAY {
	uint32_t cvalues;
	uint32_t *pproptag;
};

struct MESSAGE_STATE {
	BINARY source_key;
	uint32_t message_flags;
};

struct NOTIF_SINK {
	GUID hsession;
	uint16_t count;
	ADVISE_INFO *padvise;
};

struct ONEOFF_ENTRYID {
	uint32_t flags;
	/* 81.2B.1F.A4.BE.A3.10.19.9D.6E.00.DD.01.0F.54.02 */
	uint8_t provider_uid[16];
	uint16_t version; /* should be 0x0000 */
	uint16_t ctrl_flags;
	char *pdisplay_name;
	char *paddress_type;
	char *pmail_address;
};

struct ONEOFF_ARRAY {
	uint32_t count;
	ONEOFF_ENTRYID *pentry_id;
};

struct PERMISSION_ROW {
	uint32_t flags;
	BINARY entryid;
	uint32_t member_rights;
};

struct PERMISSION_SET {
	uint16_t count;
	PERMISSION_ROW *prows;
};

struct PROPERTY_NAME {
	uint8_t kind;
	GUID guid;
	uint32_t *plid;
	char *pname;
};

struct PROPID_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
};

struct PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
};

struct PROPTAG_ARRAY {
	uint16_t count;
	uint32_t *pproptag;
};

struct SHORT_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	uint16_t *ps;
};

struct SORT_ORDER {
	uint16_t type; /* pay attention to the 0x2000 bit */
	uint16_t propid;
	uint8_t table_sort;
};

struct SORTORDER_SET {
	uint16_t count;
	uint16_t ccategories;
	uint16_t cexpanded;
	SORT_ORDER *psort;
};

struct STATE_ARRAY {
	uint32_t count;
	MESSAGE_STATE *pstate;
};

struct STRING_ARRAY {
	union {
		uint32_t cvalues, count;
	};
	char **ppstr;
};

struct SVREID {
	BINARY *pbin;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t instance;
};

struct TAGGED_PROPVAL {
	uint32_t proptag;
	void *pvalue;
};

struct TPROPVAL_ARRAY {
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct TARRAY_SET {
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
};

struct NEWMAIL_ZNOTIFICATION {
	BINARY entryid;
	BINARY parentid;
	uint32_t flags; /* unicode or not */
	char *message_class;
	uint32_t message_flags;
};

struct OBJECT_ZNOTIFICATION {
	uint32_t object_type;
	BINARY *pentryid;
	BINARY *pparentid;
	BINARY *pold_entryid;
	BINARY *pold_parentid;
	PROPTAG_ARRAY *pproptags;
};

struct RECIPIENT_BLOCK {
	uint8_t reserved;
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
};

struct RESTRICTION_AND_OR;
struct RESTRICTION_NOT;
struct RESTRICTION_CONTENT;
struct RESTRICTION_PROPERTY;
struct RESTRICTION_PROPCOMPARE;
struct RESTRICTION_BITMASK;
struct RESTRICTION_SIZE;
struct RESTRICTION_EXIST;
struct RESTRICTION_SUBOBJ;
struct RESTRICTION_COMMENT;
struct RESTRICTION_COUNT;

struct RESTRICTION {
	enum res_type rt;
	union {
		void *pres;
		RESTRICTION_AND_OR *andor;
		RESTRICTION_NOT *xnot;
		RESTRICTION_CONTENT *cont;
		RESTRICTION_PROPERTY *prop;
		RESTRICTION_PROPCOMPARE *pcmp;
		RESTRICTION_BITMASK *bm;
		RESTRICTION_SIZE *size;
		RESTRICTION_EXIST *exist;
		RESTRICTION_SUBOBJ *sub;
		RESTRICTION_COMMENT *comment;
		RESTRICTION_COUNT *count;
	};
};

struct RESTRICTION_AND_OR {
	uint32_t count;
	RESTRICTION *pres;
};

struct RESTRICTION_NOT {
	RESTRICTION res;
};

struct RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
};

struct RESTRICTION_PROPERTY {
	enum relop relop;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
};

struct RESTRICTION_PROPCOMPARE {
	enum relop relop;
	uint32_t proptag1;
	uint32_t proptag2;
};

struct RESTRICTION_BITMASK {
	enum bm_relop bitmask_relop;
	uint32_t proptag;
	uint32_t mask;
};

struct RESTRICTION_SIZE {
	enum relop relop;
	uint32_t proptag;
	uint32_t size;
};

struct RESTRICTION_EXIST {
	uint32_t proptag;
};

struct RESTRICTION_SUBOBJ {
	uint32_t subobject;
	RESTRICTION res;
};

struct RESTRICTION_COMMENT {
	uint8_t count;
	TAGGED_PROPVAL *ppropval;
	RESTRICTION *pres;
};

struct RESTRICTION_COUNT {
	uint32_t count;
	RESTRICTION sub_res;
};

struct RULE_ACTIONS {
	uint16_t count;
	ACTION_BLOCK *pblock;
};

struct RULE_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
};

struct RULE_LIST {
	uint16_t count;
	RULE_DATA *prule;
};

struct ZMOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
};

struct ZNOTIFICATION {
	uint32_t event_type;
	void *pnotification_data; /* NEWMAIL_ZNOTIFICATION or OBJECT_ZNOTIFICATION */
};

struct ZNOTIFICATION_ARRAY {
	uint16_t count;
	ZNOTIFICATION **ppnotification;
};

/* reply or OOF action */
struct ZREPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
};

struct FORWARDDELEGATE_ACTION {
	uint16_t count;
	RECIPIENT_BLOCK *pblock;
};
