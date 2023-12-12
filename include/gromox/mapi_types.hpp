#pragma once
#if defined(COMPILE_DIAG) || defined(DEBUG_UMTA)
#	include <cassert>
#endif
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/range_set.hpp>

struct STORE_ENTRYID {
	uint32_t flags;
	uint8_t version;
	uint8_t flag;
	uint32_t wrapped_flags;
	FLATUID wrapped_provider_uid; /* g_muidStorePrivate / g_muidStorePublic */
	uint32_t wrapped_type;
	char *pserver_name;
	char *pmailbox_dn;
};

#define EITLT_PRIVATE_FOLDER						0x0001
#define EITLT_PUBLIC_FOLDER							0x0003
#define EITLT_WACKY_FOLDER							0x0005
#define EITLT_PRIVATE_MESSAGE						0x0007
#define EITLT_PUBLIC_MESSAGE						0x0009
#define EITLT_WACKY_MESSAGE							0x000b
#define EITLT_PUBLIC_FOLDER_BY_NAME					0x000c

struct FOLDER_ENTRYID {
	uint32_t flags;
	FLATUID provider_uid; /* glossary.rst:Store GUID */
	uint16_t folder_type;
	GUID database_guid;
	GLOBCNT global_counter;
	uint8_t pad[2];
};

struct MESSAGE_ENTRYID {
	uint32_t flags;
	FLATUID provider_uid; /* glossary.rst:Store GUID */
	uint16_t message_type;
	GUID folder_database_guid;
	GLOBCNT folder_global_counter;
	uint8_t pad1[2];
	GUID message_database_guid;
	GLOBCNT message_global_counter;
	uint8_t pad2[2];
};

struct MOVECOPY_ACTION {
	uint8_t same_store;
	STORE_ENTRYID *pstore_eid;
	void *pfolder_eid; /* SVREID or BINARY */

	std::string repr() const;
};

struct EXT_MOVECOPY_ACTION {
	FOLDER_ENTRYID folder_eid;
};

/* reply or OOF action */
struct REPLY_ACTION {
	uint64_t template_folder_id;
	uint64_t template_message_id;
	GUID template_guid;

	std::string repr() const;
};

struct EXT_REPLY_ACTION {
	MESSAGE_ENTRYID message_eid;
	GUID template_guid;
};

#define BOUNCE_CODE_MESSAGE_TOO_LARGE				0x0000000d
#define BOUNCE_CODE_MESSAGE_NOT_DISPLAYED			0x0000001f
#define BOUNCE_CODE_MESSAGE_DENIED					0x00000026

struct EXT_RECIPIENT_BLOCK {
	uint8_t reserved;
	uint32_t count;
	TAGGED_PROPVAL *ppropval;
};

struct EXT_FORWARDDELEGATE_ACTION {
	uint32_t count;
	EXT_RECIPIENT_BLOCK *pblock;

	EXT_RECIPIENT_BLOCK *begin() { return pblock; }
	EXT_RECIPIENT_BLOCK *end() { return pblock + count; }
	const EXT_RECIPIENT_BLOCK *begin() const { return pblock; }
	const EXT_RECIPIENT_BLOCK *end() const { return pblock + count; }
};

enum { /* ACTION_BLOCK::flavor for OP_FORWARD */
	FWD_PRESERVE_SENDER = 0x1U,
	FWD_DO_NOT_MUNGE_MSG = 0x2U,
	FWD_AS_ATTACHMENT = 0x4U,
	FWD_AS_SMS_ALERT = 0x8U,
};

enum { /* ACTION_BLOCK::flavor for OP_REPLY */
	DO_NOT_SEND_TO_ORIGINATOR = 0x1U,
	STOCK_REPLY_TEMPLATE = 0x2U,
};

struct EXT_ACTION_BLOCK {
	uint32_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
};

struct EXT_RULE_ACTIONS {
	uint32_t count;
	EXT_ACTION_BLOCK *pblock;

	EXT_ACTION_BLOCK *begin() { return pblock; }
	EXT_ACTION_BLOCK *end() { return pblock + count; }
	const EXT_ACTION_BLOCK *begin() const { return pblock; }
	const EXT_ACTION_BLOCK *end() const { return pblock + count; }
};

enum {
	ST_ENABLED             = 0x01U,
	ST_ERROR               = 0x02U,
	ST_ONLY_WHEN_OOF       = 0x04U,
	ST_KEEP_OOF_HIST       = 0x08U,
	ST_EXIT_LEVEL          = 0x10U,
	ST_SKIP_IF_SCL_IS_SAFE = 0x20U,
	ST_PARSE_ERROR         = 0x40U,
};

#define RULE_ERROR_GENERIC							0x00000001
#define RULE_ERROR_OPEN_FOLDER						0x00000002
#define RULE_ERROR_DELIVERY							0x00000003
#define RULE_ERROR_PARSING							0x00000004
#define RULE_ERROR_PROCESSING						0x00000005
#define RULE_ERROR_MOVECOPY							0x00000006
#define RULE_ERROR_PERMISSION						0x00000007
#define RULE_ERROR_DAM								0x00000008
#define RULE_ERROR_SENDAS							0x00000009
#define RULE_ERROR_RETRIEVE_TEMPLATE				0x0000000A
#define RULE_ERROR_EXECUTING						0x0000000B
#define RULE_ERROR_MAILBOX_QUOTA					0x0000000C
#define RULE_ERROR_TOO_MANY_RCPTS					0x0000000D
#define RULE_ERROR_FOLDER_QUOTA						0x0000000E			

struct NAMEDPROPERTY_INFO {
	uint16_t count;
	uint16_t *ppropid;
	PROPERTY_NAME *ppropname;
};

#define FLAGGED_PROPVAL_FLAG_AVAILABLE				0x0
#define FLAGGED_PROPVAL_FLAG_UNAVAILABLE			0x1
#define FLAGGED_PROPVAL_FLAG_ERROR					0xA

struct FLAGGED_PROPVAL {
	uint8_t flag;
	void *pvalue;
};

struct TYPED_PROPVAL {
	uint16_t type;
	void *pvalue;
};

struct LONG_TERM_ID {
	GUID guid;
	GLOBCNT global_counter;
	uint16_t padding;
};

struct LONG_TERM_ID_ARRAY {
	uint16_t count;
	LONG_TERM_ID *pids;
};

struct LONG_TERM_ID_RANGE {
	LONG_TERM_ID min;
	LONG_TERM_ID max;
};

struct XID {
	XID() = default;
	XID(GUID, eid_t cn);
	GLOBCNT local_to_gc() const { GLOBCNT r; memcpy(r.ab, local_id, 6); return r; }

	GUID guid;
	uint8_t local_id[8];
	uint8_t size;
};

#define STRING_TYPE_NONE							0x0
#define STRING_TYPE_EMPTY							0x1
#define STRING_TYPE_STRING8							0x2
#define STRING_TYPE_UNICODE_REDUCED					0x3
#define STRING_TYPE_UNICODE							0x4

struct TYPED_STRING {
	uint8_t string_type;
	char *pstring;
};

#define PROPERTY_ROW_NO_ERROR						0x00
#define PROGRESS_ROW_WITH_ERROR						0x01

#define PROPERTY_ROW_FLAG_NONE						0x00
#define PROPERTY_ROW_FLAG_FLAGGED					0x01

struct PROPERTY_ROW {
	uint8_t flag;
	void **pppropval;
};

struct PROPROW_SET {
	uint16_t count;
	PROPERTY_ROW *prows;
};

#define TABLE_SORT_ASCEND							0x0
#define TABLE_SORT_DESCEND							0x1
#define TABLE_SORT_MAXIMUM_CATEGORY					0x4
#define TABLE_SORT_MINIMUM_CATEGORY					0x8

struct PROPERTY_PROBLEM {
	uint16_t index;
	uint32_t proptag;
	uint32_t err;

	inline bool operator<(const PROPERTY_PROBLEM &o) const { return index < o.index; }
};

struct PROBLEM_ARRAY {
	uint16_t count;
	PROPERTY_PROBLEM *pproblem;

	inline PROPERTY_PROBLEM *begin() { return pproblem; }
	inline PROPERTY_PROBLEM *end() { return pproblem + count; }
	inline const PROPERTY_PROBLEM *begin() const { return pproblem; }
	inline const PROPERTY_PROBLEM *end() const { return pproblem + count; }
	bool have_index(unsigned int) const;
	PROBLEM_ARRAY &operator+=(PROBLEM_ARRAY &&);
	void emplace_back(unsigned int i, uint32_t tag, uint32_t err) {
		pproblem[count++] = PROPERTY_PROBLEM{static_cast<uint16_t>(i), tag, err};
	}
	void transform(const uint16_t *);
	size_t indexof(uint32_t tag) const;
	inline bool has(uint32_t tag) const { return indexof(tag) != npos; }
	static constexpr size_t npos = -1;
};

struct EMSAB_ENTRYID {
	uint32_t flags;
	uint32_t version; /* should be 0x00000001 */
	uint32_t type;
	char *px500dn;
};

#define DAYOFWEEK_SUNDAY							0x0
#define DAYOFWEEK_MONDAY							0x1
#define DAYOFWEEK_TUESDAY							0x2
#define DAYOFWEEK_WEDNESDAY							0x3
#define DAYOFWEEK_THURSDAY							0x4
#define DAYOFWEEK_FRIDAY							0x5
#define DAYOFWEEK_SATURDAY							0x6

struct LOGON_TIME {
	uint8_t second;
	uint8_t minute;
	uint8_t hour;
	uint8_t day_of_week;
	uint8_t day;
	uint8_t month;
	uint16_t year;
};

struct GHOST_SERVER {
	uint16_t server_count;
	uint16_t cheap_server_count;
	char **ppservers;
};

#define RECIPIENT_ROW_FLAG_RESPONSIBLE				0x0080
#define RECIPIENT_ROW_FLAG_SAME						0x0040
#define RECIPIENT_ROW_FLAG_TRANSMITTABLE			0x0020
#define RECIPIENT_ROW_FLAG_DISPLAY					0x0010
#define RECIPIENT_ROW_FLAG_EMAIL					0x0008
#define RECIPIENT_ROW_FLAG_OUTOFSTANDARD			0x8000
#define RECIPIENT_ROW_FLAG_SIMPLE					0x0400
#define RECIPIENT_ROW_FLAG_UNICODE					0x0200
#define RECIPIENT_ROW_FLAG_NONRICH					0x0100

#define RECIPIENT_ROW_TYPE_NONE						0x0
#define RECIPIENT_ROW_TYPE_X500DN					0x1
#define RECIPIENT_ROW_TYPE_MSMAIL					0x2
#define RECIPIENT_ROW_TYPE_SMTP						0x3
#define RECIPIENT_ROW_TYPE_FAX						0x4
#define RECIPIENT_ROW_TYPE_OFFICE_SYSTEM			0x5
#define RECIPIENT_ROW_TYPE_PERSONAL_DLIST1			0x6
#define RECIPIENT_ROW_TYPE_PERSONAL_DLIST2			0x7

struct RECIPIENT_ROW {
	uint8_t *pprefix_used;
	char *px500dn;
	BINARY *pentry_id;
	BINARY *psearch_key;
	char *paddress_type;
	char *pmail_address;
	char *pdisplay_name;
	char *psimple_name;
	char *ptransmittable_name;
	uint8_t have_display_type, display_type;
	uint16_t flags, count;
	PROPERTY_ROW properties;
};

struct OPENRECIPIENT_ROW {
	uint8_t recipient_type;
	uint16_t cpid;
	uint16_t reserved;
	RECIPIENT_ROW recipient_row;
};

struct MODIFYRECIPIENT_ROW {
	uint32_t row_id;
	uint8_t recipient_type;
	RECIPIENT_ROW *precipient_row;
};

struct READRECIPIENT_ROW {
	uint32_t row_id;
	uint8_t recipient_type;
	uint16_t cpid;
	uint16_t reserved;
	RECIPIENT_ROW recipient_row;
};

struct PERMISSION_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
};

struct PROPIDNAME_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
	PROPERTY_NAME *ppropname;
};

struct MESSAGE_READ_STAT {
	BINARY message_xid;
	uint8_t mark_as_read;
};

#define FAST_SOURCE_OPERATION_COPYTO				0x1
#define FAST_SOURCE_OPERATION_COPYPROPERTIES		0x2
#define FAST_SOURCE_OPERATION_COPYMESSAGES			0x3
#define FAST_SOURCE_OPERATION_COPYFOLDER			0x4

#define FAST_DEST_CONFIG_FLAG_MOVE					0x01

#define TRANSFER_STATUS_ERROR						0x0000
#define TRANSFER_STATUS_PARTIAL						0x0001
#define TRANSFER_STATUS_NOROOM						0x0002
#define TRANSFER_STATUS_DONE						0x0003

#define FAST_COPY_FOLDER_FLAG_MOVE					0x01
#define FAST_COPY_FOLDER_FLAG_COPYSUBFOLDERS		0x10

#define FAST_COPY_MESSAGE_FLAG_MOVE					0x01
#define FAST_COPY_MESSAGE_FLAG_BESTBODY				0x10
#define FAST_COPY_MESSAGE_FLAG_SENDENTRYID			0x20

#define FAST_COPY_TO_FLAG_MOVE						0x00000001
#define FAST_COPY_TO_FLAG_BESTBODY					0x00002000

#define FAST_COPY_PROPERTIES_FLAG_MOVE				0x01

#define SYNC_TYPE_CONTENTS							0x1
#define SYNC_TYPE_HIERARCHY							0x2

#define SEND_OPTIONS_UNICODE						0x1
#define SEND_OPTIONS_USECPID						0x2
#define SEND_OPTIONS_FORUPLOAD						0x3
#define SEND_OPTIONS_RECOVERMODE					0x4
#define SEND_OPTIONS_FORCEUNICODE					0x8
#define SEND_OPTIONS_PARTIAL						0x10
#define SEND_OPTIONS_RESERVED1						0x20
#define SEND_OPTIONS_RESERVED2						0x40

#define SYNC_EXTRA_FLAG_EID							0x00000001
#define SYNC_EXTRA_FLAG_MESSAGESIZE					0x00000002
#define SYNC_EXTRA_FLAG_CN							0x00000004
#define SYNC_EXTRA_FLAG_ORDERBYDELIVERYTIME			0x00000008

#define IMPORT_FLAG_ASSOCIATED						0x10
#define IMPORT_FLAG_FAILONCONFLICT					0x40

#define SYNC_DELETES_FLAG_HIERARCHY					0x01
#define SYNC_DELETES_FLAG_HARDDELETE				0x02

enum notif_type : unsigned int {
	NF_NEW_MAIL        = 0x2,
	NF_OBJECT_CREATED  = 0x4,
	NF_OBJECT_DELETED  = 0x8,
	NF_OBJECT_MODIFIED = 0x10,
	NF_OBJECT_MOVED    = 0x20,
	NF_OBJECT_COPIED   = 0x40,
	NF_SEARCH_COMPLETE = 0x80,

	/* Used only by emsmdb */
	NF_TABLE_MODIFIED  = 0x100,
	NF_EXTENDED        = 0x400,
	NF_HAS_TOTAL       = 0x1000,
	NF_HAS_UNREAD      = 0x2000,
	NF_BY_SEARCH       = 0x4000,
	NF_BY_MESSAGE      = 0x8000,
};

#define TABLE_EVENT_TABLE_CHANGED					0x0001
#define TABLE_EVENT_ROW_ADDED						0x0003
#define TABLE_EVENT_ROW_DELETED						0x0004
#define TABLE_EVENT_ROW_MODIFIED					0x0005
#define TABLE_EVENT_RESTRICTION_CHANGED				0x0007

enum {
	/* List of permanent (not removable) folders */
	PRIVATE_FID_ROOT = 0x01,
	PRIVATE_FID_DEFERRED_ACTION = 0x02,
	PRIVATE_FID_SPOOLER_QUEUE = 0x03,
	PRIVATE_FID_SHORTCUTS = 0x04,
	PRIVATE_FID_FINDER = 0x05,
	PRIVATE_FID_VIEWS = 0x06,
	PRIVATE_FID_COMMON_VIEWS = 0x07, /* Favorites */
	PRIVATE_FID_SCHEDULE = 0x08,
	PRIVATE_FID_IPMSUBTREE = 0x09,
	PRIVATE_FID_SENT_ITEMS = 0x0a,
	PRIVATE_FID_DELETED_ITEMS = 0x0b,
	PRIVATE_FID_OUTBOX = 0x0c,
	PRIVATE_FID_INBOX = 0x0d,
	PRIVATE_FID_DRAFT = 0x0e,
	PRIVATE_FID_CALENDAR = 0x0f,
	PRIVATE_FID_JOURNAL = 0x10,
	PRIVATE_FID_NOTES = 0x11,
	PRIVATE_FID_TASKS = 0x12,
	PRIVATE_FID_CONTACTS = 0x13,
	PRIVATE_FID_QUICKCONTACTS = 0x14,
	PRIVATE_FID_IMCONTACTLIST = 0x15,
	PRIVATE_FID_GALCONTACTS = 0x16,
	PRIVATE_FID_JUNK = 0x17,
	PRIVATE_FID_LOCAL_FREEBUSY = 0x18,
	PRIVATE_FID_SYNC_ISSUES = 0x19,
	PRIVATE_FID_CONFLICTS = 0x1a,
	PRIVATE_FID_LOCAL_FAILURES = 0x1b,
	PRIVATE_FID_SERVER_FAILURES = 0x1c,
	PRIVATE_FID_CONVERSATION_ACTION_SETTINGS = 0x1d,
	PRIVATE_FID_CUSTOM = 0x1e,

	PUBLIC_FID_ROOT = 0x01,
	PUBLIC_FID_IPMSUBTREE = 0x02,
	PUBLIC_FID_NONIPMSUBTREE = 0x03,
	PUBLIC_FID_EFORMSREGISTRY = 0x04,
	PUBLIC_FID_CUSTOM = 0x05,
};

#define RSF_ELID_HEADER								0x0002
#define RSF_ELID_ENTRYID							0x0001
#define ELEMENT_SENTINEL							0x0000

struct PERSISTELEMENT {
	uint16_t element_id;
	BINARY *pentry_id;
};

#define RSF_PID_RSS_SUBSCRIPTION					0x8001
#define RSF_PID_SEND_AND_TRACK						0x8002
#define RSF_PID_TODO_SEARCH							0x8004
#define RSF_PID_CONV_ACTIONS						0x8006
#define RSF_PID_COMBINED_ACTIONS					0x8007
#define RSF_PID_SUGGESTED_CONTACTS					0x8008
#define RSF_PID_CONTACT_SEARCH						0x8009
#define RSF_PID_BUDDYLIST_PDLS						0x800A
#define RSF_PID_BUDDYLIST_CONTACTS					0x800B
#define PERSIST_SENTINEL							0x0000

struct PERSISTDATA {
	uint16_t persist_id;
	PERSISTELEMENT element;
};

struct PERSISTDATA_ARRAY {
	uint8_t count;
	PERSISTDATA **ppitems;
};

/* aggregated permissions for delegation */
#define DELEGATE_PERMISSION_NONE					0x00000000
#define DELEGATE_PERMISSION_REVIEWER				0x00000001
#define DELEGATE_PERMISSION_AUTHOR					0x0000001B
#define DELEGATE_PERMISSION_EDITOR					0x0000007B

struct SYSTEMTIME {
	int16_t year;
	int16_t month;
	int16_t dayofweek;
	int16_t day;
	int16_t hour;
	int16_t minute;
	int16_t second;
	int16_t milliseconds;
};

/* pidLidTimeZoneStruct */
struct TIMEZONESTRUCT {
	int32_t bias;
	int32_t standardbias;
	int32_t daylightbias;
	int16_t standardyear;
	SYSTEMTIME standarddate;
	int16_t daylightyear;
	SYSTEMTIME daylightdate;
};

#define TZRULE_FLAG_RECUR_CURRENT_TZREG				0x0001
#define TZRULE_FLAG_EFFECTIVE_TZREG					0x0002

struct TZRULE {
	uint8_t major; /* 0x02 */
	uint8_t minor; /* 0x01 */
	uint16_t reserved; /* must be 0x003E */
	uint16_t flags;
	int16_t year;
	uint8_t x[14]; /* all zeroes */
	int32_t bias;
	int32_t standardbias;
	int32_t daylightbias;
	SYSTEMTIME standarddate;
	SYSTEMTIME daylightdate;

	inline bool operator<(const TZRULE &o) const { return year < o.year; }
};

struct TIMEZONEDEFINITION {
	uint8_t major; /* 0x02 */
	uint8_t minor; /* 0x01 */
	uint16_t reserved; /* 0x0002 */
	char* keyname;
	uint16_t crules;
	TZRULE *prules;
};

#define PATTERNTYPE_DAY								0x0000
#define PATTERNTYPE_WEEK							0x0001
#define PATTERNTYPE_MONTH							0x0002
#define PATTERNTYPE_MONTHNTH						0x0003
#define PATTERNTYPE_MONTHEND						0x0004
#define PATTERNTYPE_HJMONTH							0x000A
#define PATTERNTYPE_HJMONTHNTH						0x000B
#define PATTERNTYPE_HJMONTHEND						0x000C

namespace week_recur_bit {
static constexpr unsigned int
	sun = 1U << 0,
	mon = 1U << 1,
	tue = 1U << 2,
	wed = 1U << 3,
	thu = 1U << 4,
	fri = 1U << 5,
	sat = 1U << 6;
}

#define RECURRENCENUM_FIRST							0x00000001
#define RECURRENCENUM_SECOND						0x00000002
#define RECURRENCENUM_THIRD							0x00000003
#define RECURRENCENUM_FOURTH						0x00000004
#define RECURRENCENUM_LAST							0x00000005

union PATTERNTYPE_SPECIFIC {
	uint32_t weekrecur, dayofmonth;
	struct {
		uint32_t weekrecur, recurnum;
	} monthnth;
};

#define ENDTYPE_AFTER_DATE							0x00002021
#define ENDTYPE_AFTER_N_OCCURRENCES					0x00002022
#define ENDTYPE_NEVER_END							0x00002023
#define ENDTYPE_NEVER_END1							0xFFFFFFFF

#define FIRSTDOW_SUNDAY								0x00000000
#define FIRSTDOW_MONDAY								0x00000001
#define FIRSTDOW_TUESDAY							0x00000002
#define FIRSTDOW_WEDNESDAY							0x00000003
#define FIRSTDOW_THURSDAY							0x00000004
#define FIRSTDOW_FRIDAY								0x00000005
#define FIRSTDOW_SATURDAY							0x00000006

enum {
	ENDDATE_MISSING        = 0x5ae980df,
	ENDDATE_MISSING_RDELTA = 0x5ae980e1,
};

struct RECURRENCE_PATTERN {
	uint16_t readerversion; /* 0x3004 */
	uint16_t writerversion; /* 0x3004 */
	uint16_t recurfrequency;
	uint16_t patterntype;
	uint16_t calendartype;
	uint32_t firstdatetime;
	uint32_t period;
	uint32_t slidingflag; /* only for scheduling tasks, otherwise 0 */
	PATTERNTYPE_SPECIFIC pts;
	uint32_t endtype;
	uint32_t occurrencecount;
	uint32_t firstdow;
	uint32_t deletedinstancecount;
	uint32_t *pdeletedinstancedates;
	uint32_t modifiedinstancecount;
	uint32_t *pmodifiedinstancedates;
	uint32_t startdate;
	uint32_t enddate; /* if no enddate, should be set to ENDDATE_MISSING */
};

struct EXCEPTIONINFO {
	uint32_t startdatetime;
	uint32_t enddatetime;
	uint32_t originalstartdate;
	uint16_t overrideflags;
	char *subject;
	uint32_t meetingtype;
	uint32_t reminderdelta;
	uint32_t reminderset;
	char *location;
	uint32_t busystatus;
	uint32_t attachment;
	uint32_t subtype;
	uint32_t appointmentcolor;

	inline bool operator<(const EXCEPTIONINFO &o) const
		{ return startdatetime < o.startdatetime; }
};

struct CHANGEHIGHLIGHT {
	uint32_t size;
	uint32_t value;
	uint8_t *preserved;
};

struct EXTENDEDEXCEPTION {
	CHANGEHIGHLIGHT changehighlight;
	uint32_t reservedblockee1size;
	uint8_t *preservedblockee1;
	uint32_t startdatetime;
	uint32_t enddatetime;
	uint32_t originalstartdate;
	char *subject;
	char *location;
	uint32_t reservedblockee2size;
	uint8_t *preservedblockee2;

	inline bool operator<(const EXTENDEDEXCEPTION &o) const
		{ return startdatetime < o.startdatetime; }
};

struct APPOINTMENT_RECUR_PAT {
	RECURRENCE_PATTERN recur_pat;
	uint32_t readerversion2; /* 0x00003006 */
	uint32_t writerversion2; /* SHOULD be 0x00003009, can be 0x00003008 */
	uint32_t starttimeoffset;
	uint32_t endtimeoffset;
	uint16_t exceptioncount; /* same as modifiedinstancecount
								in recurrencepattern */
	EXCEPTIONINFO *pexceptioninfo;
	uint32_t reservedblock1size;
	uint8_t *preservedblock1;
	EXTENDEDEXCEPTION *pextendedexception;
	uint32_t reservedblock2size;
	uint8_t *preservedblock2;
};

/* GOID is not to be confused with GID (MS-OXCPRPT v25 §1.1) */
struct GLOBALOBJECTID {
	FLATUID arrayid; /* SHOULD be EncodedGlobalId */
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint64_t creationtime;
	uint8_t x[8];
	BINARY data;
	bool unparsed;
};

struct EID_ARRAY {
	uint32_t count;
	uint64_t *pids;
	inline uint64_t *begin() { return pids; }
	inline uint64_t *end() { return pids + count; }
	inline const uint64_t *begin() const { return pids; }
	inline const uint64_t *end() const { return pids + count; }
};

using INDEX_ARRAY = PROPTAG_ARRAY;

#define MESSAGE_FORMAT_PLAIN_AND_HTML				0x00100000
#define MESSAGE_FORMAT_HTML_ONLY					0x00080000
#define MESSAGE_FORMAT_PLAIN_ONLY					0x00000000

#define MAX_ATTACHMENT_NUM							200

struct EXTENDED_ERROR {
	uint16_t version;
	uint16_t padding;
	uint32_t errcode;
	LONG_TERM_ID folder_gid;
	LONG_TERM_ID message_gid;
	uint8_t reserved[24];
	BINARY *paux_bytes;
};

using REPLICA_MAPPING = BOOL (*)(BOOL, void *, uint16_t *, GUID *);
using REPLIST_ENUM = void (*)(void *, uint16_t);
using REPLICA_ENUM = void (*)(void *, uint64_t);

struct repl_node {
	repl_node() = default;
	repl_node(uint16_t r) : replid(r) {}
	repl_node(const GUID &g) : replguid(g) {}

	union {
		uint16_t replid;
		GUID replguid{};
	};
	using range_list_t = gromox::range_set<uint64_t>;
	range_list_t range_list; /* GLOBSET */
};

class idset {
	public:
	enum class type : uint8_t {
		id_packed   = 0x41, id_loose   = 0x42,
		guid_packed = 0x81, guid_loose = 0x82,
	};

	idset(idset::type t) : repl_type(t) {}
	static std::unique_ptr<idset> create(idset::type);
	bool packed() const { return static_cast<uint8_t>(repl_type) & 0x1; }

	BOOL register_mapping(void *logon_obj, REPLICA_MAPPING);
	void clear() { repl_list.clear(); }
	bool empty() const { return repl_list.empty(); }
	BOOL append(uint64_t eid);
	BOOL append_range(uint16_t replid, uint64_t low_value, uint64_t high_value);
	void remove(uint64_t eid);
	BOOL concatenate(const idset *set_src);
	bool contains(uint64_t eid) const;
	BINARY *serialize();
	BINARY *serialize_replid() const;
	BINARY *serialize_replguid();
	BOOL deserialize(const BINARY &);
	/* convert from deserialize idset into serialize idset */
	BOOL convert();
	/* get maximum of first range in idset for specified replid */
	BOOL get_repl_first_max(uint16_t replid, uint64_t *eid);
	BOOL enum_replist(void *param, REPLIST_ENUM);
	BOOL enum_repl(uint16_t replid, void *param, REPLICA_ENUM);
	inline const std::vector<repl_node> &get_repl_list() const { return repl_list; }
	void dump() const;
#ifdef COMPILE_DIAG
	inline size_t nelem() const {
		size_t x = 0;
		for (const auto &i : repl_list)
			x += i.range_list.nelem();
		return x;
	}
#endif

	private:
	std::pair<bool, repl_node::range_list_t *> get_range_by_id(uint16_t);

	void *pparam = nullptr;
	REPLICA_MAPPING mapping = nullptr;
	idset::type repl_type = idset::type::id_packed;
	/* If @repl_type is guid_packed, repl_nodes are REPLGUID_NODE. */
	std::vector<repl_node> repl_list;
};
using IDSET = idset;

enum class db_notify_type : uint8_t {
	new_mail = 1, folder_created, message_created, link_created,
	folder_deleted, message_deleted, link_deleted, folder_modified,
	message_modified, folder_moved, message_moved, folder_copied,
	message_copied, search_completed, hiertbl_changed, cttbl_changed,
	srchtbl_changed, hiertbl_row_added, cttbl_row_added, srchtbl_row_added,
	hiertbl_row_deleted, cttbl_row_deleted, srchtbl_row_deleted,
	hiertbl_row_modified, cttbl_row_modified, srchtbl_row_modified,
};

struct DB_NOTIFY {
	enum db_notify_type type;
	void *pdata;
};

struct DB_NOTIFY_NEW_MAIL {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	const char *pmessage_class;
};

struct DB_NOTIFY_FOLDER_CREATED {
	uint64_t folder_id;
	uint64_t parent_id;
	PROPTAG_ARRAY proptags;
};

struct DB_NOTIFY_MESSAGE_CREATED {
	uint64_t folder_id;
	uint64_t message_id;
	PROPTAG_ARRAY proptags;
};

struct DB_NOTIFY_LINK_CREATED {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
	PROPTAG_ARRAY proptags;
};

struct DB_NOTIFY_FOLDER_DELETED {
	uint64_t folder_id;
	uint64_t parent_id;
};

struct DB_NOTIFY_MESSAGE_DELETED {
	uint64_t folder_id;
	uint64_t message_id;
};
	
struct DB_NOTIFY_LINK_DELETED {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
};

struct DB_NOTIFY_FOLDER_MODIFIED {
	uint64_t folder_id;
	uint64_t parent_id;
	uint32_t *ptotal;
	uint32_t *punread;
	PROPTAG_ARRAY proptags;
};
	
struct DB_NOTIFY_MESSAGE_MODIFIED {
	uint64_t folder_id;
	uint64_t message_id;
	PROPTAG_ARRAY proptags;
};

struct DB_NOTIFY_FOLDER_MVCP {
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t old_folder_id;
	uint64_t old_parent_id;
};

struct DB_NOTIFY_MESSAGE_MVCP {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t old_folder_id;
	uint64_t old_message_id;
};

struct DB_NOTIFY_SEARCH_COMPLETED {
	uint64_t folder_id;
};

struct DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED {
	uint64_t row_folder_id;
	uint64_t after_folder_id;
};
using DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED = DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED;

struct DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED {
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint64_t row_instance;
	uint64_t after_folder_id;
	uint64_t after_row_id;
	uint64_t after_instance;
};
using DB_NOTIFY_CONTENT_TABLE_ROW_ADDED = DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED;

struct DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED {
	uint64_t row_folder_id;
};

struct DB_NOTIFY_CONTENT_TABLE_ROW_DELETED {
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint64_t row_instance;
};

#define LOGON_FLAG_PRIVATE							0x1
#define LOGON_FLAG_UNDER_COVER						0x2
#define LOGON_FLAG_GHOSTED							0x4
#define LOGON_FLAG_SPI_PROCESS						0x8

#define LOGON_OPEN_FLAG_USE_ADMIN_PRIVILEGE			0x1
#define LOGON_OPEN_FLAG_PUBLIC						0x2
#define LOGON_OPEN_FLAG_HOME_LOGON					0x4
#define LOGON_OPEN_FLAG_TAKE_OWNERSHIP				0x8
#define LOGON_OPEN_FLAG_ALTERNATE_SERVER			0x100
#define LOGON_OPEN_FLAG_IGNORE_HOME_MDB				0x200
#define LOGON_OPEN_FLAG_NO_MAIL						0x400
#define LOGON_OPEN_FLAG_USE_PER_MDB_REPLID_MAPPING	0x01000000
#define LOGON_OPEN_FLAG_SUPPORT_PROGRESS			0x20000000

#define RESPONSE_FLAG_RESERVED						0x1
#define RESPONSE_FLAG_OWNERRIGHT					0x2
#define RESPONSE_FLAG_SENDASRIGHT					0x4
#define RESPONSE_FLAG_OOF							0x10

#define STORE_STAT_HAS_SEARCHES						0x01000000

#define FOLDER_FLAGS_IPM							0x00000001
#define FOLDER_FLAGS_SEARCH							0x00000002
#define FOLDER_FLAGS_NORMAL							0x00000004
#define FOLDER_FLAGS_RULES							0x00000008

#define SEARCH_STATUS_NOT_INITIALIZED				0x00000000

/* ROPs share only few MAPI bits (MAPI_DEFERREDERRORS) */
#define TABLE_FLAG_ASSOCIATED						0x2
#define TABLE_FLAG_DEPTH							0x4
#define TABLE_FLAG_NONOTIFICATIONS					0x10
#define TABLE_FLAG_SOFTDELETES						0x20
#define TABLE_FLAG_USEUNICODE						0x40
#define TABLE_FLAG_SUPPRESSNOTIFICATIONS			0x80
#define TABLE_FLAG_CONVERSATIONMEMBERS				0x80

#define TABLE_FLAG_TBL_SYNC							0x0
#define TABLE_FLAG_TBL_ASYNC						0x1

enum {
	TBLSTAT_COMPLETE       = 0x0,
	TBLSTAT_SORTING        = 0x9,
	TBLSTAT_SORT_ERROR     = 0xA,
	TBLSTAT_SETTING_COLS   = 0xB,
	TBLSTAT_SETCOL_ERROR   = 0xD,
	TBLSTAT_RESTRICTING    = 0xE,
	TBLSTAT_RESTRICT_ERROR = 0xF,
};

#define QUERY_ROWS_FLAGS_ADVANCE					0x0
#define QUERY_ROWS_FLAGS_NOADVANCE					0x1
#define QUERY_ROWS_FLAGS_ENABLEPACKEDBUFFERS		0x2

#define FIND_ROW_FLAG_FORWARD						0x0
#define FIND_ROW_FLAG_BACKWARD						0x1

#define ACCESS_LEVEL_READ_ONLY						0x00000000
#define ACCESS_LEVEL_MODIFY							0x00000001

#define SAVE_FLAG_KEEPOPENREADONLY					0x01
#define SAVE_FLAG_KEEPOPENREADWRITE					0x02
#define SAVE_FLAG_FORCESAVE							0x04
#define SAVE_FLAG_DELAYEDCALL						0x08

#define RESOLVE_METHOD_DEFAULT						0x00000000
#define RESOLVE_METHOD_LAST_WRITER_WINS				0x00000001
#define RESOLVE_METHOD_NO_CONFLICT_NOTIFICATION		0x00000002

enum {
	rfDefault             = 0x0U,
	rfSuppressReceipt     = 0x1U,
	rfClearReadFlag       = 0x4U,
	rfReserved            = 0xAU,
	rfGenerateReceiptOnly = 0x10U,
	rfClearNotifyRead     = 0x20U,
	rfClearNotifyUnread   = 0x40U,
};

#define LOCK_STAT_1STLOCK							0x0
#define LOCK_STAT_1STUNLOCK							0x1
#define LOCK_STAT_1STFINISHED						0x2

#define NATIVE_BODY_UNDEFINED						0
#define NATIVE_BODY_PLAIN							1
#define NATIVE_BODY_RTF								2
#define NATIVE_BODY_HTML							3
#define NATIVE_BODY_CLEAR_SIGNED					4

#define QUERY_FLAG_NOSTRINGS						0x01
#define QUERY_FLAG_NOIDS							0x02

#define LOCK_FLAG_RDONLY_FOR_OTHERS					0x00000001

enum {
	/* First 8 bits used to transport table flags specified by OXCRPC. */
	PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY = 0x2U,
	/* Gromox-specific: */
	PERMISSIONS_TABLE_FLAG_ROPFILTER       = 0x100U,
};

#define MODIFY_PERMISSIONS_FLAG_REPLACEROWS			0x01
#define MODIFY_PERMISSIONS_FLAG_INCLUDEFREEBUSY		0x02

#define MODIFY_RULES_FLAG_REPLACE					0x01

#define RULES_TABLE_FLAG_UNICODE					0x40
#define ATTACHMENT_NUM_INVALID						0xFFFFFFFF

/* Assigned values for exchange.sqlite3:configurations.config_id */
enum sqlite_config_id {
	CONFIG_ID_MAILBOX_GUID = 1,
	CONFIG_ID_CURRENT_EID = 2,
	CONFIG_ID_MAXIMUM_EID = 3,
	CONFIG_ID_LAST_CHANGE_NUMBER = 4,
	CONFIG_ID_LAST_ARTICLE_NUMBER = 5,
	CONFIG_ID_LAST_CID = 6,
	CONFIG_ID_SEARCH_STATE = 7,
	CONFIG_ID_DEFAULT_PERMISSION = 8,
	CONFIG_ID_ANONYMOUS_PERMISSION = 9,
	CONFIG_ID_SCHEMAVERSION = 10,
};

#define ALLOCATED_EID_RANGE							0x10000
#define CHANGE_NUMBER_BEGIN							0x800000000000LL

using GET_PROPIDS = std::function<BOOL(const PROPNAME_ARRAY *, PROPID_ARRAY *)>;
/* if it returns TRUE, PROPERTY_NAME must be available */
using GET_PROPNAME = std::function<BOOL (uint16_t, PROPERTY_NAME **)>;
using GET_USER_IDS = BOOL (*)(const char *, unsigned int *, unsigned int *, enum display_type *);
using GET_USERNAME = BOOL (*)(unsigned int, char *, size_t);
using USERNAME_TO_ENTRYID = BOOL (*)(const char *, const char *, BINARY *, enum display_type *);
using EXT_BUFFER_ALLOC = void *(*)(size_t);
using ENTRYID_TO_USERNAME = BOOL (*)(const BINARY *, EXT_BUFFER_ALLOC, char *, size_t);
using ESSDN_TO_USERNAME = BOOL (*)(const char *, char *, size_t);
