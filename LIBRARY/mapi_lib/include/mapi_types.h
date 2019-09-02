#ifndef _H_MAPI_TYPES_
#define _H_MAPI_TYPES_
#include "proptags.h"
#include "common_types.h"
#include "double_list.h"


#define PROPVAL_TYPE_UNSPECIFIED					0x0000
#define PROPVAL_TYPE_SHORT							0x0002
#define PROPVAL_TYPE_LONG							0x0003
#define PROPVAL_TYPE_FLOAT							0x0004
#define PROPVAL_TYPE_DOUBLE							0x0005
#define PROPVAL_TYPE_CURRENCY						0x0006
#define PROPVAL_TYPE_FLOATINGTIME					0x0007
#define PROPVAL_TYPE_ERROR							0x000a
#define PROPVAL_TYPE_BYTE							0x000b
#define PROPVAL_TYPE_OBJECT							0x000d
#define PROPVAL_TYPE_LONGLONG						0x0014
#define PROPVAL_TYPE_STRING							0x001e
#define PROPVAL_TYPE_WSTRING						0x001f
#define PROPVAL_TYPE_FILETIME						0x0040
#define PROPVAL_TYPE_GUID							0x0048
#define PROPVAL_TYPE_SVREID							0x00fb
#define PROPVAL_TYPE_RESTRICTION					0x00fd
#define PROPVAL_TYPE_RULE							0x00fe
#define PROPVAL_TYPE_BINARY							0x0102
#define PROPVAL_TYPE_SHORT_ARRAY					0x1002
#define PROPVAL_TYPE_LONG_ARRAY						0x1003
#define PROPVAL_TYPE_LONGLONG_ARRAY					0x1014
#define PROPVAL_TYPE_STRING_ARRAY					0x101e
#define PROPVAL_TYPE_WSTRING_ARRAY					0x101f
#define PROPVAL_TYPE_GUID_ARRAY						0x1048
#define PROPVAL_TYPE_BINARY_ARRAY					0x1102

typedef struct _BINARY {
	uint32_t cb;
	uint8_t *pb;
} BINARY;

typedef struct _BINARY_ARRAY {
	uint32_t count;
	BINARY *pbin;
} BINARY_ARRAY;

typedef struct _STRING_ARRAY {
	uint32_t count;
	char **ppstr;
} STRING_ARRAY;

typedef struct _SHORT_ARRAY {
	uint32_t count;
	uint16_t *ps;
} SHORT_ARRAY;

typedef struct _LONG_ARRAY {
	uint32_t count;
	uint32_t *pl;
} LONG_ARRAY;

typedef struct _LONGLONG_ARRAY {
	uint32_t count;
	uint64_t *pll;
} LONGLONG_ARRAY;

typedef struct _GUID_ARRAY {
	uint32_t count;
	GUID *pguid;
} GUID_ARRAY;

#define KIND_LID									0x00
#define KIND_NAME									0x01
#define KIND_NONE									0xFF

typedef struct _PROPERTY_NAME {
	uint8_t kind;
	GUID guid;
	uint32_t *plid;
	char *pname;
} PROPERTY_NAME;

typedef struct _TAGGED_PROPVAL {
	uint32_t proptag;
	void *pvalue;
} TAGGED_PROPVAL;

#define RESTRICTION_TYPE_AND						0x00
#define RESTRICTION_TYPE_OR							0x01
#define RESTRICTION_TYPE_NOT						0x02
#define RESTRICTION_TYPE_CONTENT					0x03
#define RESTRICTION_TYPE_PROPERTY					0x04
#define RESTRICTION_TYPE_PROPCOMPARE				0x05
#define RESTRICTION_TYPE_BITMASK					0x06
#define RESTRICTION_TYPE_SIZE						0x07
#define RESTRICTION_TYPE_EXIST						0x08
#define RESTRICTION_TYPE_SUBOBJ						0x09
#define RESTRICTION_TYPE_COMMENT					0x0a
#define RESTRICTION_TYPE_COUNT						0x0b
#define RESTRICTION_TYPE_NULL						0xff

typedef struct _RESTRICTION {
	uint8_t rt;
	void *pres;
} RESTRICTION;

typedef struct _RESTRICTION_AND_OR {
	uint32_t count;
	RESTRICTION *pres;
} RESTRICTION_AND_OR;

typedef struct _RESTRICTION_NOT {
	RESTRICTION res;
} RESTRICTION_NOT;

#define FUZZY_LEVEL_FULLSTRING						0x00000
#define FUZZY_LEVEL_SUBSTRING						0x00001
#define FUZZY_LEVEL_PREFIX							0x00002
#define FUZZY_LEVEL_IGNORECASE						0x10000
#define FUZZY_LEVEL_IGNORENONSPACE					0x20000
#define FUZZY_LEVEL_LOOSE							0x40000

typedef struct _RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
} RESTRICTION_CONTENT;

#define RELOP_LT									0x00
#define RELOP_LE									0x01
#define RELOP_GT									0x02
#define RELOP_GE									0x03
#define RELOP_EQ									0x04
#define RELOP_NE									0x05
#define RELOP_MEMBER_OF_DL							0x64

typedef struct _RESTRICTION_PROPERTY {
	uint8_t relop;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
} RESTRICTION_PROPERTY;

typedef struct _RESTRICTION_PROPCOMPARE {
	uint8_t relop;
	uint32_t proptag1;
	uint32_t proptag2;
} RESTRICTION_PROPCOMPARE;

#define BITMASK_RELOP_EQZ							0x0
#define BITMASK_RELOP_NEZ							0x1

typedef struct _RESTRICTION_BITMASK {
	uint8_t bitmask_relop;
	uint32_t proptag;
	uint32_t mask;
} RESTRICTION_BITMASK;

typedef struct _RESTRICTION_SIZE {
	uint8_t relop;
	uint32_t proptag;
	uint32_t size;
} RESTRICTION_SIZE;

typedef struct _RESTRICTION_EXIST {
	uint32_t proptag;
} RESTRICTION_EXIST;

typedef struct _RESTRICTION_SUBOBJ {
	uint32_t subobject;
	RESTRICTION res;
} RESTRICTION_SUBOBJ;

typedef struct _RESTRICTION_COMMENT {
	uint8_t count;
	TAGGED_PROPVAL *ppropval;
	RESTRICTION *pres;
} RESTRICTION_COMMENT;

typedef struct _RESTRICTION_COUNT {
	uint32_t count;
	RESTRICTION sub_res;
} RESTRICTION_COUNT;

typedef struct _SVREID {
	BINARY *pbin;
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t instance;
} SVREID;

typedef struct _STORE_ENTRYID {
	uint32_t flags;
	 /* 38.A1.BB.10.05.E5.10.1A.A1.BB.08.00.2B.2A.56.C2 */
	uint8_t provider_uid[16];
	uint8_t version;
	uint8_t flag;
	/* emsmdb.dll
	   45.4D.53.4D.44.42.2E.44.4C.4C.00.00.00.00
	*/ 
	uint8_t dll_name[14];
	uint32_t wrapped_flags;
	/* Mailbox Store object:
		1B.55.FA.20.AA.66.11.CD.9B.C8.00.AA.00.2F.C4.5A
	   Public folder Store object:
		1C.83.02.10.AA.66.11.CD.9B.C8.00.AA.00.2F.C4.5A
	*/
	uint8_t wrapped_provider_uid[16];
	uint32_t wrapped_type;
	char *pserver_name;
	char *pmailbox_dn;
} STORE_ENTRYID;

#define EITLT_PRIVATE_FOLDER						0x0001
#define EITLT_PUBLIC_FOLDER							0x0003
#define EITLT_WACKY_FOLDER							0x0005
#define EITLT_PRIVATE_MESSAGE						0x0007
#define EITLT_PUBLIC_MESSAGE						0x0009
#define EITLT_WACKY_MESSAGE							0x000b
#define EITLT_PUBLIC_FOLDER_BY_NAME					0x000c

typedef struct _FOLDER_ENTRYID {
	uint32_t flags;
	uint8_t provider_uid[16];
	uint16_t folder_type;
	GUID database_guid;
	uint8_t global_counter[6];
	uint8_t pad[2];
} FOLDER_ENTRYID;

typedef struct _MESSAGE_ENTRYID {
	uint32_t flags;
	uint8_t provider_uid[16];
	uint16_t message_type;
	GUID folder_database_guid;
	uint8_t folder_global_counter[6];
	uint8_t pad1[2];
	GUID message_database_guid;
	uint8_t message_global_counter[6];
	uint8_t pad2[2];
} MESSAGE_ENTRYID;

typedef struct _MOVECOPY_ACTION {
	uint8_t same_store;
	STORE_ENTRYID *pstore_eid;
	void *pfolder_eid; /* SVREID or BINARY */
} MOVECOPY_ACTION;

typedef struct _EXT_MOVECOPY_ACTION {
	FOLDER_ENTRYID folder_eid;
} EXT_MOVECOPY_ACTION;

/* reply or OOF action */
typedef struct _REPLY_ACTION {
	uint64_t template_folder_id;
	uint64_t template_message_id;
	GUID template_guid;
} REPLY_ACTION;

typedef struct _EXT_REPLY_ACTION {
	MESSAGE_ENTRYID message_eid;
	GUID template_guid;
} EXT_REPLY_ACTION;

#define BOUNCE_CODE_MESSAGE_TOO_LARGE				0x0000000d
#define BOUNCE_CODE_MESSAGE_NOT_DISPLAYED			0x0000001f
#define BOUNCE_CODE_MESSAGE_DENIED					0x00000026

typedef struct _RECIPIENT_BLOCK {
	uint8_t reserved;
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
} RECIPIENT_BLOCK;

typedef struct _FORWARDDELEGATE_ACTION {
	uint16_t count;
	RECIPIENT_BLOCK *pblock;
} FORWARDDELEGATE_ACTION;

typedef struct _EXT_RECIPIENT_BLOCK {
	uint8_t reserved;
	uint32_t count;
	TAGGED_PROPVAL *ppropval;
} EXT_RECIPIENT_BLOCK;

typedef struct _EXT_FORWARDDELEGATE_ACTION {
	uint32_t count;
	EXT_RECIPIENT_BLOCK *pblock;
} EXT_FORWARDDELEGATE_ACTION;

#define ACTION_TYPE_OP_MOVE							0x1
#define ACTION_TYPE_OP_COPY							0x2
#define ACTION_TYPE_OP_REPLY						0x3
#define ACTION_TYPE_OP_OOF_REPLY					0x4
#define ACTION_TYPE_OP_DEFER_ACTION					0x5
#define ACTION_TYPE_OP_BOUNCE						0x6
#define ACTION_TYPE_OP_FORWARD						0x7
#define ACTION_TYPE_OP_DELEGATE						0x8
#define ACTION_TYPE_OP_TAG							0x9
#define ACTION_TYPE_OP_DELETE						0xA
#define ACTION_TYPE_OP_MARK_AS_READ					0xB

#define ACTION_FLAVOR_PR							0x00000001
#define ACTION_FLAVOR_NC							0x00000002
#define ACTION_FLAVOR_AT							0x00000004
#define ACTION_FLAVOR_TM							0x00000008

#define ACTION_FLAVOR_NS							0x00000001
#define ACTION_FLAVOR_ST							0x00000002

typedef struct _ACTION_BLOCK {
	uint16_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
} ACTION_BLOCK;

typedef struct _EXT_ACTION_BLOCK {
	uint32_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
} EXT_ACTION_BLOCK;

typedef struct _RULE_ACTIONS {
	uint16_t count;
	ACTION_BLOCK *pblock;
} RULE_ACTIONS;

typedef struct _EXT_RULE_ACTIONS {
	uint32_t count;
	EXT_ACTION_BLOCK *pblock;
} EXT_RULE_ACTIONS;

#define RULE_STATE_ENABLED							0x00000001
#define RULE_STATE_ERROR							0x00000002
#define RULE_STATE_ONLY_WHEN_OOF					0x00000004
#define RULE_STATE_KEEP_OOF_HIST					0x00000008
#define RULE_STATE_EXIT_LEVEL						0x00000010
#define RULE_STATE_SKIP_IF_SCL_IS_SAFE				0x00000020
#define RULE_STATE_PARSE_ERROR						0x00000040

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

typedef struct _NAMEDPROPERTY_INFOMATION {
	uint16_t count;
	uint16_t *ppropid;
	PROPERTY_NAME *ppropname;
} NAMEDPROPERTY_INFOMATION;

typedef struct _TPROPVAL_ARRAY {
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
} TPROPVAL_ARRAY;

typedef struct _TARRAY_SET {
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
} TARRAY_SET;

#define FLAGGED_PROPVAL_FLAG_AVAILABLE				0x0
#define FLAGGED_PROPVAL_FLAG_UNAVAILABLE			0x1
#define FLAGGED_PROPVAL_FLAG_ERROR					0xA

typedef struct _FLAGGED_PROPVAL {
	uint8_t flag;
	void *pvalue;
} FLAGGED_PROPVAL;

typedef struct _PROPTAG_ARRAY {
	uint16_t count;
	uint32_t *pproptag;
} PROPTAG_ARRAY;

typedef struct _TYPED_PROPVAL {
	uint16_t type;
	void *pvalue;
} TYPED_PROPVAL;

typedef struct _LONG_TERM_ID {
	GUID guid;
	uint8_t global_counter[6];
	uint16_t padding;
} LONG_TERM_ID;

typedef struct _LONG_TERM_ID_ARRAY {
	uint16_t count;
	LONG_TERM_ID *pids;
} LONG_TERM_ID_ARRAY;

typedef struct _LONG_TERM_ID_RANGE {
	LONG_TERM_ID min;
	LONG_TERM_ID max;
} LONG_TERM_ID_RANGE;

typedef struct _XID {
	GUID guid;
	uint8_t local_id[8];
} XID;

typedef struct _SIZED_XID {
	uint8_t size;
	XID xid;
} SIZED_XID;

#define STRING_TYPE_NONE							0x0
#define STRING_TYPE_EMPTY							0x1
#define STRING_TYPE_STRING8							0x2
#define STRING_TYPE_UNICODE_REDUCED					0x3
#define STRING_TYPE_UNICODE							0x4

typedef struct _TYPED_STRING {
	uint8_t string_type;
	char *pstring;
} TYPED_STRING;

#define PROPERTY_ROW_NO_ERROR						0x00
#define PROGRESS_ROW_WITH_ERROR						0x01

#define PROPERTY_ROW_FLAG_NONE						0x00
#define PROPERTY_ROW_FLAG_FLAGGED					0x01

typedef struct _PROPERTY_ROW {
	uint8_t flag;
	void **pppropval;
} PROPERTY_ROW;

typedef struct _PROPROW_SET {
	uint16_t count;
	PROPERTY_ROW *prows;
} PROPROW_SET;

#define TABLE_SORT_ASCEND							0x0
#define TABLE_SORT_DESCEND							0x1
#define TABLE_SORT_MAXIMUM_CATEGORY					0x4
#define TABLE_SORT_MINIMUM_CATEGORY					0x8

typedef struct SORT_ORDER {
	uint16_t type; /* pay attention to the 0x2000 bit!!! */
	uint16_t propid;
	uint8_t table_sort;
} SORT_ORDER;

#define MAXIMUM_SORT_COUNT							8

typedef struct _SORTORDER_SET {
	uint16_t count;
	uint16_t ccategories;
	uint16_t cexpanded;
	SORT_ORDER *psort;
} SORTORDER_SET;

#define PS_PUBLIC_STRINGS							1
#define PSETID_COMMON								2
#define PSETID_ADDRESS								3
#define PS_INTERNET_HEADERS							4
#define PSETID_APPOINTMENT							5
#define PSETID_MEETING								6
#define PSETID_LOG									7
#define PSETID_MESSAGING							8
#define PSETID_NOTE									9
#define PSETID_POSTRSS								10
#define PSETID_TASK									11
#define PSETID_UNIFIEDMESSAGING						12
#define PSETID_AIRSYNC								13
#define PSETID_SHARING								14
#define PSETID_XMLEXTRACTEDENTITIES					15
#define PS_MAPI										16
#define PSETID_ATTACHMENT							17

typedef struct _PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
} PROPNAME_ARRAY;

typedef struct _PROPID_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
} PROPID_ARRAY;

typedef struct _PROPERTY_PROBLEM {
	uint16_t index;
	uint32_t proptag;
	uint32_t err;
} PROPERTY_PROBLEM;

typedef struct _PROBLEM_ARRAY {
	uint16_t count;
	PROPERTY_PROBLEM *pproblem;
} PROBLEM_ARRAY;

#define RULE_DATA_FLAG_ADD_ROW						0x01
#define RULE_DATA_FLAG_MODIFY_ROW					0x02
#define RULE_DATA_FLAG_REMOVE_ROW					0x04

typedef struct _RULE_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
} RULE_DATA;

#define PROVIDER_UID_ADDRESS_BOOK					1
#define PROVIDER_UID_PUBLIC							2
#define PROVIDER_UID_ONE_OFF						3
#define PROVIDER_UID_STORE							4
#define PROVIDER_UID_WRAPPED_PRIVATE				5
#define PROVIDER_UID_WRAPPED_PUBLIC					6

#define ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER			0x00000000
#define ADDRESSBOOK_ENTRYID_TYPE_DLIST				0x00000001
#define ADDRESSBOOK_ENTRYID_TYPE_BULLETIN			0x00000002
#define ADDRESSBOOK_ENTRYID_TYPE_PUBLIC_FOLDER		0x00000002
#define ADDRESSBOOK_ENTRYID_TYPE_AUTO_MAILBOX		0x00000003
#define ADDRESSBOOK_ENTRYID_TYPE_ORG_MAILBOX		0x00000004
#define ADDRESSBOOK_ENTRYID_TYPE_PRIVATE_DLIST		0x00000005
#define ADDRESSBOOK_ENTRYID_TYPE_REMOTE_USER		0x00000006
#define ADDRESSBOOK_ENTRYID_TYPE_CONTAINER			0x00000100
#define ADDRESSBOOK_ENTRYID_TYPE_TEMPLATE			0x00000101
#define ADDRESSBOOK_ENTRYID_TYPE_ONE_OFF_USER		0x00000102
#define ADDRESSBOOK_ENTRYID_TYPE_SEARCH				0x00000200

typedef struct _ADDRESSBOOK_ENTRYID {
	uint32_t flags;
	 /* DC.A7.40.C8.C0.42.10.1A.B4.B9.08.00.2B.2F.E1.82 */
	uint8_t provider_uid[16];
	uint32_t version; /* should be 0x00000001 */
	uint32_t type;
	char *px500dn;
} ADDRESSBOOK_ENTRYID;


#define CTRL_FLAG_BINHEX						0x0000
#define CTRL_FLAG_UUENCODE						0x0020
#define CTRL_FLAG_APPLESINGLE					0x0040
#define CTRL_FLAG_APPLEDOUBLE					0x0060

#define CTRL_FLAG_TEXTONLY						0x0006
#define CTRL_FLAG_HTMLONLY						0x000E
#define CTRL_FLAG_TEXTANDHTML					0x0016

#define CTRL_FLAG_NORICH						0x0001
#define CTRL_FLAG_UNICODE						0x8000
#define CTRL_FLAG_DONTLOOKUP					0x1000

typedef struct _ONEOFF_ENTRYID {
	uint32_t flags;
	 /* 81.2B.1F.A4.BE.A3.10.19.9D.6E.00.DD.01.0F.54.02 */
	uint8_t provider_uid[16];
	uint16_t version; /* should be 0x0000 */
	uint16_t ctrl_flags;
	char *pdisplay_name;
	char *paddress_type;
	char *pmail_address;
} ONEOFF_ENTRYID;

typedef struct _ONEOFF_ARRAY {
	uint32_t count;
	ONEOFF_ENTRYID *pentry_id;
} ONEOFF_ARRAY;

#define DAYOFWEEK_SUNDAY							0x0
#define DAYOFWEEK_MONDAY							0x1
#define DAYOFWEEK_TUESDAY							0x2
#define DAYOFWEEK_WEDNESDAY							0x3
#define DAYOFWEEK_THURSDAY							0x4
#define DAYOFWEEK_FRIDAY							0x5
#define DAYOFWEEK_SATURDAY							0x6

typedef struct _LOGON_TIME {
	uint8_t second;
	uint8_t minute;
	uint8_t hour;
	uint8_t day_of_week;
	uint8_t day;
	uint8_t month;
	uint16_t year;
} LOGON_TIME;

typedef struct _GHOST_SERVER {
	uint16_t server_count;
	uint16_t cheap_server_count;
	char **ppservers;
} GHOST_SERVER;

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

#define DISPLAY_TYPE_MAILUSER						0x0
#define DISPLAY_TYPE_DISTLIST						0x1
#define DISPLAY_TYPE_FORUM							0x2
#define DISPLAY_TYPE_AGENT							0x3
#define DISPLAY_TYPE_ORGANIZATION					0x4
#define DISPLAY_TYPE_PRIVATE_DISTLIST				0x5
#define DISPLAY_TYPE_REMOTE_MAILUSER				0x6
#define DISPLAY_TYPE_ROOM							0x7
#define DISPLAY_TYPE_EQUIPMENT						0x8
#define DISPLAY_TYPE_SEC_DISTLIST					0x9
#define DISPLAY_TYPE_CONTAINER						0x100
#define DISPLAY_TYPE_TEMPLATE						0x101
#define DISPLAY_TYPE_ADDRESS_TEMPLATE				0x102
#define DISPLAY_TYPE_SEARCH							0x200

#define OBJECT_STORE								0x00000001
#define OBJECT_ADDRESSBOOK							0x00000002
#define OBJECT_FOLDER								0x00000003
#define OBJECT_ABCONTAINER							0x00000004
#define OBJECT_MESSAGE								0x00000005
#define OBJECT_USER									0x00000006
#define OBJECT_ATTACHMENT							0x00000007
#define OBJECT_DLIST								0x00000008


typedef struct _RECIPIENT_ROW {
	uint16_t flags;
	uint8_t *pprefix_used;
	uint8_t *pdisplay_type;
	char *px500dn;
	BINARY *pentry_id;
	BINARY *psearch_key;
	char *paddress_type;
	char *pmail_address;
	char *pdisplay_name;
	char *psimple_name;
	char *ptransmittable_name;
	uint16_t count;
	PROPERTY_ROW properties;
} RECIPIENT_ROW;

#define CP_USASCII									0x04E4
#define CP_UNICODE									0x04B0
#define CP_JAUTODETECT								0xC6F4
#define CP_KAUTODETECT								0xC705
#define CP_ISO2022JPESC								0xC42D
#define CP_ISO2022JPSIO								0xC42E

#define RECIPIENT_TYPE_NONE							0x00000000
#define RECIPIENT_TYPE_TO							0x00000001
#define RECIPIENT_TYPE_CC							0x00000002
#define RECIPIENT_TYPE_BCC							0x00000003

#define RECIPIENT_TYPE_NEED_RESEND					0x10000000
#define RECIPIENT_TYPE_NOT_NEED_RESEND				0x80000000

typedef struct _OPENRECIPIENT_ROW {
	uint8_t recipient_type;
	uint16_t cpid;
	uint16_t reserved;
	RECIPIENT_ROW recipient_row;
} OPENRECIPIENT_ROW;

typedef struct _MODIFYRECIPIENT_ROW {
	uint32_t row_id;
	uint8_t recipient_type;
	RECIPIENT_ROW *precipient_row;
} MODIFYRECIPIENT_ROW;

typedef struct _READRECIPIENT_ROW {
	uint32_t row_id;
	uint8_t recipient_type;
	uint16_t cpid;
	uint16_t reserved;
	RECIPIENT_ROW recipient_row;
} READRECIPIENT_ROW;

#define PERMISSION_DATA_FLAG_ADD_ROW				0x01
#define PERMISSION_DATA_FLAG_MODIFY_ROW				0x02
#define PERMISSION_DATA_FLAG_REMOVE_ROW				0x04

typedef struct _PERMISSION_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
} PERMISSION_DATA;

typedef struct _PROPIDNAME_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
	PROPERTY_NAME *ppropname;
} PROPIDNAME_ARRAY;

typedef struct _MESSAGE_READ_STAT {
	BINARY message_xid;
	uint8_t mark_as_read;
} MESSAGE_READ_STAT;

/* Folders Markers [MS-OXCFXICS] - 2.2.4.1.4 */
#define STARTTOPFLD								0x40090003
#define STARTSUBFLD								0x400A0003
#define ENDFOLDER								0x400B0003

/* Messages and their parts Markers [MS-OXCFXICS] - 2.2.4.1.4 */
#define STARTMESSAGE							0x400C0003
#define ENDMESSAGE								0x400D0003
#define STARTFAIMSG								0x40100003
#define STARTEMBED								0x40010003
#define ENDEMBED								0x40020003
#define STARTRECIP								0x40030003
#define ENDTORECIP								0x40040003
#define NEWATTACH								0X40000003
#define ENDATTACH								0x400E0003

/* Synchronization method Markers [MS-OXCFXICS] - 2.2.4.1.4 */
#define INCRSYNCCHG								0x40120003
#define INCRSYNCCHGPARTIAL						0x407D0003
#define INCRSYNCDEL								0x40130003
#define INCRSYNCEND								0x40140003
#define INCRSYNCREAD							0x402F0003
#define INCRSYNCSTATEBEGIN						0x403A0003
#define INCRSYNCSTATEEND						0x403B0003
#define INCRSYNCPROGRESSMODE					0x4074000B
#define INCRSYNCPROGRESSPERMSG					0x4075000B
#define INCRSYNCMESSAGE							0x40150003
#define INCRSYNCGROUPINFO						0x407B0102

/* Special */
#define FXERRORINFO								0x40180003

/* Meta-Properties [MS-OXCFXICS] - 2.2.4.1.5 */
#define META_TAG_FXDELPROP						0x40160003
#define META_TAG_ECWARNING						0x400F0003
#define META_TAG_NEWFXFOLDER					0x40110102
#define META_TAG_INCRSYNCGROUPID				0x407C0003
#define META_TAG_INCREMENTALSYNCMESSAGEPARTIAL	0x407A0003
#define META_TAG_DNPREFIX						0x4008001E

/* ICS State Properties [MS-OXCFXICS] - 2.2.1.1 */
#define META_TAG_IDSETGIVEN						0x40170003
#define META_TAG_IDSETGIVEN1					0x40170102
#define META_TAG_CNSETSEEN						0x67960102
#define META_TAG_CNSETSEENFAI					0x67DA0102
#define META_TAG_CNSETREAD						0x67D20102

/* Meta-Properties for Encoding Differences in Replica Content
   [MS-OXCFXICS] - 2.2.1.3 */
#define META_TAG_IDSETDELETED					0x67E50102
#define META_TAG_IDSETNOLONGERINSCOPE			0x40210102
#define META_TAG_IDSETEXPIRED					0x67930102
#define META_TAG_IDSETREAD						0x402D0102
#define META_TAG_IDSETUNREAD					0x402E0102

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

#define SEND_OPTION_UNICODE							0x01
#define SEND_OPTION_USECPID							0x02
#define SEND_OPTION_FORUPLOAD						0x03
#define SEND_OPTION_RECOVERMODE						0x04
#define SEND_OPTION_FORCEUNICODE					0x08
#define SEND_OPTION_PARTIALITEM						0x10

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

#define SYNC_FLAG_UNICODE							0x1
#define SYNC_FLAG_NODELETIONS						0x2
#define SYNC_FLAG_IGNORENOLONGERINSCOPE				0x4
#define SYNC_FLAG_READSTATE							0x8
#define SYNC_FLAG_FAI								0x10
#define SYNC_FLAG_NORMAL							0x20
#define SYNC_FLAG_ONLYSPECIFIEDPROPERTIES			0x80
#define SYNC_FLAG_NOFOREIGNIDENTIFIERS				0x100
#define SYNC_FLAG_RESERVED							0x1000
#define SYNC_FLAG_BESTBODY							0x2000
#define SYNC_FLAG_IGNORESPECIFIEDONFAI				0x4000
#define SYNC_FLAG_PROGRESS							0x8000

#define SYNC_EXTRA_FLAG_EID							0x00000001
#define SYNC_EXTRA_FLAG_MESSAGESIZE					0x00000002
#define SYNC_EXTRA_FLAG_CN							0x00000004
#define SYNC_EXTRA_FLAG_ORDERBYDELIVERYTIME			0x00000008

#define IMPORT_FLAG_ASSOCIATED						0x10
#define IMPORT_FLAG_FAILONCONFLICT					0x40

#define SYNC_DELETES_FLAG_HIERARCHY					0x01
#define SYNC_DELETES_FLAG_HARDDELETE				0x02

#define NOTIFICATION_TYPE_NEWMAIL					0x02
#define NOTIFICATION_TYPE_OBJECTCREATED				0x04
#define NOTIFICATION_TYPE_OBJECTDELETED				0x08
#define NOTIFICATION_TYPE_OBJECTMODIFIED			0x10
#define NOTIFICATION_TYPE_OBJECTMOVED				0x20
#define NOTIFICATION_TYPE_OBJECTCOPIED				0x40
#define NOTIFICATION_TYPE_SEARCHCOMPLETE			0x80

#define NOTIFICATION_FLAG_NEWMAIL					0x0002
#define NOTIFICATION_FLAG_OBJECTCREATED				0x0004
#define NOTIFICATION_FLAG_OBJECTDELETED				0x0008
#define NOTIFICATION_FLAG_OBJECTMODIFIED			0x0010
#define NOTIFICATION_FLAG_OBJECTMOVED				0x0020
#define NOTIFICATION_FLAG_OBJECTCOPIED				0x0040
#define NOTIFICATION_FLAG_SEARCHCOMPLETE			0x0080
#define NOTIFICATION_FLAG_TABLE_MODIFIED			0x0100
#define NOTIFICATION_FLAG_EXTENDED					0x0400

#define NOTIFICATION_FLAG_MOST_TOTAL				0x1000
#define NOTIFICATION_FLAG_MOST_UNREAD				0x2000
#define NOTIFICATION_FLAG_MOST_SEARCH				0x4000
#define NOTIFICATION_FLAG_MOST_MESSAGE				0x8000

#define TABLE_EVENT_TABLE_CHANGED					0x0001
#define TABLE_EVENT_ROW_ADDED						0x0003
#define TABLE_EVENT_ROW_DELETED						0x0004
#define TABLE_EVENT_ROW_MODIFIED					0x0005
#define TABLE_EVENT_RESTRICTION_CHANGED				0x0007

typedef struct _NOTIFICATION_DATA {
	uint16_t notification_flags;
	uint16_t *ptable_event;
	uint64_t *prow_folder_id;
	uint64_t *prow_message_id;
	uint32_t *prow_instance;
	uint64_t *pafter_folder_id;
	uint64_t *pafter_row_id;
	uint32_t *pafter_instance;
	BINARY *prow_data;
	uint64_t *pfolder_id;
	uint64_t *pmessage_id;
	uint64_t *pparent_id;
	uint64_t *pold_folder_id;
	uint64_t *pold_message_id;
	uint64_t *pold_parent_id;
	PROPTAG_ARRAY *pproptags;
	uint32_t *ptotal_count;
	uint32_t *punread_count;
	uint32_t *pmessage_flags;
	uint8_t *punicode_flag;
	char *pstr_class;
} NOTIFICATION_DATA;

#define PRIVATE_FID_ROOT							0x01
#define PRIVATE_FID_DEFERRED_ACTION					0x02
#define PRIVATE_FID_SPOOLER_QUEUE					0x03
#define PRIVATE_FID_SHORTCUTS						0x04
#define PRIVATE_FID_FINDER							0x05
#define PRIVATE_FID_VIEWS							0x06
#define PRIVATE_FID_COMMON_VIEWS					0x07
#define PRIVATE_FID_SCHEDULE						0x08
#define PRIVATE_FID_IPMSUBTREE						0x09
#define PRIVATE_FID_SENT_ITEMS						0x0a
#define PRIVATE_FID_DELETED_ITEMS					0x0b
#define PRIVATE_FID_OUTBOX							0x0c
#define PRIVATE_FID_INBOX							0x0d
#define PRIVATE_FID_DRAFT							0x0e
#define PRIVATE_FID_CALENDAR						0x0f
#define PRIVATE_FID_JOURNAL							0x10
#define PRIVATE_FID_NOTES							0x11
#define PRIVATE_FID_TASKS							0x12
#define PRIVATE_FID_CONTACTS						0x13
#define PRIVATE_FID_QUICKCONTACTS					0x14
#define PRIVATE_FID_IMCONTACTLIST					0x15
#define PRIVATE_FID_GALCONTACTS						0x16
#define PRIVATE_FID_JUNK							0x17
#define PRIVATE_FID_LOCAL_FREEBUSY					0x18
#define PRIVATE_FID_SYNC_ISSUES						0x19
#define PRIVATE_FID_CONFLICTS						0x1a
#define PRIVATE_FID_LOCAL_FAILURES					0x1b
#define PRIVATE_FID_SERVER_FAILURES					0x1c
#define PRIVATE_FID_CONVERSATION_ACTION_SETTINGS	0x1d
#define PRIVATE_FID_CUSTOM							0x1e

#define PUBLIC_FID_ROOT								0x01
#define PUBLIC_FID_IPMSUBTREE						0x02
#define PUBLIC_FID_NONIPMSUBTREE					0x03
#define PUBLIC_FID_EFORMSREGISTRY					0x04
#define PUBLIC_FID_CUSTOM							0x05

#define RSF_ELID_HEADER								0x0002
#define RSF_ELID_ENTRYID							0x0001
#define ELEMENT_SENTINEL							0x0000

typedef struct _PERSISTELEMENT {
	uint16_t element_id;
	BINARY *pentry_id;
} PERSISTELEMENT;

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

typedef struct _PERSISTDATA {
	uint16_t persist_id;
	PERSISTELEMENT element;
} PERSISTDATA;

typedef struct _PERSISTDATA_ARRAY {
	uint8_t count;
	PERSISTDATA **ppitems;
} PERSISTDATA_ARRAY;

#define PERMISSION_NONE								0x00000000
#define PERMISSION_READANY							0x00000001
#define PERMISSION_CREATE							0x00000002
#define PERMISSION_SENDAS							0x00000004 /* self defined */
#define PERMISSION_EDITOWNED						0x00000008
#define PERMISSION_DELETEOWNED						0x00000010
#define PERMISSION_EDITANY							0x00000020
#define PERMISSION_DELETEANY						0x00000040
#define PERMISSION_CREATESUBFOLDER					0x00000080
#define PERMISSION_FOLDEROWNER						0x00000100
#define PERMISSION_FOLDERCONTACT					0x00000200
#define PERMISSION_FOLDERVISIBLE					0x00000400
#define PERMISSION_FREEBUSYSIMPLE					0x00000800
#define PERMISSION_FREEBUSYDETAILED					0x00001000

/* aggregated permissions for delegation */
#define DELEGATE_PERMISSION_NONE					0x00000000
#define DELEGATE_PERMISSION_REVIEWER				0x00000001
#define DELEGATE_PERMISSION_AUTHOR					0x0000001B
#define DELEGATE_PERMISSION_EDITOR					0x0000007B

typedef struct _SYSTEMTIME {
	int16_t year;
	int16_t month;
	int16_t dayofweek;
	int16_t day;
	int16_t hour;
	int16_t minute;
	int16_t second;
	int16_t milliseconds;
} SYSTEMTIME;

/* pidLidTimeZoneStruct */
typedef struct _TIMEZONESTRUCT {
	int32_t bias;
	int32_t standardbias;
	int32_t daylightbias;
	int16_t standardyear;
	SYSTEMTIME standarddate;
	int16_t daylightyear;
	SYSTEMTIME daylightdate;
} TIMEZONESTRUCT;

#define TZRULE_FLAG_RECUR_CURRENT_TZREG				0x0001
#define TZRULE_FLAG_EFFECTIVE_TZREG					0x0002

typedef struct _TZRULE {
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
} TZRULE;

typedef struct _TIMEZONEDEFINITION {
	uint8_t major; /* 0x02 */
	uint8_t minor; /* 0x01 */
	uint16_t reserved; /* 0x0002 */
	char* keyname;
	uint16_t crules;
	TZRULE *prules;
} TIMEZONEDEFINITION;


#define RECURFREQUENCY_DAILY						0x200A
#define RECURFREQUENCY_WEEKLY						0x200B
#define RECURFREQUENCY_MONTHLY						0x200C
#define RECURFREQUENCY_YEARLY						0x200D

#define PATTERNTYPE_DAY								0x0000
#define PATTERNTYPE_WEEK							0x0001
#define PATTERNTYPE_MONTH							0x0002
#define PATTERNTYPE_MONTHNTH						0x0003
#define PATTERNTYPE_MONTHEND						0x0004
#define PATTERNTYPE_HJMONTH							0x000A
#define PATTERNTYPE_HJMONTHNTH						0x000B
#define PATTERNTYPE_HJMONTHEND						0x000C

#define	CALENDARTYPE_DEFAULT						0x0000
#define CALENDARTYPE_GREGORIAN						0x0001
#define CALENDARTYPE_GREGORIAN_US					0x0002
#define CALENDARTYPE_JAPAN							0x0003
#define CALENDARTYPE_TAIWAN							0x0004
#define CALENDARTYPE_KOREA							0x0005
#define CALENDARTYPE_HIJRI							0x0006
#define CALENDARTYPE_THAI							0x0007
#define CALENDARTYPE_HEBREW							0x0008
#define CALENDARTYPE_GREGORIAN_ME_FRENCH			0x0009
#define CALENDARTYPE_GREGORIAN_ARABIC				0x000A
#define CALENDARTYPE_GREGORIAN_XLIT_ENGLISH			0x000B
#define CALENDARTYPE_GREGORIAN_XLIT_FRENCH			0x000C
#define CALENDARTYPE_LUNAR_JAPANESE					0x000E
#define CALENDARTYPE_CHINESE_LUNAR					0x000F
#define CALENDARTYPE_SAKA							0x0010
#define CALENDARTYPE_LUNAR_ETO_CHN					0x0011
#define CALENDARTYPE_LUNAR_ETO_KOR					0x0012
#define CALENDARTYPE_LUNAR_ETO_ROKUYOU				0x0013
#define CALENDARTYPE_LUNAR_KOREAN					0x0014
#define CALENDARTYPE_UMALQURA						0x0017

#define WEEKRECURRENCEPATTERN_SU					0x00000001
#define WEEKRECURRENCEPATTERN_M						0x00000002
#define WEEKRECURRENCEPATTERN_TU					0x00000004
#define WEEKRECURRENCEPATTERN_W						0x00000008
#define WEEKRECURRENCEPATTERN_TH					0x00000010
#define WEEKRECURRENCEPATTERN_F						0x00000020
#define WEEKRECURRENCEPATTERN_SA					0x00000040

#define RECURRENCENUM_FIRST							0x00000001
#define RECURRENCENUM_SECOND						0x00000002
#define RECURRENCENUM_THIRD							0x00000003
#define RECURRENCENUM_FOURTH						0x00000004
#define RECURRENCENUM_LAST							0x00000005

typedef struct _PATTERNTYPESPECIFIC_MONTHNTH {
	uint32_t weekrecurrence;
	uint32_t recurrencenum;
} PATTERNTYPESPECIFIC_MONTHNTH;

typedef union _PATTERNTYPESPECIFIC {
	uint32_t weekrecurrence;
	uint32_t dayofmonth;
	PATTERNTYPESPECIFIC_MONTHNTH monthnth;
} PATTERNTYPESPECIFIC;

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

#define ENDDATE_MISSING								0x5AE980DF	

typedef struct _RECURRENCEPATTERN {
	uint16_t readerversion; /* 0x3004 */
	uint16_t writerversion; /* 0x3004 */
	uint16_t recurfrequency;
	uint16_t patterntype;
	uint16_t calendartype;
	uint32_t firstdatetime;
	uint32_t period;
	uint32_t slidingflag; /* only for scheduling tasks, otherwise 0 */
	PATTERNTYPESPECIFIC patterntypespecific;
	uint32_t endtype;
	uint32_t occurrencecount;
	uint32_t firstdow;
	uint32_t deletedinstancecount;
	uint32_t *pdeletedinstancedates;
	uint32_t modifiedinstancecount;
	uint32_t *pmodifiedinstancedates;
	uint32_t startdate;
	uint32_t enddate; /* if no enddate, shoule be set to 0x5AE980DF */
} RECURRENCEPATTERN;

#define OVERRIDEFLAG_SUBJECT						0x0001
#define OVERRIDEFLAG_MEETINGTYPE					0x0002
#define OVERRIDEFLAG_REMINDERDELTA					0x0004
#define OVERRIDEFLAG_REMINDER						0x0008
#define OVERRIDEFLAG_LOCATION						0x0010
#define OVERRIDEFLAG_BUSYSTATUS						0x0020
#define OVERRIDEFLAG_ATTACHMENT						0x0040
#define OVERRIDEFLAG_SUBTYPE						0x0080
#define OVERRIDEFLAG_APPTCOLOR						0x0100
#define OVERRIDEFLAG_EXCEPTIONAL_BODY				0x0200

typedef struct _EXCEPTIONINFO {
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
} EXCEPTIONINFO;

#define CHANGEHIGHLIGHT_VALUE_BIT_CH_START			0x00000001
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_END			0x00000002
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_RECUR			0x00000004
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_LOCATION		0x00000008
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_SUBJECT		0x00000010
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_REQATT			0x00000020
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_OPTATT			0x00000040
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_BODY			0x00000080
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_RESPONSE		0x00000200
#define CHANGEHIGHLIGHT_VALUE_BIT_CH_ALLOWPROPOSE	0x00000400

typedef struct _CHANGEHIGHLIGHT {
	uint32_t size;
	uint32_t value;
	uint8_t *preserved;
} CHANGEHIGHLIGHT;

typedef struct _EXTENDEDEXCEPTION {
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
} EXTENDEDEXCEPTION;

typedef struct _APPOINTMENTRECURRENCEPATTERN {
	RECURRENCEPATTERN recurrencepattern;
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
} APPOINTMENTRECURRENCEPATTERN;

typedef struct _GLOBALOBJECTID {
	uint8_t arrayid[16]; /* SHOULD be 0x04, 0x00, 0x00, 0x00,
							0x82, 0x00, 0xE0, 0x00, 0x74, 0xC5,
							0xB7, 0x10, 0x1A, 0x82, 0xE0, 0x08 */
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint64_t creationtime;
	uint8_t x[8];
	BINARY data;
} GLOBALOBJECTID;

typedef struct _EID_ARRAY {
	uint32_t count;
	uint64_t *pids;
} EID_ARRAY;

typedef PROPTAG_ARRAY INDEX_ARRAY;

#define MESSAGE_FORMAT_PLAIN_AND_HTML				0x00100000
#define MESSAGE_FORMAT_HTML_ONLY					0x00080000
#define MESSAGE_FORMAT_PLAIN_ONLY					0x00000000

#define DT_MAILUSER									0x00000000
#define DT_DISTLIST									0x00000001
#define DT_FORUM									0x00000002
#define DT_AGENT									0x00000003
#define DT_ORGANIZATION								0x00000004
#define DT_PRIVATE_DISTLIST							0x00000005
#define DT_REMOTE_MAILUSER							0x00000006
#define DT_MODIFIABLE								0x00010000
#define DT_GLOBAL									0x00020000
#define DT_LOCAL									0x00030000
#define DT_WAN										0x00040000
#define DT_NOT_SPECIFIC								0x00050000
#define DT_FOLDER									0x01000000
#define DT_FOLDER_LINK								0x02000000
#define DT_FOLDER_SPECIAL							0x04000000

#define DB_ADDRESS_TYPE_NORMAL						0
#define DB_ADDRESS_TYPE_ALIAS						1
#define DB_ADDRESS_TYPE_MLIST						2
#define DB_ADDRESS_TYPE_VIRTUAL						3

#define MAX_ATTACHMENT_NUM							200


typedef struct _EXTENDED_ERROR {
	uint16_t version;
	uint16_t padding;
	uint32_t errcode;
	LONG_TERM_ID folder_gid;
	LONG_TERM_ID message_gid;
	uint8_t reserved[24];
	BINARY *paux_bytes;
} EXTENDED_ERROR;


#define	REPL_TYPE_ID								0
#define REPL_TYPE_GUID								1

typedef BOOL (*REPLICA_MAPPING)(BOOL, void*, uint16_t*, GUID*);

typedef void (*REPLIST_ENUM)(void*, uint16_t);

typedef void (*REPLICA_ENUM)(void*, uint64_t);

typedef struct _IDSET {
	void *pparam;
	REPLICA_MAPPING mapping;
	BOOL b_serialize; /* if b_serialize is FALSE in idset and repl_type is
						REPL_TYPE_GUID, nodes in repl_list is REPLGUID_NODE */
	uint8_t repl_type;
	DOUBLE_LIST repl_list;
} IDSET;

#define PCL_CONFLICT											0x0
#define PCL_INCLUDE												0x1
#define PCL_INCLUDED											0x2
#define PCL_IDENTICAL											0x3

typedef DOUBLE_LIST PCL;

#define DB_NOTIFY_TYPE_NEW_MAIL									0x01
#define DB_NOTIFY_TYPE_FOLDER_CREATED							0x02
#define DB_NOTIFY_TYPE_MESSAGE_CREATED							0x03
#define DB_NOTIFY_TYPE_LINK_CREATED								0x04
#define DB_NOTIFY_TYPE_FOLDER_DELETED							0x05
#define DB_NOTIFY_TYPE_MESSAGE_DELETED							0x06
#define DB_NOTIFY_TYPE_LINK_DELETED								0x07
#define DB_NOTIFY_TYPE_FOLDER_MODIFIED							0x08
#define DB_NOTIFY_TYPE_MESSAGE_MODIFIED							0x09
#define DB_NOTIFY_TYPE_FOLDER_MOVED								0x0a
#define DB_NOTIFY_TYPE_MESSAGE_MOVED							0x0b
#define DB_NOTIFY_TYPE_FOLDER_COPIED							0x0c
#define DB_NOTIFY_TYPE_MESSAGE_COPIED							0x0d
#define DB_NOTIFY_TYPE_SEARCH_COMPLETED							0x0e
#define DB_NOTIFY_TYPE_HIERARCHY_TABLE_CHANGED					0x0f
#define DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED					0x10
#define DB_NOTIFY_TYPE_SEARCH_TABLE_CHANGED						0x11
#define DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED				0x12
#define DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED					0x13
#define DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_ADDED					0x14
#define DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED				0x15
#define DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED				0x16
#define DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_DELETED					0x17
#define DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED				0x18
#define DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED				0x19
#define DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_MODIFIED				0x20

typedef struct _DB_NOTIFY {
	uint8_t type;
	void *pdata;
} DB_NOTIFY;

typedef struct _DB_NOTIFY_NEW_MAIL {
	uint64_t folder_id;
	uint64_t message_id;
	uint32_t message_flags;
	const char *pmessage_class;
} DB_NOTIFY_NEW_MAIL;

typedef struct _DB_NOTIFY_FOLDER_CREATED {
	uint64_t folder_id;
	uint64_t parent_id;
	PROPTAG_ARRAY proptags;
} DB_NOTIFY_FOLDER_CREATED;

typedef struct _DB_NOTIFY_MESSAGE_CREATED {
	uint64_t folder_id;
	uint64_t message_id;
	PROPTAG_ARRAY proptags;
} DB_NOTIFY_MESSAGE_CREATED;

typedef struct _DB_NOTIFY_LINK_CREATED {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
	PROPTAG_ARRAY proptags;
} DB_NOTIFY_LINK_CREATED;

typedef struct _DB_NOTIFY_FOLDER_DELETED {
	uint64_t folder_id;
	uint64_t parent_id;
} DB_NOTIFY_FOLDER_DELETED;

typedef struct _DB_NOTIFY_MESSAGE_DELETED {
	uint64_t folder_id;
	uint64_t message_id;
} DB_NOTIFY_MESSAGE_DELETED;
	
typedef struct _DB_NOTIFY_LINK_DELETED {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t parent_id;
} DB_NOTIFY_LINK_DELETED;

typedef struct _DB_NOTIFY_FOLDER_MODIFIED {
	uint64_t folder_id;
	uint32_t *ptotal;
	uint32_t *punread;
	PROPTAG_ARRAY proptags;
} DB_NOTIFY_FOLDER_MODIFIED;
	
typedef struct _DB_NOTIFY_MESSAGE_MODIFIED {
	uint64_t folder_id;
	uint64_t message_id;
	PROPTAG_ARRAY proptags;
} DB_NOTIFY_MESSAGE_MODIFIED;

typedef struct _DB_NOTIFY_FOLDER_MVCP {
	uint64_t folder_id;
	uint64_t parent_id;
	uint64_t old_folder_id;
	uint64_t old_parent_id;
} DB_NOTIFY_FOLDER_MVCP;

typedef struct _DB_NOTIFY_MESSAGE_MVCP {
	uint64_t folder_id;
	uint64_t message_id;
	uint64_t old_folder_id;
	uint64_t old_message_id;
} DB_NOTIFY_MESSAGE_MVCP;

typedef struct _DB_NOTIFY_SEARCH_COMPLETED {
	uint64_t folder_id;
} DB_NOTIFY_SEARCH_COMPLETED;

typedef struct _DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED {
	uint64_t row_folder_id;
	uint64_t after_folder_id;
} DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED, DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED;

typedef struct _DB_NOTIFY_CONTENT_TABLE_ROW_ADDED {
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint64_t row_instance;
	uint64_t after_folder_id;
	uint64_t after_row_id;
	uint64_t after_instance;
} DB_NOTIFY_CONTENT_TABLE_ROW_ADDED, DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED;

typedef struct _DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED {
	uint64_t row_folder_id;
} DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED;

typedef struct _DB_NOTIFY_CONTENT_TABLE_ROW_DELETED {
	uint64_t row_folder_id;
	uint64_t row_message_id;
	uint64_t row_instance;
} DB_NOTIFY_CONTENT_TABLE_ROW_DELETED;

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

#define OPEN_FOLDER_FLAG_OPENSOFTDELETED			0x04

#define FOLDER_TYPE_ROOT							0x0
#define FOLDER_TYPE_GENERIC							0x1
#define FOLDER_TYPE_SEARCH							0x2

#define FOLDER_FLAGS_IPM							0x00000001
#define FOLDER_FLAGS_SEARCH							0x00000002
#define FOLDER_FLAGS_NORMAL							0x00000004
#define FOLDER_FLAGS_RULES							0x00000008

#define DELETE_FOLDER_FLAG_MESSAGES					0x1
#define DELETE_FOLDER_FLAG_FOLDERS					0x4
#define DELETE_FOLDER_FLAG_HARD_DELETE				0x10

#define SEARCH_FLAG_STOP							0x00000001
#define SEARCH_FLAG_RESTART							0x00000002
#define SEARCH_FLAG_RECURSIVE						0x00000004
#define SEARCH_FLAG_SHALLOW							0x00000008
#define SEARCH_FLAG_CONTENT_INDEXED					0x00010000
#define SEARCH_FLAG_NON_CONTENT_INDEXED				0x00020000
#define SEARCH_FLAG_STATIC							0x00040000

#define SEARCH_STATUS_NOT_INITIALIZED				0x00000000
#define SEARCH_STATUS_RUNNING						0x00000001
#define SEARCH_STATUS_REBUILD						0x00000002
#define SEARCH_STATUS_RECURSIVE						0x00000004
#define SEARCH_STATUS_COMPLETE						0x00001000
#define SEARCH_STATUS_PARTIAL						0x00002000
#define SEARCH_STATUS_STATIC						0x00010000
#define SEARCH_STATUS_MAYBE_STATIC					0x00020000
#define SEARCH_STATUS_CI_TOTALLY					0x01000000
#define SEARCH_STATUS_TWIR_TOTALLY					0x08000000

#define TABLE_FLAG_ASSOCIATED						0x2
#define TABLE_FLAG_DEPTH							0x4
#define TABLE_FLAG_DEFERREDERRORS					0x8
#define TABLE_FLAG_NONOTIFICATIONS					0x10
#define TABLE_FLAG_SOFTDELETES						0x20
#define TABLE_FLAG_USEUNICODE						0x40
#define TABLE_FLAG_SUPPRESSNOTIFICATIONS			0x80
#define TABLE_FLAG_CONVERSATIONMEMBERS				0x80

#define TABLE_FLAG_TBL_SYNC							0x0
#define TABLE_FLAG_TBL_ASYNC						0x1

#define TABLE_STATUS_COMPLETE						0x0
#define TABLE_STATUS_SORTING						0x9
#define TABLE_STATUS_SORT_ERROR						0xA
#define TABLE_STATUS_SETTING_COLS					0xB
#define TABLE_STATUS_SETCOL_ERROR					0xD
#define TABLE_STATUS_RESTRICTING					0xE
#define TABLE_STATUS_RESTRICT_ERROR					0xF

#define ROW_TYPE_LEAF_ROW							0x1
#define ROW_TYPE_EMPTY_CATEGORY						0x2
#define ROW_TYPE_EXPANDED_CATEGORY					0x3
#define ROW_TYPE_COLLAPSED_CATEGORY					0x4

#define QUERY_ROWS_FLAGS_ADVANCE					0x0
#define QUERY_ROWS_FLAGS_NOADVANCE					0x1
#define QUERY_ROWS_FLAGS_ENABLEPACKEDBUFFERS		0x2

#define SEEK_POS_BEGIN								0x0
#define SEEK_POS_CURRENT							0x1
#define SEEK_POS_END								0x2
#define SEEK_POS_CUSTOM								0x3

#define FIND_ROW_FLAG_FORWARD						0x0
#define FIND_ROW_FLAG_BACKWARD						0x1

#define OPEN_MODE_FLAG_READONLY						0x0
#define OPEN_MODE_FLAG_READWRITE					0x1
#define OPEN_MODE_FLAG_BESTACCESS					0x3
#define OPEN_MODE_FLAG_OPENSOFTDELETE				0x4

#define TAG_ACCESS_MODIFY							0x00000001
#define TAG_ACCESS_READ								0x00000002
#define TAG_ACCESS_DELETE							0x00000004
#define TAG_ACCESS_HIERARCHY						0x00000008
#define TAG_ACCESS_CONTENTS							0x00000010
#define TAG_ACCESS_FAI_CONTENTS						0x00000020

#define ACCESS_LEVEL_READ_ONLY						0x00000000
#define ACCESS_LEVEL_MODIFY							0x00000001

#define SAVE_FLAG_KEEPOPENREADONLY					0x01
#define SAVE_FLAG_KEEPOPENREADWRITE					0x02
#define SAVE_FLAG_FORCESAVE							0x04
#define SAVE_FLAG_DELAYEDCALL						0x08

#define MESSAGE_STATUS_HIGHLIGHTED					0x1
#define MESSAGE_STATUS_TAGGED						0x2
#define MESSAGE_STATUS_HIDDEN						0x4
#define MESSAGE_STATUS_DELMARKED					0x8
#define MESSAGE_STATUS_DRAFT						0x100
#define MESSAGE_STATUS_ANSWERED						0x200
#define MESSAGE_STATUS_IN_CONFLICT					0x800
#define MESSAGE_STATUS_REMOTE_DOWNLOAD				0x1000
#define MESSAGE_STATUS_REMOTE_DELETE				0x2000

#define RESOLVE_METHOD_DEFAULT						0x00000000
#define RESOLVE_METHOD_LAST_WRITER_WINS				0x00000001
#define RESOLVE_METHOD_NO_CONFLICT_NOTIFICATION		0x00000002

#define MSG_READ_FLAG_DEFAULT						0x00
#define MSG_READ_FLAG_SUPPRESS_RECEIPT				0x01
#define MSG_READ_FLAG_RESERVED						0x0a
#define MSG_READ_FLAG_CLEAR_READ_FLAG				0x04
#define MSG_READ_FLAG_GENERATE_RECEIPT_ONLY			0x10
#define MSG_READ_FLAG_CLEAR_NOTIFY_READ				0x20
#define MSG_READ_FLAG_CLEAR_NOTIFY_UNREAD			0x40

#define OPEN_EMBEDDED_FLAG_READONLY					0x0
#define OPEN_EMBEDDED_FLAG_READWRITE				0x1
#define OPEN_EMBEDDED_FLAG_CREATE					0x2

#define SUBMIT_FLAG_NONE							0x0
#define SUBMIT_FLAG_PREPROCESS						0x1
#define SUBMIT_FLAG_NEEDS_SPOOLER					0x2

#define LOCK_STAT_1STLOCK							0x0
#define LOCK_STAT_1STUNLOCK							0x1
#define LOCK_STAT_1STFINISHED						0x2

#define NATIVE_BODY_UNDEFINED						0
#define NATIVE_BODY_PLAIN							1
#define NATIVE_BODY_RTF								2
#define NATIVE_BODY_HTML							3
#define NATIVE_BODY_CLEAR_SIGNED					4

#define MESSAGE_FLAG_READ							0x00000001
#define MESSAGE_FLAG_UNSENT							0x00000008
#define MESSAGE_FLAG_RESEND							0x00000080
#define MESSAGE_FLAG_UNMODIFIED						0x00000002
#define MESSAGE_FLAG_SUBMITTED						0x00000004
#define MESSAGE_FLAG_HASATTACH						0x00000010
#define MESSAGE_FLAG_FROMME							0x00000020
#define MESSAGE_FLAG_FAI							0x00000040
#define MESSAGE_FLAG_NOTIFYREAD						0x00000100
#define MESSAGE_FLAG_NOTIFYUNREAD					0x00000200
#define MESSAGE_FLAG_EVERREAD						0x00000400
#define MESSAGE_FLAG_INTERNET						0x00002000
#define MESSAGE_FLAG_UNTRUSTED						0x00008000

#define FLAG_STATUS_FOLLOWUPCOMPLETE				0x00000001
#define FLAG_STATUS_FOLLOWUPFLAGGED					0x00000002

#define TODO_ITEM_FLAG_TIMEFLAGGED					0x00000001
#define TODO_ITEM_RECIPIENTFLAGGED					0x00000008

#define PROPIDS_FROM_NAMES_FLAG_GETONLY				0x00
#define PROPIDS_FROM_NAMES_FLAG_GETORCREATE			0x02

#define QUERY_FLAG_NOSTRINGS						0x01
#define QUERY_FLAG_NOIDS							0x02

#define COPY_FLAG_MOVE								0x1
#define COPY_FLAG_NOOVERWRITE						0x2

#define OPENSTREAM_FLAG_READONLY					0x0
#define OPENSTREAM_FLAG_READWRITE					0x1
#define OPENSTREAM_FLAG_CREATE						0x2

#define LOCK_FLAG_RDONLY_FOR_OTHERS					0x00000001

#define PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY		0x02

#define MODIFY_PERMISSIONS_FLAG_REPLACEROWS			0x01
#define MODIFY_PERMISSIONS_FLAG_INCLUDEFREEBUSY		0x02

#define MODIFY_RULES_FLAG_REPLACE					0x01

#define RULES_TABLE_FLAG_UNICODE					0x40

#define ATTACH_METHOD_NONE							0x00000000
#define ATTACH_METHOD_BY_VALUE						0x00000001
#define ATTACH_METHOD_BY_REF						0x00000002
#define ATTACH_METHOD_BY_REF_ONLY					0x00000004
#define ATTACH_METHOD_EMBEDDED						0x00000005
#define ATTACH_METHOD_STORAGE						0x00000006
#define ATTACH_METHOD_BYWEBREF						0x00000007

#define ATTACH_FLAG_INVISIBLEINHTML					0x00000001
#define ATTACH_FLAG_INVISIBLEINRTF					0x00000002
#define ATTACH_FLAG_RENDEREDINBODY					0x00000004

#define AUTO_RESPONSE_SUPPRESS_DR					0x00000001
#define AUTO_RESPONSE_SUPPRESS_NDR					0x00000002
#define AUTO_RESPONSE_SUPPRESS_RN					0x00000004
#define AUTO_RESPONSE_SUPPRESS_NRN					0x00000008
#define AUTO_RESPONSE_SUPPRESS_OOF					0x00000010
#define AUTO_RESPONSE_SUPPRESS_AUTOREPLY			0x00000020


#define EC_SUCCESS									0x00000000
#define EC_ERROR									0x80004005
#define EC_RPC_FAIL									0x80040115
#define EC_ACCESS_DENIED							0x80070005
#define EC_STREAM_ACCESS_DENIED						0x80030005
#define EC_CLIENT_VER_DISALLOWED					0x000004DF
#define EC_LOGIN_FAILURE							0x80040111
#define EC_UNKNOWN_USER								0x000003EB
#define EC_LOGIN_PERM								0x000003F2
#define EC_MAILBOX_DISABLED							0x0000096C
#define EC_UNKNOWN_CODEPAGE							0x000003EF
#define EC_MAILBOX_IN_TRANSIT						0x0000050C
#define EC_SERVER_PAUSED							0x0000047F
#define EC_VERSION_MISMATCH							0x80040110
#define EC_CACHED_MODE_REQUIRED						0x000004E1
#define EC_PROTOCOL_DISABLED						0x000007D8
#define EC_NOT_SUPPORTED							0x80040102
#define EC_ASYNC_WAIT_REJECT						0x000007EE
#define EC_WRONG_SERVER								0x00000478
#define EC_ERRORS_RETURNED							0x00040380
#define EC_DST_NULL_OBJECT							0x00000503
#define EC_SERVER_OOM								0x000003F0
#define EC_OUT_OF_RESOURCE							0x8004010E
#define EC_OUT_OF_MEMORY							0x8007000E
#define EC_RPC_FORMAT								0x000004B6
#define EC_BUFFER_TOO_SMALL							0x0000047D
#define EC_SERVER_BUSY								0x00000480
#define EC_BAD_STUB_DATA							0x000006F7
#define EC_INVALID_OBJECT							0x80040108
#define EC_INVALID_PARAMETER						0x80070057
#define EC_NO_RECEIVE_FOLDER						0x00000463
#define EC_NOT_IMPLEMENTED							0x80040FFF
#define EC_NOT_FOUND								0x8004010F
#define EC_AMBIGUOUS_RECIP							0x80040700
#define EC_NO_CREATE_SUBFOLDER_RIGHT				0x00000502
#define EC_DUPLICATE_NAME							0x80040604
#define EC_NOT_SEARCH_FOLDER						0x00000461
#define EC_NOT_INITIALIZED							0x80040605
#define EC_SEARCH_SCOPE_VIOLATED					0x00000490
#define EC_TOO_COMPLEX								0x80040117
#define EC_NULL_OBJECT								0x000004B9
#define EC_INVALID_BOOKMARK							0x80040405
#define EC_NOT_COLLAPSED							0x000004F8
#define EC_NOT_EXPANDED								0x000004F7
#define EC_OBJECT_MODIFIED							0x80040109
#define EC_ATTACHMENT_EXCEEDED						0x000004DB
#define	EC_NO_RECIPIENTS							0x80040607
#define EC_TOO_MANY_RECIPIENTS						0x00000505
#define EC_UNABLE_TO_ABORT							0x80040114
#define EC_NOT_IN_QUEUE								0x80040601
#define EC_SEEK_ERROR								0x80030019
#define EC_SYNC_CONFLICT							0x80040802
#define EC_NEW_CLIENT_CHANGE						0x00040821
#define EC_BAD_VALUE								0x80040301
#define EC_INVALID_TYPE								0x80040302
#define EC_UNSUPPORTED_TYPE							0x80040303
#define EC_UNEXPECTED_TYPE							0x80040304
#define EC_TOO_BIG									0x80040305
#define EC_DECLINE_COPY								0x80040306
#define EC_UNEXPECTED_ID							0x80040307
#define EC_QUOTA_EXCEEDED							0x000004D9
#define EC_SUBMITTED								0x80040608
#define EC_EXCEEDED_SIZE							0x80040610
#define EC_COLLIDING_NAMES							0x80040604
#define EC_FOLDER_CYCLE								0x8004060B
#define EC_MESSAGE_CYCLE							0x00000504
#define EC_NO_PARENT_FOLDER							0x80040803
#define EC_IGNORE_FAILURE							0x80040801
#define EC_INVALID_CODEPAGE							0x8004011E

#define ATTACHMENT_NUM_INVALID						0xFFFFFFFF

#define CONFIG_ID_MAILBOX_GUID						1
#define CONFIG_ID_CURRENT_EID						2
#define CONFIG_ID_MAXIMUM_EID						3
#define CONFIG_ID_LAST_CHANGE_NUMBER				4
#define CONFIG_ID_LAST_ARTICLE_NUMBER				5
#define CONFIG_ID_LAST_CID							6
#define CONFIG_ID_SEARCH_STATE						7
#define CONFIG_ID_DEFAULT_PERMISSION				8
#define CONFIG_ID_ANONYMOUS_PERMISSION				9

#define ALLOCATED_EID_RANGE							0x10000
#define CHANGE_NUMBER_BEGIN							0x800000000000LL

#define ADDRESS_TYPE_NORMAL							0
#define ADDRESS_TYPE_ALIAS							1
#define ADDRESS_TYPE_MLIST							2
#define ADDRESS_TYPE_VIRTUAL						3
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_ROOM */
#define ADDRESS_TYPE_ROOM							4
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_EQUIPMENT */
#define ADDRESS_TYPE_EQUIPMENT						5

typedef BOOL (*GET_PROPIDS)(const PROPNAME_ARRAY*, PROPID_ARRAY*);

/* if it returns TRUE, PROPERTY_NAME must be available */
typedef BOOL (*GET_PROPNAME)(uint16_t, PROPERTY_NAME**);

typedef uint32_t (*LTAG_TO_LCID)(const char*);

typedef const char* (*LCID_TO_LTAG)(uint32_t);

typedef uint32_t (*CHARSET_TO_CPID)(const char*);

typedef const char* (*CPID_TO_CHARSET)(uint32_t);

typedef const char* (*MIME_TO_EXTENSION)(const char*);

typedef const char* (*EXTENSION_TO_MIME)(const char*);

typedef BOOL (*GET_USER_IDS)(const char*, int*, int*, int*);

typedef BOOL (*GET_USERNAME)(int, char*);

typedef BOOL (*USERNAME_TO_ENTRYID)(const char*, const char*, BINARY*, int*);

typedef BOOL (*ENTRYID_TO_USERNAME)(const BINARY*, void*(*)(size_t), char*);

typedef BOOL (*ESSDN_TO_USERNAME)(const char*, char*);

#endif /* _H_MAPI_TYPES_ */
