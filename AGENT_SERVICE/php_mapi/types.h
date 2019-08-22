#ifndef _H_TYPES_
#define _H_TYPES_
#include <stdint.h>

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
#define EC_AMBIGUOUS_RECIP                          0x80040700
#define SYNC_W_PROGRESS								0x00040820


#define PROPVAL_TYPE_SHORT							0x0002
#define PROPVAL_TYPE_LONG							0x0003
#define PROPVAL_TYPE_FLOAT							0x0004
#define PROPVAL_TYPE_DOUBLE							0x0005
#define PROPVAL_TYPE_FLOATINGTIME					0x0007
#define PROPVAL_TYPE_ERROR							0x000a
#define PROPVAL_TYPE_BYTE							0x000b
#define PROPVAL_TYPE_OBJECT							0x000d
#define PROPVAL_TYPE_LONGLONG						0x0014
#define PROPVAL_TYPE_STRING							0x001e
#define PROPVAL_TYPE_WSTRING						0x001f
#define PROPVAL_TYPE_FILETIME						0x0040
#define PROPVAL_TYPE_GUID							0x0048
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

typedef struct _GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
} GUID;

typedef struct _FLATUID {
	uint8_t ab[16];
} FLATUID;

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

typedef struct _RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	TAGGED_PROPVAL propval;
} RESTRICTION_CONTENT;

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

typedef struct _MOVECOPY_ACTION {
	BINARY store_eid; /* zarafa specific */
	BINARY folder_eid; /* zarafa specific */
} MOVECOPY_ACTION;

/* reply or OOF action */
typedef struct _REPLY_ACTION {
	BINARY message_eid; /* zarafa specific */
	GUID template_guid;
} REPLY_ACTION;

typedef struct _RECIPIENT_BLOCK {
	uint8_t reserved;
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
} RECIPIENT_BLOCK;

typedef struct _FORWARDDELEGATE_ACTION {
	uint16_t count;
	RECIPIENT_BLOCK *pblock;
} FORWARDDELEGATE_ACTION;


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

typedef struct _ACTION_BLOCK {
	uint16_t length;
	uint8_t type;
	uint32_t flavor;
	uint32_t flags;
	void *pdata;
} ACTION_BLOCK;

typedef struct _RULE_ACTIONS {
	uint16_t count;
	ACTION_BLOCK *pblock;
} RULE_ACTIONS;		

typedef struct _TPROPVAL_ARRAY {
	uint16_t count;
	TAGGED_PROPVAL *ppropval;
} TPROPVAL_ARRAY;

typedef struct _TARRAY_SET {
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
} TARRAY_SET;

typedef struct _PROPTAG_ARRAY {
	uint16_t count;
	uint32_t *pproptag;
} PROPTAG_ARRAY;

typedef struct SORT_ORDER {
	uint16_t type; /* pay attention to the 0x2000 bit!!! */
	uint16_t propid;
	uint8_t table_sort;
} SORT_ORDER;

typedef struct _SORTORDER_SET {
	uint16_t count;
	uint16_t ccategories;
	uint16_t cexpanded;
	SORT_ORDER *psort;
} SORTORDER_SET;

typedef struct _PROPNAME_ARRAY {
	uint16_t count;
	PROPERTY_NAME *ppropname;
} PROPNAME_ARRAY;

typedef struct _PROPID_ARRAY {
	uint16_t count;
	uint16_t *ppropid;
} PROPID_ARRAY;

#define RULE_DATA_FLAG_ADD_ROW						0x01
#define RULE_DATA_FLAG_MODIFY_ROW					0x02
#define RULE_DATA_FLAG_REMOVE_ROW					0x04

typedef struct _RULE_DATA {
	uint8_t flags;
	TPROPVAL_ARRAY propvals;
} RULE_DATA;


#define CTRL_FLAG_BINHEX							0x0000
#define CTRL_FLAG_UUENCODE							0x0020
#define CTRL_FLAG_APPLESINGLE						0x0040
#define CTRL_FLAG_APPLEDOUBLE						0x0060

#define CTRL_FLAG_TEXTONLY							0x0006
#define CTRL_FLAG_HTMLONLY							0x000E
#define CTRL_FLAG_TEXTANDHTML						0x0016

#define CTRL_FLAG_NORICH							0x0001
#define CTRL_FLAG_UNICODE							0x8000
#define CTRL_FLAG_DONTLOOKUP						0x1000

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

typedef struct _ADVISE_INFO {
	uint32_t hstore;
	uint32_t sub_id;
} ADVISE_INFO;

typedef struct _NOTIF_SINK {
	GUID hsession;
	uint16_t count;
	ADVISE_INFO *padvise;
} NOTIF_SINK;

#define FOLDER_TYPE_GENERIC							1

#define SYNC_DELETES_FLAG_HARDDELETE				0x02

/* ---------------------- defined by zarafa ---------------------- */

#define ACCESS_TYPE_DENIED							1
#define ACCESS_TYPE_GRANT							2
#define ACCESS_TYPE_BOTH							3

#define RIGHT_NORMAL								0x00
#define RIGHT_NEW									0x01
#define RIGHT_MODIFY								0x02
#define RIGHT_DELETED								0x04
#define RIGHT_AUTOUPDATE_DENIED						0x08

#define STREAM_SEEK_SET								0
#define STREAM_SEEK_CUR								1
#define STREAM_SEEK_END								2

#define BOOKMARK_BEGINNING							0
#define BOOKMARK_CURRENT							1
#define BOOKMARK_END								2

#define MODRECIP_ADD								0x00000002
#define MODRECIP_MODIFY								0x00000004
#define MODRECIP_REMOVE								0x00000008

typedef struct _NEWMAIL_ZNOTIFICATION {
	BINARY entryid;
	BINARY parentid;
	uint32_t flags;
	char *message_class;
	uint32_t message_flags;
} NEWMAIL_ZNOTIFICATION;

#define MAPI_TABLE									1
#define MAPI_MESSAGE								2
#define MAPI_ATTACHMENT								3
#define MAPI_ABCONT									4
#define MAPI_FOLDER									5
#define MAPI_SESSION								6
#define MAPI_ADDRESSBOOK							7
#define MAPI_STORE									8
#define MAPI_MAILUSER								9
#define MAPI_DISTLIST								10
#define MAPI_PROFPROPERTY							11
#define MAPI_ADVISESINK								12
#define MAPI_ICSDOWNCTX								13
#define MAPI_ICSUPCTX								14
#define MAPI_INVALID								255

#define ROOT_HANDLE									0
#define INVALID_HANDLE								0xFFFFFFFF

typedef struct _OBJECT_ZNOTIFICATION {
	uint32_t object_type;
	BINARY *pentryid;
	BINARY *pparentid;
	BINARY *pold_entryid;
	BINARY *pold_parentid;
	PROPTAG_ARRAY *pproptags;
} OBJECT_ZNOTIFICATION;

#define EVENT_TYPE_NEWMAIL							0x00000002
#define EVENT_TYPE_OBJECTCREATED					0x00000004
#define EVENT_TYPE_OBJECTDELETED					0x00000008
#define EVENT_TYPE_OBJECTMODIFIED					0x00000010
#define EVENT_TYPE_OBJECTMOVED						0x00000020
#define EVENT_TYPE_OBJECTCOPIED						0x00000040
#define EVENT_TYPE_SEARCHCOMPLETE					0x00000080

typedef struct _ZNOTIFICATION {
	uint32_t event_type;
	void *pnotification_data; /* NEWMAIL_NOTIFICATION or OBJECT_NOTIFICATION */
} ZNOTIFICATION;

typedef struct _ZNOTIFICATION_ARRAY {
	uint16_t count;
	ZNOTIFICATION **ppnotification;
} ZNOTIFICATION_ARRAY;

typedef struct _PERMISSION_ROW {
	uint32_t flags;
	BINARY entryid;
	uint32_t member_rights;
} PERMISSION_ROW;

typedef struct _PERMISSION_SET {
	uint16_t count;
	PERMISSION_ROW *prows;
} PERMISSION_SET;

typedef struct _RULE_LIST {
	uint16_t count;
	RULE_DATA *prule;
} RULE_LIST;

#define SYNC_NEW_MESSAGE							0x800
#define SYNC_SOFT_DELETE							0x01

typedef struct _MESSAGE_STATE {
	BINARY source_key;
	uint32_t message_flags;
} MESSAGE_STATE; /* zarafa specific */

typedef struct _STATE_ARRAY {
	uint32_t count;
	MESSAGE_STATE *pstate;
} STATE_ARRAY; /* zarafa specific */

#define ICS_TYPE_CONTENTS							1
#define ICS_TYPE_HIERARCHY							2

#endif /* _H_TYPES_ */
