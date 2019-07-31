#ifndef _H_NSP_TYPES_
#define _H_NSP_TYPES_

#include "rpc_types.h"
#include "proptags.h"
#include <stdint.h>


#define RESTRICTION_TYPE_AND				0x0
#define RESTRICTION_TYPE_OR					0x1
#define RESTRICTION_TYPE_NOT				0x2
#define RESTRICTION_TYPE_CONTENT			0x3
#define RESTRICTION_TYPE_PROPERTY			0x4
#define RESTRICTION_TYPE_PROPCOMPARE		0x5
#define RESTRICTION_TYPE_BITMASK			0x6
#define RESTRICTION_TYPE_SIZE				0x7
#define RESTRICTION_TYPE_EXIST				0x8
#define RESTRICTION_TYPE_SUBRESTRICTION		0x9


#define PROPVAL_TYPE_RESERVED				0x0001
#define PROPVAL_TYPE_SHORT					0x0002
#define PROPVAL_TYPE_LONG					0x0003
#define PROPVAL_TYPE_BYTE					0x000b
#define PROPVAL_TYPE_EMBEDDEDTABLE			0x000d
#define PROPVAL_TYPE_STRING					0x001e
#define PROPVAL_TYPE_BINARY					0x0102
#define PROPVAL_TYPE_WSTRING				0x001f
#define PROPVAL_TYPE_FLATUID				0x0048
#define PROPVAL_TYPE_FILETIME				0x0040
#define PROPVAL_TYPE_ERROR					0x000a
#define PROPVAL_TYPE_SHORT_ARRAY			0x1002
#define PROPVAL_TYPE_LONG_ARRAY				0x1003
#define PROPVAL_TYPE_STRING_ARRAY			0x101e
#define PROPVAL_TYPE_BINARY_ARRAY			0x1102
#define PROPVAL_TYPE_FLATUID_ARRAY			0x1048
#define PROPVAL_TYPE_WSTRING_ARRAY			0x101f
#define PROPVAL_TYPE_FILETIME_ARRAY			0x1040

#define MOD_FLAG_DELETE						0x000000001

#define MAPI_E_SUCCESS 0x00000000
#define MAPI_E_UNBINDSUCCESS 0x000000001
#define MAPI_E_INTERFACE_NO_SUPPORT 0x80004002
#define MAPI_E_CALL_FAILED 0x80004005
#define MAPI_E_NO_SUPPORT 0x80040102
#define MAPI_E_BAD_CHARWIDTH 0x80040103
#define MAPI_E_STRING_TOO_LONG 0x80040105
#define MAPI_E_UNKNOWN_FLAGS 0x80040106
#define MAPI_E_INVALID_ENTRYID 0x80040107
#define MAPI_E_INVALID_OBJECT 0x80040108
#define MAPI_E_OBJECT_CHANGED 0x80040109
#define MAPI_E_OBJECT_DELETED 0x8004010A
#define MAPI_E_BUSY 0x8004010B
#define MAPI_E_NOT_ENOUGH_DISK 0x8004010D
#define MAPI_E_NOT_ENOUGH_RESOURCES 0x8004010E
#define MAPI_E_NOT_FOUND 0x8004010F
#define MAPI_E_VERSION 0x80040110
#define MAPI_E_LOGON_FAILED 0x80040111
#define MAPI_E_SESSION_LIMIT 0x80040112
#define MAPI_E_USER_CANCEL 0x80040113
#define MAPI_E_UNABLE_TO_ABORT 0x80040114
#define MAPI_E_DISK_ERROR 0x80040116
#define MAPI_E_TOO_COMPLEX 0x80040117
#define MAPI_E_BAD_COLUMN 0x80040118
#define MAPI_E_EXTENDED_ERROR 0x80040119
#define MAPI_E_COMPUTED 0x8004011A
#define MAPI_E_CORRUPT_DATA 0x8004011B
#define MAPI_E_UNCONFIGURED 0x8004011C
#define MAPI_E_FAILONEPROVIDER 0x8004011D
#define MAPI_E_UNKNOWN_CPID 0x8004011E
#define MAPI_E_UNKNOWN_LCID 0x8004011F
#define MAPI_E_PASSWORD_CHANGE_REQUIRED 0x80040120
#define MAPI_E_PASSWORD_EXPIRED 0x80040121
#define MAPI_E_INVALID_WORKSTATION_ACCOUNT 0x80040122
#define MAPI_E_INVALID_ACCESS_TIME 0x80040123
#define MAPI_E_ACCOUNT_DISABLED 0x80040124
#define MAPI_E_END_OF_SESSION 0x80040200
#define MAPI_E_UNKNOWN_ENTRYID 0x80040201
#define MAPI_E_MISSING_REQUIRED_COLUMN 0x80040202
#define MAPI_E_BAD_VALUE 0x80040301
#define MAPI_E_INVALID_TYPE 0x80040302
#define MAPI_E_TYPE_NO_SUPPORT 0x80040303
#define MAPI_E_UNEXPECTED_TYPE 0x80040304
#define MAPI_E_TOO_BIG 0x80040305
#define MAPI_E_DECLINE_COPY 0x80040306
#define MAPI_E_UNEXPECTED_ID 0x80040307
#define MAPI_E_UNABLE_TO_COMPLETE 0x80040400
#define MAPI_E_TIMEOUT 0x80040401
#define MAPI_E_TABLE_EMPTY 0x80040402
#define MAPI_E_TABLE_TOO_BIG 0x80040403
#define MAPI_E_INVALID_BOOKMARK 0x80040405
#define MAPI_E_WAIT 0x80040500
#define MAPI_E_CANCEL 0x80040501
#define MAPI_E_NOT_ME 0x80040502
#define MAPI_E_CORRUPT_STORE 0x80040600
#define MAPI_E_NOT_IN_QUEUE 0x80040601
#define MAPI_E_NO_SUPPRESS 0x80040602
#define MAPI_E_COLLISION 0x80040604
#define MAPI_E_NOT_INITIALIZED 0x80040605
#define MAPI_E_NON_STANDARD 0x80040606
#define MAPI_E_NO_RECIPIENTS 0x80040607
#define MAPI_E_SUBMITTED 0x80040608
#define MAPI_E_HAS_FOLDERS 0x80040609
#define MAPI_E_HAS_MESAGES 0x8004060A
#define MAPI_E_FOLDER_CYCLE 0x8004060B
#define MAPI_E_LOCKID_LIMIT 0x8004060D
#define MAPI_E_AMBIGUOUS_RECIP 0x80040700
#define MAPI_E_NAMED_PROP_QUOTA_EXCEEDED 0x80040900
#define MAPI_E_NOT_IMPLEMENTED 0x80040FFF
#define MAPI_E_NO_ACCESS 0x80070005
#define MAPI_E_NOT_ENOUGH_MEMORY 0x8007000E
#define MAPI_E_INVALID_PARAMETER 0x80070057
#define MAPI_W_ERRORS_RETURNED 0x00040380


typedef CONTEXT_HANDLE NSPI_HANDLE;


typedef struct _FLATUID {
	uint8_t ab[16];
} FLATUID;

typedef struct _STAT {
	uint32_t sort_type;
	uint32_t container_id;
	uint32_t cur_rec;
	int32_t delta;
	uint32_t num_pos;
	uint32_t total_rec;
	uint32_t codepage;
	uint32_t template_locale;
	uint32_t sort_locale;
} STAT;

typedef struct _PROPTAG_ARRAY {
	uint32_t cvalues;
	uint32_t *pproptag;
} PROPTAG_ARRAY;

typedef struct _PROPERTY_NAME {
	FLATUID *pguid;
	uint32_t reserved;
	uint32_t id;
} PROPERTY_NAME;

typedef struct _STRING_ARRAY {
	uint32_t cvalues;
	char **ppstr;
} STRING_ARRAY;

typedef struct _STRINGS_ARRAY {
	uint32_t count;
	char **ppstrings;
} STRINGS_ARRAY;

typedef struct _BINARY {
	uint32_t cb;
	uint8_t *pb;
} BINARY;

typedef struct _FILETIME {
	uint32_t low_datetime;
	uint32_t high_datetime;
} FILETIME;

typedef struct _SHORT_ARRAY {
	uint32_t cvalues;
	uint16_t *ps;
} SHORT_ARRAY;

typedef struct _LONG_ARRAY {
	uint32_t cvalues;
	uint32_t *pl;
} LONG_ARRAY;

typedef struct _BINARY_ARRAY {
	uint32_t cvalues;
	BINARY *pbin;
} BINARY_ARRAY;

typedef struct _FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
} FLATUID_ARRAY;

typedef struct _FILETIME_ARRAY {
	uint32_t cvalues;
	FILETIME *pftime;
} FILETIME_ARRAY;

typedef union _PROP_VAL_UNION {
	uint16_t s;
	uint32_t l;
	uint8_t b;
	char *pstr;
	BINARY bin;
	FLATUID *pguid;
	FILETIME ftime;
	uint32_t err;
	SHORT_ARRAY short_array;
	LONG_ARRAY long_array;
	STRING_ARRAY string_array;
	BINARY_ARRAY bin_array;
	FLATUID_ARRAY guid_array;
	FILETIME_ARRAY ftime_array;
	uint32_t reserved;
} PROP_VAL_UNION;

typedef struct _PROPERTY_VALUE {
	uint32_t proptag;
	uint32_t reserved;
	PROP_VAL_UNION value; /* type is proptag&0xFFFF */
} PROPERTY_VALUE;

typedef struct _PROPERTY_ROW {
	uint32_t reserved;
	uint32_t cvalues;
	PROPERTY_VALUE *pprops;
} PROPERTY_ROW;

typedef struct _PROPROW_SET {
	uint32_t crows;
	PROPERTY_ROW *prows;
} PROPROW_SET;

typedef struct _RESTRICTION_AND_OR {
	uint32_t cres;
	struct _RESTRICTION *pres;
} RESTRICTION_AND, RESTRICTION_OR;

typedef struct _RESTRICTION_NOT {
	struct _RESTRICTION *pres;
} RESTRICTION_NOT;

typedef struct _RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	PROPERTY_VALUE *pprop;
} RESTRICTION_CONTENT;

typedef struct _RESTRICTION_PROPERTY {
	uint32_t relop;
	uint32_t proptag;
	PROPERTY_VALUE *pprop;
} RESTRICTION_PROPERTY;

typedef struct _RESTRICTION_PROPCOMPARE {
	uint32_t relop;
	uint32_t proptag1;
	uint32_t proptag2;
} RESTRICTION_PROPCOMPARE;

typedef struct _RESTRICTION_BITMASK {
	uint32_t rel_mbr;
	uint32_t proptag;
	uint32_t mask;
} RESTRICTION_BITMASK;

typedef struct _RESTRICTION_SIZE {
	uint32_t relop;
	uint32_t proptag;
	uint32_t cb;
} RESTRICTION_SIZE;

typedef struct _RESTRICTION_EXIST {
	uint32_t reserved1;
	uint32_t proptag;
	uint32_t reserved2;
} RESTRICTION_EXIST;

typedef struct _RESTRICTION_SUB {
	uint32_t subobject;
	struct _RESTRICTION *pres;
} RESTRICTION_SUB;

typedef union _RESTRICTION_UNION {
	RESTRICTION_AND res_and;
	RESTRICTION_OR res_or;
	RESTRICTION_NOT res_not;
	RESTRICTION_CONTENT res_content;
	RESTRICTION_PROPERTY res_property;
	RESTRICTION_PROPCOMPARE res_propcompare;
	RESTRICTION_BITMASK res_bitmask;
	RESTRICTION_SIZE res_size;
	RESTRICTION_EXIST res_exist;
	RESTRICTION_SUB res_sub;
} RESTRICTION_UNION;

typedef struct _RESTRICTION {
	uint32_t res_type;
	RESTRICTION_UNION res;
} RESTRICTION;

typedef struct _PERMANENT_ENTRYID {
	uint8_t id_type;	/* constant: 0x0	*/
	uint8_t r1;			/* reserved: 0x0	*/
	uint8_t r2;			/* reserved: 0x0	*/
	uint8_t r3;			/* reserved: 0x0	*/
	FLATUID provider_uid;	/* constant: GUID_NSPI	*/
	uint32_t r4;			/* constant: 0x1	*/
	uint32_t display_type;	/* must match one of the existing display type value */
	char *pdn;				/* DN string representing the object GUID */
} PERMANENT_ENTRYID;


typedef struct _EPHEMERAL_ENTRYID {
	uint8_t id_type;	/* constant: 0x87	*/
	uint8_t r1;			/* reserved: 0x0	*/
	uint8_t r2;			/* reserved: 0x0	*/
	uint8_t r3;			/* reserved: 0x0	*/
	FLATUID	provider_uid;	/* NSPI server GUID	*/
	uint32_t r4;			/* constant: 0x1	*/
	uint32_t display_type;	/* must match one of the existing display type value */
	uint32_t mid;			/* mid of this object	*/
} EPHEMERAL_ENTRYID;

#endif /* _H_NSP_TYPES_ */

