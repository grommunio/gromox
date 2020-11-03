#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "rpc_types.h"
#include "proptags.h"

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

#define MAPI_E_UNBINDSUCCESS 0x000000001
#define MAPI_E_FAILONEPROVIDER 0x8004011D

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
	union {
		uint8_t *pb;
		char *pc;
		void *pv;
	};
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
	void *pv;
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
	PROP_VAL_UNION value; /* type is PROP_TYPE(proptag) */
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
