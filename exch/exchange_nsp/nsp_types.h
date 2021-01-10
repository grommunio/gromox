#pragma once
#include <cstdint>
#include <gromox/rpc_types.hpp>
#include <gromox/proptags.hpp>

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

#define PROPVAL_TYPE_EMBEDDEDTABLE			0x000d
#define PROPVAL_TYPE_FLATUID				0x0048
#define PROPVAL_TYPE_FLATUID_ARRAY			0x1048

#define MOD_FLAG_DELETE						0x000000001

#define MAPI_E_UNBINDSUCCESS 0x000000001
#define MAPI_E_FAILONEPROVIDER 0x8004011D

typedef CONTEXT_HANDLE NSPI_HANDLE;


struct FLATUID {
	uint8_t ab[16];
};

struct STAT {
	uint32_t sort_type;
	uint32_t container_id;
	uint32_t cur_rec;
	int32_t delta;
	uint32_t num_pos;
	uint32_t total_rec;
	uint32_t codepage;
	uint32_t template_locale;
	uint32_t sort_locale;
};

struct PROPTAG_ARRAY {
	uint32_t cvalues;
	uint32_t *pproptag;
};

struct PROPERTY_NAME {
	FLATUID *pguid;
	uint32_t reserved;
	uint32_t id;
};

struct STRING_ARRAY {
	uint32_t cvalues;
	char **ppstr;
};

struct STRINGS_ARRAY {
	uint32_t count;
	char **ppstrings;
};

struct BINARY {
	uint32_t cb;
	union {
		uint8_t *pb;
		char *pc;
		void *pv;
	};
};

struct FILETIME {
	uint32_t low_datetime;
	uint32_t high_datetime;
};

struct SHORT_ARRAY {
	uint32_t cvalues;
	uint16_t *ps;
};

struct LONG_ARRAY {
	uint32_t cvalues;
	uint32_t *pl;
};

struct BINARY_ARRAY {
	uint32_t cvalues;
	BINARY *pbin;
};

struct FLATUID_ARRAY {
	uint32_t cvalues;
	FLATUID **ppguid;
};

struct FILETIME_ARRAY {
	uint32_t cvalues;
	FILETIME *pftime;
};

union PROP_VAL_UNION {
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
};

struct PROPERTY_VALUE {
	uint32_t proptag;
	uint32_t reserved;
	PROP_VAL_UNION value; /* type is PROP_TYPE(proptag) */
};

struct PROPERTY_ROW {
	uint32_t reserved;
	uint32_t cvalues;
	PROPERTY_VALUE *pprops;
};

struct PROPROW_SET {
	uint32_t crows;
	PROPERTY_ROW *prows;
};

struct RESTRICTION;
struct RESTRICTION_AND_OR {
	uint32_t cres;
	RESTRICTION *pres;
};
typedef struct RESTRICTION_AND_OR RESTRICTION_AND, RESTRICTION_OR;

struct RESTRICTION_NOT {
	RESTRICTION *pres;
};

struct RESTRICTION_CONTENT {
	uint32_t fuzzy_level;
	uint32_t proptag;
	PROPERTY_VALUE *pprop;
};

struct RESTRICTION_PROPERTY {
	uint32_t relop;
	uint32_t proptag;
	PROPERTY_VALUE *pprop;
};

struct RESTRICTION_PROPCOMPARE {
	uint32_t relop;
	uint32_t proptag1;
	uint32_t proptag2;
};

struct RESTRICTION_BITMASK {
	uint32_t rel_mbr;
	uint32_t proptag;
	uint32_t mask;
};

struct RESTRICTION_SIZE {
	uint32_t relop;
	uint32_t proptag;
	uint32_t cb;
};

struct RESTRICTION_EXIST {
	uint32_t reserved1;
	uint32_t proptag;
	uint32_t reserved2;
};

struct RESTRICTION_SUB {
	uint32_t subobject;
	RESTRICTION *pres;
};

union RESTRICTION_UNION {
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
};

struct RESTRICTION {
	uint32_t res_type;
	RESTRICTION_UNION res;
};

struct PERMANENT_ENTRYID {
	uint8_t id_type;	/* constant: 0x0	*/
	uint8_t r1;			/* reserved: 0x0	*/
	uint8_t r2;			/* reserved: 0x0	*/
	uint8_t r3;			/* reserved: 0x0	*/
	FLATUID provider_uid;	/* constant: GUID_NSPI	*/
	uint32_t r4;			/* constant: 0x1	*/
	uint32_t display_type;	/* must match one of the existing display type value */
	char *pdn;				/* DN string representing the object GUID */
};


struct EPHEMERAL_ENTRYID {
	uint8_t id_type;	/* constant: 0x87	*/
	uint8_t r1;			/* reserved: 0x0	*/
	uint8_t r2;			/* reserved: 0x0	*/
	uint8_t r3;			/* reserved: 0x0	*/
	FLATUID	provider_uid;	/* NSPI server GUID	*/
	uint32_t r4;			/* constant: 0x1	*/
	uint32_t display_type;	/* must match one of the existing display type value */
	uint32_t mid;			/* mid of this object	*/
};
