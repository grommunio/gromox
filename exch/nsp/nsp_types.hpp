#pragma once
#include <cstdint>
#include <gromox/mapidefs.h>
#include <gromox/rpc_types.hpp>
#define MOD_FLAG_DELETE						0x000000001

using NSPI_HANDLE = CONTEXT_HANDLE;

struct STAT {
	uint32_t sort_type;
	uint32_t container_id;
	uint32_t cur_rec;
	int32_t delta;
	uint32_t num_pos;
	uint32_t total_rec;
	cpid_t codepage;
	uint32_t template_locale;
	uint32_t sort_locale;
};

/* MID_ARRAY is semantically different, but layout-compatible to LPROPTAG_ARRAY (and exchange_nsp uses the proptag deserializer). */
using MID_ARRAY = LPROPTAG_ARRAY;
using MINID_ARRAY = LPROPTAG_ARRAY;

struct NSP_PROPNAME {
	FLATUID *pguid;
	uint32_t reserved;
	uint32_t id;
};

/* MS-OXNSPI v13 §2.2.2.6 vs §2.2.7.1 oddity that is irrelevant for our implementation */
using STRINGS_ARRAY = STRING_ARRAY;

struct FILETIME {
	uint32_t low_datetime;
	uint32_t high_datetime;
};

struct FILETIME_ARRAY {
	uint32_t cvalues;
	FILETIME *pftime;
};

union PROP_VAL_UNION {
	/*
	 * A number of types are not specified in either NSPI or OXNSPI, e.g.
	 * uint64, floats… but they work regardless with MSMAPI.
	 */
	uint16_t s; /* NSPI only, not in OXNSPI */
	uint32_t l;
	uint64_t ll; /* unspecced */
	float flt; /* unspecced */
	double dbl; /* unspecced */
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
	gromox::proptag_t proptag;
	uint32_t reserved;
	PROP_VAL_UNION value; /* type is PROP_TYPE(proptag) */
};

struct NSP_PROPROW {
	PROPERTY_VALUE *find(uint32_t tag) const {
		for (size_t i = 0; i < cvalues; ++i)
			if (pprops[i].proptag == tag)
				return &pprops[i];
		return nullptr;
	}
	inline PROP_VAL_UNION *getval(uint32_t tag) const {
		auto v = find(tag);
		return v != nullptr ? &v->value : nullptr;
	}
	bool has_properror() const {
		for (size_t i = 0; i < cvalues; ++i)
			if (PROP_TYPE(pprops[i].proptag) == PT_ERROR)
				return true;
		return false;
	}

	uint32_t reserved;
	uint32_t cvalues;
	PROPERTY_VALUE *pprops;
	I_BEGIN_END(pprops, cvalues);
};

struct NSP_ROWSET {
	uint32_t crows;
	NSP_PROPROW *prows;
	I_BEGIN_END(prows, crows);
};

struct NSPRES;
struct NSPRES_AND_OR {
	uint32_t cres;
	NSPRES *pres;
};

struct NSPRES_NOT {
	NSPRES *pres;
};

struct NSPRES_CONTENT {
	uint32_t fuzzy_level;
	gromox::proptag_t proptag;
	PROPERTY_VALUE *pprop;
};

struct NSPRES_PROPERTY {
	enum relop relop;
	gromox::proptag_t proptag;
	PROPERTY_VALUE *pprop;
};

struct NSPRES_PROPCOMPARE {
	enum relop relop;
	gromox::proptag_t proptag1, proptag2;
};

struct NSPRES_BITMASK {
	enum bm_relop rel_mbr;
	gromox::proptag_t proptag;
	uint32_t mask;
};

struct NSPRES_SIZE {
	enum relop relop;
	gromox::proptag_t proptag;
	uint32_t cb;
};

struct NSPRES_EXIST {
	uint32_t reserved1;
	gromox::proptag_t proptag;
	uint32_t reserved2;
};

struct NSPRES_SUB {
	uint32_t subobject;
	NSPRES *pres;
};

union NSPRES_UNION {
	NSPRES_AND_OR res_andor;
	NSPRES_NOT res_not;
	NSPRES_CONTENT res_content;
	NSPRES_PROPERTY res_property;
	NSPRES_PROPCOMPARE res_propcompare;
	NSPRES_BITMASK res_bitmask;
	NSPRES_SIZE res_size;
	NSPRES_EXIST res_exist;
	NSPRES_SUB res_sub;
};

struct NSPRES {
	mapi_rtype res_type;
	NSPRES_UNION res;
};

struct EPHEMERAL_ENTRYID {
	uint32_t flags; /* constant: ENTRYID_TYPE_EPHEMERAL */
	uint32_t display_type;	/* must match one of the existing display type value */
	uint32_t mid;			/* mid of this object	*/
};
