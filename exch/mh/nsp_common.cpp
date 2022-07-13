#include <cstring>
#include <gromox/hpm_common.h>
#include "nsp_common.hpp"

void *cu_alloc1(size_t size)
{
	return ndr_stack_alloc(NDR_STACK_IN, size);
}

static FILETIME cu_nttime_to_filetime(uint64_t n)
{
	FILETIME f;
	f.low_datetime = n & 0xFFFFFFFF;
	f.high_datetime = n >> 32;
	return f;
}

static uint64_t cu_filetime_to_nttime(const FILETIME &f)
{
	return (static_cast<uint64_t>(f.high_datetime) << 32) | f.low_datetime;
}

FLATUID cu_guid_to_flatuid(const GUID &g)
{
	FLATUID f;
	f.ab[0] = g.time_low & 0xFF;
	f.ab[1] = (g.time_low >> 8) & 0xFF;
	f.ab[2] = (g.time_low >> 16) & 0xFF;
	f.ab[3] = (g.time_low >> 24) & 0xFF;
	f.ab[4] = g.time_mid & 0xFF;
	f.ab[5] = (g.time_mid >> 8) & 0xFF;
	f.ab[6] = g.time_hi_and_version & 0xFF;
	f.ab[7] = (g.time_hi_and_version >> 8) & 0xFF;
	memcpy(f.ab + 8,  g.clock_seq, sizeof(uint8_t) * 2);
	memcpy(f.ab + 10, g.node, sizeof(uint8_t) * 6);
	return f;
}

GUID cu_flatuid_to_guid(const FLATUID &f)
{
	GUID g;
	g.time_low = static_cast<uint32_t>(f.ab[3]) << 24;
	g.time_low |= static_cast<uint32_t>(f.ab[2]) << 16;
	g.time_low |= static_cast<uint32_t>(f.ab[1]) << 8;
	g.time_low |= f.ab[0];
	g.time_mid = static_cast<uint32_t>(f.ab[5]) << 8;
	g.time_mid |= f.ab[4];
	g.time_hi_and_version = static_cast<uint32_t>(f.ab[7]) << 8;
	g.time_hi_and_version |= f.ab[6];
	memcpy(g.clock_seq, f.ab + 8, sizeof(uint8_t) * 2);
	memcpy(g.node, f.ab + 10, sizeof(uint8_t) * 6);
	return g;
}

static BOOL cu_guid_array_to_flatuid_array(const GUID_ARRAY &g, FLATUID_ARRAY &f)
{
	f.cvalues = g.count;
	f.ppguid = cu_alloc<FLATUID *>(g.count);
	if (f.ppguid == nullptr)
		return false;
	for (size_t i = 0; i < g.count; ++i) {
		f.ppguid[i] = cu_alloc<FLATUID>();
		if (f.ppguid[i] == nullptr)
			return false;
		*f.ppguid[i] = cu_guid_to_flatuid(g.pguid[i]);
	}
	return TRUE;
}

static BOOL cu_flatuid_array_to_guid_array(const FLATUID_ARRAY &f, GUID_ARRAY &g)
{
	g.count = f.cvalues;
	g.pguid = cu_alloc<GUID>(f.cvalues);
	if (g.pguid == nullptr)
		return false;
	for (size_t i = 0; i < g.count; ++i)
		g.pguid[i] = cu_flatuid_to_guid(*f.ppguid[i]);
	return TRUE;
}

BOOL cu_propname_to_nsp(const nsp_propname2 &a, NSP_PROPNAME &p)
{
	p.pguid = cu_alloc<FLATUID>();
	if (p.pguid == nullptr)
		return false;
	*p.pguid = cu_guid_to_flatuid(a.guid);
	p.reserved = 0;
	p.id = a.id;
	return TRUE;
}

static BOOL cu_propval_to_valunion(uint16_t type, const void *x, PROP_VAL_UNION &u)
{
	switch (type) {
	case PT_SHORT:
		u.s = *static_cast<const uint16_t *>(x);
		return TRUE;
	case PT_LONG:
		u.l = *static_cast<const uint32_t *>(x);
		return TRUE;
	case PT_BOOLEAN:
		u.b = *static_cast<const uint8_t *>(x);
		return TRUE;
	case PT_STRING8:
	case PT_UNICODE:
		u.pstr = deconst(static_cast<const char *>(x));
		return TRUE;
	case PT_BINARY:
		if (x == nullptr) {
			u.bin.cb = 0;
			u.bin.pb = nullptr;
		} else {
			u.bin = *static_cast<const BINARY *>(x);
		}
		return TRUE;
	case PT_CLSID:
		u.pguid = cu_alloc<FLATUID>();
		if (u.pguid == nullptr)
			return false;
		*reinterpret_cast<FLATUID *>(u.pguid) = cu_guid_to_flatuid(*static_cast<const GUID *>(x));
		return TRUE;
	case PT_SYSTIME:
		u.ftime = cu_nttime_to_filetime(*static_cast<const uint64_t *>(x));
		return TRUE;
	case PT_ERROR:
		u.err = *static_cast<const uint32_t *>(x);
		return TRUE;
	case PT_MV_SHORT:
		if (x == nullptr) {
			u.short_array.count = 0;
			u.short_array.ps = nullptr;
		} else {
			u.short_array = *static_cast<const SHORT_ARRAY *>(x);
		}
		return TRUE;
	case PT_MV_LONG:
		if (x == nullptr) {
			u.long_array.count = 0;
			u.long_array.pl = nullptr;
		} else {
			u.long_array = *static_cast<const LONG_ARRAY *>(x);
		}
		return TRUE;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		if (x == nullptr) {
			u.string_array.count = 0;
			u.string_array.ppstr = nullptr;
		} else {
			u.string_array = *static_cast<const STRING_ARRAY *>(x);
		}
		return TRUE;
	case PT_MV_BINARY:
		if (x == nullptr) {
			u.bin_array.count = 0;
			u.bin_array.pbin = nullptr;
		} else {
			u.bin_array = *static_cast<const BINARY_ARRAY *>(x);
		}
		return TRUE;
	case PT_MV_CLSID:
		if (x == nullptr) {
			u.guid_array.cvalues = 0;
			u.guid_array.ppguid = nullptr;
			return TRUE;
		}
		return cu_guid_array_to_flatuid_array(*static_cast<const GUID_ARRAY *>(x), u.guid_array);
	}
	return false;
}

static BOOL cu_valunion_to_propval(uint16_t type, const PROP_VAL_UNION *u, void **value_out)
{
	void *value;

	switch (type) {
	case PT_SHORT:
		value = deconst(&u->s);
		break;
	case PT_LONG:
		value = deconst(&u->l);
		break;
	case PT_BOOLEAN:
		value = deconst(&u->b);
		break;
	case PT_STRING8:
	case PT_UNICODE:
		value = u->pstr;
		break;
	case PT_BINARY:
		value = u->bin.cb == 0 ? nullptr : deconst(&u->bin);
		break;
	case PT_CLSID:
		value = cu_alloc<GUID>();
		if (value == nullptr)
			return false;
		*static_cast<GUID *>(value) = cu_flatuid_to_guid(*u->pguid);
		break;
	case PT_SYSTIME:
		value = cu_alloc<uint64_t>();
		if (value == nullptr)
			return false;
		*static_cast<uint64_t *>(value) = cu_filetime_to_nttime(u->ftime);
		break;
	case PT_ERROR:
		value = deconst(&u->err);
		break;
	case PT_MV_SHORT:
		value = u->short_array.count == 0 ? nullptr : deconst(&u->short_array);
		break;
	case PT_MV_LONG:
		value = u->long_array.count == 0 ? nullptr : deconst(&u->long_array);
		break;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		value = u->string_array.count == 0 ? nullptr : deconst(&u->string_array);
		break;
	case PT_MV_BINARY:
		value = u->bin_array.count == 0 ? nullptr : deconst(&u->bin_array);
		break;
	case PT_MV_CLSID:
		if (u->guid_array.cvalues == 0) {
			value = nullptr;
			break;
		}
		value = cu_alloc<GUID_ARRAY>();
		if (value == nullptr ||
		    !cu_flatuid_array_to_guid_array(u->guid_array, *static_cast<GUID_ARRAY *>(value)))
			return false;
		break;
	default:
		return false;
	}
	*value_out = value;
	return TRUE;
}

BOOL cu_tpropval_to_propval(const TAGGED_PROPVAL &p, PROPERTY_VALUE &x)
{
	x.proptag = p.proptag;
	x.reserved = 0;
	return cu_propval_to_valunion(PROP_TYPE(p.proptag), p.pvalue, x.value);
}

BOOL cu_nsp_proprow_to_proplist(const NSP_PROPROW &row, LTPROPVAL_ARRAY &proplist)
{
	proplist.count = row.cvalues;
	proplist.propval = cu_alloc<TAGGED_PROPVAL>(row.cvalues);
	if (proplist.propval == nullptr)
		return false;
	for (size_t i = 0; i < row.cvalues; ++i) {
		auto &prop = row.pprops[i];
		proplist.propval[i].proptag = prop.proptag;
		if (!cu_valunion_to_propval(PROP_TYPE(prop.proptag),
		    &prop.value, &proplist.propval[i].pvalue))
			return false;
	}
	return TRUE;
}

BOOL cu_proplist_to_nsp_proprow(const LTPROPVAL_ARRAY &proplist, NSP_PROPROW &row)
{
	row.reserved = 0;
	row.cvalues = proplist.count;
	row.pprops = cu_alloc<PROPERTY_VALUE>(proplist.count);
	if (row.pprops == nullptr)
		return false;
	for (size_t i = 0; i < proplist.count; ++i) {
		auto &prop = row.pprops[i];
		prop.proptag = proplist.propval[i].proptag;
		prop.reserved = 0;
		if (!cu_propval_to_valunion(PROP_TYPE(prop.proptag),
		    proplist.propval[i].pvalue, prop.value))
			return false;
	}
	return TRUE;
}

static BOOL cu_nsp_proprow_to_proprow(const LPROPTAG_ARRAY &cols,
    const NSP_PROPROW &nsprow, PROPERTY_ROW &abrow)
{
	if (nsprow.cvalues == 0) {
		abrow.pppropval = nullptr;
	} else {
		abrow.pppropval = cu_alloc<void *>(nsprow.cvalues);
		if (abrow.pppropval == nullptr)
			return false;
	}
	size_t i;
	for (i = 0; i < nsprow.cvalues; ++i)
		if (PROP_TYPE(nsprow.pprops[i].proptag) == PT_ERROR)
			break;
	abrow.flag = i < nsprow.cvalues ? PROPERTY_ROW_FLAG_FLAGGED : PROPERTY_ROW_FLAG_NONE;
	for (i = 0; i < nsprow.cvalues; ++i) {
		auto &nsprop = nsprow.pprops[i];
		if (PROP_TYPE(nsprop.proptag) == PT_ERROR) {
			auto ap = cu_alloc<FLAGGED_PROPVAL>();
			if (ap == nullptr)
				return false;
			abrow.pppropval[i] = ap;
			if (nsprop.value.err == ecNotFound) {
				ap->flag   = FLAGGED_PROPVAL_FLAG_UNAVAILABLE;
				ap->pvalue = nullptr;
			} else {
				ap->flag   = FLAGGED_PROPVAL_FLAG_ERROR;
				ap->pvalue = cu_alloc<uint32_t>();
				if (ap->pvalue == nullptr)
					return false;
				*static_cast<uint32_t *>(ap->pvalue) = nsprop.value.err;
			}
		} else if (abrow.flag == PROPERTY_ROW_FLAG_NONE) {
			if (i < cols.cvalues && PROP_TYPE(cols.pproptag[i]) == PT_UNSPECIFIED) {
				auto ap = cu_alloc<TYPED_PROPVAL>();
				if (ap == nullptr)
					return false;
				abrow.pppropval[i] = ap;
				ap->type = PROP_TYPE(nsprop.proptag);
				if (!cu_valunion_to_propval(PROP_TYPE(nsprop.proptag),
				    &nsprop.value, &ap->pvalue))
					return false;
			} else if (!cu_valunion_to_propval(PROP_TYPE(nsprop.proptag),
			    &nsprop.value, &abrow.pppropval[i])) {
				return false;
			}
		} else if (i < cols.cvalues && PROP_TYPE(cols.pproptag[i]) == PT_UNSPECIFIED) {
			auto tp = cu_alloc<TYPED_PROPVAL>();
			if (tp == nullptr)
				return false;
			tp->type = PROP_TYPE(nsprop.proptag);
			if (!cu_valunion_to_propval(PROP_TYPE(nsprop.proptag),
			    &nsprop.value, &tp->pvalue))
				return false;
			auto ap = cu_alloc<FLAGGED_PROPVAL>();
			if (ap == nullptr)
				return false;
			abrow.pppropval[i] = ap;
			ap->flag = FLAGGED_PROPVAL_FLAG_AVAILABLE;
			ap->pvalue = tp;
		} else {
			auto ap = cu_alloc<FLAGGED_PROPVAL>();
			if (ap == nullptr)
				return false;
			abrow.pppropval[i] = ap;
			ap->flag = FLAGGED_PROPVAL_FLAG_AVAILABLE;
			if (!cu_valunion_to_propval(PROP_TYPE(nsprop.proptag),
			    &nsprop.value, &ap->pvalue))
				return false;
		}
	}
	return TRUE;
}

BOOL cu_nsp_rowset_to_colrow(const LPROPTAG_ARRAY *cols,
    const NSP_ROWSET &set, nsp_rowset2 &row)
{
	if (cols != nullptr)
		row.columns = *cols;
	else
		row.columns = {};
	row.row_count = set.crows;
	row.rows = cu_alloc<PROPERTY_ROW>(set.crows);
	if (row.rows == nullptr)
		return false;
	for (size_t i = 0; i < set.crows; ++i)
		if (!cu_nsp_proprow_to_proprow(row.columns, set.prows[i], row.rows[i]))
			return false;
	return TRUE;
}

static BOOL cu_to_nspres_and_or(const RESTRICTION_AND_OR &r, NSPRES_AND_OR &nr)
{
	nr.cres = r.count;
	nr.pres = cu_alloc<NSPRES>(nr.cres);
	if (nr.pres == nullptr) {
		nr.cres = 0;
		return false;
	}
	for (size_t i = 0; i < r.count; ++i)
		if (!cu_restriction_to_nspres(r.pres[i], nr.pres[i]))
			return false;
	return TRUE;
}

static BOOL cu_to_nspres_not(const RESTRICTION_NOT &r, NSPRES_NOT &nr)
{
	nr.pres = cu_alloc<NSPRES>();
	if (nr.pres == nullptr)
		return false;
	return cu_restriction_to_nspres(r.res, *nr.pres);
}

static BOOL cu_to_nspres_content(const RESTRICTION_CONTENT &r, NSPRES_CONTENT &nr)
{
	nr.fuzzy_level = r.fuzzy_level;
	nr.proptag = r.proptag;
	nr.pprop = cu_alloc<PROPERTY_VALUE>();
	if (nr.pprop == nullptr)
		return false;
	nr.pprop->proptag = r.propval.proptag;
	nr.pprop->reserved = 0;
	return cu_propval_to_valunion(PROP_TYPE(r.propval.proptag),
	       r.propval.pvalue, nr.pprop->value);
}

static BOOL cu_to_nspres_property(const RESTRICTION_PROPERTY &r, NSPRES_PROPERTY &nr)
{
	nr.relop = r.relop;
	nr.proptag = r.proptag;
	nr.pprop = cu_alloc<PROPERTY_VALUE>();
	if (nr.pprop == nullptr)
		return false;
	nr.pprop->proptag = r.propval.proptag;
	nr.pprop->reserved = 0;
	return cu_propval_to_valunion(PROP_TYPE(r.propval.proptag),
	       r.propval.pvalue, nr.pprop->value);
}

static void cu_to_nspres_propcompare(const RESTRICTION_PROPCOMPARE &r, NSPRES_PROPCOMPARE &nr)
{
	nr.relop = r.relop;
	nr.proptag1 = r.proptag1;
	nr.proptag2 = r.proptag2;
}

static void cu_to_nspres_bitmask(const RESTRICTION_BITMASK &r, NSPRES_BITMASK &nr)
{
	nr.rel_mbr = r.bitmask_relop;
	nr.proptag = r.proptag;
	nr.mask = r.mask;
}

static void cu_to_nspres_size(const RESTRICTION_SIZE &r, NSPRES_SIZE &nr)
{
	nr.relop = r.relop;
	nr.proptag = r.proptag;
	nr.cb = r.size;
}

static void cu_to_nspres_exist(const RESTRICTION_EXIST &r, NSPRES_EXIST &nr)
{
	nr.proptag = r.proptag;
}

static BOOL cu_to_nspres_subobj(const RESTRICTION_SUBOBJ &r, NSPRES_SUB &nr)
{
	nr.subobject = r.subobject;
	nr.pres = cu_alloc<NSPRES>();
	if (nr.pres == nullptr)
		return false;
	return cu_restriction_to_nspres(r.res, *nr.pres);
}

BOOL cu_restriction_to_nspres(const RESTRICTION &r, NSPRES &nr)
{
	nr.res_type = r.rt;
	switch (r.rt) {
	case RES_AND:
		return cu_to_nspres_and_or(*static_cast<RESTRICTION_AND_OR *>(r.pres), nr.res.res_andor);
	case RES_OR:
		return cu_to_nspres_and_or(*static_cast<RESTRICTION_AND_OR *>(r.pres), nr.res.res_andor);
	case RES_NOT:
		return cu_to_nspres_not(*static_cast<RESTRICTION_NOT *>(r.pres), nr.res.res_not);
	case RES_CONTENT:
		return cu_to_nspres_content(*static_cast<RESTRICTION_CONTENT *>(r.pres), nr.res.res_content);
	case RES_PROPERTY:
		return cu_to_nspres_property(*static_cast<RESTRICTION_PROPERTY *>(r.pres), nr.res.res_property);
	case RES_PROPCOMPARE:
		cu_to_nspres_propcompare(*static_cast<RESTRICTION_PROPCOMPARE *>(r.pres), nr.res.res_propcompare);
		return TRUE;
	case RES_BITMASK:
		cu_to_nspres_bitmask(*static_cast<RESTRICTION_BITMASK *>(r.pres), nr.res.res_bitmask);
		return TRUE;
	case RES_SIZE:
		cu_to_nspres_size(*static_cast<RESTRICTION_SIZE *>(r.pres), nr.res.res_size);
		return TRUE;
	case RES_EXIST:
		cu_to_nspres_exist(*static_cast<RESTRICTION_EXIST *>(r.pres), nr.res.res_exist);
		return TRUE;
	case RES_SUBRESTRICTION:
		return cu_to_nspres_subobj(*static_cast<RESTRICTION_SUBOBJ *>(r.pres), nr.res.res_sub);
	default:
		return false;
	}
	return false;
}
