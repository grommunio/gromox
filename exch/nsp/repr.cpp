// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <string>
#include <fmt/core.h>

std::string PROPERTY_VALUE::repr() const
{
#define E(p) TAGGED_PROPVAL{proptag, deconst(p)}.repr()
	switch (PROP_TYPE(proptag)) {
	case PT_SHORT:      return E(&value.s);
	case PT_LONG:       return E(&value.l);
	case PT_I8:         return E(&value.ll);
	case PT_FLOAT:      return E(&value.flt);
	case PT_DOUBLE:     return E(&value.dbl);
	case PT_BOOLEAN:    return E(&value.b);
	case PT_BINARY:     return E(value.pv);
	case PT_STRING8:    [[fallthrough]];
	case PT_UNICODE:    return E(value.pstr);
	case PT_CLSID:      return E(value.pguid);
	case PT_SYSTIME:    return E(&value.ftime);
	case PT_ERROR:      return E(&value.err);
	case PT_MV_SHORT:   return E(&value.short_array);
	case PT_MV_LONG:    return E(&value.long_array);
	case PT_MV_STRING8: [[fallthrough]];
	case PT_MV_UNICODE: return E(&value.string_array);
	case PT_MV_BINARY:  return E(&value.bin_array);
	case PT_MV_CLSID:   return E(&value.guid_array);
	case PT_MV_SYSTIME: return E(&value.ftime_array);
	default:            return "??";
	}
}

std::string NSPRES_AND_OR::repr(const char *sep) const
{
	std::string s;
	for (size_t i = 0; i < cres; ++i)
		if (i ==  0)
			s = pres[i].repr();
		else
			s += sep + pres[i].repr();
	return "RES_AOR[" + std::to_string(cres) + "]{" + std::move(s) + "}";
}

std::string NSPRES_NOT::repr() const
{
	return "RES_NOT{" + pres->repr() + "}";
}

std::string NSPRES_CONTENT::repr() const
{
	std::string ss = "RES_CONTENT{";
	switch (fuzzy_level & 0xffff) {
	case FL_FULLSTRING: ss += "FL_FULLSTRING,"; break;
	case FL_SUBSTRING: ss += "FL_SUBSTRING,"; break;
	case FL_PREFIX: ss += "FL_PREFIX,"; break;
	default: ss += "part??,"; break;
	}
	if (fuzzy_level & FL_PREFIX_ON_ANY_WORD)
		ss += "FL_PREFIX_ON_ANY_WORD,";
	if (fuzzy_level & FL_PHRASE_MATCH)
		ss += "FL_PHRASE_MATCH,";
	if (fuzzy_level & FL_IGNORECASE)
		ss += "FL_IGNORECASE,";
	if (fuzzy_level & FL_IGNORENONSPACE)
		ss += "FL_IGNORE_NON_SPACE,";
	if (fuzzy_level & FL_LOOSE)
		ss += "FL_LOOSE,";
	ss += fmt::format("{:x}h,{}", proptag, pprop->repr());
	return ss;
}

std::string NSPRES_PROPERTY::repr() const
{
	return fmt::format("RES_PROP{{val({:x}h) {} {}}}",
	       proptag, gromox::relop_repr(relop), pprop->repr());
}

std::string NSPRES_PROPCOMPARE::repr() const
{
	return fmt::format("RES_PROPCMP{{val({:x}h) {} val({})}}",
	       proptag1, gromox::relop_repr(relop), proptag2);
}

std::string NSPRES_BITMASK::repr() const
{
	std::string ss = fmt::format("RES_BITMASK{{val({:x}h & {:x}", proptag, mask);
	switch (rel_mbr) {
	case BMR_EQZ: ss += "h == 0}"; break;
	case BMR_NEZ: ss += "h != 0}"; break;
	default: ss += "h ..op?}"; break;
	}
	return ss;
}

std::string NSPRES_SIZE::repr() const
{
	return fmt::format("RES_SIZE{{{},{:x}h,{}}}",
	       gromox::relop_repr(relop), proptag, cb);
}

std::string NSPRES_EXIST::repr() const
{
	return fmt::format("RES_EXIST{{{:x}h}}", proptag);
}

std::string NSPRES_SUB::repr() const
{
	return fmt::format("RES_SUBOBJ{{{:x}h,{}}}", subobject, pres->repr());
}

std::string NSPRES::repr() const
{
	switch (res_type) {
	case RES_AND:            return "RES_AND" + res.res_andor.repr(" && ");
	case RES_OR:             return "RES_OR" + res.res_andor.repr(" || ");
	case RES_NOT:            return res.res_not.repr();
	case RES_CONTENT:        return res.res_content.repr();
	case RES_PROPERTY:       return res.res_property.repr();
	case RES_PROPCOMPARE:    return res.res_propcompare.repr();
	case RES_BITMASK:        return res.res_bitmask.repr();
	case RES_SIZE:           return res.res_size.repr();
	case RES_EXIST:          return res.res_exist.repr();
	case RES_SUBRESTRICTION: return res.res_sub.repr();
	case RES_COMMENT:        return "RES_COMMENT{..}";
	case RES_COUNT:          return "RES_COUNT{..}";
	case RES_ANNOTATION:     return "RES_ANNOTATION{..}";
	case RES_NULL:           return "RES_NULL{}";
	default:                 return "RES_??{}";
	}
}

