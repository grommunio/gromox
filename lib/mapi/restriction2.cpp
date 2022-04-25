// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
#include <sstream>
#include <string>
#include <utility>
#include <gromox/mapidefs.h>

static inline const char *relop_repr(relop r)
{
	switch (r) {
	case RELOP_LT: return "<";
	case RELOP_LE: return "<=";
	case RELOP_GT: return ">";
	case RELOP_GE: return ">=";
	case RELOP_EQ: return "==";
	case RELOP_NE: return "!=";
	case RELOP_RE: return "~=";
	case RELOP_MEMBER_OF_DL: return "DL";
	default: return "??";
	}
}

std::string TAGGED_PROPVAL::repr() const
{
	std::stringstream ss;
	switch (PROP_TYPE(proptag)) {
	#define PTI << std::hex << PROP_ID(proptag) << "h," << std::dec
	case PT_LONG: ss << "PT_LONG{" PTI << *static_cast<uint32_t *>(pvalue) << "}"; break;
	case PT_I8: ss << "PT_I8{" PTI << *static_cast<uint64_t *>(pvalue) << "}"; break;
	case PT_STRING8: ss << "PT_STRING8{" PTI << "\"" << static_cast<const char *>(pvalue) << "\"}"; break;
	case PT_UNICODE: ss << "PT_UNICODE{" PTI << "\"" << static_cast<const char *>(pvalue) << "\"}"; break;
	case PT_SVREID: {
		auto &x = *static_cast<const SVREID *>(pvalue);
		ss << "PT_SVREID{" PTI;
		if (x.pbin != nullptr)
			ss << x.pbin->cb << "bytes}";
		else
			ss << "fid=" << std::hex << x.folder_id << ",mid=" << x.message_id << ",ins=" << x.instance << "}";
		break;
	}
	default: ss << "PT_" << std::hex << proptag << "h{}"; break;
	#undef PTI
	}
	return std::move(ss).str();
}

std::string RESTRICTION::repr() const
{
	switch (rt) {
	case RES_AND: {
		auto s = andor->repr();
		s[5] = 'N';
		s[6] = 'D';
		return s;
	}
	case RES_OR: {
		auto s = andor->repr();
		s[4] = '_';
		return s;
	}
	case RES_NOT:            return xnot->repr();
	case RES_CONTENT:        return cont->repr();
	case RES_PROPERTY:       return prop->repr();
	case RES_PROPCOMPARE:    return pcmp->repr();
	case RES_BITMASK:        return bm->repr();
	case RES_SIZE:           return size->repr();
	case RES_EXIST:          return exist->repr();
	case RES_SUBRESTRICTION: return sub->repr();
	case RES_COMMENT:        return comment->repr();
	case RES_COUNT:          return count->repr();
	case RES_NULL:           return "RES_NULL{}";
	default:                 return "RES_??{}";
	}
}

std::string RESTRICTION_AND_OR::repr() const
{
	auto s = std::to_string(count);
	for (size_t i = 0; i < count; ++i)
		s += "," + pres->repr();
	return "RES_AOR{" + std::move(s) + "}";
}

std::string RESTRICTION_NOT::repr() const
{
	return "RES_NOT{" + res.repr() + "}";
}

std::string RESTRICTION_CONTENT::repr() const
{
	std::stringstream ss;
	ss << "RES_CONTENT{";
	switch (fuzzy_level & 0xffff) {
	case FL_FULLSTRING: ss << "FL_FULLSTRING,"; break;
	case FL_SUBSTRING: ss << "FL_SUBSTRING,"; break;
	case FL_PREFIX: ss << "FL_PREFIX,"; break;
	default: ss << "part??,"; break;
	}
	if (fuzzy_level & FL_PREFIX_ON_ANY_WORD)
		ss << "FL_PREFIX_ON_ANY_WORD,";
	if (fuzzy_level & FL_PHRASE_MATCH)
		ss << "FL_PHRASE_MATCH,";
	if (fuzzy_level & FL_IGNORECASE)
		ss << "FL_IGNORECASE,";
	if (fuzzy_level & FL_IGNORENONSPACE)
		ss << "FL_IGNORE_NON_SPACE,";
	if (fuzzy_level & FL_LOOSE)
		ss << "FL_LOOSE,";
	TAGGED_PROPVAL p2{PROP_TYPE(propval.proptag), propval.pvalue};
	ss << std::hex << proptag << "h," << p2.repr() << "}";
	return std::move(ss).str();
}

std::string RESTRICTION_PROPERTY::repr() const
{
	std::stringstream ss;
	TAGGED_PROPVAL p2{PROP_TYPE(propval.proptag), propval.pvalue};
	ss << "RES_PROP{val(" << std::hex << proptag << "h) " <<
	      relop_repr(relop) << " " << p2.repr() << "}";
	return std::move(ss).str();
}

std::string RESTRICTION_PROPCOMPARE::repr() const
{
	std::stringstream ss;
	ss << "RES_PROPCMP{val(" << std::hex << proptag1 << "h) " <<
	      relop_repr(relop) << " val(" << proptag2 << ")}";
	return std::move(ss).str();
}

std::string RESTRICTION_BITMASK::repr() const
{
	std::stringstream ss;
	ss << "RES_BITMASK{val(" << std::hex << proptag <<
	      "h)&" << mask;
	switch (bitmask_relop) {
	case BMR_EQZ: ss << "h==0}"; break;
	case BMR_NEZ: ss << "h!=0}"; break;
	default: ss << "h..op?}"; break;
	}
	return std::move(ss).str();
}

std::string RESTRICTION_SIZE::repr() const
{
	std::stringstream ss;
	ss << "RES_SIZE{" << relop_repr(relop) << "," << std::hex << proptag <<
	      "h," << std::dec << size << "}";
	return std::move(ss).str();
}

std::string RESTRICTION_EXIST::repr() const
{
	std::stringstream ss;
	ss << "RES_EXIST{" << std::hex << proptag << "h}";
	return std::move(ss).str();
}

std::string RESTRICTION_SUBOBJ::repr() const
{
	std::stringstream ss;
	ss << "RES_SUBOBJ{" << std::hex << subobject << "h," << res.repr() << "}";
	return std::move(ss).str();
}

std::string RESTRICTION_COMMENT::repr() const
{
	return "RES_COMMENT{" + std::to_string(count) + "," +
	       ppropval->repr() + "," + pres->repr() + "}";
}

std::string RESTRICTION_COUNT::repr() const
{
	return "RES_COUNT{" + std::to_string(count) + "," + sub_res.repr() + "}";
}
