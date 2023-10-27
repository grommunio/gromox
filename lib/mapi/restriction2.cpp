// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <fmt/core.h>
#include <libHX/string.h>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

/*
 * We should emit hexnumbers with 0x%x rather than %xh notation.
 * This makes copy-paste to source code easier.
 */

using namespace std::string_view_literals;
using namespace gromox;

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

static std::string apptime_repr(double v)
{
	auto ut = rop_util_nttime_to_unix(apptime_to_nttime_approx(v));
	char buf[80]{};
	auto tm = localtime(&ut);
	if (tm != nullptr)
		strftime(buf, std::size(buf), "~%F %T", tm);
	return fmt::format("{} (raw={})", buf, v);
}

static std::string currency_repr(int64_t v)
{
	auto w = v >= 0 ? v : -v;
	return fmt::format("{}.{:04}", v / 1000, w % 1000);
}

static std::string systime_repr(mapitime_t v)
{
	auto ut = rop_util_nttime_to_unix(v);
	char buf[80]{};
	auto tm = localtime(&ut);
	if (tm != nullptr)
		strftime(buf, std::size(buf), "%FT%T", tm);
	return fmt::format("{} (raw=0x{:x})", buf, v);
}

static std::string ptstring_repr(const char *s, bool verbose)
{
	return !verbose ? fmt::format("[{}]", strlen(s)) :
	       fmt::format("[{}]=\"{}\"", strlen(s), s);
}

std::string BINARY::repr(bool verbose) const
{
	return !verbose ? fmt::format("[{} bytes]", cb) :
	       fmt::format("[{}]=\"{}\"", cb, bin2txt(pv, cb));
}

std::string SVREID::repr(bool verbose) const
{
	if (pbin == nullptr)
		return fmt::format("fid=0x{:x},mid=0x{:x},ins=0x{:x}",
		       folder_id, message_id, instance);
	else if (verbose)
		return bin2hex(pbin->pv, pbin->cb);
	return fmt::format("[{} bytes]", pbin->cb);
}

std::string TAGGED_PROPVAL::value_repr(bool verbose) const
{
	char guidstr[GUIDSTR_SIZE];
	if (proptag & MV_FLAG) {
		auto &xl = *static_cast<const GEN_ARRAY *>(pvalue);
		auto r = fmt::format("[{}]", xl.count);
		if (!verbose)
			return r;
		r += "={";
		switch (PROP_TYPE(proptag)) {
		case PT_MV_SHORT:
			/* using sv to avoid strlen call */
			for (size_t i = 0; i < xl.count; ++i)
				if (xl.shrt[i] == 0)
					r += "0,"sv;
				else
					r += fmt::format("{}/0x{:x},", xl.shrt[i], xl.shrt[i]);
			break;
		case PT_MV_LONG:
			for (size_t i = 0; i < xl.count; ++i)
				if (xl.lng[i] == 0)
					r += "0,"sv;
				else
					r += fmt::format("{}/0x{:x},", xl.lng[i], xl.lng[i]);
			break;
		case PT_MV_FLOAT:
			for (size_t i = 0; i < xl.count; ++i)
				if (xl.flt[i] == 0)
					r += "0,"sv;
				else
					r += std::to_string(xl.flt[i]) + ",";
			break;
		case PT_MV_DOUBLE:
			for (size_t i = 0; i < xl.count; ++i)
				if (xl.dbl[i] == 0)
					r += "0,"sv;
				else
					r += std::to_string(xl.dbl[i]) + ",";
			break;
		case PT_MV_APPTIME:
			for (size_t i = 0; i < xl.count; ++i)
				r += apptime_repr(xl.dbl[i]) + ",";
			break;
		case PT_MV_CURRENCY:
			for (size_t i = 0; i < xl.count; ++i)
				if (xl.llng[i] == 0)
					r += "0,"sv;
				else
					r += currency_repr(xl.llng[i]) + ",";
			break;
		case PT_MV_I8:
			for (size_t i = 0; i < xl.count; ++i)
				if (xl.llng[i] == 0)
					r += "0,"sv;
				else
					r += fmt::format("{}/0x{:x},", xl.llng[i], xl.llng[i]);
			break;
		case PT_MV_SYSTIME:
			for (size_t i = 0; i < xl.count; ++i)
				r += systime_repr(xl.llng[i]) + ",";
			break;
		case PT_MV_BINARY:
			for (size_t i = 0; i < xl.count; ++i)
				r += xl.bin[i].repr(verbose) + ",";
			break;
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
			for (size_t i = 0; i < xl.count; ++i)
				r += ptstring_repr(xl.str[i], verbose) + ",";
			break;
		case PT_MV_CLSID:
			for (size_t i = 0; i < xl.count; ++i) {
				xl.guid[i].to_str(guidstr, std::size(guidstr));
				r += guidstr;
				r += ",";
			}
			break;
		default:
			r += fmt::format("<unrecognized proptype {:x}>", PROP_TYPE(proptag));
			break;
		}
		r += "}";
		return r;
	}
	switch (PROP_TYPE(proptag)) {
	case PT_UNSPECIFIED:
	case PT_NULL:
		return {};
	case PT_SHORT: {
		auto v = *static_cast<int16_t *>(pvalue);
		return fmt::format("{}/0x{:x}", v, v);
	}
	case PT_LONG: {
		auto v = *static_cast<int32_t *>(pvalue);
		return fmt::format("{}/0x{:x}", v, v);
	}
	case PT_FLOAT:
		return std::to_string(*static_cast<float *>(pvalue));
	case PT_DOUBLE:
		return std::to_string(*static_cast<double *>(pvalue));
	case PT_APPTIME:
		return apptime_repr(*static_cast<double *>(pvalue));
	case PT_CURRENCY:
		return currency_repr(*static_cast<int64_t *>(pvalue));
	case PT_BOOLEAN:
		static constexpr char bs[2][6] = {"false", "true"};
		return bs[*static_cast<uint8_t *>(pvalue)];
		break;
	case PT_I8: {
		auto v = *static_cast<int64_t *>(pvalue);
		return fmt::format("{}/0x{:x}", v, v);
	}
	case PT_STRING8:
	case PT_UNICODE:
		return ptstring_repr(static_cast<const char *>(pvalue), verbose);
	case PT_SYSTIME:
		return systime_repr(*static_cast<mapitime_t *>(pvalue));
	case PT_CLSID:
		static_cast<GUID *>(pvalue)->to_str(guidstr, std::size(guidstr));
		return guidstr;
	case PT_BINARY:
		return static_cast<const BINARY *>(pvalue)->repr(verbose);
	case PT_SVREID:
		return static_cast<const SVREID *>(pvalue)->repr(verbose);
	default:
		return fmt::format("<<undecodable {:x}>>", proptag);
	}
}

std::string TAGGED_PROPVAL::type_repr() const
{
	#define E(s) case (s): return #s;
	switch (PROP_TYPE(proptag)) {
	E(PT_SHORT)
	E(PT_LONG)
	E(PT_FLOAT)
	E(PT_DOUBLE)
	E(PT_APPTIME)
	E(PT_CURRENCY)
	E(PT_BOOLEAN)
	E(PT_I8)
	E(PT_STRING8)
	E(PT_UNICODE)
	E(PT_SYSTIME)
	E(PT_CLSID)
	E(PT_BINARY)
	E(PT_SVREID)
	default:
		return fmt::format("PT_{:04x}h", PROP_TYPE(proptag));
	}
	#undef E
}

std::string TAGGED_PROPVAL::repr(bool verbose) const
{
	return type_repr() + "{" + value_repr(verbose) + "}";
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
	case RES_ANNOTATION:     return "RES_ANNOTATION{}";
	case RES_NULL:           return "RES_NULL{}";
	default:                 return "RES_??{}";
	}
}

std::string RESTRICTION_AND_OR::repr() const
{
	auto s = std::to_string(count);
	for (size_t i = 0; i < count; ++i)
		s += "," + pres[i].repr();
	return "RES_AOR[" + std::to_string(count) + "]{" + std::move(s) + "}";
}

std::string RESTRICTION_NOT::repr() const
{
	return "RES_NOT{" + res.repr() + "}";
}

bool RESTRICTION_CONTENT::comparable() const
{
	auto l = PROP_TYPE(proptag);
	auto r = PROP_TYPE(propval.proptag);
	if (l == PT_UNICODE || l == PT_STRING8)
		return r == PT_UNICODE || r == PT_STRING8;
	return l == r && l == PT_BINARY;
}

bool RESTRICTION_CONTENT::eval(const void *dbval) const
{
	if (dbval == nullptr)
		return false;
	if (PROP_TYPE(proptag) == PT_BINARY) {
		auto &lhs = *static_cast<const BINARY *>(dbval);
		auto &rhs = *static_cast<const BINARY *>(propval.pvalue);
		switch (fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			return lhs.cb == rhs.cb && memcmp(lhs.pv, rhs.pv, rhs.cb) == 0;
		case FL_SUBSTRING:
			return HX_memmem(lhs.pv, lhs.cb, rhs.pv, rhs.cb) != nullptr;
		case FL_PREFIX:
			return lhs.cb >= rhs.cb && memcmp(lhs.pv, rhs.pv, rhs.cb) == 0;
		}
		return false;
	}
	auto lhs = static_cast<const char *>(dbval);
	auto rhs = static_cast<const char *>(propval.pvalue);
	bool icase = fuzzy_level & (FL_IGNORECASE | FL_LOOSE);
	switch (fuzzy_level & 0xFFFF) {
	case FL_FULLSTRING:
		return icase ? strcasecmp(lhs, rhs) == 0 : strcmp(lhs, rhs) == 0;
	case FL_SUBSTRING:
		return icase ? strcasestr(lhs, rhs) != nullptr :
		       strstr(lhs, rhs) != nullptr;
	case FL_PREFIX: {
		auto len = strlen(rhs);
		return icase ? strncasecmp(lhs, rhs, len) == 0 :
		       strncmp(lhs, rhs, len) == 0;
	}
	}
	return false;
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

bool RESTRICTION_PROPERTY::comparable() const
{
	/*
	 * The LHS of a RES_PROPERTY specifies a property, while the RHS is an
	 * immediate. To evaluate a multivalue LHS against a scalar RHS, use a
	 * RES_CONTENT instead (with limitations). To evaluate a scalar LHS
	 * against a multivalue RHS, use RES_OR instead. EXC2019 refuses
	 * comparisons with any multivalue RHS.
	 */
	auto l = PROP_TYPE(proptag);
	auto r = PROP_TYPE(propval.proptag);
	if (l == PT_UNICODE || l == PT_STRING8)
		return r == PT_UNICODE || r == PT_STRING8;
	if (l == PT_MV_UNICODE || l == PT_MV_STRING8)
		return r == PT_MV_UNICODE || r == PT_MV_STRING8;
	return l == r;
}

bool RESTRICTION_PROPERTY::eval(const void *dbval) const
{
	return propval_compare_relop_nullok(relop, PROP_TYPE(proptag),
	       dbval, propval.pvalue);
}

std::string RESTRICTION_PROPERTY::repr() const
{
	std::stringstream ss;
	TAGGED_PROPVAL p2{PROP_TYPE(propval.proptag), propval.pvalue};
	ss << "RES_PROP{val(" << std::hex << proptag << "h) " <<
	      relop_repr(relop) << " " << p2.repr() << "}";
	return std::move(ss).str();
}

bool RESTRICTION_PROPCOMPARE::comparable() const
{
	auto l = PROP_TYPE(proptag1);
	auto r = PROP_TYPE(proptag2);
	if (l == PT_UNICODE || l == PT_STRING8)
		return r == PT_UNICODE || r == PT_STRING8;
	if (l == PT_MV_UNICODE || l == PT_MV_STRING8)
		return r == PT_MV_UNICODE || r == PT_MV_STRING8;
	return l == r;
}

std::string RESTRICTION_PROPCOMPARE::repr() const
{
	std::stringstream ss;
	ss << "RES_PROPCMP{val(" << std::hex << proptag1 << "h) " <<
	      relop_repr(relop) << " val(" << proptag2 << ")}";
	return std::move(ss).str();
}

bool RESTRICTION_BITMASK::eval(const void *v) const
{
	/*
	 * (EXC2019) Run similar to propval_compare_relop_nullok;
	 * absent values are treated like 0.
	 */
	auto w = v != nullptr ? *static_cast<const uint32_t *>(v) : 0;
	return !!(w & mask) == static_cast<uint8_t>(bitmask_relop);
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

bool RESTRICTION_SIZE::eval(const void *v) const
{
	uint32_t vs = v != nullptr ? propval_size(proptag, v) : 0;
	return propval_compare_relop(relop, PT_LONG, &vs, &size);
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
	std::string s = "RES_COMMENT{props[" + std::to_string(count) + "]={";
	for (size_t i = 0; i < count; ++i)
		s += ppropval[i].repr() + ",";
	s += "},res={" + pres->repr() + "}}";
	return s;
}

std::string RESTRICTION_COUNT::repr() const
{
	return "RES_COUNT{" + std::to_string(count) + "," + sub_res.repr() + "}";
}

std::string MOVECOPY_ACTION::repr() const
{
	std::string s = "{same?=" + std::to_string(same_store);
	if (pstore_eid != nullptr) {
		s += ",store={";
		s += bin2hex(pstore_eid, offsetof(STORE_ENTRYID, pserver_name));
		s += "...,";
		s += znul(pstore_eid->pserver_name);
		s += ",";
		s += znul(pstore_eid->pmailbox_dn);
		s += "}";
	}
	if (pfolder_eid == nullptr) {
		s += ",folder=null";
	} else if (same_store) {
		auto &eid = *static_cast<const SVREID *>(pfolder_eid);
		s += ",folder={";
		if (eid.pbin != nullptr) {
			s += "b=";
			s += bin2hex(eid.pbin->pb, eid.pbin->cb);
			s += ",";
		}
		s += "fid=" + fmt::format("0x{:x}", rop_util_get_gc_value(eid.folder_id));
		s += ",mid=" + fmt::format("0x{:x}", rop_util_get_gc_value(eid.message_id));
		s += ",inst=" + std::to_string(eid.instance) + "}";
	} else {
		auto bv = static_cast<const BINARY *>(pfolder_eid);
		s += ",folder=";
		s += bin2hex(bv->pb, bv->cb);
	}
	s += "}";
	return s;
}

std::string RECIPIENT_BLOCK::repr() const
{
	std::string s = "[" + std::to_string(count) + "]={";
	for (size_t i = 0; i < count; ++i)
		s += ppropval[i].repr() + ",";
	s += "}";
	return s;
}

std::string FORWARDDELEGATE_ACTION::repr() const
{
	std::string s = "{[" + std::to_string(count) + "]={";
	for (size_t i = 0; i < count; ++i)
		s += pblock[i].repr() + ",";
	s += "}}";
	return s;
}

std::string ACTION_BLOCK::repr() const
{
	std::string s = "ACTION_BLOCK{";
	switch (type) {
	case OP_MOVE:
		s += "MOVE";
		s += static_cast<const MOVECOPY_ACTION *>(pdata)->repr();
		break;
	case OP_COPY:
		s += "COPY";
		s += static_cast<const MOVECOPY_ACTION *>(pdata)->repr();
		break;
	case OP_REPLY:
		if (flavor & DO_NOT_SEND_TO_ORIGINATOR)
			s += "nooriginator,";
		if (flavor & STOCK_REPLY_TEMPLATE)
			s += "template,";
		s += "REPLY";
		break;
	case OP_OOF_REPLY:
		s += "OOF_REPLY";
		break;
	case OP_DEFER_ACTION:
		s += "DEFER_ACTION{" + std::to_string(length) + " bytes}";
		break;
	case OP_BOUNCE:
		s += "BOUNCE{" + std::to_string(*static_cast<const uint32_t *>(pdata)) + "}";
		break;
	case OP_FORWARD:
		s += (flavor & FWD_PRESERVE_SENDER) ? "keep_from," : "replace_from,";
		s += (flavor & FWD_AS_ATTACHMENT) ? "attach," : "as_is,";
		if (flavor & FWD_DO_NOT_MUNGE_MSG)
			s += "nomunge,";
		if (flavor & FWD_AS_SMS_ALERT)
			s += "sms,";
		s += "FORWARD";
		s += static_cast<const FORWARDDELEGATE_ACTION *>(pdata)->repr();
		break;
	case OP_DELEGATE:
		s += "DELEGATE";
		s += static_cast<const FORWARDDELEGATE_ACTION *>(pdata)->repr();
		break;
	case OP_TAG:
		s += "TAG{" + static_cast<const TAGGED_PROPVAL *>(pdata)->repr() + "}";
		break;
	case OP_DELETE:
		s += "DELETE";
		break;
	case OP_MARK_AS_READ:
		s += "MARK_AS_READ";
		break;
	}
	s += "}";
	return s;
}

std::string RULE_ACTIONS::repr() const
{
	auto s = "RULE_ACTIONS{" + std::to_string(count);
	for (size_t i = 0; i < count; ++i)
		s += "," + pblock[i].repr();
	s += "}";
	return s;
}

std::string SORT_ORDER::repr() const
{
	return fmt::format("SORT_ORDER{{0x{:x},{:d}}}", PROP_TAG(type, propid), table_sort);
}

std::string SORTORDER_SET::repr() const
{
	auto s = "SORTORDER_SET{" + std::to_string(count) + "," +
	         std::to_string(ccategories) + "," +
	         std::to_string(cexpanded);
	for (unsigned int i = 0; i < count; ++i)
		s += "," + psort[i].repr();
	s += "}";
	return s;
}

std::string PROPTAG_ARRAY::repr() const
{
	std::string s = "PROPTAG_ARRAY{";
	for (unsigned int i = 0; i < count; ++i)
		s += fmt::format("0x{:x},", pproptag[i]);
	s += "}";
	return s;
}
