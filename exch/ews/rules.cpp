// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <new>
#include <span>
#include <string_view>
#include <utility>
#include <fmt/format.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "rules.hpp"

using namespace std::string_literals;
using namespace tinyxml2;

namespace gromox::EWS::Rules {

namespace {

struct def {
	const char *name;
	vtype type;
};

}

static constexpr def pred_defs[] = {
	{"Categories", vtype::strings},
	{"ContainsBodyStrings", vtype::strings},
	{"ContainsHeaderStrings", vtype::strings},
	{"ContainsRecipientStrings", vtype::strings},
	{"ContainsSenderStrings", vtype::strings},
	{"ContainsSubjectOrBodyStrings", vtype::strings},
	{"ContainsSubjectStrings", vtype::strings},
	{"FlaggedForAction", vtype::flag},
	{"FromAddresses", vtype::addresses},
	{"FromConnectedAccounts", vtype::strings},
	{"HasAttachments", vtype::boolean},
	{"Importance", vtype::importance},
	{"IsApprovalRequest", vtype::boolean},
	{"IsAutomaticForward", vtype::boolean},
	{"IsAutomaticReply", vtype::boolean},
	{"IsEncrypted", vtype::boolean},
	{"IsMeetingRequest", vtype::boolean},
	{"IsMeetingResponse", vtype::boolean},
	{"IsNDR", vtype::boolean},
	{"IsPermissionControlled", vtype::boolean},
	{"IsReadReceipt", vtype::boolean},
	{"IsSigned", vtype::boolean},
	{"IsVoicemail", vtype::boolean},
	{"ItemClasses", vtype::strings},
	{"MessageClassifications", vtype::strings},
	{"NotSentToMe", vtype::boolean},
	{"SentCcMe", vtype::boolean},
	{"SentOnlyToMe", vtype::boolean},
	{"SentToAddresses", vtype::addresses},
	{"SentToMe", vtype::boolean},
	{"SentToOrCcMe", vtype::boolean},
	{"Sensitivity", vtype::sensitivity},
	{"WithinDateRange", vtype::date_range},
	{"WithinSizeRange", vtype::size_range},
};
static_assert(std::size(pred_defs) == P_COUNT);

static constexpr def act_defs[] = {
	{"AssignCategories", vtype::strings},
	{"CopyToFolder", vtype::folder},
	{"Delete", vtype::boolean},
	{"ForwardAsAttachmentToRecipients", vtype::addresses},
	{"ForwardToRecipients", vtype::addresses},
	{"MarkImportance", vtype::importance},
	{"MarkAsRead", vtype::boolean},
	{"MoveToFolder", vtype::folder},
	{"PermanentDelete", vtype::boolean},
	{"RedirectToRecipients", vtype::addresses},
	{"SendSMSAlertToRecipients", vtype::addresses},
	{"ServerReplyWithMessage", vtype::item},
	{"StopProcessingRules", vtype::boolean},
};
static_assert(std::size(act_defs) == A_COUNT);

/* t:FlaggedForActionType and the PidLidFlagRequest text Outlook uses */
static constexpr std::pair<const char *, const char *> flag_texts[] = {
	{"Call", "Call"},
	{"DoNotForward", "Do not Forward"},
	{"FollowUp", "Follow up"},
	{"FYI", "For Your Information"},
	{"Forward", "Forward"},
	{"NoResponseNecessary", "No Response Necessary"},
	{"Read", "Read"},
	{"Reply", "Reply"},
	{"ReplyToAll", "Reply to All"},
	{"Review", "Review"},
};
static constexpr const char *importance_names[] = {"Low", "Normal", "High"};
static constexpr const char *sensitivity_names[] = {"Normal", "Personal", "Private", "Confidential"};

const char *pred_name(unsigned int k) { return pred_defs[k].name; }
const char *act_name(unsigned int k) { return act_defs[k].name; }
vtype pred_type(unsigned int k) { return pred_defs[k].type; }
vtype act_type(unsigned int k) { return act_defs[k].type; }

bool Predicates::empty() const
{
	return std::none_of(v.begin(), v.end(),
	       [](const auto &x) { return x.has_value(); });
}

std::string encode_rule_id(uint64_t id)
{
	char raw[8];
	for (unsigned int i = 0; i < 8; ++i)
		raw[i] = static_cast<char>(id >> (8 * i));
	return base64_encode({raw, sizeof(raw)});
}

std::optional<uint64_t> decode_rule_id(const std::string &s)
{
	std::string raw;
	try {
		raw = base64_decode(s);
	} catch (const std::exception &) {
		return std::nullopt;
	}
	if (raw.size() != 8)
		return std::nullopt;
	uint64_t id = 0;
	for (unsigned int i = 0; i < 8; ++i)
		id |= static_cast<uint64_t>(static_cast<uint8_t>(raw[i])) << (8 * i);
	return id;
}

/*
 * XML input. The SOAP layer has already stripped the namespace prefixes.
 */

static const char *xtext(const XMLElement *e)
{
	auto t = e->GetText();
	return t != nullptr ? t : "";
}

static bool xbool(const XMLElement *e)
{
	std::string_view t = xtext(e);
	if (t == "true" || t == "1")
		return true;
	if (t == "false" || t == "0")
		return false;
	throw ParseError(fmt::format("invalid boolean in {}", e->Name()));
}

static int32_t xint(const XMLElement *e)
{
	int v = 0;
	if (e->QueryIntText(&v) != XML_SUCCESS)
		throw ParseError(fmt::format("invalid integer in {}", e->Name()));
	return v;
}

static time_t xtime(const XMLElement *e)
{
	tm t{};
	double sec = 0;
	int tzh = 0, tzm = 0;
	if (sscanf(xtext(e), "%4d-%02d-%02dT%02d:%02d:%lf%03d:%02d",
	    &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min,
	    &sec, &tzh, &tzm) < 3)
		throw ParseError(fmt::format("invalid date in {}", e->Name()));
	t.tm_year -= 1900;
	t.tm_mon -= 1;
	t.tm_sec = static_cast<int>(sec);
	t.tm_hour -= tzh;
	t.tm_min -= tzh < 0 ? -tzm : tzm;
	auto ts = timegm(&t);
	if (ts == static_cast<time_t>(-1))
		throw ParseError(fmt::format("invalid date in {}", e->Name()));
	return ts;
}

static std::string xenum(const XMLElement *e, std::span<const char *const> names)
{
	std::string t = xtext(e);
	if (std::find_if(names.begin(), names.end(), [&](const char *n) { return t == n; }) == names.end())
		throw ParseError(fmt::format("invalid value \"{}\" in {}", t, e->Name()));
	return t;
}

static std::vector<std::string> xstrings(const XMLElement *e)
{
	std::vector<std::string> out;
	for (auto c = e->FirstChildElement("String"); c != nullptr;
	     c = c->NextSiblingElement("String"))
		out.emplace_back(xtext(c));
	return out;
}

static std::vector<Address> xaddresses(const XMLElement *e)
{
	std::vector<Address> out;
	for (auto c = e->FirstChildElement("Address"); c != nullptr;
	     c = c->NextSiblingElement("Address")) {
		Address a;
		if (auto x = c->FirstChildElement("Name"))
			a.name = xtext(x);
		if (auto x = c->FirstChildElement("EmailAddress"))
			a.email = xtext(x);
		if (auto x = c->FirstChildElement("RoutingType"))
			a.routing = xtext(x);
		out.push_back(std::move(a));
	}
	return out;
}

static FolderRef xfolder(const XMLElement *e)
{
	FolderRef f;
	if (auto c = e->FirstChildElement("FolderId")) {
		f.id = c->Attribute("Id") != nullptr ? c->Attribute("Id") : "";
		if (c->Attribute("ChangeKey") != nullptr)
			f.change_key = c->Attribute("ChangeKey");
		return f;
	}
	if (auto c = e->FirstChildElement("DistinguishedFolderId")) {
		f.distinguished = true;
		f.id = c->Attribute("Id") != nullptr ? c->Attribute("Id") : "";
		if (auto m = c->FirstChildElement("Mailbox"))
			if (auto a = m->FirstChildElement("EmailAddress"))
				f.mailbox = xtext(a);
		return f;
	}
	throw ParseError(fmt::format("{} lacks a folder id", e->Name()));
}

static Value xvalue(vtype type, const XMLElement *e)
{
	Value v;
	switch (type) {
	case vtype::strings: v.strings = xstrings(e); break;
	case vtype::addresses: v.addrs = xaddresses(e); break;
	case vtype::boolean: v.flag = xbool(e); break;
	case vtype::flag: {
		std::string t = xtext(e);
		if (t != "Any" && std::none_of(std::begin(flag_texts), std::end(flag_texts),
		    [&](const auto &p) { return t == p.first; }))
			throw ParseError(fmt::format("invalid value \"{}\" in {}", t, e->Name()));
		v.text = std::move(t);
		break;
	}
	case vtype::importance: v.text = xenum(e, importance_names); break;
	case vtype::sensitivity: v.text = xenum(e, sensitivity_names); break;
	case vtype::date_range:
		if (auto c = e->FirstChildElement("StartDateTime"))
			v.start = xtime(c);
		if (auto c = e->FirstChildElement("EndDateTime"))
			v.end = xtime(c);
		break;
	case vtype::size_range:
		if (auto c = e->FirstChildElement("MinimumSize"))
			v.min = xint(c);
		if (auto c = e->FirstChildElement("MaximumSize"))
			v.max = xint(c);
		break;
	case vtype::folder: v.folder = xfolder(e); break;
	case vtype::item:
		v.item.id = e->Attribute("Id") != nullptr ? e->Attribute("Id") : "";
		if (e->Attribute("ChangeKey") != nullptr)
			v.item.change_key = e->Attribute("ChangeKey");
		break;
	}
	return v;
}

template<typename A, size_t N> static void
xgroup(const XMLElement *e, A &arr, const def (&defs)[N])
{
	for (auto c = e->FirstChildElement(); c != nullptr; c = c->NextSiblingElement()) {
		auto it = std::find_if(std::begin(defs), std::end(defs),
		          [&](const def &d) { return strcmp(d.name, c->Name()) == 0; });
		if (it == std::end(defs))
			throw ParseError(fmt::format("unknown element {} in {}", c->Name(), e->Name()));
		arr[it - std::begin(defs)] = xvalue(it->type, c);
	}
}

Rule parse_rule(const XMLElement *e)
{
	Rule r;
	bool have_name = false, have_prio = false, have_enabled = false;
	for (auto c = e->FirstChildElement(); c != nullptr; c = c->NextSiblingElement()) {
		std::string_view n = c->Name();
		if (n == "RuleId") {
			r.id.emplace(xtext(c));
		} else if (n == "DisplayName") {
			r.name = xtext(c);
			have_name = true;
		} else if (n == "Priority") {
			r.priority = xint(c);
			have_prio = true;
		} else if (n == "IsEnabled") {
			r.enabled = xbool(c);
			have_enabled = true;
		} else if (n == "IsNotSupported") {
			r.not_supported = xbool(c);
		} else if (n == "IsInError") {
			r.in_error = xbool(c);
		} else if (n == "Conditions") {
			xgroup(c, r.conditions.v, pred_defs);
		} else if (n == "Exceptions") {
			xgroup(c, r.exceptions.v, pred_defs);
		} else if (n == "Actions") {
			xgroup(c, r.actions.v, act_defs);
		} else {
			throw ParseError(fmt::format("unknown element {} in Rule", n));
		}
	}
	if (!have_name || !have_prio || !have_enabled)
		throw ParseError("Rule requires DisplayName, Priority and IsEnabled");
	return r;
}

std::vector<Operation> parse_operations(const XMLElement *e)
{
	std::vector<Operation> ops;
	for (auto c = e->FirstChildElement(); c != nullptr; c = c->NextSiblingElement()) {
		std::string_view n = c->Name();
		Operation op;
		if (n == "DeleteRuleOperation") {
			op.kind = Operation::DELETE;
			auto id = c->FirstChildElement("RuleId");
			if (id == nullptr)
				throw ParseError("DeleteRuleOperation lacks RuleId");
			op.rule_id = xtext(id);
			ops.push_back(std::move(op));
			continue;
		}
		if (n == "CreateRuleOperation")
			op.kind = Operation::CREATE;
		else if (n == "SetRuleOperation")
			op.kind = Operation::SET;
		else
			throw ParseError(fmt::format("unknown operation {}", n));
		auto rule = c->FirstChildElement("Rule");
		if (rule == nullptr)
			throw ParseError(fmt::format("{} lacks Rule", n));
		op.rule = parse_rule(rule);
		ops.push_back(std::move(op));
	}
	return ops;
}

/*
 * XML output, types namespace
 */

static XMLElement *xput(XMLElement *parent, const char *name)
{
	return parent->InsertNewChildElement(("t:"s + name).c_str());
}

static XMLElement *xput(XMLElement *parent, const char *name, const std::string &text)
{
	auto e = xput(parent, name);
	std::string f = text;
	utf8_filter(f.data());
	f.resize(strlen(f.c_str()));
	e->SetText(f.c_str());
	return e;
}

static void xput(XMLElement *parent, const char *name, bool v)
{
	xput(parent, name)->SetText(v ? "true" : "false");
}

static void xput_time(XMLElement *parent, const char *name, time_t ts)
{
	tm t{};
	gmtime_r(&ts, &t);
	char buf[32];
	strftime(buf, std::size(buf), "%FT%TZ", &t);
	xput(parent, name)->SetText(buf);
}

static void xput_value(XMLElement *e, vtype type, const Value &v)
{
	switch (type) {
	case vtype::strings:
		for (const auto &s : v.strings)
			xput(e, "String", s);
		break;
	case vtype::addresses:
		for (const auto &a : v.addrs) {
			auto x = xput(e, "Address");
			if (!a.name.empty())
				xput(x, "Name", a.name);
			xput(x, "EmailAddress", a.email);
			xput(x, "RoutingType", a.routing.empty() ? "SMTP"s : a.routing);
		}
		break;
	case vtype::boolean:
		e->SetText(v.flag ? "true" : "false");
		break;
	case vtype::flag:
	case vtype::importance:
	case vtype::sensitivity:
		e->SetText(v.text.c_str());
		break;
	case vtype::date_range:
		if (v.start)
			xput_time(e, "StartDateTime", *v.start);
		if (v.end)
			xput_time(e, "EndDateTime", *v.end);
		break;
	case vtype::size_range:
		if (v.min)
			xput(e, "MinimumSize")->SetText(*v.min);
		if (v.max)
			xput(e, "MaximumSize")->SetText(*v.max);
		break;
	case vtype::folder: {
		auto x = xput(e, v.folder.distinguished ? "DistinguishedFolderId" : "FolderId");
		x->SetAttribute("Id", v.folder.id.c_str());
		if (!v.folder.change_key.empty())
			x->SetAttribute("ChangeKey", v.folder.change_key.c_str());
		break;
	}
	case vtype::item:
		e->SetAttribute("Id", v.item.id.c_str());
		if (!v.item.change_key.empty())
			e->SetAttribute("ChangeKey", v.item.change_key.c_str());
		break;
	}
}

template<typename A, size_t N> static void
xput_group(XMLElement *parent, const char *name, const A &arr, const def (&defs)[N])
{
	if (std::none_of(arr.begin(), arr.end(), [](const auto &x) { return x.has_value(); }))
		return;
	auto e = xput(parent, name);
	for (size_t i = 0; i < N; ++i)
		if (arr[i])
			xput_value(xput(e, defs[i].name), defs[i].type, *arr[i]);
}

void write_rule(XMLElement *parent, const Rule &r)
{
	auto e = xput(parent, "Rule");
	if (r.id)
		xput(e, "RuleId", *r.id);
	xput(e, "DisplayName", r.name);
	xput(e, "Priority")->SetText(r.priority);
	xput(e, "IsEnabled", r.enabled);
	if (r.not_supported.value_or(false))
		xput(e, "IsNotSupported", true);
	if (r.in_error.value_or(false))
		xput(e, "IsInError", true);
	xput_group(e, "Conditions", r.conditions.v, pred_defs);
	xput_group(e, "Exceptions", r.exceptions.v, pred_defs);
	xput_group(e, "Actions", r.actions.v, act_defs);
}

void write_errors(XMLElement *parent, const std::vector<OperationError> &errs)
{
	if (errs.empty())
		return;
	auto list = parent->InsertNewChildElement("m:RuleOperationErrors");
	for (const auto &oe : errs) {
		auto x = xput(list, "RuleOperationError");
		xput(x, "OperationIndex")->SetText(oe.index);
		auto ve = xput(x, "ValidationErrors");
		for (const auto &err : oe.errors) {
			auto y = xput(ve, "Error");
			xput(y, "FieldURI", err.field);
			xput(y, "ErrorCode", err.code);
			xput(y, "ErrorMessage", err.message);
			xput(y, "FieldValue", err.value);
		}
	}
}

/*
 * Common restriction helpers
 */

static bool is_str_type(uint16_t t)
{
	return t == PT_UNICODE || t == PT_STRING8;
}

/* Same property, string types treated as one */
static bool same_tag(proptag_t a, proptag_t b)
{
	if (a == b)
		return true;
	if (PROP_ID(a) != PROP_ID(b))
		return false;
	auto ta = PROP_TYPE(a), tb = PROP_TYPE(b);
	return (is_str_type(ta) && is_str_type(tb)) ||
	       (is_str_type(ta & ~MV_FLAG) && is_str_type(tb & ~MV_FLAG) &&
	       (ta & MV_FLAG) == (tb & MV_FLAG));
}

static std::string upper(std::string s)
{
	for (auto &c : s)
		c = HX_toupper(c);
	return s;
}

static std::string lower(std::string s)
{
	for (auto &c : s)
		c = HX_tolower(c);
	return s;
}

static constexpr char OOF_TPL_CLASS[] = "IPM.Note.Rules.OofTemplate.Microsoft";

/*
 * Message class predicates, written as RES_CONTENT FL_PREFIX|FL_IGNORECASE
 * on PR_MESSAGE_CLASS unless noted.
 */
static constexpr std::pair<pred_kind, const char *> class_prefixes[] = {
	{P_IsApprovalRequest, "IPM.Note.Microsoft.Approval.Request"},
	{P_IsMeetingResponse, "IPM.Schedule.Meeting.Resp."},
	{P_IsPermissionControlled, "IPM.Note.rpmsg."},
	{P_IsReadReceipt, "REPORT.IPM.Note.IPNRN"},
	{P_IsSigned, "IPM.Note.SMIME.MultipartSigned"},
	{P_IsVoicemail, "IPM.Note.Microsoft.Voicemail"},
};

/*
 * The OP_DEFER_ACTION payload grommunio-web stores when a rule has no other
 * action, the XR_Begin element of an Outlook rule stream.
 */
static constexpr uint8_t web_default_dam[] = {
	0xe0, 0xc8, 0x10, 0x00, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x02, 0x00, 0xff, 0xff, 0x00,
	0x00, 0x0c, 0x00, 0x43, 0x52, 0x75, 0x6c, 0x65, 0x45, 0x6c, 0x65, 0x6d,
	0x65, 0x6e, 0x74, 0x90, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0x64, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00,
};

bool is_visible(const TPROPVAL_ARRAY &row)
{
	auto p = row.get<const char>(PR_RULE_PROVIDER);
	return p != nullptr && strncasecmp(p, "RuleOrganizer", 13) == 0;
}

/*
 * Read side: turn any stored rule back into predicates and actions. What
 * does not map sets IsNotSupported, the remainder is still returned.
 */
namespace {

struct reader {
	reader(Env &e, Rule &r) : env(e), rule(r) {}
	bool pred(const RESTRICTION &, Predicates &);
	void item(const RESTRICTION &);
	void top(const RESTRICTION &);
	void action(const ACTION_BLOCK &);

	private:
	bool strings(const RESTRICTION &, Predicates &);
	bool addresses(const RESTRICTION &, Predicates &);
	bool flags(const RESTRICTION &, Predicates &);
	bool classes(const RESTRICTION &, Predicates &);
	bool ranges(const RESTRICTION &, Predicates &);
	bool recipients(const FORWARDDELEGATE_ACTION &, std::vector<Address> &);
	std::optional<Address> srchkey_addr(const RESTRICTION &, proptag_t);
	void set(Predicates &, pred_kind, Value &&);

	Env &env;
	Rule &rule;
	uint16_t kw = 0, fr = 0;
	bool kw_done = false, fr_done = false;

	public:
	uint16_t keywords() {
		if (!kw_done) {
			kw = env.keywords_propid(false);
			kw_done = true;
		}
		return kw;
	}
	uint16_t flagrequest() {
		if (!fr_done) {
			fr = env.flagrequest_propid(false);
			fr_done = true;
		}
		return fr;
	}
	void unsupported() { rule.not_supported = true; }
};

}

static const char *pv_str(const TAGGED_PROPVAL &pv)
{
	return is_str_type(PROP_TYPE(pv.proptag)) ? static_cast<const char *>(pv.pvalue) : nullptr;
}

/* RES_CONTENT of a string on @tag, returns the needle */
static const char *content_str(const RESTRICTION &r, proptag_t tag, unsigned int fl)
{
	if (r.rt != RES_CONTENT || !same_tag(r.cont->proptag, tag) ||
	    (r.cont->fuzzy_level & 0xffff) != fl)
		return nullptr;
	return pv_str(r.cont->propval);
}

static const BINARY *content_bin(const RESTRICTION &r, proptag_t tag)
{
	if (r.rt != RES_CONTENT || r.cont->proptag != tag ||
	    PROP_TYPE(r.cont->propval.proptag) != PT_BINARY ||
	    (r.cont->fuzzy_level & 0xffff) != FL_SUBSTRING)
		return nullptr;
	return static_cast<const BINARY *>(r.cont->propval.pvalue);
}

static const void *prop_eq(const RESTRICTION &r, proptag_t tag)
{
	if (r.rt != RES_PROPERTY || r.prop->relop != RELOP_EQ ||
	    !same_tag(r.prop->proptag, tag))
		return nullptr;
	return r.prop->propval.pvalue;
}

static std::optional<bool> prop_bool(const RESTRICTION &r, proptag_t tag)
{
	auto v = static_cast<const uint8_t *>(prop_eq(r, tag));
	if (v == nullptr)
		return std::nullopt;
	return *v != 0;
}

static const char *prop_str(const RESTRICTION &r, proptag_t tag)
{
	if (r.rt != RES_PROPERTY || r.prop->relop != RELOP_EQ ||
	    !same_tag(r.prop->proptag, tag))
		return nullptr;
	return pv_str(r.prop->propval);
}

static std::string bin_str(const BINARY &b)
{
	std::string s(b.pc != nullptr ? b.pc : "", b.cb);
	while (!s.empty() && s.back() == '\0')
		s.pop_back();
	return s;
}

/* Collect one needle per leaf, from a single leaf or a RES_OR of leaves */
template<typename F> static std::optional<std::vector<std::string>>
collect(const RESTRICTION &r, F &&leaf)
{
	std::vector<std::string> out;
	if (r.rt != RES_OR) {
		auto s = leaf(r);
		if (!s)
			return std::nullopt;
		out.push_back(std::move(*s));
		return out;
	}
	if (r.andor->count == 0)
		return std::nullopt;
	for (const auto &c : *r.andor) {
		auto s = leaf(c);
		if (!s)
			return std::nullopt;
		out.push_back(std::move(*s));
	}
	return out;
}

void reader::set(Predicates &p, pred_kind k, Value &&v)
{
	auto &slot = p.v[k];
	if (!slot) {
		slot = std::move(v);
		return;
	}
	switch (pred_type(k)) {
	case vtype::boolean:
		return;
	case vtype::date_range:
		if ((v.start && slot->start) || (v.end && slot->end))
			break;
		if (v.start)
			slot->start = v.start;
		if (v.end)
			slot->end = v.end;
		return;
	case vtype::size_range:
		if ((v.min && slot->min) || (v.max && slot->max))
			break;
		if (v.min)
			slot->min = v.min;
		if (v.max)
			slot->max = v.max;
		return;
	default:
		break;
	}
	/* Two separate predicates of one kind are AND'ed, EWS cannot say that */
	unsupported();
}

bool reader::strings(const RESTRICTION &r, Predicates &p)
{
	using svec = std::optional<std::string>;
	auto by_tag = [](proptag_t tag) {
		return [tag](const RESTRICTION &x) -> svec {
			auto s = content_str(x, tag, FL_SUBSTRING);
			return s != nullptr ? svec(s) : std::nullopt;
		};
	};
	static constexpr std::pair<pred_kind, proptag_t> simple[] = {
		{P_ContainsBodyStrings, PR_BODY},
		{P_ContainsHeaderStrings, PR_TRANSPORT_MESSAGE_HEADERS},
		{P_ContainsSubjectStrings, PR_SUBJECT},
	};
	for (const auto &[kind, tag] : simple) {
		auto v = collect(r, by_tag(tag));
		if (v) {
			set(p, kind, Value{.strings = std::move(*v)});
			return true;
		}
	}
	if (auto k = keywords(); k != 0) {
		auto v = collect(r, [k](const RESTRICTION &x) -> svec {
			if (x.rt != RES_CONTENT || PROP_ID(x.cont->proptag) != k ||
			    !is_str_type(PROP_TYPE(x.cont->proptag) & ~MV_FLAG))
				return std::nullopt;
			auto s = pv_str(x.cont->propval);
			return s != nullptr ? svec(s) : std::nullopt;
		});
		if (v) {
			set(p, P_Categories, Value{.strings = std::move(*v)});
			return true;
		}
	}
	/* Binary search key needles, written upper-cased */
	auto v = collect(r, [](const RESTRICTION &x) -> svec {
		auto b = content_bin(x, PR_SENDER_SEARCH_KEY);
		return b != nullptr ? svec(bin_str(*b)) : std::nullopt;
	});
	if (v) {
		set(p, P_ContainsSenderStrings, Value{.strings = std::move(*v)});
		return true;
	}
	v = collect(r, [](const RESTRICTION &x) -> svec {
		if (auto b = content_bin(x, PR_SEARCH_KEY))
			return bin_str(*b);
		if (x.rt != RES_SUBRESTRICTION || x.sub->subobject != PR_MESSAGE_RECIPIENTS)
			return std::nullopt;
		for (auto tag : {PR_SMTP_ADDRESS, PR_EMAIL_ADDRESS, PR_DISPLAY_NAME})
			if (auto s = content_str(x.sub->res, tag, FL_SUBSTRING))
				return s;
		return std::nullopt;
	});
	if (v) {
		set(p, P_ContainsRecipientStrings, Value{.strings = std::move(*v)});
		return true;
	}
	/* Subject-or-body: one RES_OR holding subject/body pairs */
	if (r.rt == RES_OR && r.andor->count > 0 && r.andor->count % 2 == 0) {
		std::vector<std::string> out;
		bool ok = true;
		for (size_t i = 0; ok && i < r.andor->count; i += 2) {
			auto s = content_str(r.andor->pres[i], PR_SUBJECT, FL_SUBSTRING);
			auto b = content_str(r.andor->pres[i+1], PR_BODY, FL_SUBSTRING);
			ok = s != nullptr && b != nullptr && strcmp(s, b) == 0;
			if (ok)
				out.emplace_back(s);
		}
		if (ok) {
			set(p, P_ContainsSubjectOrBodyStrings, Value{.strings = std::move(out)});
			return true;
		}
	}
	return false;
}

/* Address from a RES_COMMENT{props, RES_PROPERTY(@tag == searchkey)} */
std::optional<Address> reader::srchkey_addr(const RESTRICTION &r, proptag_t tag)
{
	const RESTRICTION *inner = &r;
	const SCommentRestriction *cmt = nullptr;
	if (r.rt == RES_COMMENT) {
		cmt = r.comment;
		if (cmt->pres == nullptr)
			return std::nullopt;
		inner = cmt->pres;
	}
	auto key = static_cast<const BINARY *>(prop_eq(*inner, tag));
	if (key == nullptr || PROP_TYPE(inner->prop->propval.proptag) != PT_BINARY)
		return std::nullopt;
	Address a;
	a.routing = "SMTP";
	auto sk = bin_str(*key);
	if (strncasecmp(sk.c_str(), "SMTP:", 5) == 0)
		a.email = lower(sk.substr(5));
	else if (strncasecmp(sk.c_str(), "EX:", 3) == 0 &&
	    env.essdn_to_smtp(sk.c_str() + 3, a.email))
		;
	else
		return std::nullopt;
	if (cmt != nullptr) {
		for (unsigned int i = 0; i < cmt->count; ++i) {
			auto &pv = cmt->ppropval[i];
			if (PROP_ID(pv.proptag) != 0x0001 || pv_str(pv) == nullptr)
				continue;
			std::string_view d = pv_str(pv);
			auto lt = d.rfind('<');
			if (lt != d.npos && d.back() == '>') {
				auto addr = d.substr(lt + 1, d.size() - lt - 2);
				if (strcasecmp(std::string(addr).c_str(), a.email.c_str()) == 0)
					a.email = addr;
				d = d.substr(0, lt);
				while (!d.empty() && d.back() == ' ')
					d.remove_suffix(1);
				a.name = d;
			} else if (strcasecmp(std::string(d).c_str(), a.email.c_str()) == 0) {
				a.email = d;
			} else {
				a.name = d;
			}
		}
	}
	return a;
}

bool reader::addresses(const RESTRICTION &r, Predicates &p)
{
	auto list = [&](const RESTRICTION &x, auto &&leaf) {
		std::vector<Address> out;
		auto one = [&](const RESTRICTION &y) {
			auto a = leaf(y);
			if (a)
				out.push_back(std::move(*a));
			return a.has_value();
		};
		if (x.rt == RES_OR) {
			if (x.andor->count == 0)
				return out;
			for (const auto &c : *x.andor)
				if (!one(c))
					return std::vector<Address>{};
			return out;
		}
		one(x);
		return out;
	};
	auto from = list(r, [&](const RESTRICTION &y) { return srchkey_addr(y, PR_SENDER_SEARCH_KEY); });
	if (!from.empty()) {
		set(p, P_FromAddresses, Value{.addrs = std::move(from)});
		return true;
	}
	auto to = list(r, [&](const RESTRICTION &y) -> std::optional<Address> {
		if (y.rt == RES_SUBRESTRICTION && y.sub->subobject == PR_MESSAGE_RECIPIENTS)
			return srchkey_addr(y.sub->res, PR_SEARCH_KEY);
		if (y.rt == RES_COMMENT)
			return srchkey_addr(y, PR_SEARCH_KEY);
		return std::nullopt;
	});
	if (!to.empty()) {
		set(p, P_SentToAddresses, Value{.addrs = std::move(to)});
		return true;
	}
	return false;
}

bool reader::flags(const RESTRICTION &r, Predicates &p)
{
	auto yes = Value{.flag = true};
	if (r.rt == RES_BITMASK && r.bm->bitmask_relop == BMR_NEZ &&
	    r.bm->proptag == PR_MESSAGE_FLAGS && r.bm->mask == MSGFLAG_HASATTACH) {
		set(p, P_HasAttachments, std::move(yes));
		return true;
	}
	if (prop_bool(r, PR_HASATTACH).value_or(false)) {
		set(p, P_HasAttachments, std::move(yes));
		return true;
	}
	if (auto v = static_cast<const uint32_t *>(prop_eq(r, PR_IMPORTANCE));
	    v != nullptr && *v < std::size(importance_names)) {
		set(p, P_Importance, Value{.text = importance_names[*v]});
		return true;
	}
	if (auto v = static_cast<const uint32_t *>(prop_eq(r, PR_SENSITIVITY));
	    v != nullptr && *v < std::size(sensitivity_names)) {
		set(p, P_Sensitivity, Value{.text = sensitivity_names[*v]});
		return true;
	}
	if (auto v = prop_bool(r, PR_MESSAGE_TO_ME)) {
		set(p, *v ? P_SentToMe : P_NotSentToMe, std::move(yes));
		return true;
	}
	if (prop_bool(r, PR_MESSAGE_RECIP_ME).value_or(false)) {
		set(p, P_SentToOrCcMe, std::move(yes));
		return true;
	}
	if (prop_bool(r, PR_AUTO_FORWARDED).value_or(false)) {
		set(p, P_IsAutomaticForward, std::move(yes));
		return true;
	}
	if (prop_eq(r, PR_FLAG_STATUS) != nullptr &&
	    *static_cast<const uint32_t *>(prop_eq(r, PR_FLAG_STATUS)) == followupFlagged) {
		set(p, P_FlaggedForAction, Value{.text = "Any"});
		return true;
	}
	if (r.rt != RES_AND)
		return false;
	auto &l = *r.andor;
	if (l.count == 3) {
		/* SentCcMe: CC_ME, RECIP_ME, !TO_ME in any order */
		bool cc = false, rme = false, nto = false;
		for (const auto &c : l) {
			if (prop_bool(c, PR_MESSAGE_CC_ME).value_or(false))
				cc = true;
			else if (prop_bool(c, PR_MESSAGE_RECIP_ME).value_or(false))
				rme = true;
			else if (prop_bool(c, PR_MESSAGE_TO_ME) == false)
				nto = true;
		}
		if (cc && rme && nto) {
			set(p, P_SentCcMe, std::move(yes));
			return true;
		}
		/* SentOnlyToMe: TO_ME, no semicolon in PR_DISPLAY_TO, empty PR_DISPLAY_CC */
		bool to = false, semi = false, nocc = false;
		for (const auto &c : l) {
			if (prop_bool(c, PR_MESSAGE_TO_ME).value_or(false)) {
				to = true;
			} else if (c.rt == RES_NOT) {
				auto s = content_str(c.xnot->res, PR_DISPLAY_TO, FL_SUBSTRING);
				semi = s != nullptr && strcmp(s, ";") == 0;
			} else if (auto s = prop_str(c, PR_DISPLAY_CC)) {
				nocc = *s == '\0';
			}
		}
		if (to && semi && nocc) {
			set(p, P_SentOnlyToMe, std::move(yes));
			return true;
		}
	}
	if (l.count == 2) {
		/* FlaggedForAction with a request text */
		auto st = static_cast<const uint32_t *>(prop_eq(l.pres[0], PR_FLAG_STATUS));
		auto f = flagrequest();
		auto txt = f != 0 ? prop_str(l.pres[1], PROP_TAG(PT_UNICODE, f)) : nullptr;
		if (st != nullptr && *st == followupFlagged && txt != nullptr) {
			auto it = std::find_if(std::begin(flag_texts), std::end(flag_texts),
			          [&](const auto &x) { return strcasecmp(x.second, txt) == 0; });
			if (it == std::end(flag_texts))
				return false;
			set(p, P_FlaggedForAction, Value{.text = it->first});
			return true;
		}
	}
	return false;
}

bool reader::classes(const RESTRICTION &r, Predicates &p)
{
	auto yes = Value{.flag = true};
	if (auto s = content_str(r, PR_MESSAGE_CLASS, FL_PREFIX)) {
		for (const auto &[kind, pfx] : class_prefixes) {
			if (strcasecmp(s, pfx) == 0) {
				set(p, kind, std::move(yes));
				return true;
			}
		}
		return false;
	}
	if (auto s = prop_str(r, PR_MESSAGE_CLASS); s != nullptr &&
	    strcasecmp(s, OOF_TPL_CLASS) == 0) {
		set(p, P_IsAutomaticReply, std::move(yes));
		return true;
	}
	if (r.rt == RES_AND && r.andor->count == 2) {
		auto &a = r.andor->pres[0], &b = r.andor->pres[1];
		auto s1 = content_str(a, PR_MESSAGE_CLASS, FL_PREFIX);
		if (s1 != nullptr && strcasecmp(s1, "IPM.Note.SMIME") == 0 &&
		    b.rt == RES_NOT) {
			auto s2 = content_str(b.xnot->res, PR_MESSAGE_CLASS, FL_PREFIX);
			if (s2 != nullptr && strcasecmp(s2, "IPM.Note.SMIME.MultipartSigned") == 0) {
				set(p, P_IsEncrypted, std::move(yes));
				return true;
			}
		}
		auto s2 = content_str(b, PR_MESSAGE_CLASS, FL_SUBSTRING);
		if (s1 != nullptr && strcasecmp(s1, "REPORT.") == 0 &&
		    s2 != nullptr && strcasecmp(s2, ".NDR") == 0) {
			set(p, P_IsNDR, std::move(yes));
			return true;
		}
	}
	/* Outlook's meeting request shape, full-string content matches */
	if (r.rt == RES_OR && r.andor->count == 2) {
		auto s1 = content_str(r.andor->pres[0], PR_MESSAGE_CLASS, FL_FULLSTRING);
		auto s2 = content_str(r.andor->pres[1], PR_MESSAGE_CLASS, FL_FULLSTRING);
		if (s1 != nullptr && s2 != nullptr &&
		    strcasecmp(s1, "IPM.Schedule.Meeting.Request") == 0 &&
		    strcasecmp(s2, "IPM.Schedule.Meeting.Canceled") == 0) {
			set(p, P_IsMeetingRequest, std::move(yes));
			return true;
		}
	}
	auto v = collect(r, [](const RESTRICTION &x) -> std::optional<std::string> {
		if (auto s = prop_str(x, PR_MESSAGE_CLASS))
			return s;
		if (auto s = content_str(x, PR_MESSAGE_CLASS, FL_FULLSTRING))
			return s;
		return std::nullopt;
	});
	if (v) {
		set(p, P_ItemClasses, Value{.strings = std::move(*v)});
		return true;
	}
	return false;
}

bool reader::ranges(const RESTRICTION &r, Predicates &p)
{
	if (r.rt == RES_AND) {
		Predicates tmp;
		reader sub(env, rule);
		for (const auto &c : *r.andor)
			if (!sub.ranges(c, tmp))
				return false;
		for (auto k : {P_WithinDateRange, P_WithinSizeRange})
			if (tmp.v[k])
				set(p, k, std::move(*tmp.v[k]));
		return true;
	}
	if (r.rt != RES_PROPERTY)
		return false;
	auto &rp = *r.prop;
	auto op = rp.relop;
	bool lower = op == RELOP_GT || op == RELOP_GE;
	bool upper = op == RELOP_LT || op == RELOP_LE;
	if (!lower && !upper)
		return false;
	if (rp.proptag == PR_MESSAGE_DELIVERY_TIME &&
	    PROP_TYPE(rp.propval.proptag) == PT_SYSTIME) {
		auto t = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(rp.propval.pvalue));
		Value v;
		(lower ? v.start : v.end) = t;
		set(p, P_WithinDateRange, std::move(v));
		return true;
	}
	if (rp.proptag == PR_MESSAGE_SIZE && PROP_TYPE(rp.propval.proptag) == PT_LONG) {
		auto kb = static_cast<int32_t>(*static_cast<const uint32_t *>(rp.propval.pvalue) / 1024);
		Value v;
		(lower ? v.min : v.max) = kb;
		set(p, P_WithinSizeRange, std::move(v));
		return true;
	}
	return false;
}

bool reader::pred(const RESTRICTION &r, Predicates &p)
{
	return strings(r, p) || addresses(r, p) || flags(r, p) ||
	       classes(r, p) || ranges(r, p);
}

void reader::item(const RESTRICTION &r)
{
	if (r.rt == RES_EXIST && r.exist->proptag == PR_MESSAGE_CLASS)
		return;
	if (r.rt == RES_NOT) {
		auto &in = r.xnot->res;
		if (pred(in, rule.exceptions))
			return;
		if (in.rt == RES_OR) {
			/* NOT(a OR b) is NOT(a) AND NOT(b) */
			for (const auto &c : *in.andor)
				if (!pred(c, rule.exceptions))
					unsupported();
			return;
		}
		unsupported();
		return;
	}
	if (pred(r, rule.conditions))
		return;
	if (r.rt == RES_AND) {
		for (const auto &c : *r.andor)
			item(c);
		return;
	}
	unsupported();
}

void reader::top(const RESTRICTION &r)
{
	item(r);
}

bool reader::recipients(const FORWARDDELEGATE_ACTION &fwd, std::vector<Address> &out)
{
	for (const auto &blk : fwd) {
		TPROPVAL_ARRAY pv{static_cast<uint16_t>(blk.count), blk.ppropval};
		Address a;
		a.routing = "SMTP";
		auto name = pv.get<const char>(PR_DISPLAY_NAME);
		if (name != nullptr)
			a.name = name;
		auto smtp = pv.get<const char>(PR_SMTP_ADDRESS);
		auto atype = pv.get<const char>(PR_ADDRTYPE);
		auto email = pv.get<const char>(PR_EMAIL_ADDRESS);
		if (smtp != nullptr && *smtp != '\0')
			a.email = smtp;
		else if (email != nullptr && atype != nullptr && strcasecmp(atype, "SMTP") == 0)
			a.email = email;
		else if (email != nullptr && atype != nullptr && strcasecmp(atype, "EX") == 0 &&
		    env.essdn_to_smtp(email, a.email))
			;
		else
			return false;
		if (a.name == a.email)
			a.name.clear();
		out.push_back(std::move(a));
	}
	return true;
}

void reader::action(const ACTION_BLOCK &act)
{
	auto &A = rule.actions.v;
	auto put = [&](act_kind k, Value &&v) {
		if (A[k])
			unsupported();
		else
			A[k] = std::move(v);
	};
	switch (act.type) {
	case OP_MOVE:
	case OP_COPY: {
		if (act.pdata == nullptr) {
			unsupported();
			return;
		}
		Value v;
		bool trash = false;
		if (!env.folder_ref(*static_cast<const MOVECOPY_ACTION *>(act.pdata), v.folder, trash)) {
			unsupported();
			return;
		}
		if (act.type == OP_MOVE && trash)
			put(A_Delete, Value{.flag = true});
		else
			put(act.type == OP_MOVE ? A_MoveToFolder : A_CopyToFolder, std::move(v));
		return;
	}
	case OP_REPLY: {
		Value v;
		if (act.flavor != 0 || act.pdata == nullptr ||
		    !env.template_ref(*static_cast<const REPLY_ACTION *>(act.pdata), v.item)) {
			unsupported();
			return;
		}
		put(A_ServerReplyWithMessage, std::move(v));
		return;
	}
	case OP_FORWARD: {
		act_kind k;
		auto fl = act.flavor;
		if (fl == 0)
			k = A_ForwardToRecipients;
		else if (fl == FWD_AS_ATTACHMENT)
			k = A_ForwardAsAttachmentToRecipients;
		else if (fl == FWD_PRESERVE_SENDER || fl == (FWD_PRESERVE_SENDER | FWD_DO_NOT_MUNGE_MSG))
			k = A_RedirectToRecipients;
		else if (fl == FWD_AS_SMS_ALERT)
			k = A_SendSMSAlertToRecipients;
		else {
			unsupported();
			return;
		}
		Value v;
		if (act.pdata == nullptr ||
		    !recipients(*static_cast<const FORWARDDELEGATE_ACTION *>(act.pdata), v.addrs)) {
			unsupported();
			return;
		}
		put(k, std::move(v));
		return;
	}
	case OP_TAG: {
		auto pv = static_cast<const TAGGED_PROPVAL *>(act.pdata);
		if (pv == nullptr) {
			unsupported();
			return;
		}
		if (pv->proptag == PR_IMPORTANCE &&
		    *static_cast<const uint32_t *>(pv->pvalue) < std::size(importance_names)) {
			put(A_MarkImportance, Value{.text = importance_names[*static_cast<const uint32_t *>(pv->pvalue)]});
			return;
		}
		auto k = keywords();
		if (k != 0 && PROP_ID(pv->proptag) == k) {
			Value v;
			if (PROP_TYPE(pv->proptag) == PT_MV_UNICODE || PROP_TYPE(pv->proptag) == PT_MV_STRING8) {
				for (auto s : *static_cast<const STRING_ARRAY *>(pv->pvalue))
					v.strings.emplace_back(s);
			} else if (pv_str(*pv) != nullptr) {
				v.strings.emplace_back(pv_str(*pv));
			}
			if (!v.strings.empty()) {
				put(A_AssignCategories, std::move(v));
				return;
			}
		}
		unsupported();
		return;
	}
	case OP_DELETE:
		put(A_PermanentDelete, Value{.flag = true});
		return;
	case OP_MARK_AS_READ:
		put(A_MarkAsRead, Value{.flag = true});
		return;
	case OP_DEFER_ACTION:
		/* grommunio-web's placeholder, means no action */
		if (act.pdata != nullptr && act.length == 9 + sizeof(web_default_dam) &&
		    memcmp(act.pdata, web_default_dam, sizeof(web_default_dam)) == 0)
			return;
		unsupported();
		return;
	default:
		unsupported();
		return;
	}
}

Rule from_mapi(const TPROPVAL_ARRAY &row, Env &env)
{
	Rule rule;
	rule.not_supported = false;
	if (auto id = row.get<const uint64_t>(PR_RULE_ID))
		rule.id = encode_rule_id(*id);
	if (auto n = row.get<const char>(PR_RULE_NAME))
		rule.name = n;
	auto st = row.get<const uint32_t>(PR_RULE_STATE);
	uint32_t state = st != nullptr ? *st : 0;
	rule.enabled = state & ST_ENABLED;
	rule.in_error = (state & (ST_ERROR | ST_PARSE_ERROR)) != 0;
	if (state & (ST_ONLY_WHEN_OOF | ST_ONLY_WHEN_OOF_EX))
		rule.not_supported = true;
	reader rd(env, rule);
	auto cond = row.get<const RESTRICTION>(PR_RULE_CONDITION);
	if (cond != nullptr)
		rd.top(*cond);
	else
		rule.not_supported = true;
	auto acts = row.get<const RULE_ACTIONS>(PR_RULE_ACTIONS);
	if (acts != nullptr)
		for (const auto &a : *acts)
			rd.action(a);
	else
		rule.not_supported = true;
	if (state & ST_EXIT_LEVEL)
		rule.actions.v[A_StopProcessingRules] = Value{.flag = true};
	return rule;
}

/*
 * Write side
 */
namespace {

struct writer {
	writer(Env &e, std::vector<ValidationError> &v) : env(e), errs(v) {}

	template<typename T> T *mk()
	{
		auto p = env.alloc(sizeof(T));
		if (p == nullptr)
			throw std::bad_alloc();
		return new(p) T{};
	}
	template<typename T> T *mk(size_t n)
	{
		auto p = static_cast<T *>(env.alloc(sizeof(T) * n));
		if (p == nullptr)
			throw std::bad_alloc();
		for (size_t i = 0; i < n; ++i)
			new(&p[i]) T{};
		return p;
	}
	char *str(const std::string &s)
	{
		auto p = static_cast<char *>(env.alloc(s.size() + 1));
		if (p == nullptr)
			throw std::bad_alloc();
		memcpy(p, s.c_str(), s.size() + 1);
		return p;
	}
	BINARY *bin(const std::string &s)
	{
		auto b = mk<BINARY>();
		b->cb = s.size();
		b->pv = env.alloc(s.size() > 0 ? s.size() : 1);
		if (b->pv == nullptr)
			throw std::bad_alloc();
		memcpy(b->pv, s.data(), s.size());
		return b;
	}
	template<typename T> T *num(T v)
	{
		auto p = mk<T>();
		*p = v;
		return p;
	}

	RESTRICTION res(mapi_rtype t, void *p)
	{
		RESTRICTION r;
		r.rt = t;
		r.pres = p;
		return r;
	}
	RESTRICTION list(mapi_rtype t, const std::vector<RESTRICTION> &v)
	{
		auto l = mk<RESTRICTION_AND_OR>();
		l->count = v.size();
		l->pres = mk<RESTRICTION>(v.size());
		std::copy(v.begin(), v.end(), l->pres);
		return res(t, l);
	}
	/* RES_OR only when there is more than one leaf */
	RESTRICTION any(const std::vector<RESTRICTION> &v)
	{
		return v.size() == 1 ? v[0] : list(RES_OR, v);
	}
	RESTRICTION xnot(const RESTRICTION &in)
	{
		auto n = mk<RESTRICTION_NOT>();
		n->res = in;
		return res(RES_NOT, n);
	}
	RESTRICTION content(proptag_t tag, uint32_t fl, const std::string &s)
	{
		auto c = mk<RESTRICTION_CONTENT>();
		c->fuzzy_level = fl;
		c->proptag = tag;
		c->propval.proptag = PROP_TYPE(tag) == PT_BINARY ? tag :
		                     CHANGE_PROP_TYPE(tag, PT_UNICODE);
		c->propval.pvalue = PROP_TYPE(tag) == PT_BINARY ?
		                    static_cast<void *>(bin(s)) : str(s);
		return res(RES_CONTENT, c);
	}
	RESTRICTION prop(relop op, proptag_t tag, void *v)
	{
		auto p = mk<RESTRICTION_PROPERTY>();
		p->relop = op;
		p->proptag = tag;
		p->propval.proptag = tag;
		p->propval.pvalue = v;
		return res(RES_PROPERTY, p);
	}
	RESTRICTION eq_bool(proptag_t tag, bool v) { return prop(RELOP_EQ, tag, num<uint8_t>(v)); }

	std::optional<RESTRICTION> pred(pred_kind, const Value &, const std::string &uri);
	ACTION_BLOCK *action(act_kind, const Value &, ACTION_BLOCK &);
	void error(const std::string &uri, const char *code, const char *msg, const std::string &value = {})
	{
		errs.push_back({uri, code, msg, value});
	}
	FORWARDDELEGATE_ACTION *recipients(const std::vector<Address> &, const std::string &uri);
	RESTRICTION addr_cond(const Address &, proptag_t);

	Env &env;
	std::vector<ValidationError> &errs;
};

}

/* Search key form of an SMTP address, ADDRTYPE:ADDRESS upper-cased */
static std::string smtp_srchkey(const std::string &addr)
{
	auto s = "SMTP:" + upper(addr);
	s.push_back('\0');
	return s;
}

static std::string oneoff_entryid(const Address &a)
{
	ONEOFF_ENTRYID e{};
	e.ctrl_flags = MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_UNICODE;
	e.pdisplay_name = a.name.empty() ? a.email : a.name;
	e.paddress_type = "SMTP";
	e.pmail_address = a.email;
	std::string out;
	out.resize(1280);
	EXT_PUSH ep;
	if (!ep.init(out.data(), out.size(), EXT_FLAG_UTF16) ||
	    ep.p_oneoff_eid(e) != pack_result::success)
		return {};
	out.resize(ep.m_offset);
	return out;
}

/*
 * RES_COMMENT{props, RES_PROPERTY(@tag == search key)} as Outlook and
 * grommunio-web write it, outlook_rule_spec.rst condition 203.
 */
RESTRICTION writer::addr_cond(const Address &a, proptag_t tag)
{
	auto c = mk<RESTRICTION_COMMENT>();
	c->count = 4;
	c->ppropval = mk<TAGGED_PROPVAL>(4);
	auto label = a.name.empty() ? a.email : a.name + " <" + a.email + ">";
	c->ppropval[0] = {PROP_TAG(PT_LONG, 0x6000), num<uint32_t>(MAPI_TO)};
	c->ppropval[1] = {PROP_TAG(PT_BINARY, 0x0001), bin(oneoff_entryid(a))};
	c->ppropval[2] = {PROP_TAG(PT_UNICODE, 0x0001), str(label)};
	c->ppropval[3] = {PR_DISPLAY_TYPE, num<uint32_t>(DT_MAILUSER)};
	c->pres = mk<RESTRICTION>();
	*c->pres = prop(RELOP_EQ, tag, bin(smtp_srchkey(a.email)));
	return res(RES_COMMENT, c);
}

std::optional<RESTRICTION> writer::pred(pred_kind k, const Value &v, const std::string &uri)
{
	/* Predicates of value false do not restrict anything */
	if (pred_type(k) == vtype::boolean && !v.flag)
		return std::nullopt;
	if ((pred_type(k) == vtype::strings && v.strings.empty()) ||
	    (pred_type(k) == vtype::addresses && v.addrs.empty())) {
		error(uri, "EmptyValueFound", "The list is empty.");
		return std::nullopt;
	}
	auto strs = [&](proptag_t tag, uint32_t fl) {
		std::vector<RESTRICTION> l;
		for (const auto &s : v.strings)
			l.push_back(content(tag, fl, s));
		return any(l);
	};
	std::vector<RESTRICTION> l;
	switch (k) {
	case P_Categories: {
		auto id = env.keywords_propid(true);
		if (id == 0) {
			error(uri, "UnexpectedError", "Cannot register the Keywords property");
			return std::nullopt;
		}
		return strs(PROP_TAG(PT_MV_UNICODE, id), FL_FULLSTRING | FL_IGNORECASE);
	}
	case P_ContainsBodyStrings:
		return strs(PR_BODY, FL_SUBSTRING | FL_IGNORECASE);
	case P_ContainsHeaderStrings:
		return strs(PR_TRANSPORT_MESSAGE_HEADERS, FL_SUBSTRING | FL_IGNORECASE);
	case P_ContainsRecipientStrings:
		for (const auto &s : v.strings) {
			auto sub = mk<RESTRICTION_SUBOBJ>();
			sub->subobject = PR_MESSAGE_RECIPIENTS;
			sub->res = content(PR_SMTP_ADDRESS, FL_SUBSTRING | FL_IGNORECASE, s);
			l.push_back(res(RES_SUBRESTRICTION, sub));
		}
		return any(l);
	case P_ContainsSenderStrings:
		/* Search keys are upper case */
		for (const auto &s : v.strings)
			l.push_back(content(PR_SENDER_SEARCH_KEY, FL_SUBSTRING, upper(s)));
		return any(l);
	case P_ContainsSubjectOrBodyStrings:
		for (const auto &s : v.strings) {
			l.push_back(content(PR_SUBJECT, FL_SUBSTRING | FL_IGNORECASE, s));
			l.push_back(content(PR_BODY, FL_SUBSTRING | FL_IGNORECASE, s));
		}
		return list(RES_OR, l);
	case P_ContainsSubjectStrings:
		return strs(PR_SUBJECT, FL_SUBSTRING | FL_IGNORECASE);
	case P_ItemClasses:
		for (const auto &s : v.strings)
			l.push_back(prop(RELOP_EQ, PR_MESSAGE_CLASS, str(s)));
		return list(RES_OR, l);
	case P_FlaggedForAction: {
		auto flagged = prop(RELOP_EQ, PR_FLAG_STATUS, num<uint32_t>(followupFlagged));
		if (v.text == "Any")
			return flagged;
		auto id = env.flagrequest_propid(true);
		if (id == 0) {
			error(uri, "UnexpectedError", "Cannot register the FlagRequest property");
			return std::nullopt;
		}
		auto it = std::find_if(std::begin(flag_texts), std::end(flag_texts),
		          [&](const auto &x) { return v.text == x.first; });
		return list(RES_AND, {flagged, prop(RELOP_EQ,
		       PROP_TAG(PT_UNICODE, id), str(it->second))});
	}
	case P_FromAddresses:
	case P_SentToAddresses:
		for (auto a : v.addrs) {
			if (auto code = env.resolve_address(a)) {
				error(uri, code, "The address is not valid.", a.email);
				return std::nullopt;
			}
			if (k == P_FromAddresses) {
				l.push_back(addr_cond(a, PR_SENDER_SEARCH_KEY));
				continue;
			}
			auto sub = mk<RESTRICTION_SUBOBJ>();
			sub->subobject = PR_MESSAGE_RECIPIENTS;
			sub->res = addr_cond(a, PR_SEARCH_KEY);
			l.push_back(res(RES_SUBRESTRICTION, sub));
		}
		return any(l);
	case P_HasAttachments: {
		auto bm = mk<RESTRICTION_BITMASK>();
		bm->bitmask_relop = BMR_NEZ;
		bm->proptag = PR_MESSAGE_FLAGS;
		bm->mask = MSGFLAG_HASATTACH;
		return res(RES_BITMASK, bm);
	}
	case P_Importance: {
		auto it = std::find(std::begin(importance_names), std::end(importance_names), v.text);
		return prop(RELOP_EQ, PR_IMPORTANCE, num<uint32_t>(it - std::begin(importance_names)));
	}
	case P_Sensitivity: {
		auto it = std::find(std::begin(sensitivity_names), std::end(sensitivity_names), v.text);
		return prop(RELOP_EQ, PR_SENSITIVITY, num<uint32_t>(it - std::begin(sensitivity_names)));
	}
	case P_IsApprovalRequest:
	case P_IsMeetingResponse:
	case P_IsPermissionControlled:
	case P_IsReadReceipt:
	case P_IsSigned:
	case P_IsVoicemail:
		for (const auto &[kind, pfx] : class_prefixes)
			if (kind == k)
				return content(PR_MESSAGE_CLASS, FL_PREFIX | FL_IGNORECASE, pfx);
		return std::nullopt;
	case P_IsAutomaticForward:
		return eq_bool(PR_AUTO_FORWARDED, true);
	case P_IsAutomaticReply:
		return prop(RELOP_EQ, PR_MESSAGE_CLASS, str(OOF_TPL_CLASS));
	case P_IsEncrypted:
		return list(RES_AND, {
			content(PR_MESSAGE_CLASS, FL_PREFIX | FL_IGNORECASE, "IPM.Note.SMIME"),
			xnot(content(PR_MESSAGE_CLASS, FL_PREFIX | FL_IGNORECASE, "IPM.Note.SMIME.MultipartSigned")),
		});
	case P_IsMeetingRequest:
		return list(RES_OR, {
			content(PR_MESSAGE_CLASS, FL_FULLSTRING | FL_IGNORECASE, "IPM.Schedule.Meeting.Request"),
			content(PR_MESSAGE_CLASS, FL_FULLSTRING | FL_IGNORECASE, "IPM.Schedule.Meeting.Canceled"),
		});
	case P_IsNDR:
		return list(RES_AND, {
			content(PR_MESSAGE_CLASS, FL_PREFIX | FL_IGNORECASE, "REPORT."),
			content(PR_MESSAGE_CLASS, FL_SUBSTRING | FL_IGNORECASE, ".NDR"),
		});
	case P_NotSentToMe:
		return eq_bool(PR_MESSAGE_TO_ME, false);
	case P_SentCcMe:
		return list(RES_AND, {
			eq_bool(PR_MESSAGE_CC_ME, true),
			eq_bool(PR_MESSAGE_RECIP_ME, true),
			eq_bool(PR_MESSAGE_TO_ME, false),
		});
	case P_SentOnlyToMe:
		return list(RES_AND, {
			eq_bool(PR_MESSAGE_TO_ME, true),
			xnot(content(PR_DISPLAY_TO, FL_SUBSTRING, ";")),
			prop(RELOP_EQ, PR_DISPLAY_CC, str("")),
		});
	case P_SentToMe:
		return eq_bool(PR_MESSAGE_TO_ME, true);
	case P_SentToOrCcMe:
		return eq_bool(PR_MESSAGE_RECIP_ME, true);
	case P_WithinDateRange:
		if (v.start)
			l.push_back(prop(RELOP_GT, PR_MESSAGE_DELIVERY_TIME,
			            num<uint64_t>(rop_util_unix_to_nttime(*v.start))));
		if (v.end)
			l.push_back(prop(RELOP_LT, PR_MESSAGE_DELIVERY_TIME,
			            num<uint64_t>(rop_util_unix_to_nttime(*v.end))));
		break;
	case P_WithinSizeRange:
		if (v.min)
			l.push_back(prop(RELOP_GE, PR_MESSAGE_SIZE,
			            num<uint32_t>(static_cast<uint32_t>(*v.min) * 1024)));
		if (v.max)
			l.push_back(prop(RELOP_LE, PR_MESSAGE_SIZE,
			            num<uint32_t>(static_cast<uint32_t>(*v.max) * 1024)));
		break;
	default:
		error(uri, "UnsupportedRule", "This condition is not supported.");
		return std::nullopt;
	}
	if (l.empty()) {
		error(uri, "MissingRangeValue", "The range has no bound.");
		return std::nullopt;
	}
	return l.size() == 1 ? l[0] : list(RES_AND, l);
}

FORWARDDELEGATE_ACTION *writer::recipients(const std::vector<Address> &addrs,
    const std::string &uri)
{
	auto fwd = mk<FORWARDDELEGATE_ACTION>();
	fwd->count = addrs.size();
	fwd->pblock = mk<RECIPIENT_BLOCK>(addrs.size());
	for (size_t i = 0; i < addrs.size(); ++i) {
		Address a = addrs[i];
		auto code = env.resolve_address(a);
		if (code != nullptr) {
			error(uri, code, "The address is not valid.", addrs[i].email);
			return nullptr;
		}
		auto &blk = fwd->pblock[i];
		blk.count = 9;
		blk.ppropval = mk<TAGGED_PROPVAL>(9);
		blk.ppropval[0] = {PR_ADDRTYPE, str("SMTP")};
		blk.ppropval[1] = {PR_EMAIL_ADDRESS, str(a.email)};
		blk.ppropval[2] = {PR_SMTP_ADDRESS, str(a.email)};
		blk.ppropval[3] = {PR_DISPLAY_NAME, str(a.name.empty() ? a.email : a.name)};
		blk.ppropval[4] = {PR_RECIPIENT_TYPE, num<uint32_t>(MAPI_TO)};
		blk.ppropval[5] = {PR_SEARCH_KEY, bin(smtp_srchkey(a.email))};
		blk.ppropval[6] = {PR_ENTRYID, bin(oneoff_entryid(a))};
		blk.ppropval[7] = {PR_OBJECT_TYPE, num<uint32_t>(static_cast<uint32_t>(MAPI_MAILUSER))};
		blk.ppropval[8] = {PR_DISPLAY_TYPE, num<uint32_t>(DT_MAILUSER)};
	}
	return fwd;
}

/* Fill @blk, or return nullptr when the action adds no block */
ACTION_BLOCK *writer::action(act_kind k, const Value &v, ACTION_BLOCK &blk)
{
	if (act_type(k) == vtype::boolean && !v.flag)
		return nullptr;
	auto uri = "Action:"s + act_name(k);
	if ((act_type(k) == vtype::strings && v.strings.empty()) ||
	    (act_type(k) == vtype::addresses && v.addrs.empty())) {
		error(uri, "EmptyValueFound", "The list is empty.");
		return nullptr;
	}
	blk = {};
	switch (k) {
	case A_MarkAsRead:
		blk.type = OP_MARK_AS_READ;
		return &blk;
	case A_PermanentDelete:
		blk.type = OP_DELETE;
		return &blk;
	case A_Delete: {
		auto mc = mk<MOVECOPY_ACTION>();
		if (auto code = env.deleted_items(*mc)) {
			error(uri, code, "The Deleted Items folder cannot be found.");
			return nullptr;
		}
		blk.type = OP_MOVE;
		blk.pdata = mc;
		return &blk;
	}
	case A_CopyToFolder:
	case A_MoveToFolder: {
		auto mc = mk<MOVECOPY_ACTION>();
		if (auto code = env.resolve_folder(v.folder, *mc)) {
			error(uri, code, "The folder is not valid.", v.folder.id);
			return nullptr;
		}
		blk.type = k == A_MoveToFolder ? OP_MOVE : OP_COPY;
		blk.pdata = mc;
		return &blk;
	}
	case A_AssignCategories: {
		auto id = env.keywords_propid(true);
		if (id == 0) {
			error(uri, "UnexpectedError", "Cannot register the Keywords property");
			return nullptr;
		}
		auto sa = mk<STRING_ARRAY>();
		sa->count = v.strings.size();
		sa->ppstr = mk<char *>(v.strings.size());
		for (size_t i = 0; i < v.strings.size(); ++i)
			sa->ppstr[i] = str(v.strings[i]);
		blk.type = OP_TAG;
		blk.pdata = mk<TAGGED_PROPVAL>();
		*static_cast<TAGGED_PROPVAL *>(blk.pdata) = {PROP_TAG(PT_MV_UNICODE, id), sa};
		return &blk;
	}
	case A_MarkImportance: {
		auto it = std::find(std::begin(importance_names), std::end(importance_names), v.text);
		blk.type = OP_TAG;
		blk.pdata = mk<TAGGED_PROPVAL>();
		*static_cast<TAGGED_PROPVAL *>(blk.pdata) = {PR_IMPORTANCE,
			num<uint32_t>(it - std::begin(importance_names))};
		return &blk;
	}
	case A_ForwardToRecipients:
	case A_ForwardAsAttachmentToRecipients:
	case A_RedirectToRecipients: {
		auto fwd = recipients(v.addrs, uri);
		if (fwd == nullptr)
			return nullptr;
		blk.type = OP_FORWARD;
		blk.flavor = k == A_ForwardAsAttachmentToRecipients ? FWD_AS_ATTACHMENT :
		             k == A_RedirectToRecipients ? FWD_PRESERVE_SENDER | FWD_DO_NOT_MUNGE_MSG : 0;
		blk.pdata = fwd;
		return &blk;
	}
	default:
		/* SendSMSAlertToRecipients: ruleproc has no SMS gateway */
		error(uri, "UnsupportedRule", "This action is not supported.");
		return nullptr;
	}
}

/*
 * Conditions are AND'ed, each exception goes into its own RES_NOT, as Outlook
 * does, see outlook_rule_spec.rst "SSRT: Organizer2". A rule without any must
 * still carry a restriction, update_folder_rule skips rules without one.
 */
bool to_mapi(const Rule &rule, Env &env, RESTRICTION *&cond,
    RULE_ACTIONS *&acts, std::vector<ValidationError> &errs)
{
	auto nerr = errs.size();
	writer w(env, errs);
	std::vector<RESTRICTION> all;
	for (unsigned int k = 0; k < P_COUNT; ++k) {
		if (rule.conditions.v[k])
			if (auto r = w.pred(static_cast<pred_kind>(k), *rule.conditions.v[k],
			    "Condition:"s + pred_name(k)))
				all.push_back(*r);
	}
	for (unsigned int k = 0; k < P_COUNT; ++k) {
		if (rule.exceptions.v[k])
			if (auto r = w.pred(static_cast<pred_kind>(k), *rule.exceptions.v[k],
			    "Exception:"s + pred_name(k)))
				all.push_back(w.xnot(*r));
	}
	cond = w.mk<RESTRICTION>();
	if (all.empty()) {
		auto ex = w.mk<RESTRICTION_EXIST>();
		ex->proptag = PR_MESSAGE_CLASS;
		*cond = w.res(RES_EXIST, ex);
	} else {
		*cond = all.size() == 1 ? all[0] : w.list(RES_AND, all);
	}

	/* Message-changing actions first, moves after, deletion last */
	static constexpr act_kind order[] = {
		A_AssignCategories, A_MarkImportance, A_MarkAsRead,
		A_ForwardToRecipients, A_ForwardAsAttachmentToRecipients,
		A_RedirectToRecipients, A_SendSMSAlertToRecipients,
		A_ServerReplyWithMessage, A_CopyToFolder, A_MoveToFolder,
		A_Delete, A_PermanentDelete,
	};
	std::vector<ACTION_BLOCK> blocks;
	for (auto k : order) {
		if (!rule.actions.v[k])
			continue;
		ACTION_BLOCK blk;
		if (w.action(k, *rule.actions.v[k], blk) != nullptr)
			blocks.push_back(blk);
	}
	if (blocks.empty()) {
		/* Only StopProcessingRules, store grommunio-web's placeholder */
		ACTION_BLOCK blk{};
		blk.type = OP_DEFER_ACTION;
		blk.length = 9 + sizeof(web_default_dam);
		blk.pdata = w.mk<uint8_t>(sizeof(web_default_dam));
		memcpy(blk.pdata, web_default_dam, sizeof(web_default_dam));
		blocks.push_back(blk);
	}
	acts = w.mk<RULE_ACTIONS>();
	acts->count = blocks.size();
	acts->pblock = w.mk<ACTION_BLOCK>(blocks.size());
	std::copy(blocks.begin(), blocks.end(), acts->pblock);
	return errs.size() == nerr;
}

/* Checks that need no mailbox, MS-OXWSRULES v9.0 §3.1.4.2.4.2 */
std::vector<ValidationError> validate(const Rule &rule, Operation::kind_t kind)
{
	std::vector<ValidationError> errs;
	if (kind == Operation::CREATE && rule.id)
		errs.push_back({"RuleId", "CreateWithRuleId",
			"Create rule operation should not have rule ID set in request.", *rule.id});
	if (kind == Operation::SET && !rule.id)
		errs.push_back({"RuleId", "MissingParameter", "The rule ID is missing.", ""});
	bool any = false;
	for (unsigned int k = 0; k < A_COUNT; ++k) {
		auto &a = rule.actions.v[k];
		if (a && (act_type(k) != vtype::boolean || a->flag))
			any = true;
	}
	if (!any)
		errs.push_back({"Actions", "MissingAction", "The rule has no action.", ""});
	return errs;
}

/*
 * Sequence numbers for @count visible rules, reusing those the visible rules
 * had before so rules of other providers keep their place.
 */
std::vector<uint32_t> assign_sequences(std::vector<uint32_t> old, size_t count)
{
	std::sort(old.begin(), old.end());
	std::vector<uint32_t> out;
	uint32_t next = old.empty() ? 10 : old.back() + 1;
	for (size_t i = 0; i < count; ++i)
		out.push_back(i < old.size() ? old[i] : next++);
	return out;
}

}
