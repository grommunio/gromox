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

}
