// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <tinyxml2.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>
#include <gromox/rop_util.hpp>
#include "../exch/ews/rules.hpp"

using namespace gromox;
using namespace gromox::EWS::Rules;
using namespace std::string_literals;

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #x); return EXIT_FAILURE; } } while (false)

static const char ns[] = "xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\" "
	"xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\"";

/* The SOAP layer strips namespace prefixes before the request is parsed */
static void strip_prefixes(tinyxml2::XMLElement *e)
{
	if (auto c = strchr(e->Name(), ':'))
		e->SetName(std::string(c + 1).c_str());
	for (auto c = e->FirstChildElement(); c != nullptr; c = c->NextSiblingElement())
		strip_prefixes(c);
}

static int t_ruleid()
{
	/* Exchange sample, MS-OXWSRULES v9.0 §4.4 */
	auto id = decode_rule_id("dCsAAABjzvA=");
	CHECK(id.has_value());
	CHECK(encode_rule_id(*id) == "dCsAAABjzvA=");
	CHECK(decode_rule_id(encode_rule_id(0x1234567890abcdefULL)) == 0x1234567890abcdefULL);
	CHECK(!decode_rule_id("AAAA").has_value());
	CHECK(!decode_rule_id("").has_value());
	return EXIT_SUCCESS;
}

/* What the clients sent, ts-rules-ev */
static const char em_ops[] =
	"<m:Operations><t:CreateRuleOperation><t:Rule>"
	"<t:DisplayName>TSR-EM-read</t:DisplayName><t:Priority>1</t:Priority>"
	"<t:IsEnabled>true</t:IsEnabled><t:IsInError>false</t:IsInError>"
	"<t:Conditions><t:ContainsSubjectStrings><t:String>*TSR-EM-read*</t:String>"
	"</t:ContainsSubjectStrings></t:Conditions><t:Exceptions />"
	"<t:Actions><t:MarkAsRead>true</t:MarkAsRead></t:Actions>"
	"</t:Rule></t:CreateRuleOperation></m:Operations>";
static const char ol_ops[] =
	"<m:Operations><t:CreateRuleOperation><t:Rule>"
	"<t:DisplayName>Betreff enth\xc3\xa4lt TSR-OL-read oder </t:DisplayName>"
	"<t:Priority>1</t:Priority><t:IsEnabled>true</t:IsEnabled>"
	"<t:IsInError>false</t:IsInError><t:Conditions><t:ContainsSubjectStrings>"
	"<t:String>TSR-OL-read</t:String></t:ContainsSubjectStrings></t:Conditions>"
	"<t:Actions><t:MarkAsRead>true</t:MarkAsRead>"
	"<t:StopProcessingRules>true</t:StopProcessingRules></t:Actions>"
	"</t:Rule></t:CreateRuleOperation></m:Operations>";

static std::vector<Operation> parse_ops(const char *xml)
{
	tinyxml2::XMLDocument doc;
	auto s = "<x "s + ns + ">" + xml + "</x>";
	if (doc.Parse(s.c_str()) != tinyxml2::XML_SUCCESS)
		throw ParseError("bad test xml");
	auto root = doc.RootElement()->FirstChildElement();
	strip_prefixes(root);
	return parse_operations(root);
}

static int t_parse()
{
	auto ops = parse_ops(em_ops);
	CHECK(ops.size() == 1);
	CHECK(ops[0].kind == Operation::CREATE);
	auto &r = ops[0].rule;
	CHECK(r.name == "TSR-EM-read");
	CHECK(r.priority == 1 && r.enabled);
	CHECK(r.in_error == false);
	CHECK(r.conditions.v[P_ContainsSubjectStrings]->strings == std::vector<std::string>{"*TSR-EM-read*"});
	CHECK(r.exceptions.empty());
	CHECK(r.actions.v[A_MarkAsRead]->flag);

	ops = parse_ops(ol_ops);
	CHECK(ops.size() == 1);
	CHECK(ops[0].rule.actions.v[A_StopProcessingRules]->flag);

	ops = parse_ops("<m:Operations><t:DeleteRuleOperation><t:RuleId>dCsAAABjzwY=</t:RuleId>"
	      "</t:DeleteRuleOperation><t:SetRuleOperation><t:Rule><t:RuleId>x</t:RuleId>"
	      "<t:DisplayName>n</t:DisplayName><t:Priority>2</t:Priority><t:IsEnabled>false</t:IsEnabled>"
	      "<t:Actions><t:MoveToFolder><t:DistinguishedFolderId Id=\"junkemail\"/></t:MoveToFolder>"
	      "</t:Actions></t:Rule></t:SetRuleOperation></m:Operations>");
	CHECK(ops.size() == 2);
	CHECK(ops[0].kind == Operation::DELETE && ops[0].rule_id == "dCsAAABjzwY=");
	CHECK(ops[1].kind == Operation::SET);
	auto &f = ops[1].rule.actions.v[A_MoveToFolder]->folder;
	CHECK(f.distinguished && f.id == "junkemail");

	for (auto bad : {
	     "<m:Operations><t:Bogus/></m:Operations>",
	     "<m:Operations><t:CreateRuleOperation><t:Rule><t:DisplayName>a</t:DisplayName>"
	     "<t:Priority>1</t:Priority></t:Rule></t:CreateRuleOperation></m:Operations>",
	     "<m:Operations><t:CreateRuleOperation><t:Rule><t:DisplayName>a</t:DisplayName>"
	     "<t:Priority>1</t:Priority><t:IsEnabled>true</t:IsEnabled><t:Conditions>"
	     "<t:Importance>Urgent</t:Importance></t:Conditions></t:Rule></t:CreateRuleOperation></m:Operations>",
	     }) {
		bool thrown = false;
		try {
			parse_ops(bad);
		} catch (const ParseError &) {
			thrown = true;
		}
		CHECK(thrown);
	}
	return EXIT_SUCCESS;
}

/* Every predicate and action survives write_rule and parse_rule */
static Value sample(vtype t, bool sender = false)
{
	Value v;
	switch (t) {
	case vtype::strings: v.strings = sender ? std::vector<std::string>{"ALPHA", "EXAMPLE.ORG"} :
	                                          std::vector<std::string>{"alpha", "Beta"}; break;
	case vtype::addresses: v.addrs = {{"Alice A.", "alice@example.org", "SMTP"}, {"", "bob@example.com", "SMTP"}}; break;
	case vtype::boolean: v.flag = true; break;
	case vtype::flag: v.text = "FollowUp"; break;
	case vtype::importance: v.text = "High"; break;
	case vtype::sensitivity: v.text = "Private"; break;
	case vtype::date_range: v.start = 1700000000; v.end = 1800000000; break;
	case vtype::size_range: v.min = 10; v.max = 100; break;
	case vtype::folder: v.folder.id = "F4711"; break;
	case vtype::item: v.item.id = "T42"; break;
	}
	return v;
}

static Rule full_rule()
{
	Rule r;
	r.name = "all";
	r.priority = 3;
	r.enabled = true;
	for (unsigned int k = 0; k < P_COUNT; ++k) {
		r.conditions.v[k] = sample(pred_type(k), k == P_ContainsSenderStrings);
		r.exceptions.v[k] = sample(pred_type(k), k == P_ContainsSenderStrings);
	}
	for (unsigned int k = 0; k < A_COUNT; ++k)
		r.actions.v[k] = sample(act_type(k));
	return r;
}

static int t_xml_roundtrip()
{
	auto r = full_rule();
	r.id = encode_rule_id(99);
	tinyxml2::XMLDocument doc;
	auto root = doc.NewElement("x");
	doc.InsertFirstChild(root);
	write_rule(root, r);
	strip_prefixes(root);
	auto r2 = parse_rule(root->FirstChildElement("Rule"));
	CHECK(r2.id == r.id && r2.name == r.name && r2.priority == r.priority);
	CHECK(r2.conditions == r.conditions);
	CHECK(r2.exceptions == r.exceptions);
	CHECK(r2.actions == r.actions);
	return EXIT_SUCCESS;
}

int main()
{
	using fn = int (*)();
	for (auto f : std::initializer_list<fn>{t_ruleid, t_parse, t_xml_roundtrip,
	     }) {
		auto ret = f();
		if (ret != EXIT_SUCCESS) {
			printf("FAILED\n");
			return ret;
		}
	}
	return EXIT_SUCCESS;
}
