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

static int t_errors_xml()
{
	tinyxml2::XMLDocument doc;
	auto root = doc.NewElement("x");
	doc.InsertFirstChild(root);
	write_errors(root, {{2, {{"RuleId", "CreateWithRuleId", "msg", "dCsAAABjz0Q="}}}});
	tinyxml2::XMLPrinter pr(nullptr, true);
	doc.Print(&pr);
	std::string out = pr.CStr();
	CHECK(out == "<x><m:RuleOperationErrors><t:RuleOperationError><t:OperationIndex>2"
	      "</t:OperationIndex><t:ValidationErrors><t:Error><t:FieldURI>RuleId</t:FieldURI>"
	      "<t:ErrorCode>CreateWithRuleId</t:ErrorCode><t:ErrorMessage>msg</t:ErrorMessage>"
	      "<t:FieldValue>dCsAAABjz0Q=</t:FieldValue></t:Error></t:ValidationErrors>"
	      "</t:RuleOperationError></m:RuleOperationErrors></x>");
	return EXIT_SUCCESS;
}

static int t_sequences()
{
	CHECK((assign_sequences({}, 2) == std::vector<uint32_t>{10, 11}));
	CHECK((assign_sequences({12, 10, 11}, 2) == std::vector<uint32_t>{10, 11}));
	CHECK((assign_sequences({10, 20}, 4) == std::vector<uint32_t>{10, 20, 21, 22}));
	return EXIT_SUCCESS;
}

/*
 * Fake mailbox. Folder ids are "F<n>" for this store and "X<n>" for
 * another one, template ids are "T<n>".
 */
class test_env final : public Env {
	public:
	void *alloc(size_t z) override { return calloc(1, z > 0 ? z : 1); }
	uint16_t keywords_propid(bool) override { return 0x8100; }
	uint16_t flagrequest_propid(bool) override { return 0x8101; }
	const char *resolve_folder(const FolderRef &f, MOVECOPY_ACTION &mc) override
	{
		if (f.id.size() < 2)
			return "InvalidFolderId";
		if (f.id[0] == 'X') {
			auto se = static_cast<STORE_ENTRYID *>(alloc(sizeof(STORE_ENTRYID)));
			se->wrapped_provider_uid = g_muidStorePrivate;
			se->pserver_name = strdup("other@example.org");
			se->pmailbox_dn = strdup("/o=x/ou=y/cn=Recipients/cn=other");
			auto b = static_cast<BINARY *>(alloc(sizeof(BINARY)));
			b->cb = f.id.size();
			b->pv = strdup(f.id.c_str());
			mc.same_store = 0;
			mc.pstore_eid = se;
			mc.pfolder_eid = b;
			return nullptr;
		}
		if (f.id[0] != 'F')
			return "FolderDoesNotExist";
		auto sv = static_cast<SVREID *>(alloc(sizeof(SVREID)));
		sv->folder_id = eid_t(1, strtoull(&f.id[1], nullptr, 0));
		mc.same_store = 1;
		mc.pfolder_eid = sv;
		return nullptr;
	}
	const char *deleted_items(MOVECOPY_ACTION &mc) override
	{
		auto sv = static_cast<SVREID *>(alloc(sizeof(SVREID)));
		sv->folder_id = eid_t(1, PRIVATE_FID_DELETED_ITEMS);
		mc.same_store = 1;
		mc.pfolder_eid = sv;
		return nullptr;
	}
	const char *resolve_template(const ItemRef &i, REPLY_ACTION &ra) override
	{
		if (i.id.size() < 2 || i.id[0] != 'T')
			return "InvalidValue";
		ra.template_folder_id = eid_t(1, PRIVATE_FID_INBOX);
		ra.template_message_id = eid_t(1, strtoull(&i.id[1], nullptr, 0));
		return nullptr;
	}
	const char *resolve_address(Address &a) override
	{
		if (strcasecmp(a.routing.c_str(), "EX") == 0) {
			if (!essdn_to_smtp(a.email.c_str(), a.email))
				return "InvalidAddress";
		}
		a.routing = "SMTP";
		return a.email.find('@') == a.email.npos ? "InvalidAddress" : nullptr;
	}
	bool folder_ref(const MOVECOPY_ACTION &mc, FolderRef &f, bool &trash) override
	{
		if (!mc.same_store) {
			auto b = static_cast<const BINARY *>(mc.pfolder_eid);
			f.id.assign(b->pc, b->cb);
			return true;
		}
		auto fid = rop_util_get_gc_value(static_cast<const SVREID *>(mc.pfolder_eid)->folder_id);
		trash = fid == PRIVATE_FID_DELETED_ITEMS;
		f.id = "F" + std::to_string(fid);
		return true;
	}
	bool template_ref(const REPLY_ACTION &ra, ItemRef &i) override
	{
		i.id = "T" + std::to_string(rop_util_get_gc_value(ra.template_message_id));
		return true;
	}
	bool essdn_to_smtp(const char *essdn, std::string &smtp) override
	{
		auto cn = strrchr(essdn, '=');
		if (cn == nullptr)
			return false;
		smtp = std::string(cn + 1) + "@example.org";
		return true;
	}
};

/* Push through the exmdb storage format and back, as the rules table does */
static TPROPVAL_ARRAY *stored(const RESTRICTION &cond, const RULE_ACTIONS &acts, uint32_t state = ST_ENABLED)
{
	static char buf[65536];
	EXT_PUSH ep;
	auto row = static_cast<TPROPVAL_ARRAY *>(calloc(1, sizeof(TPROPVAL_ARRAY)));
	row->ppropval = static_cast<TAGGED_PROPVAL *>(calloc(8, sizeof(TAGGED_PROPVAL)));
	auto c = static_cast<RESTRICTION *>(calloc(1, sizeof(RESTRICTION)));
	auto a = static_cast<RULE_ACTIONS *>(calloc(1, sizeof(RULE_ACTIONS)));
	if (!ep.init(buf, sizeof(buf), 0) || ep.p_restriction(cond) != pack_result::ok)
		return nullptr;
	auto blob = static_cast<char *>(malloc(ep.m_offset));
	memcpy(blob, buf, ep.m_offset);
	EXT_PULL pl;
	pl.init(blob, ep.m_offset, malloc, 0);
	if (pl.g_restriction(c) != pack_result::ok)
		return nullptr;
	if (!ep.init(buf, sizeof(buf), 0) || ep.p_rule_actions(acts) != pack_result::ok)
		return nullptr;
	blob = static_cast<char *>(malloc(ep.m_offset));
	memcpy(blob, buf, ep.m_offset);
	pl.init(blob, ep.m_offset, malloc, 0);
	if (pl.g_rule_actions(a) != pack_result::ok)
		return nullptr;
	auto id = static_cast<uint64_t *>(malloc(sizeof(uint64_t)));
	*id = eid_t(1, 77);
	auto st = static_cast<uint32_t *>(malloc(sizeof(uint32_t)));
	*st = state;
	row->emplace_back(PR_RULE_ID, id);
	row->emplace_back(PR_RULE_STATE, st);
	row->emplace_back(PR_RULE_CONDITION, c);
	row->emplace_back(PR_RULE_ACTIONS, a);
	return row;
}

static RESTRICTION mkres(mapi_rtype t, void *p)
{
	RESTRICTION r;
	r.rt = t;
	r.pres = p;
	return r;
}

template<typename T> static T *mk()
{
	return new T{};
}

static RESTRICTION r_content(proptag_t tag, uint32_t fl, const char *s, size_t len = 0)
{
	auto c = mk<RESTRICTION_CONTENT>();
	c->fuzzy_level = fl;
	c->proptag = tag;
	c->propval.proptag = tag;
	if (PROP_TYPE(tag) == PT_BINARY) {
		auto b = mk<BINARY>();
		b->cb = len;
		b->pv = deconst(s);
		c->propval.pvalue = b;
	} else {
		c->propval.pvalue = deconst(s);
	}
	return mkres(RES_CONTENT, c);
}

static RESTRICTION r_prop(relop op, proptag_t tag, void *v)
{
	auto p = mk<RESTRICTION_PROPERTY>();
	p->relop = op;
	p->proptag = tag;
	p->propval = {tag, v};
	return mkres(RES_PROPERTY, p);
}

static RESTRICTION r_list(mapi_rtype t, std::vector<RESTRICTION> v)
{
	auto l = mk<RESTRICTION_AND_OR>();
	l->count = v.size();
	l->pres = new RESTRICTION[v.size()];
	std::copy(v.begin(), v.end(), l->pres);
	return mkres(t, l);
}

static RULE_ACTIONS *one_action(uint8_t type, uint32_t flavor = 0, void *data = nullptr, uint16_t len = 0)
{
	auto a = mk<RULE_ACTIONS>();
	a->count = 1;
	a->pblock = new ACTION_BLOCK[1]{};
	a->pblock[0].type = type;
	a->pblock[0].flavor = flavor;
	a->pblock[0].pdata = data;
	a->pblock[0].length = len;
	return a;
}

/* Rules other clients write, outlook_rule_spec.rst and RulesData.js */
static int t_read_variants()
{
	test_env env;
	auto mark = one_action(OP_MARK_AS_READ);
	static uint32_t sz_lo = 10240, sz_hi = 102400;
	static uint8_t yes = 1;

	auto row = stored(r_list(RES_AND, {
		r_prop(RELOP_GT, PR_MESSAGE_SIZE, &sz_lo),
		r_prop(RELOP_LE, PR_MESSAGE_SIZE, &sz_hi),
		r_content(PR_SEARCH_KEY, FL_SUBSTRING, "FOO", 3),
		r_content(PR_SUBJECT_A, FL_SUBSTRING | FL_IGNORECASE, "eight"),
	}), *mark);
	CHECK(row != nullptr);
	auto r = from_mapi(*row, env);
	CHECK(!r.not_supported.value_or(false));
	CHECK(r.conditions.v[P_WithinSizeRange]->min == 10);
	CHECK(r.conditions.v[P_WithinSizeRange]->max == 100);
	CHECK(r.conditions.v[P_ContainsRecipientStrings]->strings == std::vector<std::string>{"FOO"});
	CHECK(r.conditions.v[P_ContainsSubjectStrings]->strings == std::vector<std::string>{"eight"});
	CHECK(r.actions.v[A_MarkAsRead]->flag);
	CHECK(r.enabled && r.id == encode_rule_id(eid_t(1, 77)));

	/* Outlook's To shape has no subrestriction, exceptions under one NOT(OR) */
	static char sk[] = "SMTP:CAROL@EXAMPLE.NET";
	static uint32_t mapi_to = MAPI_TO, dt = DT_MAILUSER;
	auto cmt = mk<RESTRICTION_COMMENT>();
	cmt->count = 3;
	cmt->ppropval = new TAGGED_PROPVAL[3]{
		{PROP_TAG(PT_LONG, 0x6000), &mapi_to},
		{PROP_TAG(PT_STRING8, 0x0001), deconst("Carol C <carol@example.net>")},
		{PR_DISPLAY_TYPE, &dt},
	};
	auto skbin = mk<BINARY>();
	skbin->cb = sizeof(sk);
	skbin->pv = sk;
	cmt->pres = new RESTRICTION(r_prop(RELOP_EQ, PR_SEARCH_KEY, skbin));
	auto xnot = mk<RESTRICTION_NOT>();
	xnot->res = r_list(RES_OR, {
		r_content(PR_SUBJECT, FL_SUBSTRING | FL_IGNORECASE, "s1"),
		mkres(RES_BITMASK, new RESTRICTION_BITMASK{BMR_NEZ, PR_MESSAGE_FLAGS, MSGFLAG_HASATTACH}),
	});
	row = stored(r_list(RES_AND, {mkres(RES_COMMENT, cmt), mkres(RES_NOT, xnot)}), *mark);
	CHECK(row != nullptr);
	r = from_mapi(*row, env);
	CHECK(!r.not_supported.value_or(false));
	CHECK((r.conditions.v[P_SentToAddresses]->addrs ==
	      std::vector<Address>{{"Carol C", "carol@example.net", "SMTP"}}));
	CHECK(r.exceptions.v[P_ContainsSubjectStrings]->strings == std::vector<std::string>{"s1"});
	CHECK(r.exceptions.v[P_HasAttachments]->flag);

	/* Unknown parts flag the rule, the rest is still shown */
	auto pc = mk<RESTRICTION_PROPCOMPARE>();
	pc->relop = RELOP_EQ;
	pc->proptag1 = PR_SUBJECT;
	pc->proptag2 = PR_BODY;
	row = stored(r_list(RES_AND, {mkres(RES_PROPCOMPARE, pc),
	      r_prop(RELOP_EQ, PR_MESSAGE_TO_ME, &yes)}), *mark);
	CHECK(row != nullptr);
	r = from_mapi(*row, env);
	CHECK(r.not_supported == true);
	CHECK(r.conditions.v[P_SentToMe]->flag);

	/* Delegate rule action */
	auto fwd = mk<FORWARDDELEGATE_ACTION>();
	fwd->count = 1;
	fwd->pblock = new RECIPIENT_BLOCK[1];
	fwd->pblock[0].count = 1;
	fwd->pblock[0].ppropval = new TAGGED_PROPVAL[1]{{PR_SMTP_ADDRESS, deconst("d@example.org")}};
	row = stored(r_prop(RELOP_EQ, PR_MESSAGE_TO_ME, &yes), *one_action(OP_DELEGATE, 0, fwd));
	CHECK(row != nullptr);
	CHECK(from_mapi(*row, env).not_supported == true);

	auto ex = mk<RESTRICTION_EXIST>();
	ex->proptag = PR_MESSAGE_CLASS;
	/* grommunio-web's "no action" placeholder with stop processing */
	Rule stop;
	stop.name = "stop";
	stop.priority = 1;
	stop.actions.v[A_StopProcessingRules] = Value{.flag = true};
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *acts = nullptr;
	std::vector<ValidationError> errs;
	CHECK(to_mapi(stop, env, cond, acts, errs));
	CHECK(acts->count == 1 && acts->pblock[0].type == OP_DEFER_ACTION);
	row = stored(mkres(RES_EXIST, ex), *acts, ST_ENABLED | ST_EXIT_LEVEL);
	CHECK(row != nullptr);
	r = from_mapi(*row, env);
	CHECK(!r.not_supported.value_or(false));
	CHECK(r.conditions.empty());
	CHECK(r.actions.v[A_StopProcessingRules]->flag);
	CHECK(!r.actions.v[A_MarkAsRead]);

	/* Out-of-office rules do not map */
	row = stored(mkres(RES_EXIST, ex), *mark, ST_ENABLED | ST_ONLY_WHEN_OOF);
	CHECK(from_mapi(*row, env).not_supported == true);
	return EXIT_SUCCESS;
}

static bool pred_written(unsigned int k)
{
	switch (k) {
	case P_FromConnectedAccounts:
	case P_MessageClassifications:
		return false;
	case P_FromAddresses:
	case P_SentToAddresses:
		return true;
	default:
		break;
	}
	auto t = pred_type(k);
	if (t == vtype::strings || t == vtype::flag)
		return true;
	return t != vtype::addresses;
	return false;
}

static bool act_written(unsigned int k)
{
	switch (k) {
	case A_MarkAsRead:
	case A_PermanentDelete:
	case A_Delete:
	case A_StopProcessingRules:
		return true;
	case A_CopyToFolder:
	case A_MoveToFolder:
	case A_AssignCategories:
	case A_MarkImportance:
		return true;
	case A_ForwardToRecipients:
	case A_ForwardAsAttachmentToRecipients:
	case A_RedirectToRecipients:
		return true;
	case A_ServerReplyWithMessage:
		return true;
	default:
		return false;
	}
}

/* Each predicate as condition and as exception, write then read */
static int t_predicates()
{
	test_env env;
	for (unsigned int k = 0; k < P_COUNT; ++k) {
		if (!pred_written(k))
			continue;
		for (bool exc : {false, true}) {
			Rule r;
			r.name = pred_name(k);
			r.priority = 1;
			r.enabled = true;
			auto v = sample(pred_type(k), k == P_ContainsSenderStrings);
			(exc ? r.exceptions : r.conditions).v[k] = v;
			r.actions.v[A_MarkAsRead] = Value{.flag = true};
			RESTRICTION *cond = nullptr;
			RULE_ACTIONS *acts = nullptr;
			std::vector<ValidationError> errs;
			if (!to_mapi(r, env, cond, acts, errs)) {
				fprintf(stderr, "%s: %s\n", pred_name(k), errs[0].code.c_str());
				return EXIT_FAILURE;
			}
			auto row = stored(*cond, *acts);
			CHECK(row != nullptr);
			auto r2 = from_mapi(*row, env);
			if (r2.not_supported.value_or(false) || r2.conditions != r.conditions ||
			    r2.exceptions != r.exceptions) {
				fprintf(stderr, "%s (%s): no round trip: %s\n", pred_name(k),
				        exc ? "exception" : "condition", cond->repr().c_str());
				return EXIT_FAILURE;
			}
		}
	}
	/* FlaggedForAction without a request text */
	Rule r;
	r.name = "any flag";
	r.priority = 1;
	r.conditions.v[P_FlaggedForAction] = Value{.text = "Any"};
	r.actions.v[A_MarkAsRead] = Value{.flag = true};
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *acts = nullptr;
	std::vector<ValidationError> errs;
	CHECK(to_mapi(r, env, cond, acts, errs));
	CHECK(cond->rt == RES_PROPERTY);
	CHECK(from_mapi(*stored(*cond, *acts), env).conditions == r.conditions);
	return EXIT_SUCCESS;
}

static int t_actions()
{
	test_env env;
	for (unsigned int k = 0; k < A_COUNT; ++k) {
		if (!act_written(k))
			continue;
		Rule r;
		r.name = act_name(k);
		r.priority = 1;
		r.actions.v[k] = sample(act_type(k));
		RESTRICTION *cond = nullptr;
		RULE_ACTIONS *acts = nullptr;
		std::vector<ValidationError> errs;
		if (!to_mapi(r, env, cond, acts, errs)) {
			fprintf(stderr, "%s: %s\n", act_name(k), errs[0].code.c_str());
			return EXIT_FAILURE;
		}
		auto row = stored(*cond, *acts, k == A_StopProcessingRules ? ST_EXIT_LEVEL : 0);
		CHECK(row != nullptr);
		auto r2 = from_mapi(*row, env);
		if (r2.not_supported.value_or(false) || r2.actions != r.actions) {
			fprintf(stderr, "%s: no round trip: %s\n", act_name(k), acts->repr().c_str());
			return EXIT_FAILURE;
		}
		if (k == A_Delete) {
			CHECK(acts->pblock[0].type == OP_MOVE);
		}
	}
	return EXIT_SUCCESS;
}

static int t_other_store()
{
	test_env env;
	Rule r;
	r.name = "x";
	r.priority = 1;
	r.actions.v[A_CopyToFolder] = Value{.folder = {false, "X99", "", ""}};
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *acts = nullptr;
	std::vector<ValidationError> errs;
	CHECK(to_mapi(r, env, cond, acts, errs));
	auto mc = static_cast<const MOVECOPY_ACTION *>(acts->pblock[0].pdata);
	CHECK(mc->same_store == 0);
	auto r2 = from_mapi(*stored(*cond, *acts), env);
	CHECK(r2.actions == r.actions);
	return EXIT_SUCCESS;
}

static int t_forward_shape()
{
	test_env env;
	Rule r;
	r.name = "fwd";
	r.priority = 1;
	r.actions.v[A_RedirectToRecipients] = Value{.addrs = {{"", "/o=x/ou=y/cn=Recipients/cn=dave", "EX"}}};
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *acts = nullptr;
	std::vector<ValidationError> errs;
	CHECK(to_mapi(r, env, cond, acts, errs));
	auto &blk = acts->pblock[0];
	CHECK(blk.type == OP_FORWARD);
	CHECK(blk.flavor == (FWD_PRESERVE_SENDER | FWD_DO_NOT_MUNGE_MSG));
	auto fwd = static_cast<const FORWARDDELEGATE_ACTION *>(blk.pdata);
	TPROPVAL_ARRAY pv{static_cast<uint16_t>(fwd->pblock[0].count), fwd->pblock[0].ppropval};
	CHECK(strcmp(pv.get<const char>(PR_SMTP_ADDRESS), "dave@example.org") == 0);
	CHECK(strcmp(pv.get<const char>(PR_ADDRTYPE), "SMTP") == 0);
	auto sk = pv.get<const BINARY>(PR_SEARCH_KEY);
	CHECK(sk != nullptr && sk->cb == 22 && memcmp(sk->pv, "SMTP:DAVE@EXAMPLE.ORG", 22) == 0);
	CHECK(pv.has(PR_ENTRYID));

	r.actions.v[A_RedirectToRecipients].reset();
	r.actions.v[A_SendSMSAlertToRecipients] = Value{.addrs = {{"", "+43123", "MOBILE"}}};
	CHECK(!to_mapi(r, env, cond, acts, errs));
	CHECK(errs.back().code == "UnsupportedRule");
	CHECK(errs.back().field == "Action:SendSMSAlertToRecipients");
	return EXIT_SUCCESS;
}

static bool has_error(const std::vector<ValidationError> &errs, const char *field, const char *code)
{
	for (const auto &e : errs)
		if (e.field == field && e.code == code)
			return true;
	return false;
}

static int t_validate()
{
	Rule r;
	r.name = "v";
	r.priority = 1;
	r.id = "dCsAAABjz0Q=";
	auto errs = validate(r, Operation::CREATE);
	CHECK(has_error(errs, "RuleId", "CreateWithRuleId"));
	CHECK(has_error(errs, "Actions", "MissingAction"));
	r.actions.v[A_MarkAsRead] = Value{.flag = false};
	CHECK(has_error(validate(r, Operation::SET), "Actions", "MissingAction"));
	r.id.reset();
	CHECK(has_error(validate(r, Operation::SET), "RuleId", "MissingParameter"));
	r.actions.v[A_StopProcessingRules] = Value{.flag = true};
	CHECK(validate(r, Operation::CREATE).empty());
	auto c = r;
	c.priority = 0;
	c.name.clear();
	c.conditions.v[P_ContainsSubjectStrings] = Value{.strings = {""}};
	c.conditions.v[P_ContainsBodyStrings] = Value{};
	c.conditions.v[P_ContainsHeaderStrings] = Value{.strings = {std::string(300, 'x')}};
	c.exceptions.v[P_WithinDateRange] = Value{.start = 20, .end = 10};
	c.conditions.v[P_WithinDateRange] = Value{};
	c.conditions.v[P_WithinSizeRange] = Value{.min = 0, .max = 9999990};
	c.exceptions.v[P_WithinSizeRange] = Value{.min = 50, .max = 10};
	c.conditions.v[P_FromAddresses] = Value{.addrs = {{"x", "", "SMTP"}}};
	c.exceptions.v[P_FromAddresses] = Value{.addrs = {{"x", "+431", "MOBILE"}}};
	c.actions.v[A_ForwardToRecipients] = Value{};
	errs = validate(c, Operation::CREATE);
	CHECK(has_error(errs, "Priority", "InvalidValue"));
	CHECK(has_error(errs, "DisplayName", "EmptyValueFound"));
	CHECK(has_error(errs, "Condition:ContainsSubjectStrings", "EmptyValueFound"));
	CHECK(has_error(errs, "Condition:ContainsBodyStrings", "EmptyValueFound"));
	CHECK(has_error(errs, "Condition:ContainsHeaderStrings", "StringValueTooBig"));
	CHECK(has_error(errs, "Exception:WithinDateRange", "InvalidDateRange"));
	CHECK(has_error(errs, "Condition:WithinDateRange", "MissingRangeValue"));
	CHECK(has_error(errs, "Condition:WithinSizeRange", "InvalidValue"));
	CHECK(has_error(errs, "Exception:WithinSizeRange", "InvalidSizeRange"));
	CHECK(has_error(errs, "Condition:FromAddresses", "InvalidAddress"));
	CHECK(has_error(errs, "Exception:FromAddresses", "UnsupportedAddress"));
	CHECK(has_error(errs, "Action:ForwardToRecipients", "EmptyValueFound"));
	c = r;
	c.conditions.v[P_WithinSizeRange] = Value{.min = -1};
	CHECK(has_error(validate(c, Operation::CREATE), "Condition:WithinSizeRange", "SizeLessThanZero"));

	test_env env;
	c = r;
	c.conditions.v[P_FromConnectedAccounts] = Value{.strings = {"a@b"}};
	c.exceptions.v[P_MessageClassifications] = Value{.strings = {"c"}};
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *acts = nullptr;
	errs.clear();
	CHECK(!to_mapi(c, env, cond, acts, errs));
	CHECK(has_error(errs, "Condition:FromConnectedAccounts", "ConnectedAccountNotFound"));
	CHECK(has_error(errs, "Exception:MessageClassifications", "MessageClassificationNotFound"));
	return EXIT_SUCCESS;
}

int main()
{
	using fn = int (*)();
	for (auto f : std::initializer_list<fn>{t_ruleid, t_parse, t_xml_roundtrip,
	     t_read_variants,
	     t_errors_xml, t_sequences, t_actions, t_validate,
	     t_predicates,
	     t_other_store,
	     t_forward_shape,
	     }) {
		auto ret = f();
		if (ret != EXIT_SUCCESS) {
			printf("FAILED\n");
			return ret;
		}
	}
	return EXIT_SUCCESS;
}
