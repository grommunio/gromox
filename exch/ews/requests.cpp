// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <tinyxml2.h>
#include <unordered_set>
#include <variant>
#include <vector>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <gromox/ab_tree.hpp>
#include <gromox/algorithm.hpp>
#include <gromox/clock.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/freebusy.hpp>
#include <gromox/json.hpp>
#include <gromox/mapitags.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "exceptions.hpp"
#include "namedtags.hpp"
#include "requests.hpp"

DECLARE_HPM_API(gromox::EWS, extern);

namespace gromox::EWS::Requests {

using namespace gromox;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

///////////////////////////////////////////////////////////////////////////////
//Helper functions

namespace {

static constexpr uint32_t fbRights = frightsFreeBusySimple | frightsFreeBusyDetailed;
/* Rights that let a reader read some properties of the items in a folder */
static constexpr uint32_t itemReadRights = frightsReadAny | fbRights;

/**
 * @brief      Returns whether a folder is a calendar folder
 */
static bool isCalendar(const EWSContext &ctx, const std::string &dir,
    uint64_t fid)
{
	static constexpr proptag_t tags[] = {PR_CONTAINER_CLASS};
	auto cls = ctx.getFolderProps(dir, fid, tags).get<const char>(PR_CONTAINER_CLASS);
	return cls != nullptr && class_match_prefix(cls, "IPF.Appointment") == 0;
}

/**
 * @brief      Returns the rights of the user on a folder for reading its items
 *
 * frightsFreeBusySimple and frightsFreeBusyDetailed only grant access to
 * the items of calendar folders. Without frightsReadAny they are removed
 * from the rights on any other folder. frightsReadAny grants more than
 * both on every folder, so with it the rights are returned unchanged and
 * the folder class is not looked up.
 */
static uint32_t itemRights(const EWSContext &ctx, const std::string &dir,
    uint64_t fid)
{
	auto rights = ctx.permissions(dir, fid);
	if (rights & frightsReadAny)
		return rights;
	if (rights & fbRights && !isCalendar(ctx, dir, fid))
		rights &= ~fbRights;
	return rights;
}

/**
 * @brief      Get the property tags a restriction leaf tests
 *
 * @return     Number of tags stored in @p tags
 */
static size_t leafTags(RESTRICTION &r, proptag_t *tags[2])
{
	switch (r.rt) {
	case mapi_rtype::content:
		tags[0] = &r.cont->proptag;
		return 1;
	case mapi_rtype::property:
		tags[0] = &r.prop->proptag;
		return 1;
	case mapi_rtype::propcmp:
		tags[0] = &r.pcmp->proptag1;
		tags[1] = &r.pcmp->proptag2;
		return 2;
	case mapi_rtype::bitmask:
		tags[0] = &r.bm->proptag;
		return 1;
	case mapi_rtype::exist:
		tags[0] = &r.exist->proptag;
		return 1;
	default:
		return 0;
	}
}

/**
 * @brief      Copy a restriction leaf so its tags can be changed
 */
static RESTRICTION copyLeaf(const RESTRICTION &r)
{
	RESTRICTION c;
	c.rt = r.rt;
	switch (r.rt) {
	case mapi_rtype::content:
		c.cont = EWSContext::construct<RESTRICTION_CONTENT>(*r.cont);
		break;
	case mapi_rtype::property:
		c.prop = EWSContext::construct<RESTRICTION_PROPERTY>(*r.prop);
		break;
	case mapi_rtype::propcmp:
		c.pcmp = EWSContext::construct<RESTRICTION_PROPCOMPARE>(*r.pcmp);
		break;
	case mapi_rtype::bitmask:
		c.bm = EWSContext::construct<RESTRICTION_BITMASK>(*r.bm);
		break;
	default:
		c.exist = EWSContext::construct<RESTRICTION_EXIST>(*r.exist);
		break;
	}
	return c;
}

/**
 * @brief      Build a restriction matching the private or the public items
 *
 * Private items have PR_SENSITIVITY set to SENSITIVITY_PRIVATE, public
 * items are all others.
 */
static RESTRICTION *matchPrivate(bool priv)
{
	auto eq = EWSContext::construct<RESTRICTION_PROPERTY>();
	eq->relop = priv ? relop::eq : relop::ne;
	eq->proptag = eq->propval.proptag = PR_SENSITIVITY;
	eq->propval.pvalue = EWSContext::construct<uint32_t>(SENSITIVITY_PRIVATE);
	auto res = EWSContext::construct<RESTRICTION>();
	res->rt = mapi_rtype::property;
	res->prop = eq;
	return res;
}

/**
 * @brief      Limit a restriction to the properties the reader may read
 *
 * A property that the reader may not read in an item is treated as absent
 * from that item, so the result never depends on its value.
 *
 * - A node on a property that is readable in no item gets property ID 0
 *   in its tag. No message has a property with that ID.
 * - A node on a property that is readable in public items only, see
 *   sShape::Query, becomes (public AND node) OR (private AND node0). In
 *   node0 that property has ID 0.
 * - A node that tests no single property is replaced by RES_EXIST on
 *   property ID 0, which matches no item, unless the reader may read
 *   every property of every item. EWS builds no such nodes.
 */
static void limitRestriction(const sShape &shape, RESTRICTION &r)
{
	switch (r.rt) {
	case mapi_rtype::r_and:
	case mapi_rtype::r_or:
		for (auto &sub : *r.andor)
			limitRestriction(shape, sub);
		return;
	case mapi_rtype::r_not:
		return limitRestriction(shape, r.xnot->res);
	default:
		break;
	}
	proptag_t *tags[2];
	auto n = leafTags(r, tags);
	if (n == 0) {
		if (!shape.allReadable()) {
			r.rt = mapi_rtype::exist;
			r.exist = EWSContext::construct<RESTRICTION_EXIST>();
		}
		return;
	}
	bool publicOnly = false;
	for (size_t i = 0; i < n; ++i) {
		auto q = shape.queryable(*tags[i]);
		if (q == sShape::Query::none)
			*tags[i] = PROP_TAG(PROP_TYPE(*tags[i]), 0);
		else if (q == sShape::Query::publicOnly)
			publicOnly = true;
	}
	if (!publicOnly)
		return;
	auto node0 = EWSContext::construct<RESTRICTION>(copyLeaf(r));
	n = leafTags(*node0, tags);
	for (size_t i = 0; i < n; ++i)
		if (shape.queryable(*tags[i]) == sShape::Query::publicOnly)
			*tags[i] = PROP_TAG(PROP_TYPE(*tags[i]), 0);
	auto node = EWSContext::construct<RESTRICTION>(r);
	r = *tRestriction::any(tRestriction::all(matchPrivate(false), node),
	    tRestriction::all(matchPrivate(true), node0));
}

/**
 * @brief      Limit filter and sort order to the properties the reader may read
 *
 * The filter is edited by limitRestriction(). Each sort key is handled
 * by the items in which the reader may read its property, see
 * sShape::Query.
 *
 * - In all items: the key is kept.
 * - In public items only: the key is kept. Private items then come from
 *   a table of their own, sorted by the keys readable in all items, and
 *   are listed after the others.
 * - In no item: the key is removed.
 *
 * Private items never reveal more than public ones, so no key is readable
 * in private items only.
 *
 * @param      shape     Shape restricted to the folder
 * @param      res       Restriction to limit
 * @param      sort      Sort order to limit
 * @param      privSort  Set to the order of the private items
 *
 * @return     Whether private items need a table of their own
 */
static bool limitQuery(const sShape &shape, RESTRICTION *&res,
    SORTORDER_SET *&sort, SORTORDER_SET *&privSort)
{
	privSort = nullptr;
	if (res != nullptr)
		limitRestriction(shape, *res);
	if (sort == nullptr)
		return false;
	auto keep = EWSContext::construct<SORTORDER_SET>();
	keep->psort = EWSContext::alloc<SORT_ORDER>(sort->count);
	auto priv = EWSContext::construct<SORTORDER_SET>();
	priv->psort = EWSContext::alloc<SORT_ORDER>(sort->count);
	for (const auto &key : *sort) {
		auto q = shape.queryable(PROP_TAG(key.type, key.propid));
		if (q == sShape::Query::none)
			continue;
		keep->psort[keep->count++] = key;
		if (q == sShape::Query::all)
			priv->psort[priv->count++] = key;
	}
	sort = keep->count > 0 ? keep : nullptr;
	if (priv->count == keep->count)
		return false;
	privSort = priv->count > 0 ? priv : nullptr;
	return true;
}

/**
 * @brief      Encode hex string
 *
 * @param      bin         Binary data
 *
 * @return     String containing hex encoded data
 */
std::string hexEncode(const std::string& bin)
{
	static constexpr char digits[] = "0123456789abcdef";
	std::string hex(bin.size()*2, 0);
	auto it = hex.begin();
	for (char in : bin) {
		*it++ = digits[static_cast<uint8_t>(in) >> 4];
		*it++ = digits[static_cast<uint8_t>(in) & 0xf];
	}
	return hex;
}

/**
 * @brief      Convert string to lower case
 *
 * @param      str     String to convert
 *
 * @return     Reference to the string
 */
static inline std::string &tolower_inplace(std::string &str)
{
	transform(str.begin(), str.end(), str.begin(), HX_tolower);
	return str;
}

/**
 * @brief      Derive timezone information from request headers
 *
 * Attempts to construct a SerializableTimeZone from the SOAP TimeZoneContext
 * header. The header layout is simplified to a single Period definition by
 * Exchange clients and the Bias is expressed as an ISO-8601 duration string.
 *
 * @param      ctx   Request context
 *
 * @return     Populated timezone on success, empty optional otherwise
 */
std::optional<tSerializableTimeZone> timezone_from_context(const EWSContext& ctx)
{
	const XMLElement *tag = ctx.request().header;
	if (tag == nullptr)
		return std::nullopt;
	/* SOAP::Envelope::clean() strips namespace prefixes from element names */
	tag = tag->FirstChildElement("TimeZoneContext");
	if (tag == nullptr)
		return std::nullopt;
	tag = tag->FirstChildElement("TimeZoneDefinition");
	if (tag == nullptr)
		return std::nullopt;
	tag = tag->FirstChildElement("Periods");
	if (tag == nullptr)
		return std::nullopt;
	tag = tag->FirstChildElement("Period");
	if (tag == nullptr)
		return std::nullopt;
	const char* bias = tag->Attribute("Bias");
	if (bias == nullptr || *bias == '\0')
		return std::nullopt;

	bool negative = false;
	const char* cursor = bias;
	if (*cursor == '-' || *cursor == '+') {
		negative = *cursor == '-';
		++cursor;
	}

	char* end = nullptr;
	auto seconds = HX_strtoull8601p_sec(cursor, &end);
	if (end == nullptr || end == cursor)
		return std::nullopt;

	auto minutes = static_cast<int32_t>(seconds / 60);
	if (negative)
		minutes = -minutes;
	return tSerializableTimeZone(minutes);
}

/* Copied straight outta zcore/ab_tree.cpp */
static bool ab_tree_resolve_node(const ab_tree::ab_node &node, const char *needle)
{
	using ab_tree::userinfo;
	std::string dn = node.displayname();
	if (strcasestr(dn.c_str(), needle) != nullptr)
		return true;
	if (node.dn(dn) && strcasecmp(dn.c_str(), needle) == 0)
		return true;

	switch (node.type()) {
	case ab_tree::abnode_type::user: {
		auto s = node.user_info(userinfo::mail_address);
		if (s != nullptr && strcasestr(s, needle) != nullptr)
			return true;
		for (const auto &a : node.aliases())
			if (strcasestr(a.c_str(), needle) != nullptr)
				return true;
		for (auto info : {userinfo::nick_name, userinfo::job_title,
		     userinfo::comment, userinfo::mobile_tel,
		     userinfo::business_tel, userinfo::home_address}) {
			s = node.user_info(info);
			if (s != nullptr && strcasestr(s, needle) != nullptr)
				return true;
		}
		break;
	}
	case ab_tree::abnode_type::mlist:
		node.mlist_info(&dn, nullptr, nullptr);
		if (strcasestr(dn.c_str(), needle) != nullptr)
			return true;
		break;
	default:
		break;
	}
	return false;
}

static bool ab_tree_resolvename(const ab_tree::ab_base &base, const char *needle,
    std::vector<ab_tree::minid> &result) try
{
	result.clear();
	for (auto it = base.ubegin(); it != base.uend(); ++it) {
		ab_tree::ab_node node(it);
		if (node.hidden() & AB_HIDE_RESOLVE ||
		    !ab_tree_resolve_node(node, needle))
			continue;
		result.push_back(*it);
	}
	return true;
} catch (const std::bad_alloc &) {
	return false;
}

static std::string extract_domain(const char *address)
{
	if (address == nullptr)
		return {};
	const char *at = strchr(address, '@');
	if (at == nullptr || at[1] == '\0')
		return {};
	std::string domain(at + 1);
	return tolower_inplace(domain);
}

static void resolve_domain_ids(const std::string& domain, unsigned int& domain_id, unsigned int& org_id)
{
	if (!mysql_adaptor_get_domain_ids(domain.c_str(), &domain_id, &org_id))
		throw DispatchError(E3027);
}

static bool is_visible_room(const sql_user& user)
{
	return user.dtypx == DT_ROOM && !(user.cloak_bits & AB_HIDE_FROM_GAL) && !user.username.empty();
}

static tRoomType make_room(const sql_user& user)
{
	tRoomType room;
	auto &id = room.Id.emplace();
	auto it = user.propvals.find(PR_DISPLAY_NAME);
	if (it != user.propvals.end() && !it->second.empty())
		id.Name = it->second;
	else
		id.Name = user.username;
	id.EmailAddress = user.username;
	id.RoutingType = "SMTP";
	id.MailboxType = Enum::MailboxTypeType(Enum::Mailbox);
	return room;
}

static bool collect_rooms(unsigned int domain_id, std::vector<tRoomType>* rooms=nullptr)
{
	std::vector<sql_user> users;
	if (!mysql_adaptor_get_domain_users(domain_id, users))
		throw DispatchError(E3386);
	bool found = false;
	if (rooms) {
		rooms->clear();
		rooms->reserve(users.size());
	}
	for (const auto &user : users) {
		if (!is_visible_room(user))
			continue;
		found = true;
		if (rooms)
			rooms->emplace_back(make_room(user));
		else
			break;
	}
	return found;
}

static tRoomListEntry make_room_list_entry(const sql_domain& domain)
{
	tRoomListEntry entry;
	entry.EmailAddress = std::string("rooms@") + domain.name;
	entry.RoutingType = "SMTP";
	entry.MailboxType = Enum::MailboxTypeType(Enum::PublicDL);
	entry.Name = domain.title.empty() ? domain.name : domain.title;
	return entry;
}

} //anonymous namespace
///////////////////////////////////////////////////////////////////////
//Request implementations

/**
 * @brief      Determine the mailbox an entry ID belongs to
 *
 * @param      ctx    Request context
 * @param      id     Decoded identifier
 *
 * @return     Primary address of the owning mailbox, if it is a private store
 */
static std::optional<std::string> convertid_owner(const EWSContext &ctx,
    const tBaseItemId &id) try
{
	sFolderSpec folder;
	if (id.type == tBaseItemId::ID_FOLDER)
		folder = ctx.resolveFolder(tFolderId(id.Id, tBaseItemId::ID_FOLDER));
	else if (id.type == tBaseItemId::ID_ITEM ||
	    id.type == tBaseItemId::ID_ATTACHMENT ||
	    id.type == tBaseItemId::ID_OCCURRENCE)
		folder = ctx.resolveFolder(sMessageEntryId(id.Id.data(), id.Id.size()));
	else
		return std::nullopt;
	if (folder.location != sFolderSpec::PRIVATE || !folder.target)
		return std::nullopt;
	return folder.target;
} catch (const EWSError &) {
	return std::nullopt;
}

/**
 * @brief      Process ConvertId
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mConvertIdRequest &&request, XMLElement *response, EWSContext &ctx)
{
	response->SetName("m:ConvertIdResponse");
	ctx.response().body->SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");

	mConvertIdResponse data;
	data.ResponseMessages.reserve(request.SourceIds.size());

	for (auto &sourceId : request.SourceIds) try {
		if (!std::holds_alternative<tAlternateId>(sourceId))
			throw EWSError::InternalServerError(E3251);
		tAlternateId& aid = std::get<tAlternateId>(sourceId);
		if (aid.Format == request.DestinationFormat) {
			data.ResponseMessages.emplace_back().AlternateId = std::move(aid);
		} else {
			tBaseItemId id(sBase64Binary(aid.Format == Enum::HexEntryId ?
			               hex2bin(aid.Id) : base64_decode(aid.Id)),
			               tBaseItemId::ID_GUESS);
			if (id.type == tBaseItemId::ID_UNKNOWN)
				throw EWSError::CorruptData(E3252);
			mConvertIdResponseMessage msg;
			auto mailbox = convertid_owner(ctx, id).value_or(aid.Mailbox);
			if (request.DestinationFormat == Enum::EwsId ||
			    request.DestinationFormat == Enum::EwsLegacyId)
				msg.AlternateId = tAlternateId(request.DestinationFormat, base64_encode(id.serializeId()), mailbox);
			else if (request.DestinationFormat == Enum::HexEntryId)
				msg.AlternateId = tAlternateId(request.DestinationFormat, hexEncode(id.Id), mailbox);
			else
				throw EWSError::InternalServerError(E3253);
			data.ResponseMessages.emplace_back(std::move(msg));
		}
		data.ResponseMessages.back().success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Search grommunio-web's recipient history for FindPeople matches
 *
 * FindPeople's QuerySources typically ask for both "Directory", referring the
 * ab_tree GAL and handled by the caller, and "Mailbox", referring to people
 * the user has actually corresponded with, regardless of whether they are in
 * any directory. Gromox itself does not track recently-used recipients.
 *
 * g-web maintains PSETID_Gromox:websettings_recipienthistory as a JSON blob of
 * {display_name, smtp_address, count, last_used} entries, updated whenever the
 * user sends mail. Reusing it here means Outlook's autocomplete benefits from
 * the exact same history that g-web webapp already builds, it just never gets
 * contributed to by non-gweb send actions.
 */
static void findpeople_search_recipient_history(const EWSContext &ctx,
    const std::string &query, std::vector<tPersona> &out) try
{
	const char *user = znul(ctx.auth_info().username);
	std::string dir = ctx.get_maildir(user);
	PROPERTY_NAME pn = {MNID_STRING, PSETID_Gromox, 0, deconst("websettings_recipienthistory")};
	PROPNAME_ARRAY propNames{1, &pn};
	PROPID_ARRAY propIds = ctx.getNamedPropIds(dir, propNames);
	if (propIds.size() != 1)
		return;
	const proptag_t tag = PROP_TAG(PT_UNICODE, propIds[0]);
	TPROPVAL_ARRAY props;
	if (!ctx.plugin().exmdb.get_store_properties(dir.c_str(), CP_ACP, {&tag, 1}, &props))
		return;
	auto json_str = props.get<const char>(tag);
	if (json_str == nullptr || *json_str == '\0')
		return;
	Json::Value root;
	if (!gromox::str_to_json(json_str, root) || !root.isMember("recipients"))
		return;

	for (const auto &entry : root["recipients"]) {
		auto name  = entry.get("display_name", "").asString();
		auto email = entry.get("smtp_address", "").asString();
		if (email.empty())
			continue;
		if (strcasestr(name.c_str(), query.c_str()) == nullptr &&
		    strcasestr(email.c_str(), query.c_str()) == nullptr)
			continue;

		tPersona persona;
		persona.PersonaType = "Person";
		if (!name.empty()) {
			persona.DisplayName = name;
			/*
			 * Outlook Mac's FindPeople request explicitly asks for
			 * persona:GivenName/persona:Surname
			 * (AdditionalProperties). Exchange always sends both,
			 * even for a simple two-word display name. Leaving
			 * them unset might cause Outlook to silently drop the
			 * whole persona since it asked for fields that never
			 * show up in the response.
			 */
			auto space = name.find(' ');
			if (space != std::string::npos) {
				persona.GivenName = name.substr(0, space);
				persona.Surname = name.substr(space + 1);
			} else {
				persona.GivenName = name;
			}
		}

		tEmailAddressType addr;
		addr.Name = persona.DisplayName;
		addr.EmailAddress = email;
		addr.RoutingType  = "SMTP";
		addr.MailboxType  = Enum::Mailbox;
		persona.EmailAddress = std::move(addr);

		tPersonaId pid;
		pid.Id = base64_encode(email);
		persona.PersonaId = std::move(pid);
		persona.RelevanceScore = std::min(entry.get("count", 1).asUInt(),
		                         static_cast<unsigned int>(INT32_MAX));
		out.emplace_back(std::move(persona));
	}
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
}

/**
 * @brief      Search the requesting user's own Contacts folder for FindPeople matches
 *
 * This function will match PR_DISPLAY_NAME or any of Email1/2/3EmailAddress by
 * substring, using the same restriction as g-web's own ResolveNamesModule::
 * searchContactsFolders()/getAmbigiousContactRestriction().
 */
static void findpeople_search_contacts(const EWSContext &ctx,
    const std::string &query, std::vector<tPersona> &out) try
{
	if (query.empty())
		return;
	const char *user = znul(ctx.auth_info().username);
	std::string dir = ctx.get_maildir(user);

	std::array<PROPERTY_NAME, 3> names = {NtEmailAddress1, NtEmailAddress2, NtEmailAddress3};
	PROPNAME_ARRAY propNames = {static_cast<uint16_t>(names.size()), names.data()};
	PROPID_ARRAY propIds = ctx.getNamedPropIds(dir, propNames);
	if (propIds.size() != names.size())
		return;
	std::array<proptag_t, 3> emailTags = {PROP_TAG(PT_UNICODE, propIds[0]),
		PROP_TAG(PT_UNICODE, propIds[1]), PROP_TAG(PT_UNICODE, propIds[2])};

	TAGGED_PROPVAL matchValue = {0, deconst(query.c_str())};
	std::array<RESTRICTION_CONTENT, 4> contentRestrictions{};
	std::array<RESTRICTION, 4> childRestrictions{};
	contentRestrictions[0].fuzzy_level = FL_SUBSTRING | FL_IGNORECASE;
	contentRestrictions[0].proptag = PR_DISPLAY_NAME;
	contentRestrictions[0].propval.proptag = PR_DISPLAY_NAME;
	contentRestrictions[0].propval.pvalue = matchValue.pvalue;
	childRestrictions[0].rt = RES_CONTENT;
	childRestrictions[0].cont = &contentRestrictions[0];
	for (size_t i = 0; i < emailTags.size(); ++i) {
		auto &cr = contentRestrictions[i + 1];
		cr.fuzzy_level = FL_SUBSTRING | FL_IGNORECASE;
		cr.proptag = emailTags[i];
		cr.propval.proptag = emailTags[i];
		cr.propval.pvalue = matchValue.pvalue;
		childRestrictions[i + 1].rt = RES_CONTENT;
		childRestrictions[i + 1].cont = &cr;
	}
	RESTRICTION_AND_OR orGroup = {static_cast<uint32_t>(childRestrictions.size()), childRestrictions.data()};
	RESTRICTION restriction = {RES_OR, {&orGroup}};

	uint32_t tableId = 0, rowCount = 0;
	eid_t contactsFid(1, PRIVATE_FID_CONTACTS);
	if (!ctx.plugin().exmdb.load_content_table(dir.c_str(), CP_ACP,
	    contactsFid, nullptr, TABLE_FLAG_NONOTIFICATIONS, &restriction,
	    nullptr, &tableId, &rowCount) || rowCount == 0)
		return;
	auto cl_tbl = HX::make_scope_exit([&]() {
		ctx.plugin().exmdb.unload_table(dir.c_str(), tableId);
	});

	static constexpr uint32_t maxResults = 50;
	std::array<proptag_t, 4> cols = {PR_DISPLAY_NAME, emailTags[0], emailTags[1], emailTags[2]};
	TARRAY_SET rows{};
	if (!ctx.plugin().exmdb.query_table(dir.c_str(), nullptr, CP_ACP,
	    tableId, cols, 0, std::min(rowCount, maxResults), &rows))
		return;

	for (const auto &row : rows) {
		auto name = row.get<const char>(PR_DISPLAY_NAME);
		const char *email = nullptr;
		for (auto tag : emailTags) {
			email = row.get<const char>(tag);
			if (email != nullptr && *email != '\0')
				break;
		}
		if (email == nullptr || *email == '\0')
			continue;

		std::string dispName = name != nullptr ? name : "";
		tPersona persona;
		persona.PersonaType = "Person";
		if (!dispName.empty()) {
			persona.DisplayName = dispName;
			auto space = dispName.find(' ');
			if (space != std::string::npos) {
				persona.GivenName = dispName.substr(0, space);
				persona.Surname = dispName.substr(space + 1);
			} else {
				persona.GivenName = dispName;
			}
		}

		tEmailAddressType addr;
		addr.Name = persona.DisplayName;
		addr.EmailAddress = email;
		addr.RoutingType  = "SMTP";
		addr.MailboxType  = Enum::Mailbox;
		persona.EmailAddress = std::move(addr);

		tPersonaId pid;
		pid.Id = base64_encode(email);
		persona.PersonaId = std::move(pid);
		persona.RelevanceScore = 1;
		out.emplace_back(std::move(persona));
	}
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
}

/**
 * @brief      Process AddEntityFeedback
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mAddEntityFeedbackRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:AddEntityFeedbackResponse");
	mlog(LV_DEBUG, "[ews#%d] AddEntityFeedback: discarding %zu entries",
	     ctx.context_id(), request.entries);
	mAddEntityFeedbackResponse data;
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process FindPeople
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mFindPeopleRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:FindPeopleResponse");

	mFindPeopleResponse data;
	auto &msg = data;
	const char *user = znul(ctx.auth_info().username);
	const char *at = strchr(user, '@');
	std::string domain = at ? at + 1 : user;

	std::vector<ab_tree::minid> results;
	try {
		uint32_t domId = ctx.getAccountId(domain, true);
		auto base = ab_tree::AB.get(-static_cast<int32_t>(domId));
		if (base && ab_tree_resolvename(*base, request.QueryString.c_str(), results)) {
			for (auto mid : results) {
				ab_tree::ab_node node(base.get(), mid);
				tPersona persona;
				std::string val;
				/*
				 * Outlook Mac silently discards personas with
				 * no PersonaType, even when DisplayName/
				 * EmailAddress are populated - it has no way
				 * to classify the suggestion, so it never
				 * offers it in the autocomplete list.
				 */
				persona.PersonaType = "Person";
				if (node.fetch_prop(PR_DISPLAY_NAME, val) == ecSuccess)
					persona.DisplayName = std::move(val);
				if (node.fetch_prop(PR_GIVEN_NAME, val) == ecSuccess)
					persona.GivenName = std::move(val);
				if (node.fetch_prop(PR_SURNAME, val) == ecSuccess)
					persona.Surname = std::move(val);
				std::string email;
				if (node.fetch_prop(PR_SMTP_ADDRESS, email) == ecSuccess) {
					tEmailAddressType addr;
					addr.Name         = persona.DisplayName;
					addr.EmailAddress = email;
					addr.RoutingType  = "SMTP";
					addr.MailboxType  = Enum::Mailbox;
					persona.EmailAddress = std::move(addr);
					/*
					 * Exchange also always includes a PersonaId.
					 * This will not be a real MAPI EntryID here,
					 * just a stable opaque handle derived from the
					 * address, enough for Outlook to accept the
					 * entry as resolvable/insertable.
					 */
					tPersonaId pid;
					pid.Id = base64_encode(std::move(email));
					persona.PersonaId = std::move(pid);
					persona.RelevanceScore = INT32_MAX;
				}
				if (node.fetch_prop(PR_TITLE, val) == ecSuccess)
					persona.Title = std::move(val);
				if (node.fetch_prop(PR_NICKNAME, val) == ecSuccess)
					persona.Nickname = std::move(val);
				if (node.fetch_prop(PR_PRIMARY_TELEPHONE_NUMBER, val) == ecSuccess)
					persona.BusinessPhoneNumber = std::move(val);
				if (node.fetch_prop(PR_MOBILE_TELEPHONE_NUMBER, val) == ecSuccess)
					persona.MobilePhoneNumber = std::move(val);
				if (node.fetch_prop(PR_HOME_ADDRESS_STREET, val) == ecSuccess)
					persona.HomeAddress = std::move(val);
				if (node.fetch_prop(PR_COMMENT, val) == ecSuccess)
					persona.Comment = std::move(val);
				if (persona.DisplayName || persona.EmailAddress ||
				    persona.Title || persona.Nickname ||
				    persona.BusinessPhoneNumber ||
				    persona.MobilePhoneNumber ||
				    persona.HomeAddress || persona.Comment) {
					if (!msg.People)
						msg.People.emplace();
					msg.People->emplace_back(std::move(persona));
				}
			}
		}

		/* Merge in "Mailbox" source results */
		std::vector<tPersona> history;
		findpeople_search_recipient_history(ctx, request.QueryString, history);
		findpeople_search_contacts(ctx, request.QueryString, history);
		if (!history.empty()) {
			if (!msg.People)
				msg.People.emplace();
			auto &people = *msg.People;
			for (auto &persona : history) {
				const std::string *addr = persona.EmailAddress ? &*persona.EmailAddress->EmailAddress : nullptr;
				bool dup = addr && std::any_of(people.begin(), people.end(),
				           [&](const tPersona &p) {
				                   return p.EmailAddress && p.EmailAddress->EmailAddress &&
				                          strcasecmp(p.EmailAddress->EmailAddress->c_str(), addr->c_str()) == 0;
				           });
				if (!dup)
					people.emplace_back(std::move(persona));
			}
		}
		if (msg.People) {
			msg.TotalNumberOfPeopleInView = msg.People->size();
			/*
			 * Outlook Mac's autocomplete always requests a paged
			 * view (IndexedPageItemView). Capturing Exchange shows
			 * EXC always includes FirstMatchingRowIndex/
			 * FirstLoadedRowIndex alongside
			 * TotalNumberOfPeopleInView, even for a single-page
			 * result. We do not implement actual paging, so both
			 * are always the start of (and only) page.
			 */
			msg.FirstMatchingRowIndex = 0;
			msg.FirstLoadedRowIndex = 0;
		}
	} catch (const EWSError &err) {
		mFindPeopleResponse errdata(err);
		errdata.serialize(response);
		return;
	}

	msg.success();
	data.serialize(response);
}

void process(mGetPersonaRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetPersonaResponseMessage");

	mGetPersonaResponseMessage data;

	if (!request.EmailAddress || !request.EmailAddress->EmailAddress) {
		data.error("ErrorInvalidArgument", "EmailAddress is required");
		data.serialize(response);
		return;
	}
	const auto &target = *request.EmailAddress->EmailAddress;
	const char *user = znul(ctx.auth_info().username);
	const char *at = strchr(user, '@');
	std::string domain = at ? at + 1 : user;

	try {
		uint32_t domId = ctx.getAccountId(domain, true);
		auto base = ab_tree::AB.get(-static_cast<int32_t>(domId));
		if (base) {
			for (auto it = base->ubegin(); it != base->uend(); ++it) {
				ab_tree::ab_node node(it);
				if (node.hidden() & AB_HIDE_RESOLVE)
					continue;
				std::string email;
				if (node.fetch_prop(PR_SMTP_ADDRESS, email) != ecSuccess ||
				    strcasecmp(email.c_str(), target.c_str()) != 0)
					continue;
				std::string val;
				tPersona persona;
				if (node.fetch_prop(PR_DISPLAY_NAME, val) == ecSuccess)
					persona.DisplayName = std::move(val);

				tEmailAddressType addr;
				addr.Name = persona.DisplayName;
				addr.EmailAddress = email;
				addr.RoutingType  = "SMTP";
				addr.MailboxType  = Enum::Mailbox;
				persona.EmailAddress = std::move(addr);

				tPersonaId pid;
				pid.Id = base64_encode(std::move(email));
				persona.PersonaId   = std::move(pid);
				persona.PersonaType = "Person";

				if (node.fetch_prop(PR_TITLE, val) == ecSuccess)
					persona.Title = std::move(val);
				if (node.fetch_prop(PR_NICKNAME, val) == ecSuccess)
					persona.Nickname = std::move(val);
				if (node.fetch_prop(PR_PRIMARY_TELEPHONE_NUMBER, val) == ecSuccess)
					persona.BusinessPhoneNumber = std::move(val);
				if (node.fetch_prop(PR_MOBILE_TELEPHONE_NUMBER, val) == ecSuccess)
					persona.MobilePhoneNumber = std::move(val);
				if (node.fetch_prop(PR_HOME_ADDRESS_STREET, val) == ecSuccess)
					persona.HomeAddress = std::move(val);
				if (node.fetch_prop(PR_COMMENT, val) == ecSuccess)
					persona.Comment = std::move(val);
				data.Persona = std::move(persona);
				break;
			}
		}
	} catch (const EWSError &err) {
		mGetPersonaResponseMessage errdata(err);
		errdata.serialize(response);
		return;
	}

	if (!data.Persona) {
		data.error("ErrorPersonNotFound", "No persona found for the specified email address");
		data.serialize(response);
		return;
	}

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetDelegate
 *
 * Reads the delegate configuration of a mailbox and returns the delegates
 * stored in the delegates.txt file.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetDelegateRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetDelegateResponse");

	ctx.normalize(request.Mailbox);
	std::string dir = request.Mailbox.EmailAddress? ctx.get_maildir(*request.Mailbox.EmailAddress) : ctx.auth_info().maildir;
	if (dir != ctx.auth_info().maildir)
		throw EWSError::AccessDenied(E3312);

	mGetDelegateResponse data;

	std::vector<std::string> delegate_list;
	if (!ctx.plugin().exmdb.read_delegates(dir.c_str(),
	    0, &delegate_list)) {
		data.success();
		data.serialize(response);
		return;
	}
	std::unordered_set<std::string> requested;
	if (request.UserIds) {
		for (auto &&uid : *request.UserIds)
			if (uid.PrimarySmtpAddress)
				requested.insert(std::move(*uid.PrimarySmtpAddress));
	}

	std::unordered_set<std::string> found;
	for (const auto &deleg : delegate_list) {
		if (!requested.empty() && !requested.contains(deleg))
			continue;
		auto &msg = data.ResponseMessages.emplace_back();
		msg.success();
		msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(deleg);
		std::string dispname;
		if (mysql_adaptor_get_user_displayname(deleg.c_str(),
		    dispname) && !dispname.empty())
			msg.DelegateUser.UserId.DisplayName.emplace(
			    std::move(dispname));
		if (request.IncludePermissions && *request.IncludePermissions) {
			msg.DelegateUser.DelegatePermissions.emplace(ctx.readDelegatePermissions(dir, deleg));
			msg.DelegateUser.ViewPrivateItems = sees_private_items(dir.c_str(),
				ctx.plugin().x500_org_name.c_str(), deleg.c_str());
		}
		found.insert(deleg);
	}

	if (!requested.empty()) {
		for (const auto &req : requested) {
			if (!found.contains(req)) {
				auto &msg = data.ResponseMessages.emplace_back();
				msg.error("ErrorDelegateNotFound", "Delegate not found");
				msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(req);
			}
		}
	}

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process AddDelegate
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mAddDelegateRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:AddDelegateResponse");

	ctx.normalize(request.Mailbox);
	std::string dir = request.Mailbox.EmailAddress? ctx.get_maildir(*request.Mailbox.EmailAddress) : ctx.auth_info().maildir;
	if (dir != ctx.auth_info().maildir)
		throw EWSError::AccessDenied(E3313);

	std::vector<std::string> delegate_list;
	if (!ctx.plugin().exmdb.read_delegates(dir.c_str(), 0, &delegate_list))
		throw EWSError::InternalServerError(E3316);
	std::unordered_set<std::string> existing(delegate_list.begin(), delegate_list.end());

	auto actor = get_auth_info(ctx.context_id()).username;
	auto mailbox = ctx.auth_info().username;
	bool changed = false;

	mGetDelegateResponse data;
	for (const auto &du : request.DelegateUsers) {
		auto &msg = data.ResponseMessages.emplace_back();
		if (!du.UserId.PrimarySmtpAddress ||
		    du.UserId.PrimarySmtpAddress->empty()) {
			msg.error("ErrorDelegateNoUser", "No user specified");
			continue;
		}
		const auto &addr = *du.UserId.PrimarySmtpAddress;
		if (existing.contains(addr)) {
			msg.error("ErrorDelegateAlreadyExists", "Delegate already exists");
			msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(addr);
			continue;
		}
		ctx.writeDelegateFlags(dir, addr, du.ViewPrivateItems, false);
		delegate_list.emplace_back(addr);
		existing.emplace(addr);
		changed = true;
		if (du.DelegatePermissions)
			ctx.writeDelegatePermissions(dir, addr, *du.DelegatePermissions);
		msg.success();
		msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(addr);
	}

	if (!ctx.plugin().exmdb.write_delegates(dir.c_str(), 0, delegate_list))
		throw EWSError::InternalServerError(E3317);

	if (changed) {
		mlog(LV_INFO, "ews-audit: %s added delegates to mailbox %s",
			znul(actor), znul(mailbox));
	}

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process RemoveDelegate
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mRemoveDelegateRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:RemoveDelegateResponse");

	ctx.normalize(request.Mailbox);
	std::string dir = request.Mailbox.EmailAddress? ctx.get_maildir(*request.Mailbox.EmailAddress) : ctx.auth_info().maildir;
	if (dir != ctx.auth_info().maildir)
		throw EWSError::AccessDenied(E3314);

	std::vector<std::string> delegate_list;
	if (!ctx.plugin().exmdb.read_delegates(dir.c_str(), 0, &delegate_list))
		throw EWSError::InternalServerError(E3318);

	auto actor = get_auth_info(ctx.context_id()).username;
	auto mailbox = ctx.auth_info().username;
	bool changed = false;

	mGetDelegateResponse data;
	for (const auto &uid : request.UserIds) {
		auto &msg = data.ResponseMessages.emplace_back();
		if (!uid.PrimarySmtpAddress ||
		    uid.PrimarySmtpAddress->empty()) {
			msg.error("ErrorDelegateNoUser", "No user specified");
			continue;
		}
		const auto &addr = *uid.PrimarySmtpAddress;
		auto it = ct_find(delegate_list, addr);
		if (it == delegate_list.end()) {
			msg.error("ErrorDelegateNotFound", "Delegate not found");
			msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(addr);
			continue;
		}
		ctx.writeDelegateFlags(dir, addr, {}, true);
		delegate_list.erase(it);
		changed = true;
		msg.success();
		msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(addr);
	}

	if (!ctx.plugin().exmdb.write_delegates(dir.c_str(), 0, delegate_list))
		throw EWSError::InternalServerError(E3319);

	if (changed) {
		mlog(LV_INFO, "ews-audit: %s removed delegates from mailbox %s",
			znul(actor), znul(mailbox));
	}

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process UpdateDelegate
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mUpdateDelegateRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:UpdateDelegateResponse");

	ctx.normalize(request.Mailbox);
	std::string dir = request.Mailbox.EmailAddress? ctx.get_maildir(*request.Mailbox.EmailAddress) : ctx.auth_info().maildir;
	if (dir != ctx.auth_info().maildir)
		throw EWSError::AccessDenied(E3315);

	std::vector<std::string> delegate_list;
	if (!ctx.plugin().exmdb.read_delegates(dir.c_str(), 0, &delegate_list))
		throw EWSError::InternalServerError(E3320);
	std::unordered_set<std::string> existing(delegate_list.begin(), delegate_list.end());

	auto actor = get_auth_info(ctx.context_id()).username;
	auto mailbox = ctx.auth_info().username;
	bool changed = false;

	mGetDelegateResponse data;
	for (const auto &du : request.DelegateUsers) {
		auto &msg = data.ResponseMessages.emplace_back();
		if (!du.UserId.PrimarySmtpAddress ||
		    du.UserId.PrimarySmtpAddress->empty()) {
			msg.error("ErrorDelegateNoUser", "No user specified");
			continue;
		}
		const auto &addr = *du.UserId.PrimarySmtpAddress;
		if (!existing.contains(addr)) {
			msg.error("ErrorDelegateNotFound", "Delegate not found");
			msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(addr);
			continue;
		}
		if (du.DelegatePermissions)
			changed |= ctx.writeDelegatePermissions(dir, addr, *du.DelegatePermissions);
		if (du.ViewPrivateItems) {
			ctx.writeDelegateFlags(dir, addr, du.ViewPrivateItems, false);
			changed = true;
		}
		msg.success();
		msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(addr);
	}

	if (changed) {
		mlog(LV_INFO, "ews-audit: %s updated delegates in mailbox %s",
			znul(actor), znul(mailbox));
	}
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process CreateFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mCreateFolderRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:CreateFolderResponse");

	mCreateFolderResponse data;

	sFolderSpec parent = ctx.resolveFolder(request.ParentFolderId.FolderId);
	std::string dir = ctx.getDir(parent);
	bool hasAccess = ctx.permissions(dir, parent.folderId);

	for (const sFolder &folder : request.Folders) try {
		if (!hasAccess)
			throw EWSError::AccessDenied(E3191);
		mCreateFolderResponseMessage msg;
		msg.Folders.emplace_back(ctx.create(dir, parent, folder));
		data.ResponseMessages.emplace_back(std::move(msg)).success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

static void updateOccRef(const EWSContext &ctx, const tItemId &refId,
    uint32_t resp, bool send_message, std::optional<sOccurrenceId> &declinedOcc)
{
	sOccurrenceId oid(refId.Id.data(), refId.Id.size());
	sFolderSpec pf = ctx.resolveFolder(oid);
	std::string rdir = ctx.getDir(pf);
	ctx.validate(rdir, oid);
	auto rights = ctx.permissions(rdir, pf.folderId);
	if (!(rights & frightsEditAny))
		throw EWSError::AccessDenied(E3525);
	/* The response is built from the content of the referenced item */
	if (!(rights & frightsReadAny))
		throw EWSError::AccessDenied(E3602);
	ctx.assertCanReadPrivate(rdir, pf, rights, oid.messageId());
	ctx.checkOccurrence(rdir, oid.messageId(), oid.basedate);
	/* A declined occurrence goes once the reply is out */
	if (resp == respDeclined && send_message) {
		if (!(rights & frightsDeleteAny))
			throw EWSError::AccessDenied(E3131);
		declinedOcc.emplace(oid);
		return;
	}
	uint64_t now = rop_util_current_nttime();
	uint32_t busy = resp == respAccepted ? olBusy :
	                resp == respTentative ? olTentative : olFree;
	auto pid = [&](const PROPERTY_NAME &name) {
		return ctx.getNamedPropId(rdir, name, true);
	};
	TAGGED_PROPVAL props[] = {
		{PROP_TAG(PT_LONG, pid(NtResponseStatus)), &resp},
		{PROP_TAG(PT_SYSTIME, pid(NtAppointmentReplyTime)), &now},
		{PROP_TAG(PT_LONG, pid(NtBusyStatus)), &busy},
	};
	const TPROPVAL_ARRAY proplist{std::size(props), props};
	ctx.updateOccurrence(rdir, pf.folderId, oid.messageId(),
		oid.basedate, proplist, {});
}

/**
 * @brief      Put the current ChangeKey of a message into its response item
 *
 * @param      ctx   Request context
 * @param      dir   Store directory
 * @param      mid   Message ID
 * @param      item  Response item of the message
 */
static void refresh_changekey(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, sItem &item) try
{
	auto ck = ctx.getItemProp<const BINARY>(dir, mid, PR_CHANGE_KEY);
	if (ck == nullptr)
		return;
	std::visit([&](auto &i) {
		if constexpr (std::is_base_of_v<tItem, std::decay_t<decltype(i)>>)
			if (i.ItemId)
				i.ItemId->ChangeKey.emplace(ck);
	}, item);
} catch (const DispatchError &) {
	/*
	 * The mails are out, so keep the older ChangeKey rather than fail.
	 * The client then needs to fetch the item again before an update.
	 */
}

static void updateRef(const EWSContext &ctx, const tItemId &refId,
    uint32_t resp, std::string &refDir, std::optional<sMessageEntryId> &refMid,
    bool send_message, std::optional<sOccurrenceId> &declinedOcc,
    std::optional<std::pair<std::string, uint64_t>> *calItem = nullptr,
    uint32_t *calDate = nullptr)
{
	if (refId.type == tItemId::ID_OCCURRENCE)
		return updateOccRef(ctx, refId, resp, send_message, declinedOcc);
	ctx.assertIdType(refId.type, tItemId::ID_ITEM);
	sMessageEntryId mid(refId.Id.data(), refId.Id.size());
	sFolderSpec pf = ctx.resolveFolder(mid);
	std::string rdir = ctx.getDir(pf);
	ctx.validate(rdir, mid);
	auto rights = ctx.permissions(rdir, pf.folderId);
	if (!(rights & frightsEditAny))
		throw EWSError::AccessDenied(E3526);
	if (!(rights & frightsReadAny))
		throw EWSError::AccessDenied(E3602);
	ctx.assertCanReadPrivate(rdir, pf, rights, mid.messageId());
	/* Accepting writes the meeting into the calendar of the same store */
	if ((resp == respAccepted || resp == respTentative) &&
	    pf.location == sFolderSpec::PRIVATE) {
		auto cal = ctx.permissions(rdir, eid_t(1, PRIVATE_FID_CALENDAR));
		if (!(cal & frightsOwner) &&
		    (cal & (frightsCreate | frightsEditAny)) != (frightsCreate | frightsEditAny))
			throw EWSError::AccessDenied(E3600);
	}
	const char *username = ctx.effectiveUser(pf);
	/*
	 * A delegate answering its copy acts for the principal, in the
	 * principal's calendar, see MS-OXOCAL v22.1 §3.1.5.1. Check the rights
	 * before anything is touched.
	 */
	std::optional<std::string> principal;
	if (pf.location == sFolderSpec::PRIVATE) {
		static constexpr proptag_t dtags[] = {
			PR_DELEGATED_BY_RULE, PR_RCVD_REPRESENTING_ADDRTYPE,
			PR_RCVD_REPRESENTING_EMAIL_ADDRESS,
		};
		principal = ctx.delegatePrincipal(ctx.getItemProps(rdir,
		            mid.messageId(), dtags), *pf.target);
	}
	if (principal) {
		ctx.checkPrincipalCalendar(*principal);
		if (send_message)
			ctx.validate_sendas_perms(*principal);
	}
	auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
	auto rstat = EWSContext::construct<uint32_t>(resp);
	uint32_t state = asfMeeting | asfReceived;
	auto astat = EWSContext::construct<uint32_t>(state);
	uint32_t busyValue = resp == respAccepted ? olBusy :
	                     resp == respTentative ? olTentative : olFree;
	auto bstat = EWSContext::construct<uint32_t>(busyValue);
	auto processed = EWSContext::construct<uint8_t>(1);
	auto pidResp  = ctx.getNamedPropId(rdir, NtResponseStatus, true);
	auto pidReply = ctx.getNamedPropId(rdir, NtAppointmentReplyTime, true);
	auto pidState = ctx.getNamedPropId(rdir, NtAppointmentStateFlags, true);
	auto pidBusy  = ctx.getNamedPropId(rdir, NtBusyStatus, true);
	TAGGED_PROPVAL props[] = {
		{PROP_TAG(PT_LONG, pidResp), rstat},
		{PROP_TAG(PT_SYSTIME, pidReply), now},
		{PROP_TAG(PT_LONG, pidState), astat},
		{PROP_TAG(PT_LONG, pidBusy), bstat},
		{PR_PROCESSED, processed},
	};
	TPROPVAL_ARRAY proplist{std::size(props), props};
	auto cls = ctx.getItemProp<char>(rdir, mid.messageId(), PR_MESSAGE_CLASS);
	/*
	 * A declined Meeting object leaves the calendar once the reply is out.
	 * For a delegate copy that is the principal's calendar only.
	 */
	std::optional<uint64_t> declinedCal;
	std::string calDir = rdir;
	bool isRequest = class_match_prefix(cls, "IPM.Schedule.Meeting.Request") == 0;
	if (resp == respDeclined && send_message && calItem != nullptr &&
	    pf.location == sFolderSpec::PRIVATE) {
		uint64_t calFid = pf.folderId;
		if (class_match_prefix(cls, "IPM.Appointment") == 0) {
			if (pf.folderId != eid_t(1, PRIVATE_FID_DELETED_ITEMS))
				declinedCal = mid.messageId();
		} else if (isRequest) {
			declinedCal = ctx.findMeetingObject(refId,
			              principal ? &*principal : nullptr);
			if (principal)
				calDir = ctx.get_maildir(*principal);
			calFid = eid_t(1, PRIVATE_FID_CALENDAR);
		}
		auto calRights = declinedCal ? ctx.permissions(calDir, calFid) : 0;
		if (declinedCal && !(calRights & frightsDeleteAny))
			throw EWSError::AccessDenied(E3131);
		/* The response status is also written to the calendar item */
		if (declinedCal && (calDir != rdir || *declinedCal != mid.messageId()) &&
		    !(calRights & frightsEditAny))
			throw EWSError::AccessDenied(E3603);
	}
	if (!ctx.setItemProps(rdir, username, mid.messageId(), proplist))
		throw EWSError::ItemSave(E3409);
	if (resp == respAccepted || resp == respTentative) {
		auto cal = ctx.createCalendarItemFromMeetingRequest(refId, resp,
		           principal ? &*principal : nullptr, calDate);
		if (cal && calItem != nullptr)
			calItem->emplace(principal ? ctx.get_maildir(*principal) : rdir, *cal);
	}
	if (declinedCal) {
		if (calDir != rdir || *declinedCal != mid.messageId()) {
			/* All but PR_PROCESSED, which is for the request */
			auto cpid = [&](const PROPERTY_NAME &name) {
				return ctx.getNamedPropId(calDir, name, true);
			};
			TAGGED_PROPVAL cprops[] = {
				{PROP_TAG(PT_LONG, cpid(NtResponseStatus)), rstat},
				{PROP_TAG(PT_SYSTIME, cpid(NtAppointmentReplyTime)), now},
				{PROP_TAG(PT_LONG, cpid(NtAppointmentStateFlags)), astat},
				{PROP_TAG(PT_LONG, cpid(NtBusyStatus)), bstat},
			};
			TPROPVAL_ARRAY calProps{std::size(cprops), cprops};
			if (!ctx.setItemProps(calDir, username, *declinedCal, calProps))
				throw EWSError::ItemSave(E3582);
		}
		calItem->emplace(calDir, *declinedCal);
	}
	if (pf.location == sFolderSpec::PRIVATE && rights & frightsDeleteAny &&
	    isRequest) {
		refDir = rdir;
		refMid = mid;
	}
}

/*
 * Reply/forward and meeting response objects are treated the same way as a
 * regular tMessage for persistence and sender identity purposes.
 */
static bool is_message_like(const sCreateItem &item)
{
	return std::holds_alternative<tMessage>(item) ||
	       std::holds_alternative<tReplyToItem>(item) ||
	       std::holds_alternative<tReplyAllToItem>(item) ||
	       std::holds_alternative<tForwardItem>(item) ||
	       std::holds_alternative<tAcceptItem>(item) ||
	       std::holds_alternative<tTentativelyAcceptItem>(item) ||
	       std::holds_alternative<tDeclineItem>(item);
}

/*
 * Exchange keeps a SaveOnly message as a draft until it is sent. Importers
 * opt out by setting PR_MESSAGE_FLAGS themselves.
 */
static bool client_sets_msgflags(const sCreateItem &item)
{
	auto &base = std::visit([](const auto &i) -> const tItem & {
		if constexpr (std::is_base_of_v<tItem, std::decay_t<decltype(i)>>)
			return i;
		else
			return i.Message;
	}, item);
	return base.IsDraft || std::any_of(base.ExtendedProperty.begin(),
	       base.ExtendedProperty.end(), [](const tExtendedProperty &p) {
	       	return p.propval.proptag == PR_MESSAGE_FLAGS;
	       });
}

/*
 * Folder for CreateItem when no SavedItemFolderId is given. Exchange keeps
 * the copy of a sent message in Sent Items and an unsent one in Drafts.
 * Calendar items, contacts and tasks go to their own default folder.
 */
static const char *default_folder(const sCreateItem &item,
    const Enum::MessageDispositionType &disp)
{
	if (std::holds_alternative<tCalendarItem>(item))
		return Enum::calendar;
	if (std::holds_alternative<tContact>(item))
		return Enum::contacts;
	if (std::holds_alternative<tTask>(item))
		return Enum::tasks;
	if (is_message_like(item)) {
		if (disp == Enum::SendAndSaveCopy)
			return Enum::sentitems;
		if (disp == Enum::SaveOnly)
			return Enum::drafts;
	}
	return Enum::outbox;
}

/**
 * @brief      Process CreateItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mCreateItemRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:CreateItemResponse");

	mCreateItemResponse data;

	std::optional<sFolderSpec> savedFolder;
	if (request.SavedItemFolderId)
		savedFolder = ctx.resolveFolder(request.SavedItemFolderId->FolderId);

	if (!request.MessageDisposition)
		request.MessageDisposition = Enum::SaveOnly;
	if (!request.SendMeetingInvitations)
		request.SendMeetingInvitations = Enum::SendToNone;
	bool send_message = request.MessageDisposition == Enum::SendOnly ||
	                    request.MessageDisposition == Enum::SendAndSaveCopy;

	data.ResponseMessages.reserve(request.Items.size());
	for (sCreateItem &item : request.Items) try {
		auto targetFolder = savedFolder;
		if (!targetFolder)
			targetFolder = ctx.resolveFolder(tDistinguishedFolderId(
			               default_folder(item, *request.MessageDisposition)));
		std::string dir = ctx.getDir(*targetFolder);
		if (!(ctx.permissions(dir, targetFolder->folderId) &
		    (frightsOwner | frightsCreate)))
			throw EWSError::AccessDenied(E3130);

		if (auto srr = std::get_if<tSuppressReadReceipt>(&item)) {
			/* Response object, nothing is stored or sent */
			if (srr->ReferenceItemId)
				ctx.suppressReadReceipt(*srr->ReferenceItemId);
			data.ResponseMessages.emplace_back().success();
			continue;
		}
		if (auto ccl = std::get_if<tCancelCalendarItem>(&item)) {
			/* Response object, the cancellation is built from the meeting */
			if (ccl->ReferenceItemId)
				ctx.cancelCalendarItem(*ccl->ReferenceItemId,
					request.MessageDisposition == Enum::SendAndSaveCopy);
			data.ResponseMessages.emplace_back().success();
			continue;
		}

		if (auto remove = std::get_if<tRemoveItem>(&item)) {
			/* Response object: nothing is stored and nothing is sent */
			if (remove->ReferenceItemId)
				ctx.removeMeetingCancellation(*remove->ReferenceItemId);
			data.ResponseMessages.emplace_back().success();
			continue;
		}

		mCreateItemResponseMessage msg;
		bool isMessageLike = is_message_like(item);
		bool persist = !(isMessageLike && request.MessageDisposition == Enum::SendOnly);

		auto content = ctx.toContent(dir, *targetFolder, item, persist);

		if (isMessageLike &&
		    request.MessageDisposition == Enum::SaveOnly &&
		    !client_sets_msgflags(item)) {
			auto flags = content->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
			uint32_t newFlags = (flags != nullptr ? *flags : 0) | MSGFLAG_UNSENT;
			if (content->proplist.set(PR_MESSAGE_FLAGS, &newFlags) == ecServerOOM)
				throw EWSError::NotEnoughMemory(E3358);
		}

		if (isMessageLike &&
		    request.MessageDisposition == Enum::SaveOnly &&
		    !content->proplist.has(PR_SENT_REPRESENTING_EMAIL_ADDRESS)) {
			/*
			 * Only fall back to the mailbox owner's default
			 * identity if the client did not already supply one.
			 */
			const char *sender = ctx.effectiveUser(*targetFolder);
			if (sender == nullptr || *sender == '\0')
				sender = ctx.auth_info().username;

			if (sender != nullptr && *sender != '\0') {
				content->proplist.set(PR_SENT_REPRESENTING_ADDRTYPE, "SMTP");
				content->proplist.set(PR_SENDER_ADDRTYPE, "SMTP");
				content->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, sender);
				content->proplist.set(PR_SENDER_EMAIL_ADDRESS, sender);
				content->proplist.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, sender);
				content->proplist.set(PR_SENDER_SMTP_ADDRESS, sender);
				content->proplist.set(PR_SENT_REPRESENTING_NAME, sender);
				content->proplist.set(PR_SENDER_NAME, sender);
			}
		}

		bool isResponse = std::holds_alternative<tAcceptItem>(item) ||
		                  std::holds_alternative<tTentativelyAcceptItem>(item) ||
		                  std::holds_alternative<tDeclineItem>(item);
		/* Responses carry the attendee identity, see sendMeetingResponse */
		if (isMessageLike && !isResponse && send_message)
			ctx.stampSubmitIdentity(dir, *content);
		if (send_message || (std::holds_alternative<tCalendarItem>(item) &&
		    request.SendMeetingInvitations != Enum::SendToNone))
			ctx.validate_sendas_perms(*content);

		const tItemId *responseRef = nullptr;
		if (auto acc = std::get_if<tAcceptItem>(&item))
			responseRef = acc->ReferenceItemId ?
			              &*acc->ReferenceItemId : nullptr;
		else if (auto tent = std::get_if<tTentativelyAcceptItem>(&item))
			responseRef = tent->ReferenceItemId ?
			              &*tent->ReferenceItemId : nullptr;
		else if (auto dec = std::get_if<tDeclineItem>(&item))
			responseRef = dec->ReferenceItemId ?
			              &*dec->ReferenceItemId : nullptr;
		if (send_message && responseRef != nullptr) {
			auto refFolder = ctx.resolveFolder(sMessageEntryId(
			                 responseRef->Id.data(), responseRef->Id.size()));
			if (refFolder.location == sFolderSpec::PRIVATE)
				ctx.validate_sendas_perms(*refFolder.target);
		}

		std::optional<sMessageEntryId> refMid;
		std::string refDir;
		std::optional<sOccurrenceId> declinedOcc;
		std::optional<std::pair<std::string, uint64_t>> calItem;
		uint32_t calDate = 0;
		if (auto acc = std::get_if<tAcceptItem>(&item)) {
			if (acc->ReferenceItemId)
				updateRef(ctx, *acc->ReferenceItemId,
				          respAccepted, refDir, refMid,
				          send_message, declinedOcc, &calItem, &calDate);
		} else if (auto tent = std::get_if<tTentativelyAcceptItem>(&item)) {
			if (tent->ReferenceItemId)
				updateRef(ctx, *tent->ReferenceItemId,
				          respTentative, refDir, refMid,
				          send_message, declinedOcc, &calItem, &calDate);
		} else if (auto dec = std::get_if<tDeclineItem>(&item)) {
			if (dec->ReferenceItemId)
				updateRef(ctx, *dec->ReferenceItemId,
				          respDeclined, refDir, refMid,
				          send_message, declinedOcc, &calItem);
		}
		if (isResponse) {
			bool sent = responseRef != nullptr &&
			            ctx.sendMeetingResponse(*responseRef,
			            *content, send_message);
			/* Keep no copy of a response that was not sent */
			if (send_message && !sent)
				persist = false;
		}
		/*
		 * Exchange returns the calendar item of the attendee along with
		 * the response. macOS Calendar keys its event to the first item.
		 */
		if (calItem) {
			uint64_t calFid = eid_t(1, PRIVATE_FID_CALENDAR);
			/* A declined one is returned from Deleted Items */
			if (std::holds_alternative<tDeclineItem>(item)) {
				auto eid = ctx.getItemEntryId(calItem->first, calItem->second);
				auto bin = static_cast<const BINARY *>(eid.pvalue);
				sMessageEntryId calMeid(bin->pb, bin->cb);
				calFid = eid_t(1, PRIVATE_FID_DELETED_ITEMS);
				calItem->second = ctx.moveCopyItem(calItem->first,
				                  calMeid, calFid, false);
			}
			sShape calShape;
			calShape.add(PR_ENTRYID, sShape::FL_FIELD).add(PR_CHANGE_KEY, sShape::FL_FIELD).add(PR_MESSAGE_CLASS);
			/* The CalendarItemType of a series is derived from these */
			calShape.add(NtAppointmentRecur, PT_BINARY, sShape::FL_FIELD)
			        .add(NtRecurring, PT_BOOLEAN, sShape::FL_FIELD)
			        .add(NtExceptionReplaceTime, PT_SYSTIME, sShape::FL_FIELD);
			/* For one occurrence, Exchange returns that occurrence */
			if (calDate != 0) {
				/* The occurrence times need the series start and zone */
				calShape.add(PR_START_DATE, sShape::FL_FIELD)
				        .add(NtAppointmentTimeZoneDefinitionRecur, PT_BINARY);
				msg.Items.emplace_back(ctx.loadOccurrence(calItem->first,
					calFid, calItem->second, calDate, calShape));
			} else
				msg.Items.emplace_back(ctx.loadItem(calItem->first,
					calFid, calItem->second, calShape));
		}
		/* Exchange moves an answered request to Deleted Items */
		if (refMid)
			ctx.moveCopyItem(refDir, *refMid, eid_t(1, PRIVATE_FID_DELETED_ITEMS), false);
		if (declinedOcc) {
			sFolderSpec pf = ctx.resolveFolder(*declinedOcc);
			ctx.deleteOccurrence(ctx.getDir(pf), pf.folderId,
				declinedOcc->messageId(), declinedOcc->basedate);
		}
		if (isMessageLike &&
		    request.MessageDisposition == Enum::SendAndSaveCopy) {
			auto flags = content->proplist.get<uint32_t>(PR_MESSAGE_FLAGS);
			if (flags != nullptr)
				*flags &= ~(MSGFLAG_SUBMITTED | MSGFLAG_UNSENT);
			content->proplist.set(PR_READ, &byte_value_one);
		}
		/*
		 * Like Exchange, keep the delivery time a client gives and
		 * default it to now. Sending stamps the submit time over the
		 * one the client gave, which also becomes the Date header.
		 */
		auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
		if (!content->proplist.has(PR_MESSAGE_DELIVERY_TIME) &&
		    content->proplist.set(PR_MESSAGE_DELIVERY_TIME, now) == ecServerOOM)
			throw EWSError::NotEnoughMemory(E3358);
		if ((send_message && isMessageLike) ||
		    !content->proplist.has(PR_CLIENT_SUBMIT_TIME))
			if (content->proplist.set(PR_CLIENT_SUBMIT_TIME, now) == ecServerOOM)
				throw EWSError::NotEnoughMemory(E3358);
		/* Send first so that a failed send leaves no copy behind */
		if (isMessageLike && !isResponse && send_message)
			ctx.send(dir, 0, *content);
		if (persist) {
			/* Exchange returns the IDs of attachments it was given */
			bool atts = std::visit([](const auto &i) {
				if constexpr (std::is_base_of_v<tItem, std::decay_t<decltype(i)>>)
					return i.Attachments.has_value();
				else
					return false;
			}, item);
			msg.Items.emplace_back(ctx.create(dir, *targetFolder, *content, atts));
		}
		/* Like Exchange, only save an appointment without attendees */
		bool cal_invite = std::holds_alternative<tCalendarItem>(item) &&
		                  ctx.has_rcpt_address(*content);
		if (cal_invite &&
		    request.SendMeetingInvitations == Enum::SendToAllAndSaveCopy) {
			sFolderSpec sentitems = ctx.resolveFolder(tDistinguishedFolderId(Enum::sentitems));
			uint64_t newMid;
			if (!ctx.plugin().exmdb.allocate_message_id(dir.c_str(),
				sentitems.folderId, &newMid))
				throw EWSError::InternalServerError(E3424);
			BOOL result;
			auto messageId = *content->proplist.get<const uint64_t>(PidTagMid);
			if (!ctx.plugin().exmdb.movecopy_message(dir.c_str(), CP_ACP,
				messageId, sentitems.folderId, newMid, false, &result)
				|| !result)
				throw EWSError::InternalServerError(E3427);
			const char* username = ctx.effectiveUser(sentitems);
			TAGGED_PROPVAL props[] = {
				{PR_MESSAGE_CLASS, deconst("IPM.Schedule.Meeting.Request")},
				{PR_RESPONSE_REQUESTED, deconst(&byte_value_one)},
				{PR_CLIENT_SUBMIT_TIME, now},
				{PR_MESSAGE_DELIVERY_TIME, now},
			};
			TPROPVAL_ARRAY proplist{std::size(props), props};
			if (!ctx.setItemProps(dir, username, newMid, proplist))
				throw EWSError::ItemSave(E3410);
			MESSAGE_CONTENT *sendcontent = nullptr;
			if (!ctx.plugin().exmdb.read_message(dir.c_str(),
				username, CP_ACP, newMid, &sendcontent)
				|| sendcontent == nullptr)
				throw EWSError::ItemNotFound(E3391);
			ctx.send(dir, messageId, *sendcontent);
			/* Exchange reports MeetingRequestWasSent from now on */
			ctx.markInvited(dir, *targetFolder, messageId);
			if (!msg.Items.empty())
				refresh_changekey(ctx, dir, messageId, msg.Items.back());
		}
		if (cal_invite &&
		    request.SendMeetingInvitations == Enum::SendOnlyToAll) {
			content->proplist.set(PR_MESSAGE_CLASS, "IPM.Schedule.Meeting.Request");
			content->proplist.set(PR_CLIENT_SUBMIT_TIME, now);
			content->proplist.set(PR_MESSAGE_DELIVERY_TIME, now);
			ctx.send(dir, 0, *content);
		}
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process CreateAttachment
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mCreateAttachmentRequest &&request, XMLElement *response,
    const EWSContext &ctx)
{
	response->SetName("m:CreateAttachmentResponse");

	mCreateAttachmentResponse data;
	try {
		ctx.assertIdType(request.ParentItemId.type, tFolderId::ID_ITEM);
		sMessageEntryId mid(request.ParentItemId.Id.data(), request.ParentItemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(mid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, mid);
		// XXX: Permission check is wrong; we must check whether message can be modified
		auto rights = ctx.permissions(dir, parentFolder.folderId);
		if (!(rights & frightsEditAny))
			throw EWSError::AccessDenied(E3190);
		ctx.assertCanReadPrivate(dir, parentFolder, rights, mid.messageId());

		for (const tFileAttachment &att : request.Attachments) try {
			auto mInst = ctx.plugin().loadCurrentMessageInstance(dir,
			             parentFolder.folderId, mid.messageId());
			uint32_t aInstId = 0, aNum = 0;
			if (!ctx.plugin().exmdb.create_attachment_instance(dir.c_str(),
			    mInst->instanceId, &aInstId, &aNum))
				throw EWSError::ItemSave(E3094);

			static constexpr uint32_t rendpos = UINT32_MAX;
			mapitime_t modtime = rop_util_current_nttime();
			const TAGGED_PROPVAL initProps[] = {
				{PR_ATTACH_NUM, &aNum},
				{PR_RENDERING_POSITION, deconst(&rendpos)},
				{PR_CREATION_TIME, &modtime},
				{PR_LAST_MODIFICATION_TIME, &modtime},
			};
			const TPROPVAL_ARRAY initList = {std::size(initProps), deconst(initProps)};
			PROBLEM_ARRAY initProblems;
			if (!ctx.plugin().exmdb.set_instance_properties(dir.c_str(),
			    aInstId, &initList, &initProblems))
				throw EWSError::ItemSave(E3429);

			ATTACHMENT_CONTENT ac{};
			auto props = att.props();
			ac.proplist.count = props.size();
			ac.proplist.ppropval = props.data();
			ac.pembedded = nullptr;
			PROBLEM_ARRAY problems;
			if (!ctx.plugin().exmdb.write_attachment_instance(dir.c_str(),
			    aInstId, &ac, false, &problems))
				throw EWSError::ItemSave(E3430);
			ec_error_t err;
			if (!ctx.plugin().exmdb.flush_instance(dir.c_str(),
			    aInstId, &err) || err != ecSuccess)
				throw EWSError::ItemSave(E3431);
			ctx.stampInstance(dir, mid.messageId(), mInst->instanceId);
			if (!ctx.plugin().exmdb.flush_instance(dir.c_str(),
			    mInst->instanceId, &err) || err != ecSuccess)
				throw EWSError::ItemSave(E3476);

			mCreateAttachmentResponseMessage msg;
			sAttachmentId aid(ctx.getItemEntryId(dir, mid.messageId()), aNum);
			msg.Attachments.emplace_back(ctx.loadAttachment(dir, aid));
			msg.success();
			data.ResponseMessages.emplace_back(std::move(msg));
		} catch (const EWSError &err) {
			data.ResponseMessages.emplace_back(err);
		}
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process DeleteAttachment
 *
 * Delete one or more attachments from existing items.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mDeleteAttachmentRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:DeleteAttachmentResponse");

	mDeleteAttachmentResponse data;
	data.ResponseMessages.reserve(request.AttachmentIds.size());
	for (const tRequestAttachmentId &raid : request.AttachmentIds) try {
		sAttachmentId aid(raid.Id.data(), raid.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(aid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, aid);
		// XXX: Permission check is wrong; we must check whether message can be modified
		auto rights = ctx.permissions(dir, parentFolder.folderId);
		if (!(rights & frightsEditAny))
			throw EWSError::AccessDenied(E3444);
		ctx.assertCanReadPrivate(dir, parentFolder, rights, aid.messageId());

		auto mInst = ctx.plugin().loadCurrentMessageInstance(dir,
		             parentFolder.folderId, aid.messageId(), true);
		if (!ctx.plugin().exmdb.delete_message_instance_attachment(dir.c_str(),
		    mInst->instanceId, aid.attachment_num))
			throw EWSError::ItemSave(E3432);
		ctx.stampInstance(dir, aid.messageId(), mInst->instanceId);
		ec_error_t err;
		if (!ctx.plugin().exmdb.flush_instance(dir.c_str(),
		    mInst->instanceId, &err) || err != ecSuccess)
			throw EWSError::ItemSave(E3433);
		/*
		 * Keep the message instance. A reload would renumber the
		 * attachments and shift the AttachmentIds the client holds.
		 */
		ctx.plugin().unloadAttachmentInstance(dir, aid.messageId(),
			aid.attachment_num);

		static constexpr proptag_t propids[] = {PR_ENTRYID, PR_CHANGE_KEY};
		static constexpr PROPTAG_ARRAY proptags = {std::size(propids), deconst(propids)};
		TPROPVAL_ARRAY props = ctx.getItemProps(dir, aid.messageId(), proptags);
		auto entryId   = props.get<const BINARY>(PR_ENTRYID);
		auto changeKey = props.get<const BINARY>(PR_CHANGE_KEY);

		mDeleteAttachmentResponseMessage msg;
		if(entryId && changeKey) {
			auto &rootItemId = msg.RootItemId.emplace();
			rootItemId.RootItemId = sMessageEntryId(entryId->pv, entryId->cb).serialize();
			rootItemId.RootItemChangeKey = sBase64Binary(changeKey);
		}
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process DeleteFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mDeleteFolderRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:DeleteFolderResponse");

	static constexpr proptag_t parentFidTag = PidTagParentFolderId;
	static constexpr PROPTAG_ARRAY parentTags = {1, deconst(&parentFidTag)};

	mDeleteFolderResponse data;
	data.ResponseMessages.reserve(request.FolderIds.size());

	for (const tFolderId &folderId : request.FolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		if (folder.isDistinguished())
			throw EWSError::DeleteDistinguishedFolder(E3156);
		std::string dir = ctx.getDir(folder);
		TPROPVAL_ARRAY parentProps = ctx.getFolderProps(dir, folder.folderId, parentTags);
		auto parentFolderId = parentProps.get<const uint64_t>(parentFidTag);
		if (!parentFolderId)
			throw DispatchError(E3166);
		sFolderSpec parentFolder = folder;
		parentFolder.folderId = *parentFolderId;

		if (request.DeleteType == Enum::MoveToDeletedItems) {
			if (folder.location == folder.PUBLIC)
				throw EWSError::MoveCopyFailed(E3158);
			uint32_t accountId = ctx.getAccountId(ctx.auth_info().username, false);
			uint64_t newParentId = eid_t(1, PRIVATE_FID_DELETED_ITEMS);
			ctx.moveCopyFolder(dir, folder, newParentId, accountId, false);
		} else {
			if (!(ctx.permissions(dir, folder.folderId) & frightsOwner))
				throw EWSError::AccessDenied(E3573);
			bool hard = request.DeleteType == Enum::HardDelete;
			/* exmdb only deletes empty folders, Exchange takes the content along */
			uint32_t flags = DEL_MESSAGES | DEL_FOLDERS | DEL_ASSOCIATED |
			                 (hard ? DELETE_HARD_DELETE : 0);
			BOOL partial;
			if (!ctx.plugin().exmdb.empty_folder(dir.c_str(), CP_ACP,
			    ctx.effectiveUser(folder), folder.folderId, flags,
			    &partial) || partial)
				throw EWSError::CannotDeleteObject(E3574);
			BOOL result;
			if (!ctx.plugin().exmdb.delete_folder(dir.c_str(), CP_ACP,
			    folder.folderId, hard ? TRUE : false, &result) || !result)
				throw EWSError::CannotDeleteObject(E3165);
		}
		data.ResponseMessages.emplace_back().success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process DeleteItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mDeleteItemRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:DeleteItemResponse");

	mDeleteItemResponse data;
	data.ResponseMessages.reserve(request.ItemIds.size());
	auto& exmdb = ctx.plugin().exmdb;

	for (const auto &id : request.ItemIds) try {
		tItemId itemId = id.itemId();
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parent = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(parent);
		ctx.validate(dir, meid);
		auto rights = ctx.permissions(dir, parent.folderId);
		if (!(rights & frightsDeleteAny))
			throw EWSError::AccessDenied(E3131);
		ctx.assertCanReadPrivate(dir, parent, rights, meid.messageId());

		std::optional<uint32_t> basedate;
		if (auto occ = std::get_if<tOccurrenceItemId>(&id.asVariant())) {
			basedate = ctx.resolveOccurrenceIndex(dir,
			           meid.messageId(), occ->InstanceIndex);
		} else if (itemId.type == tItemId::ID_OCCURRENCE) {
			basedate = sOccurrenceId(itemId.Id.data(),
			           itemId.Id.size()).basedate;
			ctx.checkOccurrence(dir, meid.messageId(), *basedate);
		}

		if (request.SendMeetingCancellations &&
		    *request.SendMeetingCancellations != Enum::SendToNone &&
		    (basedate || itemId.type == tItemId::ID_ITEM) &&
		    ctx.isOrganizer(dir, meid.messageId()))
			ctx.sendMeetingCancellation(dir, meid, parent,
				*request.SendMeetingCancellations == Enum::SendToAllAndSaveCopy,
				basedate);

		if (basedate) {
			ctx.deleteOccurrence(dir, parent.folderId,
				meid.messageId(), *basedate);
			data.ResponseMessages.emplace_back().success();
		} else if (request.DeleteType == Enum::MoveToDeletedItems) {
			uint64_t newMid = 0;
			if (!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &newMid))
				throw EWSError::MoveCopyFailed(E3425);

			sFolderSpec deletedItems = ctx.resolveFolder(tDistinguishedFolderId(Enum::deleteditems));
			BOOL result = false;
			if (!exmdb.movecopy_message(dir.c_str(), CP_ACP,
			    meid.messageId(), deletedItems.folderId, newMid,
			    TRUE, &result) || !result)
				throw EWSError::MoveCopyFailed(E3133);

			data.ResponseMessages.emplace_back().success();
		} else {
			auto eid = meid.messageId();
			auto fid = meid.folderId();
			EID_ARRAY eids{1, &eid};
			BOOL hardDelete = request.DeleteType == Enum::HardDelete ? TRUE : false;
			BOOL partial = false;
			if (!ctx.plugin().exmdb.delete_messages(dir.c_str(),
			    CP_ACP, ctx.effectiveUser(parent), fid, eids,
			    hardDelete, &partial) || partial)
				throw EWSError::CannotDeleteObject(E3134);

			data.ResponseMessages.emplace_back().success();
		}
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process EmptyFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mEmptyFolderRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:EmptyFolderResponse");

	mEmptyFolderResponse data;
	data.ResponseMessages.reserve(request.FolderIds.size());

	if (request.DeleteType == Enum::MoveToDeletedItems)
		throw DispatchError(E3181);
	uint32_t deleteFlags = DEL_MESSAGES | DEL_ASSOCIATED;
	deleteFlags |= (request.DeleteType == Enum::HardDelete ? DELETE_HARD_DELETE : 0) |
	               (request.DeleteSubFolders ? DEL_FOLDERS : 0);
	for (const sFolderId &folderId : request.FolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3179);
		const char* username = ctx.effectiveUser(folder);
		BOOL partial;
		if (!ctx.plugin().exmdb.empty_folder(dir.c_str(), CP_ACP,
		    username, folder.folderId, deleteFlags, &partial) || partial)
			throw EWSError::CannotEmptyFolder(E3180);
		data.ResponseMessages.emplace_back().success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}


/**
 * @brief      Process FindFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mFindFolderRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:FindFolderResponse");

	sShape shape(request.FolderShape);
	uint8_t tableFlags = request.Traversal == Enum::Deep ? TABLE_FLAG_DEPTH :
	                     request.Traversal == Enum::SoftDeleted ? TABLE_FLAG_SOFTDELETES : 0;

	const RESTRICTION* res = nullptr; // Must be built for every store individually (named properties)
	std::string lastDir; // Simple restriction caching

	auto& exmdb = ctx.plugin().exmdb;
	mFindFolderResponse data;
	data.ResponseMessages.reserve(request.ParentFolderIds.size());
	auto paging = request.IndexedPageFolderView ? &*request.IndexedPageFolderView :
	              request.FractionalPageFolderView ? &*request.FractionalPageFolderView :
	              static_cast<tBasePagingType *>(nullptr);
	uint32_t maxResults = paging && paging->MaxEntriesReturned ? *paging->MaxEntriesReturned : 0;

	for (const sFolderId &folderId : request.ParentFolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		if (!(itemRights(ctx, dir, folder.folderId) & (frightsVisible | fbRights)))
			throw EWSError::AccessDenied(E3218);
		if (dir != lastDir) {
			auto getId = [&](const PROPERTY_NAME& name){return ctx.getNamedPropId(dir, name);};
			res = request.Restriction ? request.Restriction->build(getId) : nullptr;
			lastDir = dir;
		}
		uint32_t tableId, rowCount;
		const char* username = ctx.effectiveUser(folder);
		if (!exmdb.load_hierarchy_table(dir.c_str(), folder.folderId,
		    username, tableFlags, res, &tableId, &rowCount))
			throw EWSError::FolderPropertyRequestFailed(E3219);
		auto unloadTable = HX::make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
		if (!rowCount) {
			mFindFolderResponseMessage msg;
			msg.RootFolder.emplace();
			if (paging)
				paging->update(*msg.RootFolder, 0, 0);
			msg.RootFolder->IncludesLastItemInRange = true;
			msg.RootFolder->TotalItemsInView = 0;
			msg.success();
			data.ResponseMessages.emplace_back(std::move(msg));
			continue;
		}
		ctx.getNamedTags(dir, shape);
		PROPTAG_ARRAY tags = shape.proptags();
		TARRAY_SET table;
		uint32_t offset = paging ? std::min(paging->offset(rowCount), rowCount) : 0;
		uint32_t results = rowCount - offset;
		if (maxResults)
			results = std::min(maxResults, results);
		exmdb.query_table(dir.c_str(), ctx.auth_info().username,
			CP_UTF8, tableId, tags, offset, results, &table);
		mFindFolderResponseMessage msg;
		msg.RootFolder.emplace().Folders.reserve(rowCount);
		for (const TPROPVAL_ARRAY &props : table) {
			shape.clean();
			shape.properties(props);
			sFolder& child = msg.RootFolder->Folders.emplace_back(tBaseFolderType::create(shape));
			const auto &fid = std::visit([](auto &&f) STATIC_IN_CXX23 -> std::optional<tFolderId> & { return f.FolderId; }, child);
			if (shape.special && fid)
				std::visit([&](auto& f) {ctx.loadSpecial(dir, sFolderEntryId(fid->Id.data(), fid->Id.size()).folderId(), f,
						                                 shape.special);}, child);
		}
		if (paging)
			paging->update(*msg.RootFolder, results, rowCount);
		msg.RootFolder->IncludesLastItemInRange = results + offset >= rowCount;
		msg.RootFolder->TotalItemsInView = rowCount;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Reload binary row values that exmdb clamped to 510 bytes
 *
 * @param      ctx    Request context
 * @param      dir    Store directory
 * @param      props  Table row
 */
static void unclamp_binaries(const EWSContext &ctx, const std::string &dir,
    TPROPVAL_ARRAY &props)
{
	std::vector<proptag_t> tags;
	for (const auto &pv : props)
		if (PROP_TYPE(pv.proptag) == PT_BINARY &&
		    static_cast<const BINARY *>(pv.pvalue)->cb == 510)
			tags.push_back(pv.proptag);
	if (tags.empty())
		return;
	auto eid = props.get<const BINARY>(PR_ENTRYID);
	if (eid == nullptr)
		return;
	sMessageEntryId meid(eid->pb, eid->cb);
	for (const auto &pv : ctx.getItemProps(dir, meid.messageId(), tags))
		if (auto tp = props.find(pv.proptag))
			tp->pvalue = pv.pvalue;
}

/**
 * @brief      Process FindItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mFindItemRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:FindItemResponse");

	sShape shape(request.ItemShape);
	shape.special &= ~sShape::AssociatedCalendarItemId;
	shape.x500Org = ctx.plugin().x500_org_name.c_str();
	uint8_t tableFlags = request.Traversal == Enum::SoftDeleted ? TABLE_FLAG_SOFTDELETES :
	                     request.Traversal == Enum::Associated ? TABLE_FLAG_ASSOCIATED :
	                     request.Traversal == Enum::Shallow ? 0 : TABLE_FLAG_DEPTH;
	const RESTRICTION* res = nullptr; // Must be built for every store individually (named properties)
	const SORTORDER_SET* sort = nullptr; // Lol same
	/* Table of the private items, see limitQuery */
	const RESTRICTION *privRes = nullptr;
	const SORTORDER_SET *privSort = nullptr;
	bool split = false;
	std::string lastDir; // Simple restriction caching
	uint32_t lastRights = 0;

	auto& exmdb = ctx.plugin().exmdb;
	mFindItemResponse data;
	data.ResponseMessages.reserve(request.ParentFolderIds.size());
	// Specified as variant, so as long as at most one is given everything works as expected
	auto paging = request.IndexedPageItemView ? &*request.IndexedPageItemView :
	              request.FractionalPageItemView ? &*request.FractionalPageItemView :
	              request.CalendarView ? &*request.CalendarView :
	              request.ContactsView ? &*request.ContactsView :
	              static_cast<tBasePagingType *>(nullptr);
	uint32_t maxResults = paging && paging->MaxEntriesReturned ? *paging->MaxEntriesReturned : 0;
	/*
	 * A CalendarView must report the individual occurrences of a series
	 * rather than the series itself, so recurring masters are expanded
	 * below. Other view types keep returning rows verbatim.
	 */
	auto calView = request.CalendarView ? &*request.CalendarView : nullptr;
	time_t viewStart = 0, viewEnd = std::numeric_limits<time_t>::max();
	if (calView != nullptr) {
		if (calView->StartDate)
			viewStart = rop_util_nttime_to_unix(calView->StartDate->toNT());
		if (calView->EndDate)
			viewEnd = rop_util_nttime_to_unix(calView->EndDate->toNT());
	}

	for (const sFolderId &folderId : request.ParentFolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		auto rights = itemRights(ctx, dir, folder.folderId);
		if (!(rights & itemReadRights))
			throw EWSError::AccessDenied(E3244);
		ctx.restrictShape(dir, folder, rights, shape);
		if (dir != lastDir || rights != lastRights) {
			auto getId = [&](const PROPERTY_NAME& name){return ctx.getNamedPropId(dir, name);};
			auto getEssdn = [&](const char *addr) {
				std::string essdn;
				if (cvt_username_to_essdn(addr, ctx.plugin().x500_org_name.c_str(),
				    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
				    essdn) != ecSuccess)
					essdn.clear();
				return essdn;
			};
			auto res1 = request.Restriction ? request.Restriction->build(getId, getEssdn) : nullptr;
			auto res2 = paging ? paging->restriction(getId) : nullptr;
			auto newRes = tRestriction::all(res1, res2);
			auto newSort = request.SortOrder ? tFieldOrder::build(*request.SortOrder, getId) : nullptr;
			SORTORDER_SET *newPrivSort;
			split = limitQuery(shape, newRes, newSort, newPrivSort);
			if (split) {
				auto copy = newRes != nullptr ? EWSContext::construct<RESTRICTION>(*newRes) : nullptr;
				privRes = tRestriction::all(copy, matchPrivate(true));
				newRes = tRestriction::all(newRes, matchPrivate(false));
			}
			res = newRes;
			sort = newSort;
			privSort = newPrivSort;
			lastDir = dir;
			lastRights = rights;
		}
		uint32_t tableId, rowCount, privTable = 0, privCount = 0;
		if (!exmdb.load_content_table(dir.c_str(), CP_UTF8, folder.folderId,
		    "", tableFlags, res, sort, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3245);
		auto unloadTable = HX::make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
		if (split && !exmdb.load_content_table(dir.c_str(), CP_UTF8,
		    folder.folderId, "", tableFlags, privRes, privSort,
		    &privTable, &privCount))
			throw EWSError::ItemPropertyRequestFailed(E3245);
		auto unloadPriv = HX::make_scope_exit([&, privTable] {
			if (split)
				exmdb.unload_table(dir.c_str(), privTable);
		});
		/* Rows of the private table come after those of the other */
		uint32_t pubCount = rowCount;
		rowCount += privCount;
		if (!rowCount) {
			mFindItemResponseMessage msg;
			msg.RootFolder.emplace();
			if (paging)
				paging->update(*msg.RootFolder, 0, 0);
			msg.RootFolder->IncludesLastItemInRange = true;
			msg.RootFolder->TotalItemsInView = 0;
			msg.success();
			data.ResponseMessages.emplace_back(std::move(msg));
			continue;
		}
		ctx.getNamedTags(dir, shape);
		/*
		 * Expansion needs the recurrence blob and the entry id of every
		 * row. They are appended to the query rather than to the shape,
		 * so item construction - and therefore the response for single
		 * appointments - stays exactly as the client requested it.
		 */
		std::vector<proptag_t> tagvec(shape.proptags_vec());
		proptag_t recurTag = 0, startTag = 0;
		if (calView != nullptr) {
			recurTag = PROP_TAG(PT_BINARY, ctx.getNamedPropId(dir, NtAppointmentRecur));
			startTag = PROP_TAG(PT_SYSTIME, ctx.getNamedPropId(dir, NtAppointmentStartWhole));
			for (proptag_t extra : {recurTag, startTag, proptag_t(PR_ENTRYID)})
				if (std::find(tagvec.begin(), tagvec.end(), extra) == tagvec.end())
					tagvec.push_back(extra);
		}
		PROPTAG_ARRAY tags = {static_cast<uint16_t>(tagvec.size()), tagvec.data()};
		TARRAY_SET table;
		uint32_t offset = paging ? std::min(paging->offset(rowCount), rowCount) : 0;
		/*
		 * MaxEntriesReturned limits occurrences, not rows: one row can
		 * expand into many items, and they only come out in order once
		 * every row has been expanded. The cap is therefore applied
		 * after sorting, not while querying.
		 */
		uint32_t results = maxResults && calView == nullptr ?
			std::min(maxResults, rowCount - offset) : rowCount - offset;
		TARRAY_SET privRows;
		std::vector<TPROPVAL_ARRAY *> rows;
		if (offset < pubCount)
			exmdb.query_table(dir.c_str(), ctx.auth_info().username,
				CP_UTF8, tableId, tags, offset,
				std::min(results, pubCount - offset), &table);
		if (offset + results > pubCount) {
			uint32_t privOffset = offset > pubCount ? offset - pubCount : 0;
			exmdb.query_table(dir.c_str(), ctx.auth_info().username,
				CP_UTF8, privTable, tags, privOffset,
				offset + results - pubCount - privOffset, &privRows);
		}
		rows.insert(rows.end(), table.pparray, table.pparray + table.count);
		rows.insert(rows.end(), privRows.pparray, privRows.pparray + privRows.count);

		mFindItemResponseMessage msg;
		auto &items = msg.RootFolder.emplace().Items;
		items.reserve(rowCount);
		/* CalendarView: items keyed by start, to be ordered later */
		std::vector<std::pair<uint64_t, sItem>> calItems;
		for (auto row : rows) {
			TPROPVAL_ARRAY &props = *row;
			unclamp_binaries(ctx, dir, props);
			shape.clean();
			shape.properties(props);
			const BINARY *recur = recurTag != 0 ? props.get<const BINARY>(recurTag) : nullptr;
			const BINARY *eid = recurTag != 0 ? props.get<const BINARY>(PR_ENTRYID) : nullptr;
			try {
				if (recur != nullptr && recur->cb > 0 && eid != nullptr) {
					/* Recurring master: report its occurrences, not the series */
					sMessageEntryId meid(eid->pc, eid->cb);
					for (auto &occ : ctx.expandOccurrences(dir, meid.folderId(),
					     meid.messageId(), viewStart, viewEnd, shape)) {
						auto &start = std::get<tCalendarItem>(occ).Start;
						calItems.emplace_back(start ? start->toNT() : 0, std::move(occ));
					}
					continue;
				}
				sItem child = tItem::create(shape);
				const auto &iid = std::visit([](auto &&i) STATIC_IN_CXX23 -> std::optional<tItemId> & { return i.ItemId; }, child);
				if (shape.specials() && iid) {
					sMessageEntryId meid(iid->Id.data(), iid->Id.size());
					std::visit([&](auto& i) {ctx.loadSpecial(dir, meid.folderId(), meid.messageId(), i, shape.specials());}, child);
				}
				if (calView != nullptr) {
					auto start = props.get<const uint64_t>(startTag);
					calItems.emplace_back(start != nullptr ? *start : 0, std::move(child));
				} else {
					items.emplace_back(std::move(child));
				}
			} catch (const DispatchError &err) {
				/*
				 * One unreadable appointment - e.g. a
				 * PidLidAppointmentRecur blob that cannot be parsed -
				 * must not take down the response for the whole folder.
				 */
				mlog(LV_WARN, "ews: FindItem skipped an item in %s: %s",
				     dir.c_str(), err.what());
			} catch (const InputError &err) {
				mlog(LV_WARN, "ews: FindItem skipped an item in %s: %s",
				     dir.c_str(), err.what());
			}
		}
		size_t total = calItems.size();
		if (calView != nullptr) {
			/* Occurrences are produced per series, so order by start */
			std::stable_sort(calItems.begin(), calItems.end(),
				[](const auto &a, const auto &b) { return a.first < b.first; });
			if (maxResults != 0 && calItems.size() > maxResults)
				calItems.erase(calItems.begin() + maxResults, calItems.end());
			for (auto &ci : calItems)
				items.emplace_back(std::move(ci.second));
		}
		if (paging)
			paging->update(*msg.RootFolder, results, rowCount);
		msg.RootFolder->IncludesLastItemInRange = calView != nullptr ?
			items.size() >= total : results + offset >= rowCount;
		msg.RootFolder->TotalItemsInView = calView != nullptr ?
			total : rowCount;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process GetAppManifests
 *
 * Provides a stub that returns an empty Manifests node.
 *
 * @todo       This function lacks most of its functionality and is practically worthless.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetAppManifestsRequest&&, XMLElement *response, const EWSContext&)
{
	response->SetName("m:GetAppManifestsResponse");

	mGetAppManifestsResponse data;
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetUnifiedGroupsSettings
 *
 * Outlook asks for this at startup and prompts for credentials again when
 * the request fails. Answer like Exchange SE, which reports all groups
 * features off.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUnifiedGroupsSettingsRequest &&, XMLElement *response,
    const EWSContext &)
{
	response->SetName("m:GetUnifiedGroupsSettingsResponseMessage");
	mGetUnifiedGroupsSettingsResponse data;
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetAppMarketplaceUrl
 *
 * Stub reporting the marketplace as unavailable, like Exchange does
 * when no marketplace is configured.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetAppMarketplaceUrlRequest &&, XMLElement *response, const EWSContext &)
{
	response->SetName("m:GetAppMarketplaceUrlResponse");

	mGetAppMarketplaceUrlResponse data;
	data.error("ErrorMarketplaceWebServicesUrlNotAvailable",
		"The app marketplace is not available.");
	data.serialize(response);
}

/**
 * @brief      Process GetAttachment
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetAttachmentRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetAttachmentResponse");

	mGetAttachmentResponse data;
	data.ResponseMessages.reserve(request.AttachmentIds.size());
	for (const tRequestAttachmentId &raid : request.AttachmentIds) try {
		sAttachmentId aid(raid.Id.data(), raid.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(aid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, aid);
		auto rights = ctx.permissions(dir, parentFolder.folderId);
		if (!(rights & frightsReadAny))
			throw EWSError::AccessDenied(E3135);
		ctx.assertCanReadPrivate(dir, parentFolder, rights, aid.messageId());
		mGetAttachmentResponseMessage msg;
		msg.Attachments.emplace_back(ctx.loadAttachment(dir, aid));
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process GetEvents
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetEventsRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetEventsResponse");

	mGetEventsResponse data;
	try {
		auto [events, more] = ctx.getEvents(request.SubscriptionId);
		mGetEventsResponseMessage& msg = data.ResponseMessages.emplace_back();
		tNotification& notification = msg.Notification.emplace();
		notification.SubscriptionId = std::move(request.SubscriptionId);
		notification.events = std::move(events);
		notification.MoreEvents = more;
		if (notification.events.empty())
			notification.events.emplace_back(aStatusEvent());
		msg.success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process GetFolder
 *
 * Return properties of a list of folders.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetFolderRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetFolderResponse");

	sShape shape(request.FolderShape);

	mGetFolderResponse data;
	data.ResponseMessages.reserve(request.FolderIds.size());
	for (auto &folderId : request.FolderIds) try {
		sFolderSpec folder;
		folder = ctx.resolveFolder(folderId);
		if (!folder.target)
			folder.target = ctx.auth_info().username;
		folder.normalize();
		std::string dir = ctx.getDir(folder);
		if (!(itemRights(ctx, dir, folder.folderId) & (frightsVisible | fbRights)))
			throw EWSError::AccessDenied(E3136);
		mGetFolderResponseMessage msg;
		msg.Folders.emplace_back(ctx.loadFolder(dir, folder.folderId, shape));
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

namespace {

constexpr eid_t rules_inbox(1, PRIVATE_FID_INBOX);
const PROPERTY_NAME NtFlagRequest = {MNID_ID, PSETID_Common, PidLidFlagRequest};
const PROPERTY_NAME NtRuleTemplate = {MNID_STRING, PSETID_Gromox, 0, deconst("ews_rule_template")};

/**
 * @brief      Rows of the Inbox rules table that EWS manages
 *
 * Same selection as grommunio-web: PR_RULE_PROVIDER starting with
 * "RuleOrganizer". Delegate, out-of-office and import rules are left out.
 */
struct rule_row {
	uint64_t id = 0;
	uint32_t seq = 0, state = 0;
	TPROPVAL_ARRAY *props = nullptr;
};

/**
 * @brief      Mailbox services for the rule mapper
 */
class RulesEnv final : public Rules::Env {
	public:
	RulesEnv(const EWSContext &c, const std::string &d, const std::string &u) :
		ctx(c), exmdb(c.plugin().exmdb), dir(d), user(u)
	{}

	void *alloc(size_t z) override { return EWSContext::alloc(z); }

	uint16_t keywords_propid(bool create) override { return named(NtCategories, create); }
	uint16_t flagrequest_propid(bool create) override { return named(NtFlagRequest, create); }

	const char *resolve_folder(const Rules::FolderRef &, MOVECOPY_ACTION &) override;
	const char *deleted_items(MOVECOPY_ACTION &) override;
	const char *resolve_template(const Rules::ItemRef &, REPLY_ACTION &) override;
	const char *resolve_address(Rules::Address &) override;
	bool folder_ref(const MOVECOPY_ACTION &, Rules::FolderRef &, bool &) override;
	bool template_ref(const REPLY_ACTION &, Rules::ItemRef &) override;
	bool essdn_to_smtp(const char *, std::string &) override;
	void rollback();

	std::vector<eid_t> created_templates;

	private:
	uint16_t named(const PROPERTY_NAME &name, bool create)
	{
		try {
			return ctx.getNamedPropId(dir, name, create);
		} catch (const std::exception &) {
			return 0;
		}
	}

	const EWSContext &ctx;
	const EWSPlugin::_exmdb &exmdb;
	std::string dir, user;
};

const char *RulesEnv::resolve_folder(const Rules::FolderRef &f, MOVECOPY_ACTION &mc) try
{
	sFolderSpec spec;
	if (f.distinguished) {
		spec = sFolderSpec(tDistinguishedFolderId(f.id));
		spec.target = f.mailbox.empty() ? user : f.mailbox;
	} else {
		auto raw = base64_decode(f.id);
		if (raw.empty() || raw.back() != tBaseItemId::ID_FOLDER)
			return "InvalidFolderId";
		raw.pop_back();
		spec = ctx.resolveFolder(tFolderId(sBase64Binary(std::move(raw)), tBaseItemId::ID_FOLDER));
	}
	/* Rules cannot target public folders */
	if (spec.location != sFolderSpec::PRIVATE)
		return "InvalidFolderId";
	auto tdir = ctx.getDir(spec);
	BOOL exist = false;
	if (!exmdb.is_folder_present(tdir.c_str(), spec.folderId, &exist) || !exist)
		return "FolderDoesNotExist";
	if (tdir == dir) {
		auto sv = EWSContext::construct<SVREID>();
		sv->folder_id = eid_t(spec.folderId);
		mc.same_store = 1;
		mc.pfolder_eid = sv;
		return nullptr;
	}
	/* Another mailbox, ruleproc checks the owner's rights on delivery */
	std::string essdn;
	if (cvt_username_to_essdn(spec.target->c_str(), ctx.plugin().x500_org_name.c_str(),
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids, essdn) != ecSuccess)
		return "InvalidFolderId";
	auto se = EWSContext::construct<STORE_ENTRYID>();
	se->wrapped_provider_uid = g_muidStorePrivate;
	se->wrapped_type = OPENSTORE_HOME_LOGON | OPENSTORE_TAKE_OWNERSHIP;
	se->pserver_name = EWSContext::cpystr(*spec.target);
	se->pmailbox_dn = EWSContext::cpystr(essdn);
	auto eid = ctx.getFolderEntryId(tdir, spec.folderId);
	mc.same_store = 0;
	mc.pstore_eid = se;
	mc.pfolder_eid = eid.pvalue;
	return nullptr;
} catch (const std::exception &) {
	return "InvalidFolderId";
}

const char *RulesEnv::deleted_items(MOVECOPY_ACTION &mc)
{
	auto sv = EWSContext::construct<SVREID>();
	sv->folder_id = eid_t(1, PRIVATE_FID_DELETED_ITEMS);
	mc.same_store = 1;
	mc.pfolder_eid = sv;
	return nullptr;
}

/**
 * @brief      Find or create the reply template of a ServerReplyWithMessage
 *
 * An existing Inbox reply template is used as is. Any other message of the
 * mailbox is copied into a new one, MS-OXORULE v23.0 §3.1.4.2.5, and marked
 * so it can be removed once no rule refers to it.
 */
const char *RulesEnv::resolve_template(const Rules::ItemRef &ref, REPLY_ACTION &ra) try
{
	auto raw = base64_decode(ref.id);
	if (raw.empty() || raw.back() != tBaseItemId::ID_ITEM)
		return "InvalidValue";
	raw.pop_back();
	sMessageEntryId meid(raw.data(), raw.size());
	if (!meid.isPrivate() || meid.accountId() != ctx.getAccountId(user, false))
		return "InvalidValue";
	/* A delegate must not copy items it cannot read into a template */
	ctx.validate(dir, meid);
	if (!(ctx.permissions(dir, meid.folderId()) & frightsReadAny))
		return "InvalidValue";
	MESSAGE_CONTENT *content = nullptr;
	if (!exmdb.read_message(dir.c_str(), nullptr, CP_ACP, meid.messageId(),
	    &content) || content == nullptr)
		return "InvalidValue";
	auto &pl = content->proplist;
	auto fai = pl.get<const uint8_t>(PR_ASSOCIATED);
	auto cls = pl.get<const char>(PR_MESSAGE_CLASS);
	auto tid = pl.get<const BINARY>(PR_REPLY_TEMPLATE_ID);
	if (fai != nullptr && *fai != 0 && cls != nullptr &&
	    strncasecmp(cls, "IPM.Note.Rules.ReplyTemplate.", 29) == 0 &&
	    meid.folderId() == rules_inbox && tid != nullptr && tid->cb == sizeof(GUID)) {
		ra.template_folder_id = rules_inbox;
		ra.template_message_id = meid.messageId();
		ra.template_guid = rop_util_binary_to_guid(tid);
		return nullptr;
	}

	message_content_ptr copy(content->dup());
	if (copy == nullptr)
		return "UnexpectedError";
	auto &props = copy->proplist;
	static constexpr proptag_t rm[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST, PR_ENTRYID, PR_SOURCE_KEY,
		PR_PARENT_SOURCE_KEY, PR_PARENT_ENTRYID,
	};
	for (auto t : rm)
		props.erase(t);
	auto marker = named(NtRuleTemplate, true);
	if (marker == 0)
		return "UnexpectedError";
	auto guid = GUID::random_new();
	char gbuf[16];
	EXT_PUSH ep;
	if (!ep.init(gbuf, sizeof(gbuf), 0) || ep.p_guid(guid) != pack_result::ok)
		return "UnexpectedError";
	BINARY gbin{sizeof(gbuf), {gbuf}};
	uint8_t one = 1;
	if (props.set(PR_MESSAGE_CLASS, "IPM.Note.Rules.ReplyTemplate.Microsoft") != ecSuccess ||
	    props.set(PR_ASSOCIATED, &one) != ecSuccess ||
	    props.set(PR_REPLY_TEMPLATE_ID, &gbin) != ecSuccess ||
	    props.set(PROP_TAG(PT_BOOLEAN, marker), &one) != ecSuccess)
		return "UnexpectedError";
	uint64_t outmid = 0, outcn = 0;
	ec_error_t err = ecSuccess;
	if (!exmdb.write_message(dir.c_str(), CP_ACP, rules_inbox, copy.get(),
	    {}, &outmid, &outcn, &err) || err != ecSuccess)
		return "UnexpectedError";
	created_templates.push_back(eid_t(outmid));
	ra.template_folder_id = rules_inbox;
	ra.template_message_id = eid_t(outmid);
	ra.template_guid = guid;
	return nullptr;
} catch (const std::exception &) {
	return "InvalidValue";
}

/**
 * @brief      Delete templates made for a request that did not go through
 */
void RulesEnv::rollback()
{
	if (created_templates.empty())
		return;
	BOOL partial = false;
	exmdb.delete_messages(dir.c_str(), CP_ACP, nullptr, rules_inbox,
		created_templates, true, &partial);
	created_templates.clear();
}

const char *RulesEnv::resolve_address(Rules::Address &a)
{
	if (strcasecmp(a.routing.c_str(), "EX") == 0) {
		try {
			a.email = ctx.essdn_to_username(a.email);
		} catch (const std::exception &) {
			return "InvalidAddress";
		}
	}
	a.routing = "SMTP";
	if (a.email.find('@') == a.email.npos)
		return "InvalidAddress";
	return nullptr;
}

bool RulesEnv::folder_ref(const MOVECOPY_ACTION &mc, Rules::FolderRef &ref, bool &trash) try
{
	std::string tdir;
	uint64_t fid = 0;
	sBase64Binary eid;
	if (mc.same_store) {
		auto sv = static_cast<const SVREID *>(mc.pfolder_eid);
		if (sv == nullptr || sv->pbin != nullptr)
			return false;
		tdir = dir;
		fid = sv->folder_id;
		eid = sBase64Binary(ctx.getFolderEntryId(dir, fid));
	} else {
		auto se = mc.pstore_eid;
		auto bin = static_cast<const BINARY *>(mc.pfolder_eid);
		if (se == nullptr || bin == nullptr || se->pserver_name == nullptr ||
		    se->wrapped_provider_uid != g_muidStorePrivate)
			return false;
		sFolderEntryId feid(bin->pv, bin->cb);
		if (!feid.isPrivate())
			return false;
		eid = sBase64Binary(bin);
		auto spec = ctx.resolveFolder(tFolderId(eid, tBaseItemId::ID_FOLDER));
		tdir = ctx.getDir(spec);
		fid = spec.folderId;
	}
	/*
	 * Exchange cannot move into another mailbox, and Outlook for Mac
	 * offers to delete such rules. Report them as not supported.
	 */
	if (tdir != dir || !sFolderEntryId(eid.data(), eid.size()).isPrivate())
		return false;
	trash = eid_t(fid).gcv() == PRIVATE_FID_DELETED_ITEMS;
	/* Outlook for Mac crashes on a rule folder without ChangeKey */
	auto ck = ctx.getFolderProp<BINARY>(tdir, fid, PR_CHANGE_KEY);
	if (ck == nullptr)
		return false;
	ref.id = base64_encode(tFolderId(std::move(eid), tBaseItemId::ID_FOLDER).serializeId());
	ref.change_key = base64_encode(*ck);
	return true;
} catch (const std::exception &) {
	return false;
}

bool RulesEnv::template_ref(const REPLY_ACTION &ra, Rules::ItemRef &ref) try
{
	auto eid = ctx.getItemEntryId(dir, ra.template_message_id);
	ref.id = base64_encode(tItemId(sBase64Binary(eid), tBaseItemId::ID_ITEM).serializeId());
	return true;
} catch (const std::exception &) {
	return false;
}

bool RulesEnv::essdn_to_smtp(const char *essdn, std::string &smtp) try
{
	smtp = ctx.essdn_to_username(essdn);
	return true;
} catch (const std::exception &) {
	return false;
}

/**
 * @brief      Resolve the mailbox of a rules request
 *
 * Rules of another mailbox need owner rights on its Inbox, as
 * ropModifyRules does.
 *
 * @return     Home directory and user name
 */
std::pair<std::string, std::string>
rules_mailbox(const EWSContext &ctx, const std::optional<std::string> &smtp)
{
	std::string user = smtp && !smtp->empty() ? *smtp : ctx.auth_info().username;
	sFolderSpec inbox(user, rules_inbox);
	inbox.location = sFolderSpec::PRIVATE;
	auto dir = ctx.getDir(inbox);
	if (!(ctx.permissions(dir, inbox.folderId) & frightsOwner))
		throw EWSError::AccessDenied(E3607);
	return {std::move(dir), std::move(user)};
}

/**
 * @brief      Message ids of the Outlook rule blob FAIs in the Inbox
 */
std::vector<eid_t> find_rule_blobs(const EWSContext &ctx, const std::string &dir)
{
	auto &exmdb = ctx.plugin().exmdb;
	static constexpr RESTRICTION_EXIST rst_a = {PR_MESSAGE_CLASS};
	static constexpr RESTRICTION_CONTENT rst_b = {FL_IGNORECASE, PR_MESSAGE_CLASS, {PT_UNICODE, deconst("IPM.RuleOrganizer")}};
	static constexpr RESTRICTION rst_c[2] = {{RES_EXIST, {deconst(&rst_a)}}, {RES_CONTENT, {deconst(&rst_b)}}};
	static constexpr RESTRICTION_AND_OR rst_d = {std::size(rst_c), deconst(rst_c)};
	static constexpr RESTRICTION rst_e = {RES_AND, {deconst(&rst_d)}};
	uint32_t table_id = 0, count = 0;
	if (!exmdb.load_content_table(dir.c_str(), CP_ACP, rules_inbox, nullptr,
	    TABLE_FLAG_ASSOCIATED, &rst_e, nullptr, &table_id, &count))
		throw EWSError::InternalServerError(E3608);
	auto cl = HX::make_scope_exit([&]() { exmdb.unload_table(dir.c_str(), table_id); });
	std::vector<eid_t> mids;
	if (count == 0)
		return mids;
	static constexpr proptag_t tags[] = {PidTagMid};
	TARRAY_SET set{};
	if (!exmdb.query_table(dir.c_str(), nullptr, CP_ACP, table_id, {tags, std::size(tags)}, 0, count, &set))
		throw EWSError::InternalServerError(E3608);
	for (const auto &row : set)
		if (auto mid = row.get<const uint64_t>(PidTagMid))
			mids.push_back(eid_t(*mid));
	return mids;
}

/**
 * @brief      Load the visible rules of the Inbox, in execution order
 */
std::vector<rule_row> load_rules(const EWSContext &ctx, const std::string &dir, bool all = false)
{
	auto &exmdb = ctx.plugin().exmdb;
	uint32_t table_id = 0, count = 0;
	if (!exmdb.load_rule_table(dir.c_str(), rules_inbox, 0, nullptr, &table_id, &count))
		throw EWSError::InternalServerError(E3606);
	auto cl = HX::make_scope_exit([&]() { exmdb.unload_table(dir.c_str(), table_id); });
	std::vector<rule_row> rows;
	if (count == 0)
		return rows;
	static constexpr proptag_t tags[] = {
		PR_RULE_ID, PR_RULE_SEQUENCE, PR_RULE_STATE, PR_RULE_NAME,
		PR_RULE_PROVIDER, PR_RULE_LEVEL, PR_RULE_CONDITION, PR_RULE_ACTIONS,
	};
	TARRAY_SET set{};
	if (!exmdb.query_table(dir.c_str(), nullptr, CP_ACP, table_id, {tags, std::size(tags)}, 0, count, &set))
		throw EWSError::InternalServerError(E3606);
	for (auto &row : set) {
		auto id = row.get<const uint64_t>(PR_RULE_ID);
		if (id == nullptr || (!all && !Rules::is_visible(row)))
			continue;
		auto seq = row.get<const uint32_t>(PR_RULE_SEQUENCE);
		auto st = row.get<const uint32_t>(PR_RULE_STATE);
		rows.push_back({*id, seq != nullptr ? *seq : 0, st != nullptr ? *st : 0, &row});
	}
	std::stable_sort(rows.begin(), rows.end(), [](const rule_row &a, const rule_row &b) {
		return a.seq != b.seq ? a.seq < b.seq : eid_t(a.id).gcv() < eid_t(b.id).gcv();
	});
	return rows;
}

}

/**
 * @brief      Process GetInboxRulesRequest
 *
 * Returns the Inbox rules managed through the rules organizer, in execution
 * order. Rules that EWS cannot express come back with IsNotSupported.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetInboxRulesRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetInboxRulesResponse");

	mGetInboxRulesResponse data;
	try {
		auto [dir, user] = rules_mailbox(ctx, request.MailboxSmtpAddress);
		/* MS-OXWSRULES v9.0 §3.1.4.1.3.2: always present */
		data.OutlookRuleBlobExists = !find_rule_blobs(ctx, dir).empty();
		RulesEnv env(ctx, dir, user);
		int32_t prio = 0;
		for (const auto &row : load_rules(ctx, dir)) {
			auto rule = Rules::from_mapi(*row.props, env);
			rule.priority = ++prio;
			data.InboxRules.push_back(std::move(rule));
		}
		data.success();
	} catch (const EWSError &err) {
		data = mGetInboxRulesResponse();
		static_cast<mResponseMessageType &>(data) = mResponseMessageType(err);
	}
	data.serialize(response);
}

namespace {

/**
 * @brief      Rule list entry during UpdateInboxRules
 */
struct rule_slot {
	const rule_row *old = nullptr; /* nullptr: created */
	const Rules::Rule *rule = nullptr; /* nullptr: unchanged */
	RESTRICTION *cond = nullptr;
	RULE_ACTIONS *acts = nullptr;
	uint32_t state = 0;
};

/**
 * @brief      Organizer2 provider data, outlook_rule_spec.rst "FAI message: RuleV2"
 */
BINARY *provider_data()
{
	auto bin = EWSContext::construct<BINARY>();
	bin->cb = 16;
	bin->pv = EWSContext::alloc(16);
	double apptime = static_cast<double>(time(nullptr)) / 86400 + 25569;
	EXT_PUSH ep;
	if (!ep.init(bin->pv, 16, 0) || ep.p_uint32(1) != pack_result::ok ||
	    ep.p_uint32(1) != pack_result::ok || ep.p_double(apptime) != pack_result::ok)
		throw EWSError::NotEnoughMemory(E3129);
	return bin;
}

/**
 * @brief      Delete reply templates that EWS made and no rule uses anymore
 */
void purge_templates(const EWSContext &ctx, const std::string &dir)
{
	auto &exmdb = ctx.plugin().exmdb;
	propid_t marker = 0;
	try {
		marker = ctx.getNamedPropId(dir, NtRuleTemplate, false);
	} catch (const std::exception &) {
		return;
	}
	if (marker == 0)
		return;
	RESTRICTION_EXIST ex{PROP_TAG(PT_BOOLEAN, marker)};
	RESTRICTION res{RES_EXIST, {&ex}};
	uint32_t table_id = 0, count = 0;
	if (!exmdb.load_content_table(dir.c_str(), CP_ACP, rules_inbox, nullptr,
	    TABLE_FLAG_ASSOCIATED, &res, nullptr, &table_id, &count))
		return;
	auto cl = HX::make_scope_exit([&]() { exmdb.unload_table(dir.c_str(), table_id); });
	if (count == 0)
		return;
	static constexpr proptag_t tags[] = {PidTagMid};
	TARRAY_SET set{};
	if (!exmdb.query_table(dir.c_str(), nullptr, CP_ACP, table_id, {tags, std::size(tags)}, 0, count, &set))
		return;
	std::unordered_set<uint64_t> used;
	for (const auto &row : load_rules(ctx, dir, true)) {
		auto acts = row.props->get<const RULE_ACTIONS>(PR_RULE_ACTIONS);
		if (acts == nullptr)
			continue;
		for (const auto &a : *acts)
			if ((a.type == OP_REPLY || a.type == OP_OOF_REPLY) && a.pdata != nullptr)
				used.insert(static_cast<const REPLY_ACTION *>(a.pdata)->template_message_id);
	}
	std::vector<eid_t> orphans;
	for (const auto &row : set)
		if (auto mid = row.get<const uint64_t>(PidTagMid); mid != nullptr && !used.contains(*mid))
			orphans.push_back(eid_t(*mid));
	if (orphans.empty())
		return;
	BOOL partial = false;
	exmdb.delete_messages(dir.c_str(), CP_ACP, nullptr, rules_inbox,
		orphans, true, &partial);
}

}

/**
 * @brief      Process UpdateInboxRulesRequest
 *
 * All operations are validated first. Any error leaves the rules untouched
 * and reports every failed operation, MS-OXWSRULES v9.0 §3.1.4.2. The
 * remaining changes are written in one update_folder_rule batch.
 *
 * Priorities are positions among the rules GetInboxRules returns. The
 * sequence numbers those rules had are reused, so delegate and
 * out-of-office rules keep their place in the execution order.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mUpdateInboxRulesRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:UpdateInboxRulesResponse");

	mUpdateInboxRulesResponse data;
	std::optional<RulesEnv> env;
	try {
		auto &exmdb = ctx.plugin().exmdb;
		auto [dir, user] = rules_mailbox(ctx, request.MailboxSmtpAddress);
		bool remove_blob = request.RemoveOutlookRuleBlob.value_or(false);
		auto blobs = find_rule_blobs(ctx, dir);
		if (!blobs.empty() && !remove_blob)
			throw EWSError::OutlookRuleBlobExists(E3609);
		auto rows = load_rules(ctx, dir);
		env.emplace(ctx, dir, user);

		std::vector<rule_slot> list;
		for (const auto &row : rows)
			list.push_back({&row, nullptr, nullptr, nullptr, row.state});
		auto find = [&](const std::string &id) {
			auto v = Rules::decode_rule_id(id);
			return v ? std::find_if(list.begin(), list.end(), [&](const rule_slot &s) {
				return s.old != nullptr && s.old->id == *v;
			}) : list.end();
		};
		std::unordered_set<std::string> touched;
		std::vector<Rules::OperationError> errors;
		for (size_t i = 0; i < request.Operations.size(); ++i) {
			auto &op = request.Operations[i];
			std::string id = op.kind == Rules::Operation::DELETE ? op.rule_id :
			                 op.rule.id.value_or(std::string{});
			std::vector<Rules::ValidationError> ve;
			auto it = list.end();
			if (op.kind == Rules::Operation::DELETE ||
			    (op.kind == Rules::Operation::SET && op.rule.id)) {
				it = find(id);
				if (!id.empty() && !touched.insert(id).second)
					ve.push_back({"RuleId", "DuplicatedOperationOnTheSameRule",
						"Only one operation per rule is allowed.", id});
				else if (it == list.end())
					ve.push_back({"RuleId", "RuleNotFound", "The rule was not found.", id});
			}
			if (op.kind == Rules::Operation::DELETE) {
				if (ve.empty())
					list.erase(it);
				else
					errors.push_back({static_cast<int32_t>(i), std::move(ve)});
				continue;
			}
			Rules::strip_wildcards(op.rule);
			auto rv = Rules::validate(op.rule, op.kind);
			ve.insert(ve.end(), rv.begin(), rv.end());
			if (ve.empty() && it != list.end() && op.kind == Rules::Operation::SET &&
			    Rules::from_mapi(*it->old->props, *env).not_supported.value_or(false))
				ve.push_back({"IsNotSupported", "UnsupportedRule",
					"The rule cannot be changed through EWS.", id});
			rule_slot slot;
			if (ve.empty() && Rules::to_mapi(op.rule, *env, slot.cond, slot.acts, ve)) {
				uint32_t state = 0;
				if (op.kind == Rules::Operation::SET) {
					slot.old = it->old;
					state = it->state & ~(ST_ENABLED | ST_EXIT_LEVEL);
					if (!op.rule.in_error.value_or(true))
						state &= ~(ST_ERROR | ST_PARSE_ERROR);
					list.erase(it);
				}
				auto &stop = op.rule.actions.v[Rules::A_StopProcessingRules];
				if (op.rule.enabled)
					state |= ST_ENABLED;
				if (stop && stop->flag)
					state |= ST_EXIT_LEVEL;
				slot.rule = &op.rule;
				slot.state = state;
				auto pos = std::min(static_cast<size_t>(op.rule.priority - 1), list.size());
				list.insert(list.begin() + pos, slot);
			}
			if (!ve.empty())
				errors.push_back({static_cast<int32_t>(i), std::move(ve)});
		}
		if (!errors.empty()) {
			env->rollback();
			data.error("ErrorInboxRulesValidationError",
				"Validation error occurred during rule operation execution.");
			data.RuleOperationErrors = std::move(errors);
			data.serialize(response);
			return;
		}

		if (remove_blob && !blobs.empty()) {
			BOOL partial = false;
			if (!exmdb.delete_messages(dir.c_str(), CP_ACP, nullptr,
			    rules_inbox, blobs, true, &partial))
				throw EWSError::InternalServerError(E3610);
		}

		std::vector<uint32_t> old_seqs;
		for (const auto &row : rows)
			old_seqs.push_back(row.seq);
		auto seqs = Rules::assign_sequences(std::move(old_seqs), list.size());
		std::vector<RULE_DATA> batch;
		auto mkrow = [&](uint8_t flags, std::vector<TAGGED_PROPVAL> &&pv) {
			auto arr = EWSContext::alloc<TAGGED_PROPVAL>(pv.size());
			std::copy(pv.begin(), pv.end(), arr);
			batch.push_back({flags, {static_cast<uint16_t>(pv.size()), arr}});
		};
		for (const auto &row : rows)
			if (std::none_of(list.begin(), list.end(), [&](const rule_slot &s) { return s.old == &row; }))
				mkrow(ROW_REMOVE, {{PR_RULE_ID, deconst(&row.id)}});
		static constexpr uint32_t zero = 0;
		for (size_t i = 0; i < list.size(); ++i) {
			auto &s = list[i];
			auto seq = &seqs[i];
			if (s.old != nullptr && s.rule == nullptr) {
				if (s.old->seq != *seq)
					mkrow(ROW_MODIFY, {{PR_RULE_ID, deconst(&s.old->id)},
						{PR_RULE_SEQUENCE, seq}});
				continue;
			}
			std::vector<TAGGED_PROPVAL> pv = {
				{PR_RULE_NAME, deconst(s.rule->name.c_str())},
				{PR_RULE_SEQUENCE, seq},
				{PR_RULE_STATE, &s.state},
				{PR_RULE_CONDITION, s.cond},
				{PR_RULE_ACTIONS, s.acts},
			};
			if (s.old != nullptr) {
				pv.push_back({PR_RULE_ID, deconst(&s.old->id)});
				mkrow(ROW_MODIFY, std::move(pv));
				continue;
			}
			pv.push_back({PR_RULE_PROVIDER, deconst("RuleOrganizer")});
			pv.push_back({PR_RULE_LEVEL, deconst(&zero)});
			pv.push_back({PR_RULE_PROVIDER_DATA, provider_data()});
			mkrow(ROW_ADD, std::move(pv));
		}
		/* Removals first so they make room for the additions */
		std::stable_partition(batch.begin(), batch.end(),
			[](const RULE_DATA &r) { return r.flags == ROW_REMOVE; });
		BOOL exceed = false;
		if (!batch.empty() && !exmdb.update_folder_rule(dir.c_str(), rules_inbox,
		    static_cast<uint16_t>(batch.size()), batch.data(), &exceed))
			throw EWSError::InternalServerError(E3611);
		if (exceed)
			throw EWSError::RulesOverQuota(E3612);
		env->created_templates.clear();
		purge_templates(ctx, dir);
		data.success();
	} catch (const EWSError &err) {
		if (env)
			env->rollback();
		data = mUpdateInboxRulesResponse();
		static_cast<mResponseMessageType &>(data) = mResponseMessageType(err);
	}
	data.serialize(response);
}

/**
 * @brief      Process GetMailTipsRequest
 *
 * Provides the functionality of GetMailTips
 *
 * In its current state it does nothing more than echoing back the recipient list.
 *
 * @todo       This function lacks most of its functionality and is practically worthless.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetMailTipsRequest &&request, XMLElement *response, const EWSContext&)
{
	response->SetName("m:GetMailTipsResponse");

	mGetMailTipsResponse data;
	data.ResponseMessages.reserve(request.Recipients.size());

	for (auto &recipient : request.Recipients) {
		mMailTipsResponseMessageType& mailTipsResponseMessage = data.ResponseMessages.emplace_back();
		tMailTips& mailTips = mailTipsResponseMessage.MailTips.emplace();
		mailTips.RecipientAddress = std::move(recipient);
		mailTips.RecipientAddress.Name.emplace("");
		auto &oof = mailTips.OutOfOffice.emplace();
		oof.OofState = "Disabled";
		oof.OofReply.emplace(std::string{});
		mailTipsResponseMessage.success();
	}

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetServerTimeZones
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetServerTimeZonesRequest &&request, XMLElement *response, const EWSContext &)
{
	response->SetName("m:GetServerTimeZonesResponse");

	bool full = request.ReturnFullTimeZoneData.value_or(true);
	std::vector<std::string_view> blobs;
	if (request.Ids) {
		for (const auto &id : *request.Ids)
			if (auto tzd = wintz_to_tzdef(id.c_str()))
				blobs.push_back(*tzd);
	} else {
		blobs = wintz_all_tzdefs();
	}
	mGetServerTimeZonesResponseMessage msg;
	for (auto blob : blobs) {
		auto tzdef = EXT_PULL::bin_to_tzdef(blob);
		if (tzdef && tzdef->keyname.size() > 0)
			msg.TimeZoneDefinitions.emplace_back(std::move(*tzdef), full);
	}
	std::sort(msg.TimeZoneDefinitions.begin(), msg.TimeZoneDefinitions.end(),
		[](const tServerTimeZone &a, const tServerTimeZone &b) { return a.tz.keyname < b.tz.keyname; });
	msg.success();
	mGetServerTimeZonesResponse data;
	data.ResponseMessages.emplace_back(std::move(msg));
	data.serialize(response);
}

/**
 * @brief      Process GetRoomListsRequest
 */
void process(mGetRoomListsRequest&&, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetRoomListsResponse");

	auto user_domain = extract_domain(ctx.auth_info().username);
	if (user_domain.empty())
		throw DispatchError(E3090(ctx.auth_info().username));

	unsigned int user_domain_id = 0, org_id = 0;
	resolve_domain_ids(user_domain, user_domain_id, org_id);
	(void)user_domain_id;

	std::vector<unsigned int> domain_ids;
	if (!mysql_adaptor_get_org_domains(org_id, domain_ids))
		throw DispatchError(E3387);

	mGetRoomListsResponse data;
	std::vector<tRoomListEntry> lists;
	lists.reserve(domain_ids.size());

	for (unsigned int domain_id : domain_ids) {
		sql_domain info;
		if (!mysql_adaptor_get_domain_info(domain_id, info))
			throw DispatchError(E3388);
		if (!collect_rooms(domain_id))
			continue;
		lists.emplace_back(make_room_list_entry(info));
	}

	if (!lists.empty())
		data.RoomLists = std::move(lists);
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetRoomsRequest
 */
void process(mGetRoomsRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetRoomsResponse");

	ctx.normalize(request.RoomList);
	if (!request.RoomList.EmailAddress)
		throw DispatchError(E3441("RoomList"));

	auto user_domain = extract_domain(ctx.auth_info().username);
	if (user_domain.empty())
		throw DispatchError(E3442(ctx.auth_info().username));
	unsigned int user_domain_id = 0, user_org_id = 0;
	resolve_domain_ids(user_domain, user_domain_id, user_org_id);

	auto target_domain = extract_domain(request.RoomList.EmailAddress->c_str());
	if (target_domain.empty())
		throw DispatchError(E3443(*request.RoomList.EmailAddress));
	unsigned int target_domain_id = 0, target_org_id = 0;
	resolve_domain_ids(target_domain, target_domain_id, target_org_id);

	if (user_org_id != target_org_id)
		throw EWSError::AccessDenied(E3018);

	std::vector<tRoomType> rooms;
	collect_rooms(target_domain_id, &rooms);

	mGetRoomsResponse data;
	data.Rooms = std::move(rooms);
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetServiceConfigurationRequest
 *
 * Provides the functionality of GetServiceConfiguration
 *
 * Current implementation is basically a stub and only delivers static data;
 *
 * @todo       This function lacks most of its functionality.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetServiceConfigurationRequest&&, XMLElement *response, const EWSContext&)
{
	response->SetName("m:GetServiceConfigurationResponse");

	mGetServiceConfigurationResponse data;
	mGetServiceConfigurationResponseMessageType& msg = data.ResponseMessages.emplace_back();
	msg.MailTipsConfiguration.emplace();
	msg.success();

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetUserAvailabilityRequest
 *
 * Resolves the request timezone and returns free/busy data for the selected
 * mailboxes. Any per-mailbox failures are reported through the response
 * messages instead of aborting the whole SOAP request.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUserAvailabilityRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetUserAvailabilityResponse");

	if (!request.FreeBusyViewOptions && !request.SuggestionsViewOptions)
		throw EWSError::InvalidFreeBusyViewType(E3013);
	if (!request.TimeZone) {
		if (auto tz = timezone_from_context(ctx))
			request.TimeZone.emplace(std::move(*tz));
	}

	mGetUserAvailabilityResponse data;
	data.FreeBusyResponseArray.emplace().reserve(request.MailboxDataArray.size());

	if (!request.TimeZone) {
		const auto err = EWSError::TimeZone(E3014);
		for (size_t i = 0; i < request.MailboxDataArray.size(); ++i) {
			auto& fbr = data.FreeBusyResponseArray->emplace_back();
			fbr.ResponseMessage.emplace(err);
		}
		data.serialize(response);
		return;
	}

	tDuration &TimeWindow = request.FreeBusyViewOptions ?
	                        request.FreeBusyViewOptions->TimeWindow :
	                        request.SuggestionsViewOptions->DetailedSuggestionsWindow;

	tFreeBusyViewOptions default_view_options;
	const auto &view_options = request.FreeBusyViewOptions ?
	                           *request.FreeBusyViewOptions :
	                           default_view_options;

	const tSerializableTimeZone& timezone = *request.TimeZone;
	const auto windowStart = timezone.remove(TimeWindow.StartTime);
	const auto windowEnd = timezone.remove(TimeWindow.EndTime);
	auto start = clock::to_time_t(windowStart);
	auto end   = clock::to_time_t(windowEnd);
	auto interval = view_options.interval();
	if (view_options.merged() && (interval < 5 || interval > 1440 ||
	    interval * 60 > end - start))
		throw EWSError::InvalidMergedFreeBusyInterval(E3614);
	if (view_options.merged() && end - start > 62 * 86400)
		throw EWSError::TimeIntervalTooBig(E3615);

	for (const tMailboxData &MailboxData : request.MailboxDataArray) try {
		std::string maildir;
		try {
			maildir = ctx.get_maildir(MailboxData.Email);
		} catch (const EWSError &) {
			/* Not a local mailbox: report an empty view like Exchange */
			auto &fbr = data.FreeBusyResponseArray->emplace_back();
			fbr.FreeBusyView.emplace();
			fbr.ResponseMessage.emplace(EWSError::MailRecipientNotFound(E3499));
			continue;
		}
		/* No user means the owner, see get_freebusy() */
		tFreeBusyView fbv(maildir == ctx.auth_info().maildir ? nullptr :
			ctx.auth_info().username, maildir.c_str(),
			ctx.plugin().x500_org_name.c_str(), start, end,
			view_options);
		mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back(std::move(fbv));
		if (fbr.FreeBusyView && fbr.FreeBusyView->CalendarEventArray) {
			for (auto &event : *fbr.FreeBusyView->CalendarEventArray) {
				event.StartTime.offset = timezone.offset(event.StartTime.time);
				event.EndTime.offset = timezone.offset(event.EndTime.time);
			}
		}
		fbr.ResponseMessage.emplace().success();
	} catch (const EWSError &err) {
		mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back();
		fbr.ResponseMessage.emplace(err);
	} catch (const std::exception &err) {
		mlog(LV_ERR, "[ews#%d] failed to resolve availability for %s: %s",
		    ctx.context_id(), MailboxData.Email.Address.c_str(), err.what());
		mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back();
		fbr.ResponseMessage.emplace(EWSError::InternalServerError(err.what()));
	}

	data.serialize(response);
}

/**
 * @brief      Process GetDtreamingEventsRequest
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetStreamingEventsRequest &&request, XMLElement *response, EWSContext &ctx)
{
	response->SetName("m:GetStreamingEventsResponse");

	mGetStreamingEventsResponse data;
	mGetStreamingEventsResponseMessage& msg = data.ResponseMessages.emplace_back();

	ctx.enableEventStream(request.ConnectionTimeout);
	for (const tSubscriptionId &subscription : request.SubscriptionIds)
		if (!ctx.streamEvents(subscription))
			msg.ErrorSubscriptionIds.emplace_back(subscription);
	if (msg.ErrorSubscriptionIds.empty()) {
		msg.success();
		msg.ConnectionStatus = Enum::OK;
	} else {
		/*
		 * A faulted subscription (e.g. event backlog overflow, see
		 * EWSPlugin::event()) never becomes valid again on its own.
		 * The client must Subscribe anew and resync.
		 */
		msg.error("ErrorInvalidSubscription", "Subscription is invalid.");
		msg.ConnectionStatus = Enum::Closed;
	}

	data.serialize(response);
}

/**
 * @brief      Process CreateUserConfiguration
 *
 * Create a new FAI message to hold user configuration data.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mCreateUserConfigurationRequest &&request, XMLElement *response,
    const EWSContext &ctx)
{
	response->SetName("m:CreateUserConfigurationResponse");

	mCreateUserConfigurationResponse data;
	try {
		auto &exmdb = ctx.plugin().exmdb;
		const auto &reqName  = request.UserConfiguration.UserConfigurationName;
		const auto &folderId = reqName.FolderId;
		sFolderSpec folder;

		if (auto raw = std::get_if<tFolderId>(&folderId))
			folder = ctx.resolveFolder(*raw);
		else if (auto dist = std::get_if<tDistinguishedFolderId>(&folderId))
			folder = ctx.resolveFolder(*dist);
		else
			throw EWSError::InvalidFolderId(E3420);

		if (!folder.target)
			folder.target = ctx.auth_info().username;
		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsCreate))
			throw EWSError::AccessDenied(E3434);

		uint64_t messageId, changeNumber;
		if (!exmdb.allocate_message_id(dir.c_str(),
		    folder.folderId, &messageId))
			throw EWSError::ItemSave(E3413);
		if (!exmdb.allocate_cn(dir.c_str(), &changeNumber))
			throw EWSError::ItemSave(E3414);

		bool isPublic = folder.location == folder.PUBLIC;
		uint32_t accountId = ctx.getAccountId(*folder.target, isPublic);
		XID xid{isPublic ?
			rop_util_make_domain_guid(accountId) :
			rop_util_make_user_guid(accountId),
			changeNumber};
		BINARY ckeyBin = ctx.serialize(xid);
		auto pclBin = ctx.mkPCL(xid);

		std::string configClass = "IPM.Configuration." + reqName.Name;
		std::vector<TAGGED_PROPVAL> props;
		props.push_back({PidTagMid, &messageId});
		props.push_back({PidTagChangeNumber, &changeNumber});
		props.push_back({PR_CHANGE_KEY, &ckeyBin});
		props.push_back({PR_PREDECESSOR_CHANGE_LIST, pclBin.get()});
		props.emplace_back(PR_ASSOCIATED, deconst(&byte_value_one));
		props.push_back({PR_MESSAGE_CLASS, deconst(configClass.c_str())});
		props.emplace_back(PR_READ, deconst(&byte_value_one));
		auto modtime = rop_util_current_nttime();
		props.push_back({PR_LAST_MODIFICATION_TIME, &modtime});

		auto& userConfiguration = request.UserConfiguration;
		if (userConfiguration.XmlData) {
			auto bin = EWSContext::construct<BINARY>(BINARY{
			           static_cast<uint32_t>(userConfiguration.XmlData->size()),
			           {EWSContext::alloc<char>(userConfiguration.XmlData->size())}});
			memcpy(bin->pc, userConfiguration.XmlData->data(), bin->cb);
			props.push_back({PR_ROAMING_XMLSTREAM, bin});
		}
		if (userConfiguration.BinaryData) {
			auto bin = EWSContext::construct<BINARY>(BINARY{
			           static_cast<uint32_t>(userConfiguration.BinaryData->size()),
			           {EWSContext::alloc<char>(userConfiguration.BinaryData->size())}});
			memcpy(bin->pc, userConfiguration.BinaryData->data(), bin->cb);
			props.push_back({PR_ROAMING_BINARYSTREAM, bin});
		}

		MESSAGE_CONTENT content{};
		content.proplist.count = props.size();
		content.proplist.ppropval = props.data();

		ec_error_t err;
		uint64_t outmid = 0, outcn = 0;
		if (!exmdb.write_message(dir.c_str(), CP_ACP,
		    folder.folderId, &content, {}, &outmid,
		    &outcn, &err) || err != ecSuccess)
			throw EWSError::ItemSave(E3415);

		mCreateUserConfigurationResponseMessage msg;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.clear();
		data.ResponseMessages.emplace_back(err);
	}
	data.serialize(response);
}

/**
 * @brief      Process GetUserConfigurationRequest
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUserConfigurationRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetUserConfigurationResponse");

	mGetUserConfigurationResponse data;
	try {
		auto &exmdb = ctx.plugin().exmdb;
		const auto &reqName = request.UserConfigurationName;
		const auto &folderId = reqName.FolderId;
		sFolderSpec folder;

		if (auto raw = std::get_if<tFolderId>(&folderId))
			folder = ctx.resolveFolder(*raw);
		else if (auto dist = std::get_if<tDistinguishedFolderId>(&folderId))
			folder = ctx.resolveFolder(*dist);
		else
			throw EWSError::InvalidFolderId(E3421);

		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			throw EWSError::AccessDenied(E3435);

		std::string configClass = "IPM.Configuration." + reqName.Name;
		RESTRICTION_PROPERTY resProp{RELOP_EQ, PR_MESSAGE_CLASS,
			{PR_MESSAGE_CLASS, const_cast<char *>(configClass.c_str())}};
		RESTRICTION res{RES_PROPERTY, {&resProp}};

		uint32_t tableId = 0, rowCount = 0;
		const char *username = ctx.effectiveUser(folder);
		if (!exmdb.load_content_table(dir.c_str(), CP_UTF8, folder.folderId, username,
		    TABLE_FLAG_ASSOCIATED, &res, nullptr, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3438);
		auto unloadTable = HX::make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
		if (rowCount == 0)
			throw EWSError::ItemNotFound(E3392);

		static constexpr proptag_t midTag = PidTagMid;
		TARRAY_SET rows;
		exmdb.query_table(dir.c_str(), username, CP_UTF8, tableId,
			{&midTag, 1}, 0, 1, &rows);
		if (rows.count == 0 || rows.pparray[0] == nullptr)
			throw EWSError::ItemNotFound(E3393);
		auto mid = rows.pparray[0]->get<const uint64_t>(PidTagMid);
		if (mid == nullptr)
			throw EWSError::ItemNotFound(E3394);

		static constexpr proptag_t propTags[] = {
			PR_ENTRYID, PR_CHANGE_KEY, PR_ROAMING_XMLSTREAM, PR_ROAMING_BINARYSTREAM,
		};
		const PROPTAG_ARRAY props = {std::size(propTags), deconst(propTags)};
		TPROPVAL_ARRAY propvals = ctx.getItemProps(dir, *mid, props);

		mGetUserConfigurationResponseMessage& msg = data.ResponseMessages.emplace_back();
		msg.UserConfiguration.emplace(reqName);
		auto &config = *msg.UserConfiguration;

		auto propType = request.UserConfigurationProperties;
		bool includeAll = propType == Enum::All;

		if (includeAll || propType == Enum::Id) {
			if (const auto *entryId = propvals.get<const BINARY>(PR_ENTRYID))
				config.ItemId.emplace(sBase64Binary(entryId), tBaseItemId::ID_ITEM);
			else
				throw EWSError::ItemPropertyRequestFailed(E3024);
			if (const auto *changeKey = propvals.get<const BINARY>(PR_CHANGE_KEY))
				config.ItemId->ChangeKey.emplace(sBase64Binary(changeKey));
		}

		// Dictionary support (PR_ROAMING_DICTIONARY) is not implemented yet
		if (includeAll || propType == Enum::XmlData) {
			if (const auto *xmlData = propvals.get<const BINARY>(PR_ROAMING_XMLSTREAM))
				config.XmlData.emplace(xmlData);
		}
		if (includeAll || propType == Enum::BinaryData) {
			if (const auto *binData = propvals.get<const BINARY>(PR_ROAMING_BINARYSTREAM))
				config.BinaryData.emplace(binData);
		}

		msg.success();
	} catch (const EWSError &err) {
		data.ResponseMessages.clear();
		data.ResponseMessages.emplace_back(err);
	}
	data.serialize(response);
}

/**
 * @brief      Process UpdateUserConfiguration
 *
 * Update XmlData and/or BinaryData properties on an existing
 * user configuration object (FAI message).
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mUpdateUserConfigurationRequest &&request, XMLElement *response,
    const EWSContext &ctx)
{
	response->SetName("m:UpdateUserConfigurationResponse");

	mUpdateUserConfigurationResponse data;
	try {
		auto &exmdb = ctx.plugin().exmdb;
		const auto &reqName  = request.UserConfiguration.UserConfigurationName;
		const auto &folderId = reqName.FolderId;
		sFolderSpec folder;

		if (auto raw = std::get_if<tFolderId>(&folderId))
			folder = ctx.resolveFolder(*raw);
		else if (auto dist = std::get_if<tDistinguishedFolderId>(&folderId))
			folder = ctx.resolveFolder(*dist);
		else
			throw EWSError::InvalidFolderId(E3422);

		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsEditAny))
			throw EWSError::AccessDenied(E3436);

		std::string configClass = "IPM.Configuration." + reqName.Name;
		const RESTRICTION_PROPERTY resProp =
			{RELOP_EQ, PR_MESSAGE_CLASS,
			 {PR_MESSAGE_CLASS, deconst(configClass.c_str())}};
		const RESTRICTION res = {RES_PROPERTY, {deconst(&resProp)}};

		uint32_t tableId = 0, rowCount = 0;
		const char *username = ctx.effectiveUser(folder);
		if (!exmdb.load_content_table(dir.c_str(), CP_UTF8,
		    folder.folderId, username, TABLE_FLAG_ASSOCIATED,
		    &res, nullptr, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3439);
		auto unloadTable = HX::make_scope_exit([&] { exmdb.unload_table(dir.c_str(), tableId); });
		if (rowCount == 0)
			throw EWSError::ItemNotFound(E3395);

		static constexpr proptag_t rowTags[] = {PidTagMid, PR_ENTRYID};
		TARRAY_SET rows;
		if (!exmdb.query_table(dir.c_str(), username, CP_UTF8,
		    tableId, {rowTags, std::size(rowTags)}, 0, 1, &rows))
			throw EWSError::ItemNotFound(E3396);
		if (rows.count == 0 || rows.pparray[0] == nullptr)
			throw EWSError::ItemNotFound(E3397);
		auto mid = rows.pparray[0]->get<const uint64_t>(PidTagMid);
		if (mid == nullptr)
			throw EWSError::ItemNotFound(E3398);
		auto entryId = rows.pparray[0]->find(PR_ENTRYID);
		if (entryId == nullptr)
			throw EWSError::ItemNotFound(E3613);

		sShape shape;
		auto& userConfiguration = request.UserConfiguration;
		if (userConfiguration.XmlData) {
			auto bin = EWSContext::construct<BINARY>(BINARY{
			           static_cast<uint32_t>(userConfiguration.XmlData->size()),
			           {EWSContext::alloc<char>(userConfiguration.XmlData->size())}});
			memcpy(bin->pc, userConfiguration.XmlData->data(), bin->cb);
			shape.write(TAGGED_PROPVAL{PR_ROAMING_XMLSTREAM, bin});
		}
		if (userConfiguration.BinaryData) {
			auto bin = EWSContext::construct<BINARY>(BINARY{
			           static_cast<uint32_t>(userConfiguration.BinaryData->size()),
			           {EWSContext::alloc<char>(userConfiguration.BinaryData->size())}});
			memcpy(bin->pc, userConfiguration.BinaryData->data(), bin->cb);
			shape.write(TAGGED_PROPVAL{PR_ROAMING_BINARYSTREAM, bin});
		}

		if (userConfiguration.XmlData || userConfiguration.BinaryData) {
			ctx.updated(dir, sMessageEntryId(*entryId), shape);
			const TPROPVAL_ARRAY propArray = shape.write();
			PROBLEM_ARRAY problems;
			if (!exmdb.set_message_properties(dir.c_str(),
			    username, CP_ACP, *mid, &propArray, &problems))
				throw EWSError::ItemSave(E3416);
		}

		mUpdateUserConfigurationResponseMessage msg;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.clear();
		data.ResponseMessages.emplace_back(err);
	}
	data.serialize(response);
}

/**
 * @brief      Process DeleteUserConfigurationRequest
 *
 * Delete a user configuration object (FAI message) from a folder.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mDeleteUserConfigurationRequest &&request,
    XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:DeleteUserConfigurationResponse");

	mDeleteUserConfigurationResponse data;
	try {
		auto &exmdb = ctx.plugin().exmdb;
		const auto &reqName  = request.UserConfigurationName;
		const auto &folderId = reqName.FolderId;
		sFolderSpec folder;

		if (auto raw = std::get_if<tFolderId>(&folderId))
			folder = ctx.resolveFolder(*raw);
		else if (auto dist = std::get_if<tDistinguishedFolderId>(&folderId))
			folder = ctx.resolveFolder(*dist);
		else
			throw EWSError::InvalidFolderId(E3423);

		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3437);

		std::string configClass = "IPM.Configuration." + reqName.Name;
		const RESTRICTION_PROPERTY resProp =
			{RELOP_EQ, PR_MESSAGE_CLASS,
			 {PR_MESSAGE_CLASS, deconst(configClass.c_str())}};
		const RESTRICTION res = {RES_PROPERTY, {deconst(&resProp)}};

		uint32_t tableId = 0, rowCount = 0;
		const char *username = ctx.effectiveUser(folder);
		if (!exmdb.load_content_table(dir.c_str(), CP_UTF8,
		    folder.folderId, username, TABLE_FLAG_ASSOCIATED,
		    &res, nullptr, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3440);
		auto unloadTable = HX::make_scope_exit([&] { exmdb.unload_table(dir.c_str(), tableId); });
		if (rowCount == 0)
			throw EWSError::ItemNotFound(E3399);

		static constexpr proptag_t midTag = PidTagMid;
		TARRAY_SET rows;
		if (!exmdb.query_table(dir.c_str(), username, CP_UTF8,
		    tableId, {&midTag, 1}, 0, 1, &rows))
			throw EWSError::ItemNotFound(E3400);
		if (rows.count == 0 || rows.pparray[0] == nullptr)
			throw EWSError::ItemNotFound(E3401);
		auto mid = rows.pparray[0]->get<const uint64_t>(PidTagMid);
		if (mid == nullptr)
			throw EWSError::ItemNotFound(E3402);

		eid_t eid = *mid;
		EID_ARRAY eids{1, &eid};
		BOOL partial;
		if (!exmdb.delete_messages(dir.c_str(), CP_ACP,
		    username, folder.folderId, eids, TRUE,
		    &partial) || partial)
			throw EWSError::CannotDeleteObject(E3447);

		mDeleteUserConfigurationResponseMessage msg;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.clear();
		data.ResponseMessages.emplace_back(err);
	}
	data.serialize(response);
}

/**
 * @brief      Process GetUserOofSettingsRequest
 *
 * Provides the functionality of GetUserOofSettingsRequest
 *
 * @todo       Check if error handling can be improved
 *             (using the response message instead of SOAP faults)
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUserOofSettingsRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	//Set name of the response node
	response->SetName("m:GetUserOofSettingsResponse");

	ctx.normalize(request.Mailbox);
	if (strcasecmp(request.Mailbox.Address.c_str(), ctx.auth_info().username)) {
		mGetUserOofSettingsResponse data;
		data.ResponseMessage = mResponseMessageType(EWSError::AccessDenied(E3011));
		data.serialize(response);
		return;
	}

	//Initialize response data structure
	mGetUserOofSettingsResponse data;
	data.OofSettings.emplace();

	//Get OOF state
	std::string maildir = ctx.get_maildir(request.Mailbox);
	static constexpr proptag_t oof_tags[] = {
		PR_EC_OUTOFOFFICE, PR_EC_ALLOW_EXTERNAL, PR_EC_EXTERNAL_AUDIENCE,
		PR_EC_OUTOFOFFICE_FROM, PR_EC_OUTOFOFFICE_UNTIL,
		PR_EC_OUTOFOFFICE_MSG, PR_EC_EXTERNAL_REPLY,
	};
	TPROPVAL_ARRAY props{};
	if (!ctx.plugin().exmdb.autoreply_getprop(maildir.c_str(), CP_UTF8,
	    {oof_tags, std::size(oof_tags)}, &props))
		throw DispatchError(E3011);
	auto oof_state = props.get<const uint32_t>(PR_EC_OUTOFOFFICE);
	switch (oof_state != nullptr ? *oof_state : 0) {
	case 1:
		data.OofSettings->OofState = "Enabled"; break;
	case 2:
		data.OofSettings->OofState = "Scheduled"; break;
	default:
		data.OofSettings->OofState = "Disabled"; break;
	}
	auto allow_ext = props.get<const uint8_t>(PR_EC_ALLOW_EXTERNAL);
	auto ext_audience = props.get<const uint8_t>(PR_EC_EXTERNAL_AUDIENCE);
	if (allow_ext != nullptr && *allow_ext)
		data.OofSettings->ExternalAudience = (ext_audience != nullptr && *ext_audience) ? "Known" : "All";
	else
		data.OofSettings->ExternalAudience = "None";
	auto start_time = props.get<const mapitime_t>(PR_EC_OUTOFOFFICE_FROM);
	auto end_time = props.get<const mapitime_t>(PR_EC_OUTOFOFFICE_UNTIL);
	if (start_time != nullptr && end_time != nullptr) {
		auto &Duration = data.OofSettings->Duration.emplace();
		Duration.StartTime = rop_util_nttime_to_unix2(*start_time);
		Duration.EndTime = rop_util_nttime_to_unix2(*end_time);
	} else {
		/*
		 * Even when OOF is inactive, some Outlooks crash when XML tags
		 * are missing.
		 */
		auto &dur = data.OofSettings->Duration.emplace();
		dur.StartTime = clock::now();
		dur.EndTime = dur.StartTime + std::chrono::days(1);
	}
	auto int_reply = props.get<const char>(PR_EC_OUTOFOFFICE_MSG);
	if (int_reply != nullptr)
		data.OofSettings->InternalReply.emplace(std::string(int_reply));
	else
		data.OofSettings->InternalReply.emplace(std::string{});
	auto ext_reply = props.get<const char>(PR_EC_EXTERNAL_REPLY);
	if (ext_reply != nullptr)
		data.OofSettings->ExternalReply.emplace(std::string(ext_reply));
	else
		data.OofSettings->ExternalReply.emplace(std::string{});

	//Finalize response
	data.ResponseMessage.success();
	data.serialize(response);
}

/**
 * @brief      Process GetUserAvailabilityRequest
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUserPhotoRequest &&request, XMLElement *response, EWSContext &ctx)
{
	response->SetName("m:GetUserPhotoResponse");

	mGetUserPhotoResponse data;
	const BINARY *photodata = nullptr;

	try {
		std::string dir = ctx.get_maildir(request.Email);
		PROPERTY_NAME photo = {MNID_STRING, PSETID_Gromox, 0, deconst("photo")};
		PROPNAME_ARRAY propNames{1, &photo};
		PROPID_ARRAY propIds = ctx.getNamedPropIds(dir, propNames);
		if (propIds.size() != 1)
			throw std::runtime_error("failed to get photo property id");
		const proptag_t tag = PROP_TAG(PT_BINARY, propIds[0]);
		TPROPVAL_ARRAY props;
		ctx.plugin().exmdb.get_store_properties(dir.c_str(), CP_ACP, {&tag, 1}, &props);
		photodata = props.get<const BINARY>(tag);
	} catch (const std::exception &err) {
		mlog(LV_WARN, "[ews#%d] Failed to load organizational user photo: %s", ctx.context_id(), err.what());
	}

	if (photodata == nullptr || photodata->cb == 0) {
		/*
		 * Not a local mailbox user (or one without an org photo set) -
		 * fall back to the requesting user's own saved contact for this
		 * address, if any (see EWSContext::findContactPhoto).
		 */
		try {
			std::string ownDir = ctx.get_maildir(ctx.auth_info().username);
			photodata = ctx.findContactPhoto(ownDir, request.Email);
		} catch (const std::exception &err) {
			mlog(LV_WARN, "[ews#%d] Failed to load contact photo: %s", ctx.context_id(), err.what());
		}
	}

	if (photodata && photodata->cb)
		data.PictureData = photodata;
	else
		ctx.code(http_status::not_found);
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process CopyFolder or MoveFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(const mBaseMoveCopyFolder &request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName(request.copy ? "m:CopyFolderResponse" : "m:MoveFolderResponse");

	sFolderSpec dstFolder = ctx.resolveFolder(request.ToFolderId.FolderId);
	std::string dir = ctx.getDir(dstFolder);
	uint32_t accountId = ctx.getAccountId(ctx.auth_info().username, false);

	bool dstAccess = ctx.permissions(dir, dstFolder.folderId);

	using MCResponse = std::variant<mCopyFolderResponse, mMoveFolderResponse>;
	auto data = request.copy ? MCResponse(std::in_place_index_t<0>{}) :
	            MCResponse(std::in_place_index_t<1>{});
	std::visit([&](auto& d){d.ResponseMessages.reserve(request.FolderIds.size());}, data);

	sShape shape = sShape(tFolderResponseShape());

	for (const tFolderId &folderId : request.FolderIds) try {
		if (!dstAccess)
			throw EWSError::AccessDenied(E3167);
		sFolderSpec folder = ctx.resolveFolder(folderId);
		if (folder.location != dstFolder.location)
			/* Attempt to move to a different store */
			throw EWSError::CrossMailboxMoveCopy(E3168);
		folder.folderId = ctx.moveCopyFolder(dir, folder, dstFolder.folderId, accountId, request.copy);
		auto& msg = std::visit([&](auto& d) -> mFolderInfoResponseMessage&
			                    {return static_cast<mFolderInfoResponseMessage&>(d.ResponseMessages.emplace_back());}, data);
		msg.Folders.emplace_back(ctx.loadFolder(dir, folder.folderId, shape));
		msg.success();
	} catch (const EWSError &err) {
		std::visit([&](auto& d){d.ResponseMessages.emplace_back(err);}, data);
	}

	std::visit([&](auto& d){d.serialize(response);}, data);
}

/**
 * @brief      Process CopyItem or MoveItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(const mBaseMoveCopyItem &request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName(request.copy ? "m:CopyItemResponse" : "m:MoveItemResponse");

	sFolderSpec dstFolder = ctx.resolveFolder(request.ToFolderId.FolderId);
	std::string dir = ctx.getDir(dstFolder);

	bool dstAccess = ctx.permissions(dir, dstFolder.folderId);

	using MCResponse = std::variant<mCopyItemResponse, mMoveItemResponse>;
	auto data = request.copy ? MCResponse(std::in_place_index_t<0>{}) :
	            MCResponse(std::in_place_index_t<1>{});
	std::visit([&](auto& d){d.ResponseMessages.reserve(request.ItemIds.size());}, data);

	sShape shape = sShape(tItemResponseShape());

	for (const auto &id : request.ItemIds) try {
		tItemId itemId = id.itemId();
		if (!dstAccess)
			throw EWSError::AccessDenied(E3184);
		if (id.isOccurrence())
			throw EWSError::CalendarCannotMoveOrCopyOccurrence(E3480);
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec sourceFolder = ctx.resolveFolder(meid);
		if (sourceFolder.target != dstFolder.target)
			throw EWSError::CrossMailboxMoveCopy(E3186);
		ctx.validate(dir, meid);
		auto rights = ctx.permissions(dir, sourceFolder.folderId);
		if (!(rights & frightsReadAny))
			throw EWSError::AccessDenied(E3185);
		ctx.assertCanReadPrivate(dir, sourceFolder, rights, meid.messageId());
		uint64_t newItemId = ctx.moveCopyItem(dir, meid, dstFolder.folderId, request.copy);
		auto& msg = std::visit([&](auto& d) -> mItemInfoResponseMessage&
			                   {return static_cast<mItemInfoResponseMessage&>(d.ResponseMessages.emplace_back());}, data);
		if (request.ReturnNewItemIds.value_or(true))
			msg.Items.emplace_back(ctx.loadItem(dir, dstFolder.folderId, newItemId, shape));
		msg.success();
	} catch (const EWSError &err) {
		std::visit([&](auto& d){d.ResponseMessages.emplace_back(err);}, data);
	}

	std::visit([&](auto& d){d.serialize(response);}, data);
}

/**
 * @brief      Process MarkAsJunk
 *
 * Moves item(s) to or from the Junk Email folder (IsJunk selects the
 * direction, MoveItem gates whether anything is actually moved).
 *
 * The blocked/safe sender list update that real Exchange performs as
 * part of this operation is not implemented - gromox currently has no
 * data model for such a list, so this only covers the move semantics.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mMarkAsJunkRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:MarkAsJunkResponse");

	mMarkAsJunkResponse data;
	data.ResponseMessages.reserve(request.ItemIds.size());

	for (const auto &id : request.ItemIds) try {
		tItemId itemId = id.itemId();
		if (id.isOccurrence())
			throw EWSError::InvalidId(E3481);
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec sourceFolder = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(sourceFolder);
		ctx.validate(dir, meid);
		auto rights = ctx.permissions(dir, sourceFolder.folderId);
		if (!(rights & frightsReadAny))
			throw EWSError::AccessDenied(E3472);
		ctx.assertCanReadPrivate(dir, sourceFolder, rights, meid.messageId());

		auto &msg = data.ResponseMessages.emplace_back();
		if (request.MoveItem) {
			sFolderSpec dstFolder = ctx.resolveFolder(tDistinguishedFolderId(
				request.IsJunk ? Enum::junkemail : Enum::inbox));
			dstFolder.target = sourceFolder.target;
			dstFolder.normalize();
			std::string dstDir = ctx.getDir(dstFolder);
			if (!(ctx.permissions(dstDir, dstFolder.folderId) & frightsCreate))
				throw EWSError::AccessDenied(E3473);
			uint64_t newItemId = ctx.moveCopyItem(dir, meid, dstFolder.folderId, false);
			sShape idShape{tItemResponseShape()};
			sItem movedItem = ctx.loadItem(dstDir, dstFolder.folderId, newItemId, idShape);
			msg.MovedItemId = std::visit([](auto &&i) STATIC_IN_CXX23 -> std::optional<tItemId> { return i.ItemId; }, movedItem);
		}
		msg.success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process SetUserOofSettingsRequest
 *
 * Provides functionality of SetUserOofSettingsRequest
 *
 * @todo       Check if error handling can be improved
 *             (using the response message instead of SOAP faults)
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSetUserOofSettingsRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:SetUserOofSettingsResponse");

	ctx.normalize(request.Mailbox);
	if (strcasecmp(request.Mailbox.Address.c_str(), ctx.auth_info().username)) {
		mGetUserOofSettingsResponse data;
		data.ResponseMessage = mResponseMessageType(EWSError::AccessDenied(E3012));
		data.serialize(response);
		return;
	}
	std::string maildir = ctx.get_maildir(request.Mailbox);

	tUserOofSettings& OofSettings = request.UserOofSettings;

	uint32_t oof_state = OofSettings.OofState;
	std::string externalAudience = OofSettings.ExternalAudience;
	uint8_t allow_external_oof = tolower_inplace(externalAudience) != "none";
	//Note: counterintuitive but intentional: known -> 1, all -> 0
	uint8_t external_audience = externalAudience == "known";
	if (allow_external_oof && !external_audience && externalAudience != "all")
		throw DispatchError(E3009(OofSettings.ExternalAudience));

	std::vector<TAGGED_PROPVAL> pvs;
	pvs.push_back(TAGGED_PROPVAL{PR_EC_OUTOFOFFICE, &oof_state});
	pvs.push_back(TAGGED_PROPVAL{PR_EC_ALLOW_EXTERNAL, &allow_external_oof});
	pvs.push_back(TAGGED_PROPVAL{PR_EC_EXTERNAL_AUDIENCE, &external_audience});
	mapitime_t nt_start{}, nt_end{};
	if (OofSettings.Duration) {
		nt_start = rop_util_unix_to_nttime(OofSettings.Duration->StartTime);
		nt_end = rop_util_unix_to_nttime(OofSettings.Duration->EndTime);
		pvs.push_back(TAGGED_PROPVAL{PR_EC_OUTOFOFFICE_FROM, &nt_start});
		pvs.push_back(TAGGED_PROPVAL{PR_EC_OUTOFOFFICE_UNTIL, &nt_end});
	}
	std::string int_msg, ext_msg;
	if (OofSettings.InternalReply && OofSettings.InternalReply->Message)
		int_msg = *OofSettings.InternalReply->Message;
	pvs.push_back(TAGGED_PROPVAL{PR_EC_OUTOFOFFICE_MSG, deconst(int_msg.c_str())});
	if (OofSettings.ExternalReply && OofSettings.ExternalReply->Message)
		ext_msg = *OofSettings.ExternalReply->Message;
	pvs.push_back(TAGGED_PROPVAL{PR_EC_EXTERNAL_REPLY, deconst(ext_msg.c_str())});
	/*
	 * Exchange has no OOF reply subject, its replies are titled
	 * "Automatic reply: <subject>". Drop one a non-EWS client stored.
	 */
	pvs.push_back(TAGGED_PROPVAL{PR_EC_OUTOFOFFICE_SUBJECT, deconst("")});
	pvs.push_back(TAGGED_PROPVAL{PR_EC_EXTERNAL_SUBJECT, deconst("")});
	TPROPVAL_ARRAY vals = {static_cast<uint16_t>(pvs.size()), pvs.data()};
	PROBLEM_ARRAY problems{};
	if (!ctx.plugin().exmdb.autoreply_setprop(maildir.c_str(), CP_UTF8,
	    &vals, &problems))
		throw DispatchError(E3012);

	mSetUserOofSettingsResponse data;
	data.ResponseMessage.success();
	data.serialize(response);
}

/**
 * @brief      Process SyncFolderHierachy
 *
 * Return folder updates and hierarchy sync information
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSyncFolderHierarchyRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:SyncFolderHierarchyResponse");

	auto& exmdb = ctx.plugin().exmdb;
	if (!request.SyncFolderId)
		request.SyncFolderId.emplace(tDistinguishedFolderId(Enum::msgfolderroot));

	sSyncState syncState;
	if (request.SyncState && !request.SyncState->empty())
		syncState.init(*request.SyncState);
	syncState.convert();

	sFolderSpec folder = ctx.resolveFolder(request.SyncFolderId->FolderId);
	if (!folder.target)
		folder.target = ctx.auth_info().username;
	std::string dir = ctx.getDir(folder.normalize());

	mSyncFolderHierarchyResponse data;
	if (!(ctx.permissions(dir, folder.folderId) & frightsVisible)) {
		data.ResponseMessages.emplace_back(EWSError::AccessDenied(E3137));
		data.serialize(response);
		return;
	}

	FOLDER_CHANGES changes;
	uint64_t lastCn;
	EID_ARRAY given_fids, deleted_fids;
	if (!exmdb.get_hierarchy_sync(dir.c_str(), folder.folderId, ctx.effectiveUser(folder),
	                             &syncState.given, &syncState.seen, &changes, &lastCn, &given_fids, &deleted_fids))
		throw DispatchError(E3030);

	sShape shape(request.FolderShape);

	mSyncFolderHierarchyResponseMessage& msg = data.ResponseMessages.emplace_back();
	auto& msgChanges = msg.Changes.emplace();
	msgChanges.reserve(changes.count + deleted_fids.count);
	for (const auto &folderProps : changes) {
		auto folderId = folderProps.get<uint64_t>(PidTagFolderId);
		if (!folderId)
			continue;
		folder.folderId = *folderId;
		if (!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			continue;
		auto folderData = ctx.loadFolder(dir, folder.folderId, shape);
		if (syncState.given.contains(*folderId))
			msgChanges.emplace_back(tSyncFolderHierarchyUpdate(std::move(folderData)));
		else
			msgChanges.emplace_back(tSyncFolderHierarchyCreate(std::move(folderData)));
	}
	for (auto fid : deleted_fids)
		msgChanges.emplace_back(tSyncFolderHierarchyDelete(ctx.getFolderEntryId(dir, fid)));

	syncState.update(given_fids, deleted_fids, lastCn);
	msg.SyncState = syncState.serialize();
	msg.IncludesLastFolderInRange = true;
	msg.success();

	data.serialize(response);
}

/**
 * @brief      Process SyncFolderItems
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSyncFolderItemsRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:SyncFolderItemsResponse");

	sFolderSpec folder = ctx.resolveFolder(request.SyncFolderId.FolderId);

	sSyncState syncState;
	if (request.SyncState && !request.SyncState->empty())
		syncState.init(*request.SyncState);
	syncState.convert();

	if (!folder.target)
		folder.target = ctx.auth_info().username;
	std::string dir = ctx.getDir(folder.normalize());

	mSyncFolderItemsResponse data;
	auto rights = itemRights(ctx, dir, folder.folderId);
	if (!(rights & itemReadRights)) {
		data.ResponseMessages.emplace_back(EWSError::AccessDenied(E3138));
		data.serialize(response);
		return;
	}
	auto& exmdb = ctx.plugin().exmdb;

	uint32_t fai_count, normal_count;
	uint64_t fai_total, normal_total, last_cn, last_readcn;
	EID_ARRAY updated_mids, chg_mids, given_mids, deleted_mids, nolonger_mids, read_mids, unread_mids;
	bool getFai = request.SyncScope && *request.SyncScope == Enum::NormalAndAssociatedItems;
	auto pseen_fai = getFai ? &syncState.seen_fai : nullptr;
	if (!exmdb.get_content_sync(dir.c_str(), folder.folderId, ctx.effectiveUser(folder),
	    &syncState.given, &syncState.seen, pseen_fai, &syncState.read,
	    CP_ACP, nullptr, TRUE, &fai_count, &fai_total, &normal_count,
	    &normal_total, &updated_mids, &chg_mids, &last_cn, &given_mids,
	    &deleted_mids, &nolonger_mids, &read_mids, &unread_mids,
	    &last_readcn))
		throw DispatchError(E3031);

	sShape shape(request.ItemShape);
	shape.special &= ~sShape::AssociatedCalendarItemId;
	ctx.restrictShape(dir, folder, rights, shape);
	sMailboxInfo mbinfo = ctx.getMailboxInfo(dir, folder.location == folder.PUBLIC);
	// Generate message entry IDs on the fly as we have all necessary information
	// Use template entry ID and fill in the message Id as needed
	sMessageEntryId templId = ctx.plugin().mkMessageEntryId(mbinfo, folder.folderId, eid_t(1, 0));

	uint32_t maxItems = request.MaxChangesReturned;
	uint32_t maxSync = ctx.plugin().max_sync_changes;
	if (maxSync != 0 && maxItems > maxSync)
		maxItems = maxSync;
	bool clipped = false;

	try {
		mSyncFolderItemsResponseMessage msg;
		msg.Changes.reserve(std::min(chg_mids.count + deleted_mids.count + read_mids.count + unread_mids.count, maxItems));
		maxItems -= deleted_mids.count = std::min(deleted_mids.count, maxItems);
		for (auto mid : deleted_mids) {
			msg.Changes.emplace_back(tSyncFolderItemsDelete(templId.messageId(mid).serialize()));
			syncState.given.remove(mid);
		}
		clipped = clipped || nolonger_mids.count > maxItems;
		maxItems -= nolonger_mids.count = std::min(nolonger_mids.count, maxItems);
		for (auto mid : nolonger_mids) {
			msg.Changes.emplace_back(tSyncFolderItemsDelete(templId.messageId(mid).serialize()));
			syncState.given.remove(mid);
		}
		clipped = clipped || chg_mids.count > maxItems;
		maxItems -= chg_mids.count = std::min(chg_mids.count, maxItems);
		for (auto mid : chg_mids) {
			auto changeNum = ctx.getItemProp<const uint64_t>(dir, mid, PidTagChangeNumber);
			if (!changeNum)
				continue;
			try {
				if (ct_contains(updated_mids, mid))
					msg.Changes.emplace_back(tSyncFolderItemsUpdate{{{}, ctx.loadItem(dir, folder.folderId, mid, shape)}});
				else
					msg.Changes.emplace_back(tSyncFolderItemsCreate{{{}, ctx.loadItem(dir, folder.folderId, mid, shape)}});
			} catch (const std::exception &e) {
				mlog(LV_WARN, "[ews] skipping mid %llxh in sync: %s",
					static_cast<unsigned long long>(mid), e.what());
			}
			if (!syncState.given.append(mid) || !syncState.seen.append(*changeNum))
				throw DispatchError(E3065);
		}
		uint32_t readSynced = syncState.readOffset;
		uint32_t skip = std::min(syncState.readOffset, read_mids.count);
		read_mids.count = std::min(read_mids.count - skip, maxItems) + skip;
		maxItems -= read_mids.count - skip;
		clipped = clipped || read_mids.count - skip > maxItems;
		for (auto mid : read_mids)
			msg.Changes.emplace_back(tSyncFolderItemsReadFlag{{}, tItemId(templId.messageId(mid).serialize()), true});
		readSynced += read_mids.count - skip;
		skip = std::min(unread_mids.count, syncState.readOffset - read_mids.count + skip);
		unread_mids.count = std::min(unread_mids.count - skip, maxItems) + skip;
		clipped = clipped || unread_mids.count - skip > maxItems;
		for (auto mid : unread_mids)
			msg.Changes.emplace_back(tSyncFolderItemsReadFlag{{}, tItemId(templId.messageId(mid).serialize()), false});
		if (!clipped) {
			syncState.seen.clear();
			syncState.seen_fai.clear();
			syncState.read.clear();
			if (last_cn) {
				auto gc = eid_t(last_cn).gcv();
				if (!syncState.seen.append_range(1, 1, gc) ||
				    (getFai && !syncState.seen_fai.append_range(1, 1, gc)))
					throw DispatchError(E3066);
			}
			if (last_readcn && !syncState.read.append_range(1, 1, eid_t(last_readcn).gcv()))
				throw DispatchError(E3448);
			syncState.readOffset = 0;
		} else {
			syncState.readOffset = readSynced + unread_mids.count - skip;
		}
		msg.SyncState = syncState.serialize();
		msg.IncludesLastItemInRange = !clipped;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}
	data.serialize(response);
}

/**
 * @brief      Process GetItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 *
 * @todo optimize shape generation
 */
void process(mGetItemRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:GetItemResponse");

	mGetItemResponse data;
	data.ResponseMessages.reserve(request.ItemIds.size());
	sShape shape(request.ItemShape);
	shape.add(PR_SUBJECT);
	/* Like Exchange, unlike FindItem */
	if (request.ItemShape.BaseShape.index() >= 1)
		shape.special |= sShape::Attendees;
	auto actor = get_auth_info(ctx.context_id()).username;
	uint32_t max_get = ctx.plugin().max_get_items, gotten = 0;

	for (const auto &id : request.ItemIds) try {
		if (max_get != 0 && gotten++ >= max_get)
			throw EWSError::ServerBusy(E3453);

		tItemId itemId = id.itemId();
		sMessageEntryId eid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(eid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, eid);
		auto rights = itemRights(ctx, dir, parentFolder.folderId);
		if (!(rights & itemReadRights))
			throw EWSError::AccessDenied(E3139);
		ctx.restrictShape(dir, parentFolder, rights, shape);
		mGetItemResponseMessage msg;
		auto mid = eid.messageId();
		if (id.holds_alternative<tOccurrenceItemId>()) {
			const tOccurrenceItemId& occurrenceId = std::get<tOccurrenceItemId>(id.asVariant());
			auto basedate = ctx.resolveOccurrenceIndex(dir, mid, occurrenceId.InstanceIndex);
			msg.Items.emplace_back(ctx.loadOccurrence(dir, parentFolder.folderId, mid, basedate, shape));
		} else if (itemId.type == tItemId::ID_OCCURRENCE) {
			sOccurrenceId oid(itemId.Id.data(), itemId.Id.size());
			msg.Items.emplace_back(ctx.loadOccurrence(dir, parentFolder.folderId, mid, oid.basedate, shape));
		} else {
			msg.Items.emplace_back(ctx.loadItem(dir, parentFolder.folderId, mid, shape));
		}
		if (shape.specials() & sShape::Conflicts && parentFolder.location == sFolderSpec::PRIVATE)
			std::visit([&](auto &item) {
				if constexpr (std::is_base_of_v<sCalendarMeetingRequestCommon, std::decay_t<decltype(item)>>) {
					auto s = shape.get<uint64_t>(NtCommonStart, sShape::FL_ANY);
					auto e = shape.get<uint64_t>(NtCommonEnd, sShape::FL_ANY);
					time_t start = item.Start ? clock::to_time_t(item.Start->time) :
					               s != nullptr ? rop_util_nttime_to_unix(*s) : 0;
					time_t end = item.End ? clock::to_time_t(item.End->time) :
					             e != nullptr ? rop_util_nttime_to_unix(*e) : 0;
					if (start == 0 || end == 0)
						return;
					item.loadConflicts(dir == ctx.auth_info().maildir ? nullptr :
						ctx.auth_info().username, dir.c_str(),
						ctx.plugin().x500_org_name.c_str(),
						shape.get<BINARY>(NtCleanGlobalObjectId, sShape::FL_ANY), start, end);
					if (item.ConflictingMeetings)
						ctx.conflictItemIds(parentFolder, dir, *item.ConflictingMeetings);
					if (item.AdjacentMeetings)
						ctx.conflictItemIds(parentFolder, dir, *item.AdjacentMeetings);
				}
			}, msg.Items.back());

		auto subject = shape.get<const char>(PR_SUBJECT, sShape::FL_ANY);
		std::string mailbox = "public folders";
		if (parentFolder.location == sFolderSpec::PRIVATE)
			mailbox = "mailbox " + *parentFolder.target;

		mlog(LV_INFO, "ews-audit: %s accessed message \"%s\" in %s",
			znul(actor), txt2cstr(subject).c_str(), mailbox.c_str());

		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	} catch (const std::exception &) {
		data.ResponseMessages.emplace_back(EWSError::ItemCorrupt(E3303));
	}

	data.serialize(response);
}

/**
 * @brief      Process ResolveNames
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 *
 * @todo consider attributes
 * @todo support contacts
 */
void process(mResolveNamesRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:ResolveNamesResponse");

	mResolveNamesResponse data;

	const char *unres = strchr(request.UnresolvedEntry.c_str(), ':'); /* CONST-STRCHR-MARKER */
	unres = unres ? unres + 1 : request.UnresolvedEntry.c_str();
	request.UnresolvedEntry = gx_utf8_to_punycode(unres);

	/* Try partial matching via address book tree first */
	const char *user = znul(ctx.auth_info().username);
	const char *at = strchr(user, '@');
	std::string domain = at ? at + 1 : user;

	std::vector<ab_tree::minid> results;
	uint32_t domId = ctx.getAccountId(domain, true);
	auto base = ab_tree::AB.get(-static_cast<int32_t>(domId));
	if (base)
		ab_tree_resolvename(*base, request.UnresolvedEntry.c_str(), results);
	if (base && results.size() > 0) {
		auto &msg = data.ResponseMessages.emplace_back();
		auto &resolutionSet = msg.ResolutionSet.emplace();
		for (auto mid : results) {
			ab_tree::ab_node node(base.get(), mid);
			auto email = node.user_info(ab_tree::userinfo::mail_address);
			if (email == nullptr || *email == '\0')
				continue;
			auto &resol = resolutionSet.Resolution.emplace_back();
			resol.Mailbox.EmailAddress = email;
			resol.Mailbox.Name = node.displayname();
			resol.Mailbox.RoutingType = "SMTP";
			resol.Mailbox.MailboxType = Enum::Mailbox;
			TPROPVAL_ARRAY userProps{};
			if (mysql_adaptor_get_user_properties(email, userProps) &&
			    userProps.count != 0) {
				resol.Contact.emplace(sShape(userProps));
				tpropval_array_free_internal(&userProps);
			}
		}
		if (resolutionSet.Resolution.empty()) {
			/*
			 * All ab_tree results lacked SMTP addresses, fall
			 * through to exact match.
			 */
			data.ResponseMessages.pop_back();
		} else {
			resolutionSet.TotalItemsInView = resolutionSet.Resolution.size();
			resolutionSet.IncludesLastItemInRange = true;
			if (resolutionSet.Resolution.size() > 1)
				msg.warning("ErrorNameResolutionMultipleResults",
					"Multiple results were found.");
			else
				msg.success();
			data.serialize(response);
			return;
		}
	}

	/* Fall back to exact match */
	TPROPVAL_ARRAY userProps{};
	if (!mysql_adaptor_get_user_properties(request.UnresolvedEntry.c_str(), userProps))
		throw DispatchError(E3067);
	if (!userProps.count) {
		data.ResponseMessages.emplace_back(EWSError::NameResolutionNoResults(E3259));
		data.serialize(response);
		return;
	}
	TAGGED_PROPVAL* displayName = userProps.find(PR_DISPLAY_NAME);

	mResolveNamesResponseMessage& msg = data.ResponseMessages.emplace_back();
	auto& resolutionSet = msg.ResolutionSet.emplace();
	tResolution& resol = resolutionSet.Resolution.emplace_back();
	resol.Mailbox.Name = displayName ? static_cast<const char *>(displayName->pvalue) : request.UnresolvedEntry;
	resol.Mailbox.EmailAddress = request.UnresolvedEntry;
	resol.Mailbox.RoutingType = "SMTP";
	resol.Mailbox.MailboxType = Enum::Mailbox;

	tContact& cnt = resol.Contact.emplace(sShape(userProps));
	tpropval_array_free_internal(&userProps);

	resolutionSet.TotalItemsInView = resolutionSet.Resolution.size();
	resolutionSet.IncludesLastItemInRange = true;

	std::vector<std::string> aliases;
	if (!mysql_adaptor_get_user_aliases(request.UnresolvedEntry.c_str(), aliases))
		throw DispatchError(E3068);
	if (aliases.size() > 0) {
		aliases.resize(std::min(aliases.size(), static_cast<size_t>(3)));
		cnt.EmailAddresses.emplace().reserve(aliases.size());
		uint8_t index = 0;
		for (auto &alias : aliases)
			cnt.EmailAddresses->emplace_back(tEmailAddressDictionaryEntry(std::move(alias),
			                                                              Enum::EmailAddressKeyType(index++)));
	}

	msg.success();

	data.serialize(response);
}

/**
 * @brief      Process ExpandDL
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mExpandDLRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:ExpandDLResponse");

	mExpandDLResponse data;
	mExpandDLResponseMessage &msg = data.ResponseMessages.emplace_back();

	ctx.normalize(request.Mailbox);
	if (!request.Mailbox.EmailAddress.has_value() ||
	    request.Mailbox.EmailAddress->empty()) {
		msg = mExpandDLResponseMessage(EWSError::NameResolutionNoResults(E3310));
		data.serialize(response);
		return;
	}

	const auto &address = *request.Mailbox.EmailAddress;
	std::vector<std::string> member_list;
	int result = 0;
	if (!mysql_adaptor_get_mlist_memb(address.c_str(), address.c_str(),
	    &result, member_list) || result != 0) {
		msg = mExpandDLResponseMessage(EWSError::NameResolutionNoResults(E3311));
		data.serialize(response);
		return;
	}

	auto &dlexp = msg.DLExpansion.emplace();
	auto domain = extract_domain(ctx.auth_info().username);
	uint32_t domId = 0;
	ab_tree::ab::const_base_ref base;
	if (!domain.empty()) {
		domId = ctx.getAccountId(domain, true);
		base  = ab_tree::AB.get(-static_cast<int32_t>(domId));
	}

	for (const auto &member : member_list) {
		auto &mbx = dlexp.Mailbox.emplace_back();
		mbx.EmailAddress = member;
		mbx.RoutingType  = "SMTP";

		unsigned int user_id = 0, domain_id = 0;
		enum display_type dt = DT_MAILUSER;
		if (base && mysql_adaptor_get_user_ids(member.c_str(),
		    &user_id, &domain_id, &dt)) {
			ab_tree::minid mid(ab_tree::minid::address, user_id);
			ab_tree::ab_node node(base, mid);
			if (node.valid()) {
				mbx.Name = node.displayname();
				mbx.MailboxType = node.type() == ab_tree::abnode_type::mlist ?
				                  Enum::MailboxTypeType(Enum::PublicDL) :
				                  Enum::MailboxTypeType(Enum::Mailbox);
				continue;
			}
		}
		mbx.Name = member;
		mbx.MailboxType = dt == DT_DISTLIST ?
		                  Enum::MailboxTypeType(Enum::PublicDL) :
		                  Enum::MailboxTypeType(Enum::Mailbox);
	}

	dlexp.TotalItemsInView = dlexp.Mailbox.size();
	dlexp.IncludesLastItemInRange = true;
	msg.success();
	data.serialize(response);
}

/**
 * @brief      Process SendItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSendItemRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:SendItemResponse");

	mSendItemResponse data;

	// Specified as explicit error in the documentation
	if (!request.SaveItemToFolder && request.SavedItemFolderId) {
		data.ResponseMessages.emplace_back(EWSError::InvalidSendItemSaveSettings(E3140));
		data.serialize(response);
		return;
	}
	sFolderSpec saveFolder = request.SavedItemFolderId ?
		ctx.resolveFolder(request.SavedItemFolderId->FolderId) :
		sFolderSpec(tDistinguishedFolderId(Enum::sentitems));
	if (request.SavedItemFolderId && !(ctx.permissions(ctx.getDir(saveFolder), saveFolder.folderId) & frightsCreate)) {
		data.ResponseMessages.emplace_back(EWSError::AccessDenied(E3141));
		data.serialize(response);
		return;
	}

	data.ResponseMessages.reserve(request.ItemIds.size());
	for (const auto &id: request.ItemIds) try {
		tItemId itemId = id.itemId();
		if (id.isOccurrence())
			throw EWSError::InvalidId(E3482);
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec folder = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(folder);
		auto rights = ctx.permissions(dir, folder.folderId);
		if (!(rights & frightsReadAny))
			throw EWSError::AccessDenied(E3142);
		ctx.assertCanReadPrivate(dir, folder, rights, meid.messageId());

		MESSAGE_CONTENT *rdcontent = nullptr;
		if (!ctx.plugin().exmdb.read_message(dir.c_str(),
		    ctx.effectiveUser(folder), CP_ACP, meid.messageId(),
		    &rdcontent) || rdcontent == nullptr)
			throw EWSError::ItemNotFound(E3403);
		/* read_message memory is ndr_stack backed, so dup() before editing */
		message_content_ptr content(rdcontent->dup());
		if (content == nullptr)
			throw EWSError::NotEnoughMemory(E3532);
		ctx.stampSubmitIdentity(dir, *content);
		ctx.validate_sendas_perms(*content);
		uint64_t saveFid = 0;
		if (request.SavedItemFolderId) {
			if (saveFolder.target != folder.target)
				throw EWSError::CrossMailboxMoveCopy(E3496);
			saveFid = saveFolder.folderId;
		} else if (folder.location == sFolderSpec::PRIVATE) {
			saveFid = eid_t(1, PRIVATE_FID_SENT_ITEMS);
		}
		ctx.send(dir, meid.messageId().gcv(), *content);

		/* Exchange moves the sent item to the save folder or drops it */
		auto username = ctx.effectiveUser(folder);
		if (!request.SaveItemToFolder) {
			auto eid = meid.messageId();
			EID_ARRAY eids{1, &eid};
			BOOL partial = false;
			if (!ctx.plugin().exmdb.delete_messages(dir.c_str(),
			    CP_ACP, username, folder.folderId, eids, false,
			    &partial) || partial)
				throw EWSError::CannotDeleteObject(E3497);
		} else {
			auto flags = content->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
			uint32_t newFlags = (flags != nullptr ? *flags : 0) &
			                    ~(MSGFLAG_SUBMITTED | MSGFLAG_UNSENT);
			const TAGGED_PROPVAL sprops[] = {
				{PR_MESSAGE_FLAGS, &newFlags},
				{PR_READ, deconst(&byte_value_one)},
			};
			const TPROPVAL_ARRAY proplist = {std::size(sprops), deconst(sprops)};
			/* The copy made by the move gets a change number of its own */
			bool move = saveFid != 0 && saveFid != folder.folderId;
			PROBLEM_ARRAY problems;
			bool ok = move ?
			          ctx.plugin().exmdb.set_message_properties(dir.c_str(),
			          username, CP_ACP, meid.messageId(), &proplist, &problems) :
			          ctx.setItemProps(dir, username, meid.messageId(), proplist);
			if (!ok)
				throw EWSError::ItemSave(E3498);
			if (move)
				ctx.moveCopyItem(dir, meid, saveFid, false);
		}

		data.ResponseMessages.emplace_back().success();
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process UpdateFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mUpdateFolderRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:UpdateFolderResponse");

	mUpdateFolderResponse data;
	data.ResponseMessages.reserve(request.FolderChanges.size());
	sShape idOnly((tFolderResponseShape()));
	idOnly.add(PR_DISPLAY_NAME);

	auto actor = get_auth_info(ctx.context_id()).username;

	for (const auto &change : request.FolderChanges) try {
		sFolderSpec folder = ctx.resolveFolder(change.folderId);
		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsEditAny))
			throw EWSError::AccessDenied(E3174);
		sShape shape(change);
		ctx.getNamedTags(dir, shape, true);
		for (const auto &update : change.Updates)
			if (std::holds_alternative<tSetFolderField>(update))
				std::get<tSetFolderField>(update).put(shape);
		bool permission_change = shape.permissionSet != nullptr || shape.calendarPermissionSet != nullptr;
		TPROPVAL_ARRAY props = shape.write();
		PROPTAG_ARRAY tagsRm = shape.remove();
		PROBLEM_ARRAY problems;
		if (!ctx.plugin().exmdb.set_folder_properties(dir.c_str(), CP_ACP,
		    folder.folderId, &props, &problems))
			throw EWSError::FolderSave(E3175);
		if (!ctx.plugin().exmdb.remove_folder_properties(dir.c_str(),
		    folder.folderId, tagsRm))
			throw EWSError::FolderSave(E3176);
		if (shape.permissionSet)
			ctx.writePermissions(dir, folder.folderId, tPermissionSet(shape.permissionSet).write());
		else if (shape.calendarPermissionSet)
			ctx.writePermissions(dir, folder.folderId, tCalendarPermissionSet(shape.calendarPermissionSet).write());
		ctx.updated(dir, folder);
		mUpdateFolderResponseMessage msg;
		msg.Folders.emplace_back(ctx.loadFolder(dir, folder.folderId, idOnly));

		if (permission_change) {
			auto folder_name =
				idOnly.get<const char>(PR_DISPLAY_NAME, sShape::FL_ANY);

			std::string mailbox = "public folders";
			if (folder.location == sFolderSpec::PRIVATE)
				mailbox = "mailbox " + *folder.target;

			mlog(LV_INFO, "ews-audit: %s changed permissions on folder \"%s\" in %s",
				znul(actor), txt2cstr(folder_name).c_str(),
				mailbox.c_str());
		}

		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process Subscribe
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSubscribeRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:SubscribeResponse");

	mSubscribeResponse data;
	mSubscribeResponseMessage& msg = data.ResponseMessages.emplace_back();
	msg.SubscriptionId = std::visit([&](const auto& sub){return ctx.subscribe(sub);}, request.subscription);
	msg.success();

	data.serialize(response);
}

/**
 * @brief      Process Unsubscribe
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mUnsubscribeRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:UnsubscribeResponse");

	mUnsubscribeResponse data;
	if (ctx.unsubscribe(request.SubscriptionId))
		data.ResponseMessages.emplace_back().success();
	else
		data.ResponseMessages.emplace_back("Error", "ErrorSubscriptionNotFound", "Subscription not found");

	data.serialize(response);
}

/**
 * @brief      Keep task status, percentage and completion in step
 *
 * Like Exchange, each change of one of them adjusts the others, in the
 * order of the updates. The state starts from the stored item.
 *
 * @param      ctx    Request context
 * @param      dir    Store directory
 * @param      mid    Message ID of the task
 * @param      set    Field just written to the shape
 * @param      shape  Shape holding the written value
 * @param      task   Task state, loaded on first use
 */
static void upd_task_state(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, const tSetItemField &set, const sShape &shape,
    std::optional<sTaskState> &task)
{
	auto uri = std::get_if<tFieldURI>(&set.fieldURI.asVariant());
	if (uri == nullptr)
		return;
	const auto &f = uri->FieldURI;
	if (f != "task:PercentComplete" && f != "task:Status" &&
	    f != "task:CompleteDate")
		return;
	auto stTag = shape.tag(NtTaskStatus);
	auto pcTag = shape.tag(NtPercentComplete);
	auto dcTag = shape.tag(NtTaskDateCompleted);
	if (!task) {
		const proptag_t tags[] = {stTag, pcTag, dcTag};
		auto props = ctx.getItemProps(dir, mid, tags);
		task.emplace();
		if (auto v = props.get<const uint32_t>(stTag))
			task->status = *v;
		if (auto v = props.get<const double>(pcTag))
			task->percent = *v;
		if (auto v = props.get<const uint64_t>(dcTag))
			task->completed = *v;
	}
	const TAGGED_PROPVAL *p;
	if (f == "task:PercentComplete") {
		if ((p = shape.writes(pcTag)) != nullptr)
			task->setPercent(*static_cast<double *>(p->pvalue));
	} else if (f == "task:Status") {
		if ((p = shape.writes(stTag)) != nullptr)
			task->setStatus(*static_cast<uint32_t *>(p->pvalue));
	} else if ((p = shape.writes(dcTag)) != nullptr) {
		task->setCompleteDate(*static_cast<uint64_t *>(p->pvalue));
	}
}

/**
 * @brief      Write the follow-up flag of an update
 *
 * The to-do flags depend on whether the item was sent, and the to-do
 * title on the subject.
 *
 * @param      ctx    Request context
 * @param      dir    Store directory
 * @param      mid    Message ID of the item
 * @param      shape  Shape of the update
 */
static void upd_flag(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, sShape &shape)
{
	auto reqTag = shape.tag(NtFlagRequest);
	const proptag_t tags[] = {PR_MESSAGE_CLASS, PR_MESSAGE_FLAGS,
		PR_SUBJECT, reqTag};
	auto props = ctx.getItemProps(dir, mid, tags);
	auto cls = props.get<const char>(PR_MESSAGE_CLASS);
	/* Exchange cannot flag these */
	if (cls != nullptr && (class_match_prefix(cls, "IPM.Task") == 0 ||
	    class_match_prefix(cls, "IPM.Appointment") == 0))
		throw EWSError::InternalServerError(E3626);
	auto flags = props.get<const uint32_t>(PR_MESSAGE_FLAGS);
	auto subject = props.get<const char>(PR_SUBJECT);
	if (auto w = shape.writes(PR_SUBJECT))
		subject = static_cast<const char *>(w->pvalue);
	EWSContext::writeFlag(tFlagType(shape.flag), shape, subject,
		flags != nullptr && *flags & MSGFLAG_UNSENT,
		reqTag != 0 && props.has(reqTag));
}

/**
 * @brief      Apply DeleteItemField to a meeting attendee list
 *
 * An attendee list without Attendee children clears that kind, so
 * updateAttendees drops the rows and cancels the meeting for them.
 */
static void delete_attendees(const sItemChangeDescription &update,
    sShape &shape)
{
	static const XMLElement *const empty = [] {
		static XMLDocument doc;
		return doc.NewElement("Attendees");
	}();
	auto del = std::get_if<tDeleteItemField>(&update);
	if (del == nullptr)
		return;
	auto uri = std::get_if<tFieldURI>(&del->fieldURI.asVariant());
	if (uri == nullptr)
		return;
	if (uri->FieldURI == "calendar:RequiredAttendees")
		shape.requiredAttendees = empty;
	else if (uri->FieldURI == "calendar:OptionalAttendees")
		shape.optionalAttendees = empty;
	else if (uri->FieldURI == "calendar:Resources")
		shape.resourceAttendees = empty;
}

/**
 * @brief      Check whether an ItemChange only edits attendee lists
 *
 * MS-OXOCAL v22.1 §3.1.4.7.3.4: only such an update can go to the added
 * attendees alone. Any other change concerns all attendees.
 */
static bool attendees_only(const tItemChange &change)
{
	for (const auto &update : change.Updates) {
		auto &path = std::visit([](const auto &u) -> const tPath & {
		             	return u.fieldURI;
		             }, update);
		auto uri = std::get_if<tFieldURI>(&path.asVariant());
		if (uri == nullptr ||
		    (uri->FieldURI != "calendar:RequiredAttendees" &&
		    uri->FieldURI != "calendar:OptionalAttendees" &&
		    uri->FieldURI != "calendar:Resources"))
			return false;
	}
	return true;
}

/**
 * @brief      Check whether an ItemChange only sets the read flag
 */
static bool read_flag_only(const tItemChange &change)
{
	for (const auto &update : change.Updates) {
		auto set = std::get_if<tSetItemField>(&update);
		if (set == nullptr)
			return false;
		auto uri = std::get_if<tFieldURI>(&set->fieldURI.asVariant());
		if (uri == nullptr || uri->FieldURI != "message:IsRead")
			return false;
	}
	return !change.Updates.empty();
}

/* What an update of one occurrence needs to know about it */
struct occ_info {
	std::optional<std::pair<uint64_t, uint64_t>> times;
	std::optional<TZDEF> start_zone, end_zone;
};

/* Local time of @utc, rechecked with the bias at that local time */
static bool utc_to_local(const TZDEF &zone, time_t utc, time_t &local)
{
	int64_t bias;
	if (!tz_to_offset(zone, utc, bias))
		return false;
	local = utc - bias * 60;
	if (!tz_to_offset(zone, local, bias))
		return false;
	local = utc - bias * 60;
	return true;
}

/**
 * @brief      Read the times of an update in the zones Exchange uses
 *
 * setDatetimeFields converts the times left without offset with the new
 * zone of their side.
 *
 * @param      occ   Times and zones when the update is for one occurrence
 *
 * @return     The sides whose time was taken from the stored item
 */
static uint8_t upd_zone_times(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, sShape &shape, const occ_info &occ)
{
	const proptag_t tags[] = {
		shape.tag(NtCommonStart), shape.tag(NtCommonEnd),
		shape.tag(NtAppointmentTimeZoneDefinitionStartDisplay),
		shape.tag(NtAppointmentTimeZoneDefinitionEndDisplay),
	};
	auto &naive = shape.offsetProps;
	bool any = shape.tzWrite != 0;
	for (auto t : {tags[0], tags[1]})
		any |= t != 0 && ct_contains(naive, t);
	if (!any)
		return 0;
	for (const auto &name : {shape.tzStartName, shape.tzEndName})
		if (!name.empty() && !lookup_tz_get_tzdef(name.c_str()))
			throw EWSError::TimeZone(E3623);
	auto props = ctx.getItemProps(dir, mid, proptag_cspan{tags});
	uint64_t stored[2]{};
	bool have[2]{};
	if (occ.times) {
		stored[0] = occ.times->first, stored[1] = occ.times->second;
		have[0] = have[1] = true;
	} else {
		for (int k = 0; k < 2; ++k) {
			auto v = props.get<const uint64_t>(tags[k]);
			if (v != nullptr)
				stored[k] = *v, have[k] = true;
		}
	}
	uint8_t derived = 0;
	auto side = [&](int k, uint8_t bit) {
		auto ttag = tags[k];
		if (ttag == 0)
			return;
		auto zone = k == 0 ? occ.start_zone : occ.end_zone;
		if (!zone)
			zone = binary_to_tzdef(props.get<const BINARY>(tags[k + 2]));
		if (!zone)
			return;
		auto w = shape.writes(ttag);
		bool given = w != nullptr, local = given && ct_contains(naive, ttag);
		if (shape.tzWrite & bit) {
			if (local)
				return;
			if (!given && !have[k])
				return;
			auto t = given ? *static_cast<const uint64_t *>(w->pvalue) : stored[k];
			time_t wall;
			if (!utc_to_local(*zone, rop_util_nttime_to_unix(t), wall))
				return;
			shape.write(TAGGED_PROPVAL{ttag, EWSContext::construct<uint64_t>(
				rop_util_unix_to_nttime(wall))});
			naive.emplace_back(ttag);
			if (!given)
				derived |= bit;
			return;
		}
		if (!local)
			return;
		auto wall = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(w->pvalue));
		int64_t bias;
		if (!tz_to_offset(*zone, wall, bias))
			return;
		shape.write(TAGGED_PROPVAL{ttag, EWSContext::construct<uint64_t>(
			rop_util_unix_to_nttime(wall + bias * 60))});
		std::erase(naive, ttag);
	};
	side(0, sShape::TZ_START);
	side(1, sShape::TZ_END);
	return derived;
}

/**
 * @brief      Refuse an update that leaves the end before the start
 *
 * Exchange answers a zone change that causes it differently from times
 * given that way.
 */
static void upd_check_order(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, const sShape &shape, const occ_info &occ, uint8_t derived)
{
	const proptag_t tags[] = {shape.tag(NtCommonStart), shape.tag(NtCommonEnd)};
	auto ws = shape.writes(tags[0]), we = shape.writes(tags[1]);
	if (ws == nullptr && we == nullptr)
		return;
	uint64_t start = 0, end = 0;
	if (occ.times) {
		std::tie(start, end) = *occ.times;
	} else {
		auto props = ctx.getItemProps(dir, mid, proptag_cspan{tags});
		auto s = props.get<const uint64_t>(tags[0]);
		auto e = props.get<const uint64_t>(tags[1]);
		if (s != nullptr)
			start = *s;
		if (e != nullptr)
			end = *e;
	}
	if (ws != nullptr)
		start = *static_cast<const uint64_t *>(ws->pvalue);
	if (we != nullptr)
		end = *static_cast<const uint64_t *>(we->pvalue);
	if (start == 0 || end == 0 || end >= start)
		return;
	if (derived != 0)
		throw EWSError::ItemSavePropertyError(E3621);
	throw EWSError::CalendarEndDateIsEarlierThanStartDate(E3622);
}

/**
 * @brief      Refuse a write without the current change key
 *
 * Like Exchange, only AlwaysOverwrite writes without it. A key that
 * cannot be an XID is not compared, as in Exchange.
 */
static void upd_check_change_key(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, const std::optional<sBase64Binary> &key)
{
	if (!key || key->empty())
		throw EWSError::ChangeKeyRequiredForWriteOperations(E3619);
	/* A GUID and a counter of 1 to 8 bytes */
	if (key->size() < 17 || key->size() > 24)
		return;
	static constexpr proptag_t tags[] = {PR_CHANGE_KEY};
	auto props = ctx.getItemProps(dir, mid, proptag_cspan{tags});
	auto cur = props.get<const BINARY>(PR_CHANGE_KEY);
	if (cur != nullptr && (cur->cb != key->size() ||
	    memcmp(cur->pb, key->data(), cur->cb) != 0))
		throw EWSError::IrresolvableConflict(E3620);
}

/**
 * @brief      Refuse an UpdateItem whose send would fail
 *
 * Exchange rejects the whole request, the update included, when a
 * recipient of the message to send is not resolved.
 */
static void upd_check_resolved(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, const sShape &shape)
{
	void *cls = nullptr;
	if (!ctx.plugin().exmdb.get_message_property(dir.c_str(), nullptr,
	    CP_ACP, mid, PR_MESSAGE_CLASS, &cls) || cls == nullptr ||
	    class_match_prefix(static_cast<const char *>(cls), "IPM.Note") != 0)
		return;
	const tinyxml2::XMLElement *given[] = {
		shape.toRecipients, shape.ccRecipients, shape.bccRecipients,
	};
	for (auto xml : given) {
		if (xml == nullptr)
			continue;
		for (auto e = xml->FirstChildElement("Mailbox"); e != nullptr;
		     e = e->NextSiblingElement("Mailbox")) {
			tEmailAddressType addr(e);
			if (!addr.empty() && !addr.addressable())
				throw EWSError::InvalidRecipients(E3618(*addr.Name));
		}
	}
	TARRAY_SET rows{};
	if (!ctx.plugin().exmdb.get_message_rcpts(dir.c_str(), mid, &rows))
		throw EWSError::ItemNotFound(E3494);
	for (const auto &row : rows) {
		auto type = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
		auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		/* Same rows as EWSContext::send() checks */
		if ((type != nullptr && *type >= MAPI_TO && *type <= MAPI_BCC &&
		    given[*type - MAPI_TO] != nullptr) ||
		    (flags != nullptr && (*flags & recipOrganizer ||
		    !(*flags & recipSendable))) || ctx.addressable(row))
			continue;
		auto name = row.get<const char>(PR_DISPLAY_NAME);
		throw EWSError::InvalidRecipients(E3618(name != nullptr ? name : ""));
	}
}

static void process_upditem_2(mUpdateItemRequest &request, const EWSContext &ctx,
    const std::string &dir, const char *username, sMessageEntryId &mid)
{
	MESSAGE_CONTENT *sendcontent = nullptr;
	if (!ctx.plugin().exmdb.read_message(dir.c_str(),
	    username, CP_ACP, mid.messageId(), &sendcontent) ||
	    sendcontent == nullptr)
		throw EWSError::ItemNotFound(E3464);
	auto cls = sendcontent->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (cls == nullptr || class_match_prefix(cls, "IPM.Note") != 0)
		return;

	std::vector<TAGGED_PROPVAL> sprops;
	auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
	sprops.push_back({PR_CLIENT_SUBMIT_TIME, now});
	sprops.push_back({PR_MESSAGE_DELIVERY_TIME, now});
	auto flags = sendcontent->proplist.get<const uint32_t>(PR_MESSAGE_FLAGS);
	if (flags != nullptr && *flags & MSGFLAG_UNSENT)
		sprops.push_back({PR_MESSAGE_FLAGS,
			EWSContext::construct<uint32_t>(*flags & ~MSGFLAG_UNSENT)});

	std::vector<proptag_t> drop;
	auto ident = ctx.submitIdentity(dir, sendcontent->proplist, drop);
	sprops.insert(sprops.end(), ident.begin(), ident.end());

	/* Stamp the draft only after it was sent */
	message_content_ptr content(sendcontent->dup());
	if (content == nullptr)
		throw EWSError::NotEnoughMemory(E3532);
	for (const auto &prop : sprops)
		if (content->proplist.set(prop) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3530);
	for (auto tag : drop)
		content->proplist.erase(tag);
	ctx.validate_sendas_perms(*content);
	ctx.send(dir, mid.messageId().gcv(), *content);

	const TPROPVAL_ARRAY proplist = {static_cast<uint16_t>(sprops.size()), sprops.data()};
	PROBLEM_ARRAY problems;
	if (!ctx.plugin().exmdb.set_message_properties(dir.c_str(),
	    username, CP_ACP, mid.messageId(), &proplist, &problems))
		throw EWSError::ItemSave(E3465);
	if (!drop.empty() && !ctx.plugin().exmdb.remove_message_properties(
	    dir.c_str(), CP_ACP, mid.messageId(), drop))
		throw EWSError::ItemSave(E3531);

	if (*request.MessageDisposition == Enum::SendAndSaveCopy) {
		sFolderSpec sentitems = ctx.resolveFolder(tDistinguishedFolderId(Enum::sentitems));
		uint64_t newMid = 0;
		if (!ctx.plugin().exmdb.allocate_message_id(dir.c_str(),
		    sentitems.folderId, &newMid))
			throw EWSError::MoveCopyFailed(E3467);
		BOOL result = false;
		if (!ctx.plugin().exmdb.movecopy_message(dir.c_str(),
		    CP_ACP, mid.messageId(), sentitems.folderId,
		    newMid, TRUE, &result) || !result)
			throw EWSError::MoveCopyFailed(E3468);
	} else {
		auto eid = mid.messageId();
		auto fid = mid.folderId();
		EID_ARRAY eids{1, &eid};
		BOOL partial = false;
		if (!ctx.plugin().exmdb.delete_messages(dir.c_str(),
		    CP_ACP, username, fid, eids, false, &partial) ||
		    partial)
			throw EWSError::CannotDeleteObject(E3469);
	}
}

/**
 * @brief      Process UpdateItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 *
 * @todo check whether instances should rathe be used
 */
/**
 * @brief      Whether the item is the organizer's copy of a meeting
 */
static bool upd_is_organizer_copy(const EWSContext &ctx,
    const std::string &dir, uint64_t mid)
{
	void *cls = nullptr;
	if (!ctx.plugin().exmdb.get_message_property(dir.c_str(), nullptr,
	    CP_ACP, mid, PR_MESSAGE_CLASS, &cls) || cls == nullptr)
		return false;
	return class_match_prefix(static_cast<const char *>(cls),
	       "IPM.Appointment") == 0 && ctx.isOrganizer(dir, mid);
}

/* Properties PidLidChangeHighlight looks at, in BIT_CH order */
static std::vector<proptag_t> upd_highlight_tags(const EWSContext &ctx,
    const std::string &dir)
{
	const PROPERTY_NAME pn[] = {
		NtAppointmentStartWhole, NtAppointmentEndWhole,
		NtAppointmentRecur, NtLocation,
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = ctx.getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(pn) ||
	    std::find(ids.cbegin(), ids.cend(), 0) != ids.cend())
		throw EWSError::ItemSave(E3541);
	return {PROP_TAG(PT_SYSTIME, ids[0]), PROP_TAG(PT_SYSTIME, ids[1]),
	        PROP_TAG(PT_BINARY, ids[2]), PROP_TAG(PT_UNICODE, ids[3]),
	        PR_SUBJECT, PR_BODY};
}

static std::vector<std::string> upd_attendees(const EWSContext &ctx,
    const TARRAY_SET &rows, uint32_t type)
{
	std::vector<std::string> out;
	for (const auto &row : rows) {
		auto rtype = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
		auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (rtype == nullptr || (*rtype & 0xf) != type ||
		    (flags != nullptr && *flags & recipOrganizer))
			continue;
		auto a = ctx.rcptAddress(row);
		HX_strlower(a.data());
		out.emplace_back(std::move(a));
	}
	std::sort(out.begin(), out.end());
	return out;
}

/**
 * @brief      Work out what an update changed in the item properties
 *
 * MS-OXOCAL v22.1 §2.2.6.2
 *
 * @param      before    Values of @tags before the update
 *
 * @return     PidLidChangeHighlight bits
 */
static uint32_t upd_highlight(const EWSContext &ctx, const std::string &dir,
    uint64_t mid, const std::vector<proptag_t> &tags,
    const TPROPVAL_ARRAY &before)
{
	static constexpr uint32_t bits[] = {
		BIT_CH_START, BIT_CH_END, BIT_CH_RECUR, BIT_CH_LOCATION,
		BIT_CH_SUBJECT, BIT_CH_BODY,
	};
	if (tags.empty())
		return 0;
	if (tags.size() != std::size(bits))
		throw EWSError::ItemSave(E3541);
	auto after = ctx.getItemProps(dir, mid, tags);
	uint32_t ch = 0;
	for (size_t i = 0; i < tags.size(); ++i)
		if (!propval_compare_relop_nullok(RELOP_EQ, PROP_TYPE(tags[i]),
		    before.getval(tags[i]), after.getval(tags[i])))
			ch |= bits[i];
	return ch;
}

/**
 * @brief      Work out which attendee kinds an update added to
 *
 * MS-OXOCAL v22.1 §2.2.6.2: BIT_CH_REQATT and BIT_CH_OPTATT stand for
 * added attendees, removed ones set no bit.
 *
 * @param      oldRcpts  Recipients before the update
 *
 * @return     PidLidChangeHighlight bits
 */
static uint32_t upd_added_attendees(const EWSContext &ctx,
    const std::string &dir, uint64_t mid, const TARRAY_SET &oldRcpts)
{
	TARRAY_SET rcpts{};
	if (!ctx.plugin().exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
		throw EWSError::ItemNotFound(E3494);
	uint32_t ch = 0;
	for (auto [type, bit] : {std::pair{MAPI_TO, BIT_CH_REQATT}, std::pair{MAPI_CC, BIT_CH_OPTATT}}) {
		auto o = upd_attendees(ctx, oldRcpts, type);
		auto n = upd_attendees(ctx, rcpts, type);
		if (!std::includes(o.cbegin(), o.cend(), n.cbegin(), n.cend()))
			ch |= bit;
	}
	return ch;
}

void process(mUpdateItemRequest &&request, XMLElement *response, const EWSContext &ctx)
{
	response->SetName("m:UpdateItemResponse");

	mUpdateItemResponse data;
	data.ResponseMessages.reserve(request.ItemChanges.size());

	sShape idOnly;
	idOnly.add(PR_ENTRYID, sShape::FL_FIELD).add(PR_CHANGE_KEY, sShape::FL_FIELD).add(PR_MESSAGE_CLASS);
	idOnly.add(PR_START_DATE, sShape::FL_FIELD);
	idOnly.add(NtAppointmentRecur, PT_BINARY, sShape::FL_FIELD);
	idOnly.add(NtRecurring, PT_BOOLEAN, sShape::FL_FIELD);
	idOnly.add(NtExceptionReplaceTime, PT_SYSTIME, sShape::FL_FIELD);
	idOnly.add(NtAppointmentTimeZoneDefinitionRecur, PT_BINARY);
	for (const auto &change : request.ItemChanges) try {
		tItemId itemId = change.ItemId.itemId();
		sMessageEntryId mid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(mid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, mid);
		auto rights = ctx.permissions(dir, parentFolder.folderId);
		if (!(rights & frightsEditAny))
			throw EWSError::AccessDenied(E3445);
		ctx.assertCanReadPrivate(dir, parentFolder, rights, mid.messageId());
		/* The update goes out in the owner's name, check before writing */
		bool orgCopy = request.SendMeetingInvitationsOrCancellations &&
		    *request.SendMeetingInvitationsOrCancellations != Enum::SendToNone &&
		    upd_is_organizer_copy(ctx, dir, mid.messageId());
		if (orgCopy)
			ctx.validate_sendas_perms(ctx.storeOwner(dir));
		if (!ctx.plugin().lenient_change_keys &&
		    request.ConflictResolution.value_or("") != "AlwaysOverwrite")
			upd_check_change_key(ctx, dir, mid.messageId(), itemId.ChangeKey);
		std::vector<proptag_t> hlTags;
		TPROPVAL_ARRAY hlBefore{};
		if (orgCopy && !change.ItemId.isOccurrence()) {
			hlTags = upd_highlight_tags(ctx, dir);
			hlBefore = ctx.getItemProps(dir, mid.messageId(), hlTags);
		}
		sShape shape(change);
		/*
		 * Pre-register timezone properties that setDatetimeFields may
		 * write, so they are included in the named property
		 * resolution.
		 */
		shape.add(NtAppointmentTimeZoneDefinitionStartDisplay, PT_BINARY);
		shape.add(NtAppointmentTimeZoneDefinitionEndDisplay, PT_BINARY);
		shape.add(NtAppointmentTimeZoneDefinitionRecur, PT_BINARY);
		shape.add(NtTimeZoneStruct, PT_BINARY);
		/* Written by upd_zone_times and setDatetimeFields */
		shape.add(NtCommonStart, PT_SYSTIME);
		shape.add(NtCommonEnd, PT_SYSTIME);
		shape.add(NtAppointmentStartWhole, PT_SYSTIME);
		shape.add(NtAppointmentEndWhole, PT_SYSTIME);
		shape.add(NtPrivate, PT_BOOLEAN);
		shape.add(NtReminderSet, PT_BOOLEAN);
		shape.add(NtReminderDelta, PT_LONG);
		shape.add(NtReminderTime, PT_SYSTIME);
		shape.add(NtReminderSignalTime, PT_SYSTIME);
		shape.add(NtRecurring, PT_BOOLEAN);
		/* Written by applyRecurrence and moveRecurrence */
		shape.add(NtAppointmentRecur, PT_BINARY);
		shape.add(NtRecurrenceType, PT_LONG);
		shape.add(NtClipStart, PT_SYSTIME);
		shape.add(NtClipEnd, PT_SYSTIME);
		/* Written by sTaskState::write and upd_flag */
		shape.add(NtTaskStatus, PT_LONG);
		shape.add(NtPercentComplete, PT_DOUBLE);
		shape.add(NtTaskComplete, PT_BOOLEAN);
		shape.add(NtTaskDateCompleted, PT_SYSTIME);
		/* Written by upd_flag */
		shape.add(NtFlagRequest, PT_UNICODE);
		shape.add(NtToDoTitle, PT_UNICODE);
		shape.add(NtTaskStartDate, PT_SYSTIME);
		shape.add(NtTaskDueDate, PT_SYSTIME);
		ctx.getNamedTags(dir, shape, true);
		std::optional<sTaskState> task;
		for (const auto &update : change.Updates) {
			if (auto set = std::get_if<tSetItemField>(&update)) {
				set->put(shape);
				upd_task_state(ctx, dir, mid.messageId(),
					*set, shape, task);
			}
			delete_attendees(update, shape);
		}
		if (task)
			task->write(shape);
		tContact::genFields(shape);
		std::optional<uint32_t> occBase;
		if (change.ItemId.holds_alternative<tOccurrenceItemId>()) {
			const auto &o = std::get<tOccurrenceItemId>(change.ItemId.asVariant());
			occBase = ctx.resolveOccurrenceIndex(dir, mid.messageId(),
			          o.InstanceIndex);
		} else if (itemId.type == tItemId::ID_OCCURRENCE) {
			occBase = sOccurrenceId(itemId.Id.data(), itemId.Id.size()).basedate;
		}
		occ_info occ;
		if (occBase && (shape.tzWrite != 0 ||
		    shape.writes(shape.tag(NtCommonStart)) != nullptr ||
		    shape.writes(shape.tag(NtCommonEnd)) != nullptr)) {
			occ.times = ctx.occurrenceTimes(dir, mid.messageId(), *occBase);
			std::tie(occ.start_zone, occ.end_zone) = ctx.occurrenceZones(dir,
				parentFolder.folderId, mid.messageId(), *occBase);
		}
		auto derived = upd_zone_times(ctx, dir, mid.messageId(), shape, occ);
		tCalendarItem::setDatetimeFields(shape);
		upd_check_order(ctx, dir, mid.messageId(), shape, occ, derived);
		if (!change.ItemId.isOccurrence() && request.MessageDisposition &&
		    (*request.MessageDisposition == Enum::SendOnly ||
		    *request.MessageDisposition == Enum::SendAndSaveCopy))
			upd_check_resolved(ctx, dir, mid.messageId(), shape);
		if (shape.recurrence && change.ItemId.isOccurrence())
			throw EWSError::InvalidPropertySet(E3484);
		if (shape.recurrence)
			ctx.applyRecurrence(dir, mid.messageId(), shape.recurrence, shape);
		else if (!change.ItemId.isOccurrence())
			ctx.moveRecurrence(dir, mid.messageId(), shape);
		if (shape.flag != nullptr)
			upd_flag(ctx, dir, mid.messageId(), shape);
		const char* username = ctx.effectiveUser(parentFolder);
		mUpdateItemResponseMessage msg;
		uint32_t occ_basedate = 0;
		Enum::CalendarItemUpdateOperationType mode =
			request.SendMeetingInvitationsOrCancellations.value_or(
			Enum::SendToNone);
		std::optional<TARRAY_SET> oldRcpts;
		bool organizer = false;
		if (change.ItemId.holds_alternative<tOccurrenceItemId>()) {
			const auto& occurrence  = std::get<tOccurrenceItemId>(change.ItemId.asVariant());
			occ_basedate = ctx.resolveOccurrenceIndex(dir,
			               mid.messageId(), occurrence.InstanceIndex);
			TPROPVAL_ARRAY props = shape.write();
			const auto &tagsRm = shape.remove_vec();
			ctx.updateOccurrence(dir, parentFolder.folderId,
				mid.messageId(), occ_basedate, props, tagsRm);
		} else if (itemId.type == tItemId::ID_OCCURRENCE) {
			sOccurrenceId oid(itemId.Id.data(), itemId.Id.size());
			occ_basedate = oid.basedate;
			TPROPVAL_ARRAY props = shape.write();
			const auto &tagsRm = shape.remove_vec();
			ctx.updateOccurrence(dir, parentFolder.folderId,
				mid.messageId(), occ_basedate, props, tagsRm);
		} else if (shape.mimeContent) {
			ctx.updated(dir, mid, shape);
			auto content = ctx.toContent(dir, *shape.mimeContent);
			for (auto tag : shape.remove())
				content->proplist.erase(tag);
			for (const auto &prop : shape.write()) {
				auto ret = content->proplist.set(prop);
				if (ret == ecServerOOM)
					throw EWSError::ItemSave(E3035);
			}
			auto error = content->proplist.set(PidTagMid, EWSContext::construct<uint64_t>(rop_util_make_eid(1, mid.message_gc)));
			if (error == ecServerOOM)
				throw EWSError::ItemSave(E3449);
			if (!content->proplist.has(PidTagChangeNumber))
				throw EWSError::ItemSave(E3255);
			uint64_t outmid = 0, outcn = 0;
			if (!ctx.plugin().exmdb.write_message(dir.c_str(),
			    CP_ACP, parentFolder.folderId, content.get(), {},
			    &outmid, &outcn, &error) || error != ecSuccess)
				throw EWSError::ItemSave(E3446);
		} else {
			ctx.updateReminder(dir, mid.messageId(), shape);
			if (!read_flag_only(change))
				ctx.updated(dir, mid, shape);
			TPROPVAL_ARRAY props = shape.write();
			const auto &tagsRm = shape.remove_vec();
			PROBLEM_ARRAY problems;
			if (!ctx.plugin().exmdb.remove_message_properties(dir.c_str(),
			    CP_ACP, mid.messageId(), tagsRm))
				throw EWSError::ItemSave(E3093);
			auto readprop = props.find(PR_READ);
			if (readprop != nullptr) {
				uint8_t mark_as_read = *static_cast<uint8_t *>(readprop->pvalue);
				uint64_t read_cn;
				if (!ctx.plugin().exmdb.set_message_read_state(dir.c_str(),
				    username, mid.messageId(), mark_as_read, &read_cn))
					throw EWSError::ItemSave(E3417);
				/*
				 * props is a shallow view onto ndr_stack-alloc-backed data, so
				 * props.erase() must not be used.
				 */
				readprop->proptag = PR_NULL;
				if (mark_as_read != 0 &&
				    !request.SuppressReadReceipts.value_or(false))
					ctx.notifyReadReceipt(dir, mid.messageId());
			}
			/* Filter out e.g. neutralized PR_READ entries */
			props.count = std::remove_if(props.ppropval, props.ppropval + props.count,
			              [](const TAGGED_PROPVAL &v) STATIC_IN_CXX23 {
			              	return PROP_TYPE(v.proptag) == PT_NULL;
			              }) - props.ppropval;
			if (props.count > 0 &&
			    !ctx.plugin().exmdb.set_message_properties(dir.c_str(),
			    username, CP_ACP, mid.messageId(), &props, &problems))
				throw EWSError::ItemSave(E3418);
			msg.ConflictResults.Count = problems.count;
			ctx.plugin().unloadMessageInstance(dir, mid.messageId());
			if (shape.requiredAttendees || shape.optionalAttendees ||
			    shape.resourceAttendees) {
				oldRcpts.emplace();
				if (!ctx.plugin().exmdb.get_message_rcpts(
				    dir.c_str(), mid.messageId(), &*oldRcpts))
					throw EWSError::ItemNotFound(E3494);
				/* updateAttendees marks it as organized */
				organizer = ctx.isOrganizer(dir,
				            mid.messageId());
				/*
				 * MS-OXOCAL v22.1 §3.1.4.7.3.2: responses stay
				 * unless the update is a significant change
				 */
				auto ch = upd_highlight(ctx, dir,
				          mid.messageId(), hlTags, hlBefore);
				ctx.updateAttendees(dir, parentFolder,
				    mid.messageId(), shape, *oldRcpts,
				    !(ch & (BIT_CH_START | BIT_CH_END | BIT_CH_RECUR)));
			}
			if (shape.toRecipients || shape.ccRecipients ||
			    shape.bccRecipients)
				ctx.updateMessageRecipients(dir, parentFolder,
				    mid.messageId(), shape);
		}
		/* An attendee's copy sends nothing, like in Exchange */
		if (orgCopy && occ_basedate != 0) {
			ctx.sendOccurrenceUpdate(dir, mid, parentFolder,
				mode == Enum::SendToAllAndSaveCopy ||
				mode == Enum::SendToChangedAndSaveCopy, occ_basedate);
		} else if (orgCopy) {
			/*
			 * A change other than to the attendee lists affects
			 * every attendee, so it goes to all of them.
			 */
			bool addedOnly = oldRcpts && attendees_only(change) &&
			                 (mode == Enum::SendOnlyToChanged ||
			                 mode == Enum::SendToChangedAndSaveCopy);
			/*
			 * MS-OXOCAL v22.1 §2.2.6.5, §3.1.4.7.3.1: a new start,
			 * end or recurrence, or added attendees, make a full
			 * update, everything else an informational one.
			 */
			auto hl = upd_highlight(ctx, dir, mid.messageId(),
			          hlTags, hlBefore);
			if (oldRcpts)
				hl |= upd_added_attendees(ctx, dir,
				      mid.messageId(), *oldRcpts);
			bool full = hl & (BIT_CH_START | BIT_CH_END |
			            BIT_CH_RECUR | BIT_CH_REQATT | BIT_CH_OPTATT);
			ctx.sendMeetingUpdate(dir, parentFolder,
			    mid.messageId(), addedOnly ? &*oldRcpts : nullptr,
			    mode == Enum::SendToAllAndSaveCopy ||
			    mode == Enum::SendToChangedAndSaveCopy, hl,
			    full || addedOnly);
		}
		if (orgCopy && oldRcpts && organizer)
			/* MS-OXWSMTGS v14.0 §2.2.5.3 */
			ctx.cancelRemovedAttendees(dir, parentFolder,
			    mid.messageId(), *oldRcpts,
			    mode == Enum::SendToAllAndSaveCopy ||
			    mode == Enum::SendToChangedAndSaveCopy);
		/* The sends write to the meeting, so load it after them */
		if (occ_basedate != 0)
			msg.Items.emplace_back(ctx.loadOccurrence(dir, parentFolder.folderId, mid.messageId(), occ_basedate, idOnly));
		else
			msg.Items.emplace_back(ctx.loadItem(dir, mid.folderId(), mid.messageId(), idOnly));
		if (occ_basedate == 0 && request.MessageDisposition &&
		    (*request.MessageDisposition == Enum::SendOnly ||
		    *request.MessageDisposition == Enum::SendAndSaveCopy))
			process_upditem_2(request, ctx, dir, username, mid);
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch (const EWSError &err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

}
