// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <tinyxml2.h>
#include <unordered_set>
#include <variant>
#include <vector>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <gromox/ab_tree.hpp>
#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/eid_array.hpp>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/mapitags.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "exceptions.hpp"
#include "namedtags.hpp"
#include "requests.hpp"

namespace gromox::EWS::Requests {

using namespace gromox;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

///////////////////////////////////////////////////////////////////////////////
//Helper functions

namespace {

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
 * @brief      Read message body from reply file
 *
 * @param      path    Path to the file
 *
 * @return     Body content or empty optional on error
 */
std::optional<std::string> readMessageBody(const std::string &path) try
{
	std::ifstream ifs(path, std::ios::in | std::ios::ate | std::ios::binary);
	if (!ifs.is_open())
		return std::nullopt;
	size_t totalLength = ifs.tellg();
	ifs.seekg(std::ios::beg);
	while (!ifs.eof()) {
		ifs.ignore(std::numeric_limits<std::streamsize>::max(), '\r');
		if (ifs.get() == '\n' && ifs.get() == '\r' && ifs.get() == '\n')
			break;
	}
	if (ifs.eof())
		return std::nullopt;
	size_t headerLenght = ifs.tellg();
	std::string content(totalLength - headerLenght, 0);
	ifs.read(content.data(), content.size());
	return content;
} catch (const std::exception &e) {
	mlog(LV_ERR, "[ews] %s", e.what());
	return std::nullopt;
}

/**
 * @brief      Write message body to reply file
 *
 * If either the ReplyBody or its Message field are empty, the file is deleted instead.
 *
 * @param      path    Path to the file
 * @param      reply   Reply body
 */
void writeMessageBody(const std::string &path, const std::optional<tReplyBody> &reply)
{
	if (!reply || !reply->Message)
		return (void) unlink(path.c_str());
	static constexpr char header[] = "Content-Type: text/html;\r\n\tcharset=\"utf-8\"\r\n\r\n";
	auto& content = *reply->Message;
	std::ofstream file(path, std::ios::binary); /* FMODE_PUBLIC */
	file.write(header, std::size(header) - 1);
	file.write(content.c_str(), content.size());
	file.close();
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
		throw DispatchError(E3027);
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
 * @brief      Process ConvertId
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mConvertIdRequest&& request, XMLElement* response, EWSContext& ctx)
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
			std::string dir = ctx.get_maildir(aid.Mailbox);
			tBaseItemId id(sBase64Binary(aid.Format == Enum::HexEntryId ?
			               hex2bin(aid.Id) : base64_decode(aid.Id)),
			               tBaseItemId::ID_GUESS);
			if (id.type == tBaseItemId::ID_UNKNOWN)
				throw EWSError::CorruptData(E3252);
			mConvertIdResponseMessage msg;
			if (request.DestinationFormat == Enum::EwsId ||
			    request.DestinationFormat == Enum::EwsLegacyId)
				msg.AlternateId = tAlternateId(request.DestinationFormat, base64_encode(id.serializeId()), aid.Mailbox);
			else if (request.DestinationFormat == Enum::HexEntryId)
				msg.AlternateId = tAlternateId(request.DestinationFormat, hexEncode(id.Id), aid.Mailbox);
			else
				throw EWSError::InternalServerError(E3253);
			data.ResponseMessages.emplace_back(std::move(msg));
		}
		data.ResponseMessages.back().success();
	} catch(const EWSError& err) {
		data.ResponseMessages.emplace_back(err);
	}

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
	auto &msg = data.ResponseMessages.emplace_back();
	std::string domain = znul(ctx.auth_info().username);
	auto at = domain.find('@');
	if (at != std::string::npos)
		domain.erase(0, at + 1);

	std::vector<ab_tree::minid> results;
	try {
		uint32_t domId = ctx.getAccountId(domain, true);
		auto base = ab_tree::AB.get(-static_cast<int32_t>(domId));
		if (base && ab_tree_resolvename(*base, request.QueryString.c_str(), results)) {
			for (auto mid : results) {
				ab_tree::ab_node node(base.get(), mid);
				tPersona persona;
				std::string val;
				if (node.fetch_prop(PR_DISPLAY_NAME, val) == ecSuccess)
					persona.DisplayName = std::move(val);
				if (node.fetch_prop(PR_SMTP_ADDRESS, val) == ecSuccess)
					persona.EmailAddress = std::move(val);
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
				    persona.HomeAddress || persona.Comment)
					msg.People.emplace().emplace_back(std::move(persona));
			}
			if (msg.People)
				msg.TotalNumberOfPeopleInView = msg.People->size();
		}
	} catch (const EWSError &err) {
		data.ResponseMessages.clear();
		data.ResponseMessages.emplace_back(err);
		data.serialize(response);
		return;
	}

	msg.success();
	data.serialize(response);
}

/**
 * @brief      Process GetDelegate
 *
 * Reads the delegate configuration of a mailbox and returns the delegates
 * stored in the delegates.txt file. Only basic information (primary SMTP
 * address) is returned for each delegate.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
*/
void process(mGetDelegateRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:GetDelegateResponse");

	ctx.normalize(request.Mailbox);

	mGetDelegateResponse data;

	std::vector<std::string> delegate_list;
	std::string maildir = ctx.get_maildir(request.Mailbox);
	auto path = maildir + "/config/delegates.txt";
	auto err  = read_file_by_line(path.c_str(), delegate_list);
	if (err != 0) {
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
		if (requested.empty() || requested.contains(deleg)) {
			auto &msg = data.ResponseMessages.emplace_back();
			msg.success();
			msg.DelegateUser.UserId.PrimarySmtpAddress.emplace(deleg);
			found.insert(deleg);
		}
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

	data.serialize(response);
}

/**
 * @brief      Process CreateFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mCreateFolderRequest&& request, XMLElement* response, const EWSContext& ctx)
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
	} catch(const EWSError& err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process CreateItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mCreateItemRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:CreateItemResponse");

	mCreateItemResponse data;

	std::optional<sFolderSpec> targetFolder;
	if (request.SavedItemFolderId)
		targetFolder = ctx.resolveFolder(request.SavedItemFolderId->FolderId);
	else
		targetFolder = ctx.resolveFolder(tDistinguishedFolderId("outbox"));
	std::string dir = ctx.getDir(*targetFolder);
	bool hasAccess = ctx.permissions(dir, targetFolder->folderId) & (frightsOwner | frightsCreate);

	if (!request.MessageDisposition)
		request.MessageDisposition = Enum::SaveOnly;
	if (!request.SendMeetingInvitations)
		request.SendMeetingInvitations = Enum::SendToNone;
	bool sendMessages = request.MessageDisposition == Enum::SendOnly
		|| request.MessageDisposition == Enum::SendAndSaveCopy
		|| request.SendMeetingInvitations == Enum::SendOnlyToAll
		|| request.SendMeetingInvitations == Enum::SendToAllAndSaveCopy;

	data.ResponseMessages.reserve(request.Items.size());
	for (sItem &item : request.Items) try {
		if (!hasAccess)
			throw EWSError::AccessDenied(E3130);

		mCreateItemResponseMessage msg;
		bool persist = !(std::holds_alternative<tMessage>(item) && request.MessageDisposition == Enum::SendOnly);
		bool send = std::holds_alternative<tMessage>(item) && sendMessages;
		auto content = ctx.toContent(dir, *targetFolder, item, persist);

		auto updateRef = [&](const tItemId &refId, uint32_t resp) {
			ctx.assertIdType(refId.type, tItemId::ID_ITEM);
			sMessageEntryId mid(refId.Id.data(), refId.Id.size());
			sFolderSpec pf = ctx.resolveFolder(mid);
			std::string rdir = ctx.getDir(pf);
			ctx.validate(rdir, mid);
			const char *username = ctx.effectiveUser(pf);
			auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
			auto rstat = EWSContext::construct<uint32_t>(resp);
			uint32_t state = asfMeeting | asfReceived;
			auto astat = EWSContext::construct<uint32_t>(state);
			uint32_t busyValue = resp == respAccepted ? olBusy :
			                     resp == respTentative ? olTentative : olFree;
			auto bstat = EWSContext::construct<uint32_t>(busyValue);
			auto pidResp  = ctx.getNamedPropId(rdir, NtResponseStatus, true);
			auto pidReply = ctx.getNamedPropId(rdir, NtAppointmentReplyTime, true);
			auto pidState = ctx.getNamedPropId(rdir, NtAppointmentStateFlags, true);
			auto pidBusy  = ctx.getNamedPropId(rdir, NtBusyStatus, true);
			TAGGED_PROPVAL props[] = {
				{PROP_TAG(PT_LONG, pidResp), rstat},
				{PROP_TAG(PT_SYSTIME, pidReply), now},
				{PROP_TAG(PT_LONG, pidState), astat},
				{PROP_TAG(PT_LONG, pidBusy), bstat},
			};
			TPROPVAL_ARRAY proplist{std::size(props), props};
			PROBLEM_ARRAY problems;
			if (!ctx.plugin().exmdb.set_message_properties(rdir.c_str(), username, CP_ACP,
				mid.messageId(), &proplist, &problems))
				throw EWSError::ItemSave(E3092);
			if (resp == respAccepted || resp == respTentative)
				ctx.createCalendarItemFromMeetingRequest(refId, resp);
		};
		if (auto acc = std::get_if<tAcceptItem>(&item)) {
			if (acc->ReferenceItemId)
				updateRef(*acc->ReferenceItemId, respAccepted);
		} else if (auto tent = std::get_if<tTentativelyAcceptItem>(&item)) {
			if (tent->ReferenceItemId)
				updateRef(*tent->ReferenceItemId, respTentative);
		} else if (auto dec = std::get_if<tDeclineItem>(&item)) {
			if (dec->ReferenceItemId)
				updateRef(*dec->ReferenceItemId, respDeclined);
		}
		if (persist)
			msg.Items.emplace_back(ctx.create(dir, *targetFolder, *content));
		if (std::holds_alternative<tCalendarItem>(item) && sendMessages &&
		    request.SendMeetingInvitations == Enum::SendToAllAndSaveCopy) {
			sFolderSpec sentitems = ctx.resolveFolder(tDistinguishedFolderId(Enum::sentitems));
			uint64_t newMid;
			if (!ctx.plugin().exmdb.allocate_message_id(dir.c_str(),
				sentitems.folderId, &newMid))
				throw EWSError::InternalServerError(E3132);
			BOOL result;
			auto messageId = *content->proplist.get<const uint64_t>(PidTagMid);
			if (!ctx.plugin().exmdb.movecopy_message(dir.c_str(), CP_ACP,
				messageId, sentitems.folderId, newMid, false, &result)
				|| !result)
				throw EWSError::InternalServerError(E3301);
			const char* username = ctx.effectiveUser(sentitems);
			auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
			static constexpr uint8_t proptrue = 1;
			TAGGED_PROPVAL props[] = {
				{PR_MESSAGE_CLASS, deconst("IPM.Schedule.Meeting.Request")},
				{PR_RESPONSE_REQUESTED, deconst(&proptrue)},
				{PR_CLIENT_SUBMIT_TIME, now},
				{PR_MESSAGE_DELIVERY_TIME, now},
			};
			TPROPVAL_ARRAY proplist{std::size(props), props};
			PROBLEM_ARRAY problems;
			if (!ctx.plugin().exmdb.set_message_properties(dir.c_str(),
				username, CP_ACP, newMid, &proplist, &problems))
				throw EWSError::ItemSave(E3092);
			MESSAGE_CONTENT *sendcontent = nullptr;
			if (!ctx.plugin().exmdb.read_message(dir.c_str(),
				username, CP_ACP, newMid, &sendcontent)
				|| sendcontent == nullptr)
				throw EWSError::ItemNotFound(E3143);
			ctx.send(dir, messageId, *sendcontent);
		}
		if (send)
			ctx.send(dir, 0, *content);
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
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
		if (!(ctx.permissions(dir, parentFolder.folderId) & frightsEditAny))
			throw EWSError::AccessDenied(E3190);

		for (const tFileAttachment &att : request.Attachments) try {
			auto mInst = ctx.plugin().loadMessageInstance(dir,
			             mid.folderId(), mid.messageId());
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
				throw EWSError::ItemSave(E3094);

			ATTACHMENT_CONTENT ac{};
			std::vector<TAGGED_PROPVAL> props;
			if (att.Name) {
				props.push_back({PR_ATTACH_LONG_FILENAME, EWSContext::cpystr(*att.Name)});
				props.push_back({PR_ATTACH_FILENAME, EWSContext::cpystr(*att.Name)});
				props.push_back({PR_DISPLAY_NAME, EWSContext::cpystr(*att.Name)});
			}
			static constexpr uint32_t method = ATTACH_BY_VALUE;
			props.push_back({PR_ATTACH_METHOD, EWSContext::construct<uint32_t>(method)});
			if (att.IsInline && *att.IsInline) {
				static constexpr uint32_t flags = ATT_MHTML_REF;
				props.push_back({PR_ATTACH_FLAGS, EWSContext::construct<uint32_t>(flags)});
			}
			if (att.IsContactPhoto && *att.IsContactPhoto)
				props.push_back({PR_ATTACHMENT_CONTACTPHOTO, EWSContext::construct<uint8_t>(1)});
			if (att.Content) {
				auto bin = EWSContext::construct<BINARY>(BINARY{static_cast<uint32_t>(att.Content->size()), {EWSContext::alloc<uint8_t>(att.Content->size())}});
				memcpy(bin->pv, att.Content->data(), att.Content->size());
				props.push_back({PR_ATTACH_DATA_BIN, bin});
				props.push_back({PR_ATTACH_SIZE, EWSContext::construct<int32_t>(bin->cb)});
			}
			ac.proplist.count = props.size();
			ac.proplist.ppropval = props.data();
			ac.pembedded = nullptr;
			PROBLEM_ARRAY problems;
			if (!ctx.plugin().exmdb.write_attachment_instance(dir.c_str(),
			    aInstId, &ac, false, &problems))
				throw EWSError::ItemSave(E3094);
			ec_error_t err;
			if (!ctx.plugin().exmdb.flush_instance(dir.c_str(),
			    aInstId, &err) || err != ecSuccess)
				throw EWSError::ItemSave(E3094);

			sShape shape;
			ctx.updated(dir, mid, shape);
			TPROPVAL_ARRAY msgProps = shape.write();
			PROBLEM_ARRAY msgProblems;
			if (!ctx.plugin().exmdb.set_message_properties(dir.c_str(),
			    ctx.effectiveUser(parentFolder), CP_ACP, mid.messageId(),
			    &msgProps, &msgProblems))
				throw EWSError::ItemSave(E3092);

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
 * @brief      Process DeleteFolder
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mDeleteFolderRequest&& request, XMLElement* response, const EWSContext& ctx)
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
			uint64_t newParentId = rop_util_make_eid_ex(1, PRIVATE_FID_DELETED_ITEMS);
			ctx.moveCopyFolder(dir, folder, newParentId, accountId, false);
		} else {
			bool hard = request.DeleteType == Enum::HardDelete;
			BOOL result;
			if (!ctx.plugin().exmdb.delete_folder(dir.c_str(), CP_ACP,
			    folder.folderId, hard ? TRUE : false, &result) || !result)
				throw EWSError::CannotDeleteObject(E3165);
		}
		data.ResponseMessages.emplace_back().success();
	} catch(const EWSError& err) {
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
void process(mDeleteItemRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:DeleteItemResponse");

	mDeleteItemResponse data;
	data.ResponseMessages.reserve(request.ItemIds.size());
	auto& exmdb = ctx.plugin().exmdb;

	for (const tItemId &itemId : request.ItemIds) try {
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parent = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(parent);
		ctx.validate(dir, meid);
		if (!(ctx.permissions(dir, parent.folderId) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3131);
		if (request.DeleteType == Enum::MoveToDeletedItems) {
			uint64_t newMid;
			if (!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &newMid))
				throw EWSError::MoveCopyFailed(E3132);

			sFolderSpec deletedItems = ctx.resolveFolder(tDistinguishedFolderId(Enum::deleteditems));
			BOOL result;
			if (!exmdb.movecopy_message(dir.c_str(), CP_ACP,
			    meid.messageId(), deletedItems.folderId, newMid,
			    TRUE, &result) || !result)
				throw EWSError::MoveCopyFailed(E3133);

			data.ResponseMessages.emplace_back().success();
		} else {
			uint64_t eid = meid.messageId();
			uint64_t fid = rop_util_make_eid_ex(1, meid.folderId());
			EID_ARRAY eids{1, &eid};
			BOOL hardDelete = request.DeleteType == Enum::HardDelete ? TRUE : false;
			BOOL partial;
			if (!ctx.plugin().exmdb.delete_messages(dir.c_str(),
			    CP_ACP, ctx.effectiveUser(parent), fid, &eids,
			    hardDelete, &partial) || partial)
				throw EWSError::CannotDeleteObject(E3134);

			data.ResponseMessages.emplace_back().success();
		}
	} catch(const EWSError& err) {
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
void process(mEmptyFolderRequest&& request, XMLElement* response, const EWSContext& ctx)
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
	} catch(const EWSError& err) {
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
void process(mFindFolderRequest&& request, XMLElement* response, const EWSContext& ctx)
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
		if (!(ctx.permissions(dir, folder.folderId) & frightsVisible))
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
			data.ResponseMessages.emplace_back().success();
			continue;
		}
		ctx.getNamedTags(dir, shape);
		PROPTAG_ARRAY tags = shape.proptags();
		TARRAY_SET table;
		uint32_t offset = paging ? paging->offset(rowCount) : 0;
		uint32_t results = maxResults ? std::min(maxResults, rowCount - offset) : rowCount;
		exmdb.query_table(dir.c_str(), ctx.auth_info().username, CP_UTF8, tableId, &tags, offset,
			              results, &table);
		mFindFolderResponseMessage msg;
		msg.RootFolder.emplace().Folders.reserve(rowCount);
		for (const TPROPVAL_ARRAY &props : table) {
			shape.clean();
			shape.properties(props);
			sFolder& child = msg.RootFolder->Folders.emplace_back(tBaseFolderType::create(shape));
			const auto& fid = std::visit([](auto&& f) -> std::optional<tFolderId>& {return f.FolderId;}, child);
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
	} catch(const EWSError& err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process FindItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mFindItemRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:FindItemResponse");

	sShape shape(request.ItemShape);
	uint8_t tableFlags = request.Traversal == Enum::SoftDeleted ? TABLE_FLAG_SOFTDELETES :
	                     request.Traversal == Enum::Associated ? TABLE_FLAG_ASSOCIATED :
	                     request.Traversal == Enum::Shallow ? 0 : TABLE_FLAG_DEPTH;
	const RESTRICTION* res = nullptr; // Must be built for every store individually (named properties)
	const SORTORDER_SET* sort = nullptr; // Lol same
	std::string lastDir; // Simple restriction caching

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

	for (const sFolderId &folderId : request.ParentFolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			throw EWSError::AccessDenied(E3244);
		if (dir != lastDir) {
			auto getId = [&](const PROPERTY_NAME& name){return ctx.getNamedPropId(dir, name);};
			auto res1 = request.Restriction ? request.Restriction->build(getId) : nullptr;
			auto res2 = paging ? paging->restriction(getId) : nullptr;
			res = tRestriction::all(res1, res2);
			sort = request.SortOrder ? tFieldOrder::build(*request.SortOrder, getId) : nullptr;
			lastDir = dir;
		}
		uint32_t tableId, rowCount;
		if (!exmdb.load_content_table(dir.c_str(), CP_UTF8, folder.folderId,
		    "", tableFlags, res, sort, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3245);
		auto unloadTable = HX::make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
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
		PROPTAG_ARRAY tags = shape.proptags();
		TARRAY_SET table;
		uint32_t offset = paging ? paging->offset(rowCount) : 0;
		uint32_t results = maxResults ? std::min(maxResults, rowCount - offset) : rowCount;
		exmdb.query_table(dir.c_str(), ctx.auth_info().username, CP_UTF8, tableId, &tags, offset, results, &table);
		mFindItemResponseMessage msg;
		msg.RootFolder.emplace().Items.reserve(rowCount);
		for (const TPROPVAL_ARRAY &props : table) {
			shape.clean();
			shape.properties(props);
			sItem& child = msg.RootFolder->Items.emplace_back(tItem::create(shape));
			const auto& iid = std::visit([](auto&& i) -> std::optional<tItemId>& {return i.ItemId;}, child);
			if (shape.special && iid) {
				sMessageEntryId meid(iid->Id.data(), iid->Id.size());
				std::visit([&](auto& i) {ctx.loadSpecial(dir, meid.folderId(), meid.messageId(), i, shape.special);}, child);
			}
		}
		if (paging)
			paging->update(*msg.RootFolder, results, rowCount);
		msg.RootFolder->IncludesLastItemInRange = results + offset >= rowCount;
		msg.RootFolder->TotalItemsInView = rowCount;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
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
void process(mGetAppManifestsRequest&&, XMLElement* response, const EWSContext&)
{
	response->SetName("m:GetAppManifestsResponse");

	mGetAppManifestsResponse data;
	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetAttachment
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetAttachmentRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:GetAttachmentResponse");

	mGetAttachmentResponse data;
	data.ResponseMessages.reserve(request.AttachmentIds.size());
	for (const tRequestAttachmentId &raid : request.AttachmentIds) try {
		sAttachmentId aid(raid.Id.data(), raid.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(aid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, aid);
		if (!(ctx.permissions(dir, parentFolder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3135);
		mGetAttachmentResponseMessage msg;
		msg.Attachments.emplace_back(ctx.loadAttachment(dir, aid));
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
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
void process(mGetEventsRequest&& request, XMLElement* response, const EWSContext& ctx)
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
void process(mGetFolderRequest&& request, XMLElement* response, const EWSContext& ctx)
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
		if (!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			throw EWSError::AccessDenied(E3136);
		mGetFolderResponseMessage msg;
		msg.Folders.emplace_back(ctx.loadFolder(dir, folder.folderId, shape));
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

/**
 * @brief      Process GetInboxRulesRequest
 *
 * Provides the functionality of GetInboxRules
 *
 * In its current state it does nothing more than sending no rules response.
 *
 * @todo       This function lacks most of its functionality and is practically worthless.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetInboxRulesRequest&&, XMLElement* response, const EWSContext&)
{
	response->SetName("m:GetInboxRulesResponse");

	mGetInboxRulesResponse data;
	data.OutlookRuleBlobExists = false;

	data.success();
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
void process(mGetMailTipsRequest&& request, XMLElement* response, const EWSContext&)
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
 * @brief      Process GetRoomListsRequest
 */
void process(mGetRoomListsRequest&&, XMLElement* response, const EWSContext& ctx)
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
		throw DispatchError(E3027);

	mGetRoomListsResponse data;
	std::vector<tRoomListEntry> lists;
	lists.reserve(domain_ids.size());

	for (unsigned int domain_id : domain_ids) {
		sql_domain info;
		if (!mysql_adaptor_get_domain_info(domain_id, info))
			throw DispatchError(E3027);
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
void process(mGetRoomsRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:GetRoomsResponse");

	ctx.normalize(request.RoomList);
	if (!request.RoomList.EmailAddress)
		throw DispatchError(E3090("RoomList"));

	auto user_domain = extract_domain(ctx.auth_info().username);
	if (user_domain.empty())
		throw DispatchError(E3090(ctx.auth_info().username));
	unsigned int user_domain_id = 0, user_org_id = 0;
	resolve_domain_ids(user_domain, user_domain_id, user_org_id);

	auto target_domain = extract_domain(request.RoomList.EmailAddress->c_str());
	if (target_domain.empty())
		throw DispatchError(E3090(*request.RoomList.EmailAddress));
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
void process(mGetServiceConfigurationRequest&&, XMLElement* response, const EWSContext&)
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
 * Provides the functionality of GetUserAvailabilityRequest
 *
 * @todo       Implement timezone transformations
 * @todo       Check if error handling can be improved
 *             (using the response message instead of SOAP faults)
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUserAvailabilityRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:GetUserAvailabilityResponse");

	if (!request.FreeBusyViewOptions && !request.SuggestionsViewOptions)
		throw EWSError::InvalidFreeBusyViewType(E3013);
	if (!request.TimeZone) {
		auto tag = ctx.request().header;
		if (tag != nullptr)
			tag = tag->FirstChildElement("t:TimeZoneContext");
		if (tag != nullptr)
			tag = tag->FirstChildElement("t:TimeZoneDefinition");
		if (tag != nullptr)
			tag = tag->FirstChildElement("t:Periods");
		if (tag != nullptr)
			tag = tag->FirstChildElement("t:Period");
		/* Input is like <t:Period Bias="P0DT0H0M0.0S" Name="Standard" Id="Std" /> */
		auto bias = tag != nullptr ? tag->Attribute("Bias") : nullptr;
		if (bias != nullptr) {
			char *end = nullptr;
			auto minutes = HX_strtoull8601p_sec(bias, &end) / 60;
			if (minutes != 0 || end != nullptr)
				request.TimeZone.emplace(minutes);
		}
	}
	if (!request.TimeZone)
		throw EWSError::TimeZone(E3014);

	tDuration &TimeWindow = request.FreeBusyViewOptions ?
	                        request.FreeBusyViewOptions->TimeWindow :
	                        request.SuggestionsViewOptions->DetailedSuggestionsWindow;

	mGetUserAvailabilityResponse data;
	data.FreeBusyResponseArray.emplace().reserve(request.MailboxDataArray.size());
	for (const tMailboxData &MailboxData : request.MailboxDataArray) try {
		auto maildir = ctx.get_maildir(MailboxData.Email);
		auto start = clock::to_time_t(request.TimeZone->remove(TimeWindow.StartTime));
		auto end   = clock::to_time_t(request.TimeZone->remove(TimeWindow.EndTime));
		tFreeBusyView fbv(ctx.auth_info().username, maildir.c_str(), start, end);
		mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back(std::move(fbv));
		for (auto &event : *fbr.FreeBusyView->CalendarEventArray) {
			event.StartTime.offset = request.TimeZone->offset(event.StartTime.time);
			event.EndTime.offset = request.TimeZone->offset(event.EndTime.time);
		}
		fbr.ResponseMessage.emplace().success();
	} catch(const EWSError& err) {
		mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back();
		fbr.ResponseMessage.emplace(err);
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
void process(mGetStreamingEventsRequest&& request, XMLElement* response, EWSContext& ctx)
{
	response->SetName("m:GetStreamingEventsResponse");

	mGetStreamingEventsResponse data;
	mGetStreamingEventsResponseMessage& msg = data.ResponseMessages.emplace_back();

	ctx.enableEventStream(request.ConnectionTimeout);
	for (const tSubscriptionId &subscription : request.SubscriptionIds)
		if (!ctx.streamEvents(subscription))
			msg.ErrorSubscriptionIds.emplace_back(subscription);
	if (msg.ErrorSubscriptionIds.empty())
		msg.success();
	else
		msg.error("ErrorInvalidSubscription", "Subscription is invalid.");
	msg.ConnectionStatus = Enum::OK;

	data.serialize(response);
}

/**
 * @brief      Process GetUserConfigurationRequest
 *
 * Provides the functionality of GetUserConfiguration
 *
 * In its current state it does nothing more than sending not found response.
 *
 * @todo       This function lacks most of its functionality and is practically worthless.
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mGetUserConfigurationRequest&& request, XMLElement* response, const EWSContext& ctx)
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
		else if (reqName.FolderId.valueless_by_exception())
			throw EWSError::InvalidFolderId(E3252);

		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			throw EWSError::AccessDenied(E3218);

		std::string configClass = "IPM.Configuration." + reqName.Name;
		RESTRICTION_PROPERTY resProp{RELOP_EQ, PR_MESSAGE_CLASS,
			{PR_MESSAGE_CLASS, const_cast<char *>(configClass.c_str())}};
		RESTRICTION res{RES_PROPERTY, {&resProp}};

		uint32_t tableId = 0, rowCount = 0;
		const char *username = ctx.effectiveUser(folder);
		if (!exmdb.load_content_table(dir.c_str(), CP_UTF8, folder.folderId, username,
		    TABLE_FLAG_ASSOCIATED, &res, nullptr, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3245);
		auto unloadTable = HX::make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
		if (rowCount == 0)
			throw EWSError::ItemNotFound(E3143);

		static constexpr proptag_t midTag = PidTagMid;
		static constexpr PROPTAG_ARRAY midTags = {1, deconst(&midTag)};
		TARRAY_SET rows;
		exmdb.query_table(dir.c_str(), username, CP_UTF8, tableId, &midTags, 0, 1, &rows);
		if (rows.count == 0 || rows.pparray[0] == nullptr)
			throw EWSError::ItemNotFound(E3143);
		auto mid = rows.pparray[0]->get<const uint64_t>(PidTagMid);
		if (mid == nullptr)
			throw EWSError::ItemNotFound(E3143);

		static constexpr proptag_t propTags[] = {
			PR_ENTRYID, PR_CHANGE_KEY, PR_ROAMING_XMLSTREAM, PR_ROAMING_BINARYSTREAM,
		};
		const PROPTAG_ARRAY props = {std::size(propTags), deconst(propTags)};
		TPROPVAL_ARRAY propvals = ctx.getItemProps(dir, *mid, props);

		mGetUserConfigurationResponseMessage& msg = data.ResponseMessages.emplace_back();
		msg.UserConfiguration.emplace(tUserConfigurationType{reqName});
		auto &config = *msg.UserConfiguration;
		config.UserConfigurationName = reqName;

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
void process(mGetUserOofSettingsRequest&& request, XMLElement* response, const EWSContext& ctx)
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
	static constexpr struct cfg_directive oof_defaults[] = {
		{"allow_external_oof", "0", CFG_BOOL},
		{"external_audience", "0", CFG_BOOL},
		{"oof_state", "0"},
		CFG_TABLE_END,
	};
	std::string maildir = ctx.get_maildir(request.Mailbox);
	auto configPath = maildir + "/config/autoreply.cfg";
	auto configFile = config_file_init(configPath.c_str(), oof_defaults);
	unsigned int oof_state  = configFile != nullptr ? configFile->get_ll("oof_state") : 0;
	bool allow_external_oof = configFile != nullptr ? configFile->get_ll("allow_external_oof") : false;
	bool external_audience  = configFile != nullptr ? configFile->get_ll("external_audience") : false;
	switch (oof_state) {
	case 1:
		data.OofSettings->OofState = "Enabled"; break;
	case 2:
		data.OofSettings->OofState = "Scheduled"; break;
	default:
		data.OofSettings->OofState = "Disabled"; break;
	}
	if (allow_external_oof)
		data.OofSettings->ExternalAudience = external_audience ? "Known" : "All";
	else
		data.OofSettings->ExternalAudience = "None";
	auto start_time = configFile != nullptr ? configFile->get_value("start_time") : nullptr;
	auto end_time   = configFile != nullptr ? configFile->get_value("end_time") : nullptr;
	if (start_time != nullptr && end_time != nullptr) {
		tDuration& Duration = data.OofSettings->Duration.emplace();
		Duration.StartTime = clock::from_time_t(strtoll(start_time, nullptr, 0));
		Duration.EndTime = clock::from_time_t(strtoll(end_time, nullptr, 0));
	} else {
		auto &dur = data.OofSettings->Duration.emplace();
		dur.StartTime = clock::now();
		dur.EndTime = dur.StartTime + std::chrono::days(1);
	}
	auto reply = readMessageBody(maildir + "/config/internal-reply");
	if (reply)
		data.OofSettings->InternalReply.emplace(std::move(reply));
	else
		data.OofSettings->InternalReply.emplace(std::string{});
	if ((reply = readMessageBody(maildir + "/config/external-reply")))
		data.OofSettings->ExternalReply.emplace(std::move(reply));
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
void process(mGetUserPhotoRequest&& request, XMLElement* response, EWSContext& ctx)
{
	response->SetName("m:GetUserPhotoResponse");

	mGetUserPhotoResponse data;

	try {
		std::string dir = ctx.get_maildir(request.Email);
		PROPERTY_NAME photo = {MNID_STRING, PSETID_Gromox, 0, deconst("photo")};
		PROPNAME_ARRAY propNames{1, &photo};
		PROPID_ARRAY propIds = ctx.getNamedPropIds(dir, propNames);
		if (propIds.size() != 1)
			throw std::runtime_error("failed to get photo property id");
		proptag_t tag = PROP_TAG(PT_BINARY, propIds[0]);
		PROPTAG_ARRAY tags{1, &tag};
		TPROPVAL_ARRAY props;
		ctx.plugin().exmdb.get_store_properties(dir.c_str(), CP_ACP, &tags, & props);
		auto photodata = props.get<const BINARY>(tag);
		if (photodata && photodata->cb)
			data.PictureData = photodata;
		else
			ctx.code(http_status::not_found);
	} catch (const std::exception &err) {
		ctx.code(http_status::not_found);
		mlog(LV_WARN, "[ews#%d] Failed to load user photo: %s", ctx.context_id(), err.what());
	}
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
void process(const mBaseMoveCopyFolder& request, XMLElement* response, const EWSContext& ctx)
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
	} catch(const EWSError& err) {
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
void process(const mBaseMoveCopyItem& request, XMLElement* response, const EWSContext& ctx)
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

	for (const tItemId &itemId : request.ItemIds) try {
		if (!dstAccess)
			throw EWSError::AccessDenied(E3184);
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec sourceFolder = ctx.resolveFolder(meid);
		if (sourceFolder.target != dstFolder.target)
			throw EWSError::CrossMailboxMoveCopy(E3186);
		ctx.validate(dir, meid);
		if (!(ctx.permissions(dir, sourceFolder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3185);
		uint64_t newItemId = ctx.moveCopyItem(dir, meid, dstFolder.folderId, request.copy);
		auto& msg = std::visit([&](auto& d) -> mItemInfoResponseMessage&
			                   {return static_cast<mItemInfoResponseMessage&>(d.ResponseMessages.emplace_back());}, data);
		if (!request.ReturnNewItemIds || !*request.ReturnNewItemIds)
			msg.Items.emplace_back(ctx.loadItem(dir, dstFolder.folderId, newItemId, shape));
		msg.success();
	} catch(const EWSError& err) {
		std::visit([&](auto& d){d.ResponseMessages.emplace_back(err);}, data);
	}

	std::visit([&](auto& d){d.serialize(response);}, data);
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
void process(mSetUserOofSettingsRequest&& request, XMLElement* response, const EWSContext& ctx)
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
	int oof_state, allow_external_oof, external_audience;

	oof_state = OofSettings.OofState;

	std::string externalAudience = OofSettings.ExternalAudience;
	allow_external_oof = tolower_inplace(externalAudience) != "none";
	//Note: counterintuitive but intentional: known -> 1, all -> 0
	external_audience = externalAudience == "known";
	if (allow_external_oof && !external_audience && externalAudience != "all")
		throw DispatchError(E3009(OofSettings.ExternalAudience));

	std::string filename = maildir+"/config/autoreply.cfg";
	std::ofstream file(filename); /* FMODE_PUBLIC */
	file << "oof_state = " << oof_state << "\n"
	     << "allow_external_oof = " << allow_external_oof << "\n";
	if (allow_external_oof)
		file << "external_audience = " << external_audience << "\n";
	if (OofSettings.Duration)
		file << "start_time = " << clock::to_time_t(OofSettings.Duration->StartTime) << "\n"
		     << "end_time = " << clock::to_time_t(OofSettings.Duration->EndTime) << "\n";
	file.close();

	writeMessageBody(maildir+"/config/internal-reply", OofSettings.InternalReply);
	writeMessageBody(maildir+"/config/external-reply", OofSettings.ExternalReply);

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
void process(mSyncFolderHierarchyRequest&& request, XMLElement* response, const EWSContext& ctx)
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
void process(mSyncFolderItemsRequest&& request, XMLElement* response, const EWSContext& ctx)
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
	if (!(ctx.permissions(dir, folder.folderId) & frightsReadAny)) {
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
	sMailboxInfo mbinfo = ctx.getMailboxInfo(dir, folder.location == folder.PUBLIC);
	// Generate message entry IDs on the fly as we have all necessary information
	// Use template entry ID and fill in the message Id as needed
	sMessageEntryId templId = ctx.plugin().mkMessageEntryId(mbinfo, folder.folderId, rop_util_make_eid_ex(1, 0));

	uint32_t maxItems = request.MaxChangesReturned;
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
			if (eid_array_check(&updated_mids, mid))
				msg.Changes.emplace_back(tSyncFolderItemsUpdate{{{}, ctx.loadItem(dir, folder.folderId, mid, shape)}});
			else
				msg.Changes.emplace_back(tSyncFolderItemsCreate{{{}, ctx.loadItem(dir, folder.folderId, mid, shape)}});
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
				auto gc = rop_util_get_gc_value(last_cn);
				if (!syncState.seen.append_range(1, 1, gc) ||
				    (getFai && !syncState.seen_fai.append_range(1, 1, gc)))
					throw DispatchError(E3066);
			}
			if (last_readcn && !syncState.read.append_range(1, 1, rop_util_get_gc_value(last_readcn)))
				throw DispatchError(E3066);
			syncState.readOffset = 0;
		} else {
			syncState.readOffset = readSynced + unread_mids.count - skip;
		}
		msg.SyncState = syncState.serialize();
		msg.IncludesLastItemInRange = !clipped;
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
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
void process(mGetItemRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:GetItemResponse");

	mGetItemResponse data;
	data.ResponseMessages.reserve(request.ItemIds.size());
	sShape shape(request.ItemShape);
	for (auto &itemId : request.ItemIds) try {
		if (itemId.type != tItemId::ID_ITEM && itemId.type != tItemId::ID_OCCURRENCE)
			ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId eid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(eid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, eid);
		if (!(ctx.permissions(dir, parentFolder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3139);
		mGetItemResponseMessage msg;
		auto mid = eid.messageId();
		if (itemId.type == tItemId::ID_OCCURRENCE) {
			sOccurrenceId oid(itemId.Id.data(), itemId.Id.size());
			msg.Items.emplace_back(ctx.loadOccurrence(dir, parentFolder.folderId, mid, oid.basedate, shape));
		} else {
			msg.Items.emplace_back(ctx.loadItem(dir, parentFolder.folderId, mid, shape));
		}
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
		data.ResponseMessages.emplace_back(err);
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
void process(mResolveNamesRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:ResolveNamesResponse");

	mResolveNamesResponse data;

	const char *unres = strchr(request.UnresolvedEntry.c_str(), ':'); /* CONST-STRCHR-MARKER */
	unres = unres ? unres + 1 : request.UnresolvedEntry.c_str();
	request.UnresolvedEntry = gx_utf8_to_punycode(unres);

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
	resol.Mailbox.MailboxType = Enum::Mailbox; // Currently the only supported

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
 * @brief      Process SendItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSendItemRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:SendItemResponse");

	mSendItemResponse data;

	// Specified as explicit error in the documentation
	if (!request.SaveItemToFolder && request.SavedItemFolderId) {
		data.Responses.emplace_back(EWSError::InvalidSendItemSaveSettings(E3140));
		data.serialize(response);
		return;
	}
	sFolderSpec saveFolder = request.SavedItemFolderId ?
		ctx.resolveFolder(request.SavedItemFolderId->FolderId) :
		sFolderSpec(tDistinguishedFolderId(Enum::sentitems));
	if (request.SavedItemFolderId && !(ctx.permissions(ctx.getDir(saveFolder), saveFolder.folderId) & frightsCreate)) {
		data.Responses.emplace_back(EWSError::AccessDenied(E3141));
		data.serialize(response);
		return;
	}

	data.Responses.reserve(request.ItemIds.size());
	for (tItemId &itemId : request.ItemIds) try {
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec folder = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(folder);
		if (!(ctx.permissions(dir, folder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3142);

		MESSAGE_CONTENT *content = nullptr;
		if (!ctx.plugin().exmdb.read_message(dir.c_str(),
		    ctx.effectiveUser(folder), CP_ACP, meid.messageId(),
		    &content) || content == nullptr)
			throw EWSError::ItemNotFound(E3143);
		ctx.send(dir, rop_util_get_gc_value(meid.messageId()), *content);

		if (request.SaveItemToFolder)
			ctx.create(dir, folder, *content);

		data.Responses.emplace_back().success();
	} catch(const EWSError& err) {
		data.Responses.emplace_back(err);
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
void process(mUpdateFolderRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:UpdateFolderResponse");

	mUpdateFolderResponse data;
	data.ResponseMessages.reserve(request.FolderChanges.size());
	sShape idOnly((tFolderResponseShape()));

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
		TPROPVAL_ARRAY props = shape.write();
		PROPTAG_ARRAY tagsRm = shape.remove();
		PROBLEM_ARRAY problems;
		if (!ctx.plugin().exmdb.set_folder_properties(dir.c_str(), CP_ACP,
		    folder.folderId, &props, &problems))
			throw EWSError::FolderSave(E3175);
		if (!ctx.plugin().exmdb.remove_folder_properties(dir.c_str(),
		    folder.folderId, &tagsRm))
			throw EWSError::FolderSave(E3176);
		if (shape.permissionSet)
			ctx.writePermissions(dir, folder.folderId, tPermissionSet(shape.permissionSet).write());
		else if (shape.calendarPermissionSet)
			ctx.writePermissions(dir, folder.folderId, tCalendarPermissionSet(shape.calendarPermissionSet).write());
		ctx.updated(dir, folder);
		mUpdateFolderResponseMessage msg;
		msg.Folders.emplace_back(ctx.loadFolder(dir, folder.folderId, idOnly));
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
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
void process(mSubscribeRequest&& request, XMLElement* response, const EWSContext& ctx)
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
void process(mUnsubscribeRequest&& request, XMLElement* response, const EWSContext& ctx)
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
 * @brief      Process UpdateItem
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 *
 * @todo check whether instances should rathe be used
 */
void process(mUpdateItemRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("m:UpdateItemResponse");

	mUpdateItemResponse data;
	data.ResponseMessages.reserve(request.ItemChanges.size());

	sShape idOnly;
	idOnly.add(PR_ENTRYID, sShape::FL_FIELD).add(PR_CHANGE_KEY, sShape::FL_FIELD).add(PR_MESSAGE_CLASS);
	for (const auto &change : request.ItemChanges) try {
		ctx.assertIdType(change.ItemId.type, tFolderId::ID_ITEM);
		sMessageEntryId mid(change.ItemId.Id.data(), change.ItemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(mid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, mid);
		if (!(ctx.permissions(dir, parentFolder.folderId) & frightsEditAny))
			throw EWSError::AccessDenied(E3190);
		sShape shape(change);
		ctx.getNamedTags(dir, shape, true);
		for (const auto &update : change.Updates) {
			if (std::holds_alternative<tSetItemField>(update))
				std::get<tSetItemField>(update).put(shape);
		}
		tContact::genFields(shape);
		tCalendarItem::setDatetimeFields(shape);
		const char* username = ctx.effectiveUser(parentFolder);
		ctx.updated(dir, mid, shape);
		mUpdateItemResponseMessage msg;
		if (shape.mimeContent) {
			EWSContext::MCONT_PTR content = ctx.toContent(dir, *shape.mimeContent);
			for (auto tag : shape.remove())
				content->proplist.erase(tag);
			for (const auto &prop : shape.write()) {
				auto ret = content->proplist.set(prop);
				if (ret == ecServerOOM)
					throw EWSError::ItemSave(E3035);
			}
			auto error = content->proplist.set(PidTagMid, EWSContext::construct<uint64_t>(rop_util_make_eid(1, mid.message_gc)));
			if (error == ecServerOOM)
				throw EWSError::ItemSave(E3035);
			if (!content->proplist.has(PidTagChangeNumber))
				throw EWSError::ItemSave(E3255);
			uint64_t outmid = 0, outcn = 0;
			if (!ctx.plugin().exmdb.write_message(dir.c_str(),
			    CP_ACP, parentFolder.folderId, content.get(), {},
			    &outmid, &outcn, &error) || error != ecSuccess)
				throw EWSError::ItemSave(E3255);
		} else {
			TPROPVAL_ARRAY props = shape.write();
			PROPTAG_ARRAY tagsRm = shape.remove();
			PROBLEM_ARRAY problems;
			if (!ctx.plugin().exmdb.remove_message_properties(dir.c_str(),
			    CP_ACP, mid.messageId(), &tagsRm))
				throw EWSError::ItemSave(E3093);
			if (!ctx.plugin().exmdb.set_message_properties(dir.c_str(),
			    username, CP_ACP, mid.messageId(), &props, &problems))
				throw EWSError::ItemSave(E3092);
			msg.ConflictResults.Count = problems.count;
		}
		msg.Items.emplace_back(ctx.loadItem(dir, mid.folderId(), mid.messageId(), idOnly));
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
		data.ResponseMessages.emplace_back(err);
	}

	data.serialize(response);
}

}
