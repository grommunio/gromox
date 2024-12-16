// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <fstream>
#include <variant>
#include <sys/stat.h>
#include <sys/wait.h>
#include <tinyxml2.h>

#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/eid_array.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "exceptions.hpp"
#include "requests.hpp"

namespace gromox::EWS::Requests
{

using std::optional;
using std::string;
using std::min;
using std::max;
using namespace gromox;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

///////////////////////////////////////////////////////////////////////////////
//Helper functions

namespace
{

/**
 * @brief      Decode hex string
 *
 * @param      hex         Hex encoded input string
 *
 * @throw      InputError  Input string is not properly hex-encoded
 *
 * @return     String containing decoded binary data
 */
std::string hexDecode(const std::string& hex)
{
	static auto charVal = [](int c) {
		return (c >= '0' && c <= '9')? c-'0' : (c >= 'a' && c <= 'f')? c-'a'+10 : throw InputError(E3249(char(c)));
	};
	if(hex.size() % 2)
		throw InputError(E3250);
	std::string bin(hex.size()/2, 0);
	auto it = hex.begin();
	for(char& out : bin)
		out = char(charVal(tolower(*it++)) << 4 | charVal(tolower(*it++)));
	return bin;
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
	for(char in : bin) {
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
static inline std::string &tolower(std::string &str)
{
	transform(str.begin(), str.end(), str.begin(), ::tolower);
	return str;
}

/**
 * @brief      Read message body from reply file
 *
 * @param      path    Path to the file
 *
 * @return     Body content or empty optional on error
 */
optional<string> readMessageBody(const std::string& path) try
{
	std::ifstream ifs(path, std::ios::in | std::ios::ate | std::ios::binary);
	if(!ifs.is_open())
		return std::nullopt;
	size_t totalLength = ifs.tellg();
	ifs.seekg(std::ios::beg);
	while(!ifs.eof())
	{
		ifs.ignore(std::numeric_limits<std::streamsize>::max(), '\r');
		if(ifs.get() == '\n' && ifs.get() == '\r' && ifs.get() == '\n')
			break;
	}
	if(ifs.eof())
		return std::nullopt;
	size_t headerLenght = ifs.tellg();
	string content(totalLength-headerLenght, 0);
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
void writeMessageBody(const std::string& path, const optional<tReplyBody>& reply)
{
	if(!reply || !reply->Message)
		return (void) unlink(path.c_str());
	static constexpr char header[] = "Content-Type: text/html;\r\n\tcharset=\"utf-8\"\r\n\r\n";
	auto& content = *reply->Message;
	std::ofstream file(path, std::ios::binary); /* FMODE_PUBLIC */
	file.write(header, std::size(header)-1);
	file.write(content.c_str(), content.size());
	file.close();
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

	for(auto& sourceId : request.SourceIds) try {
		if(!std::holds_alternative<tAlternateId>(sourceId))
			throw EWSError::InternalServerError(E3251);
		tAlternateId& aid = std::get<tAlternateId>(sourceId);
		if(aid.Format == request.DestinationFormat)
			data.ResponseMessages.emplace_back().AlternateId = std::move(aid);
		else {
			std::string dir = ctx.get_maildir(aid.Mailbox);
			tBaseItemId id(sBase64Binary(aid.Format == Enum::HexEntryId? hexDecode(aid.Id) : base64_decode(aid.Id)),
				           tBaseItemId::ID_GUESS);
			if(id.type == tBaseItemId::ID_UNKNOWN)
				throw EWSError::CorruptData(E3252);
			mConvertIdResponseMessage msg;
			if(request.DestinationFormat == Enum::EwsId || request.DestinationFormat == Enum::EwsLegacyId)
				msg.AlternateId = tAlternateId(request.DestinationFormat, base64_encode(id.serializeId()), aid.Mailbox);
			else if(request.DestinationFormat == Enum::HexEntryId)
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

	sFolderSpec parent = ctx.resolveFolder(request.ParentFolderId.folderId);
	std::string dir = ctx.getDir(parent);
	bool hasAccess = ctx.permissions(dir, parent.folderId);

	for(const sFolder& folder : request.Folders) try {
		if(!hasAccess)
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
	if(request.SavedItemFolderId)
		targetFolder = ctx.resolveFolder(request.SavedItemFolderId->folderId);
	else
		targetFolder = ctx.resolveFolder(tDistinguishedFolderId("outbox"));
	std::string dir = ctx.getDir(*targetFolder);
	bool hasAccess = ctx.permissions(dir, targetFolder->folderId) & (frightsOwner | frightsCreate);

	if(!request.MessageDisposition)
		request.MessageDisposition = Enum::SaveOnly;
	if(!request.SendMeetingInvitations)
		request.SendMeetingInvitations = Enum::SendToNone;
	bool sendMessages = request.MessageDisposition == Enum::SendOnly || request.MessageDisposition == Enum::SendAndSaveCopy;

	data.ResponseMessages.reserve(request.Items.size());
	for(sItem& item : request.Items) try
	{
		if(!hasAccess)
			throw EWSError::AccessDenied(E3130);

		mCreateItemResponseMessage msg;
		bool persist = !(std::holds_alternative<tMessage>(item) && request.MessageDisposition == Enum::SendOnly);
		bool send = std::holds_alternative<tMessage>(item) &&	sendMessages;
		auto content = ctx.toContent(dir, *targetFolder, item, persist);
		if(persist)
			msg.Items.emplace_back(ctx.create(dir, *targetFolder, *content));
		if(send)
			ctx.send(dir, 0, *content);
		msg.success();
		data.ResponseMessages.emplace_back(std::move(msg));
	} catch(const EWSError& err) {
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

	static constexpr uint32_t parentFidTag = PidTagParentFolderId;
	static constexpr PROPTAG_ARRAY parentTags = {1, deconst(&parentFidTag)};

	mDeleteFolderResponse data;
	data.ResponseMessages.reserve(request.FolderIds.size());

	for(const tFolderId& folderId : request.FolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		if(folder.isDistinguished())
			throw EWSError::DeleteDistinguishedFolder(E3156);
		std::string dir = ctx.getDir(folder);
		TPROPVAL_ARRAY parentProps = ctx.getFolderProps(dir, folder.folderId, parentTags);
		auto parentFolderId = parentProps.get<const uint64_t>(parentFidTag);
		if(!parentFolderId)
			throw DispatchError(E3166);
		sFolderSpec parentFolder = folder;
		parentFolder.folderId = *parentFolderId;

		if(request.DeleteType == Enum::MoveToDeletedItems) {
			if(folder.location == folder.PUBLIC)
				throw EWSError::MoveCopyFailed(E3158);
			uint32_t accountId = ctx.getAccountId(ctx.auth_info().username, false);
			uint64_t newParentId = rop_util_make_eid_ex(1, PRIVATE_FID_DELETED_ITEMS);
			ctx.moveCopyFolder(dir, folder, newParentId, accountId, false);
		} else {
			bool hard = request.DeleteType == Enum::HardDelete;
			BOOL result;
			if(!ctx.plugin().exmdb.delete_folder(dir.c_str(), CP_ACP, folder.folderId, hard? TRUE : false, &result) || !result)
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

	for(const tItemId& itemId : request.ItemIds) try
	{
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parent = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(parent);
		ctx.validate(dir, meid);
		if(!(ctx.permissions(dir, parent.folderId) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3131);
		if(request.DeleteType == Enum::MoveToDeletedItems) {
			uint64_t newMid;
			if(!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &newMid))
				throw EWSError::MoveCopyFailed(E3132);

			sFolderSpec deletedItems = ctx.resolveFolder(tDistinguishedFolderId(Enum::deleteditems));
			BOOL result;
			if (!exmdb.movecopy_message(dir.c_str(), CP_ACP,
			    meid.messageId(), deletedItems.folderId, newMid,
			    TRUE, &result) || !result)
				throw EWSError::MoveCopyFailed(E3133);
			else
				data.ResponseMessages.emplace_back().success();
		} else {
			uint64_t eid = meid.messageId();
			uint64_t fid = rop_util_make_eid_ex(1, meid.folderId());
			EID_ARRAY eids{1, &eid};
			BOOL hardDelete = request.DeleteType == Enum::HardDelete? TRUE : false;
			BOOL partial;
			if (!ctx.plugin().exmdb.delete_messages(dir.c_str(),
			    CP_ACP, ctx.effectiveUser(parent), fid, &eids,
			    hardDelete, &partial) || partial)
				throw EWSError::CannotDeleteObject(E3134);
			else
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

	if(request.DeleteType == Enum::MoveToDeletedItems)
		throw DispatchError(E3181);
	uint32_t deleteFlags = DEL_MESSAGES | DEL_ASSOCIATED;
	deleteFlags |= (request.DeleteType == Enum::HardDelete? DELETE_HARD_DELETE : 0) |
	               (request.DeleteSubFolders? DEL_FOLDERS : 0);
	for(const sFolderId& folderId : request.FolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		if(!(ctx.permissions(dir, folder.folderId) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3179);
		const char* username = ctx.effectiveUser(folder);
		BOOL partial;
		if(!ctx.plugin().exmdb.empty_folder(dir.c_str(), CP_ACP, username, folder.folderId, deleteFlags, &partial)
		   || partial)
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
	uint8_t tableFlags = request.Traversal == Enum::Deep? TABLE_FLAG_DEPTH :
	                     request.Traversal == Enum::SoftDeleted? TABLE_FLAG_SOFTDELETES : 0;

	const RESTRICTION* res = nullptr; // Must be built for every store individually (named properties)
	std::string lastDir; // Simple restriction caching

	auto& exmdb = ctx.plugin().exmdb;
	mFindFolderResponse data;
	data.ResponseMessages.reserve(request.ParentFolderIds.size());
	tBasePagingType* paging = request.IndexedPageFolderView? &*request.IndexedPageFolderView :
	                          request.FractionalPageFolderView? &*request.FractionalPageFolderView :
	                          static_cast<tBasePagingType*>(nullptr);
	uint32_t maxResults = paging && paging->MaxEntriesReturned? *paging->MaxEntriesReturned : 0;

	for(const sFolderId&  folderId : request.ParentFolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		if(!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			throw EWSError::AccessDenied(E3218);
		if(dir != lastDir) {
			auto getId = [&](const PROPERTY_NAME& name){return ctx.getNamedPropId(dir, name);};
			res = request.Restriction? request.Restriction->build(getId) : nullptr;
			lastDir = dir;
		}
		uint32_t tableId, rowCount;
		const char* username = ctx.effectiveUser(folder);
		if(!exmdb.load_hierarchy_table(dir.c_str(), folder.folderId, username, tableFlags, res, &tableId, &rowCount))
			throw EWSError::FolderPropertyRequestFailed(E3219);
		auto unloadTable = make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
		if(!rowCount) {
			data.ResponseMessages.emplace_back().success();
			continue;
		}
		ctx.getNamedTags(dir, shape);
		PROPTAG_ARRAY tags = shape.proptags();
		TARRAY_SET table;
		uint32_t offset = paging? paging->offset(rowCount) : 0;
		uint32_t results = maxResults? std::min(maxResults, rowCount-offset) : rowCount;
		exmdb.query_table(dir.c_str(), ctx.auth_info().username, CP_UTF8, tableId, &tags, offset,
			              results, &table);
		mFindFolderResponseMessage msg;
		msg.RootFolder.emplace().Folders.reserve(rowCount);
		for(const TPROPVAL_ARRAY& props : table) {
			shape.clean();
			shape.properties(props);
			sFolder& child = msg.RootFolder->Folders.emplace_back(tBaseFolderType::create(shape));
			const auto& fid = std::visit([](auto&& f) -> std::optional<tFolderId>& {return f.FolderId;}, child);
			if(shape.special && fid)
				std::visit([&](auto& f) {ctx.loadSpecial(dir, sFolderEntryId(fid->Id.data(), fid->Id.size()).folderId(), f,
						                                 shape.special);}, child);
		}
		if(paging)
			paging->update(*msg.RootFolder, results, rowCount);
		msg.RootFolder->IncludesLastItemInRange = results+offset >= rowCount;
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
	uint8_t tableFlags = request.Traversal == Enum::SoftDeleted? TABLE_FLAG_SOFTDELETES :
	                     request.Traversal == Enum::Associated? TABLE_FLAG_ASSOCIATED :
	                     request.Traversal == Enum::Shallow? 0 : TABLE_FLAG_DEPTH;
	const RESTRICTION* res = nullptr; // Must be built for every store individually (named properties)
	const SORTORDER_SET* sort = nullptr; // Lol same
	std::string lastDir; // Simple restriction caching

	auto& exmdb = ctx.plugin().exmdb;
	mFindItemResponse data;
	data.ResponseMessages.reserve(request.ParentFolderIds.size());
	// Specified as variant, so as long as at most one is given everything works as expected
	tBasePagingType* paging = request.IndexedPageItemView? &*request.IndexedPageItemView :
	                          request.FractionalPageItemView? &*request.FractionalPageItemView :
	                          request.CalendarView? &*request.CalendarView :
	                          request.ContactsView? &*request.ContactsView :
	                          static_cast<tBasePagingType*>(nullptr);
	uint32_t maxResults = paging && paging->MaxEntriesReturned? *paging->MaxEntriesReturned : 0;

	for(const sFolderId&  folderId : request.ParentFolderIds) try {
		sFolderSpec folder = ctx.resolveFolder(folderId);
		std::string dir = ctx.getDir(folder);
		if(!(ctx.permissions(dir, folder.folderId) & frightsVisible))
			throw EWSError::AccessDenied(E3244);
		if(dir != lastDir) {
			auto getId = [&](const PROPERTY_NAME& name){return ctx.getNamedPropId(dir, name);};
			RESTRICTION* res1 = request.Restriction? request.Restriction->build(getId) : nullptr;
			RESTRICTION* res2 = paging? paging->restriction(getId) : nullptr;
			res = tRestriction::all(res1, res2);
			sort = request.SortOrder? tFieldOrder::build(*request.SortOrder, getId) : nullptr;
			lastDir = dir;
		}
		uint32_t tableId, rowCount;
		if(!exmdb.load_content_table(dir.c_str(), CP_UTF8, folder.folderId, "", tableFlags, res, sort, &tableId, &rowCount))
			throw EWSError::ItemPropertyRequestFailed(E3245);
		auto unloadTable = make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
		if(!rowCount) {
			data.ResponseMessages.emplace_back().success();
			continue;
		}
		ctx.getNamedTags(dir, shape);
		PROPTAG_ARRAY tags = shape.proptags();
		TARRAY_SET table;
		uint32_t offset = paging? paging->offset(rowCount) : 0;
		uint32_t results = maxResults? std::min(maxResults, rowCount-offset) : rowCount;
		exmdb.query_table(dir.c_str(), ctx.auth_info().username, CP_UTF8, tableId, &tags, offset, results, &table);
		mFindItemResponseMessage msg;
		msg.RootFolder.emplace().Items.reserve(rowCount);
		for(const TPROPVAL_ARRAY& props : table) {
			shape.clean();
			shape.properties(props);
			sItem& child = msg.RootFolder->Items.emplace_back(tItem::create(shape));
			const auto& iid = std::visit([](auto&& i) -> std::optional<tItemId>& {return i.ItemId;}, child);
			if(shape.special && iid) {
				sMessageEntryId meid(iid->Id.data(), iid->Id.size());
				std::visit([&](auto& i) {ctx.loadSpecial(dir, meid.folderId(), meid.messageId(), i, shape.special);}, child);
			}
		}
		if(paging)
			paging->update(*msg.RootFolder, results, rowCount);
		msg.RootFolder->IncludesLastItemInRange = results+offset >= rowCount;
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
	for(const tRequestAttachmentId& raid : request.AttachmentIds) try
	{
		sAttachmentId aid(raid.Id.data(), raid.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(aid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, aid);
		if(!(ctx.permissions(dir, parentFolder.folderId) & frightsReadAny))
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
		if(notification.events.empty())
			notification.events.emplace_back(aStatusEvent());
		msg.success();
	} catch(EWSError& err) {
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
	for(auto& folderId : request.FolderIds) try
	{
		sFolderSpec folder;
		folder = ctx.resolveFolder(folderId);
		if(!folder.target)
			folder.target = ctx.auth_info().username;
		folder.normalize();
		std::string dir = ctx.getDir(folder);
		if(!(ctx.permissions(dir, folder.folderId) & frightsVisible))
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

	for(auto& recipient : request.Recipients)
	{
		mMailTipsResponseMessageType& mailTipsResponseMessage = data.ResponseMessages.emplace_back();
		tMailTips& mailTips = mailTipsResponseMessage.MailTips.emplace();
		mailTips.RecipientAddress = std::move(recipient);
		mailTips.RecipientAddress.Name.emplace("");
		mailTipsResponseMessage.success();
	}

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

	if(!request.FreeBusyViewOptions && !request.SuggestionsViewOptions)
		throw EWSError::InvalidFreeBusyViewType(E3013);
	if(!request.TimeZone)
		throw EWSError::TimeZone(E3014);

	tDuration& TimeWindow = request.FreeBusyViewOptions? request.FreeBusyViewOptions->TimeWindow :
	                                                     request.SuggestionsViewOptions->DetailedSuggestionsWindow;

	mGetUserAvailabilityResponse data;
	data.FreeBusyResponseArray.emplace().reserve(request.MailboxDataArray.size());
	for(const tMailboxData& MailboxData : request.MailboxDataArray) try
	{
		string maildir = ctx.get_maildir(MailboxData.Email);
		auto start = clock::to_time_t(request.TimeZone->remove(TimeWindow.StartTime));
		auto end   = clock::to_time_t(request.TimeZone->remove(TimeWindow.EndTime));
		tFreeBusyView fbv(ctx.auth_info().username, maildir.c_str(), start, end);
		mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back(std::move(fbv));
		for(auto& event : *fbr.FreeBusyView->CalendarEventArray)
		{
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
	for(const tSubscriptionId& subscription : request.SubscriptionIds)
		if(!ctx.streamEvents(subscription))
			msg.ErrorSubscriptionIds.emplace_back(subscription);
	if(msg.ErrorSubscriptionIds.empty())
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
void process(mGetUserConfigurationRequest&&, XMLElement* response, const EWSContext&)
{
	response->SetName("m:GetUserConfigurationResponse");

	mGetUserConfigurationResponse data;
	mGetUserConfigurationResponseMessage& msg = data.ResponseMessages.emplace_back();

	msg.error("ErrorItemNotFound", "Object not found in the information store");
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
	if(strcasecmp(request.Mailbox.Address.c_str(), ctx.auth_info().username)) {
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
	string configPath = maildir+"/config/autoreply.cfg";
	auto configFile = config_file_init(configPath.c_str(), oof_defaults);
	if(configFile) {
		auto oof_state          = configFile->get_ll("oof_state");
		auto allow_external_oof = configFile->get_ll("allow_external_oof");
		auto external_audience  = configFile->get_ll("external_audience");
		switch(oof_state) {
		case 1:
			data.OofSettings->OofState = "Enabled"; break;
		case 2:
			data.OofSettings->OofState = "Scheduled"; break;
		default:
			data.OofSettings->OofState = "Disabled"; break;
		}
		if(allow_external_oof)
			data.OofSettings->ExternalAudience = external_audience? "Known" : "All";
		else
			data.OofSettings->ExternalAudience = "None";
		auto start_time = configFile->get_value("start_time");
		auto end_time = configFile->get_value("end_time");
		if (start_time != nullptr && end_time != nullptr) {
			tDuration& Duration = data.OofSettings->Duration.emplace();
			Duration.StartTime = clock::from_time_t(strtoll(start_time, nullptr, 0));
			Duration.EndTime = clock::from_time_t(strtoll(end_time, nullptr, 0));
		}
		optional<string> reply = readMessageBody(maildir+"/config/internal-reply");
		if(reply)
			data.OofSettings->InternalReply.emplace(std::move(reply));
		if((reply = readMessageBody(maildir+"/config/external-reply")))
			data.OofSettings->ExternalReply.emplace(std::move(reply));
	} else
	{
		data.OofSettings->OofState = "Disabled";
		data.OofSettings->ExternalAudience = "None";
	}

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
		uint32_t tag = PROP_TAG(PT_BINARY, propIds[0]);
		PROPTAG_ARRAY tags{1, &tag};
		TPROPVAL_ARRAY props;
		ctx.plugin().exmdb.get_store_properties(dir.c_str(), CP_ACP, &tags, & props);
		auto photodata = props.get<const BINARY>(tag);
		if(photodata && photodata->cb)
			data.PictureData = photodata;
		else
			ctx.code(http_status::not_found);
	} catch(std::exception& err){
		ctx.code(http_status::not_found);
		mlog(LV_WARN, "[ews#%d] Failed to load user photo: %s", ctx.ID(), err.what());
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
	response->SetName(request.copy? "m:CopyFolderResponse" : "m:MoveFolderResponse");

	sFolderSpec dstFolder = ctx.resolveFolder(request.ToFolderId.folderId);
	std::string dir = ctx.getDir(dstFolder);
	uint32_t accountId = ctx.getAccountId(ctx.auth_info().username, false);

	bool dstAccess = ctx.permissions(dir, dstFolder.folderId);

	using MCResponse = std::variant<mCopyFolderResponse, mMoveFolderResponse>;
	auto data = request.copy ? MCResponse(std::in_place_index_t<0>{}) :
	            MCResponse(std::in_place_index_t<1>{});
	std::visit([&](auto& d){d.ResponseMessages.reserve(request.FolderIds.size());}, data);

	sShape shape = sShape(tFolderResponseShape());

	for(const tFolderId& folderId : request.FolderIds) try {
		if(!dstAccess)
			throw EWSError::AccessDenied(E3167);
		sFolderSpec folder = ctx.resolveFolder(folderId);
		if(folder.location != dstFolder.location) // Attempt to move to a different store
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
	response->SetName(request.copy? "m:CopyItemResponse" : "m:MoveItemResponse");

	sFolderSpec dstFolder = ctx.resolveFolder(request.ToFolderId.folderId);
	std::string dir = ctx.getDir(dstFolder);

	bool dstAccess = ctx.permissions(dir, dstFolder.folderId);

	using MCResponse = std::variant<mCopyItemResponse, mMoveItemResponse>;
	auto data = request.copy ? MCResponse(std::in_place_index_t<0>{}) :
	            MCResponse(std::in_place_index_t<1>{});
	std::visit([&](auto& d){d.ResponseMessages.reserve(request.ItemIds.size());}, data);

	sShape shape = sShape(tItemResponseShape());

	for(const tItemId& itemId : request.ItemIds) try {
		if(!dstAccess)
			throw EWSError::AccessDenied(E3184);
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec sourceFolder = ctx.resolveFolder(meid);
		if(sourceFolder.target != dstFolder.target)
			throw EWSError::CrossMailboxMoveCopy(E3186);
		ctx.validate(dir, meid);
		if(!(ctx.permissions(dir, sourceFolder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3185);
		uint64_t newItemId = ctx.moveCopyItem(dir, meid, dstFolder.folderId, request.copy);
		auto& msg = std::visit([&](auto& d) -> mItemInfoResponseMessage&
			                   {return static_cast<mItemInfoResponseMessage&>(d.ResponseMessages.emplace_back());}, data);
		if(!request.ReturnNewItemIds || !*request.ReturnNewItemIds)
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
	if(strcasecmp(request.Mailbox.Address.c_str(), ctx.auth_info().username)){
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
	allow_external_oof = !(tolower(externalAudience) == "none");
	//Note: counterintuitive but intentional: known -> 1, all -> 0
	external_audience = externalAudience == "known";
	if(allow_external_oof && !external_audience && externalAudience != "all")
		throw DispatchError(E3009(OofSettings.ExternalAudience));

	std::string filename = maildir+"/config/autoreply.cfg";
	std::ofstream file(filename); /* FMODE_PUBLIC */
	file << "oof_state = " << oof_state << "\n"
	     << "allow_external_oof = " << allow_external_oof << "\n";
	if(allow_external_oof)
		file << "external_audience = " << external_audience << "\n";
	if(OofSettings.Duration)
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
	if(!request.SyncFolderId)
		request.SyncFolderId.emplace(tDistinguishedFolderId(Enum::msgfolderroot));

	sSyncState syncState;
	if(request.SyncState && !request.SyncState->empty())
		syncState.init(*request.SyncState);
	syncState.convert();

	sFolderSpec folder = ctx.resolveFolder(request.SyncFolderId->folderId);
	if(!folder.target)
		folder.target = ctx.auth_info().username;
	std::string dir = ctx.getDir(folder.normalize());

	mSyncFolderHierarchyResponse data;
	if(!(ctx.permissions(dir, folder.folderId) & frightsVisible))
	{
		data.ResponseMessages.emplace_back(EWSError::AccessDenied(E3137));
		data.serialize(response);
		return;
	}

	FOLDER_CHANGES changes;
	uint64_t lastCn;
	EID_ARRAY given_fids, deleted_fids;
	if(!exmdb.get_hierarchy_sync(dir.c_str(), folder.folderId, ctx.effectiveUser(folder),
	                             &syncState.given, &syncState.seen, &changes, &lastCn, &given_fids, &deleted_fids))
		throw DispatchError(E3030);

	sShape shape(request.FolderShape);

	mSyncFolderHierarchyResponseMessage& msg = data.ResponseMessages.emplace_back();
	auto& msgChanges = msg.Changes.emplace();
	msgChanges.reserve(changes.count+deleted_fids.count);
	for (const auto &folderProps : changes) {
		auto folderId = folderProps.get<uint64_t>(PidTagFolderId);
		if(!folderId)
			continue;
		folder.folderId = *folderId;
		if(!(ctx.permissions(dir, folder.folderId) & frightsVisible))
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

	sFolderSpec folder = ctx.resolveFolder(request.SyncFolderId.folderId);

	sSyncState syncState;
	if(request.SyncState && !request.SyncState->empty())
		syncState.init(*request.SyncState);
	syncState.convert();

	if(!folder.target)
		folder.target = ctx.auth_info().username;
	std::string dir = ctx.getDir(folder.normalize());

	mSyncFolderItemsResponse data;
	if(!(ctx.permissions(dir, folder.folderId) & frightsReadAny))
	{
		data.ResponseMessages.emplace_back(EWSError::AccessDenied(E3138));
		data.serialize(response);
		return;
	}
	auto& exmdb = ctx.plugin().exmdb;

	uint32_t fai_count, normal_count;
	uint64_t fai_total, normal_total, last_cn, last_readcn;
	EID_ARRAY updated_mids, chg_mids, given_mids, deleted_mids, nolonger_mids, read_mids, unread_mids;
	bool getFai = request.SyncScope && *request.SyncScope == Enum::NormalAndAssociatedItems;
	idset* pseen_fai = getFai? &syncState.seen : nullptr;
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
		msg.Changes.reserve(min(chg_mids.count+deleted_mids.count+read_mids.count+unread_mids.count, maxItems));
		maxItems -= deleted_mids.count = min(deleted_mids.count, maxItems);
		for (auto mid : deleted_mids) {
			msg.Changes.emplace_back(tSyncFolderItemsDelete(templId.messageId(mid).serialize()));
			syncState.given.remove(mid);
		}
		clipped = clipped || nolonger_mids.count > maxItems;
		maxItems -= nolonger_mids.count = min(nolonger_mids.count, maxItems);
		for (auto mid : nolonger_mids) {
			msg.Changes.emplace_back(tSyncFolderItemsDelete(templId.messageId(mid).serialize()));
			syncState.given.remove(mid);
		}
		clipped = clipped || chg_mids.count > maxItems;
		maxItems -= chg_mids.count = min(chg_mids.count, maxItems);
		for (auto mid : chg_mids) {
			auto changeNum = ctx.getItemProp<const uint64_t>(dir, mid, PidTagChangeNumber);
			if(!changeNum)
				continue;
			if(eid_array_check(&updated_mids, mid))
				msg.Changes.emplace_back(tSyncFolderItemsUpdate{{{}, ctx.loadItem(dir, folder.folderId, mid, shape)}});
			else
				msg.Changes.emplace_back(tSyncFolderItemsCreate{{{}, ctx.loadItem(dir, folder.folderId, mid, shape)}});
			if(!syncState.given.append(mid) || !syncState.seen.append(*changeNum))
				throw DispatchError(E3065);
		}
		uint32_t readSynced = syncState.readOffset;
		uint32_t skip = min(syncState.readOffset, read_mids.count);
		read_mids.count = min(read_mids.count-skip, maxItems)+skip;
		maxItems -= read_mids.count-skip;
		clipped = clipped || read_mids.count-skip > maxItems;
		for (auto mid : read_mids)
			msg.Changes.emplace_back(tSyncFolderItemsReadFlag{{}, tItemId(templId.messageId(mid).serialize()), true});
		readSynced += read_mids.count-skip;
		skip = min(unread_mids.count, syncState.readOffset-read_mids.count+skip);
		unread_mids.count = min(unread_mids.count-skip, maxItems)+skip;
		clipped = clipped || unread_mids.count-skip > maxItems;
		for (auto mid : unread_mids)
			msg.Changes.emplace_back(tSyncFolderItemsReadFlag{{}, tItemId(templId.messageId(mid).serialize()), false});
		if(!clipped)
		{
			syncState.seen.clear();
			syncState.read.clear();
			if((last_cn && !syncState.seen.append_range(1, 1, rop_util_get_gc_value(last_cn))) ||
			   (last_readcn && !syncState.read.append_range(1, 1, rop_util_get_gc_value(last_readcn))))
				throw DispatchError(E3066);
			syncState.readOffset = 0;
		}
		else
			syncState.readOffset = readSynced+unread_mids.count-skip;
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
	for(auto& itemId : request.ItemIds) try {
		if(itemId.type != tItemId::ID_ITEM && itemId.type != tItemId::ID_OCCURRENCE)
			ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId eid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(eid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, eid);
		if(!(ctx.permissions(dir, parentFolder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3139);
		mGetItemResponseMessage msg;
		auto mid = eid.messageId();
		if(itemId.type == tItemId::ID_OCCURRENCE) {
			sOccurrenceId oid(itemId.Id.data(), itemId.Id.size());
			msg.Items.emplace_back(ctx.loadOccurrence(dir, parentFolder.folderId, mid, oid.basedate, shape));
		} else
			msg.Items.emplace_back(ctx.loadItem(dir, parentFolder.folderId, mid, shape));
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
	unres = unres? unres+1 : request.UnresolvedEntry.c_str();
	request.UnresolvedEntry = gx_utf8_to_punycode(unres);

	TPROPVAL_ARRAY userProps{};
	if (!mysql_adaptor_get_user_properties(request.UnresolvedEntry.c_str(), userProps))
		throw DispatchError(E3067);
	if(!userProps.count) {
		data.ResponseMessages.emplace_back(EWSError::NameResolutionNoResults(E3259));
		data.serialize(response);
		return;
	}
	TAGGED_PROPVAL* displayName = userProps.find(PR_DISPLAY_NAME);

	mResolveNamesResponseMessage& msg = data.ResponseMessages.emplace_back();
	auto& resolutionSet = msg.ResolutionSet.emplace();
	tResolution& resol = resolutionSet.emplace_back();
	resol.Mailbox.Name = displayName? static_cast<const char*>(displayName->pvalue) : request.UnresolvedEntry;
	resol.Mailbox.EmailAddress = request.UnresolvedEntry;
	resol.Mailbox.RoutingType = "SMTP";
	resol.Mailbox.MailboxType = Enum::Mailbox; // Currently the only supported

	tContact& cnt = resol.Contact.emplace(sShape(userProps));
	tpropval_array_free_internal(&userProps);

	std::vector<std::string> aliases;
	if (!mysql_adaptor_get_user_aliases(request.UnresolvedEntry.c_str(), aliases))
		throw DispatchError(E3068);
	if (aliases.size() > 0) {
		aliases.resize(min(aliases.size(), static_cast<size_t>(3)));
		cnt.EmailAddresses.emplace().reserve(aliases.size());
		uint8_t index = 0;
		for (auto& alias : aliases)
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
	if(!request.SaveItemToFolder && request.SavedItemFolderId) {
		data.Responses.emplace_back(EWSError::InvalidSendItemSaveSettings(E3140));
		data.serialize(response);
		return;
	}
	sFolderSpec saveFolder = request.SavedItemFolderId? ctx.resolveFolder(request.SavedItemFolderId->folderId) :
	                                                    sFolderSpec(tDistinguishedFolderId(Enum::sentitems));
	if(request.SavedItemFolderId && !(ctx.permissions(ctx.getDir(saveFolder), saveFolder.folderId) & frightsCreate)) {
		data.Responses.emplace_back(EWSError::AccessDenied(E3141));
		data.serialize(response);
		return;
	}

	data.Responses.reserve(request.ItemIds.size());
	for(tItemId& itemId : request.ItemIds) try {
		ctx.assertIdType(itemId.type, tItemId::ID_ITEM);
		sMessageEntryId meid(itemId.Id.data(), itemId.Id.size());
		sFolderSpec folder = ctx.resolveFolder(meid);
		std::string dir = ctx.getDir(folder);
		if(!(ctx.permissions(dir, folder.folderId) & frightsReadAny))
			throw EWSError::AccessDenied(E3142);

		MESSAGE_CONTENT *content = nullptr;
		if (!ctx.plugin().exmdb.read_message(dir.c_str(),
		    ctx.effectiveUser(folder), CP_ACP, meid.messageId(),
		    &content) || content == nullptr)
			throw EWSError::ItemNotFound(E3143);
		ctx.send(dir, rop_util_get_gc_value(meid.messageId()), *content);

		if(request.SaveItemToFolder)
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

	for(const auto& change : request.FolderChanges) try {
		sFolderSpec folder = ctx.resolveFolder(change.folderId);
		std::string dir = ctx.getDir(folder);
		if(!(ctx.permissions(dir, folder.folderId) & frightsEditAny))
			throw EWSError::AccessDenied(E3174);
		sShape shape(change);
		ctx.getNamedTags(dir, shape, true);
		for(const auto& update : change.Updates) {
			if (std::holds_alternative<tSetFolderField>(update))
				std::get<tSetFolderField>(update).put(shape);
		}
		TPROPVAL_ARRAY props = shape.write();
		PROPTAG_ARRAY tagsRm = shape.remove();
		PROBLEM_ARRAY problems;
		if(!ctx.plugin().exmdb.set_folder_properties(dir.c_str(), CP_ACP,folder.folderId, &props, &problems))
			throw EWSError::FolderSave(E3175);
		if(!ctx.plugin().exmdb.remove_folder_properties(dir.c_str(), folder.folderId, &tagsRm))
			throw EWSError::FolderSave(E3176);
		if(shape.permissionSet)
			ctx.writePermissions(dir, folder.folderId, tPermissionSet(shape.permissionSet).write());
		else if(shape.calendarPermissionSet)
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
	if(ctx.unsubscribe(request.SubscriptionId))
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
	for(const auto& change : request.ItemChanges) try {
		ctx.assertIdType(change.ItemId.type, tFolderId::ID_ITEM);
		sMessageEntryId mid(change.ItemId.Id.data(), change.ItemId.Id.size());
		sFolderSpec parentFolder = ctx.resolveFolder(mid);
		std::string dir = ctx.getDir(parentFolder);
		ctx.validate(dir, mid);
		if(!(ctx.permissions(dir, parentFolder.folderId) & frightsEditAny))
			throw EWSError::AccessDenied(E3190);
		sShape shape(change);
		ctx.getNamedTags(dir, shape, true);
		for(const auto& update : change.Updates) {
			if (std::holds_alternative<tSetItemField>(update))
				std::get<tSetItemField>(update).put(shape);
		}
		tContact::genFields(shape);
		const char* username = ctx.effectiveUser(parentFolder);
		ctx.updated(dir, mid, shape);
		mUpdateItemResponseMessage msg;
		if(shape.mimeContent) {
			EWSContext::MCONT_PTR content = ctx.toContent(dir, *shape.mimeContent);
			for(uint32_t tag : shape.remove())
				content->proplist.erase(tag);
			for (const auto &prop : shape.write()) {
				auto ret = content->proplist.set(prop);
				if (ret == -ENOMEM)
					throw EWSError::ItemSave(E3035);
			}
			auto ret = content->proplist.set(PidTagMid, EWSContext::construct<uint64_t>(rop_util_make_eid(1, mid.message_global_counter)));
			if (ret == -ENOMEM)
				throw EWSError::ItemSave(E3035);
			ec_error_t error;
			if (!ctx.plugin().exmdb.write_message(dir.c_str(),
			    CP_ACP, parentFolder.folderId, content.get(),
			    &error) || error)
				throw EWSError::ItemSave(E3255);
		} else {
			TPROPVAL_ARRAY props = shape.write();
			PROPTAG_ARRAY tagsRm = shape.remove();
			PROBLEM_ARRAY problems;
			if(!ctx.plugin().exmdb.remove_message_properties(dir.c_str(), CP_ACP, mid.messageId(), &tagsRm))
				throw EWSError::ItemSave(E3093);
			if(!ctx.plugin().exmdb.set_message_properties(dir.c_str(), username, CP_ACP, mid.messageId(), &props, &problems))
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
