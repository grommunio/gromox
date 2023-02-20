// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#include <algorithm>
#include <fstream>

#include <sys/stat.h>
#include <sys/wait.h>
#include <tinyxml2.h>

#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>

#include "exceptions.hpp"
#include "requests.hpp"

namespace gromox::EWS::Requests
{

using namespace gromox;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace std;
using namespace tinyxml2;

using Clock = time_point::clock;
using std::to_string;

///////////////////////////////////////////////////////////////////////////////
//Helper functions

namespace
{

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
	ifstream ifs(path, ios::in | ios::ate | ios::binary);
	if(!ifs.is_open())
		return nullopt;
	size_t totalLength = ifs.tellg();
	ifs.seekg(ios::beg);
	while(!ifs.eof())
	{
		ifs.ignore(numeric_limits<std::streamsize>::max(), '\r');
		if(ifs.get() == '\n' && ifs.get() == '\r' && ifs.get() == '\n')
			break;
	}
	if(ifs.eof())
		return nullopt;
	size_t headerLenght = ifs.tellg();
	string content(totalLength-headerLenght, 0);
	ifs.read(content.data(), content.size());
	return content;
} catch (const std::exception &e) {
	mlog(LV_ERR, "[ews] %s\n", e.what());
	return nullopt;
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
	static const char header[] = "Content-Type: text/html;\r\n\tcharset=\"utf-8\"\r\n\r\n";
	auto& content = *reply->Message;
	ofstream file(path, ios::binary);
	file.write(header, std::size(header)-1);
	file.write(content.c_str(), content.size());
	file.close();
	chmod(path.c_str(), 0666);
}

} //anonymous namespace
///////////////////////////////////////////////////////////////////////
//Request implementations

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
	ctx.experimental();

	response->SetName("m:GetFolderResponse");

	sProptags requestedTags = ctx.collectTags(request.FolderShape);
	if(requestedTags.tags.size() > std::numeric_limits<decltype(PROPTAG_ARRAY::count)>::max())
		throw InputError(E3029);
	const PROPTAG_ARRAY tags{uint16_t(requestedTags.tags.size()), requestedTags.tags.data()};

	mGetFolderResponse data;
	data.ResponseMessages.reserve(request.FolderIds.size());
	for(auto& folderId : request.FolderIds)
	{
		sFolderSpec folderSpec;
		try {
			folderSpec = std::visit([&ctx](auto&& v){return ctx.resolveFolder(v);}, folderId);
		} catch (DeserializationError& err) {
			data.ResponseMessages.emplace_back("Error", "ErrorFolderNotFound", err.what());
			continue;
		}
		if(!folderSpec.target)
			folderSpec.target = ctx.auth_info.username;
		folderSpec.normalize();

		mGetFolderResponseMessage& msg = data.ResponseMessages.emplace_back();
		TPROPVAL_ARRAY folderProps = ctx.getFolderProps(folderSpec, tags);
		msg.Folders.emplace_back(tBaseFolderType::create(folderProps));

		msg.success();
	}
	data.serialize(response);
}

/**
 * @brief      Process GetMailTipsRequest
 *
 * Provides the functionality of GetMailTips
 * (../php/ews/exchange.php:398).
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
		mailTipsResponseMessage.success();
	}

	data.success();
	data.serialize(response);
}

/**
 * @brief      Process GetServiceConfigurationRequest
 *
 * Provides the functionality of GetServiceConfiguration
 * (../php/ews/exchange.php:450).
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
 * (../php/ews/exchange.php:225).
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
		throw InputError(E3013);
	if(!request.TimeZone)
		throw InputError(E3014);

	tDuration& TimeWindow = request.FreeBusyViewOptions? request.FreeBusyViewOptions->TimeWindow :
	                                                     request.SuggestionsViewOptions->DetailedSuggestionsWindow;

	mGetUserAvailabilityResponse data;
	data.FreeBusyResponseArray.emplace().reserve(request.MailboxDataArray.size());
	for(const tMailboxData& MailboxData : request.MailboxDataArray)
	{
		try {
			string maildir = ctx.get_maildir(MailboxData.Email);
			time_t start = gromox::time_point::clock::to_time_t(request.TimeZone->remove(TimeWindow.StartTime));
			time_t end = gromox::time_point::clock::to_time_t(request.TimeZone->remove(TimeWindow.EndTime));
			tFreeBusyView fbv(ctx.auth_info.username, maildir.c_str(), start, end, ctx);
			mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back(move(fbv));
			for(auto& event : *fbr.FreeBusyView->CalendarEventArray)
			{
				event.StartTime.offset = request.TimeZone->offset(event.StartTime.time);
				event.EndTime.offset = request.TimeZone->offset(event.EndTime.time);
			}
			fbr.ResponseMessage.emplace().success();
		} catch (const AccessDenied &) {
			mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back();
			fbr.FreeBusyView.emplace();
			fbr.ResponseMessage.emplace("Error", "InvalidAccessLevel",
			                            "Cannot access freebusy data of "+MailboxData.Email.Address);
		} catch (const DispatchError &err) {
			mFreeBusyResponse& fbr = data.FreeBusyResponseArray->emplace_back();
			fbr.ResponseMessage.emplace("Error", "ErrorMailRecipientNotFound", "Failed to get freebusy data: "s+err.what());
		}
	}
	data.serialize(response);
}

/**
 * @brief      Process GetUserOofSettingsRequest
 *
 * Provides the functionality of GetUserOofSettingsRequest
 * (../php/ews/exchange.php:16).
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
	if(strcasecmp(request.Mailbox.Address.c_str(), ctx.auth_info.username))
		throw AccessDenied(E3011);

	//Initialize response data structure
	mGetUserOofSettingsResponse data;
	data.OofSettings.emplace();

	//Get OOF state
	std::string maildir = ctx.get_maildir(request.Mailbox);
	string configPath = maildir+"/config/autoreply.cfg";
	auto configFile = config_file_init(configPath.c_str(), nullptr);
	if(configFile) {
		int oof_state = 0;
		int allow_external_oof = 0, external_audience = 0;
		configFile->get_int("oof_state", &oof_state);
		configFile->get_int("allow_external_oof", &allow_external_oof);
		configFile->get_int("external_audience", &external_audience);
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
			Duration.StartTime = Clock::from_time_t(strtoll(start_time, nullptr, 0));
			Duration.EndTime = Clock::from_time_t(strtoll(end_time, nullptr, 0));
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
 * @brief      Process SetUserOofSettingsRequest
 *
 * Provides functionality of SetUserOofSettingsRequest
 * (../php/ews/exchange.php:134).
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
	if(strcasecmp(request.Mailbox.Address.c_str(), ctx.auth_info.username))
		throw AccessDenied(E3012);
	std::string maildir = ctx.get_maildir(request.Mailbox);

	tUserOofSettings& OofSettings = request.UserOofSettings;
	int oof_state, allow_external_oof, external_audience;

	if(tolower(OofSettings.OofState) == "disabled")
		oof_state = 0;
	else if(OofSettings.OofState == "enabled")
		oof_state = 1;
	else if(OofSettings.OofState == "scheduled")
		oof_state = 2;
	else
		throw DispatchError(E3008(OofSettings.OofState));

	allow_external_oof = !(tolower(OofSettings.ExternalAudience) == "none");
	//Note: counterintuitive but intentional: known -> 1, all -> 0
	external_audience = OofSettings.ExternalAudience == "known";
	if(allow_external_oof && !external_audience && OofSettings.ExternalAudience != "all")
		throw DispatchError(E3009(OofSettings.ExternalAudience));

	std::string filename = maildir+"/config/autoreply.cfg";
	ofstream file(filename);
	file << "oof_state = " << oof_state << "\n"
	     << "allow_external_oof = " << allow_external_oof << "\n";
	if(allow_external_oof)
		file << "external_audience = " << external_audience << "\n";
	if(OofSettings.Duration)
		file << "start_time = " << Clock::to_time_t(OofSettings.Duration->StartTime) << "\n"
		     << "end_time = " << Clock::to_time_t(OofSettings.Duration->EndTime) << "\n";
	file.close();
	chmod(filename.c_str(), 0666);

	writeMessageBody(maildir+"/config/internal-reply", OofSettings.InternalReply);
	writeMessageBody(maildir+"/config/external-reply", OofSettings.ExternalReply);

	mSetUserOofSettingsResponse data;
	data.ResponseMessage.success();
	data.serialize(response);
}

/**
 * @brief      Process GetFolder
 *
 * Return folder updates and hierarchy sync information
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSyncFolderHierarchyRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	ctx.experimental();

	response->SetName("m:SyncFolderHierarchyResponse");

	auto& exmdb = ctx.plugin.exmdb;
	if(!request.SyncFolderId)
		request.SyncFolderId.emplace(tDistinguishedFolderId(Enum::msgfolderroot));

	sSyncState syncState;
	if(request.SyncState && !request.SyncState->empty())
		syncState.init(*request.SyncState);

	sFolderSpec folder = std::visit([&ctx](auto&& v){return ctx.resolveFolder(v);}, request.SyncFolderId->folderId);
	if(!folder.target)
		folder.target = ctx.auth_info.username;
	std::string dir = ctx.getDir(folder.normalize());

	FOLDER_CHANGES changes;
	uint64_t lastCn;
	EID_ARRAY given_fids, deleted_fids;
	if(!exmdb.get_hierarchy_sync(dir.c_str(), folder.folderId, nullptr,
	                             &syncState.given, &syncState.seen, &changes, &lastCn, &given_fids, &deleted_fids))
		throw DispatchError(E3030);
	sProptags requestedTags = ctx.collectTags(request.FolderShape);
	std::sort(requestedTags.tags.begin(), requestedTags.tags.end());

	mSyncFolderHierarchyResponse data;
    mSyncFolderHierarchyResponseMessage& msg = data.ResponseMessages.emplace_back();
	auto& msgChanges = msg.Changes.emplace();
	msgChanges.reserve(changes.count+deleted_fids.count);
	for(TPROPVAL_ARRAY* folderProps = changes.pfldchgs; folderProps < changes.pfldchgs+changes.count; ++folderProps)
	{
		uint64_t* folderId = folderProps->get<uint64_t>(PidTagFolderId);
		if(!folderId)
			continue;
		PROPTAG_ARRAY tags {uint16_t(requestedTags.tags.size()), requestedTags.tags.data()};
		TPROPVAL_ARRAY props = ctx.getFolderProps(sFolderSpec(*folder.target, *folderId), tags);
		auto folderData = tBaseFolderType::create(props);
		if(syncState.given.hint(*folderId))
			msgChanges.emplace_back(tSyncFolderHierarchyUpdate(std::move(folderData)));
		else
			msgChanges.emplace_back(tSyncFolderHierarchyCreate(std::move(folderData)));
	}

	for(uint64_t* fid = deleted_fids.pids; fid < deleted_fids.pids+deleted_fids.count; ++fid)
	{
		TAGGED_PROPVAL entryID = ctx.getFolderEntryId(sFolderSpec(*folder.target, *fid));
		msgChanges.emplace_back(tSyncFolderHierarchyDelete(entryID));
	}

	syncState.update(given_fids, deleted_fids, lastCn);
	msg.SyncState = syncState.serialize();
	msg.IncludesLastFolderInRange = true;
	msg.success();

	data.serialize(response);
}

void process(mSyncFolderItemsRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	ctx.experimental();

	response->SetName("m:SyncFolderItemsResponse");

	sFolderSpec folder = std::visit([&ctx](auto&& v){return ctx.resolveFolder(v);}, request.SyncFolderId.folderId);

	sSyncState syncState;
	if(request.SyncState && !request.SyncState->empty())
		syncState.init(*request.SyncState);

	if(!folder.target)
		folder.target = ctx.auth_info.username;
	std::string dir = ctx.getDir(folder.normalize());
	const char* username = folder.target == ctx.auth_info.username? nullptr : ctx.auth_info.username;

	auto& exmdb = ctx.plugin.exmdb;

	uint32_t fai_count, normal_count;
	uint64_t fai_total, normal_total, last_cn, last_readcn;
	EID_ARRAY updated_mids, chg_mids, given_mids, deleted_mids, nolonger_mids, read_mids, unread_mids;

	bool getFai = request.SyncScope && *request.SyncScope == "NormalAndAssociatedItems";
	idset* pseen_fai = getFai? &syncState.seen_fai : nullptr;
	if (!exmdb.get_content_sync(dir.c_str(), folder.folderId, username,
	    &syncState.given, &syncState.seen, pseen_fai, &syncState.read,
	    CP_ACP, nullptr, TRUE, &fai_count, &fai_total, &normal_count,
	    &normal_total, &updated_mids, &chg_mids, &last_cn, &given_mids,
	    &deleted_mids, &nolonger_mids, &read_mids, &unread_mids,
	    &last_readcn))
		throw DispatchError(E3031);
	syncState.update(given_mids, deleted_mids, last_cn);

	sProptags itemTags = ctx.collectTags(request.ItemShape);
	if(itemTags.tags.size() > std::numeric_limits<uint16_t>::max())
		throw DispatchError(E3032);
	PROPTAG_ARRAY requestedTags{uint16_t(itemTags.tags.size()), itemTags.tags.data()};

	mSyncFolderItemsResponse data;
	mSyncFolderItemsResponseMessage& msg = data.ResponseMessages.emplace_back();
	msg.Changes.reserve(updated_mids.count+chg_mids.count+deleted_mids.count+read_mids.count+unread_mids.count);
	for(uint64_t* mid = deleted_mids.pids; mid < deleted_mids.pids+deleted_mids.count; ++mid)
		msg.Changes.emplace_back(tSyncFolderItemsDelete(ctx.getItemEntryId(dir, *mid)));
	for(uint64_t* mid = nolonger_mids.pids; mid < nolonger_mids.pids+nolonger_mids.count; ++mid)
		msg.Changes.emplace_back(tSyncFolderItemsDelete(ctx.getItemEntryId(dir, *mid)));
	for(uint64_t* mid = updated_mids.pids; mid < updated_mids.pids+updated_mids.count; ++mid)
	{
		TPROPVAL_ARRAY itemProps = ctx.getItemProps(dir, *mid, requestedTags);
		msg.Changes.emplace_back(tSyncFolderItemsCreate{{{}, tItem::create(itemProps)}});
	}
	for(uint64_t* mid = chg_mids.pids; mid < chg_mids.pids+chg_mids.count; ++mid)
	{
		TPROPVAL_ARRAY itemProps = ctx.getItemProps(dir, *mid, requestedTags);
		msg.Changes.emplace_back(tSyncFolderItemsCreate{{{}, tItem::create(itemProps)}});
	}
	for(uint64_t* mid = read_mids.pids; mid < read_mids.pids+read_mids.count; ++mid)
		msg.Changes.emplace_back(tSyncFolderItemsReadFlag{{}, tItemId(ctx.getItemEntryId(dir, *mid)), true});
	for(uint64_t* mid = unread_mids.pids; mid < read_mids.pids+read_mids.count; ++mid)
		msg.Changes.emplace_back(tSyncFolderItemsReadFlag{{}, tItemId(ctx.getItemEntryId(dir, *mid)), false});
	msg.SyncState = syncState.serialize();
	msg.IncludesLastItemInRange = true;
	msg.success();

	data.serialize(response);
}

}
