// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#include <algorithm>
#include <fstream>

#include <sys/stat.h>
#include <tinyxml2.h>

#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/mysql_adaptor.hpp>

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
inline std::string& tolower(std::string& str)
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
} catch(std::exception& e)
{
	printf("[ews] %s\n", e.what());
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

}
///////////////////////////////////////////////////////////////////////
//Request implementations

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
	response->SetName("GetMailTipsResponse");

	mGetMailTipsResponse data;
	data.ResponseMessages.reserve(request.Recipients.size());

	for(auto& recipient : request.Recipients)
	{
		tMailTips& mailTips = data.ResponseMessages.emplace_back().MailTips.emplace();
		mailTips.RecipientAddress = std::move(recipient);
	}

	data.serialize(response);
}

/**
 * @brief      Process GetUserOofSettingsRequest
 *
 * Provides the functionality of GetUserOofSettingsRequest
 * (../php/ews/exchange.php:16).
 *
 * @todo       Check permissions?
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
	response->SetName("GetUserOofSettingsResponse");

	//Initialize response data structure
	mGetUserOofSettingsResponse data;
	data.UserOofSettings.emplace();

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
			data.UserOofSettings->OofState = "Enabled"; break;
		case 2:
			data.UserOofSettings->OofState = "Scheduled"; break;
		default:
			data.UserOofSettings->OofState = "Disabled"; break;
		}
		if(allow_external_oof)
			data.UserOofSettings->ExternalAudience = external_audience? "Known" : "All";
		else
			data.UserOofSettings->ExternalAudience = "None";
		try {
			time_t start_time = configFile->get_ll("start_time");
			time_t end_time = configFile->get_ll("end_time");
			tDuration& Duration = data.UserOofSettings->Duration.emplace();
			Duration.StartTime = Clock::from_time_t(start_time);
			Duration.EndTime = Clock::from_time_t(end_time);
		} catch (cfg_error&) {}
		optional<string> reply = readMessageBody(maildir+"/config/internal-reply");
		if(reply)
			data.UserOofSettings->InternalReply.emplace(std::move(reply));
		if((reply = readMessageBody(maildir+"/config/external-reply")))
			data.UserOofSettings->ExternalReply.emplace(std::move(reply));
	} else
	{
		data.UserOofSettings->OofState = "Disabled";
		data.UserOofSettings->ExternalAudience = "None";
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
 * @todo       Check permissions?
 * @todo       Check if error handling can be improved
 *             (using the response message instead of SOAP faults)
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 * @param      ctx       Request context
 */
void process(mSetUserOofSettingsRequest&& request, XMLElement* response, const EWSContext& ctx)
{
	response->SetName("SetUserOofSettingsResponse");

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

}
