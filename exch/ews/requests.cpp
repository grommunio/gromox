// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#include <algorithm>
#include <fstream>

#include <tinyxml2.h>

#include <gromox/clock.hpp>
#include <gromox/config_file.hpp>
#include <gromox/mysql_adaptor.hpp>

#include "exceptions.hpp"
#include "requests.hpp"

namespace gromox::EWS::Requests
{

using namespace gromox;
using namespace gromox::EWS::Structures;
using namespace std;
using namespace tinyxml2;

using gromox::EWS::Exceptions::DispatchError;
using gromox::EWS::Exceptions::NotImplementedError;

using Clock = time_point::clock;

/**
 * @brief      Convert string to lower case
 *
 * @param      str     String to convert
 *
 * @return     Reference to the string
 */
inline string& tolower(string& str)
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
static optional<string> readMessageBody(const std::string& path) try
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
 * @brief      Process GetUserOofSettingsRequest
 *
 * Provides most of the functionality of GetUserOofSettingsRequest
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
	string RoutingType = request.Mailbox.RoutingType.value_or("smtp");
	string maildir;
	if(tolower(RoutingType) == "ex"){
		request.Mailbox.Address = ctx.plugin.essdn_to_username(request.Mailbox.Address);
		RoutingType = "smtp";
	}
	if(RoutingType == "smtp") {
		char temp[256];
		if(!ctx.plugin.mysql.get_maildir(request.Mailbox.Address.c_str(), temp, arsizeof(temp)))
			throw DispatchError("Failed to get user maildir");
		maildir = temp;
	} else
		throw DispatchError("E-2011: unrecognized RoutingType '"+RoutingType+"'");

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

}
