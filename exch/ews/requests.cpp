// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#include <tinyxml2.h>

#include <gromox/clock.hpp>

#include "requests.hpp"

namespace gromox::EWS::Requests
{

using namespace gromox;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

/**
 * @brief      Process GetUserOofSettingsRequest
 *
 * Currently just a proof-of-concept dummy.
 *
 * @todo       Implement actual functionality
 *
 * @param      request   Request data
 * @param      response  XMLElement to store response in
 */
void process(mGetUserOofSettingsRequest&&, XMLElement* response, const EWSContext&)
{
	//Set name of the response node
	response->SetName("GetUserOofSettingsResponse");

	//Initialize response data structure
	mGetUserOofSettingsResponse data;
	data.UserOofSettings.emplace();
	data.UserOofSettings->Duration.emplace();
	data.UserOofSettings->Duration->StartTime = gromox::time_point::clock::now();

	//Write payload
	data.UserOofSettings->OofState = "Disabled";
	data.UserOofSettings->ExternalAudience = "None";

	//Finalize response
	data.ResponseMessage.success();
	data.UserOofSettings->Duration->EndTime = gromox::time_point::clock::now();
	data.serialize(response);
}

}
