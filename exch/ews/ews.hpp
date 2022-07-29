// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <gromox/hpm_common.h>

#include "soaputil.hpp"

namespace gromox::EWS {

/**
 * @brief      EWS request context
 */
struct EWSContext
{
	inline EWSContext(int ID, HTTP_AUTH_INFO auth_info, const char* data, uint64_t length) :
		ID(ID), orig(*get_request(ID)), auth_info(auth_info), request(data, length)
	{}

	int ID = 0;
	HTTP_REQUEST &orig;
	HTTP_AUTH_INFO auth_info{};
	SOAP::Envelope request;
	SOAP::Envelope response;
};

}
