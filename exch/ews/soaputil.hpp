// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#pragma once

#include <string>

#include <tinyxml2.h>

namespace gromox::EWS::SOAP
{

static constexpr char NS_SOAP[] = "http://schemas.xmlsoap.org/soap/envelope/";
static constexpr char NS_XSI[] = "http://www.w3.org/2001/XMLSchema-instance";
static constexpr char NS_XSD[] = "http://www.w3.org/2001/XMLSchema";
static constexpr char NS_MSGS[] = "http://schemas.microsoft.com/exchange/services/2006/messages";
static constexpr char NS_TYPS[] = "http://schemas.microsoft.com/exchange/services/2006/types";

/**
 * @brief      Basic class to manage SOAP Envelopes
 */
class Envelope {
	public:
	Envelope();
	explicit Envelope(const char*, size_t=static_cast< size_t >(-1));

	tinyxml2::XMLDocument doc; ///< XML document containing the envelope
	tinyxml2::XMLElement* body; ///< SOAP body element
	tinyxml2::XMLElement* header; ///< SOAP header element

	static std::string fault(const char*, const char*);

	private:
	static void clean(tinyxml2::XMLElement*);
};

}
