// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.

#pragma once
#include <array>
#include <string>
#include <tinyxml2.h>

namespace gromox::EWS::SOAP {

static constexpr char NS_SOAP[] = "http://schemas.xmlsoap.org/soap/envelope/";
static constexpr char NS_XSI[] = "http://www.w3.org/2001/XMLSchema-instance";
static constexpr char NS_XSD[] = "http://www.w3.org/2001/XMLSchema";
static constexpr char NS_TYPS[] = "http://schemas.microsoft.com/exchange/services/2006/types";

struct VersionInfo {
	std::array<uint16_t, 4> server; ///< Server version
	std::string schema; ///< EWS schema version string
};


/**
 * @brief      Basic class to manage SOAP Envelopes
 */
class Envelope {
	public:
	static constexpr bool WITHOUT_DECL = false;

	explicit Envelope(const VersionInfo &, bool with_decl = true);
	explicit Envelope(const char *, size_t = static_cast<size_t>(-1));

	tinyxml2::XMLDocument doc; ///< XML document containing the envelope
	tinyxml2::XMLElement* body; ///< SOAP body element
	tinyxml2::XMLElement* header; ///< SOAP header element

	static std::string fault(const char*, const char*);

	private:
	static void clean(tinyxml2::XMLElement*);
};

}
