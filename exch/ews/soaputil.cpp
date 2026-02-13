// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <stdexcept>
#include <string>
#include <fmt/core.h>
#include <gromox/defs.h>

#include "exceptions.hpp"
#include "soaputil.hpp"

using std::string;
using namespace std::string_literals;
using namespace tinyxml2;

using gromox::EWS::Exceptions::SOAPError;

namespace gromox::EWS::SOAP {

/**
 * @brief      Generate empty SOAP Envelope
 */
Envelope::Envelope(const VersionInfo &ver, bool with_decl)
{
	if (with_decl) {
		auto decl = doc.NewDeclaration();
		doc.InsertEndChild(decl);
	}
	XMLElement *root = doc.NewElement("SOAP:Envelope");
	doc.InsertEndChild(root);
	root->SetAttribute("xmlns:SOAP", NS_SOAP);
	root->SetAttribute("xmlns:xsi", NS_XSI);
	root->SetAttribute("xmlns:xsd", NS_XSD);
	header = root->InsertNewChildElement("SOAP:Header");
	body = root->InsertNewChildElement("SOAP:Body");

	XMLElement *ServerVersionInfo = header->InsertNewChildElement("t:ServerVersionInfo");
	ServerVersionInfo->SetAttribute("xmlns:t", NS_TYPS);
	ServerVersionInfo->SetAttribute("MajorVersion", ver.server[0]);
	ServerVersionInfo->SetAttribute("MinorVersion", ver.server[1]);
	ServerVersionInfo->SetAttribute("MajorBuildNumber", ver.server[2]);
	ServerVersionInfo->SetAttribute("MinorBuildNumber", ver.server[3]);
	ServerVersionInfo->SetAttribute("Version", ver.schema.c_str());
}

/**
 * @brief      Read SOAP Envelope from XML string
 *
 * @param      content  Content of the XML document
 */
Envelope::Envelope(const char* content, size_t nBytes)
{
	doc.Parse(content, nBytes);
	XMLElement *envelope = doc.RootElement();
	if (!envelope)
		throw SOAPError("Invalid XML");
	clean(envelope);
	if (envelope->Name() != "Envelope"s)
		throw SOAPError("Invalid SOAP envelope");
	header = envelope->FirstChildElement("Header");
	body = envelope->FirstChildElement("Body");
	if (!body)
		throw SOAPError("Missing body");
}

/**
 * @brief      Remove namespaces from document
 *
 * @todo       Add proper namespace support...
 *
 * @param      element  XMLElement to clean
 */
void Envelope::clean(XMLElement *element)
{
	const char* prefix = strchr(element->Name(), ':');
	if (prefix)
		element->SetName(prefix + 1);
	for (XMLElement *child = element->FirstChildElement(); child != nullptr;
	     child = child->NextSiblingElement())
		clean(child);
}

/**
 * @brief      Render SOAP Fault message
 *
 * @param      code     SOAP Fault Code (usually "Client" or "Server")
 * @param      message  Detailed error message
 *
 * @return     SOAP Fault response data
 */
string Envelope::fault(const char* code, const char* message)
{
	return fmt::format(
	        "<SOAP:Envelope xmlns:SOAP=\"http://schemas.xmlsoap.org/soap/envelope/\""
	                      " xmlns:xsi=\"http://www.w3.org/1999/XMLSchema-instance\">"
	          "<SOAP:Body>"
	            "<SOAP:Fault>"
	              "<faultcode xsi:type=\"xsd:string\">{}</faultcode>"
	              "<faultstring xsi:type=\"xsd:string\">{}</faultstring>"
	            "</SOAP:Fault>"
	          "</SOAP:Body>"
		"</SOAP:Envelope>",
		code, message);
}

}
