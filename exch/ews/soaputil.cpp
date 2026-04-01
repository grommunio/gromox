// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2026 grommunio GmbH
// This file is part of Gromox.
#include <cassert>
#include <stdexcept>
#include <string>
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
string Envelope::fault(const char *code, const char *message)
{
	XMLDocument doc;
	auto root = doc.NewElement("SOAP:Envelope");
	doc.InsertEndChild(root);
	root->SetAttribute("xmlns:SOAP", NS_SOAP);
	root->SetAttribute("xmlns:xsi", NS_XSI);
	root->InsertNewChildElement("SOAP:Header");
	auto body = root->InsertNewChildElement("SOAP:Body");
	auto fault = body->InsertNewChildElement("SOAP:Fault");
	auto fc = fault->InsertNewChildElement("faultcode");
	fc->SetAttribute("xsi:type", "xsd:string");
	fc->SetText(code);
	auto fs = fault->InsertNewChildElement("faultstring");
	fs->SetAttribute("xsi:type", "xsd:string");
	fs->SetText(message);
	XMLPrinter printer(nullptr, true);
	doc.Print(&printer);
	return printer.CStr();
}

}
