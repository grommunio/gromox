// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#include <stdexcept>
#include <string>
#include <fmt/core.h>
#include <gromox/defs.h>

#include "exceptions.hpp"
#include "soaputil.hpp"

using namespace std;
using namespace tinyxml2;

using gromox::EWS::Exceptions::SOAPError;

namespace gromox::EWS::SOAP
{

/**
 * @brief      Generate empty SOAP Envelope
 */
Envelope::Envelope()
{
        XMLElement* root = doc.NewElement("Soap:Envelope");
        doc.InsertFirstChild(root);
        root->SetAttribute("xmlns:Soap", NS_SOAP);
        header = root->InsertNewChildElement("Soap:Header");
        body = root->InsertNewChildElement("Soap:Body");
}

/**
 * @brief      Read SOAP Envelope from XML string
 *
 * @param      content  Content of the XML document
 */
Envelope::Envelope(const char* content, size_t nBytes)
{
    using namespace string_literals;
    doc.Parse(content, nBytes);
    XMLElement* envelope = doc.RootElement();
    if(!envelope)
        throw SOAPError("Invalid XML");
    clean(envelope);
    if(envelope->Name() != "Envelope"s)
        throw SOAPError("Invalid SOAP envelope");
    header = envelope->FirstChildElement("Header");
    body = envelope->FirstChildElement("Body");
    if(!body)
        throw SOAPError("Missing body");
}

/**
 * @brief      Remove namespaces from document
 *
 * @todo       Add proper namespace support...
 *
 * @param      element  XMLElement to clean
 */
void Envelope::clean(XMLElement* element)
{
    const char* prefix = strchr(element->Name(), ':');
    if(prefix)
        element->SetName(prefix+1);
    for(XMLElement* child = element->FirstChildElement(); child; child = child->NextSiblingElement())
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
	        "<SOAP:Envelope xmlns:SOAP = \"http://schemas.xmlsoap.org/soap/envelope/\""
	                      " xmlns:xsi = \"http://www.w3.org/1999/XMLSchema-instance\">"
	          "<SOAP:Body>"
	            "<SOAP:Fault>"
	              "<faultcode xsi:type = \"xsd:string\">SOAP:{}</faultcode>"
	              "<faultstring xsi:type = \"xsd:string\">{}</faultstring>"
	            "</SOAP:Fault>"
	          "</SOAP:Body>"
		"</SOAP:Envelope>",
		code, message);
}

}
