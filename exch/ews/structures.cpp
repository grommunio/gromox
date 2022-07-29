// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.

#include "serialization.hpp"
#include "soaputil.hpp"
#include "structures.hpp"

using namespace gromox::EWS;
using namespace gromox::EWS::Serialization;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

//Shortcuts to call toXML* and fromXML* functions on members
#define XMLINIT(name) name(fromXMLNode<decltype(name)>(xml, # name))
#define XMLDUMP(name) toXMLNode(xml, # name, name)
#define XMLINITA(name) name(fromXMLAttr<decltype(name)>(xml, # name))
#define XMLDUMPA(name) toXMLAttr(xml, # name, name)


///////////////////////////////////////////////////////////////////////////////////////////////////

void tDuration::serialize(XMLElement* xml) const
{
    XMLDUMP(StartTime);
    XMLDUMP(EndTime);
}

tMailbox::tMailbox(const XMLElement* xml) :
    XMLINIT(Name), XMLINIT(Address), XMLINIT(RoutingType)
{}


void tReplyBody::serialize(XMLElement* xml) const
{
	XMLDUMP(Message);
	XMLDUMPA(lang);
}

void tUserOofSettings::serialize(XMLElement* xml) const
{
    XMLDUMP(OofState);
    XMLDUMP(ExternalAudience);
    XMLDUMP(Duration);
    XMLDUMP(InternalReply);
    XMLDUMP(ExternalReply);
}

///////////////////////////////////////////////////////////////////////////////////////////////////

mGetUserOofSettingsRequest::mGetUserOofSettingsRequest(const XMLElement* xml) :
    XMLINIT(Mailbox)
{}

void mGetUserOofSettingsResponse::serialize(XMLElement* xml) const
{
    XMLDUMP(ResponseMessage);
    XMLDUMP(UserOofSettings);
    XMLDUMP(AllowExternalOof);
}

void mResponseMessageType::success()
{
    ResponseClass = "Success";
    ResponseCode = "NoError";
}

void mResponseMessageType::serialize(tinyxml2::XMLElement* xml) const
{
    XMLDUMPA(ResponseClass);
    XMLDUMP(MessageText);
    XMLDUMP(ResponseCode);
    XMLDUMP(DescriptiveLinkKey);
}
