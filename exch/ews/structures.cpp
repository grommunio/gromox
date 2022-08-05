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
//Additional non-inline deserialization functions
//Might go into a separate file if number grows

XMLError ExplicitConvert<gromox::time_point>::deserialize(const tinyxml2::XMLElement* xml, gromox::time_point& value)
{
		const char* data = xml->GetText();
		if(!data)
			return tinyxml2::XML_NO_TEXT_NODE;
		tm t{};
		float seconds = 0, unused;
		int tz_hour = 0, tz_min = 0;
		if(std::sscanf(data, "%4d-%02d-%02dT%02d:%02d:%f%03d:%02d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min,
		               &seconds, &tz_hour, &tz_min) < 6) //Timezone info is optional, date and time values mandatory
			return tinyxml2::XML_CAN_NOT_CONVERT_TEXT;
		t.tm_sec = int(seconds);
		t.tm_year -= 1900;
		t.tm_mon -= 1;
		t.tm_hour -= tz_hour;
		t.tm_min -= tz_hour	< 0? -tz_min : tz_min;
		time_t timestamp = mktime(&t)-timezone;
		if(timestamp == time_t(-1))
			return tinyxml2::XML_CAN_NOT_CONVERT_TEXT;
		value = gromox::time_point::clock::from_time_t(timestamp);
		seconds = std::modf(seconds, &unused);
		value += std::chrono::microseconds(int(seconds*1000000));
		return tinyxml2::XML_SUCCESS;
	}

///////////////////////////////////////////////////////////////////////////////////////////////////

tDuration::tDuration(const XMLElement* xml) :
    XMLINIT(StartTime), XMLINIT(EndTime)
{}

void tDuration::serialize(XMLElement* xml) const
{
	XMLDUMP(StartTime);
	XMLDUMP(EndTime);
}

tMailbox::tMailbox(const XMLElement* xml) :
    XMLINIT(Name), XMLINIT(Address), XMLINIT(RoutingType)
{}


tReplyBody::tReplyBody(const XMLElement* xml):
    XMLINIT(Message), XMLINITA(lang)
{}

void tReplyBody::serialize(XMLElement* xml) const
{
	XMLDUMP(Message);
	XMLDUMPA(lang);
}

tUserOofSettings::tUserOofSettings(const XMLElement* xml) :
    XMLINIT(OofState),
    XMLINIT(ExternalAudience),
    XMLINIT(Duration),
    XMLINIT(InternalReply),
    XMLINIT(ExternalReply)
{}

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

mSetUserOofSettingsRequest::mSetUserOofSettingsRequest(const XMLElement* xml) :
    XMLINIT(Mailbox), XMLINIT(UserOofSettings)
{}

void mSetUserOofSettingsResponse::serialize(XMLElement* xml) const
{XMLDUMP(ResponseMessage);}
