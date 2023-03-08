// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
/**
 * @brief      Implementation of EWS structure (de-)serialization
 */
#include <gromox/ext_buffer.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

#include "exceptions.hpp"
#include "ews.hpp"
#include "serialization.hpp"
#include "structures.hpp"

using namespace gromox::EWS;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Serialization;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

using namespace std::string_literals;

//Shortcuts to call toXML* and fromXML* functions on members
#define XMLINIT(name) name(fromXMLNode<decltype(name)>(xml, #name)) ///< Init member from XML node
#define VXMLINIT(name) name(fromXMLNode<decltype(name)>(xml, nullptr)) ///< Init variant from XML node
#define XMLDUMPM(name) toXMLNode(xml, "m:"#name, name) ///< Write member into XML node (Messages namespace)
#define XMLDUMPT(name) toXMLNode(xml, "t:"#name, name) ///< Write member into XML node (Types namespace)
#define XMLINITA(name) name(fromXMLAttr<decltype(name)>(xml, #name)) ///< Initialize member from XML attribute
#define XMLDUMPA(name) toXMLAttr(xml, #name, name) ///< Write member into XML attribute

#define EXT_TRY(expr) EWSContext::ext_error(expr)

namespace
{

/**
 * @brief     Compute Base64 encoded string
 *
 * @param     data    Data to encode
 * @param     len     Number of bytes
 *
 * @return    Base64 encoded string
 */
std::string b64encode(const void* data, size_t len)
{
	std::string out(4*((len+2)/3)+1, '\0');
	size_t outlen;
	encode64(data, len, out.data(), out.length(), &outlen);
	out.resize(outlen);
	return out;
}

/**
 * @brief     Compute Base64 decoded string
 *
 * @param     data    Data to decode
 * @param     len     Number of bytes
 *
 * @return    Base64 encoded string
 */
std::vector<uint8_t> b64decode(const char* data, size_t len)
{
	std::vector<uint8_t> out(len*3/4+1, 0);
	size_t outlen;
	if(decode64(data, len, out.data(), out.size(), &outlen))
		throw DeserializationError(E3033);
	out.resize(outlen);
	return out;
}

/**
 * @brief     Generic deleter struct
 *
 * Provides explicit deleters for classes without destructor.
 */
struct Cleaner
{
	inline void operator()(BINARY* x) {rop_util_free_binary(x);}
	inline void operator()(TPROPVAL_ARRAY* x) {tpropval_array_free(x);}
};

} // Anonymous namespace


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
    t.tm_min -= tz_hour < 0? -tz_min : tz_min;
    time_t timestamp = mktime(&t)-timezone;
    if(timestamp == time_t(-1))
        return tinyxml2::XML_CAN_NOT_CONVERT_TEXT;
    value = gromox::time_point::clock::from_time_t(timestamp);
    seconds = std::modf(seconds, &unused);
    value += std::chrono::microseconds(int(seconds*1000000));
    return tinyxml2::XML_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Decode Base64 encoded data from XML element
 */
sBase64Binary::sBase64Binary(const XMLElement* xml)
{
	const char* data = xml->GetText();
	if(!data)
		throw DeserializationError(E3034(xml->Name()));
	std::vector<uint8_t>::operator=(b64decode(data, strlen(data)));
}

/**
 * @brief     Decode Base64 encoded data from XML attribute
 */
sBase64Binary::sBase64Binary(const XMLAttribute* xml) : std::vector<uint8_t>(b64decode(xml->Value(), strlen(xml->Value())))
{}

/**
 * @brief     Return Base64 encoded data
 *
 * @return    std::string conatining base64 encoded data
 */
std::string sBase64Binary::serialize() const
{return empty()? std::string() : b64encode(data(), size());}

/**
 * @brief     Store Base64 encoded data in xml element
 *
 * @param     xml     XML element to store data in
 */
void sBase64Binary::serialize(XMLElement* xml) const
{xml->SetText(empty()? "" : b64encode(data(), size()).c_str());}

/**
 * @brief     Read entry ID from XML attribute
 *
 * @param     xml     XML attribute containing Base64 encoded entry ID
 */
sFolderEntryId::sFolderEntryId(const XMLAttribute* xml)
{
	sBase64Binary bin(xml);
	init(bin.data(), bin.size());
}

/**
 * @brief     Generate entry ID object
 *
 * @return    String containing base64 encoded entry ID
 */
std::string sFolderEntryId::serialize() const
{
	char buff[64];
	EXT_PUSH ext_push;
	ext_push.init(buff, 64, 0, nullptr);
	EXT_TRY(ext_push.p_folder_eid(*this));
	return b64encode(buff, ext_push.m_offset);
}

/**
 * @brief     Serialize sync state
 *
 * @return    Base64 encoded state
 */
std::string sSyncState::serialize()
{
	std::unique_ptr<TPROPVAL_ARRAY, Cleaner> pproplist(tpropval_array_init());
	if (!pproplist)
		throw DispatchError(E3035);
	std::unique_ptr<BINARY, Cleaner> ser(given.serialize());
	if (!ser || pproplist->set(MetaTagIdsetGiven1, ser.get()))
		throw DispatchError(E3036);
	ser.reset(seen.serialize());
	if (!ser || pproplist->set(MetaTagCnsetSeen, ser.get()))
		throw DispatchError(E3037);
	ser.reset();
	if(!seen_fai.empty())
	{
		ser.reset(seen_fai.serialize());
		if (!ser || pproplist->set(MetaTagCnsetSeenFAI, ser.get()))
			throw DispatchError(E3038);
	}
	if(!read.empty())
	{
		ser.reset(read.serialize());
		if (!ser || pproplist->set(MetaTagCnsetRead, ser.get()))
			throw DispatchError(E3039);
	}
	ser.reset();
	if (readOffset != 0 && pproplist->set(MetaTagReadOffset, &readOffset) != 0)
		/* ignore error */;

	EXT_PUSH stateBuffer;
	if(!stateBuffer.init(nullptr, 0, 0) || stateBuffer.p_tpropval_a(*pproplist) != EXT_ERR_SUCCESS)
		throw DispatchError(E3040);

	return b64encode(stateBuffer.m_vdata, stateBuffer.m_offset);
}

/**
 * @brief     Parse time string
 *
 *  Accepts HH:MM:SS format.
 *
 * @param     xml
 */
sTime::sTime(const XMLElement* xml)
{
	const char* data = xml->GetText();
	if(!data)
		throw DeserializationError(E3041(xml->Name()));
	if(sscanf(data, "%02hhu:%02hhu:%02hhu", &hour, &minute, &second) != 3)
		throw DeserializationError(E3042(xml->Name(), xml->GetText()));
}

void sTimePoint::serialize(XMLElement* xml) const
{
	tm t;
	time_t timestamp = gromox::time_point::clock::to_time_t(time-offset);
	gmtime_r(&timestamp, &t);
	auto frac = time.time_since_epoch() % std::chrono::seconds(1);
	long fsec = std::chrono::duration_cast<std::chrono::microseconds>(frac).count();
	int off = -int(offset.count());
	if(offset.count() == 0)
		xml->SetText(fmt::format("{:%FT%T}.{:06}Z", t, fsec).c_str());
	else
		xml->SetText(fmt::format("{:%FT%T}.{:06}{:+03}{:02}", t, fsec, off / 60, abs(off) % 60).c_str());
}

///////////////////////////////////////////////////////////////////////////////////////////////////

void tBaseFolderType::serialize(XMLElement* xml) const
{
	XMLDUMPT(FolderId);
	XMLDUMPT(ParentFolderId);
	XMLDUMPT(FolderClass);
	XMLDUMPT(DisplayName);
	XMLDUMPT(TotalCount);
	XMLDUMPT(ChildFolderCount);
	for(const tExtendedProperty& ep : ExtendedProperty)
		toXMLNode(xml, "t:ExtendedProperty", ep);
}

tBaseItemId::tBaseItemId(const XMLElement* xml) :
    XMLINITA(Id), XMLINITA(ChangeKey)
{}

void tBaseItemId::serialize(XMLElement* xml) const
{
	XMLDUMPA(Id);
	XMLDUMPA(ChangeKey);
}

void tBody::serialize(tinyxml2::XMLElement* xml) const
{
	xml->SetText(c_str());
	XMLDUMPA(BodyType);
	XMLDUMPA(IsTruncated);
}

void tCalendarEventDetails::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(ID);
	XMLDUMPT(Subject);
	XMLDUMPT(Location);
	XMLDUMPT(IsMeeting);
	XMLDUMPT(IsRecurring);
	XMLDUMPT(IsException);
	XMLDUMPT(IsReminderSet);
	XMLDUMPT(IsPrivate);
}

void tCalendarEvent::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(StartTime);
	XMLDUMPT(EndTime);
	XMLDUMPT(BusyType);
	XMLDUMPT(CalendarEventDetails);
}

tDistinguishedFolderId::tDistinguishedFolderId(const tinyxml2::XMLElement* xml) :
    XMLINIT(Mailbox),
    XMLINITA(ChangeKey),
    XMLINITA(Id)
{}

tDuration::tDuration(const XMLElement* xml) :
    XMLINIT(StartTime), XMLINIT(EndTime)
{}

void tDuration::serialize(XMLElement* xml) const
{
	XMLDUMPT(StartTime);
	XMLDUMPT(EndTime);
}

tEmailAddressType::tEmailAddressType(const tinyxml2::XMLElement* xml) :
    XMLINIT(Name),
    XMLINIT(EmailAddress),
    XMLINIT(RoutingType),
    XMLINIT(MailboxType),
    XMLINIT(ItemId),
    XMLINIT(OriginalDisplayName)
{}

void tEmailAddressType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(Name);
    XMLDUMPT(EmailAddress);
    XMLDUMPT(RoutingType);
    XMLDUMPT(MailboxType);
    XMLDUMPT(ItemId);
    XMLDUMPT(OriginalDisplayName);
}

tExtendedFieldURI::tExtendedFieldURI(const tinyxml2::XMLElement* xml) :
    XMLINITA(PropertyTag),
    XMLINITA(PropertyType),
    XMLINITA(PropertyId),
    XMLINITA(PropertySetId),
    XMLINITA(PropertyName)
{}

void tExtendedFieldURI::serialize(XMLElement* xml) const
{
	XMLDUMPA(PropertyType);
	XMLDUMPA(PropertyTag);
	XMLDUMPA(PropertyId);
	XMLDUMPA(PropertySetId);
	XMLDUMPA(PropertyName);
}

void tExtendedProperty::serialize(XMLElement* xml) const
{
	const void* data = propval.pvalue;
	if(!data)
		return;
	bool ismv = propval.proptag & MV_FLAG;
	if(propname.kind == KIND_NONE)
		toXMLNode(xml , "t:ExtendedFieldURI", tExtendedFieldURI(propval.proptag));
	else
		toXMLNode(xml , "t:ExtendedFieldURI", tExtendedFieldURI(PROP_TYPE(propval.proptag), propname));
	XMLElement* value = xml->InsertNewChildElement(ismv? "t:Values" : "t:Value");
	if(!ismv)
		return serialize(data, 0, PROP_TYPE(propval.proptag), value);
}

tFieldURI::tFieldURI(const XMLElement* xml) :
    XMLINITA(FieldURI)
{}

void tFlagType::serialize(XMLElement* xml) const
{XMLDUMPT(FlagStatus);}

tFolderResponseShape::tFolderResponseShape(const XMLElement* xml) :
    XMLINIT(BaseShape),
    XMLINIT(AdditionalProperties)
{}

void tFolderType::serialize(XMLElement* xml) const
{
	tBaseFolderType::serialize(xml);
	XMLDUMPT(UnreadCount);
}

void tFreeBusyView::serialize(XMLElement* xml) const
{
	XMLDUMPT(FreeBusyViewType);
	XMLDUMPT(MergedFreeBusy);
	XMLDUMPT(CalendarEventArray);
}

tFreeBusyViewOptions::tFreeBusyViewOptions(const tinyxml2::XMLElement* xml) :
    XMLINIT(TimeWindow), XMLINIT(MergedFreeBusyIntervalInMinutes), XMLINIT(RequestedView)
{}

tGuid::tGuid(const XMLAttribute* xml)
{
	if(!from_str(xml->Value()))
		throw DeserializationError(E3063);
}


void tItem::serialize(XMLElement* xml) const
{
	XMLDUMPT(ItemId);
	XMLDUMPT(ParentFolderId);
	XMLDUMPT(ItemClass);
	XMLDUMPT(Subject);
	XMLDUMPT(Body);
	XMLDUMPT(DateTimeReceived);
	XMLDUMPT(Size);
	XMLDUMPT(InReplyTo);
	XMLDUMPT(DateTimeSent);
	XMLDUMPT(DisplayCc);
	XMLDUMPT(DisplayTo);
	XMLDUMPT(DisplayBcc);
	XMLDUMPT(HasAttachments);
	XMLDUMPT(LastModifiedName);
	XMLDUMPT(LastModifiedTime);
	XMLDUMPT(IsAssociated);
	XMLDUMPT(ConversationId);
	XMLDUMPT(Flag);
	for(const tExtendedProperty& ep : ExtendedProperty)
		toXMLNode(xml, "t:ExtendedProperty", ep);
}

tItemResponseShape::tItemResponseShape(const XMLElement* xml) :
    XMLINIT(BodyType),
    XMLINIT(AdditionalProperties)
{}

tMailbox::tMailbox(const XMLElement* xml) :
    XMLINIT(Name), XMLINIT(Address), XMLINIT(RoutingType)
{}

tMailboxData::tMailboxData(const tinyxml2::XMLElement* xml) :
    XMLINIT(Email), XMLINIT(AttendeeType), XMLINIT(ExcludeConflicts)
{}

void tMailTips::serialize(XMLElement* xml) const
{
	XMLDUMPT(RecipientAddress);
	XMLDUMPT(PendingMailTips);
}

void tMailTipsServiceConfiguration::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(MailTipsEnabled);
	XMLDUMPT(MaxRecipientsPerGetMailTipsRequest);
	XMLDUMPT(MaxMessageSize);
	XMLDUMPT(LargeAudienceThreshold);
	XMLDUMPT(ShowExternalRecipientCount);
	XMLDUMPT(InternalDomains);
	XMLDUMPT(PolicyTipsEnabled);
	XMLDUMPT(LargeAudienceCap);
}

void tMessage::serialize(tinyxml2::XMLElement* xml) const
{
	tItem::serialize(xml);
	XMLDUMPT(Sender);
	XMLDUMPT(ToRecipients);
	XMLDUMPT(CcRecipients);
	XMLDUMPT(BccRecipients);
	XMLDUMPT(IsReadReceiptRequested);
	XMLDUMPT(IsDeliveryReceiptRequested);
	XMLDUMPT(From);
	XMLDUMPT(IsRead);
	XMLDUMPT(IsResponseRequested);
	XMLDUMPT(ReplyTo);
	XMLDUMPT(ReceivedBy);
	XMLDUMPT(ReceivedRepresenting);
}

tPath::tPath(const XMLElement* xml)
        : Base(fromXMLNodeDispatch<Base>(xml))
{}

tReplyBody::tReplyBody(const XMLElement* xml):
    XMLINIT(Message), XMLINITA(lang)
{}

void tReplyBody::serialize(XMLElement* xml) const
{
	XMLDUMPT(Message);
	XMLDUMPA(lang);
}

tSerializableTimeZoneTime::tSerializableTimeZoneTime(const tinyxml2::XMLElement* xml) :
    XMLINIT(Bias),
    XMLINIT(Time),
    XMLINIT(DayOrder),
    XMLINIT(Month),
    XMLINIT(DayOfWeek),
    XMLINIT(Year)
{}

tSerializableTimeZone::tSerializableTimeZone(const tinyxml2::XMLElement* xml) :
    XMLINIT(Bias), XMLINIT(StandardTime), XMLINIT(DaylightTime)
{}

void tSingleRecipient::serialize(XMLElement* xml) const
{XMLDUMPT(Mailbox);}

void tSmtpDomain::serialize(XMLElement* xml) const
{
	XMLDUMPT(Name);
	XMLDUMPT(IncludeSubdomains);
}

tSuggestionsViewOptions::tSuggestionsViewOptions(const tinyxml2::XMLElement* xml) :
    XMLINIT(GoodThreshold),
    XMLINIT(MaximumResultsByDay),
    XMLINIT(MaximumNonWorkHourResultsByDay),
    XMLINIT(MeetingDurationInMinutes),
    XMLINIT(MinimumSuggestionQuality),
    XMLINIT(DetailedSuggestionsWindow),
    XMLINIT(CurrentMeetingTime),
    XMLINIT(GlobalObjectId)
{}

void tSyncFolderHierarchyCU::serialize(XMLElement* xml) const
{XMLDUMPT(folder);}

tSyncFolderHierarchyDelete::tSyncFolderHierarchyDelete(const sBase64Binary& fEntryID) :
    FolderId(fEntryID)
{}

void tSyncFolderHierarchyDelete::serialize(XMLElement* xml) const
{XMLDUMPT(FolderId);}

void tSyncFolderItemsCU::serialize(XMLElement* xml) const
{XMLDUMPT(item);}

tSyncFolderItemsDelete::tSyncFolderItemsDelete(const TAGGED_PROPVAL& tp) : ItemId(tp)
{}


void tSyncFolderItemsDelete::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPT(ItemId);}

void tSyncFolderItemsReadFlag::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(ItemId);
	XMLDUMPT(IsRead);
}

tTargetFolderIdType::tTargetFolderIdType(const XMLElement* xml) :
    VXMLINIT(folderId)
{}

tUserOofSettings::tUserOofSettings(const XMLElement* xml) :
    XMLINIT(OofState),
    XMLINIT(ExternalAudience),
    XMLINIT(Duration),
    XMLINIT(InternalReply),
    XMLINIT(ExternalReply)
{}

void tUserOofSettings::serialize(XMLElement* xml) const
{
	XMLDUMPT(OofState);
	XMLDUMPT(ExternalAudience);
	XMLDUMPT(Duration);
	XMLDUMPT(InternalReply);
	XMLDUMPT(ExternalReply);
}

mGetFolderRequest::mGetFolderRequest(const XMLElement* xml) :
    XMLINIT(FolderShape), XMLINIT(FolderIds)
{}


void mGetFolderResponseMessage::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(Folders);
}

void mGetFolderResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mFreeBusyResponse::serialize(XMLElement* xml) const
{
	XMLDUMPM(ResponseMessage);
	XMLDUMPM(FreeBusyView);
}

mGetMailTipsRequest::mGetMailTipsRequest(const XMLElement* xml) :
    XMLINIT(SendingAs),
    XMLINIT(Recipients)
{}

void mMailTipsResponseMessageType::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(MailTips);
}

void mGetMailTipsResponse::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(ResponseMessages);
}

mGetServiceConfigurationRequest::mGetServiceConfigurationRequest(const XMLElement* xml) :
    XMLINIT(ActingAs), XMLINIT(RequestedConfiguration)
{}

void mGetServiceConfigurationResponse::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(ResponseMessages);
}

void mGetServiceConfigurationResponseMessageType::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(MailTipsConfiguration);
}

mGetUserAvailabilityRequest::mGetUserAvailabilityRequest(const XMLElement* xml) :
    XMLINIT(TimeZone), XMLINIT(MailboxDataArray), XMLINIT(FreeBusyViewOptions), XMLINIT(SuggestionsViewOptions)
{}

void mGetUserAvailabilityResponse::serialize(XMLElement* xml) const
{XMLDUMPM(FreeBusyResponseArray);}

mGetUserOofSettingsRequest::mGetUserOofSettingsRequest(const XMLElement* xml) :
    XMLINIT(Mailbox)
{}

void mGetUserOofSettingsResponse::serialize(XMLElement* xml) const
{
	XMLDUMPM(ResponseMessage);
	XMLDUMPT(OofSettings);
	XMLDUMPM(AllowExternalOof);
}

//TODO: Verify namespaces
void mResponseMessageType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPA(ResponseClass);
	XMLDUMPM(ResponseCode);
	XMLDUMPM(MessageText);
	XMLDUMPM(DescriptiveLinkKey);
}

mSetUserOofSettingsRequest::mSetUserOofSettingsRequest(const XMLElement* xml) :
    XMLINIT(Mailbox), XMLINIT(UserOofSettings)
{}

void mSetUserOofSettingsResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessage);}

mSyncFolderHierarchyRequest::mSyncFolderHierarchyRequest(const XMLElement* xml) :
    XMLINIT(FolderShape),
    XMLINIT(SyncFolderId),
    XMLINIT(SyncState)
{}

void mSyncFolderHierarchyResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(SyncState);
	XMLDUMPM(IncludesLastFolderInRange);
	XMLDUMPM(Changes);
}

void mSyncFolderHierarchyResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mSyncFolderItemsRequest::mSyncFolderItemsRequest(const XMLElement* xml) :
	XMLINIT(ItemShape),
	XMLINIT(SyncFolderId),
	XMLINIT(SyncState),
	XMLINIT(MaxChangesReturned),
	XMLINIT(SyncScope)
{}

void mSyncFolderItemsResponseMessage::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(SyncState);
	XMLDUMPM(IncludesLastItemInRange);
	XMLDUMPM(Changes);
}

void mSyncFolderItemsResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mGetItemRequest::mGetItemRequest(const XMLElement* xml) :
	XMLINIT(ItemShape),
	XMLINIT(ItemIds)
{}

void mGetItemResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mGetItemResponseMessage::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(Items);
}
