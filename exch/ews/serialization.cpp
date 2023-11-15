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
#define VXMLINIT(name) name(fromXMLNodeVariantFind<decltype(name)>(xml)) ///< Init variant from XML node
#define XMLDUMPM(name) toXMLNode(xml, "m:"#name, name) ///< Write member into XML node (Messages namespace)
#define XMLDUMPT(name) toXMLNode(xml, "t:"#name, name) ///< Write member into XML node (Types namespace)
#define XMLINITA(name) name(fromXMLAttr<decltype(name)>(xml, #name)) ///< Initialize member from XML attribute
#define XMLDUMPA(name) toXMLAttr(xml, #name, name) ///< Write member into XML attribute

#define EXT_TRY(expr) EWSContext::ext_error(expr)

namespace
{

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

void sAttachmentId::serialize(XMLElement* xml) const
{
	char buff[128], enc[256];
	EXT_PUSH ext_push;
	ext_push.init(buff, 128, 0, nullptr);
	EXT_TRY(ext_push.p_msg_eid(*this));
	EXT_TRY(ext_push.p_uint32(attachment_num));
	EXT_TRY(ext_push.p_int8(tBaseItemId::ID_ATTACHMENT));
	encode64(ext_push.m_vdata, ext_push.m_offset, enc, 256, nullptr);
	xml->SetAttribute("Id", enc);
}

void sOccurrenceId::serialize(XMLElement* xml) const
{
	char buff[128], enc[256];
	EXT_PUSH ext_push;
	ext_push.init(buff, 128, 0, nullptr);
	EXT_TRY(ext_push.p_msg_eid(*this));
	EXT_TRY(ext_push.p_uint32(basedate));
	EXT_TRY(ext_push.p_int8(tBaseItemId::ID_OCCURRENCE));
	encode64(ext_push.m_vdata, ext_push.m_offset, enc, 256, nullptr);
	xml->SetAttribute("Id", enc);
}

/**
 * @brief     Decode Base64 encoded data from XML element
 */
sBase64Binary::sBase64Binary(const XMLElement* xml)
{
	const char* data = xml->GetText();
	if(!data)
		throw DeserializationError(E3034(xml->Name()));
	assign(base64_decode(data));
}

/**
 * @brief     Decode Base64 encoded data from XML attribute
 */
sBase64Binary::sBase64Binary(const XMLAttribute *xml) : std::string(base64_decode(xml->Value()))
{}

/**
 * @brief     Return Base64 encoded data
 *
 * @return    std::string containing base64 encoded data
 */
std::string sBase64Binary::serialize() const
{ return empty() ? std::string() : base64_encode(*this); }

/**
 * @brief     Store Base64 encoded data in xml element
 *
 * @param     xml     XML element to store data in
 */
void sBase64Binary::serialize(XMLElement* xml) const
{ xml->SetText(empty() ? "" : base64_encode(*this).c_str()); }

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
 * @return    Base64 binary containing entry ID
 */
sBase64Binary sFolderEntryId::serialize() const
{
	sBase64Binary bin;
	bin.resize(46);
	EXT_PUSH ext_push;
	ext_push.init(bin.data(), 46, 0, nullptr);
	EXT_TRY(ext_push.p_folder_eid(*this));
	bin.resize(ext_push.m_offset);
	return bin;
}

/**
 * @brief     Generate entry ID object
 *
 * @return    Base64 binary containing entry ID
 */
sBase64Binary sMessageEntryId::serialize() const
{
	sBase64Binary bin;
	bin.resize(70);
	EXT_PUSH ext_push;
	ext_push.init(bin.data(), 70, 0, nullptr);
	EXT_TRY(ext_push.p_msg_eid(*this));
	bin.resize(ext_push.m_offset);
	return bin;
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
		throw EWSError::NotEnoughMemory(E3035);
	std::unique_ptr<BINARY, Cleaner> ser(given.serialize());
	if (!ser || pproplist->set(MetaTagIdsetGiven1, ser.get()))
		throw EWSError::NotEnoughMemory(E3036);
	ser.reset(seen.serialize());
	if (!ser || pproplist->set(MetaTagCnsetSeen, ser.get()))
		throw EWSError::NotEnoughMemory(E3037);
	ser.reset();
	if(!seen_fai.empty())
	{
		ser.reset(seen_fai.serialize());
		if (!ser || pproplist->set(MetaTagCnsetSeenFAI, ser.get()))
			throw EWSError::NotEnoughMemory(E3038);
	}
	if(!read.empty())
	{
		ser.reset(read.serialize());
		if (!ser || pproplist->set(MetaTagCnsetRead, ser.get()))
			throw EWSError::NotEnoughMemory(E3039);
	}
	ser.reset();
	if (readOffset != 0 && pproplist->set(MetaTagReadOffset, &readOffset) != 0)
		/* ignore error */;

	EXT_PUSH stateBuffer;
	if(!stateBuffer.init(nullptr, 0, EXT_FLAG_WCOUNT) || stateBuffer.p_tpropval_a(*pproplist) != EXT_ERR_SUCCESS)
		throw EWSError::NotEnoughMemory(E3040);

	return base64_encode({stateBuffer.m_cdata, stateBuffer.m_offset});
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
	std::string dtstr = fmt::format("{:%FT%T}", t);
	if(fsec)
		dtstr += fmt::format(".{:06}", fsec);
	dtstr += off? fmt::format("{:+03}{:02}", off/60, abs(off)%60) : "Z";
	xml->SetText(dtstr.c_str());
}

///////////////////////////////////////////////////////////////////////////////////////////////////

void tAttachment::serialize(XMLElement* xml) const
{
	XMLDUMPT(AttachmentId);
	XMLDUMPT(Name);
	XMLDUMPT(ContentType);
	XMLDUMPT(ContentId);
	XMLDUMPT(ContentLocation);
	XMLDUMPT(AttachmentOriginalUrl);
	XMLDUMPT(Size);
	XMLDUMPT(LastModifiedTime);
	XMLDUMPT(IsInline);
}

tBaseFolderType::tBaseFolderType(const XMLElement* xml) :
	XMLINIT(FolderClass),
	XMLINIT(DisplayName)
{
	for(const tinyxml2::XMLElement* xp = xml->FirstChildElement("ExtendedProperty"); xp; xp = xp->NextSiblingElement("ExtendedProperty"))
		ExtendedProperty.emplace_back(xp);
}

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
{
	if(Id.empty())
		type = ID_UNKNOWN;
	else {
		char t = Id.back();
		type = (t < 0 || t > ID_OCCURRENCE)? ID_UNKNOWN : IdType(t);
		Id.pop_back();
	}
}

void tBaseItemId::serialize(XMLElement* xml) const
{
	IdType t = type;
	if(t == ID_UNKNOWN)  // try to guess from entry id size, if that fails, someone forgot to mark the correct type
		t = Id.size() == 46? ID_FOLDER : Id.size() == 70? ID_ITEM : throw DispatchError(E3212);
	Id.append(1, t);
	XMLDUMPA(Id);
	Id.pop_back();
	XMLDUMPA(ChangeKey);
}

void tBaseObjectChangedEvent::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(TimeStamp);
	XMLDUMPT(objectId);
	XMLDUMPT(ParentFolderId);
}

tBaseSubscriptionRequest::tBaseSubscriptionRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(FolderIds),
	XMLINIT(EventTypes)
{}

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

void tIntervalRecurrencePatternBase::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPT(Interval);}

void tRelativeYearlyRecurrencePattern::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(DaysOfWeek);
	XMLDUMPT(DayOfWeekIndex);
	XMLDUMPT(Month);
}

void tAbsoluteYearlyRecurrencePattern::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(DayOfMonth);
	XMLDUMPT(Month);
}

void tRelativeMonthlyRecurrencePattern::serialize(tinyxml2::XMLElement* xml) const
{
	tIntervalRecurrencePatternBase::serialize(xml);

	XMLDUMPT(DaysOfWeek);
	XMLDUMPT(DayOfWeekIndex);
}

void tAbsoluteMonthlyRecurrencePattern::serialize(tinyxml2::XMLElement* xml) const
{
	tIntervalRecurrencePatternBase::serialize(xml);

	XMLDUMPT(DayOfMonth);
}

void tWeeklyRecurrencePattern::serialize(tinyxml2::XMLElement* xml) const
{
	tIntervalRecurrencePatternBase::serialize(xml);

	XMLDUMPT(DaysOfWeek);
	XMLDUMPT(FirstDayOfWeek);
}

void tDailyRecurrencePattern::serialize(tinyxml2::XMLElement* xml) const
{
	tIntervalRecurrencePatternBase::serialize(xml);
}

void tRecurrenceRangeBase::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(StartDate);
}

void tNoEndRecurrenceRange::serialize(tinyxml2::XMLElement* xml) const
{
	tRecurrenceRangeBase::serialize(xml);
}

void tNotification::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(SubscriptionId);
	XMLDUMPT(MoreEvents);
	for(const auto& event : events)
		XMLDUMPT(event);
}

void tEndDateRecurrenceRange::serialize(tinyxml2::XMLElement* xml) const
{
	tRecurrenceRangeBase::serialize(xml);

	XMLDUMPT(EndDate);
}

void tNumberedRecurrenceRange::serialize(tinyxml2::XMLElement* xml) const
{
	tRecurrenceRangeBase::serialize(xml);

	XMLDUMPT(NumberOfOccurrences);
}

void tRecurrenceType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(RecurrencePattern);
	XMLDUMPT(RecurrenceRange);
}

void tOccurrenceInfoType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(ItemId);
	XMLDUMPT(Start);
	XMLDUMPT(End);
	XMLDUMPT(OriginalStart);
}

void tDeletedOccurrenceInfoType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPT(Start);
}

tCalendarItem::tCalendarItem(const tinyxml2::XMLElement* xml) :
	tItem(xml),
	XMLINIT(UID),
	XMLINIT(Start),
	XMLINIT(End),
	XMLINIT(OriginalStart),
	XMLINIT(IsAllDayEvent),
	XMLINIT(LegacyFreeBusyStatus),
	XMLINIT(Location),
	XMLINIT(IsMeeting),
	XMLINIT(IsCancelled),
	XMLINIT(IsRecurring),
	XMLINIT(MeetingRequestWasSent),
	XMLINIT(IsResponseRequested),
	XMLINIT(MyResponseType),
	XMLINIT(Organizer),
//	XMLINIT(RequiredAttendees),
//	XMLINIT(OptionalAttendees),
//	XMLINIT(Resources),
	XMLINIT(AppointmentReplyTime),
	XMLINIT(AppointmentSequenceNumber),
	XMLINIT(AppointmentState),
//	XMLINIT(Recurrence),
	XMLINIT(AllowNewTimeProposal)
{}

void tCalendarItem::serialize(tinyxml2::XMLElement* xml) const
{
	tItem::serialize(xml);

	XMLDUMPT(UID);
	XMLDUMPT(RecurrenceId);
	XMLDUMPT(Start);
	XMLDUMPT(End);
	XMLDUMPT(IsAllDayEvent);
	XMLDUMPT(LegacyFreeBusyStatus);
	XMLDUMPT(Location);
	XMLDUMPT(IsMeeting);
	XMLDUMPT(IsCancelled);
	XMLDUMPT(IsRecurring);
	XMLDUMPT(MeetingRequestWasSent);
	XMLDUMPT(IsResponseRequested);
	XMLDUMPT(MyResponseType);
	XMLDUMPT(Organizer);
	XMLDUMPT(RequiredAttendees);
	XMLDUMPT(OptionalAttendees);
	XMLDUMPT(Resources);
	XMLDUMPT(AppointmentReplyTime);
	XMLDUMPT(AppointmentSequenceNumber);
	XMLDUMPT(AppointmentState);
	XMLDUMPT(Recurrence);
	XMLDUMPT(ModifiedOccurrences);
	XMLDUMPT(DeletedOccurrences);
	XMLDUMPT(AllowNewTimeProposal);
}

tChangeDescription::tChangeDescription(const tinyxml2::XMLElement* xml) :
	fieldURI(fromXMLNodeVariantFind<tPath::Base>(xml))
{}

void tConflictResults::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPT(Count);}

tContact::tContact(const tinyxml2::XMLElement* xml) :
	tItem(xml),
	XMLINIT(FileAs),
	XMLINIT(DisplayName),
	XMLINIT(GivenName),
	XMLINIT(Initials),
	XMLINIT(MiddleName),
	XMLINIT(Nickname),
	XMLINIT(CompanyName),
//	XMLINIT(EmailAddresses),
//	XMLINIT(PhoneNumbers),
	XMLINIT(AssistantName),
	XMLINIT(ContactSource),
	XMLINIT(Department),
	XMLINIT(JobTitle),
	XMLINIT(OfficeLocation),
	XMLINIT(Surname)
{}

void tContact::serialize(tinyxml2::XMLElement* xml) const
{
	tItem::serialize(xml);

	XMLDUMPT(FileAs);
	XMLDUMPT(DisplayName);
	XMLDUMPT(GivenName);
	XMLDUMPT(Initials);
	XMLDUMPT(MiddleName);
	XMLDUMPT(Nickname);
	XMLDUMPT(CompanyName);
	XMLDUMPT(EmailAddresses);
	XMLDUMPT(PhoneNumbers);
	XMLDUMPT(AssistantName);
	XMLDUMPT(Department);
	XMLDUMPT(ContactSource);
	XMLDUMPT(JobTitle);
	XMLDUMPT(OfficeLocation);
	XMLDUMPT(Surname);
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

void tEmailAddressDictionaryEntry::serialize(tinyxml2::XMLElement* xml) const
{
	xml->SetText(Entry.c_str());
	XMLDUMPA(Key);
	XMLDUMPA(Name);
	XMLDUMPA(RoutingType);
	XMLDUMPA(MailboxType);
}

void tFileAttachment::serialize(tinyxml2::XMLElement* xml) const
{
	tAttachment::serialize(xml);
	XMLDUMPT(IsContactPhoto);
	XMLDUMPT(Content);
}

void tPhoneNumberDictionaryEntry::serialize(tinyxml2::XMLElement* xml) const
{
	xml->SetText(Entry.c_str());
	XMLDUMPA(Key);
}

tPullSubscriptionRequest::tPullSubscriptionRequest(const tinyxml2::XMLElement* xml) :
	tBaseSubscriptionRequest(xml),
	XMLINIT(Timeout)
{}

tExtendedFieldURI::tExtendedFieldURI(const tinyxml2::XMLElement* xml) :
	XMLINITA(PropertyTag),
	XMLINITA(PropertyType),
	XMLINITA(PropertyId),
	XMLINITA(DistinguishedPropertySetId),
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

tExtendedProperty::tExtendedProperty(const XMLElement* xml) :
	XMLINIT(ExtendedFieldURI)
{
	const XMLElement* value = xml->FirstChildElement("Value");
	const XMLElement* values = xml->FirstChildElement("Values");
	uint16_t type = ExtendedFieldURI.type();
	propval.proptag = ExtendedFieldURI.tag()? ExtendedFieldURI.tag() : type;
	bool ismv = type & MV_FLAG;
	if(value && values)
		throw InputError(E3094);
	if(ismv && !values)
		throw InputError(E3095);
	if(!ismv && !value)
		throw InputError(E3096);
	deserialize(ismv? values : value, type);
}

void tExtendedProperty::serialize(XMLElement* xml) const
{
	const void* data = propval.pvalue;
	if(!data)
		return;
	XMLDUMPT(ExtendedFieldURI);
	bool ismv = propval.proptag & MV_FLAG;
	XMLElement* value = xml->InsertNewChildElement(ismv? "t:Values" : "t:Value");
	serialize(data, PROP_TYPE(propval.proptag), value);
}

tFieldURI::tFieldURI(const XMLElement* xml) :
	XMLINITA(FieldURI)
{}

void tFlagType::serialize(XMLElement* xml) const
{XMLDUMPT(FlagStatus);}

tFolderChange::tFolderChange(const tinyxml2::XMLElement* xml) :
	VXMLINIT(folderId),
	XMLINIT(Updates)
{}

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

tIndexedFieldURI::tIndexedFieldURI(const XMLElement* xml) :
	XMLINITA(FieldURI),
	XMLINITA(FieldIndex)
{}

void tInternetMessageHeader::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPA(HeaderName);
	xml->SetText(content.c_str());
}

tItem::tItem(const tinyxml2::XMLElement* xml) :
	XMLINIT(MimeContent),
//	XMLINIT(ItemId),
//	XMLINIT(ParentFolderId),
	XMLINIT(ItemClass),
	XMLINIT(Subject),
	XMLINIT(Sensitivity),
//	XMLINIT(Body),
//	XMLINIT(Attachments),
//	XMLINIT(DateTimeReceived),
//	XMLINIT(Size),
	XMLINIT(Categories),
	XMLINIT(Importance),
	XMLINIT(InReplyTo),
	XMLINIT(IsSubmitted),
	XMLINIT(IsDraft),
	XMLINIT(IsFromMe),
	XMLINIT(IsResend),
	XMLINIT(IsUnmodified),
//	XMLINIT(InternetMessageHeaders),
//	XMLINIT(DateTimeSent),
//	XMLINIT(DateTimeCreated),
	XMLINIT(DisplayCc),
	XMLINIT(DisplayTo),
	XMLINIT(DisplayBcc),
//	XMLINIT(HasAttachments),
//	XMLINIT(Culture),
//	XMLINIT(LastModifiedName),
//	XMLINIT(LastModifiedTime),
	XMLINIT(IsAssociated)
//	XMLINIT(ConversationId),
//	XMLINIT(Flag)
{
	for(const tinyxml2::XMLElement* xp = xml->FirstChildElement("ExtendedProperty"); xp; xp = xp->NextSiblingElement("ExtendedProperty"))
		ExtendedProperty.emplace_back(xp);
}

void tItem::serialize(XMLElement* xml) const
{
	auto mc = XMLDUMPT(MimeContent);
	if(mc)
		mc->SetAttribute("CharacterSet", "UTF-8");
	XMLDUMPT(ItemId);
	XMLDUMPT(ParentFolderId);
	XMLDUMPT(ItemClass);
	XMLDUMPT(Subject);
	XMLDUMPT(Sensitivity);
	XMLDUMPT(Body);
	XMLDUMPT(Attachments);
	XMLDUMPT(DateTimeReceived);
	XMLDUMPT(Size);
	XMLDUMPT(Categories);
	XMLDUMPT(Importance);
	XMLDUMPT(InReplyTo);
	XMLDUMPT(IsSubmitted);
	XMLDUMPT(IsDraft);
	XMLDUMPT(IsFromMe);
	XMLDUMPT(IsResend);
	XMLDUMPT(IsUnmodified);
	XMLDUMPT(InternetMessageHeaders);
	XMLDUMPT(DateTimeSent);
	XMLDUMPT(DateTimeCreated);
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

tItemChange::tItemChange(const XMLElement* xml) :
	XMLINIT(ItemId),
	XMLINIT(Updates)
{}

tItemResponseShape::tItemResponseShape(const XMLElement* xml) :
	XMLINIT(IncludeMimeContent),
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

tMessage::tMessage(const tinyxml2::XMLElement* xml) :
	tItem(xml),
	XMLINIT(Sender),
	XMLINIT(ToRecipients),
	XMLINIT(CcRecipients),
	XMLINIT(BccRecipients),
	XMLINIT(IsReadReceiptRequested),
	XMLINIT(IsDeliveryReceiptRequested),
	XMLINIT(ConversationIndex),
	XMLINIT(ConversationTopic),
	XMLINIT(From),
	XMLINIT(InternetMessageId),
	XMLINIT(IsRead),
	XMLINIT(IsResponseRequested),
	XMLINIT(References),
	XMLINIT(ReplyTo),
	XMLINIT(ReceivedBy),
	XMLINIT(ReceivedRepresenting)
{}

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
	XMLDUMPT(InternetMessageId);
	XMLDUMPT(IsRead);
	XMLDUMPT(IsResponseRequested);
	XMLDUMPT(References);
	XMLDUMPT(ReplyTo);
	XMLDUMPT(ReceivedBy);
	XMLDUMPT(ReceivedRepresenting);
}

void tModifiedEvent::serialize(tinyxml2::XMLElement* xml) const
{
	tBaseObjectChangedEvent::serialize(xml);
	XMLDUMPT(UnreadCount);
}

void tMovedCopiedEvent::serialize(tinyxml2::XMLElement* xml) const
{
	tBaseObjectChangedEvent::serialize(xml);
	XMLDUMPT(oldObjectId);
	XMLDUMPT(OldParentFolderId);
}

tPath::tPath(const XMLElement* xml) : Base(fromXMLNodeDispatch<Base>(xml))
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

tSetFolderField::tSetFolderField(const tinyxml2::XMLElement* xml) : tChangeDescription(xml)
{
	for(const tinyxml2::XMLElement* child = xml->FirstChildElement(); child; child = child->NextSiblingElement())
		if(std::binary_search(folderTypes.begin(), folderTypes.end(), child->Name(),
		                      [](const char* s1, const char* s2){return strcmp(s1, s2) < 0;})) {
			folder = child;
			break;
		}
	if(!folder)
		throw InputError(E3177);
}

tSetItemField::tSetItemField(const tinyxml2::XMLElement* xml) : tChangeDescription(xml)
{
	for(const tinyxml2::XMLElement* child = xml->FirstChildElement(); child; child = child->NextSiblingElement())
		if(std::binary_search(itemTypes.begin(), itemTypes.end(), child->Name(),
		                      [](const char* s1, const char* s2){return strcmp(s1, s2) < 0;})) {
			item = child;
			break;
		}
	if(!item)
		throw InputError(E3097);
}

tSingleRecipient::tSingleRecipient(const tinyxml2::XMLElement* xml) :
	XMLINIT(Mailbox)
{}

void tSingleRecipient::serialize(XMLElement* xml) const
{XMLDUMPT(Mailbox);}

void tAttendee::serialize(XMLElement* xml) const
{
	XMLDUMPT(Mailbox);
	XMLDUMPT(ResponseType);
	XMLDUMPT(LastResponseTime);
	XMLDUMPT(ProposedStart);
	XMLDUMPT(ProposedEnd);
}

void tSmtpDomain::serialize(XMLElement* xml) const
{
	XMLDUMPT(Name);
	XMLDUMPT(IncludeSubdomains);
}

/**
 * @brief      Base64 encode 32bit unsigned integer
 *
 * @param      v   Value to encode
 * @param      d   Destination buffer. Must have space for 6 characters. Pointer is moved to the end of the string.
 */
constexpr void tSubscriptionId::encode(uint32_t v, char*& d)
{
	for(uint32_t offset = 0; offset < 31; offset += 6)
		*d++ = b64[(v & (0x3fu << offset)) >> offset];
}

/**
 * @brief      Base64 decode 32bit unsigned integer
 *
 * @param      s   Data to decode. Pointer is moved to the end of the string.
 *
 * @throw      DeserializationError  The input contains invalid characters
 *
 * @return Decoded value
 */
constexpr uint32_t tSubscriptionId::decode(const uint8_t*& s)
{
	uint32_t res = 0;
	for(uint32_t offset = 0; offset < 6; ++s, ++offset)
		res |= *s < 128 && i64[*s] >= 0? (i64[*s] << offset*6) : throw DeserializationError(E3112);
	return res;
}

tSubscriptionId::tSubscriptionId(const tinyxml2::XMLElement* xml)
{
	const char* data = xml->GetText();
	size_t len;
	if(!data || (len = strlen(data)) != 12)
		throw DeserializationError(E3201);
	const uint8_t* d = reinterpret_cast<const uint8_t*>(data);
	ID = decode(d);
	timeout = decode(d);
}

void tSubscriptionId::serialize(tinyxml2::XMLElement* xml) const
{
	std::string res(12, 0);
	char* data = res.data();
	encode(ID, data);
	encode(timeout, data);
	xml->SetText(res.c_str());
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

///////////////////////////////////////////////////////////////////////////////////////////////////

mBaseMoveCopyFolder::mBaseMoveCopyFolder(const tinyxml2::XMLElement* xml, bool c) :
	XMLINIT(ToFolderId),
	XMLINIT(FolderIds),
	copy(c)
{}

mBaseMoveCopyItem::mBaseMoveCopyItem(const tinyxml2::XMLElement* xml, bool c) :
	XMLINIT(ToFolderId),
	XMLINIT(ItemIds),
	XMLINIT(ReturnNewItemIds),
	copy(c)
{}

mCopyFolderRequest::mCopyFolderRequest(const tinyxml2::XMLElement* xml) :
	mBaseMoveCopyFolder(xml, true)
{}

void mCopyFolderResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mCopyItemRequest::mCopyItemRequest(const tinyxml2::XMLElement* xml) :
	mBaseMoveCopyItem(xml, true)
{}

void mCopyItemResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mCreateFolderRequest::mCreateFolderRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(ParentFolderId),
	XMLINIT(Folders)
{}

void mCreateFolderResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mCreateItemRequest::mCreateItemRequest(const tinyxml2::XMLElement* xml) :
	XMLINITA(MessageDisposition),
	XMLINITA(SendMeetingInvitations),
	XMLINIT(SavedItemFolderId),
	XMLINIT(Items)
{}

void mCreateItemResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mDeleteFolderRequest::mDeleteFolderRequest(const tinyxml2::XMLElement* xml) :
	XMLINITA(DeleteType),
	XMLINIT(FolderIds)
{}

void mDeleteFolderResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mDeleteItemRequest::mDeleteItemRequest(const tinyxml2::XMLElement* xml) :
	XMLINITA(DeleteType),
	XMLINIT(ItemIds)
{}

void mDeleteItemResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mEmptyFolderRequest::mEmptyFolderRequest(const tinyxml2::XMLElement* xml) :
	XMLINITA(DeleteType),
	XMLINITA(DeleteSubFolders),
	XMLINIT(FolderIds)
{}

void mEmptyFolderResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mFolderInfoResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(Folders);
}

mGetAttachmentRequest::mGetAttachmentRequest(const XMLElement* xml) :
	XMLINIT(AttachmentIds)
{}

void mGetAttachmentResponseMessage::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(Attachments);
}

mGetEventsRequest::mGetEventsRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(SubscriptionId)
{}

void mGetEventsResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mGetEventsResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(Notification);
}

void mGetAttachmentResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

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

mGetStreamingEventsRequest::mGetStreamingEventsRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(SubscriptionIds),
	XMLINIT(ConnectionTimeout)
{}

void mGetStreamingEventsResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mGetStreamingEventsResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPM(Notifications);
	XMLDUMPM(ErrorSubscriptionIds);
	XMLDUMPM(ConnectionStatus);
}

mGetUserAvailabilityRequest::mGetUserAvailabilityRequest(const XMLElement* xml) :
	XMLINIT(TimeZone),
	XMLINIT(MailboxDataArray),
	XMLINIT(FreeBusyViewOptions),
	XMLINIT(SuggestionsViewOptions)
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

mGetUserPhotoRequest::mGetUserPhotoRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(Email)
{}

void mGetUserPhotoResponse::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(HasChanged);
	XMLDUMPM(PictureData);
}

void mItemInfoResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(Items);
}

mMoveFolderRequest::mMoveFolderRequest(const tinyxml2::XMLElement* xml) :
	mBaseMoveCopyFolder(xml, false)
{}

void mMoveFolderResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mMoveItemRequest::mMoveItemRequest(const tinyxml2::XMLElement* xml) :
	mBaseMoveCopyItem(xml, false)
{}

void mMoveItemResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mResponseMessageType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPA(ResponseClass);
	XMLDUMPM(ResponseCode);
	XMLDUMPM(MessageText);
	XMLDUMPM(DescriptiveLinkKey);
}

mSendItemRequest::mSendItemRequest(const tinyxml2::XMLElement* xml) :
	XMLINITA(SaveItemToFolder),
	XMLINIT(ItemIds),
	XMLINIT(SavedItemFolderId)
{}

void mSendItemResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(Responses);}

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

void tFindResponsePagingAttributes::serialize(XMLElement* xml) const
{
	XMLDUMPA(IndexedPagingOffset);
	XMLDUMPA(NumeratorOffset);
	XMLDUMPA(AbsoluteDenominator);
	XMLDUMPA(IncludesLastItemInRange);
	XMLDUMPA(TotalItemsInView);
}

void tResolution::serialize(XMLElement* xml) const
{
	tFindResponsePagingAttributes::serialize(xml);

	XMLDUMPT(Mailbox);
	XMLDUMPT(Contact);
}

mResolveNamesRequest::mResolveNamesRequest(const XMLElement* xml) :
	XMLINIT(ParentFolderIds),
	XMLINIT(UnresolvedEntry),
	XMLINITA(ReturnFullContactData),
	XMLINITA(SearchScope),
	XMLINITA(ContactDataShape)
{}

void mResolveNamesResponseMessage::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(ResolutionSet);
}

void mResolveNamesResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mUpdateFolderRequest::mUpdateFolderRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(FolderChanges)
{}

void mUpdateFolderResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mSubscribeRequest::mSubscribeRequest(const tinyxml2::XMLElement* xml) :
	VXMLINIT(subscription)
{}

void mSubscribeResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mSubscribeResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMPM(SubscriptionId);
}

mUnsubscribeRequest::mUnsubscribeRequest(const tinyxml2::XMLElement* xml) :
	XMLINIT(SubscriptionId)
{}

void mUnsubscribeResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

mUpdateItemRequest::mUpdateItemRequest(const XMLElement* xml) :
	XMLINIT(ItemChanges)
{}

void mUpdateItemResponse::serialize(XMLElement* xml) const
{XMLDUMPM(ResponseMessages);}

void mUpdateItemResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mItemInfoResponseMessage::serialize(xml);
	XMLDUMPM(ConflictResults);
}
