// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
/**
 * @brief      Implementation of EWS structure (de-)serialization
 */
#include <iterator>

#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

#include <gromox/ical.hpp>
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

using namespace std::string_literals;
using namespace Exceptions;
using gromox::EWS::SOAP::NS_MSGS;
using gromox::EWS::SOAP::NS_TYPS;

///////////////////////////////////////////////////////////////////////////////////////////////////

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

decltype(sFolderSpec::distNameInfo) sFolderSpec::distNameInfo = {{
    {"calendar", PRIVATE_FID_CALENDAR, sFolderSpec::CALENDAR, true},
    {"conflicts", PRIVATE_FID_CONFLICTS, sFolderSpec::NORMAL, true},
    {"contacts", PRIVATE_FID_CONTACTS, sFolderSpec::CONTACTS, true},
    {"deleteditems", PRIVATE_FID_DELETED_ITEMS, sFolderSpec::NORMAL, true},
    {"drafts", PRIVATE_FID_DRAFT, sFolderSpec::NORMAL, true},
    {"imcontactlist", PRIVATE_FID_IMCONTACTLIST, sFolderSpec::NORMAL, true},
    {"inbox", PRIVATE_FID_INBOX, sFolderSpec::NORMAL, true},
    {"journal", PRIVATE_FID_JOURNAL, sFolderSpec::NORMAL, true},
    {"junkemail", PRIVATE_FID_JUNK, sFolderSpec::NORMAL, true},
    {"localfailures", PRIVATE_FID_LOCAL_FAILURES, sFolderSpec::NORMAL, true},
    {"msgfolderroot", PRIVATE_FID_IPMSUBTREE, sFolderSpec::NORMAL, true},
    {"notes", PRIVATE_FID_NOTES, sFolderSpec::NORMAL, true},
    {"outbox", PRIVATE_FID_OUTBOX, sFolderSpec::NORMAL, true},
    {"publicfoldersroot", PUBLIC_FID_IPMSUBTREE, sFolderSpec::NORMAL, false},
    {"quickcontacts", PRIVATE_FID_QUICKCONTACTS, sFolderSpec::NORMAL, true},
    {"root", PRIVATE_FID_ROOT, sFolderSpec::NORMAL, true},
    {"scheduled", PRIVATE_FID_SCHEDULE, sFolderSpec::NORMAL, true},
    {"sentitems", PRIVATE_FID_SENT_ITEMS, sFolderSpec::NORMAL, true},
    {"serverfailures", PRIVATE_FID_SERVER_FAILURES, sFolderSpec::NORMAL, true},
    {"syncissues", PRIVATE_FID_SYNC_ISSUES, sFolderSpec::NORMAL, true},
    {"tasks", PRIVATE_FID_TASKS, sFolderSpec::TASKS, true},
}};

/**
 * @brief     Derive folder specification from FolderId type
 *
 * Currently uses a custom human readable format.
 *
 * @todo     Use a better Id representation
 *
 * @param    folder  Folder ID
 */
sFolderSpec::sFolderSpec(const tFolderId& folder)
{
	size_t b1 = folder.Id.find(':');
	size_t b2 = folder.Id.find(':', b1+1);
	if(b1 == std::string::npos || b2 == std::string::npos)
		throw DeserializationError("Malformed folder specification: "+folder.Id);
	if(b1 > 0)
		target = folder.Id.substr(0, b1);
	printf("%s\n", folder.Id.substr(b1+1, b2-b1).c_str());
	printf("%s\n", folder.Id.substr(b2+1).c_str());
	folderId = std::stoull(folder.Id.substr(b1+1, b2-b1));
	type = Type(std::stoul(folder.Id.substr(b2+1)));
}

/**
 * @brief     Derive folder specification from distinguished ID
 *
 * @param     folder  Distinguished ID
 */
sFolderSpec::sFolderSpec(const tDistinguishedFolderId& folder)
{
	auto it = std::find_if(distNameInfo.begin(), distNameInfo.end(),
	                       [&folder](const auto& elem){return folder.Id == elem.name;});
	if(it == distNameInfo.end())
		throw DeserializationError("Unknown distinguished folder id "+folder.Id);
	folderId = rop_util_make_eid_ex(1, it->id);
	type = it->type;
	location = it->isPrivate? PRIVATE : PUBLIC;
	if(folder.Mailbox)
		target = folder.Mailbox->EmailAddress;
}

/**
 * @brief     Explicit initialization for direct serialization
 */
sFolderSpec::sFolderSpec(const std::string_view& target, uint64_t folderId, Type type) :
    target(target), folderId(folderId), type(type)
{}

/**
 * @brief     Trim target specification according to location
 */
void sFolderSpec::normalize()
{
	if(location != PUBLIC || !target)
		return;
	size_t at = target->find('@');
	if(at == std::string::npos)
		return;
	target->erase(0, at+1);
}

/**
 * @brief     Generate ID string from specification
 *
 * @todo      Use a better Id representation
 *
 * @return    ID string
 */
std::string sFolderSpec::serialize() const
{
	return (target? *target : "")+':'+std::to_string(folderId)+':'+std::to_string(type);
}

///////////////////////////////////////////////////////////////////////////////

sTime::sTime(const XMLElement* xml)
{
	const char* data = xml->GetText();
	if(!data)
		throw DeserializationError("Element '"s+xml->Name()+"'is empty");
	if(sscanf(data, "%02hhu:%02hhu:%02hhu", &hour, &minute, &second) != 3)
		throw DeserializationError("Element "s+xml->Name()+"="+xml->GetText()+"' has bad format (expected hh:mm:ss)");
}

sTimePoint::sTimePoint(const gromox::time_point& tp) : time(tp)
{}

sTimePoint::sTimePoint(const gromox::time_point& tp, const tSerializableTimeZone& tz) :
    time(tp), offset(tz.offset(tp))
{}

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
		xml->SetText(fmt::format("{:%FT%T}.{:06}{:+03}{:02}",
			t, fsec, off / 60, abs(off) % 60).c_str());
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Types implementation


void tBaseFolderType::serialize(XMLElement* xml) const
{
	XMLDUMP(FolderId);
	XMLDUMP(ParentFolderId);
	XMLDUMP(FolderClass);
	XMLDUMP(DisplayName);
	XMLDUMP(TotalCount);
	XMLDUMP(ChildFolderCount);
	for(const tExtendedProperty& ep : ExtendendProperty)
		toXMLNode(xml, "ExtendedProperty", ep);
}

///////////////////////////////////////////////////////////////////////////////

void tCalendarEventDetails::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMP(ID);
	XMLDUMP(Subject);
	XMLDUMP(Location);
	XMLDUMP(IsMeeting);
	XMLDUMP(IsRecurring);
	XMLDUMP(IsException);
	XMLDUMP(IsReminderSet);
	XMLDUMP(IsPrivate);
}

///////////////////////////////////////////////////////////////////////////////


void tCalendarEvent::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMP(StartTime);
	XMLDUMP(EndTime);
	XMLDUMP(BusyType);
	XMLDUMP(CalenderEventDetails);
}

///////////////////////////////////////////////////////////////////////////////

tDistinguishedFolderId::tDistinguishedFolderId(const tinyxml2::XMLElement* xml) :
    XMLINIT(Mailbox),
    XMLINITA(ChangeKey),
    XMLINITA(Id)
{}

///////////////////////////////////////////////////////////////////////////////

tDuration::tDuration(const XMLElement* xml) :
    XMLINIT(StartTime), XMLINIT(EndTime)
{}

void tDuration::serialize(XMLElement* xml) const
{
	XMLDUMP(StartTime);
	XMLDUMP(EndTime);
}

///////////////////////////////////////////////////////////////////////////////

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
	XMLDUMP(Name);
    XMLDUMP(EmailAddress);
    XMLDUMP(RoutingType);
    XMLDUMP(MailboxType);
    XMLDUMP(ItemId);
    XMLDUMP(OriginalDisplayName);
}

///////////////////////////////////////////////////////////////////////////////

decltype(tExtendedFieldURI::typeMap) tExtendedFieldURI::typeMap = {{
	{"ApplicationTime", PT_APPTIME},
	{"ApplicationTimeArray", PT_MV_APPTIME},
	{"Binary", PT_BINARY},
	{"BinaryArray", PT_MV_BINARY},
	{"Boolean", PT_BOOLEAN},
	{"CLSID", PT_CLSID},
	{"CLSIDArray", PT_MV_CLSID},
	{"Currency", PT_CURRENCY},
	{"CurrencyArray", PT_MV_CURRENCY},
	{"Double", PT_DOUBLE},
	{"DoubleArray", PT_MV_DOUBLE},
	{"Error", PT_ERROR},
	{"Float", PT_FLOAT},
	{"FloatArray", PT_MV_FLOAT},
	{"Integer", PT_LONG},
	{"IntegerArray", PT_MV_LONG},
	{"Long", PT_I8},
	{"LongArray", PT_MV_I8},
	{"Null", PT_UNSPECIFIED},
	{"Object", PT_OBJECT},
	//{"ObjectArray", ???},
	{"Short", PT_SHORT},
	{"ShortArray", PT_MV_SHORT},
	{"String", PT_UNICODE},
	{"StringArray", PT_MV_UNICODE},
	{"SystemTime", PT_SYSTIME},
	{"SystemTimeArray", PT_MV_SYSTIME},
}};

tExtendedFieldURI::tExtendedFieldURI(const tinyxml2::XMLElement* xml) :
    XMLINITA(PropertyTag),
    XMLINITA(PropertyType)
{}

/**
 * @brief     Generate URI from tag ID
 *
 * @param     tag     Property tag ID
 */
tExtendedFieldURI::tExtendedFieldURI(uint32_t tag) :
    PropertyTag(std::in_place_t(), 6, '0'),
    PropertyType(typeName(PROP_TYPE(tag)))
{
	static constexpr char digits[] = "0123456789abcdef";
	std::string& proptag = *PropertyTag;
	proptag[0] = '0';
	proptag[1] = 'x';
	proptag[2] = digits[(tag >> 28) & 0xF];
	proptag[3] = digits[(tag >> 24) & 0xF];
	proptag[4] = digits[(tag >> 20) & 0xF];
	proptag[5] = digits[(tag >> 16) & 0xF];
}

/**
 * @brief      Derive property tag from Tag/Type specification
 *
 * @return     Tag ID
 */
uint32_t tExtendedFieldURI::tag() const
{
	if(!PropertyTag)
		throw InputError("Missing PropertyTag");
	static auto compval = [](const TMEntry& v1, const char* const v2){return strcmp(v1.first, v2) < 0;};
	auto it = std::lower_bound(typeMap.begin(), typeMap.end(), PropertyType.c_str(), compval);
	if(it == typeMap.end() || strcmp(it->first, PropertyType.c_str()))
		throw InputError("Unknown tag type "+PropertyType);
	unsigned long long tagId = std::stoull(*PropertyTag, nullptr, 0);
	return PROP_TAG(it->second, tagId);
}

void tExtendedFieldURI::serialize(XMLElement* xml) const
{
	XMLDUMPA(PropertyType);
	XMLDUMPA(PropertyTag);
}

/**
 * @brief     Get EWS type name from tag type
 *
 * @param     type    Tag type to convert
 *
 * @return    EWS type name
 */
const char* tExtendedFieldURI::typeName(uint16_t type)
{
	switch(type)
	{
	case PT_MV_APPTIME: return "ApplicationTimeArray";
	case PT_APPTIME: return "ApplicationTime";
	case PT_BINARY: return "Binary";
	case PT_MV_BINARY: return "BinaryArray";
	case PT_BOOLEAN: return "Boolean";
	case PT_CLSID: return "CLSID";
	case PT_MV_CLSID: return "CLSIDArray";
	case PT_CURRENCY: return "Currency";
	case PT_MV_CURRENCY: return "CurrencyArray";
	case PT_DOUBLE: return "Double";
	case PT_MV_DOUBLE: return "DoubleArray";
	case PT_ERROR: return "Error";
	case PT_FLOAT: return "Float";
	case PT_MV_FLOAT: return "FloatArray";
	case PT_LONG: return "Integer";
	case PT_MV_LONG: return "IntegerArray";
	case PT_I8: return "Long";
	case PT_MV_I8: return "LongArray";
	case PT_UNSPECIFIED: return "Null";
	case PT_OBJECT: return "Object";
	case PT_SHORT: return "Short";
	case PT_MV_SHORT: return "ShortArray";
	case PT_UNICODE: return "String";
	case PT_MV_UNICODE: return "StringArray";
	case PT_SYSTIME: return "SystemTime";
	case PT_MV_SYSTIME: return "SystemTimeArray";
	default: return "Unknown";
	}
}

///////////////////////////////////////////////////////////////////////////////

tExtendedProperty::tExtendedProperty(const TAGGED_PROPVAL& tp) : propval(tp)
{}

void tExtendedProperty::serialize(const void* data, size_t idx, uint16_t type, XMLElement* xml) const
{
	switch(type)
	{
	case PT_BOOLEAN:
		return xml->SetText(bool(*(reinterpret_cast<const char*>(data)+idx)));
	case PT_SHORT:
		return xml->SetText(*(reinterpret_cast<const uint16_t*>(data)+idx));
	case PT_LONG:
	case PT_ERROR:
		return xml->SetText(*(reinterpret_cast<const uint32_t*>(data)+idx));
	case PT_I8:
	case PT_CURRENCY:
	case PT_SYSTIME:
		return xml->SetText(*(reinterpret_cast<const uint64_t*>(data)+idx));
	case PT_FLOAT:
		return xml->SetText(*(reinterpret_cast<const float*>(data)+idx));
	case PT_DOUBLE:
	case PT_APPTIME:
		return xml->SetText(*(reinterpret_cast<const double*>(data)+idx));
	case PT_STRING8:
	case PT_UNICODE:
		return xml->SetText((reinterpret_cast<const char*>(data)));
	}
}

void tExtendedProperty::serialize(XMLElement* xml) const
{
	const void* data = propval.pvalue;
	if(!data)
		return;
	bool ismv = propval.proptag & MV_FLAG;
	toXMLNode(xml , "ExtendedFieldURI", tExtendedFieldURI(propval.proptag));
	XMLElement* value = xml->InsertNewChildElement(ismv? "Values" : "Value");
	if(!ismv)
		return serialize(data, 0, PROP_TYPE(propval.proptag), value);
	throw NotImplementedError("MV tags are currently not supported");
}

///////////////////////////////////////////////////////////////////////////////

decltype(tFieldURI::fieldMap) tFieldURI::fieldMap = {
	{"folder:FolderId", PidTagFolderId},
	{"folder:ParentFolderId", PidTagParentFolderId},
	{"folder:DisplayName", PR_DISPLAY_NAME},
	{"folder:UnreadCount", PR_CONTENT_UNREAD},
	{"folder:TotalCount", PR_CONTENT_COUNT},
	{"folder:ChildFolderCount", PR_FOLDER_CHILD_COUNT},
	{"folder:FolderClass", PR_CONTAINER_CLASS},
	//{"folder:SearchParameters", ???},
	//{"folder:ManagedFolderInformation", ??},
	//{"folder:PermissionSet", ???},
	//{"folder:EffectiveRights", ???},
	//{"folder:SharingEffectiveRights", ??},
    //{"folder:DistinguishedFolderId", ???},
	//{"folder:PolicyTag", ???},
	//{"folder:ArchiveTag", ???},
	//{"folder:ReplicaList", ???},
};

tFieldURI::tFieldURI(const XMLElement* xml) :
    XMLINITA(FieldURI)
{}

/**
 * @brief     Get tag ID from field URI
 *
 * @return    Property tag ID
 */
uint32_t tFieldURI::tag() const
{
	auto it = fieldMap.find(FieldURI);
	if(it == fieldMap.end())
		throw InputError("Unknown field type "+FieldURI);
	return it->second;
}

///////////////////////////////////////////////////////////////////////////////

tFolderId::tFolderId(const XMLElement* xml) :
    XMLINITA(Id), XMLINITA(ChangeKey)
{}

void tFolderId::serialize(XMLElement* xml) const
{
	XMLDUMPA(Id);
	XMLDUMPA(ChangeKey);
}

///////////////////////////////////////////////////////////////////////////////

tFolderResponseShape::tFolderResponseShape(const XMLElement* xml) :
    XMLINIT(BaseShape),
    XMLINIT(AdditionalProperties)
{}

/**
 * @brief      Collect tag IDs from tag specifications
 *
 * @return     Vector of tag IDs
 */
std::vector<uint32_t> tFolderResponseShape::tags() const
{
	size_t tagCount = 1+(AdditionalProperties? AdditionalProperties->size() : 0);
	size_t baseShape = BaseShape.index();
	if(baseShape >= 1)
		tagCount += tagsDefault.size();
	std::vector<uint32_t> ret;
	ret.reserve(tagCount);
	ret.emplace_back(PR_CHANGE_KEY);
	if(baseShape >= 1)
		ret.insert(ret.end(), tagsDefault.begin(), tagsDefault.end());
	if(AdditionalProperties)
		for(const auto& additional : *AdditionalProperties)
			try {
				ret.emplace_back(additional.tag());
			} catch (InputError&) {}
	return ret;
}

///////////////////////////////////////////////////////////////////////////////

tFolderShape::tFolderShape(const XMLElement* xml)
        : Base(fromXMLNodeDispatch<Base>(xml))
{}

uint32_t tFolderShape::tag() const
{return std::visit([](auto&& v){return v.tag();}, *static_cast<const Base*>(this));};

///////////////////////////////////////////////////////////////////////////////

void tFolderType::serialize(XMLElement* xml) const
{
	tBaseFolderType::serialize(xml);
	XMLDUMP(UnreadCount);
}

///////////////////////////////////////////////////////////////////////////////

void tFreeBusyView::serialize(XMLElement* xml) const
{
	xml->SetAttribute("xmlns", NS_TYPS);
	XMLDUMP(FreeBusyViewType);
	XMLDUMP(MergedFreeBusy);
	XMLDUMP(CalendarEventArray);
}

///////////////////////////////////////////////////////////////////////////////

tFreeBusyViewOptions::tFreeBusyViewOptions(const tinyxml2::XMLElement* xml) :
    XMLINIT(TimeWindow), XMLINIT(MergedFreeBusyIntervalInMinutes), XMLINIT(RequestedView)
{}

///////////////////////////////////////////////////////////////////////////////

tMailbox::tMailbox(const XMLElement* xml) :
    XMLINIT(Name), XMLINIT(Address), XMLINIT(RoutingType)
{}

///////////////////////////////////////////////////////////////////////////////

tMailboxData::tMailboxData(const tinyxml2::XMLElement* xml) :
    XMLINIT(Email), XMLINIT(AttendeeType), XMLINIT(ExcludeConflicts)
{}

///////////////////////////////////////////////////////////////////////////////

void tMailTips::serialize(XMLElement* xml) const
{
	XMLDUMP(RecipientAddress);
	XMLDUMP(PendingMailTips);
}

///////////////////////////////////////////////////////////////////////////////

void tMailTipsServiceConfiguration::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMP(MailTipsEnabled);
	XMLDUMP(MaxRecipientsPerGetMailTipsRequest);
	XMLDUMP(MaxMessageSize);
	XMLDUMP(LargeAudienceThreshold);
	XMLDUMP(ShowExternalRecipientCount);
	XMLDUMP(InternalDomains);
	XMLDUMP(PolicyTipsEnabled);
	XMLDUMP(LargeAudienceCap);
}

///////////////////////////////////////////////////////////////////////////////

tReplyBody::tReplyBody(const XMLElement* xml):
    XMLINIT(Message), XMLINITA(lang)
{}

void tReplyBody::serialize(XMLElement* xml) const
{
	XMLDUMP(Message);
	XMLDUMPA(lang);
}

///////////////////////////////////////////////////////////////////////////////

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

/**
 * @brief      Calculate time zone offset for time point
 *
 * @param      tp      Time point to calculate offset for
 *
 * @return     Offset in minutes
 */
std::chrono::minutes tSerializableTimeZone::offset(const time_point& tp) const
{
	time_t temp = time_point::clock::to_time_t(tp)-Bias*60;
	tm datetime;
	gmtime_r(&temp, &datetime);

	auto &first  = StandardTime.Month < DaylightTime.Month? StandardTime : DaylightTime;
	auto &second = StandardTime.Month < DaylightTime.Month? DaylightTime : StandardTime;

	int firstDO    = first.DayOrder == 5 ? -1 : int(first.DayOrder);
	int secondDO   = second.DayOrder == 5 ? -1 : int(second.DayOrder);
	int firstMday  = ical_get_dayofmonth(datetime.tm_year + 1900,
	                 first.Month, firstDO, int(first.DayOfWeek.index()));
	int secondMday = ical_get_dayofmonth(datetime.tm_year + 1900,
	                 second.Month, secondDO, int(second.DayOfWeek.index()));

	int64_t dStamp = int64_t(datetime.tm_sec) + datetime.tm_min * 60 +
	                 datetime.tm_hour * 3600 + datetime.tm_mday * 86400 +
	                 (datetime.tm_mon + 1) * 2678400;
	int64_t fStamp = int64_t(first.Time.second) + first.Time.minute * 60 +
	                 first.Time.hour * 3600 + firstMday * 86400 +
	                 first.Month * 2678400;
	int64_t sStamp = int64_t(second.Time.second) + second.Time.minute * 60 +
	                 second.Time.hour * 3600 + secondMday * 86400 +
	                 second.Month * 2678400;

	int bias = dStamp < fStamp || dStamp >= sStamp ? second.Bias : first.Bias;
	return std::chrono::minutes(Bias+bias);
}

/**
 * @brief      Convert from UTC to timezone
 *
 * @param      tp     Time point to convert
 *
 * @return     Adjusted time point
 */
gromox::time_point tSerializableTimeZone::apply(const gromox::time_point& tp) const
{return tp+offset(tp);}


/**
 * @brief      Convert from UTC to timezone
 *
 * @param      tp     Time point to convert
 *
 * @return     Adjusted time point
 */
gromox::time_point tSerializableTimeZone::remove(const gromox::time_point& tp) const
{return tp-offset(tp);}

///////////////////////////////////////////////////////////////////////////////

void tSmtpDomain::serialize(XMLElement* xml) const
{
	XMLDUMP(Name);
	XMLDUMP(IncludeSubdomains);
}

///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////

tUserOofSettings::tUserOofSettings(const XMLElement* xml) :
    XMLINIT(OofState),
    XMLINIT(ExternalAudience),
    XMLINIT(Duration),
    XMLINIT(InternalReply),
    XMLINIT(ExternalReply)
{}

void tUserOofSettings::serialize(XMLElement* xml) const
{
	xml->SetAttribute("xmlns", NS_TYPS);
	XMLDUMP(OofState);
	XMLDUMP(ExternalAudience);
	XMLDUMP(Duration);
	XMLDUMP(InternalReply);
	XMLDUMP(ExternalReply);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Message implementation

mGetFolderRequest::mGetFolderRequest(const XMLElement* xml) :
    XMLINIT(FolderShape), XMLINIT(FolderIds)
{}


void mGetFolderResponseMessage::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMP(Folders);
}

void mGetFolderResponse::serialize(XMLElement* xml) const
{XMLDUMP(ResponseMessages);}

///////////////////////////////////////////////////////////////////////////////

mFreeBusyResponse::mFreeBusyResponse(tFreeBusyView&& fbv) : FreeBusyView(std::move(fbv))
{}

void mFreeBusyResponse::serialize(XMLElement* xml) const
{
	xml->SetAttribute("xmlns", NS_MSGS);
	XMLDUMP(ResponseMessage);
	XMLDUMP(FreeBusyView);
}

///////////////////////////////////////////////////////////////////////////////

mGetMailTipsRequest::mGetMailTipsRequest(const XMLElement* xml) :
    XMLINIT(SendingAs),
    XMLINIT(Recipients),
    XMLINIT(MailTipsRequested)
{}

void mMailTipsResponseMessageType::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMP(MailTips);
}

void mGetMailTipsResponse::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMP(ResponseMessages);
}


///////////////////////////////////////////////////////////////////////////////

mGetServiceConfigurationRequest::mGetServiceConfigurationRequest(const XMLElement* xml) :
    XMLINIT(ActingAs), XMLINIT(RequestedConfiguration)
{}

void mGetServiceConfigurationResponse::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMP(ResponseMessages);
}

void mGetServiceConfigurationResponseMessageType::serialize(XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMP(MailTipsConfiguration);
}

///////////////////////////////////////////////////////////////////////////////

mGetUserAvailabilityRequest::mGetUserAvailabilityRequest(const XMLElement* xml) :
    XMLINIT(TimeZone), XMLINIT(MailboxDataArray), XMLINIT(FreeBusyViewOptions), XMLINIT(SuggestionsViewOptions)
{}

void mGetUserAvailabilityResponse::serialize(XMLElement* xml) const
{XMLDUMP(FreeBusyResponseArray);}

///////////////////////////////////////////////////////////////////////////////

mGetUserOofSettingsRequest::mGetUserOofSettingsRequest(const XMLElement* xml) :
    XMLINIT(Mailbox)
{}

void mGetUserOofSettingsResponse::serialize(XMLElement* xml) const
{
	xml->SetAttribute("xmlns", NS_MSGS);
	XMLDUMP(ResponseMessage);
	toXMLNode(xml, "OofSettings", UserOofSettings);
	XMLDUMP(AllowExternalOof);
}

///////////////////////////////////////////////////////////////////////////////

mResponseMessageType::mResponseMessageType(const std::string& ResponseClass, const std::optional<std::string>& ResponseCode,
                                           const std::optional<std::string>& MessageText) :
    ResponseClass(ResponseClass), MessageText(MessageText), ResponseCode(ResponseCode)
{}

/**
 * @brief      Set response data to success
 *
 * @return     *this
 */
mResponseMessageType& mResponseMessageType::success()
{
	ResponseClass = "Success";
	ResponseCode = "NoError";
	return *this;
}

void mResponseMessageType::serialize(tinyxml2::XMLElement* xml) const
{
	XMLDUMPA(ResponseClass);
	XMLDUMP(ResponseCode);
	XMLDUMP(MessageText);
	XMLDUMP(DescriptiveLinkKey);
}

///////////////////////////////////////////////////////////////////////////////

mSetUserOofSettingsRequest::mSetUserOofSettingsRequest(const XMLElement* xml) :
    XMLINIT(Mailbox), XMLINIT(UserOofSettings)
{}

void mSetUserOofSettingsResponse::serialize(XMLElement* xml) const
{
	xml->SetAttribute("xmlns", NS_MSGS);
	XMLDUMP(ResponseMessage);
}
