// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
/**
 * @brief      Implementation of EWS structure (de-)serialization
 */
#include <iterator>

#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include <gromox/ical.hpp>

#include "ews.hpp"
#include "serialization.hpp"
#include "soaputil.hpp"
#include "structures.hpp"

using namespace gromox::EWS;
using namespace gromox::EWS::Serialization;
using namespace gromox::EWS::Structures;
using namespace tinyxml2;

//Shortcuts to call toXML* and fromXML* functions on members
#define XMLINIT(name) name(fromXMLNode<decltype(name)>(xml, # name)) ///< Init member from XML node
#define VXMLINIT(name) name(fromXMLNode<decltype(name)>(xml, nullptr)) ///< Init variant from XML node
#define XMLDUMP(name) toXMLNode(xml, # name, name) ///< Write member into XML node
#define VXMLDUMP(name) toXMLNode(xml, getName(name, # name), name) ///< Write variant into XML node
#define XMLINITA(name) name(fromXMLAttr<decltype(name)>(xml, # name)) ///< Initialize member from XML attribute
#define XMLDUMPA(name) toXMLAttr(xml, # name, name) ///< Write member into XML attribute

using namespace std::string_literals;
using namespace Exceptions;
using gromox::EWS::SOAP::NS_MSGS;
using gromox::EWS::SOAP::NS_TYPS;

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
std::string b64decode(const char* data, size_t len)
{
	std::string out(len*3/4+1, '\0');
	size_t outlen;
	if(decode64(data, len, out.data(), out.length(), &outlen))
		throw DeserializationError("Invalid base64 string");
	out.resize(outlen);
	return out;
}
}

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

/**
 * @brief     Decode Base64 encoded data from XML element
 */
sBase64Binary::sBase64Binary(const XMLElement* xml)
{
	const char* data = xml->GetText();
	if(!data)
		throw DeserializationError("Element '"s+xml->Name()+"'is empty");
	assign(b64decode(data, strlen(data)));
}

/**
 * @brief     Decode Base64 encoded data from XML attribute
 */
sBase64Binary::sBase64Binary(const XMLAttribute* xml) : std::string(b64decode(xml->Value(), strlen(xml->Value())))
{}

/**
 * @brief     Initilize binary data from tagged propval
 *
 * Propval type must be PT_BINARY.
 */
sBase64Binary::sBase64Binary(const TAGGED_PROPVAL& tp)
{
	if(PROP_TYPE(tp.proptag) != PT_BINARY)
		throw DispatchError("Can only convert binary properties to Base64Binary");
	const BINARY* bin = static_cast<const BINARY*>(tp.pvalue);
	assign(bin->pc, bin->cb);
}

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

///////////////////////////////////////////////////////////////////////////////////////////////////

#define TRY(expr) EWSContext::ext_error(expr)

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
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
sFolderEntryId::sFolderEntryId(const void* data, uint64_t size)
{init(data, size);}

/**
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
void sFolderEntryId::init(const void* data, uint64_t size)
{
	EXT_PULL ext_pull;
	if(size >	std::numeric_limits<uint32_t>::max())
		throw DeserializationError("Folder entry ID data to large");
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_folder_eid(this));
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
	TRY(ext_push.p_folder_eid(*this));
	return b64encode(buff, ext_push.m_offset);
}

/**
 * @brief     Retrieve account ID from entry ID
 *
 * @return    User or domain ID (depending on isPrivate())
 */
uint32_t sFolderEntryId::accountId() const
{return database_guid.time_low;}

/**
 * @brief     Retrieve folder ID from entryID
 *
 * @return    Folder ID
 */
uint64_t sFolderEntryId::folderId() const
{return rop_util_gc_to_value(global_counter);}

/**
 * @brief     Retrieve folder type
 *
 * @return    true if folder is private, false otherwise
 */
bool sFolderEntryId::isPrivate() const
{return folder_type == EITLT_PRIVATE_FOLDER;}

#undef TRY

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * List of known distinguished folder IDs
 *
 * Must be sorted alphabetically by name.
 */
decltype(sFolderSpec::distNameInfo) sFolderSpec::distNameInfo = {{
    {"calendar", PRIVATE_FID_CALENDAR, true},
    {"conflicts", PRIVATE_FID_CONFLICTS, true},
    {"contacts", PRIVATE_FID_CONTACTS, true},
    {"deleteditems", PRIVATE_FID_DELETED_ITEMS, true},
    {"drafts", PRIVATE_FID_DRAFT, true},
    {"imcontactlist", PRIVATE_FID_IMCONTACTLIST, true},
    {"inbox", PRIVATE_FID_INBOX, true},
    {"journal", PRIVATE_FID_JOURNAL, true},
    {"junkemail", PRIVATE_FID_JUNK, true},
    {"localfailures", PRIVATE_FID_LOCAL_FAILURES, true},
    {"msgfolderroot", PRIVATE_FID_IPMSUBTREE, true},
    {"notes", PRIVATE_FID_NOTES, true},
    {"outbox", PRIVATE_FID_OUTBOX, true},
    {"publicfoldersroot", PUBLIC_FID_IPMSUBTREE, false},
    {"quickcontacts", PRIVATE_FID_QUICKCONTACTS, true},
    {"root", PRIVATE_FID_ROOT, true},
    {"scheduled", PRIVATE_FID_SCHEDULE, true},
    {"sentitems", PRIVATE_FID_SENT_ITEMS, true},
    {"serverfailures", PRIVATE_FID_SERVER_FAILURES, true},
    {"syncissues", PRIVATE_FID_SYNC_ISSUES, true},
    {"tasks", PRIVATE_FID_TASKS, true},
}};

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
	location = it->isPrivate? PRIVATE : PUBLIC;
	if(folder.Mailbox)
		target = folder.Mailbox->EmailAddress;
}

/**
 * @brief     Explicit initialization for direct serialization
 */
sFolderSpec::sFolderSpec(const std::string& target, uint64_t folderId) :
    target(target), folderId(folderId)
{}

/**
 * @brief     Trim target specification according to location
 */
sFolderSpec& sFolderSpec::normalize()
{
	if(location != PUBLIC || !target)
		return *this;
	size_t at = target->find('@');
	if(at == std::string::npos)
		return *this;
	target->erase(0, at+1);
	return *this;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Default constructor
 *
 * Initializes given and seen member for deserialization
 */
sSyncState::sSyncState() :
    given(false, REPL_TYPE_ID), seen(false, REPL_TYPE_ID)
{}

/**
 * @brief     Deserialize sync state
 *
 * @param     data64  Base64 encoded data
 */
void sSyncState::init(const std::string& data64)
{
	EXT_PULL ext_pull;
	TPROPVAL_ARRAY propvals;

	std::string data = base64_decode(data64);

	seen.clear();
	given.clear();
	if(data.size() <= 16)
		return;
	if(data.size() > std::numeric_limits<uint32_t>::max())
		throw InputError("Sync state too big");
	ext_pull.init(data.data(), uint32_t(data.size()), EWSContext::alloc, 0);
	if(ext_pull.g_tpropval_a(&propvals) != EXT_ERR_SUCCESS)
		return;
	for (TAGGED_PROPVAL* propval = propvals.ppropval; propval < propvals.ppropval+propvals.count; ++propval)
	{
		switch (propval->proptag) {
		case MetaTagIdsetGiven1:
			if(!given.deserialize(static_cast<BINARY *>(propval->pvalue)))
				throw InputError("Failed to deserialize idset");
			if(!given.convert())
				throw InputError("Failed to convert idset");
			break;
		case MetaTagCnsetSeen:
			if(!seen.deserialize(static_cast<BINARY *>(propval->pvalue)) || !seen.convert())
				throw InputError("Failed to deserialize cnset");
			break;
		}
	}
}

/**
 * @brief     Update sync state with given and seen information
 *
 * @param     given_fids  Ids marked as given
 * @param     lastCn      Change number marked as seen
 */
void sSyncState::update(const EID_ARRAY& given_fids, uint64_t lastCn)
{
	seen.clear();
	given.convert();
	for(uint64_t* pid = given_fids.pids; pid < given_fids.pids+given_fids.count; ++pid)
		if(!given.append(*pid))
			throw DispatchError("Failed to generated sync state idset");
	seen.convert();
	if(lastCn && !seen.append_range(1, 1, rop_util_get_gc_value(lastCn)))
		throw DispatchError("Failed to generate sync state cnset");
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
		throw DispatchError("Out of memory");
	std::unique_ptr<BINARY, Cleaner> ser(given.serialize());
	if (!ser || pproplist->set(MetaTagIdsetGiven1, ser.get()))
		throw DispatchError("Failed to generate sync state idset data");
	ser.reset(seen.serialize());
	if (!ser || pproplist->set(MetaTagCnsetSeen, ser.get()))
		throw DispatchError("Failed to generate sync state cnset data");
	ser.reset();

	EXT_PUSH stateBuffer;
	if(!stateBuffer.init(nullptr, 0, 0) || stateBuffer.p_tpropval_a(*pproplist) != EXT_ERR_SUCCESS)
		throw DispatchError("Failed to generate sync state");

	return b64encode(stateBuffer.m_vdata, stateBuffer.m_offset);
}

///////////////////////////////////////////////////////////////////////////////

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

/**
 * @brief     Convert propvals to structured folder information
 *
 * If `filter` is not empty, all proptags not contained are ignored.
 * `filter` must be sorted in ascending order.
 *
 * @param     folder          Folder specification
 * @param     folderProps     folder property values
 * @param     filter          Sorted array of properties to consider
 */
tBaseFolderType::tBaseFolderType(const TPROPVAL_ARRAY& folderProps, const TagFilter& filter)
{
	tFolderId& fId = FolderId.emplace();
	for(const TAGGED_PROPVAL* tp = folderProps.ppropval; tp < folderProps.ppropval+folderProps.count; ++tp)
	{
		if(!filter.empty() && !std::binary_search(filter.begin(), filter.end(), tp->proptag))
			continue;
		switch(tp->proptag)
		{
		case PR_CONTENT_UNREAD:
			break;
		case PR_CHANGE_KEY: {
			const BINARY* ck = reinterpret_cast<const BINARY*>(tp->pvalue);
			fId.ChangeKey = b64encode(ck->pb, ck->cb);
			break;
		}
		case PR_CONTAINER_CLASS:
			FolderClass = reinterpret_cast<const char*>(tp->pvalue); break;
		case PR_CONTENT_COUNT:
			TotalCount = *reinterpret_cast<uint32_t*>(tp->pvalue); break;
		case PR_DISPLAY_NAME:
			DisplayName = reinterpret_cast<const char*>(tp->pvalue); break;
		case PR_ENTRYID:
			fId.Id = *tp; break;
		case PR_FOLDER_CHILD_COUNT:
			ChildFolderCount = *reinterpret_cast<uint32_t*>(tp->pvalue); break;
		case PR_PARENT_ENTRYID: {
			tFolderId& pf = ParentFolderId.emplace();
			pf.Id = *tp;
			break;
		}
		default:
			ExtendendProperty.emplace_back(*tp);
		}
	}
}

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

/**
 * @brief     Create folder from properties
 *
 * Automatically uses information from the tags to fill in folder id and type.
 *
 * @param     target          User or domain name the folder belongs to
 * @param     folderProps     Folder properties
 * @param     filter          Property filter, @see tBaseFolderType::tBaseFolderType
 *
 * @return    Variant containing the folder information struct
 */
sFolder tBaseFolderType::create(const TPROPVAL_ARRAY& folderProps, const TagFilter& filter)
{
	enum Type :uint8_t {NORMAL, CALENDAR, TASKS, CONTACTS, SEARCH};
	const char* frClass = folderProps.get<const char>(PR_CONTAINER_CLASS);
	Type folderType = NORMAL;
	if(frClass)
	{
		if(!strcmp(frClass, "IPF.Appointment"))
			folderType = CALENDAR;
		else if(!strcmp(frClass, "IPF.Task"))
			folderType = TASKS;
		else if(!strcmp(frClass, "IPF.Contact"))
			folderType = CONTACTS;
	}
	switch(folderType)
	{
	case CALENDAR:
		return tCalendarFolderType(folderProps, filter);
	case CONTACTS:
		return tContactsFolderType(folderProps, filter);
	case SEARCH:
		return tSearchFolderType(folderProps, filter);
	case TASKS:
		return tTasksFolderType(folderProps, filter);
	default:
		return tFolderType(folderProps, filter);
	}
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
	//throw NotImplementedError("MV tags are currently not supported");
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

tFolderId::tFolderId(const sBase64Binary& fEntryID) : Id(fEntryID)
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
	size_t tagCount = tagsIdOnly.size()+(AdditionalProperties? AdditionalProperties->size() : 0);
	size_t baseShape = BaseShape.index();
	if(baseShape >= 1)
		tagCount += tagsDefault.size();
	std::vector<uint32_t> ret;
	ret.reserve(tagCount);
	ret.insert(ret.end(), tagsIdOnly.begin(), tagsIdOnly.end());
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

tFolderType::tFolderType(const TPROPVAL_ARRAY& folderProps, const TagFilter& filter) :
    tBaseFolderType(folderProps, filter)
{
	if((filter.empty() || std::binary_search(filter.begin(), filter.end(), PR_CONTENT_UNREAD))
	        && folderProps.has(PR_CONTENT_UNREAD))
		UnreadCount = *folderProps.get<uint32_t>(PR_CONTENT_UNREAD);
}

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

tSyncFolderHierarchyCU::tSyncFolderHierarchyCU(sFolder&& folder) : folder(folder)
{}

void tSyncFolderHierarchyCU::serialize(XMLElement* xml) const
{VXMLDUMP(folder);}

tSyncFolderHierarchyDelete::tSyncFolderHierarchyDelete(const sBase64Binary& fEntryID) :
    FolderId(fEntryID)
{}

void tSyncFolderHierarchyDelete::serialize(XMLElement* xml) const
{XMLDUMP(FolderId);}

///////////////////////////////////////////////////////////////////////////////

tTargetFolderIdType::tTargetFolderIdType(const XMLElement* xml) :
    VXMLINIT(folderId)
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

///////////////////////////////////////////////////////////////////////////////

mSyncFolderHierarchyRequest::mSyncFolderHierarchyRequest(const XMLElement* xml) :
    XMLINIT(FolderShape),
    XMLINIT(SyncFolderId),
    XMLINIT(SyncState)
{}

void mSyncFolderHierarchyResponseMessage::serialize(tinyxml2::XMLElement* xml) const
{
	mResponseMessageType::serialize(xml);
	XMLDUMP(SyncState);
	XMLDUMP(IncludesLastFolderInRange);
	XMLDUMP(Changes);
}

void mSyncFolderHierarchyResponse::serialize(tinyxml2::XMLElement* xml) const
{XMLDUMP(ResponseMessages);}
