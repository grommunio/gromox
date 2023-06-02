// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
/**
 * @brief      Implementation of EWS structure methods
 *
 * This file only contains data type logic, the implementation
 * of (de-)serialization functions was moved to serialization.cpp.
 */
#include <algorithm>
#include <iterator>
#include <utility>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/ical.hpp>

#include "ews.hpp"
#include "structures.hpp"

using namespace gromox::EWS;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace std::string_literals;
using namespace tinyxml2;

namespace
{

inline gromox::time_point nttime_to_time_point(uint64_t nttime)
{return gromox::time_point::clock::from_time_t(rop_util_nttime_to_unix(nttime));}

/**
 * @brief     Access contained value, create if empty
 *
 * @param     container   (Possibly empty) container
 * @param     args        Arguments used for creation if container is empty
 *
 * @return    Reference to contained value
 */
template<typename T, typename... Args>
T& defaulted(std::optional<T>& container, Args&&... args)
{return container? *container : container.emplace(std::forward<Args...>(args)...);}

/**
 * @brief      Fill field from property
 *
 * Value version.
 *
 * @param      props      Property list
 * @param      tag        Tag to search for
 * @param      target     Target field
 *
 * @tparam     T          Target type
 * @tparam     PT         Property type
 */
template<typename T, typename PT=T, std::enable_if_t<!std::is_pointer_v<PT>, bool> = false>
void fromProp(const TPROPVAL_ARRAY& props, uint32_t tag, std::optional<T>& target)
{
	const TAGGED_PROPVAL* prop = props.find(tag);
	if(prop)
		target.emplace(*static_cast<const PT*>(prop->pvalue));
}

/**
 * @brief      Fill field from property
 *
 * Pointer version.
 *
 * @param      props      Property list
 * @param      tag        Tag to search for
 * @param      target     Target field
 *
 * @tparam     T          Target type
 * @tparam     PT         Property type
 */
template<typename T, typename PT=T, std::enable_if_t<std::is_pointer_v<PT>, bool> = true>
void fromProp(const TPROPVAL_ARRAY& props, uint32_t tag, std::optional<T>& target)
{
	const TAGGED_PROPVAL* prop = props.find(tag);
	if(prop)
		target.emplace(static_cast<PT>(prop->pvalue));
}

/**
 * @brief      Fill string from property
 *
 * Shortcut for fromProp<std::string, const char*>.
 *
 * @param      props      Property list
 * @param      tag        Tag to search for
 * @param      target     Target field
 */
template<>
void fromProp(const TPROPVAL_ARRAY& props, uint32_t tag, std::optional<std::string>& target)
{return fromProp<std::string, const char*>(props, tag, target);}

/**
 * @brief      Fill time field from property
 *
 * Automatically performs conversion from NT to UNIX timestamp.
 *
 * @param      props      Property list
 * @param      tag        Tag to search for
 * @param      target     Target field
 */
void fromProp(const TPROPVAL_ARRAY& props, uint32_t tag, std::optional<sTimePoint>& target)
{
	const TAGGED_PROPVAL* prop = props.find(tag);
	if(prop)
		target.emplace(sTimePoint::fromNT(*static_cast<const uint64_t*>(prop->pvalue)));
}

}

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Initilize binary data from tagged propval
 *
 * Propval type must be PT_BINARY.
 */
sBase64Binary::sBase64Binary(const TAGGED_PROPVAL& tp)
{
	if(PROP_TYPE(tp.proptag) != PT_BINARY)
		throw DispatchError(E3049);
	const BINARY* bin = static_cast<const BINARY*>(tp.pvalue);
	assign(bin->pb, bin->pb+bin->cb);
}

///////////////////////////////////////////////////////////////////////////////////////////////////

#define TRY(expr) EWSContext::ext_error(expr)

/**
 * @brief      Create attachment ID from message entry ID and index
 */
sAttachmentId::sAttachmentId(const sMessageEntryId& meid, uint32_t num) : sMessageEntryId(meid), attachment_num(num)
{}

/**
 * @brief      Create attachment ID from message entry ID property and index
 */
sAttachmentId::sAttachmentId(const TAGGED_PROPVAL& tp, uint32_t num) : sMessageEntryId(tp), attachment_num(num)
{}

/**
 * @brief      Load attachment id from binary data
 */
sAttachmentId::sAttachmentId(const void* data, uint64_t size)
{
	EXT_PULL ext_pull;
	if(size > std::numeric_limits<uint32_t>::max())
		throw DeserializationError(E3081);
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this));
	TRY(ext_pull.g_uint32(&attachment_num));
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
		throw DeserializationError(E3050);
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_folder_eid(this));
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

/**
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
sMessageEntryId::sMessageEntryId(const void* data, uint64_t size)
{init(data, size);}

/**
 * @brief      Create message entry ID from property
 */
sMessageEntryId::sMessageEntryId(const TAGGED_PROPVAL& tp)
{
	if(PROP_TYPE(tp.proptag) != PT_BINARY)
		throw DispatchError(E3082);
	const BINARY* bin = static_cast<const BINARY*>(tp.pvalue);
	init(bin->pv, bin->cb);
}

/**
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
void sMessageEntryId::init(const void* data, uint64_t size)
{
	EXT_PULL ext_pull;
	if(size >	std::numeric_limits<uint32_t>::max())
		throw DeserializationError(E3050);
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this));
}

/**
 * @brief     Retrieve account ID from entry ID
 *
 * @return    User or domain ID (depending on isPrivate())
 */
uint32_t sMessageEntryId::accountId() const
{return folder_database_guid.time_low;}

/**
 * @brief     Retrieve parent folder ID from entryID
 *
 * @return    folder ID
 */
uint64_t sMessageEntryId::folderId() const
{return rop_util_gc_to_value(folder_global_counter);}

/**
 * @brief     Retrieve message ID from entryID
 *
 * @return    message ID
 */
eid_t sMessageEntryId::messageId() const
{return rop_util_make_eid_ex(1, rop_util_gc_to_value(message_global_counter));}

/**
 * @brief     Retrieve message type
 *
 * @return    true if message is private, false otherwise
 */
bool sMessageEntryId::isPrivate() const
{return message_type == EITLT_PRIVATE_MESSAGE;}

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
		throw DeserializationError(E3051(folder.Id));
	folderId = rop_util_make_eid_ex(1, it->id);
	location = it->isPrivate? PRIVATE : PUBLIC;
	if(folder.Mailbox)
		target = folder.Mailbox->EmailAddress;
}

/**
 * @brief     Explicit initialization for direct serialization
 */
sFolderSpec::sFolderSpec(const std::string &t, uint64_t fid) :
	target(t), folderId(fid)
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
    given(false, REPL_TYPE_ID),
    seen(false, REPL_TYPE_ID),
    read(false, REPL_TYPE_ID),
    seen_fai(false, REPL_TYPE_ID)
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
	read.clear();
	seen_fai.clear();
	if(data.size() <= 16)
		return;
	if(data.size() > std::numeric_limits<uint32_t>::max())
		throw InputError(E3052);
	ext_pull.init(data.data(), uint32_t(data.size()), EWSContext::alloc, 0);
	if(ext_pull.g_tpropval_a(&propvals) != EXT_ERR_SUCCESS)
		return;
	for (TAGGED_PROPVAL* propval = propvals.ppropval; propval < propvals.ppropval+propvals.count; ++propval)
	{
		switch (propval->proptag) {
		case MetaTagIdsetGiven1:
			if (!given.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw InputError(E3053);
			break;
		case MetaTagCnsetSeen:
			if (!seen.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw InputError(E3054);
			break;
		case MetaTagCnsetRead:
			if (!read.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw InputError(E3055);
			break;
		case MetaTagCnsetSeenFAI:
			if (!seen_fai.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw InputError(E3056);
			break;
		case MetaTagReadOffset: //PR_READ, but with long type -> number of read states already delivered
			readOffset = *static_cast<uint32_t*>(propval->pvalue);
		}
	}
}

/**
 * @brief      Call convert on all idsets
 */
void sSyncState::convert()
{
	if(!given.convert() || !seen.convert() || !read.convert() || !seen_fai.convert())
			throw DispatchError(E3064);
}

/**
 * @brief     Update sync state with given and seen information
 *
 * @param     given_fids  Ids marked as given
 * @param     lastCn      Change number marked as seen
 */
void sSyncState::update(const EID_ARRAY& given_fids, const EID_ARRAY& deleted_fids, uint64_t lastCn)
{
	for(uint64_t* pid = deleted_fids.pids; pid < deleted_fids.pids+deleted_fids.count; ++pid)
		given.remove(*pid);
	for(uint64_t* pid = given_fids.pids; pid < given_fids.pids+given_fids.count; ++pid)
		if(!given.append(*pid))
			throw DispatchError(E3057);
	seen.clear();
	if(lastCn && !seen.append_range(1, 1, rop_util_get_gc_value(lastCn)))
		throw DispatchError(E3058);
}

///////////////////////////////////////////////////////////////////////////////

sTimePoint::sTimePoint(const gromox::time_point& tp) : time(tp)
{}

sTimePoint::sTimePoint(const gromox::time_point& tp, const tSerializableTimeZone& tz) :
    time(tp), offset(tz.offset(tp))
{}

/**
 * @brief      Generate time point from NT timestamp
 */
sTimePoint sTimePoint::fromNT(uint64_t timestamp)
{return gromox::time_point::clock::from_time_t(rop_util_nttime_to_unix(timestamp));}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Types implementation

tAttachment::tAttachment(const sAttachmentId& aid, const TPROPVAL_ARRAY& props)
{
	AttachmentId.emplace(aid);
	fromProp(props, PR_DISPLAY_NAME, Name);
	fromProp(props, PR_ATTACH_MIME_TAG, ContentType);
	fromProp(props, PR_ATTACH_SIZE, Size);
	fromProp(props, PR_LAST_MODIFICATION_TIME, LastModifiedTime);
}

sAttachment tAttachment::create(const sAttachmentId& aid, const TPROPVAL_ARRAY& props)
{
	const TAGGED_PROPVAL* prop = props.find(PR_ATTACH_METHOD);
	if(prop)
		switch(*static_cast<const uint32_t*>(prop->pvalue)) {
		case ATTACH_EMBEDDED_MSG:
			return sAttachment(std::in_place_type_t<tItemAttachment>(), aid, props);
		case ATTACH_BY_REFERENCE:
			return sAttachment(std::in_place_type_t<tReferenceAttachment>(), aid, props);
		}
	return sAttachment(std::in_place_type_t<tFileAttachment>(), aid, props);
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Convert propvals to structured folder information
 *
 * @param     folderProps     folder property values
 */
tBaseFolderType::tBaseFolderType(const TPROPVAL_ARRAY& folderProps)
{
	tFolderId& fId = FolderId.emplace();
	for(const TAGGED_PROPVAL* tp = folderProps.ppropval; tp < folderProps.ppropval+folderProps.count; ++tp)
	{
		switch(tp->proptag)
		{
		case PR_CONTENT_UNREAD:
			break;
		case PR_CHANGE_KEY:
			fId.ChangeKey.emplace(*tp); break;
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
		case PR_PARENT_ENTRYID:
			ParentFolderId.emplace().Id = *tp; break;
		default:
			ExtendedProperty.emplace_back(*tp);
		}
	}
}

/**
 * @brief     Create folder from properties
 *
 * Automatically uses information from the tags to fill in folder id and type.
 *
 * @param     folderProps     Folder properties
 *
 * @return    Variant containing the folder information struct
 */
sFolder tBaseFolderType::create(const TPROPVAL_ARRAY& folderProps)
{
	enum Type : uint8_t {NORMAL, CALENDAR, TASKS, CONTACTS, SEARCH};
	const char* frClass = folderProps.get<const char>(PR_CONTAINER_CLASS);
	const uint32_t* frType = folderProps.get<uint32_t>(PR_FOLDER_TYPE);
	Type folderType = NORMAL;
	if(frType && *frType == FOLDER_SEARCH)
		folderType = SEARCH;
	else if(frClass)
	{
		if(!strncmp(frClass, "IPF.Appointment", 15))
			folderType = CALENDAR;
		else if(!strncmp(frClass, "IPF.Contact", 11))
			folderType = CONTACTS;
		else if(!strncmp(frClass, "IPF.Task", 8))
			folderType = TASKS;
	}
	switch(folderType)
	{
	case CALENDAR:
		return tCalendarFolderType(folderProps);
	case CONTACTS:
		return tContactsFolderType(folderProps);
	case SEARCH:
		return tSearchFolderType(folderProps);
	case TASKS:
		return tTasksFolderType(folderProps);
	default:
		return tFolderType(folderProps);
	}
}

tBaseItemId::tBaseItemId(const sBase64Binary& fEntryID, const std::optional<sBase64Binary>& chKey) :
    Id(fEntryID), ChangeKey(chKey)
{}

///////////////////////////////////////////////////////////////////////////////

tCalendarItem::tCalendarItem(const TPROPVAL_ARRAY& propvals, const sNamedPropertyMap& namedProps) : tItem(propvals, namedProps)
{}

///////////////////////////////////////////////////////////////////////////////
#define pval(type) static_cast<const type*>(tp->pvalue)
tContact::tContact(const TPROPVAL_ARRAY& propvals, const sNamedPropertyMap& namedProps) : tItem(propvals, namedProps)
{
	PhoneNumbers.emplace().reserve(9); // currently available phone properties
	for(const TAGGED_PROPVAL* tp = propvals.ppropval; tp < propvals.ppropval+propvals.count; ++tp)
	{
		switch(tp->proptag)
		{
		// TODO FileAs
		case PR_DISPLAY_NAME:
			DisplayName = pval(char); break;
		case PR_GIVEN_NAME:
			GivenName = pval(char); break;
		// TODO Initials
		case PR_MIDDLE_NAME:
			MiddleName = pval(char); break;
		case PR_NICKNAME:
			Nickname = pval(char); break;
		case PR_COMPANY_NAME:
			CompanyName = pval(char); break;
		// TODO ContactSource
		case PR_ASSISTANT:
			AssistantName = pval(char); break;
		case PR_DEPARTMENT_NAME:
			Department = pval(char); break;
		case PR_TITLE:
			JobTitle = pval(char); break;
		case PR_OFFICE_LOCATION:
			OfficeLocation = pval(char); break;
		case PR_SURNAME:
			Surname = pval(char); break;
		case PR_BUSINESS_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::BusinessPhone));
			break;
		case PR_HOME_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::HomePhone));
			break;
		case PR_PRIMARY_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::PrimaryPhone));
			break;
		case PR_BUSINESS2_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::BusinessPhone2));
			break;
		case PR_MOBILE_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::MobilePhone));
			break;
		case PR_PAGER_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::Pager));
			break;
		case PR_PRIMARY_FAX_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::BusinessFax));
			break;
		case PR_ASSISTANT_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::AssistantPhone));
			break;
		case PR_HOME2_TELEPHONE_NUMBER:
			PhoneNumbers->emplace_back(tPhoneNumberDictionaryEntry(pval(char), Enum::HomePhone2));
			break;
		default:
			break;
		}
	}
}
#undef pval
///////////////////////////////////////////////////////////////////////////////

tDistinguishedFolderId::tDistinguishedFolderId(const std::string_view& name) :
    Id(name)
{}

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

decltype(tExtendedFieldURI::propsetIds) tExtendedFieldURI::propsetIds = {
	&PSETID_MEETING,
	&PSETID_APPOINTMENT,
	&PSETID_COMMON,
	&PS_PUBLIC_STRINGS,
	&PSETID_ADDRESS,
	&PS_INTERNET_HEADERS,
	&PSETID_CALENDARASSISTANT,
	&PSETID_UNIFIEDMESSAGING,
	&PSETID_TASK,
	&PSETID_SHARING
};

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
 * @brief     Initialize from properties
 *
 * Maps
 * `PR_DISPLAY_NAME` -> Name
 * `PR_EMAIL_ADDRESS` -> EmailAddress
 * `PR_ADDRTYPE` ->RoutingType
 *
 * @param     tps     Properties to use
 */
tEmailAddressType::tEmailAddressType(const TPROPVAL_ARRAY& tps)
{
	const char* data;
	if((data = tps.get<const char>(PR_DISPLAY_NAME)))
		Name = data;
	if((data = tps.get<const char>(PR_EMAIL_ADDRESS)))
		EmailAddress = data;
	if((data = tps.get<const char>(PR_ADDRTYPE)))
		RoutingType = data;
}

tEmailAddressDictionaryEntry::tEmailAddressDictionaryEntry(const std::string& email,
	const Enum::EmailAddressKeyType& eakt)
{
	Entry = email;
	Key = eakt;
}

tPhoneNumberDictionaryEntry::tPhoneNumberDictionaryEntry(std::string phone,
	Enum::PhoneNumberKeyType pnkt)
{
	Entry = phone;
	Key = pnkt;
}

/**
 * @brief     Generate URI from named property
 *
 * @param     type       Property type
 * @param     propname   Property name information
 */
tExtendedFieldURI::tExtendedFieldURI(uint16_t type, const PROPERTY_NAME& propname) :
    PropertyType(typeName(type)),
    PropertySetId(propname.guid)
{
	if(propname.kind == MNID_ID)
		PropertyId = propname.lid;
	else if(propname.kind == MNID_STRING)
		PropertyName = propname.pname;
}

/**
 * @brief     Collect property tags and names for field URI

 * @param     tags    Inserter to use for property tags
 * @param     names   Inserter to use for property names
 * @param     types   Inserter to use for the type of each named property
 */
void tExtendedFieldURI::tags(vector_inserter<uint32_t>& tags, vector_inserter<PROPERTY_NAME>& names,
                             vector_inserter<uint16_t>& types, uint64_t&) const
{
	static auto compval = [](const TMEntry& v1, const char* const v2){return strcmp(v1.first, v2) < 0;};
	auto type = std::lower_bound(typeMap.begin(), typeMap.end(), PropertyType.c_str(), compval);
	if(type == typeMap.end() || strcmp(type->first, PropertyType.c_str()))
		throw InputError(E3059(PropertyType));
	if(PropertyTag)
	{
		unsigned long long tagId = std::stoull(*PropertyTag, nullptr, 16);
		tags = PROP_TAG(type->second, tagId);
	}
	else if(PropertySetId || DistinguishedPropertySetId)
	{
		PROPERTY_NAME name{};
		name.guid = PropertySetId? *PropertySetId : *propsetIds[DistinguishedPropertySetId->index()];
		if(PropertyName)
		{
			name.kind = MNID_STRING;
			name.pname = const_cast<char*>(PropertyName->c_str());
		}
		else if(PropertyId)
		{
			name.kind = MNID_ID;
			name.lid = *PropertyId;
		}
		else
			throw InputError(E3060);
		names = name;
		types = type->second;
	}
	else
		throw InputError(E3061);
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

tExtendedProperty::tExtendedProperty(const TAGGED_PROPVAL& tp, const PROPERTY_NAME& pn) : propval(tp), propname(pn)
{}

/**
 * @brief      Unpack multi-value property
 *
 * @param      data  Property data
 * @param      type  Property type
 * @param      xml   XML node to store values in
 * @param      value Pointer to member containing values
 *
 * @tparam     C     Structure used to hold values
 * @tparam     T     Type of the values to store
 */
template<typename C, typename T>
inline void tExtendedProperty::serializeMV(const void* data, uint16_t type, XMLElement* xml, T* C::*value) const
{
	const C* content = static_cast<const C*>(data);
	for(T* val = content->*value; val < content->*value+content->count; ++val)
		if constexpr(std::is_same_v<T, char*>)
			serialize(*val, type&~0x1000, xml->InsertNewChildElement("t:Value"));
		else
			serialize(val, type&~0x1000, xml->InsertNewChildElement("t:Value"));
}

/**
 * @brief      Write property value to XML
 *
 * @param      data  Property data
 * @param      type  Property type
 * @param      xml   XML node to store value(s) in
 */
void tExtendedProperty::serialize(const void* data, uint16_t type, XMLElement* xml) const
{
	switch(type)
	{
	case PT_BOOLEAN:
		return xml->SetText(bool(*(reinterpret_cast<const char*>(data))));
	case PT_SHORT:
		return xml->SetText(*(reinterpret_cast<const uint16_t*>(data)));
	case PT_LONG:
	case PT_ERROR:
		return xml->SetText(*(reinterpret_cast<const uint32_t*>(data)));
	case PT_I8:
	case PT_CURRENCY:
	case PT_SYSTIME:
		return xml->SetText(*(reinterpret_cast<const uint64_t*>(data)));
	case PT_FLOAT:
		return xml->SetText(*(reinterpret_cast<const float*>(data)));
	case PT_DOUBLE:
	case PT_APPTIME:
		return xml->SetText(*(reinterpret_cast<const double*>(data)));
	case PT_STRING8:
	case PT_UNICODE:
		return xml->SetText((reinterpret_cast<const char*>(data)));
	case PT_MV_SHORT:
		return serializeMV(data, type, xml, &SHORT_ARRAY::ps);
	case PT_MV_LONG:
		return serializeMV(data, type, xml, &LONG_ARRAY::pl);
	case PT_MV_I8:
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
		return serializeMV(data, type, xml, &LONGLONG_ARRAY::pll);
	case PT_MV_FLOAT:
		return serializeMV(data, type, xml, &FLOAT_ARRAY::mval);
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		return serializeMV(data, type, xml, &DOUBLE_ARRAY::mval);
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		return serializeMV(data, type, xml, &STRING_ARRAY::ppstr);
	}
}

///////////////////////////////////////////////////////////////////////////////

decltype(tFieldURI::tagMap) tFieldURI::tagMap = {
	{"folder:FolderId", PidTagFolderId},
	{"folder:ParentFolderId", PR_PARENT_ENTRYID},
	{"folder:DisplayName", PR_DISPLAY_NAME},
	{"folder:UnreadCount", PR_CONTENT_UNREAD},
	{"folder:TotalCount", PR_CONTENT_COUNT},
	{"folder:ChildFolderCount", PR_FOLDER_CHILD_COUNT},
	{"folder:FolderClass", PR_CONTAINER_CLASS},
	{"item:ConversationId", PR_CONVERSATION_ID},
	{"item:DisplayTo", PR_DISPLAY_TO},
	{"item:DateTimeCreated", PR_CREATION_TIME},
	{"item:DateTimeReceived", PR_MESSAGE_DELIVERY_TIME},
	{"item:DateTimeSent", PR_CLIENT_SUBMIT_TIME},
	{"item:HasAttachments", PR_HASATTACH},
	{"item:Importance", PR_IMPORTANCE},
	{"item:InReplyTo", PR_IN_REPLY_TO_ID},
	{"item:IsAssociated", PR_ASSOCIATED},
	{"item:ItemClass", PR_MESSAGE_CLASS},
	{"item:LastModifiedName", PR_LAST_MODIFIER_NAME},
	{"item:LastModifiedTime", PR_LAST_MODIFICATION_TIME},
	{"item:Sensitivity", PR_SENSITIVITY},
	{"item:Size", PR_MESSAGE_SIZE},
	{"item:Subject", PR_SUBJECT},
	{"message:ConversationIndex", PR_CONVERSATION_INDEX},
	{"message:ConversationTopic", PR_CONVERSATION_TOPIC},
	{"message:From", PR_SENT_REPRESENTING_ADDRTYPE},
	{"message:From", PR_SENT_REPRESENTING_EMAIL_ADDRESS},
	{"message:From", PR_SENT_REPRESENTING_NAME},
	{"message:InternetMessageId", PR_INTERNET_MESSAGE_ID},
	{"message:IsDeliveryReceiptRequested", PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED},
	{"message:IsRead", PR_READ},
	{"message:IsReadReceiptRequested", PR_READ_RECEIPT_REQUESTED},
	{"message:ReceivedBy", PR_RECEIVED_BY_ADDRTYPE},
	{"message:ReceivedBy", PR_RECEIVED_BY_EMAIL_ADDRESS},
	{"message:ReceivedBy", PR_RECEIVED_BY_NAME},
	{"message:ReceivedRepresenting", PR_RCVD_REPRESENTING_ADDRTYPE},
	{"message:ReceivedRepresenting", PR_RCVD_REPRESENTING_EMAIL_ADDRESS},
	{"message:ReceivedRepresenting", PR_RCVD_REPRESENTING_NAME},
	{"message:References", PR_INTERNET_REFERENCES},
	{"message:Sender", PR_SENDER_ADDRTYPE},
	{"message:Sender", PR_SENDER_EMAIL_ADDRESS},
	{"message:Sender", PR_SENDER_NAME},
};

decltype(tFieldURI::nameMap) tFieldURI::nameMap = {
	{"item:Categories", {{MNID_STRING, PS_PUBLIC_STRINGS, 0, const_cast<char*>("Keywords")}, PT_MV_UNICODE}}
};

decltype(tFieldURI::specialMap) tFieldURI::specialMap = {{
	{"item:Attachments", sShape::Attachments},
	{"item:Body", sShape::Body},
	{"item:IsDraft", sShape::MessageFlags},
	{"item:IsFromMe", sShape::MessageFlags},
	{"item:IsResend", sShape::MessageFlags},
	{"item:IsSubmitted", sShape::MessageFlags},
	{"item:IsUnmodified", sShape::MessageFlags},
	{"message:BccRecipients", sShape::BccRecipients},
	{"message:CcRecipients", sShape::CcRecipients},
	{"message:ToRecipients", sShape::ToRecipients},
}};

/**
 * @brief     Collect property tags and names for field URI

 * @param     tags    Inserter to use for property tags
 * @param     names   Inserter to use for property names
 * @param     types   Inserter to use for the type of each named property
 * @param     special Bit map to store special property flags in
 */
void tFieldURI::tags(vector_inserter<uint32_t>& tagins, vector_inserter<PROPERTY_NAME>& nameins,
                     vector_inserter<uint16_t>& typeins, uint64_t& special) const
{
	auto tags = tagMap.equal_range(FieldURI);
	for(auto it = tags.first; it != tags.second; ++it)
		tagins = it->second;
	auto names = nameMap.equal_range(FieldURI);
	for(auto it = names.first; it != names.second; ++it)
	{
		nameins = it->second.first;
		typeins = it->second.second;
	}
	static auto compval = [](const SMEntry& v1, const char* const v2){return strcmp(v1.first, v2) < 0;};
	auto specials = std::lower_bound(specialMap.begin(), specialMap.end(), FieldURI.c_str(), compval);
	if(specials != specialMap.end() && specials->first == FieldURI)
		special |= specials->second;
}

///////////////////////////////////////////////////////////////////////////////


tFileAttachment::tFileAttachment(const sAttachmentId& aid, const TPROPVAL_ARRAY& props) : tAttachment(aid, props)
{
	TAGGED_PROPVAL* tp = props.find(PR_ATTACH_DATA_BIN);
	if(tp)
		Content.emplace(*tp);
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collect property tags and names for folder shape

 * @param     tags    Inserter to use for property tags
 * @param     names   Inserter to use for property names
 * @param     types   Inserter to use for the type of each named property
 * @param     special Bit map to store special property flags in
 */
void tFolderResponseShape::tags(vector_inserter<uint32_t>& tagIns, vector_inserter<PROPERTY_NAME>& nameIns,
                                vector_inserter<uint16_t>& typeIns, uint64_t& special) const
{
	size_t baseShape = BaseShape.index();
	for(uint32_t tag : tagsIdOnly)
		tagIns = tag;
	if(baseShape >= 1)
		for(uint32_t tag : tagsDefault)
			tagIns = tag;
	if(AdditionalProperties)
		for(const auto& additional : *AdditionalProperties)
			additional.tags(tagIns, nameIns, typeIns, special);
}

///////////////////////////////////////////////////////////////////////////////

tFolderType::tFolderType(const TPROPVAL_ARRAY& folderProps) :
    tBaseFolderType(folderProps)
{
	if(folderProps.has(PR_CONTENT_UNREAD))
		UnreadCount = *folderProps.get<uint32_t>(PR_CONTENT_UNREAD);
}

///////////////////////////////////////////////////////////////////////////////

tGuid::tGuid(const GUID& guid) : GUID(guid)
{}

std::string tGuid::serialize() const
{
	std::string repr(36, '\0');
	to_str(repr.data(), 37);
	return repr;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * TODO: Implement tag mapping
 */
void tIndexedFieldURI::tags(vector_inserter<uint32_t>&, vector_inserter<PROPERTY_NAME>&, vector_inserter<uint16_t>&, uint64_t&) const
{}

///////////////////////////////////////////////////////////////////////////////

#define pval(type) static_cast<const type*>(tp->pvalue)

tItem::tItem(const TPROPVAL_ARRAY& propvals, const sNamedPropertyMap& namedProps)
{
	for(const TAGGED_PROPVAL* tp = propvals.ppropval; tp < propvals.ppropval+propvals.count; ++tp)
	{
		if(mapNamedProperty(*tp, namedProps))
			continue;
		switch(tp->proptag)
		{
		//tMessage
		case PidTagChangeNumber:
		case PR_CONVERSATION_INDEX:
		case PR_CONVERSATION_TOPIC:
		case PR_READ:
		case PR_INTERNET_MESSAGE_ID:
		case PR_INTERNET_REFERENCES:
		case PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED:
		case PR_READ_RECEIPT_REQUESTED:
		case PR_RECEIVED_BY_ADDRTYPE:
		case PR_RECEIVED_BY_EMAIL_ADDRESS:
		case PR_RECEIVED_BY_NAME:
		case PR_RCVD_REPRESENTING_ADDRTYPE:
		case PR_RCVD_REPRESENTING_EMAIL_ADDRESS:
		case PR_RCVD_REPRESENTING_NAME:
		case PR_SENDER_ADDRTYPE:
		case PR_SENDER_EMAIL_ADDRESS:
		case PR_SENDER_NAME:
		case PR_SENT_REPRESENTING_ADDRTYPE:
		case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		case PR_SENT_REPRESENTING_NAME:
		//tContact
		case PR_DISPLAY_NAME:
		case PR_GIVEN_NAME:
		case PR_MIDDLE_NAME:
		case PR_NICKNAME:
		case PR_COMPANY_NAME:
		case PR_ASSISTANT:
		case PR_DEPARTMENT_NAME:
		case PR_TITLE:
		case PR_OFFICE_LOCATION:
		case PR_SURNAME:
		case PR_BUSINESS_TELEPHONE_NUMBER:
		case PR_HOME_TELEPHONE_NUMBER:
		case PR_PRIMARY_TELEPHONE_NUMBER:
		case PR_BUSINESS2_TELEPHONE_NUMBER:
		case PR_MOBILE_TELEPHONE_NUMBER:
		case PR_PAGER_TELEPHONE_NUMBER:
		case PR_PRIMARY_FAX_NUMBER:
		case PR_ASSISTANT_TELEPHONE_NUMBER:
		case PR_HOME2_TELEPHONE_NUMBER:
			continue;
		case PR_ASSOCIATED:
			IsAssociated.emplace(*pval(uint8_t)); break;
		case PR_BODY:
			if(!Body)
				Body.emplace(pval(char), Enum::Text); //Do not overwrite (Best -> HTML takes precedence)
			break;
		case PR_CHANGE_KEY:
			ItemId? ItemId->ChangeKey = *tp : ItemId.emplace().ChangeKey.emplace(*tp); break;
		case PR_CLIENT_SUBMIT_TIME:
			DateTimeSent = sTimePoint::fromNT(*pval(uint64_t)); break;
		case PR_CONVERSATION_ID:
			ConversationId.emplace(*tp); break;
		case PR_CREATION_TIME:
			DateTimeCreated.emplace(nttime_to_time_point(*pval(uint64_t))); break;
		case PR_DISPLAY_CC:
			DisplayCc.emplace(pval(char)); break;
		case PR_DISPLAY_BCC:
			DisplayBcc.emplace(pval(char)); break;
		case PR_DISPLAY_TO:
			DisplayTo.emplace(pval(char)); break;
		case PR_ENTRYID:
			ItemId? ItemId->Id = *tp : ItemId.emplace(*tp); break;
		case PR_HASATTACH:
			HasAttachments.emplace(*pval(uint8_t)); break;
		case PR_FLAG_STATUS:
			Flag.emplace().FlagStatus = *pval(uint32_t) == followupFlagged? Enum::Flagged :
			                            *pval(uint32_t) == followupComplete? Enum::Complete : Enum::NotFlagged;
			break;
		case PR_HTML: {
			const BINARY* content = pval(BINARY);
			Body.emplace(std::string_view(content->pc, content->cb), Enum::HTML); break;
			}
		case PR_IMPORTANCE:
			Importance = *pval(uint32_t) == IMPORTANCE_LOW? Enum::Low :
			             *pval(uint32_t) == IMPORTANCE_HIGH? Enum::High : Enum::Normal;
			break;
		case PR_IN_REPLY_TO_ID:
			InReplyTo.emplace(pval(char)); break;
		case PR_LAST_MODIFIER_NAME:
			LastModifiedName.emplace(pval(char)); break;
		case PR_LAST_MODIFICATION_TIME:
			LastModifiedTime.emplace(nttime_to_time_point(*pval(uint64_t))); break;
		case PR_MESSAGE_CLASS:
			ItemClass.emplace(pval(char)); break;
		case PR_MESSAGE_DELIVERY_TIME:
			DateTimeReceived = sTimePoint::fromNT(*pval(uint64_t)); break;
		case PR_MESSAGE_FLAGS:
			IsSubmitted = *pval(uint32_t) & MSGFLAG_SUBMITTED;
			IsDraft = *pval(uint32_t) & MSGFLAG_UNSENT;
			IsFromMe = *pval(uint32_t) & MSGFLAG_FROMME;
			IsResend = *pval(uint32_t) & MSGFLAG_RESEND;
			IsUnmodified = *pval(uint32_t) & MSGFLAG_UNMODIFIED;
			break;
		case PR_MESSAGE_SIZE:
			Size.emplace(*pval(uint32_t)); break;
		case PR_PARENT_ENTRYID:
			ParentFolderId.emplace(*tp); break;
		case PR_SENSITIVITY:
			try {
				Sensitivity.emplace(size_t(*pval(uint32_t)));
			} catch (EnumError& e) {
				mlog(LV_WARN, "[ews] could not set sensitivity: %s", e.what());
			}
			break;
		case PR_SUBJECT:
			Subject.emplace(pval(char)); break;
		default:
			ExtendedProperty.emplace_back(*tp);
		}
	}
}

#undef pval

sItem tItem::create(const TPROPVAL_ARRAY& itemProps, const sNamedPropertyMap& namedProps)
{
	const char* itemClass = itemProps.get<const char>(PR_MESSAGE_CLASS);
	if(!itemClass)
		return tItem(itemProps, namedProps);
	if(!strcasecmp(itemClass, "IPM.Note"))
		return tMessage(itemProps, namedProps);
	else if(!strcasecmp(itemClass, "IPM.Appointment"))
		return tCalendarItem(itemProps, namedProps);
	else if(!strcasecmp(itemClass, "IPM.Contact"))
		return tContact(itemProps, namedProps);
	return tItem(itemProps, namedProps);
}

/**
 * @brief     Try to map named property
 *
 * Tries to find the corresponding named property in the map and stores it in
 * the proper field or an extended property.
 * Returns immediately if the given property tag is not in the named property
 * range.
 *
 * @param     tp          Property to map
 * @param     namedProps  Map of requested named properties
 *
 * @return    true if property was mapped, false otherwise
 */
bool tItem::mapNamedProperty(const TAGGED_PROPVAL& tp, const sNamedPropertyMap& namedProps)
{
	sNamedPropertyMap::const_iterator entry;
	if(PROP_ID(tp.proptag) < 0x8000 || (entry = namedProps.find(tp.proptag)) == namedProps.end())
		return false;
	const PROPERTY_NAME& pn = entry->second;
	if(pn.kind == MNID_STRING)
	{
		if(pn.guid == PS_PUBLIC_STRINGS)
		{
			if(!strcmp(pn.pname, "Keywords"))
			{
				const STRING_ARRAY* content = static_cast<const STRING_ARRAY*>(tp.pvalue);
				if(content->count)
					Categories.emplace(content->ppstr, content->ppstr+content->count);
				return true;
			}
		}
	}
	//Otherwise just put it into an extended attribute
	ExtendedProperty.emplace_back(tp, pn);
	return true;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collect property tags and names for item shape

 * @param     tags    Inserter to use for property tags
 * @param     names   Inserter to use for property names
 * @param     types   Inserter to use for the type of each named property
 * @param     special Bit map to store special property flags in
 */
void tItemResponseShape::tags(vector_inserter<uint32_t>& tagIns, vector_inserter<PROPERTY_NAME>& nameIns,
                              vector_inserter<uint16_t>& typeIns, uint64_t& special) const
{
	for(uint32_t tag : tagsIdOnly)
		tagIns = tag;
	if(IncludeMimeContent && *IncludeMimeContent)
		special |= sShape::MimeContent;
	if(AdditionalProperties)
		for(const auto& additional : *AdditionalProperties)
			additional.tags(tagIns, nameIns, typeIns, special);
	if(special & sShape::Body)
	{
		std::string_view type = BodyType? *BodyType : Enum::Best;
		if(type == Enum::Best || type == Enum::Text)
			tagIns = PR_BODY;
		if(type == Enum::Best || type == Enum::HTML)
			tagIns = PR_HTML;
		special &= ~sShape::Body;
	}
	if(special & sShape::MessageFlags)
	{
		tagIns = PR_MESSAGE_FLAGS;
		special &= ~sShape::MessageFlags;
	}
}

///////////////////////////////////////////////////////////////////////////////

#define pval(type) static_cast<const type*>(tp->pvalue)

tMessage::tMessage(const TPROPVAL_ARRAY& propvals, const sNamedPropertyMap& namedProps) : tItem(propvals, namedProps)
{
	for(const TAGGED_PROPVAL* tp = propvals.ppropval; tp < propvals.ppropval+propvals.count; ++tp)
		switch(tp->proptag)
		{
		case PR_CONVERSATION_INDEX:
			ConversationIndex = *tp; break;
		case PR_CONVERSATION_TOPIC:
		   ConversationTopic = pval(char); break;
		case PR_READ:
			IsRead = *pval(bool); break;
		case PR_INTERNET_MESSAGE_ID:
			InternetMessageId = pval(char); break;
		case PR_INTERNET_REFERENCES:
			References = pval(char); break;
		case PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED:
			IsDeliveryReceiptRequested = *pval(bool); break;
		case PR_READ_RECEIPT_REQUESTED:
			IsReadReceiptRequested = *pval(bool); break;
		case PR_RECEIVED_BY_ADDRTYPE:
			defaulted(ReceivedBy).Mailbox.RoutingType = pval(char); break;
		case PR_RECEIVED_BY_EMAIL_ADDRESS:
			defaulted(ReceivedBy).Mailbox.EmailAddress = pval(char); break;
		case PR_RECEIVED_BY_NAME:
			defaulted(ReceivedBy).Mailbox.Name = pval(char); break;
		case PR_RCVD_REPRESENTING_ADDRTYPE:
			defaulted(ReceivedRepresenting).Mailbox.RoutingType = pval(char); break;
		case PR_RCVD_REPRESENTING_EMAIL_ADDRESS:
			defaulted(ReceivedRepresenting).Mailbox.EmailAddress = pval(char); break;
		case PR_RCVD_REPRESENTING_NAME:
			defaulted(ReceivedRepresenting).Mailbox.Name = pval(char); break;
		case PR_SENDER_ADDRTYPE:
			defaulted(Sender).Mailbox.RoutingType = pval(char); break;
		case PR_SENDER_EMAIL_ADDRESS:
			defaulted(Sender).Mailbox.EmailAddress = pval(char); break;
		case PR_SENDER_NAME:
			defaulted(Sender).Mailbox.Name = pval(char); break;
		case PR_SENT_REPRESENTING_ADDRTYPE:
			defaulted(From).Mailbox.RoutingType = pval(char); break;
		case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
			defaulted(From).Mailbox.EmailAddress = pval(char); break;
		case PR_SENT_REPRESENTING_NAME:
			defaulted(From).Mailbox.Name = pval(char); break;
		default:
			break;
		}
}

#undef pval

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collect property tags and names for path specification

 * @param     tags    Inserter to use for property tags
 * @param     names   Inserter to use for property names
 * @param     types   Inserter to use for the type of each named property
 * @param     special Bit map to store special property flags in
 */
void tPath::tags(vector_inserter<uint32_t>& tagIns, vector_inserter<PROPERTY_NAME>& nameIns,
                     vector_inserter<uint16_t>& typeIns, uint64_t& special) const
{return std::visit([&](auto&& v){return v.tags(tagIns, nameIns, typeIns, special);}, *static_cast<const Base*>(this));};

///////////////////////////////////////////////////////////////////////////////

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

tSyncFolderHierarchyCU::tSyncFolderHierarchyCU(sFolder &&f) : folder(std::move(f))
{}

///////////////////////////////////////////////////////////////////////////////

tTargetFolderIdType::tTargetFolderIdType(std::variant<tFolderId, tDistinguishedFolderId>&& id) :
    folderId(std::move(id))
{}

///////////////////////////////////////////////////////////////////////////////

mFreeBusyResponse::mFreeBusyResponse(tFreeBusyView&& fbv) : FreeBusyView(std::move(fbv))
{}

///////////////////////////////////////////////////////////////////////////////

mResponseMessageType::mResponseMessageType(const std::string& rclass,
    const std::optional<std::string> &rcode, const std::optional<std::string> &mt) :
	ResponseClass(rclass), MessageText(mt), ResponseCode(rcode)
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
