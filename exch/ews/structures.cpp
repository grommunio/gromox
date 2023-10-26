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
#include <set>
#include <utility>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/freebusy.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/ical.hpp>

#include "ews.hpp"
#include "structures.hpp"
#include "namedtags.hpp"

using namespace gromox::EWS;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace std::string_literals;
using namespace tinyxml2;

namespace
{

/**
 * @brief      Helper struct for property type derivation
 *
 * Provides a mapping from the requested EWS/C++ type to the (likely)
 * corresponding property type (e.g. std::string -> const char*).
 * Fundamental type are mapped automatically, compound types always need an
 * explicit mapping (via template specialization).
 *
 * Note that this is only for convenience and does not provide any type safety.
 *
 * @tparam     T     Requested type
 */
template<typename T> struct _propType {
	using type = typename std::conditional_t<std::is_fundamental_v<T>, T, void>;
};

template<> struct _propType<bool> {using type = uint8_t;};
template<> struct _propType<std::string> {using type = char*;};
template<> struct _propType<sBase64Binary> {using type = BINARY*;};

/**
 * Type alias mapping EWS/C++ type to property type.
 */
template<typename T> using PropType	= typename _propType<T>::type;

/**
 * Type used for the count member of a class.
 */
template<class C>
using count_t = decltype(C::count);

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
 * @param      prop       Property or nullptr
 * @param      target     Destination variable
 *
 * @tparam     T          Type of the field
 * @tparam     PT         Type of the value contained in the property
 */
template<typename T, typename PT=PropType<T>, std::enable_if_t<!std::is_same_v<PT, void>, bool> = true>
void fromProp(const TAGGED_PROPVAL* prop, std::optional<T>& target)
{
	if(!prop)
		return;
	if constexpr(std::is_pointer_v<PT>)
		target.emplace(static_cast<PT>(prop->pvalue));
	else
		target.emplace(*static_cast<const PT*>(prop->pvalue));
}

/**
 * @brief      Fill field from property
 *
 * @param      prop       Property or nullptr
 * @param      target     Destination variable
 *
 * @tparam     T          Type of the field
 * @tparam     PT         Type of the value contained in the property
 */
template<typename T, typename PT=PropType<T>, std::enable_if_t<!std::is_same_v<PT, void>, bool> = true>
void fromProp(const TAGGED_PROPVAL* prop, T& target)
{
	if(!prop)
		return;
	if constexpr(std::is_pointer_v<PT>)
		target = static_cast<PT>(prop->pvalue);
	else
		target = *static_cast<const PT*>(prop->pvalue);
}

/**
 * @brief      Read time point from property
 *
 * @param      prop    Property or nullptr
 * @param      target  Destination variable
 */
void fromProp(const TAGGED_PROPVAL* prop, std::optional<sTimePoint>& target)
{
	if(prop)
		target.emplace(sTimePoint::fromNT(*static_cast<const uint64_t*>(prop->pvalue)));
}

/**
 * @brief      Get maximum number of contained objects
 *
 * @tparam     C     Container class
 *
 * @return     Maximum number of objects
 */
template<class C>
constexpr size_t max_count()
{return std::numeric_limits<count_t<C>>::max();}

/**
 * @brief      Convert STL vector to gromox array
 *
 * The resulting array does not own the content and merely provides a view of
 * the data, acting as a compatibility layer between STL and gromox types.
 *
 * Throws a DispatchError if the destination array type does not have
 * sufficient capacity for the data.
 *
 * @param      data  Data to wrap
 *
 * @tparam     C     Container class
 * @tparam     T     Contained object type
 *
 * @return     Gromox array view of the data
 */
template<class C, typename T>
inline C mkArray(const std::vector<T>& data)
{
	if(data.size() > max_count<C>())
		throw DispatchError(E3099);
	return C{count_t<C>(data.size()), const_cast<T*>(data.data())};
}

/**
 * @brief      Remove leading and trailing whitespaces
 *
 * @param      sv      String to trim
 *
 * @return     Trimmed version
 */
std::string_view trim(const std::string_view& sv)
{
	size_t from = 0, to = sv.length();
	while(from < to && std::isspace(sv[from])) ++from;
	while(to > from && std::isspace(sv[to-1])) --to;
	return sv.substr(from, to-from);
}

/**
 * @brief      Determine size of the primary property structure
 *
 * Calculates amount of memory to allocate for a given type.
 * Includes only the primary structure used for storage, i.e. the contained
 * type itself for single values and a management structure
 * (e.g. BINARY, X_ARRAY) for complext types. Does not take into account any
 * further necessary allocations.
 *
 * In case of dynamic length types (e.g. PT_UNICODE), returns 0.
 *
 * @param      type  Property type ID
 *
 * @return     Memory requirement of property type
 */
constexpr size_t typeWidth(uint16_t type)
{
	switch (type) {
	case PT_UNSPECIFIED:  return sizeof(TYPED_PROPVAL);
	case PT_BOOLEAN:      return 1;
	case PT_SHORT:        return 2;
	case PT_LONG:
	case PT_FLOAT:
	case PT_ERROR:        return 4;
	case PT_DOUBLE:
	case PT_CURRENCY:
	case PT_APPTIME:
	case PT_I8:
	case PT_SYSTIME:      return 8;
	case PT_OBJECT:
	case PT_BINARY:       return sizeof(BINARY);
	case PT_CLSID:        return sizeof(GUID);
	case PT_SVREID:       return sizeof(SVREID);
	case PT_SRESTRICTION: return sizeof(RESTRICTION);
	case PT_ACTIONS:      return sizeof(RULE_ACTIONS);
	case PT_MV_SHORT:     return sizeof(SHORT_ARRAY);
	case PT_MV_LONG:      return sizeof(LONG_ARRAY);
	case PT_MV_FLOAT:     return sizeof(FLOAT_ARRAY);
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:   return sizeof(DOUBLE_ARRAY);
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_SYSTIME:   return sizeof(LONGLONG_ARRAY);
	case PT_MV_STRING8:
	case PT_MV_UNICODE:   return sizeof(STRING_ARRAY);
	case PT_MV_CLSID:     return sizeof(GUID_ARRAY);
	case PT_MV_BINARY:    return sizeof(BINARY_ARRAY);
	default:              return 0;
	}
}

/**
 * @brief Generate space separated list of days as string
 *
 * @param weekrecur    Bit pattern
 * @param daysofweek   Return string
 *
 * PatterTypeSpecific Week
 * X  (1 bit): This bit is not used. MUST be zero and MUST be ignored.
 * Sa (1 bit): (0x00000040) The event occurs on Saturday.
 * F  (1 bit): (0x00000020) The event occurs on Friday.
 * Th (1 bit): (0x00000010) The event occurs on Thursday.
 * W  (1 bit): (0x00000008) The event occurs on Wednesday.
 * Tu (1 bit): (0x00000004) The event occurs on Tuesday.
 * M  (1 bit): (0x00000002) The event occurs on Monday.
 * Su (1 bit): (0x00000001) The event occurs on Sunday.
 * unused (3 bytes): These bits are not used. MUST be zero and MUST be ignored.
 */
void daysofweek_to_str(const uint32_t& weekrecur, std::string& daysofweek)
{
	for(uint8_t wd = 0; wd < 7; ++wd)
		if(weekrecur & (1 << wd))
			daysofweek.append(Enum::DayOfWeekType::Choices[wd]).append(" ");
	// remove trailing space
	if(!daysofweek.empty() && std::isspace(daysofweek.back()))
		daysofweek.pop_back();
}

/**
 * @brief Get the recurrence pattern structure
 *
 * @param recurData    Recurrence data
 * @return APPOINTMENT_RECUR_PAT Appointment recurrence pattern
 */
APPOINTMENT_RECUR_PAT getAppointmentRecur(const BINARY* recurData)
{
	EXT_PULL ext_pull;
	APPOINTMENT_RECUR_PAT apprecurr;
	ext_pull.init(recurData->pb, recurData->cb, gromox::zalloc, EXT_FLAG_UTF16);
	if(ext_pull.g_apptrecpat(&apprecurr) != EXT_ERR_SUCCESS)
		throw InputError(E3109);
	return apprecurr;
}

/**
 * @brief Get the Recurrence Pattern object
 *
 * @param apprecurr    Appointment recurrence pattern
 * @return tRecurrencePattern
 */
tRecurrencePattern get_recurrence_pattern(const APPOINTMENT_RECUR_PAT& apprecurr)
{
	ICAL_TIME itime;
	std::string daysofweek("");
	switch (apprecurr.recur_pat.patterntype)
	{
	case PATTERNTYPE_DAY:
		return tDailyRecurrencePattern(apprecurr.recur_pat.period / 1440);
	case PATTERNTYPE_WEEK:
	{
		daysofweek_to_str(apprecurr.recur_pat.pts.weekrecur, daysofweek);
		return tWeeklyRecurrencePattern(apprecurr.recur_pat.period, daysofweek,
			Enum::DayOfWeekType(uint8_t(apprecurr.recur_pat.firstdow)));
	}
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_MONTHEND:
	case PATTERNTYPE_HJMONTH:
	case PATTERNTYPE_HJMONTHEND:
	{
		ical_get_itime_from_yearday(1601,
			apprecurr.recur_pat.firstdatetime / 1440 + 1, &itime);
		if(apprecurr.recur_pat.period % 12 != 0)
			return tAbsoluteMonthlyRecurrencePattern(apprecurr.recur_pat.period,
				apprecurr.recur_pat.pts.dayofmonth);
		return tAbsoluteYearlyRecurrencePattern(apprecurr.recur_pat.pts.dayofmonth,
			Enum::MonthNamesType(uint8_t(itime.month - 1)));
	}
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH:
	{
		ical_get_itime_from_yearday(1601,
			apprecurr.recur_pat.firstdatetime / 1440 + 1, &itime);
		daysofweek_to_str(apprecurr.recur_pat.pts.weekrecur, daysofweek);
		Enum::DayOfWeekIndexType dayofweekindex(uint8_t(
			apprecurr.recur_pat.pts.monthnth.recurnum - 1));
		if(apprecurr.recur_pat.period % 12 != 0)
			return tRelativeMonthlyRecurrencePattern(apprecurr.recur_pat.period,
				daysofweek, dayofweekindex);
		return tRelativeYearlyRecurrencePattern(daysofweek, dayofweekindex,
			Enum::MonthNamesType(uint8_t(itime.month - 1)));
	}
	default:
		throw InputError(E3110);
	}
}

/**
 * @brief Get the Recurrence Range object
 *
 * @param apprecurr    Appointment recurrence pattern
 * @return tRecurrenceRange
 */
tRecurrenceRange get_recurrence_range(const APPOINTMENT_RECUR_PAT& apprecurr)
{
	auto startdate = rop_util_rtime_to_unix2(apprecurr.recur_pat.startdate);
	switch (apprecurr.recur_pat.endtype)
	{
	case ENDTYPE_AFTER_N_OCCURRENCES:
		return tNumberedRecurrenceRange(startdate, apprecurr.recur_pat.occurrencecount);
	case ENDTYPE_AFTER_DATE:
		return tEndDateRecurrenceRange(startdate,
			rop_util_rtime_to_unix2(apprecurr.recur_pat.enddate));
	default:
		return tNoEndRecurrenceRange(startdate);
	}
}

/**
 * @brief process deleted and modified occurrences
 *
 * @param entryid      Entryid of the master appointment
 * @param apprecurr    Appointment recurrence pattern
 * @param modOccs      Vector containing modified occurrences
 * @param delOccs      Vector containing deleted occurrences
 */
void process_occurrences(const TAGGED_PROPVAL* entryid, const APPOINTMENT_RECUR_PAT& apprecurr,
	std::vector<tOccurrenceInfoType>& modOccs,
	std::vector<tDeletedOccurrenceInfoType>& delOccs)
{
	std::set<uint32_t> mod_insts(apprecurr.recur_pat.pmodifiedinstancedates,
		apprecurr.recur_pat.pmodifiedinstancedates + apprecurr.recur_pat.modifiedinstancecount);

	size_t del_count = 0; // counter for deleted occurrences
	for(size_t i = 0; i < apprecurr.recur_pat.deletedinstancecount; ++i)
	{
		if(mod_insts.find(apprecurr.recur_pat.pdeletedinstancedates[i]) != mod_insts.end())
			modOccs.emplace_back(tOccurrenceInfoType({
				sOccurrenceId(*entryid, apprecurr.pexceptioninfo[i-del_count].originalstartdate),
				rop_util_rtime_to_unix2(apprecurr.pexceptioninfo[i-del_count].startdatetime),
				rop_util_rtime_to_unix2(apprecurr.pexceptioninfo[i-del_count].enddatetime),
				rop_util_rtime_to_unix2(apprecurr.pexceptioninfo[i-del_count].originalstartdate)}));
		else
		{
			del_count++;
			delOccs.emplace_back(tDeletedOccurrenceInfoType{rop_util_rtime_to_unix2(
				apprecurr.recur_pat.pdeletedinstancedates[i])});
		}
	}
}

}

///////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Construct from BINARY pointer
 *
 * @param      bin   Binary data. Must not be nullptr.
 */
sBase64Binary::sBase64Binary(const BINARY* bin)
{assign(bin->pb, bin->pb+bin->cb);}

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

#define TRY(expr, msg, rc) EWSContext::ext_error(expr, msg, rc)

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
		throw EWSError::InvalidAttachmentId(E3081);
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this), E3146, "ErrorInvalidAttachmentId");
	TRY(ext_pull.g_uint32(&attachment_num), E3147,"ErrorInvalidAttachmentId");
}

/**
 * @brief      Create occurrence ID from message entry ID property and basedate
 */
sOccurrenceId::sOccurrenceId(const TAGGED_PROPVAL& tp, uint32_t bd) : sMessageEntryId(tp), basedate(bd)
{}


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
		throw EWSError::InvalidFolderId(E3050);
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_folder_eid(this), E3148, "ErrorInvalidFolderId");
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
		throw EWSError::InvalidId(E3050);
	ext_pull.init(data, uint32_t(size), EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this), E3149, "ErrorInvalidId");
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
		throw EWSError::FolderNotFound(E3051(folder.Id));
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
 * @brief      Check whether the folder is a distinguished (fixed ID) folder
 *
 * @return     true if the folder is distinguished, false otherwise
 */
bool sFolderSpec::isDistinguished() const
{return rop_util_get_gc_value(folderId) < (location == PUBLIC? PUBLIC_FID_CUSTOM : PRIVATE_FID_CUSTOM);}

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

sShape::PropInfo::PropInfo(uint8_t f, const PROPERTY_NAME* n) : name(n), flags(f)
{}

sShape::PropInfo::PropInfo(uint8_t f, const TAGGED_PROPVAL* p) : prop(p), flags(f)
{}

/**
 * @brief      Initialize shape from folder shape
 *
 * @param      shape  Requested shape
 */
sShape::sShape(const tFolderResponseShape& shape)
{shape.tags(*this);}

/**
 * @brief      Initialize shape from item shape
 *
 * @param      shape  Requested shape
 */
sShape::sShape(const tItemResponseShape& shape)
{shape.tags(*this);}

/**
 * @brief      Initialize shape from changes list
 *
 * @param      changes  List of folder changes
 */
sShape::sShape(const tFolderChange& changes)
{
	for(const auto& change : changes.Updates) {
		if(std::holds_alternative<tSetFolderField>(change))
			std::get<tSetFolderField>(change).fieldURI.tags(*this);
		else if(std::holds_alternative<tDeleteFolderField>(change))
			std::get<tDeleteFolderField>(change).fieldURI.tags(*this, false);
		else
			mlog(LV_WARN, "[ews] AppendToFolderField not implemented - ignoring");
	}
}

/**
 * @brief      Initialize shape from changes list
 *
 * @param      changes  List of item changes
 */
sShape::sShape(const tItemChange& changes)
{
	for(const auto& change : changes.Updates) {
		if(std::holds_alternative<tSetItemField>(change))
			std::get<tSetItemField>(change).fieldURI.tags(*this);
		else if(std::holds_alternative<tDeleteItemField>(change))
			std::get<tDeleteItemField>(change).fieldURI.tags(*this, false);
		else
			mlog(LV_WARN, "[ews] AppendToItemField not implemented - ignoring");
	}
}

/**
 * @brief      Initialize shape properties
 *
 * Marks each property as explicitely requested as field.
 *
 * @param      tp     Array of propvals
 */
sShape::sShape(const TPROPVAL_ARRAY& tp)
{
	props.reserve(tp.count);
	for(const TAGGED_PROPVAL* prop = tp.ppropval; prop != tp.ppropval+tp.count; ++prop)
		props.emplace(prop->proptag, PropInfo(FL_FIELD, prop));
}

/**
 * @brief      Add a tag to the shape
 *
 * @param      tag    Tag ID
 * @param      flags  Shape target flags
 *
 * @return     Reference to self
 */
sShape& sShape::add(uint32_t tag, uint8_t flags)
{
	auto it = props.find(tag);
	if(it == props.end()) {
		((flags & FL_RM)? dTags : tags).emplace_back(tag);
		it = props.emplace(tag, flags).first;
	}
	it->second.flags |= flags;
	return *this;
}

/**
 * @brief      Add named property to the shape
 *
 * @param      name   Property name
 * @param      type   Property type
 * @param      flags  Shape target flags
 *
 * @return     Reference to self
 */
sShape& sShape::add(const PROPERTY_NAME& name, uint16_t type, uint8_t flags)
{
	names.emplace_back(name);
	namedTags.emplace_back(type);
	nameMeta.emplace_back(flags);
	namedCache.emplace_back(TAGGED_PROPVAL{});
	return *this;
}

/**
 * @brief      Provide array of tags marked for deletion
 *
 * @return     Tag array to delete
 */
PROPTAG_ARRAY sShape::remove() const
{return mkArray<PROPTAG_ARRAY>(dTags);}

/**
 * @brief      Add property for writing
 *
 * Added properties currently cannot be read/removed and are not registered
 * in the central structure used by `get` due to lack of use cases and
 * significant additional overhead.
 *
 * Does not perform a deep copy of the property, the value must stay valid.
 *
 * @param      tp    Property to add
 */
void sShape::write(const TAGGED_PROPVAL& tp)
{
	/* Currently not needed, but I'll leave this here in case it becomes necessary
    TAGGED_PROPVAL* prop = EWSContext::alloc<TAGGED_PROPVAL>();
	*prop = tp;
	props[tp.proptag].prop = prop; */
	auto it = std::find_if(wProps.begin(), wProps.end(), [&](const TAGGED_PROPVAL& t){return t.proptag == tp.proptag;});
	if(it == wProps.end())
		wProps.emplace_back(tp);
	else
		*it = tp;
}

/**
 * @brief      Add named property for writing
 *
 * Automatically provides the correct tag ID.
 * If the name cannot be found nothing happens.
 *
 * @param      name  Property name
 * @param      tp    Property to add
 */
void sShape::write(const PROPERTY_NAME& name, const TAGGED_PROPVAL& tp)
{
	auto it = std::find(names.begin(), names.end(), name);
	if(it == names.end()) {
		namedTags.emplace_back(tp.proptag);
		nameMeta.emplace_back(0);
		names.emplace_back(name);
		namedCache.emplace_back(tp);
		return;
	}
	auto index = std::distance(names.begin(), it);
	TAGGED_PROPVAL augmented{namedTags[index], tp.pvalue};
	write(augmented);
}

/**
 * @brief      Provide array of properties to write to exmdb
 *
 * @return     Array of properties to write
 */
TPROPVAL_ARRAY sShape::write() const
{return mkArray<TPROPVAL_ARRAY>(wProps);}

bool sShape::writes(uint32_t tag) const
{return std::find_if(wProps.begin(), wProps.end(), [=](const TAGGED_PROPVAL& tp){return tp.proptag == tag;}) != wProps.end();}


/**
 * @brief      Reset all properties to unloaded
 */
void sShape::clean()
{
	for(auto& entry : props)
		entry.second.prop = nullptr;
}

/**
 * @brief      Retrieve property by tag
 *
 * @param      tag   Tag ID
 * @param      mask  Mask of flags or FL_ANY
 *
 * @return     Pointer to property or nullptr if not found
 */
const TAGGED_PROPVAL* sShape::get(uint32_t tag, uint8_t mask) const
{
	auto it = props.find(tag);
	if(it == props.end() || (mask != FL_ANY && !(it->second.flags & mask)))
		return nullptr;
	return it->second.prop;
}

/**
 * @brief      Retrieve property by name
 *
 * @param      name  Property name
 * @param      mask  Mask of flags or FL_ANY
 *
 * @return     Pointer to property or nullptr if not found
 */
const TAGGED_PROPVAL* sShape::get(const PROPERTY_NAME& name, uint8_t mask) const
{
	auto it = std::find(names.begin(), names.end(), name);
	if(it == names.end())
		return nullptr;
	auto index = std::distance(names.begin(), it);
	return get(namedTags[index], mask);
}

/**
 * @brief      Get property data
 *
 * @param      tag   Tag ID
 * @param      mask  Mask of flags or FL_ANY
 *
 * @tparam     T     Property value type
 *
 * @return     Pointer to property value or nullptr if not found
 */
template<typename T> const T* sShape::get(uint32_t tag, uint8_t mask) const
{
	const TAGGED_PROPVAL* prop = get(tag, mask);
	return prop? static_cast<const T*>(prop->pvalue) : nullptr;
}

/**
 * @brief      Wrap requested property names
 *
 * @return     The propname array
 */
PROPNAME_ARRAY sShape::namedProperties() const
{return PROPNAME_ARRAY{uint16_t(names.size()), const_cast<PROPERTY_NAME*>(names.data())};}

/**
 * @brief      Set named property IDs
 *
 * The ID array must have the same count as the stored property names.
 *
 * @param      ids   IDs of the named properties
 *
 * @return     true if successful, false otherwise.
 */
bool sShape::namedProperties(const PROPID_ARRAY& ids)
{
	if(ids.count != names.size()) //Abort if sizes don't match
		return false;
	size_t namedAdd = 0, namedRm = 0;
	for(uint32_t tag : namedTags) {//Remove all named tags
		auto it = props.find(tag);
		if(it == props.end())
			continue;
		++((it->second.flags & FL_RM)? namedRm : namedAdd);
		props.erase(it);
	}
	if(tags.size() >= namedAdd)
		tags.resize(tags.size()-namedAdd);
	if(dTags.size() >=namedRm)
		dTags.resize(dTags.size()-namedRm);//Truncate named IDs
	for(size_t index = 0; index < names.size(); ++index) { //Add named IDs
		uint32_t tag = PROP_TAG(PROP_TYPE(namedTags[index]), ids.ppropid[index]);
		namedTags[index] = tag;
		if(!PROP_ID(tag))
			continue;
		if(nameMeta[index] & FL_RM)
			dTags.emplace_back(tag);
		else {
			props.emplace(tag, PropInfo(nameMeta[index], &names[index]));
			tags.emplace_back(tag);
		}
	}
	if(namedCache.size() == namedTags.size()) {
		for(size_t index = 0; index < namedTags.size(); ++index)
			if(namedCache[index].proptag)
				write(names[index], TAGGED_PROPVAL{namedTags[index], namedCache[index].pvalue});
		namedCache.clear();
	}
	return true;
}

/**
 * @brief      Set properties
 *
 * @param      properties  Properties to set
 */
void sShape::properties(const TPROPVAL_ARRAY& properties)
{
	for(const TAGGED_PROPVAL* prop = properties.ppropval; prop != properties.ppropval+properties.count; ++prop)
		props[prop->proptag].prop = prop;
}

/**
 * @brief      Wrap requested property tag IDs
 *
 * @return     Tag ID array
 */
PROPTAG_ARRAY sShape::proptags() const
{return PROPTAG_ARRAY{uint16_t(tags.size()), const_cast<uint32_t*>(tags.data())};}

/**
 * @brief      Store extended properties
 *
 * @param      extprops  Location to store extended properties in
 */
void sShape::putExtended(std::vector<tExtendedProperty>& extprops) const
{
	for(const auto& prop : props)
		if(prop.second.flags & FL_EXT && prop.second.prop)
			extprops.emplace_back(*prop.second.prop, prop.second.name? *prop.second.name : NONAME);
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
		throw EWSError::InvalidSyncStateData(E3052);
	ext_pull.init(data.data(), uint32_t(data.size()), EWSContext::alloc, 0);
	if(ext_pull.g_tpropval_a(&propvals) != EXT_ERR_SUCCESS)
		return;
	for (TAGGED_PROPVAL* propval = propvals.ppropval; propval < propvals.ppropval+propvals.count; ++propval)
	{
		switch (propval->proptag) {
		case MetaTagIdsetGiven1:
			if (!given.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw EWSError::InvalidSyncStateData(E3053);
			break;
		case MetaTagCnsetSeen:
			if (!seen.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw EWSError::InvalidSyncStateData(E3054);
			break;
		case MetaTagCnsetRead:
			if (!read.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw EWSError::InvalidSyncStateData(E3055);
			break;
		case MetaTagCnsetSeenFAI:
			if (!seen_fai.deserialize(*static_cast<const BINARY *>(propval->pvalue)))
				throw EWSError::InvalidSyncStateData(E3056);
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
 * @brief     Create time point from date-time string
 *
 * @throw     DeserializationError   Conversion failed
 *
 * @param     Date-time string
 */
sTimePoint::sTimePoint(const char* dtstr)
{
	if(!dtstr)
		throw EWSError::SchemaValidation(E3150);
	tm t{};
	float seconds = 0, unused;
	int tz_hour = 0, tz_min = 0;
	if(sscanf(dtstr, "%4d-%02d-%02dT%02d:%02d:%f%03d:%02d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min,
	          &seconds, &tz_hour, &tz_min) < 6) //Timezone info is optional, date and time values mandatory
		throw EWSError::SchemaValidation(E3151);
	t.tm_sec = int(seconds);
	t.tm_year -= 1900;
	t.tm_mon -= 1;
	time_t timestamp = mktime(&t)-timezone;
	if(timestamp == time_t(-1))
		throw EWSError::ValueOutOfRange(E3152);
	time = gromox::time_point::clock::from_time_t(timestamp);
	seconds = std::modf(seconds, &unused);
	time += std::chrono::microseconds(int(seconds*1000000));
	offset = std::chrono::minutes(60*tz_hour+(tz_hour < 0? -tz_min : tz_min));
}

/**
 * @brief      Generate time point from NT timestamp
 */
sTimePoint sTimePoint::fromNT(uint64_t timestamp)
{return sTimePoint{rop_util_nttime_to_unix2(timestamp)};}

/**
 * @brief     Convert time point to NT timestamp
 */
uint64_t sTimePoint::toNT() const
{return rop_util_unix_to_nttime(time-offset);}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Types implementation

tAttachment::tAttachment(const sAttachmentId& aid, const TPROPVAL_ARRAY& props)
{
	AttachmentId.emplace(aid);
	fromProp(props.find(PR_ATTACH_LONG_FILENAME), Name);
	fromProp(props.find(PR_ATTACH_MIME_TAG), ContentType);
	fromProp(props.find(PR_ATTACH_CONTENT_ID), ContentId);
	fromProp(props.find(PR_ATTACH_SIZE), Size);
	fromProp(props.find(PR_LAST_MODIFICATION_TIME), LastModifiedTime);
	uint32_t* flags = props.get<uint32_t>(PR_ATTACH_FLAGS);
	if(flags)
		IsInline = *flags & ATT_MHTML_REF;
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


tBaseFolderType::tBaseFolderType(const sShape& shape)
{
	const TAGGED_PROPVAL* prop;
	fromProp(shape.get(PR_CHANGE_KEY), defaulted(FolderId).ChangeKey);
	fromProp(shape.get(PR_CONTAINER_CLASS), FolderClass);
	fromProp(shape.get(PR_CONTENT_COUNT), TotalCount);
	fromProp(shape.get(PR_DISPLAY_NAME), DisplayName);
	fromProp(shape.get(PR_ENTRYID), defaulted(FolderId).Id);
	fromProp(shape.get(PR_FOLDER_CHILD_COUNT), ChildFolderCount);
	if((prop = shape.get(PR_PARENT_ENTRYID)))
		fromProp(prop, defaulted(ParentFolderId).Id);
	shape.putExtended(ExtendedProperty);
}

sFolder tBaseFolderType::create(const sShape& shape)
{
	enum Type : uint8_t {NORMAL, CALENDAR, TASKS, CONTACTS, SEARCH};
	const char* frClass = shape.get<char>(PR_CONTAINER_CLASS, sShape::FL_ANY);
	const uint32_t* frType = shape.get<uint32_t>(PR_FOLDER_TYPE, sShape::FL_ANY);
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
		return tCalendarFolderType(shape);
	case CONTACTS:
		return tContactsFolderType(shape);
	case SEARCH:
		return tSearchFolderType(shape);
	case TASKS:
		return tTasksFolderType(shape);
	default:
		return tFolderType(shape);
	}
}

///////////////////////////////////////////////////////////////////////////////

tBaseItemId::tBaseItemId(const sBase64Binary& fEntryID, const std::optional<sBase64Binary>& chKey) :
    Id(fEntryID), ChangeKey(chKey)
{}

tBaseObjectChangedEvent::tBaseObjectChangedEvent(const sTimePoint& ts, std::variant<tFolderId, tItemId>&& oid, tFolderId&& fid) :
    TimeStamp(ts), objectId(std::move(oid)), ParentFolderId(std::move(fid))
{}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Create gromox event mask from event list
 *
 * @return gromox event mask
 *
 * @todo actual implementation...
 */
uint16_t tBaseSubscriptionRequest::eventMask() const
{
	uint16_t res = 0;
	for(auto event : EventTypes)
		switch(event.index()) {
		case 0: // CopiedEvent
			res |= NF_OBJECT_COPIED; break;
		case 1: // CreatedEvent
			res |= NF_OBJECT_CREATED; break;
		case 2: // DeletedEvent
			res |= NF_OBJECT_DELETED; break;
		case 3: // ModifiedEvent
			res |= NF_OBJECT_MODIFIED; break;
		case 4: // MovedEvent
			res |= NF_OBJECT_MOVED; break;
		case 5: // NewMailEvent
			res |= NF_NEW_MAIL; break;
		}
	return res;
}

///////////////////////////////////////////////////////////////////////////////
tCalendarItem::tCalendarItem(const sShape& shape) : tItem(shape)
{
	fromProp(shape.get(PR_RESPONSE_REQUESTED), IsResponseRequested);
	const TAGGED_PROPVAL* prop;
	if((prop = shape.get(PR_SENDER_ADDRTYPE)))
		fromProp(prop, defaulted(Organizer).Mailbox.RoutingType);
	if((prop = shape.get(PR_SENDER_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(Organizer).Mailbox.EmailAddress);
	if((prop = shape.get(PR_SENDER_NAME)))
		fromProp(prop, defaulted(Organizer).Mailbox.Name);

	if ((prop = shape.get(NtAppointmentNotAllowPropose)))
		AllowNewTimeProposal.emplace(!*static_cast<const uint8_t*>(prop->pvalue));

	if((prop = shape.get(NtAppointmentRecur)))
	{
		const BINARY* recurData = static_cast<BINARY*>(prop->pvalue);
		if(recurData->cb > 0) {
			APPOINTMENT_RECUR_PAT apprecurr = getAppointmentRecur(recurData);

			auto& rec = Recurrence.emplace();
			rec.RecurrencePattern = get_recurrence_pattern(apprecurr);
			rec.RecurrenceRange = get_recurrence_range(apprecurr);

			// The count of the exceptions (modified and deleted occurrences)
			// is summed in deletedinstancecount
			if(apprecurr.recur_pat.deletedinstancecount > 0)
			{
				std::vector<tOccurrenceInfoType> modOccs;
				std::vector<tDeletedOccurrenceInfoType> delOccs;
				auto entryid_propval = shape.get(PR_ENTRYID);
				process_occurrences(entryid_propval, apprecurr, modOccs, delOccs);
				if(modOccs.size() > 0)
					ModifiedOccurrences.emplace(modOccs);
				if(delOccs.size() > 0)
					DeletedOccurrences.emplace(delOccs);
			}
		}
	}

	if ((prop = shape.get(NtAppointmentReplyTime)))
		AppointmentReplyTime.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));

	fromProp(shape.get(NtAppointmentSequence), AppointmentSequenceNumber);

	if((prop = shape.get(NtAppointmentStateFlags)))
	{
		const uint32_t* stateFlags = static_cast<const uint32_t*>(prop->pvalue);
		AppointmentState.emplace(*stateFlags);
		IsMeeting = *stateFlags & asfMeeting ? TRUE : false;
		IsCancelled = *stateFlags & asfCanceled ? TRUE : false;
	}

	fromProp(shape.get(NtAppointmentSubType), IsAllDayEvent);

	if ((prop = shape.get(NtBusyStatus)))
	{
		const uint32_t* busyStatus = static_cast<const uint32_t*>(prop->pvalue);
		Enum::LegacyFreeBusyType freeBusy = Enum::NoData;
		switch (*busyStatus)
		{
			case olFree:             freeBusy = Enum::Free; break;
			case olTentative:        freeBusy = Enum::Tentative; break;
			case olBusy:             freeBusy = Enum::Busy; break;
			case olOutOfOffice:      freeBusy = Enum::OOF; break;
			case olWorkingElsewhere: freeBusy = Enum::WorkingElsewhere; break;
		}
		LegacyFreeBusyStatus.emplace(freeBusy);
	}

	if ((prop = shape.get(NtCommonEnd)))
		End.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));

	if ((prop = shape.get(NtCommonStart)))
		Start.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));

	fromProp(shape.get(NtFInvited), MeetingRequestWasSent);
	fromProp(shape.get(NtLocation), Location);

	if ((prop = shape.get(NtResponseStatus)))
	{
		const uint8_t* responseStatus = static_cast<const uint8_t*>(prop->pvalue);
		Enum::ResponseTypeType responseType = Enum::Unknown;
		switch(*responseStatus)
		{
			case olResponseOrganized:    responseType = Enum::Organizer; break;
			case olResponseTentative:    responseType = Enum::Tentative; break;
			case olResponseAccepted:     responseType = Enum::Accept; break;
			case olResponseDeclined:     responseType = Enum::Decline; break;
			case olResponseNotResponded: responseType = Enum::NoResponseReceived; break;
		}
		MyResponseType.emplace(responseType);

	}

	if ((prop = shape.get(NtGlobalObjectId)))
	{
		const BINARY* goid = static_cast<BINARY*>(prop->pvalue);
		if(goid->cb > 0) {
			std::string uid(goid->cb*2+1, 0);
			encode_hex_binary(goid->pb, goid->cb, uid.data(), int(uid.size()));
			UID.emplace(std::move(uid));
		}
	}
}

///////////////////////////////////////////////////////////////////////////////

tCalendarEvent::tCalendarEvent(const freebusy_event& fb_event) :
	StartTime(time_point::clock::from_time_t(fb_event.start_time)),
	EndTime(time_point::clock::from_time_t(fb_event.end_time))
{
	switch(fb_event.busy_status)
	{
		case olFree:             BusyType = "Free"; break;
		case olTentative:        BusyType = "Tentative"; break;
		case olBusy:             BusyType = "Busy"; break;
		case olOutOfOffice:      BusyType = "OOF"; break;
		case olWorkingElsewhere: BusyType = "WorkingElsewhere"; break;
		default:                 BusyType = "NoData"; break;
	}

	if (!fb_event.details.has_value())
		return;

	auto &details = CalendarEventDetails.emplace();
	if (fb_event.details->id != nullptr)
		details.ID = fb_event.details->id;
	if (fb_event.details->subject != nullptr)
		details.Subject = fb_event.details->subject;
	if (fb_event.details->location != nullptr)
		details.Location = fb_event.details->location;
	details.IsMeeting     = fb_event.details->is_meeting;
	details.IsRecurring   = fb_event.details->is_recurring;
	details.IsException   = fb_event.details->is_exception;
	details.IsReminderSet = fb_event.details->is_reminderset;
	details.IsPrivate     = fb_event.details->is_private;
}

///////////////////////////////////////////////////////////////////////////////

tFreeBusyView::tFreeBusyView(const char *username, const char *dir,
    time_t start_time, time_t end_time)
{
	std::vector<freebusy_event> fb_data;
	if (!get_freebusy(username, dir, start_time, end_time, fb_data))
		throw EWSError::FreeBusyGenerationFailed(E3144);

	FreeBusyViewType = std::all_of(fb_data.begin(), fb_data.end(),
		[](freebusy_event fb_event) { return fb_event.details.has_value(); }) ?
		"Detailed" : "FreeBusy";

	auto &cal_events = CalendarEventArray.emplace();
	cal_events.reserve(fb_data.size());

	std::copy(fb_data.begin(), fb_data.end(), std::back_inserter(cal_events));
}

///////////////////////////////////////////////////////////////////////////////

/**
 * Alphabetically sorted array of valid folder-related XML tags
 */
decltype(tChangeDescription::folderTypes) tChangeDescription::folderTypes = {
	"CalendarFolder",
	"ContactsFolder",
	"Folder",
	"SearchFolder",
	"TasksFolder"
};

/**
 * Alphabetically sorted array of valid item-related XML tags
 */
decltype(tChangeDescription::itemTypes) tChangeDescription::itemTypes = {
	"CalendarItem",
	"Contact",
	"DistributionList",
	"Item",
	"MeetingCancellation",
	"MeetingMessage",
	"MeetingRequest",
	"MeetingResponse",
	"Message",
	"Network",
	"Person",
	"PostItem",
	"RoleMember",
	"SharingMessage",
	"Task"
};

/**
 * List of field -> conversion function mapping
 */
decltype(tChangeDescription::fields) tChangeDescription::fields = {{
	{"Categories", {tChangeDescription::convCategories}},
	{"DisplayName", {[](auto&&... args){convText(PR_DISPLAY_NAME, args...);}}},
	{"Importance", {[](auto&&... args){convEnumIndex<Enum::ImportanceChoicesType>(PR_IMPORTANCE, args...);}}},
	{"IsRead", {[](auto&&... args){convBool(PR_READ, args...);}}},
	{"LastModifiedName", {[](auto&&... args){convText(PR_LAST_MODIFIER_NAME, args...);}}},
	{"Sensitivity", {[](auto&&... args) {convEnumIndex<Enum::SensitivityChoicesType>(PR_SENSITIVITY, args...);}}},
}};


/**
 * @brief      Find field information for given type/name combination
 *
 * Tries to find the best match for the type, i.e. if an exact match for the
 * given type exists, returns the corresponding field, otherwise selects the
 * generic fallback (unset type) for that field.
 *
 * This behavior is necessary because the typing is inconsistent in Outlook,
 * e.g. the item:Sensitivity URI might be given as Message::Sensitivity field.
 *
 * @param      type  Object type name
 * @param      name  Field name
 *
 * @return     Field information or nullptr if not found
 */
const tChangeDescription::Field* tChangeDescription::find(const char* type, const char* name)
{
	const Field *specific = nullptr, *general = nullptr;
	auto matches = fields.equal_range(name);
	for(auto it = matches.first; it != matches.second; ++it)
		if(!it->second.type)
			general = &it->second;
		else if(!strcmp(it->second.type, type))
			specific = &it->second;
	return specific? specific : general;
}

/**
 * @brief      Create property
 *
 * @param      tag   Tag ID
 * @param      val   Property value
 *
 * @tparam     T     Type of the contained value
 *
 * @return     Property containing a copy of the value
 */
template<typename T>
TAGGED_PROPVAL tChangeDescription::mkProp(uint32_t tag, const T& val)
{
	TAGGED_PROPVAL tp{tag, EWSContext::alloc<T>()};
	*static_cast<T*>(tp.pvalue) = val;
	return tp;
}

/**
 * @brief      Convert XML object to property
 *
 * @param      type   Object name
 * @param      name   Field name
 * @param      value  Value structure
 * @param      shape  Shape to write the property to
 */
void tChangeDescription::convProp(const char* type, const char* name, const tinyxml2::XMLElement* value, sShape& shape)
{
	const Field* field = find(type, name);
	if(!field) {
		mlog(LV_WARN, "ews: no conversion for %s::%s", type, name);
		return;
	}
	field->conv(value, shape);
}

/**
 * @brief      Property conversion function for boolean fields
 *
 * @param      tag    Tag ID
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convBool(uint32_t tag, const XMLElement* v, sShape& shape)
{
	bool value;
	if(v->QueryBoolText(&value))
		throw EWSError::InvalidExtendedPropertyValue(E3100(v->GetText()? v->GetText() : "(nil)"));
	shape.write(mkProp(tag, uint8_t(value? TRUE : false)));
}

/**
 * @brief      Property coversion function for enumerations
 *
 * Converts string to corresponding index and stores it in a numeric property.
 *
 * @param      tag    Tag ID
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 *
 * @tparam     ET     Enumeration type
 * @tparam     PT     Numeric property type
 */
template<typename ET, typename PT>
void tChangeDescription::convEnumIndex(uint32_t tag, const XMLElement* v, sShape& shape)
{shape.write(mkProp(tag, PT(ET(v->GetText()).index())));}

/**
 * @brief      Property conversion function for boolean fields
 *
 * @param      tag    Tag ID
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convText(uint32_t tag, const XMLElement* v, sShape& shape)
{
	const char* text = v->GetText();
	shape.write(TAGGED_PROPVAL{tag, const_cast<char*>(text? text : "")});
}

void tChangeDescription::convCategories(const XMLElement* v, sShape& shape)
{
	uint32_t count = 0;
	for(const XMLElement* s = v->FirstChildElement("String"); s; s = s->NextSiblingElement("String"))
		++count;
	STRING_ARRAY* categories = EWSContext::construct<STRING_ARRAY>(STRING_ARRAY{count, EWSContext::alloc<char*>(count)});
	char** dest = categories->ppstr;
	for(const XMLElement* s = v->FirstChildElement("String"); s; s = s->NextSiblingElement("String"))
		strcpy(*dest++ = EWSContext::alloc<char>(strlen(s->GetText())+1), s->GetText());
	shape.write(NtCategories, TAGGED_PROPVAL{PT_MV_UNICODE, categories});
}

///////////////////////////////////////////////////////////////////////////////

tContact::tContact(const sShape& shape) : tItem(shape)
{
	fromProp(shape.get(PR_DISPLAY_NAME), DisplayName);
	fromProp(shape.get(PR_GIVEN_NAME), GivenName);
	// TODO Initials
	fromProp(shape.get(PR_MIDDLE_NAME), MiddleName);
	fromProp(shape.get(PR_NICKNAME), Nickname);
	fromProp(shape.get(PR_COMPANY_NAME), CompanyName);
	// TODO ContactSource
	fromProp(shape.get(PR_ASSISTANT), AssistantName);
	fromProp(shape.get(PR_DEPARTMENT_NAME), Department);
	fromProp(shape.get(PR_TITLE), JobTitle);
	fromProp(shape.get(PR_OFFICE_LOCATION), OfficeLocation);
	fromProp(shape.get(PR_SURNAME), Surname);
	const char* val;
	if((val = shape.get<char>(PR_BUSINESS_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::BusinessPhone));
	if((val = shape.get<char>(PR_HOME_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::HomePhone));
	if((val = shape.get<char>(PR_PRIMARY_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::PrimaryPhone));
	if((val = shape.get<char>(PR_BUSINESS2_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::BusinessPhone2));
	if((val = shape.get<char>(PR_MOBILE_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::MobilePhone));
	if((val = shape.get<char>(PR_PAGER_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::Pager));
	if((val = shape.get<char>(PR_PRIMARY_FAX_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::BusinessFax));
	if((val = shape.get<char>(PR_ASSISTANT_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::AssistantPhone));
	if((val = shape.get<char>(PR_HOME2_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::HomePhone2));

}

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
    PropertyTag(PROP_ID(tag)),
    PropertyType(typeName(PROP_TYPE(tag)))
{}

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

tAttendee::tAttendee(const TPROPVAL_ARRAY& tps)
{
	const char* data;
	if((data = tps.get<const char>(PR_DISPLAY_NAME)))
		Mailbox.Name = data;
	if((data = tps.get<const char>(PR_EMAIL_ADDRESS)))
		Mailbox.EmailAddress = data;
	if((data = tps.get<const char>(PR_ADDRTYPE)))
		Mailbox.RoutingType = data;
}

tEmailAddressDictionaryEntry::tEmailAddressDictionaryEntry(const std::string& email,
    const Enum::EmailAddressKeyType &eakt) :
	Entry(email), Key(eakt)
{}

tPhoneNumberDictionaryEntry::tPhoneNumberDictionaryEntry(std::string phone,
    Enum::PhoneNumberKeyType pnkt) :
	Entry(std::move(phone)), Key(std::move(pnkt))
{}

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
 * @brief      Get Tag ID
 *
 * @return     Tag ID or 0 if named property
 */
uint32_t tExtendedFieldURI::tag() const
{return PropertyTag? PROP_TAG(type(), *PropertyTag) : 0;}

/**
 * @brief      Get property name
 *
 * @return     Property name or KIND_NONE name if regular tag.
 */
PROPERTY_NAME tExtendedFieldURI::name() const
{
	static constexpr PROPERTY_NAME NONAME{KIND_NONE, {}, 0, nullptr};
	if(!PropertySetId && !DistinguishedPropertySetId)
		return NONAME;
	PROPERTY_NAME name{};
	name.guid = PropertySetId? *PropertySetId : *propsetIds[DistinguishedPropertySetId->index()];
	if(PropertyName) {
		name.kind = MNID_STRING;
		name.pname = const_cast<char*>(PropertyName->c_str());
	} else if(PropertyId) {
		name.kind = MNID_ID;
		name.lid = *PropertyId;
	} else
		return NONAME;
	return name;
}

/**
 * @brief      Write tag information to shape
 *
 * @param      shape  Shape to store tag in
 * @param      add    Whether the tag is to be added or removed
 */
void tExtendedFieldURI::tags(sShape& shape, bool add) const
{
	if(PropertyTag)
		shape.add(tag(), add? sShape::FL_EXT : sShape::FL_RM);
	else if((PropertySetId || DistinguishedPropertySetId) && (PropertyName || PropertyId))
		shape.add(name(), type(), add? sShape::FL_EXT : sShape::FL_RM);
	else
		throw InputError(E3061);
}

/**
 * @brief      Get tag type
 *
 * @return     Tag type ID
 */
uint16_t tExtendedFieldURI::type() const
{
	static auto compval = [](const TMEntry& v1, const char* const v2){return strcmp(v1.first, v2) < 0;};
	auto type = std::lower_bound(typeMap.begin(), typeMap.end(), PropertyType.c_str(), compval);
	if(type == typeMap.end() || strcmp(type->first, PropertyType.c_str()))
		throw InputError(E3059(PropertyType));
	return type->second;
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

tExtendedProperty::tExtendedProperty(const TAGGED_PROPVAL& tp, const PROPERTY_NAME& pn) :
	  ExtendedFieldURI(pn.kind == KIND_NONE? tExtendedFieldURI(tp.proptag) : tExtendedFieldURI(PROP_TYPE(tp.proptag), pn)),
	  propval(tp)
{}

/**
 * @brief      Deserialize multi-value property
 *
 * @param      xml     XML values node
 * @param      type    Property type
 * @param      values  Member to write values to
 *
 * @tparam     C     Container type
 * @tparam     T     Value type
 */
template<typename C, typename T>
void tExtendedProperty::deserializeMV(const XMLElement* xml, uint16_t type, T* C::* values)
{
	C* container = static_cast<C*>(propval.pvalue);
	container->count = 0;
	for(const XMLElement* child = xml->FirstChildElement("Value"); child; child = child->NextSiblingElement("Value"))
		++container->count;
	container->*values = EWSContext::alloc<T>(container->count);
	const XMLElement* child = xml->FirstChildElement("Value");
	for(T* value = container->*values; value < container->*values+container->count; ++value) {
		deserialize(child, type&~MV_FLAG, value);
		child = child->NextSiblingElement("Value");
	}
}

/**
 * @brief      Deserialize property
 *
 * @param      xml   XML value node
 * @param      type  Property type
 * @param      dest  Value destination or nullptr to automatically allocate
 */
void tExtendedProperty::deserialize(const XMLElement* xml, uint16_t type, void* dest)
{
	size_t allocSize = typeWidth(type);
	if(!dest)
		propval.pvalue = dest = allocSize? EWSContext::alloc(allocSize) : nullptr;
	const char* content = xml->GetText();
	switch(type) {
	case PT_SHORT:{
		int temp;
		XMLError res = xml->QueryIntText(&temp);
		if(res != XML_SUCCESS || temp & ~0xFFFF)
			throw EWSError::InvalidExtendedPropertyValue(E3101(content? content : "(nil)"));
		*static_cast<uint16_t*>(dest) = uint16_t(temp);
		break;
	}
	case PT_ERROR:
	case PT_LONG:
		if(xml->QueryUnsignedText(static_cast<uint32_t*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3102(content? content : "(nil)"));
		break;
	case PT_FLOAT:
		if(xml->QueryFloatText(static_cast<float*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3103(content? content : "(nil)"));
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		if(xml->QueryDoubleText(static_cast<double*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3104(content? content : "(nil)"));
		break;
	case PT_BOOLEAN:
		if(xml->QueryBoolText(static_cast<bool*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3105(content? content : "(nil)"));
		break;
	case PT_CURRENCY:
	case PT_I8:
		if(xml->QueryUnsigned64Text(static_cast<uint64_t*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3106(content? content : "(nil)"));
		break;
	case PT_SYSTIME:
		*static_cast<uint64_t*>(dest) = sTimePoint(xml->GetText()).toNT(); break;
	case PT_STRING8:
	case PT_UNICODE: {
		size_t len = xml->GetText()? strlen(xml->GetText()) : 0;
		if(!dest)
			propval.pvalue = dest = EWSContext::alloc(len+1);
		else
			dest = *static_cast<char**>(dest) = EWSContext::alloc<char>(len+1);
		memcpy(static_cast<char*>(dest), len? xml->GetText() : "", len+1);
		break;
	}
	case PT_MV_SHORT:
		deserializeMV(xml, type, &SHORT_ARRAY::ps); break;
	case PT_MV_LONG:
		deserializeMV(xml, type, &LONG_ARRAY::pl); break;
	case PT_MV_FLOAT:
		deserializeMV(xml, type, &FLOAT_ARRAY::mval); break;
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
		deserializeMV(xml, type, &DOUBLE_ARRAY::mval); break;
	case PT_MV_I8:
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
		deserializeMV(xml, type, &LONGLONG_ARRAY::pll); break;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		deserializeMV(xml, type, &STRING_ARRAY::ppstr); break;
	default:
		throw NotImplementedError(E3107(tExtendedFieldURI::typeName(type)));
	}
}

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
			serialize(*val, type&~MV_FLAG, xml->InsertNewChildElement("t:Value"));
		else
			serialize(val, type&~MV_FLAG, xml->InsertNewChildElement("t:Value"));
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
		return xml->SetText(bool(*(reinterpret_cast<const uint8_t*>(data))));
	case PT_SHORT:
		return xml->SetText(*(reinterpret_cast<const uint16_t*>(data)));
	case PT_LONG:
	case PT_ERROR:
		return xml->SetText(*(reinterpret_cast<const uint32_t*>(data)));
	case PT_I8:
	case PT_CURRENCY:
		return xml->SetText(*(reinterpret_cast<const uint64_t*>(data)));
	case PT_SYSTIME:
		return sTimePoint::fromNT(*reinterpret_cast<const uint64_t*>(data)).serialize(xml);
	case PT_FLOAT:
		return xml->SetText(*(reinterpret_cast<const float*>(data)));
	case PT_DOUBLE:
	case PT_APPTIME:
		return xml->SetText(*(reinterpret_cast<const double*>(data)));
	case PT_STRING8:
	case PT_UNICODE:
		return xml->SetText((reinterpret_cast<const char*>(data)));
	case PT_BINARY:
		return xml->SetText(sBase64Binary(static_cast<const BINARY*>(data)).serialize().c_str());
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
	{"item:InternetMessageHeaders", PR_TRANSPORT_MESSAGE_HEADERS},
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
	// {"calendar:DeletedOccurrences", },
	// {"calendar:EndTimeZone", },
	{"calendar:IsResponseRequested", PR_RESPONSE_REQUESTED},
	// {"calendar:ModifiedOccurrences", },
	{"calendar:Organizer", PR_SENDER_ADDRTYPE},
	{"calendar:Organizer", PR_SENDER_EMAIL_ADDRESS},
	{"calendar:Organizer", PR_SENDER_NAME},
	// {"calendar:OriginalStart", },
	// {"calendar:StartTimeZone", },
};

decltype(tFieldURI::nameMap) tFieldURI::nameMap = {
	{"calendar:AllowNewTimeProposal", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentNotAllowPropose, const_cast<char*>("AppointmentSubType")}, PT_BOOLEAN}},
	{"calendar:AppointmentReplyTime", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentReplyTime, const_cast<char*>("AppointmentReplyTime")}, PT_SYSTIME}},
	{"calendar:AppointmentState", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStateFlags, const_cast<char*>("AppointmentStateFlags")}, PT_LONG}},
	{"calendar:AppointmentSequenceNumber", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSequence, const_cast<char*>("AppointmentSequence")}, PT_LONG}},
	{"calendar:End", {{MNID_ID, PSETID_COMMON, PidLidCommonEnd, const_cast<char*>("CommonEnd")}, PT_SYSTIME}},
	{"calendar:IsAllDayEvent", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSubType, const_cast<char*>("AppointmentSubType")}, PT_BOOLEAN}},
	{"calendar:IsCancelled", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStateFlags, const_cast<char*>("AppointmentStateFlags")}, PT_LONG}},
	{"calendar:IsMeeting", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStateFlags, const_cast<char*>("AppointmentStateFlags")}, PT_LONG}},
	{"calendar:IsRecurring", {{MNID_ID, PSETID_APPOINTMENT, PidLidRecurring, const_cast<char*>("Recurring")}, PT_BOOLEAN}},
	{"calendar:LegacyFreeBusyStatus", {{MNID_ID, PSETID_APPOINTMENT, PidLidBusyStatus, const_cast<char*>("BusyStatus")}, PT_LONG}},
	{"calendar:Location", {{MNID_ID, PSETID_APPOINTMENT, PidLidLocation, const_cast<char*>("Location")}, PT_UNICODE}},
	{"calendar:MeetingRequestWasSent", {{MNID_ID, PSETID_APPOINTMENT, PidLidFInvited, const_cast<char*>("FInvited")}, PT_BOOLEAN}},
	{"calendar:MyResponseType", {{MNID_ID, PSETID_APPOINTMENT, PidLidResponseStatus, const_cast<char*>("ResponseStatus")}, PT_LONG}},
	{"calendar:Recurrence", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur, const_cast<char*>("AppointmentRecur")}, PT_BINARY}},
	{"calendar:DeletedOccurrences", {{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur, const_cast<char*>("AppointmentRecur")}, PT_BINARY}},
	{"calendar:Start", {{MNID_ID, PSETID_COMMON, PidLidCommonStart, const_cast<char*>("CommonStart")}, PT_SYSTIME}},
	{"calendar:UID", {{MNID_ID, PSETID_MEETING, PidLidGlobalObjectId, const_cast<char*>("GlobalObjectId")}, PT_BINARY}},
	{"item:Categories", {NtCategories, PT_MV_UNICODE}},
};

decltype(tFieldURI::specialMap) tFieldURI::specialMap = {{
	{"calendar:OptionalAttendees", sShape::OptionalAttendees},
	{"calendar:RequiredAttendees", sShape::RequiredAttendees},
	{"calendar:Resources", sShape::Resources},
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

void tFieldURI::tags(sShape& shape, bool add) const
{
	auto tags = tagMap.equal_range(FieldURI);
	for(auto it = tags.first; it != tags.second; ++it)
		shape.add(it->second, add? sShape::FL_FIELD : sShape::FL_RM);

	auto names = nameMap.equal_range(FieldURI);
	for(auto it = names.first; it != names.second; ++it)
		shape.add(it->second.first, it->second.second, add? sShape::FL_FIELD : sShape::FL_RM);

	static auto compval = [](const SMEntry& v1, const char* const v2){return strcmp(v1.first, v2) < 0;};
	auto specials = std::lower_bound(specialMap.begin(), specialMap.end(), FieldURI.c_str(), compval);
	if(specials != specialMap.end() && specials->first == FieldURI)
		shape.special |= specials->second;
}

///////////////////////////////////////////////////////////////////////////////

tFileAttachment::tFileAttachment(const sAttachmentId& aid, const TPROPVAL_ARRAY& props) : tAttachment(aid, props)
{
	TAGGED_PROPVAL* tp = props.find(PR_ATTACH_DATA_BIN);
	if(tp) {
		Content.emplace(*tp);
		Size = Content->size();
	}
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collect property tags and names for folder shape

 * @param     shape   Shape to store tags in
 */
void tFolderResponseShape::tags(sShape& shape) const
{
	for(uint32_t tag : tagsStructural)
		shape.add(tag);
	size_t baseShape = BaseShape.index();
	for(uint32_t tag : tagsIdOnly)
		shape.add(tag, sShape::FL_FIELD);
	if(baseShape >= 1)
		for(uint32_t tag : tagsDefault)
			shape.add(tag, sShape::FL_FIELD);
	if(AdditionalProperties)
		for(const auto& additional : *AdditionalProperties)
			additional.tags(shape);
}

///////////////////////////////////////////////////////////////////////////////

tFolderType::tFolderType(const sShape& shape) : tBaseFolderType(shape)
{fromProp(shape.get(PR_CONTENT_UNREAD), UnreadCount);}

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
void tIndexedFieldURI::tags(sShape&, bool) const
{}


///////////////////////////////////////////////////////////////////////////////

tInternetMessageHeader::tInternetMessageHeader(const std::string_view& hn, const std::string_view& c) :
	HeaderName(hn),
	content(c)
{}

/**
 * @brief      Parse internet message headers
 *
 * @param      content   Content to parse
 *
 * @return List of header objects
 */
std::vector<tInternetMessageHeader> tInternetMessageHeader::parse(std::string_view content)
{
	std::vector<tInternetMessageHeader> result;
	if(content.empty())
		return result;
	for(size_t from = 0, to; from != content.npos; from = to == content.npos? to : to+1) {
		to = content.find('\n', from);
		std::string_view line = content.substr(from, to-from);
		if(line.empty() || (std::isspace(line[0]) && content.empty()))
			continue;
		size_t sep;
		if(std::isspace(line[0]))
			result.back().content.append(" ").append(trim(line));
		else if((sep = line.find(':')) == std::string_view::npos)
			continue;
		else
			result.emplace_back(line.substr(0, sep), trim(line.substr(sep+1)));
	}
	return result;
}

///////////////////////////////////////////////////////////////////////////////

tItem::tItem(const sShape& shape)
{
	const uint32_t* v32;
	const TAGGED_PROPVAL* prop;
	fromProp(shape.get(PR_ASSOCIATED), IsAssociated);
	const TAGGED_PROPVAL *bodyText = shape.get(PR_BODY), *bodyHtml = shape.get(PR_HTML);
	if(bodyHtml) {
		const BINARY* content = reinterpret_cast<const BINARY*>(bodyHtml->pvalue);
		Body.emplace(std::string_view(content->pc, content->cb), Enum::HTML);
	}
	else if(bodyText)
		Body.emplace(reinterpret_cast<const char*>(bodyText->pvalue), Enum::Text);

	if((prop = shape.get(PR_CHANGE_KEY)))
		fromProp(prop, defaulted(ItemId).ChangeKey);
	fromProp(shape.get(PR_CLIENT_SUBMIT_TIME), DateTimeSent);
	if((prop = shape.get(PR_CONVERSATION_ID)))
		fromProp(prop, defaulted(ConversationId).Id);
	fromProp(shape.get(PR_CREATION_TIME), DateTimeCreated);
	fromProp(shape.get(PR_DISPLAY_BCC), DisplayBcc);
	fromProp(shape.get(PR_DISPLAY_CC), DisplayCc);
	fromProp(shape.get(PR_DISPLAY_TO),DisplayTo);
	if((prop = shape.get(PR_ENTRYID)))
		fromProp(prop, defaulted(ItemId).Id);
	fromProp(shape.get(PR_HASATTACH), HasAttachments);
	if((v32 = shape.get<uint32_t>(PR_IMPORTANCE)))
		Importance = *v32 == IMPORTANCE_LOW? Enum::Low : *v32 == IMPORTANCE_HIGH? Enum::High : Enum::Normal;
	fromProp(shape.get(PR_IN_REPLY_TO_ID), InReplyTo);
	fromProp(shape.get(PR_LAST_MODIFIER_NAME), LastModifiedName);
	fromProp(shape.get(PR_LAST_MODIFICATION_TIME), LastModifiedTime);
	fromProp(shape.get(PR_MESSAGE_CLASS), ItemClass);
	fromProp(shape.get(PR_MESSAGE_DELIVERY_TIME), DateTimeReceived);
	if((v32 = shape.get<uint32_t>(PR_MESSAGE_FLAGS))) {
		IsSubmitted = *v32 & MSGFLAG_SUBMITTED;
		IsDraft = *v32 & MSGFLAG_UNSENT;
		IsFromMe = *v32 & MSGFLAG_FROMME;
		IsResend = *v32 & MSGFLAG_RESEND;
		IsUnmodified = *v32 & MSGFLAG_UNMODIFIED;
	}
	fromProp(shape.get(PR_MESSAGE_SIZE), Size);
	if((prop = shape.get(PR_PARENT_ENTRYID)))
		fromProp(prop, defaulted(ParentFolderId).Id);
	if((v32 = shape.get<uint32_t>(PR_SENSITIVITY)))
		Sensitivity = *v32 == SENSITIVITY_PRIVATE? Enum::Private :
		              *v32 == SENSITIVITY_COMPANY_CONFIDENTIAL? Enum::Confidential :
		              *v32 == SENSITIVITY_PERSONAL? Enum::Personal : Enum::Normal;
	fromProp(shape.get(PR_SUBJECT), Subject);
	if((prop = shape.get(PR_TRANSPORT_MESSAGE_HEADERS)))
		InternetMessageHeaders.emplace(tInternetMessageHeader::parse(static_cast<const char*>(prop->pvalue)));
	if((prop = shape.get(NtCategories)) && PROP_TYPE(prop->proptag) == PT_MV_UNICODE) {
		const STRING_ARRAY* categories = static_cast<const STRING_ARRAY*>(prop->pvalue);
		Categories.emplace(categories->count);
		char** src = categories->ppstr;
		for(std::string& dest : *Categories)
			dest = *src++;
	}
	shape.putExtended(ExtendedProperty);
};

sItem tItem::create(const sShape& shape)
{
	const char* itemClass = shape.get<char>(PR_MESSAGE_CLASS, sShape::FL_ANY);
	if(!itemClass)
		return tItem(shape);
	if(!strcasecmp(itemClass, "IPM.Note"))
		return tMessage(shape);
	else if(!strcasecmp(itemClass, "IPM.Appointment"))
		return tCalendarItem(shape);
	else if(!strcasecmp(itemClass, "IPM.Contact"))
		return tContact(shape);
	return tItem(shape);
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collect property tags and names for folder shape

 * @param     shape   Shape to store tags in
 */
void tItemResponseShape::tags(sShape& shape) const
{

	for(uint32_t tag : tagsStructural)
		shape.add(tag);
	for(uint32_t tag : tagsIdOnly)
		shape.add(tag, sShape::FL_FIELD);
	if(IncludeMimeContent && *IncludeMimeContent)
		shape.special |= sShape::MimeContent;
	if(AdditionalProperties)
		for(const auto& additional : *AdditionalProperties)
			additional.tags(shape);
	if(shape.special & sShape::Body)
	{
		std::string_view type = BodyType? *BodyType : Enum::Best;
		if(type == Enum::Best || type == Enum::Text)
			shape.add(PR_BODY, sShape::FL_FIELD);
		if(type == Enum::Best || type == Enum::HTML)
			shape.add(PR_HTML, sShape::FL_FIELD);
		shape.special &= ~sShape::Body;
	}
	if(shape.special & sShape::MessageFlags)
	{
		shape.add(PR_MESSAGE_FLAGS, sShape::FL_FIELD);
		shape.special &= ~sShape::MessageFlags;
	}
}

///////////////////////////////////////////////////////////////////////////////

tMessage::tMessage(const sShape& shape) : tItem(shape)
{
	const TAGGED_PROPVAL* prop;
	fromProp(shape.get(PR_CONVERSATION_INDEX), ConversationIndex);
	fromProp(shape.get(PR_CONVERSATION_TOPIC), ConversationTopic);
	fromProp(shape.get(PR_INTERNET_MESSAGE_ID), InternetMessageId);
	fromProp(shape.get(PR_INTERNET_REFERENCES), References);
	fromProp(shape.get(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED), IsDeliveryReceiptRequested);
	if((prop = shape.get(PR_RCVD_REPRESENTING_ADDRTYPE)))
		fromProp(prop, defaulted(ReceivedRepresenting).Mailbox.RoutingType);
	if((prop = shape.get(PR_RCVD_REPRESENTING_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(ReceivedRepresenting).Mailbox.EmailAddress);
	if((prop = shape.get(PR_RCVD_REPRESENTING_NAME)))
		fromProp(prop, defaulted(ReceivedRepresenting).Mailbox.Name);
	fromProp(shape.get(PR_READ), IsRead);
	fromProp(shape.get(PR_READ_RECEIPT_REQUESTED), IsReadReceiptRequested);
	if((prop = shape.get(PR_RECEIVED_BY_ADDRTYPE)))
		fromProp(prop, defaulted(ReceivedBy).Mailbox.RoutingType);
	if((prop = shape.get(PR_RECEIVED_BY_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(ReceivedBy).Mailbox.EmailAddress);
	if((prop = shape.get(PR_RECEIVED_BY_NAME)))
		fromProp(prop, defaulted(ReceivedBy).Mailbox.Name);
	if((prop = shape.get(PR_SENDER_ADDRTYPE)))
		fromProp(prop, defaulted(Sender).Mailbox.RoutingType);
	if((prop = shape.get(PR_SENDER_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(Sender).Mailbox.EmailAddress);
	if((prop = shape.get(PR_SENDER_NAME)))
		fromProp(prop, defaulted(Sender).Mailbox.Name);
	if((prop = shape.get(PR_SENT_REPRESENTING_ADDRTYPE)))
		fromProp(prop, defaulted(From).Mailbox.RoutingType);
	if((prop = shape.get(PR_SENT_REPRESENTING_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(From).Mailbox.EmailAddress);
	if((prop = shape.get(PR_SENT_REPRESENTING_NAME)))
		fromProp(prop, defaulted(From).Mailbox.Name);
}

///////////////////////////////////////////////////////////////////////////////

tMovedCopiedEvent::tMovedCopiedEvent(const sTimePoint& ts, std::variant<tFolderId, tItemId>&& oid, tFolderId&& fid,
                                     std::variant<aOldFolderId, aOldItemId>&& ooid, tFolderId&& ofid) :
    tBaseObjectChangedEvent(ts, std::move(oid), std::move(fid)),
    oldObjectId(std::move(ooid)),
    OldParentFolderId(std::move(ofid))
{}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Collect property tags and names for path specification

 * @param     shape   Shape to write tags to
 */
void tPath::tags(sShape& shape, bool add) const
{return std::visit([&](auto&& v){return v.tags(shape, add);}, asVariant());};

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

/**
 * @brief      Write property to shape
 *
 * @param      shape  Shape to write property to
 */
void tSetFolderField::put(sShape& shape) const
{
	const XMLElement* child = folder->FirstChildElement();
	if(!child)
		throw EWSError::InvalidExtendedPropertyValue(E3178);
	if(!strcmp(child->Name(), "ExtendedProperty")) {
		tExtendedProperty prop(child);
		if(prop.ExtendedFieldURI.tag())
			shape.write(prop.propval);
		else
			shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	}
	else
		convProp(folder->Name(), child->Name(), child, shape);
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Write property to shape
 *
 * @param      shape  Shape to write property to
 */
void tSetItemField::put(sShape& shape) const
{
	const XMLElement* child = item->FirstChildElement();
	if(!child)
		throw EWSError::InvalidExtendedPropertyValue(E3108);
	if(!strcmp(child->Name(), "ExtendedProperty")) {
		tExtendedProperty prop(child);
		if(prop.ExtendedFieldURI.tag())
			shape.write(prop.propval);
		else
			shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	}
	else
		convProp(item->Name(), child->Name(), child, shape);
}

///////////////////////////////////////////////////////////////////////////////

std::atomic<uint32_t> tSubscriptionId::globcnt = 0;

/**
 * @brief      Constructor for single subscription ID
 *
 * @param      t   Subscription timeout (minutes)
 */
tSubscriptionId::tSubscriptionId(uint32_t t) : ID(++globcnt), timeout(t)
{}

/**
 * @brief      Constructor for single subscription ID
 *
 * @param      ID  Subscription key
 * @param      t   Subscription timeout (minutes)
 */
tSubscriptionId::tSubscriptionId(uint32_t id, uint32_t t) : ID(++globcnt), timeout(t)
{}

///////////////////////////////////////////////////////////////////////////////


tSyncFolderHierarchyCU::tSyncFolderHierarchyCU(sFolder &&f) : folder(std::move(f))
{}

///////////////////////////////////////////////////////////////////////////////

tTargetFolderIdType::tTargetFolderIdType(sFolderId&& id) :
    folderId(std::move(id))
{}

///////////////////////////////////////////////////////////////////////////////

mFreeBusyResponse::mFreeBusyResponse(tFreeBusyView&& fbv) : FreeBusyView(std::move(fbv))
{}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Initialize response message
 *
 * @param      rclass  Response class, either "Success", "Error" or "Warning"
 * @param      rcode   EWS Error code
 * @param      mt      Error message text
 */
mResponseMessageType::mResponseMessageType(const std::string& rclass,
    const std::optional<std::string> &rcode, const std::optional<std::string> &mt) :
	ResponseClass(rclass), MessageText(mt), ResponseCode(rcode)
{}

/**
 * @brief      Convert EWSError to response message
 *
 * @param      err   Original EWS error
 */
mResponseMessageType::mResponseMessageType(const EWSError& err) :
	ResponseClass("Error"),
	MessageText(err.what()),
	ResponseCode(err.type)
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

/**
 * @brief      Set response message to error state
 *
 * @param      rcode   EWS Error code
 * @param      mt      Error message text
 *
 * @return     *this
 */
mResponseMessageType& mResponseMessageType::error(const std::string& rcode, const std::string& mt)
{
	ResponseClass = "Error";
	MessageText = mt;
	ResponseCode = rcode;
	return *this;
}
