// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2024 grommunio GmbH
// This file is part of Gromox.
/**
 * @brief      Implementation of EWS structure methods
 *
 * This file only contains data type logic, the implementation
 * of (de-)serialization functions was moved to serialization.cpp.
 */
#include <algorithm>
#include <ctime>
#include <iterator>
#include <set>
#include <utility>
#include <libHX/ctype_helper.h>
#include <vmime/header.hpp>
#include <vmime/text.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/freebusy.hpp>
#include <gromox/ical.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include "ews.hpp"
#include "structures.hpp"
#include "namedtags.hpp"

using namespace gromox::EWS;
using namespace gromox::EWS::Exceptions;
using namespace gromox::EWS::Structures;
using namespace std::string_literals;
using namespace tinyxml2;

namespace {

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

static constexpr uint32_t U_DEFAULT = 0, U_ANON = 0xffffffff;

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
{
	return container ? *container : container.emplace(std::forward<Args...>(args)...);
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
void fromProp(const TAGGED_PROPVAL* prop, std::optional<T>& target)
{
	if (!prop)
		return;
	if constexpr (std::is_pointer_v<PT>)
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
	if (!prop)
		return;
	if constexpr (std::is_pointer_v<PT>)
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
	if (prop)
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
{
	return std::numeric_limits<count_t<C>>::max();
}

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
	if (data.size() > max_count<C>())
		throw DispatchError(E3099);
	return C{count_t<C>(data.size()), deconst(data.data())};
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
 * PatternTypeSpecific Week/MonthNth
 * X  (1 bit): This bit is not used. MUST be zero and MUST be ignored.
 * Sa (1 bit): (0x00000040) The event occurs on Saturday.
 * F  (1 bit): (0x00000020) The event occurs on Friday.
 * Th (1 bit): (0x00000010) The event occurs on Thursday.
 * W  (1 bit): (0x00000008) The event occurs on Wednesday.
 * Tu (1 bit): (0x00000004) The event occurs on Tuesday.
 * M  (1 bit): (0x00000002) The event occurs on Monday.
 * Su (1 bit): (0x00000001) The event occurs on Sunday.
 * unused (3 bytes): These bits are not used. MUST be zero and MUST be ignored.
 * Nth Day of month: (bits M, Tu, W, Th, F, SA, Su are set) - only rptMonthNth
 * Nth Weekday of month: (bits M, Tu, W, Th, F are set) - only rptMonthNth
 * Nth Weekend of month: (bits Sa, Su are set) - only rptMonthNth
 */
void daysofweek_to_str(const uint32_t& weekrecur, std::string& daysofweek)
{
	switch(weekrecur) {
	case 0x7F:
		daysofweek.append(Enum::Day); return;
	case 0x3E:
		daysofweek.append(Enum::Weekday); return;
	case 0x41:
		daysofweek.append(Enum::WeekendDay); return;
	}
	for (uint8_t wd = 0; wd < 7; ++wd)
		if (weekrecur & (1 << wd))
			daysofweek.append(Enum::DayOfWeekType::Choices[wd]).append(" ");
	// remove trailing space
	if (!daysofweek.empty() && HX_isspace(daysofweek.back()))
		daysofweek.pop_back();
}

/**
 * @brief Get the appointment recurrence pattern structure
 *
 * @param recurData    Recurrence data
 * @return APPOINTMENT_RECUR_PAT Appointment recurrence pattern
 */
APPOINTMENT_RECUR_PAT getAppointmentRecurPattern(const BINARY* recurData)
{
	EXT_PULL ext_pull;
	APPOINTMENT_RECUR_PAT apprecurr;
	ext_pull.init(recurData->pb, recurData->cb, gromox::zalloc, EXT_FLAG_UTF16);
	if (ext_pull.g_apptrecpat(&apprecurr) != pack_result::ok)
		throw InputError(E3109);
	return apprecurr;
}

/**
 * @brief Get the recurrence pattern structure
 *
 * @param recurData    Recurrence data
 * @return RECURRENCE_PATTERN Recurrence pattern
 */
RECURRENCE_PATTERN getRecurPattern(const BINARY* recurData)
{
	EXT_PULL ext_pull;
	RECURRENCE_PATTERN recurr;
	ext_pull.init(recurData->pb, recurData->cb, gromox::zalloc, EXT_FLAG_UTF16);
	if (ext_pull.g_recpat(&recurr) != pack_result::ok)
		throw InputError(E3248);
	return recurr;
}

/**
 * @brief Get the Recurrence Pattern object
 *
 * @param recur_pat    Recurrence pattern
 * @return tRecurrencePattern
 */
tRecurrencePattern get_recurrence_pattern(const RECURRENCE_PATTERN& recur_pat)
{
	ical_time itime;
	std::string daysofweek;
	switch (recur_pat.patterntype) {
	case rptMinute:
		if (recur_pat.slidingflag)
			return tDailyRegeneratingPattern(recur_pat.period / 1440);
		return tDailyRecurrencePattern(recur_pat.period / 1440);
	case rptWeek: {
		daysofweek_to_str(recur_pat.pts.weekrecur, daysofweek);
		if (recur_pat.slidingflag)
			return tWeeklyRegeneratingPattern(recur_pat.period);
		return tWeeklyRecurrencePattern(recur_pat.period, daysofweek,
				Enum::DayOfWeekType(static_cast<uint8_t>(recur_pat.firstdow)));
	}
	case rptMonth:
	case rptMonthEnd:
	case rptHjMonth:
	case rptHjMonthEnd: {
		ical_get_itime_from_yearday(1601,
			recur_pat.firstdatetime / 1440 + 1, &itime);
		if (recur_pat.period % 12 != 0) {
			if (recur_pat.slidingflag)
				return tMonthlyRegeneratingPattern(recur_pat.period);
			return tAbsoluteMonthlyRecurrencePattern(recur_pat.period,
				recur_pat.pts.dayofmonth);
		}
		if (recur_pat.slidingflag)
			return tYearlyRegeneratingPattern(recur_pat.period);
		return tAbsoluteYearlyRecurrencePattern(recur_pat.pts.dayofmonth,
				Enum::MonthNamesType(static_cast<uint8_t>(itime.month - 1)));
	}
	case rptMonthNth:
	case rptHjMonthNth: {
		ical_get_itime_from_yearday(1601,
			recur_pat.firstdatetime / 1440 + 1, &itime);
		daysofweek_to_str(recur_pat.pts.weekrecur, daysofweek);
		Enum::DayOfWeekIndexType dayofweekindex(static_cast<uint8_t>(
			recur_pat.pts.monthnth.recurnum - 1));
		if (recur_pat.period % 12 != 0) {
			if (recur_pat.slidingflag)
				return tMonthlyRegeneratingPattern(recur_pat.period);
			return tRelativeMonthlyRecurrencePattern(recur_pat.period,
					daysofweek, dayofweekindex);
		}
		if (recur_pat.slidingflag)
			return tYearlyRegeneratingPattern(recur_pat.period);
		return tRelativeYearlyRecurrencePattern(daysofweek, dayofweekindex,
				Enum::MonthNamesType(static_cast<uint8_t>(itime.month - 1)));
	}
	default:
		throw InputError(E3110);
	}
}

/**
 * @brief Get the Recurrence Range object
 *
 * @param recur_pat    Recurrence pattern
 * @return tRecurrenceRange
 */
tRecurrenceRange get_recurrence_range(const RECURRENCE_PATTERN& recur_pat)
{
	auto startdate = rop_util_rtime_to_unix2(recur_pat.startdate);
	switch (recur_pat.endtype) {
	case IDC_RCEV_PAT_ERB_AFTERNOCCUR:
		return tNumberedRecurrenceRange(startdate, recur_pat.occurrencecount);
	case IDC_RCEV_PAT_ERB_END:
		return tEndDateRecurrenceRange(startdate,
			rop_util_rtime_to_unix2(recur_pat.enddate));
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
	for (size_t i = 0; i < apprecurr.recur_pat.deletedinstancecount; ++i) {
		if (mod_insts.find(apprecurr.recur_pat.pdeletedinstancedates[i]) != mod_insts.end()) {
			modOccs.emplace_back(tOccurrenceInfoType({
				sOccurrenceId(*entryid, apprecurr.pexceptioninfo[i-del_count].originalstartdate),
				rop_util_rtime_to_unix2(apprecurr.pexceptioninfo[i-del_count].startdatetime),
				rop_util_rtime_to_unix2(apprecurr.pexceptioninfo[i-del_count].enddatetime),
				rop_util_rtime_to_unix2(apprecurr.pexceptioninfo[i-del_count].originalstartdate)}));
		} else {
			del_count++;
			delOccs.emplace_back(tDeletedOccurrenceInfoType{rop_util_rtime_to_unix2(
				apprecurr.recur_pat.pdeletedinstancedates[i] + apprecurr.starttimeoffset)});
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
sBase64Binary::sBase64Binary(const BINARY *bin) : std::string(*bin)
{}

/**
 * @brief     Initilize binary data from tagged propval
 *
 * Propval type must be PT_BINARY.
 */
sBase64Binary::sBase64Binary(const TAGGED_PROPVAL& tp)
{
	if (PROP_TYPE(tp.proptag) != PT_BINARY)
		throw DispatchError(E3049);
	assign(*static_cast<const BINARY *>(tp.pvalue));
}

/**
 * @brief     Create from (binary) string
 *
 * Does not decode the input but copies it directly.
 *
 * @param    data   Binary data to copy
 */
sBase64Binary::sBase64Binary(std::string &&data) : std::string(std::move(data))
{}

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
	if (size > std::numeric_limits<uint32_t>::max())
		throw EWSError::InvalidAttachmentId(E3081);
	ext_pull.init(data, size, EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this), E3146, "ErrorInvalidAttachmentId");
	TRY(ext_pull.g_uint32(&attachment_num), E3147,"ErrorInvalidAttachmentId");
}

/**
 * @brief      Create occurrence ID from message entry ID property and basedate
 */
sOccurrenceId::sOccurrenceId(const TAGGED_PROPVAL& tp, uint32_t bd) : sMessageEntryId(tp), basedate(bd)
{}

/**
 * @brief      Load occurrence id from binary data
 */
sOccurrenceId::sOccurrenceId(const void* data, uint64_t size)
{
	EXT_PULL ext_pull;
	if (size > std::numeric_limits<uint32_t>::max())
		throw EWSError::InvalidOccurrenceId(E3205);
	ext_pull.init(data, size, EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this), E3206, "ErrorInvalidOccurrenceId");
	TRY(ext_pull.g_uint32(&basedate), E3207, "ErrorInvalidOccurrenceId");
}

/**
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
sFolderEntryId::sFolderEntryId(const void* data, uint64_t size)
{
	init(data, size);
}

/**
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
void sFolderEntryId::init(const void* data, uint64_t size)
{
	EXT_PULL ext_pull;
	if (size > std::numeric_limits<uint32_t>::max() || (data == nullptr && size > 0))
		throw EWSError::InvalidFolderId(E3050);
	if (data == nullptr)
		return;
	ext_pull.init(data, size, EWSContext::alloc, 0);
	TRY(ext_pull.g_folder_eid(this), E3148, "ErrorInvalidFolderId");
}

/**
 * @brief     Retrieve account ID from entry ID
 *
 * @return    User or domain ID (depending on isPrivate())
 */
uint32_t sFolderEntryId::accountId() const
{
	return folder_dbguid.time_low;
}

/**
 * @brief     Retrieve folder ID from entryID
 *
 * @return    Folder ID
 */
uint64_t sFolderEntryId::folderId() const
{
	return rop_util_gc_to_value(folder_gc);
}

/**
 * @brief     Retrieve folder type
 *
 * @return    true if folder is private, false otherwise
 */
bool sFolderEntryId::isPrivate() const
{
	return eid_type == EITLT_PRIVATE_FOLDER;
}

/**
 * @brief     Parse entry ID from binary data
 *
 * @param     data     Buffer containing the entry ID
 * @param     size     Size of the buffer
 */
sMessageEntryId::sMessageEntryId(const void* data, uint64_t size)
{
	init(data, size);
}

/**
 * @brief      Create message entry ID from property
 */
sMessageEntryId::sMessageEntryId(const TAGGED_PROPVAL& tp)
{
	if (PROP_TYPE(tp.proptag) != PT_BINARY)
		throw DispatchError(E3082);
	const BINARY* bin = static_cast<const BINARY*>(tp.pvalue);
	if (bin != nullptr)
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
	if (size > std::numeric_limits<uint32_t>::max() || (data == nullptr && size > 0))
		throw EWSError::InvalidId(E3050);
	if (data == nullptr)
		return;
	ext_pull.init(data, size, EWSContext::alloc, 0);
	TRY(ext_pull.g_msg_eid(this), E3149, "ErrorInvalidId");
}

/**
 * @brief     Retrieve account ID from entry ID
 *
 * @return    User or domain ID (depending on isPrivate())
 */
uint32_t sMessageEntryId::accountId() const
{
	return folder_dbguid.time_low;
}

/**
 * @brief     Retrieve parent folder ID from entryID
 *
 * @return    folder ID
 */
uint64_t sMessageEntryId::folderId() const
{
	return rop_util_gc_to_value(folder_gc);
}

/**
 * @brief     Retrieve message ID from entryID
 *
 * @return    message ID
 */
eid_t sMessageEntryId::messageId() const
{
	return rop_util_make_eid_ex(1, rop_util_gc_to_value(message_gc));
}

/**
 * @brief      Set message ID parrt of the entry ID
 *
 * @param      mid   Message ID
 *
 * @return     *this
 */
sMessageEntryId& sMessageEntryId::messageId(eid_t mid)
{
	message_gc = rop_util_get_gc_array(mid);
	return *this;
}

/**
 * @brief     Retrieve message type
 *
 * @return    true if message is private, false otherwise
 */
bool sMessageEntryId::isPrivate() const
{
	return eid_type == EITLT_PRIVATE_MESSAGE;
}

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
	if (it == distNameInfo.end())
		throw EWSError::FolderNotFound(E3051(folder.Id));
	folderId = rop_util_make_eid_ex(1, it->id);
	location = it->isPrivate ? PRIVATE : PUBLIC;
	if (folder.Mailbox)
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
{
	return rop_util_get_gc_value(folderId) < CUSTOM_EID_BEGIN;
}

/**
 * @brief     Trim target specification according to location
 */
sFolderSpec& sFolderSpec::normalize()
{
	if (location != PUBLIC || !target)
		return *this;
	size_t at = target->find('@');
	if (at == std::string::npos)
		return *this;
	target->erase(0, at + 1);
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
{
	shape.tags(*this);
}

/**
 * @brief      Initialize shape from item shape
 *
 * @param      shape  Requested shape
 */
sShape::sShape(const tItemResponseShape& shape)
{
	shape.tags(*this);
}

/**
 * @brief      Initialize shape from changes list
 *
 * @param      changes  List of folder changes
 */
sShape::sShape(const tFolderChange& changes)
{
	for (const auto &change : changes.Updates) {
		if (std::holds_alternative<tSetFolderField>(change))
			std::get<tSetFolderField>(change).fieldURI.tags(*this);
		else if (std::holds_alternative<tDeleteFolderField>(change))
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
	for (const auto &change : changes.Updates) {
		if (std::holds_alternative<tSetItemField>(change))
			std::get<tSetItemField>(change).fieldURI.tags(*this);
		else if (std::holds_alternative<tDeleteItemField>(change))
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
	for (const auto &prop : tp)
		props.emplace(prop.proptag, PropInfo(FL_FIELD, &prop));
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
	if (it == props.end()) {
		if (flags & FL_RM)
			dTags.emplace_back(tag);
		else
			tags.emplace_back(tag);
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
{
	return mkArray<PROPTAG_ARRAY>(dTags);
}

/**
 * @brief      Whether the tag was originally requested
 *
 * @param      tag    Tag to check
 * @param      mask   Flag mask
 *
 * @return     True if the property was requested, false otherwise
 */
bool sShape::requested(uint32_t tag, uint8_t mask) const
{
	auto it = props.find(tag);
	return it != props.end() && (mask == FL_ANY || it->second.flags & mask);
}

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
	if (it == wProps.end())
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
	if (it == names.end()) {
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
{
	return mkArray<TPROPVAL_ARRAY>(wProps);
}

/**
 * @brief      Get property that is about to be written
 *
 * @param      tag  Tag of the property
 *
 * @return     Property or nullptr if not present
 */
const TAGGED_PROPVAL* sShape::writes(uint32_t tag) const
{
	auto it = std::find_if(wProps.begin(), wProps.end(), [=](const TAGGED_PROPVAL& tp){return tp.proptag == tag;});
	return it != wProps.end() ? &*it : nullptr;
}

/**
 * @brief      Get property that is about to be written
 *
 * @param      tag  Tag of the property
 *
 * @return     Property or nullptr if not present
 */
const TAGGED_PROPVAL* sShape::writes(const PROPERTY_NAME& name) const
{
	auto it = std::find_if(names.begin(), names.end(), [&](const PROPERTY_NAME& n){return n == name;});
	if (it == names.end())
		return nullptr;
	size_t index = std::distance(names.begin(), it);
	if (namedCache.size() == names.size())
		/* Named property IDs have not yet been retrieved */
		return &namedCache[index];
	if (namedTags.size() == names.size())
		/* Named property IDS vae been retrieved */
		return writes(namedTags[index]);
	return nullptr;
}



/**
 * @brief      Reset all properties to unloaded
 */
void sShape::clean()
{
	for (auto &entry : props)
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
	if (it == props.end() || (mask != FL_ANY && !(it->second.flags & mask)))
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
	if (it == names.end())
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
	return prop ? static_cast<const T *>(prop->pvalue) : nullptr;
}

/**
 * @brief      Get property data
 *
 * @param      name  Property name
 * @param      mask  Mask of flags or FL_ANY
 *
 * @tparam     T     Property value type
 *
 * @return     Pointer to property value or nullptr if not found
 */
template<typename T> const T* sShape::get(const PROPERTY_NAME& name, uint8_t mask) const
{
	auto it = std::find(names.begin(), names.end(), name);
	if (it == names.end())
		return nullptr;
	auto index = std::distance(names.begin(), it);
	return get<T>(namedTags[index], mask);
}

/**
 * @brief      Wrap requested property names
 *
 * @return     The propname array
 */
PROPNAME_ARRAY sShape::namedProperties() const
{
	return PROPNAME_ARRAY{static_cast<uint16_t>(names.size()), deconst(names.data())};
}

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
	if (ids.size() != names.size()) // Abort if sizes do not match
		return false;
	size_t namedAdd = 0, namedRm = 0;
	for (uint32_t tag : namedTags) {//Remove all named tags
		auto it = props.find(tag);
		if (it == props.end())
			continue;
		if (it->second.flags & FL_RM)
			++namedRm;
		else
			++namedAdd;
		props.erase(it);
	}
	if (tags.size() >= namedAdd)
		tags.resize(tags.size()-namedAdd);
	if (dTags.size() >=namedRm)
		dTags.resize(dTags.size()-namedRm);//Truncate named IDs
	for (size_t index = 0; index < names.size(); ++index) { //Add named IDs
		uint32_t tag = PROP_TAG(PROP_TYPE(namedTags[index]), ids[index]);
		namedTags[index] = tag;
		if (!PROP_ID(tag))
			continue;
		if (nameMeta[index] & FL_RM) {
			dTags.emplace_back(tag);
		} else {
			props.emplace(tag, PropInfo(nameMeta[index], &names[index]));
			tags.emplace_back(tag);
		}
	}
	if (namedCache.size() == namedTags.size()) {
		for (size_t index = 0; index < namedTags.size(); ++index)
			if (namedCache[index].proptag)
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
	for (const auto &prop : properties)
		props[prop.proptag].prop = &prop;
}

/**
 * @brief      Wrap requested property tag IDs
 *
 * @return     Tag ID array
 */
PROPTAG_ARRAY sShape::proptags() const
{
	return PROPTAG_ARRAY{static_cast<uint16_t>(tags.size()), deconst(tags.data())};
}

/**
 * @brief      Store extended properties
 *
 * @param      extprops  Location to store extended properties in
 */
void sShape::putExtended(std::vector<tExtendedProperty>& extprops) const
{
	for (const auto &prop : props)
		if (prop.second.flags & FL_EXT && prop.second.prop)
			extprops.emplace_back(*prop.second.prop,
				prop.second.name ? *prop.second.name : NONAME);
}

/**
 * @brief      Get tag ID from name
 *
 * @param      name  Name to resolve
 *
 * @return     Property tag or 0 if unknown
 */
uint32_t sShape::tag(const PROPERTY_NAME& name) const
{
	auto it = std::find(names.begin(), names.end(), name);
	return it == names.end() ? 0 : namedTags[std::distance(names.begin(), it)];
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Default constructor
 *
 * Initializes given and seen member for deserialization
 */
sSyncState::sSyncState() :
	given(idset::type::id_packed),
	seen(idset::type::id_packed),
	read(idset::type::id_packed),
	seen_fai(idset::type::id_packed)
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
	if (data.size() <= 16)
		return;
	if (data.size() > std::numeric_limits<uint32_t>::max())
		throw EWSError::InvalidSyncStateData(E3052);
	ext_pull.init(data.data(), data.size(), EWSContext::alloc, EXT_FLAG_WCOUNT);
	if (ext_pull.g_tpropval_a(&propvals) != pack_result::ok)
		return;
	for (const auto &pv : propvals) {
		switch (pv.proptag) {
		case MetaTagIdsetGiven1:
			if (!given.deserialize(*static_cast<const BINARY *>(pv.pvalue)))
				throw EWSError::InvalidSyncStateData(E3053);
			break;
		case MetaTagCnsetSeen:
			if (!seen.deserialize(*static_cast<const BINARY *>(pv.pvalue)))
				throw EWSError::InvalidSyncStateData(E3054);
			break;
		case MetaTagCnsetRead:
			if (!read.deserialize(*static_cast<const BINARY *>(pv.pvalue)))
				throw EWSError::InvalidSyncStateData(E3055);
			break;
		case MetaTagCnsetSeenFAI:
			if (!seen_fai.deserialize(*static_cast<const BINARY *>(pv.pvalue)))
				throw EWSError::InvalidSyncStateData(E3056);
			break;
		case MetaTagReadOffset:
			/* PR_READ, but with long type -> number of read states already delivered */
			readOffset = *static_cast<uint32_t *>(pv.pvalue);
			break;
		}
	}
}

/**
 * @brief      Call convert on all idsets
 */
void sSyncState::convert()
{
	if (!given.convert() || !seen.convert() || !read.convert() || !seen_fai.convert())
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
	for (auto pid : deleted_fids)
		given.remove(pid);
	for (auto pid : given_fids)
		if (!given.append(pid))
			throw DispatchError(E3057);
	seen.clear();
	if (lastCn && !seen.append_range(1, 1, rop_util_get_gc_value(lastCn)))
		throw DispatchError(E3058);
}

///////////////////////////////////////////////////////////////////////////////

sTimePoint::sTimePoint(time_point tp) : time(tp)
{}

sTimePoint::sTimePoint(time_point tp, const tSerializableTimeZone& tz) :
    time(tp), offset(tz.offset(tp))
{}

/**
 * @brief     Create time point from date-time string
 *
 * As of 2025-01-27 we have identified 3 different datetime formats sent by
 * the clients.
 * Zulu time (UTC), no DST, no offset:
 * `<t:Start>2024-04-29T19:30:00Z</t:Start>`
 * With the offset information in datetime, additionally a timezone tag:
 * `<t:Start>2024-11-27T13:00:00+01:00</t:Start>`
 * `<t:StartTimeZone Id="W. Europe Standard Time"/>`
 * `<t:EndTimeZone Id="W. Europe Standard Time"/>`
 * Local time with a timezone tag, it's necessary to calculate the offset:
 * `<t:Start>2024-09-25T09:00:00</t:Start>`
 * ```
 * <t:ExtendedProperty>
 *   <t:ExtendedFieldURI PropertyName="CalendarTimeZone" PropertySetId="A7B529B5-4B75-47A7-A24F-20743D6C55CD" PropertyType="String"/>
 *   <t:Value>Europe/Vienna</t:Value>
 * </t:ExtendedProperty>
 * ```
 * `<t:MeetingTimeZone TimeZoneName="W. Europe Standard Time"/>`
 *
 * @throw     DeserializationError   Conversion failed
 *
 * @param     Date-time string
 */
sTimePoint::sTimePoint(const char* dtstr)
{
	if (!dtstr)
		throw EWSError::SchemaValidation(E3150);
	tm t{};
	double seconds = 0;
	int tz_hour = 0, tz_min = 0;
	/* Timezone info is optional, date and time values mandatory */
	if (sscanf(dtstr, "%4d-%02d-%02dT%02d:%02d:%lf%03d:%02d", &t.tm_year,
	    &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &seconds, &tz_hour,
	    &tz_min) < 6)
		throw EWSError::SchemaValidation(E3151);
	t.tm_year -= 1900;
	t.tm_mon -= 1;
	auto timestamp = timegm(&t);
	if (timestamp == static_cast<time_t>(-1))
		throw EWSError::ValueOutOfRange(E3152);
	time = clock::from_time_t(timestamp);
	time += std::chrono::duration_cast<time_point::duration>(std::chrono::duration<double>(seconds));
	offset = std::chrono::minutes(60 * (-tz_hour) + (tz_hour > 0 ? -tz_min : tz_min));
	if (strlen(dtstr) == 19)
		calcOffset = true;
}

/**
 * @brief      Generate time point from NT timestamp
 */
sTimePoint sTimePoint::fromNT(uint64_t timestamp)
{
	return sTimePoint{rop_util_nttime_to_unix2(timestamp)};
}

/**
 * @brief     Convert time point to NT timestamp
 */
uint64_t sTimePoint::toNT() const
{
	return rop_util_unix_to_nttime(time + offset);
}

/**
 * @brief     Whether it's necessary to calculate the offset from timezone
 */
bool sTimePoint::needCalcOffset() const
{
	return calcOffset;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Types implementation

tAlternateIdBase::tAlternateIdBase(Enum::IdFormatType format) : Format(format)
{}

tAlternateId::tAlternateId(Enum::IdFormatType format, std::string id, std::string mailbox) :
	tAlternateIdBase(format),
	Id(std::move(id)),
	Mailbox(std::move(mailbox))
{}

tAttachment::tAttachment(const sAttachmentId& aid, const TPROPVAL_ARRAY& props)
{
	AttachmentId.emplace(aid);
	fromProp(props.find(PR_ATTACH_LONG_FILENAME), Name);
	fromProp(props.find(PR_ATTACH_MIME_TAG), ContentType);
	fromProp(props.find(PR_ATTACH_CONTENT_ID), ContentId);
	fromProp(props.find(PR_ATTACH_SIZE), Size);
	fromProp(props.find(PR_LAST_MODIFICATION_TIME), LastModifiedTime);
	auto flags = props.get<const uint32_t>(PR_ATTACH_FLAGS);
	if (flags != nullptr && *flags & ATT_MHTML_REF)
		IsInline = true;
}

sAttachment tAttachment::create(const sAttachmentId& aid, const TPROPVAL_ARRAY& props)
{
	const TAGGED_PROPVAL* prop = props.find(PR_ATTACH_METHOD);
	if (prop)
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
	if ((prop = shape.get(PR_PARENT_ENTRYID)))
		fromProp(prop, defaulted(ParentFolderId).Id);
	shape.putExtended(ExtendedProperty);
}

sFolder tBaseFolderType::create(const sShape& shape)
{
	enum Type : uint8_t {NORMAL, CALENDAR, TASKS, CONTACTS, SEARCH};
	const char* frClass = shape.get<char>(PR_CONTAINER_CLASS, sShape::FL_ANY);
	const uint32_t* frType = shape.get<uint32_t>(PR_FOLDER_TYPE, sShape::FL_ANY);
	Type folderType = NORMAL;
	if (frType && *frType == FOLDER_SEARCH) {
		folderType = SEARCH;
	} else if (frClass) {
		if (class_match_prefix(frClass, "IPF.Appointment") == 0)
			folderType = CALENDAR;
		else if (class_match_prefix(frClass, "IPF.Contact") == 0)
			folderType = CONTACTS;
		else if (class_match_prefix(frClass, "IPF.Task") == 0)
			folderType = TASKS;
	}
	switch (folderType) {
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

/**
 * @brief      Create item id from binary data
 *
 * When providing the special IdType `ID_GUESS`, attempts to guess the correct
 * id type from the data. If guessing fails, the type is set to `ID_UNKNOWN`.
 *
 * @param      fEntryID
 * @param t
 */
tBaseItemId::tBaseItemId(const sBase64Binary& fEntryID, IdType t) : type(t)
{
	/* Extra byte is appended for encoding during serialization, prevent reallocation */
	Id.reserve(fEntryID.size() + 1);
	Id = fEntryID;
	if (type == ID_GUESS) {
		switch(Id.size()) {
		case 46: // Size of folder entry ids
			type = ID_FOLDER; break;
		case 70: // Size of message entry ids
			type = ID_ITEM; break;
		case 47: // Tagged folder entry id
		case 71: // Tagged message entry id
		case 75: { // Tagged attachment or occurence id
			char temp = Id.back();
			type = temp < 0 || temp > ID_OCCURRENCE ? ID_UNKNOWN : IdType(temp);
			Id.pop_back();
			break;
		}
		default:
			type = ID_UNKNOWN;
		}
	}
}

/**
 * @brief     Generate serialized string
 *
 * @return    String containing the Id including type marker
 */
std::string tBaseItemId::serializeId() const
{
	IdType t = type;
	if (t == ID_UNKNOWN)
		/* try to guess from entry id size, if that fails, someone forgot to mark the correct type */
		t = Id.size() == 46 ? ID_FOLDER :
		    Id.size() == 70 ? ID_ITEM : throw DispatchError(E3212);
	std::string data;
	data.reserve(Id.size()+1);
	data = Id;
	data.append(1, type);
	return data;
}


tBaseObjectChangedEvent::tBaseObjectChangedEvent(const sTimePoint& ts, std::variant<tFolderId, tItemId>&& oid, tFolderId&& fid) :
    TimeStamp(ts), objectId(std::move(oid)), ParentFolderId(std::move(fid))
{}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Default implementation for paging offset
 *
 * @return     Always 0
 */
uint32_t tBasePagingType::offset(uint32_t) const
{
	return 0;
}

/**
 * @brief      Default implementation for paging restriction
 *
 * @return     Always nullptr.
 */
RESTRICTION* tBasePagingType::restriction(const sGetNameId&) const
{
	return nullptr;
}

/**
 * @brief      Default implementation for paging update. Does nothing.
 */
void tBasePagingType::update(tFindResponsePagingAttributes&, uint32_t, uint32_t) const
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
	for (auto event : EventTypes)
		switch(event.index()) {
		case 0: // CopiedEvent
			res |= fnevObjectCopied; break;
		case 1: // CreatedEvent
			res |= fnevObjectCreated; break;
		case 2: // DeletedEvent
			res |= fnevObjectDeleted; break;
		case 3: // ModifiedEvent
			res |= fnevObjectModified; break;
		case 4: // MovedEvent
			res |= fnevObjectMoved; break;
		case 5: // NewMailEvent
			res |= fnevNewMail; break;
		}
	return res;
}

///////////////////////////////////////////////////////////////////////////////
tTask::tTask(const sShape& shape) : tItem(shape)
{
	tTask::update(shape);
}

void tTask::update(const sShape& shape)
{
	tItem::update(shape);
	const TAGGED_PROPVAL* prop;
	fromProp(shape.get(NtTaskActualEffort), ActualWork);
	fromProp(shape.get(NtBilling), BillingInformation);
	if ((prop = shape.get(NtCompanies)) && PROP_TYPE(prop->proptag) == PT_MV_UNICODE) {
		const STRING_ARRAY* companies = static_cast<const STRING_ARRAY*>(prop->pvalue);
		Companies.emplace(companies->count);
		char** src = companies->ppstr;
		for (std::string &dest : *Companies)
			dest = *src++;
	}
	if ((prop = shape.get(NtTaskDateCompleted)))
		CompleteDate.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
	if ((prop = shape.get(NtTaskDueDate)))
		DueDate.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
	if ((prop = shape.get(NtTaskStartDate)))
		StartDate.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
	fromProp(shape.get(NtTaskComplete), IsComplete);
	fromProp(shape.get(NtTaskFRecurring), IsRecurring);
	fromProp(shape.get(NtMileage), Mileage);
	fromProp(shape.get(NtTaskOwner), Owner);
	fromProp(shape.get(NtPercentComplete), PercentComplete);
	if ((prop = shape.get(NtTaskStatus))) {
		const uint32_t* taskStatus = static_cast<const uint32_t*>(prop->pvalue);
		Enum::TaskStatusType statusType = Enum::NotStarted;
		switch (*taskStatus) {
			case tsvInProgress: statusType = Enum::InProgress; break;
			case tsvComplete:   statusType = Enum::Completed; break;
			case tsvWaiting:    statusType = Enum::WaitingOnOthers; break;
			case tsvDeferred:   statusType = Enum::Deferred; break;
		}
		Status.emplace(statusType);
	}
	fromProp(shape.get(NtTaskEstimatedEffort), TotalWork);
	if ((prop = shape.get(NtTaskRecurrence))) {
		const BINARY* recurData = static_cast<BINARY*>(prop->pvalue);
		if (recurData->cb > 0) {
			RECURRENCE_PATTERN recurr = getRecurPattern(recurData);
			auto& rec = Recurrence.emplace();
			rec.TaskRecurrencePattern = get_recurrence_pattern(recurr);
			rec.RecurrenceRange = get_recurrence_range(recurr);
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
tCalendarItem::tCalendarItem(const sShape& shape) : tItem(shape)
{
	tCalendarItem::update(shape);
}

void tCalendarItem::update(const sShape& shape)
{
	tItem::update(shape);
	fromProp(shape.get(PR_RESPONSE_REQUESTED), IsResponseRequested);
	const TAGGED_PROPVAL* prop;
	if ((prop = shape.get(PR_SENDER_ADDRTYPE)))
		fromProp(prop, defaulted(Organizer).Mailbox.RoutingType);
	if ((prop = shape.get(PR_SENDER_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(Organizer).Mailbox.EmailAddress);
	if ((prop = shape.get(PR_SENDER_NAME)))
		fromProp(prop, defaulted(Organizer).Mailbox.Name);

	if ((prop = shape.get(NtAppointmentNotAllowPropose)))
		AllowNewTimeProposal.emplace(!*static_cast<const uint8_t*>(prop->pvalue));

	if ((prop = shape.get(NtAppointmentRecur))) {
		CalendarItemType.emplace(Enum::RecurringMaster);
		const BINARY* recurData = static_cast<BINARY*>(prop->pvalue);
		if (recurData->cb > 0) {
			APPOINTMENT_RECUR_PAT apprecurr = getAppointmentRecurPattern(recurData);

			auto& rec = Recurrence.emplace();
			rec.RecurrencePattern = get_recurrence_pattern(apprecurr.recur_pat);
			rec.RecurrenceRange = get_recurrence_range(apprecurr.recur_pat);

			// The count of the exceptions (modified and deleted occurrences)
			// is summed in deletedinstancecount
			if (apprecurr.recur_pat.deletedinstancecount > 0) {
				std::vector<tOccurrenceInfoType> modOccs;
				std::vector<tDeletedOccurrenceInfoType> delOccs;
				auto entryid_propval = shape.get(PR_ENTRYID);
				process_occurrences(entryid_propval, apprecurr, modOccs, delOccs);
				if (modOccs.size() > 0)
					ModifiedOccurrences.emplace(modOccs);
				if (delOccs.size() > 0)
					DeletedOccurrences.emplace(delOccs);
			}
		}
	} else {
		CalendarItemType.emplace(Enum::Single); // TODO correct type
	}

	if ((prop = shape.get(NtAppointmentReplyTime)))
		AppointmentReplyTime.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));

	fromProp(shape.get(NtAppointmentSequence), AppointmentSequenceNumber);

	if ((prop = shape.get(NtAppointmentStateFlags))) {
		const uint32_t* stateFlags = static_cast<const uint32_t*>(prop->pvalue);
		AppointmentState.emplace(*stateFlags);
		IsMeeting = *stateFlags & asfMeeting ? TRUE : false;
		IsCancelled = *stateFlags & asfCanceled ? TRUE : false;
	} else {
		AppointmentState = 0;
		IsMeeting = false;
		IsCancelled = false;
	}

	fromProp(shape.get(NtAppointmentSubType), IsAllDayEvent);

	if ((prop = shape.get(NtBusyStatus))) {
		const uint32_t* busyStatus = static_cast<const uint32_t*>(prop->pvalue);
		Enum::LegacyFreeBusyType freeBusy = Enum::NoData;
		switch (*busyStatus) {
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

	if ((prop = shape.get(NtResponseStatus))) {
		const uint8_t* responseStatus = static_cast<const uint8_t*>(prop->pvalue);
		Enum::ResponseTypeType responseType = Enum::Unknown;
		switch (*responseStatus) {
			case respOrganized:    responseType = Enum::Organizer; break;
			case respTentative:    responseType = Enum::Tentative; break;
			case respAccepted:     responseType = Enum::Accept; break;
			case respDeclined:     responseType = Enum::Decline; break;
			case respNotResponded: responseType = Enum::NoResponseReceived; break;
		}
		MyResponseType.emplace(responseType);
	} else {
		MyResponseType.emplace(Enum::Unknown);
	}

	if ((prop = shape.get(NtGlobalObjectId))) {
		const BINARY* goid = static_cast<BINARY*>(prop->pvalue);
		if (goid->cb > 0) {
			std::string uid(goid->cb * 2, 0);
			/* s[s.size()]='\0' is allowed >= C++17: */
			encode_hex_binary(goid->pb, goid->cb, uid.data(), static_cast<int>(uid.size() + 1));
			UID.emplace(std::move(uid));
		}
	}

	// TODO: check if we should use some other property for RecurrenceId
	if ((prop = shape.get(NtExceptionReplaceTime)))
		RecurrenceId.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));

	if ((prop = shape.get(PR_CREATION_TIME)))
		fromProp(prop, DateTimeStamp);
	else
		fromProp(shape.get(PR_LOCAL_COMMIT_TIME), DateTimeStamp);
}

/**
 * @brief      Set calendar item's datetime fields from written properties
 *             depending on their values
 *
 * @param      shape   Shape to update with generated fields
 */
void tCalendarItem::setDatetimeFields(sShape& shape)
{
	uint32_t tag;
	int64_t startOffset = 0, endOffset = 0;
	std::optional<uint64_t> startTime = 0, endTime = 0;
	fromProp(shape.writes(NtCommonStart), startTime);
	fromProp(shape.writes(NtCommonEnd), endTime);
	if ((tag = shape.tag(NtCalendarTimeZone))) {
		std::optional<std::string> calTimezone;
		fromProp(shape.writes(NtCalendarTimeZone), calTimezone);
		if (calTimezone.has_value()) {
			auto buf = ianatz_to_tzdef(calTimezone.value().c_str());
			if (buf != nullptr) {
				size_t len = buf->size();
				if (len > std::numeric_limits<uint32_t>::max())
					throw InputError(E3293);
				BINARY *tmp_bin = EWSContext::construct<BINARY>(BINARY{static_cast<uint32_t>(buf->size()),
					{reinterpret_cast<uint8_t*>(const_cast<char*>(buf->data()))}});
				shape.write(NtAppointmentTimeZoneDefinitionStartDisplay,
					TAGGED_PROPVAL{PT_BINARY, tmp_bin});
				shape.write(NtAppointmentTimeZoneDefinitionEndDisplay,
					TAGGED_PROPVAL{PT_BINARY, tmp_bin});
				EXT_PULL ext_pull;
				TZDEF tzdef;
				ext_pull.init(buf->data(), buf->size(), EWSContext::alloc, EXT_FLAG_UTF16);
				if (ext_pull.g_tzdef(&tzdef) != pack_result::ok)
					throw EWSError::InternalServerError(E3294);
				auto& op = shape.offsetProps;
				if ((tag = shape.tag(NtCommonStart)) &&
				    startTime.has_value() &&
				    std::find(op.begin(), op.end(), tag) != op.end())
					offset_from_tz(&tzdef, rop_util_nttime_to_unix(startTime.value()), startOffset);
				if ((tag = shape.tag(NtCommonEnd)) &&
				    endTime.has_value() &&
				    std::find(op.begin(), op.end(), tag) != op.end())
					offset_from_tz(&tzdef, rop_util_nttime_to_unix(endTime.value()), endOffset);
			}
		}
	}

	for (auto &prop : {NtCommonStart, NtCommonEnd}) {
		if ((tag = shape.tag(prop))) {
			switch (prop.lid) {
			case PidLidCommonStart: {
				auto start = EWSContext::construct<uint64_t>(startTime.value() + startOffset * 600000000);
				shape.write(NtCommonStart, TAGGED_PROPVAL{PT_SYSTIME, start});
				shape.write(NtAppointmentStartWhole, TAGGED_PROPVAL{PT_SYSTIME, start});
				shape.write(TAGGED_PROPVAL{PR_START_DATE, start});
				break;
			}
			case PidLidCommonEnd: {
				auto end = EWSContext::construct<uint64_t>(endTime.value() + endOffset * 600000000);
				shape.write(NtCommonEnd, TAGGED_PROPVAL{PT_SYSTIME, end});
				shape.write(NtAppointmentEndWhole, TAGGED_PROPVAL{PT_SYSTIME, end});
				shape.write(TAGGED_PROPVAL{PR_END_DATE, end});
				break;
			}
			}
		}
	}
}


///////////////////////////////////////////////////////////////////////////////

tCalendarEvent::tCalendarEvent(const freebusy_event& fb_event) :
	StartTime(clock::from_time_t(fb_event.start_time)),
	EndTime(clock::from_time_t(fb_event.end_time))
{
	switch (fb_event.busy_status) {
		case olFree:             BusyType = "Free"; break;
		case olTentative:        BusyType = "Tentative"; break;
		case olBusy:             BusyType = "Busy"; break;
		case olOutOfOffice:      BusyType = "OOF"; break;
		case olWorkingElsewhere: BusyType = "WorkingElsewhere"; break;
		default:                 BusyType = "NoData"; break;
	}

	if (!fb_event.has_details)
		return;

	auto &details = CalendarEventDetails.emplace();
	if (fb_event.id != nullptr)
		details.ID = fb_event.id;
	if (fb_event.subject != nullptr)
		details.Subject = fb_event.subject;
	if (fb_event.location != nullptr)
		details.Location = fb_event.location;
	details.IsMeeting     = fb_event.is_meeting;
	details.IsRecurring   = fb_event.is_recurring;
	details.IsException   = fb_event.is_exception;
	details.IsReminderSet = fb_event.is_reminderset;
	details.IsPrivate     = fb_event.is_private;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Cerate restriction to filter by date
 *
 * @param      time      Timestamp to filter by
 * @param      isStart   Whether timestamp marks beginning of the time range
 * @param      getId     Function to retrieve named property IDs
 *
 * @return     Pointer to restriction or nullptr if no condition is set
 */
RESTRICTION* tCalendarView::datefilter(const sTimePoint& time, bool isStart, const sGetNameId& getId)
{
	static const PROPERTY_NAME startName = {MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole, nullptr},
		endName = {MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole, nullptr};
	// Counterintuitive: isStart == true -> check if end of event is after start, invert for isStart == false
	const PROPERTY_NAME &tagName = isStart ? endName : startName;
	RESTRICTION* res = EWSContext::construct<RESTRICTION>();
	res->rt = mapi_rtype::property;
	res->prop = EWSContext::construct<RESTRICTION_PROPERTY>();
	res->prop->relop = isStart ? relop::ge : relop::le;
	res->prop->proptag = res->prop->propval.proptag = PROP_TAG(PT_SYSTIME, getId(tagName));
	res->prop->propval.pvalue = EWSContext::construct<uint64_t>(time.toNT());
	return res;
}

/**
 * @brief      Generate restriction to filter by event time
 *
 * New restriction is stack allocated and must not be freed manually.
 *
 * @return     Pointer to restriction or nullptr if no condition is set
 */
RESTRICTION* tCalendarView::restriction(const sGetNameId& getId) const
{
	auto startRes = StartDate ? datefilter(*StartDate, true, getId) : nullptr;
	auto endRes = EndDate ? datefilter(*EndDate, false, getId) : nullptr;
	return tRestriction::all(startRes, endRes);
}

///////////////////////////////////////////////////////////////////////////////

tFreeBusyView::tFreeBusyView(const char *username, const char *dir,
    time_t start_time, time_t end_time)
{
	std::vector<freebusy_event> fb_data;
	if (!get_freebusy(username, dir, start_time, end_time, fb_data))
		throw EWSError::FreeBusyGenerationFailed(E3144);

	FreeBusyViewType = std::all_of(fb_data.begin(), fb_data.end(),
		[](const freebusy_event &fb_event) { return fb_event.has_details; }) ?
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
	"Task",
};

/**
 * List of field -> conversion function mapping
 */
decltype(tChangeDescription::fields) tChangeDescription::fields = {{
	{"Assistant", {[](auto&&... args){convText(PR_ASSISTANT, args...);}}},
	{"Body", {tChangeDescription::convBody}},
	{"Birthday", {[](auto&&... args){convDate(PR_BIRTHDAY, args...);}}},
	{"BusinessHomePage", {[](auto&&... args){convText(PR_BUSINESS_HOME_PAGE, args...);}}},
	{"Categories", {[](auto&&... args){convStrArray(NtCategories, args...);}}},
	{"Children", {[](auto&&... args){convStrArray(PR_CHILDRENS_NAMES, args...);}}},
	{"CompanyName", {[](auto&&... args){convText(PR_COMPANY_NAME, args...);}}},
	{"Department", {[](auto&&... args){convText(PR_DEPARTMENT_NAME, args...);}}},
	{"DisplayName", {[](auto&&... args){convText(PR_DISPLAY_NAME, args...);}}},
	{"End", {[](auto&&... args){convDate(NtCommonEnd, args...);}}},
	{"FileAs", {[](auto&&... args){convText(NtFileAs, args...);}}},
	{"Generation", {[](auto&&... args){convText(PR_GENERATION, args...);}}},
	{"GivenName", {[](auto&&... args){convText(PR_GIVEN_NAME, args...);}}},
	{"Importance", {[](auto&&... args){convEnumIndex<Enum::ImportanceChoicesType>(PR_IMPORTANCE, args...);}}},
	{"Initials", {[](auto&&... args){convText(PR_INITIALS, args...);}}},
	{"IsAllDayEvent", {[](auto &&...args) { convBool(NtAppointmentSubType, args...); }}},
	{"IsDeliveryReceiptRequested", {[](auto&&... args){convBool(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED, args...);}}},
	{"IsRead", {[](auto&&... args){convBool(PR_READ, args...);}}},
	{"IsReadReceiptRequested", {[](auto&&... args){convBool(PR_READ_RECEIPT_REQUESTED, args...);}}},
	{"JobTitle", {[](auto&&... args){convText(PR_TITLE, args...);}}},
	{"LastModifiedName", {[](auto&&... args){convText(PR_LAST_MODIFIER_NAME, args...);}}},
	{"MimeContent", {[](const tinyxml2::XMLElement* xml, sShape& shape){shape.mimeContent = base64_decode(xml->GetText());}}},
	{"Nickname", {[](auto&&... args){convText(PR_NICKNAME, args...);}}},
	{"OfficeLocation", {[](auto&&... args){convText(PR_OFFICE_LOCATION, args...);}}},
	{"PermissionSet", {[](const tinyxml2::XMLElement* xml, sShape& shape){shape.calendarPermissionSet = xml;}, "CalendarFolder"}},
	{"PermissionSet", {[](const tinyxml2::XMLElement* xml, sShape& shape){shape.permissionSet = xml;}}},
	{"PostalAddressIndex", {[](auto&&... args) {convEnumIndex<Enum::PhysicalAddressIndexType>(NtPostalAddressIndex, args...);}}},
	{"Sensitivity", {[](auto&&... args) {convEnumIndex<Enum::SensitivityChoicesType>(PR_SENSITIVITY, args...);}}},
	{"Subject", {[](auto&&... args){convText(PR_SUBJECT, args...);}}},
	{"Surname", {[](auto&&... args){convText(PR_SURNAME, args...);}}},
	{"SpouseName", {[](auto&&... args){convText(PR_SPOUSE_NAME, args...);}}},
	{"Start", {[](auto&&... args){convDate(NtCommonStart, args...);}}},
	{"WeddingAnniversary", {[](auto&&... args){convDate(PR_WEDDING_ANNIVERSARY, args...);}}},
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
	for (auto it = matches.first; it != matches.second; ++it) {
		if (!it->second.type)
			general = &it->second;
		else if (!strcmp(it->second.type, type))
			specific = &it->second;
	}
	return specific ? specific : general;
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
	return TAGGED_PROPVAL{tag, EWSContext::construct<T>(val)};
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
	if (!field) {
		mlog(LV_WARN, "ews: no conversion for %s::%s", type, name);
		return;
	}
	field->conv(value, shape);
}

/**
 * @brief      Convert Body tag to property
 *
 * @param      xml     XML node containing the body
 * @param      shape   Shape to store the data in
 */
void tChangeDescription::convBody(const tinyxml2::XMLElement* xml, sShape& shape)
{
	const char* bodyType = xml->Attribute("BodyType");
	Enum::BodyTypeType type = bodyType ? bodyType : Enum::Text;
	auto text = znul(xml->GetText());
	if (type == Enum::Text) {
		shape.write(TAGGED_PROPVAL{PR_BODY, const_cast<char*>(text)});
		return;
	}
	size_t len = strlen(text);
	if (len > std::numeric_limits<uint32_t>::max())
		throw InputError(E3256);
	BINARY *html = EWSContext::construct<BINARY>(BINARY{static_cast<uint32_t>(strlen(text)),
	               {reinterpret_cast<uint8_t*>(const_cast<char*>(text))}});
	shape.write(TAGGED_PROPVAL{PR_HTML, html});
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
	if (v->QueryBoolText(&value))
		throw EWSError::InvalidExtendedPropertyValue(E3100(v->GetText() ? v->GetText() : "(nil)"));
	shape.write(mkProp(tag, static_cast<uint8_t>(value ? TRUE : false)));
}

/**
 * @brief      Property conversion function for boolean fields
 *
 * @param      name   Tag name
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convBool(const PROPERTY_NAME &name,
    const XMLElement *v, sShape& shape)
{
	uint32_t tag = shape.tag(name);
	if (tag)
		convBool(tag, v, shape);
}

/**
 * @brief      Property conversion function for datetime fields
 *
 * @param      tag    Tag ID
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convDate(uint32_t tag, const XMLElement* v, sShape& shape)
{
	const char* text = v->GetText();
	if (!text)
		throw EWSError::InvalidExtendedPropertyValue(E3257);
	shape.write(mkProp(tag, sTimePoint(text).toNT()));
	if (strlen(text) == 19)
		shape.offsetProps.emplace_back(tag);
}

/**
 * @brief      Property conversion function for datetime fields
 *
 * @param      name   Tag name
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convDate(const PROPERTY_NAME& name, const XMLElement* v, sShape& shape)
{
	uint32_t tag = shape.tag(name);
	if (tag)
		convDate(tag, v, shape);
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
{
	shape.write(mkProp(tag, PT{ET{v->GetText()}.index()}));
}

/**
 * @brief      Property coversion function for enumerations
 *
 * Converts string to corresponding index and stores it in a numeric property.
 *
 * @param      name   Property name
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 *
 * @tparam     ET     Enumeration type
 * @tparam     PT     Numeric property type
 */
template<typename ET, typename PT>
void tChangeDescription::convEnumIndex(const PROPERTY_NAME& name, const XMLElement* v, sShape& shape)
{
	shape.write(mkProp(shape.tag(name), PT(ET(v->GetText()).index())));
}

/**
 * @brief      Property conversion function for text fields
 *
 * @param      tag    Tag ID
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convText(uint32_t tag, const XMLElement* v, sShape& shape)
{
	shape.write(TAGGED_PROPVAL{tag, deconst(znul(v->GetText()))});
}

/**
 * @brief      Property conversion function for text fields
 *
 * @param      name   Tag name
 * @param      v      XML value node
 * @param      shape  Shape to store property in
 */
void tChangeDescription::convText(const PROPERTY_NAME& name, const XMLElement* v, sShape& shape)
{
	uint32_t tag = shape.tag(name);
	if (tag)
		convText(tag, v, shape);
}

void tChangeDescription::convStrArray(uint32_t tag, const XMLElement* v, sShape& shape)
{
	uint32_t count = 0;
	for (const XMLElement *s = v->FirstChildElement("String"); s != nullptr;
	     s = s->NextSiblingElement("String"))
		++count;
	STRING_ARRAY* categories = EWSContext::construct<STRING_ARRAY>(STRING_ARRAY{count, EWSContext::alloc<char*>(count)});
	char** dest = categories->ppstr;
	for (const XMLElement *s = v->FirstChildElement("String"); s != nullptr;
	     s = s->NextSiblingElement("String"))
		strcpy(*dest++ = EWSContext::alloc<char>(strlen(s->GetText()) + 1), s->GetText());
	shape.write(TAGGED_PROPVAL{tag, categories});
}

void tChangeDescription::convStrArray(const PROPERTY_NAME& name, const XMLElement* v, sShape& shape)
{
	uint32_t tag = shape.tag(name);
	if (tag)
		convStrArray(tag, v, shape);
}

///////////////////////////////////////////////////////////////////////////////

tContact::tContact(const sShape& shape) : tItem(shape)
{
	tContact::update(shape);
}

/**
 * @brief      Generate composite contact fields from written properties
 *
 * @param      shape   Shape to update with generated fields
 */
void tContact::genFields(sShape& shape)
{
	std::optional<std::string> street, city, state, country, postal;

	uint32_t tag;
	if ((tag = shape.tag(NtBusinessAddress)) && !shape.writes(tag)) {
		fromProp(shape.writes(NtBusinessAddressStreet), street);
		fromProp(shape.writes(NtBusinessAddressCity), city);
		fromProp(shape.writes(NtBusinessAddressState), state);
		fromProp(shape.writes(NtBusinessAddressCountry), country);
		fromProp(shape.writes(NtBusinessAddressPostalCode), postal);
		if (street || city || state || country || postal) {
			std::string addr = mkAddress(street, city, state, postal, country);
			shape.write(TAGGED_PROPVAL{tag, EWSContext::cpystr(addr)});
			street.reset(), city.reset(), state.reset(), country.reset(), postal.reset();
		}
	}
	if ((tag = shape.tag(NtHomeAddress)) && !shape.writes(tag)) {
		fromProp(shape.writes(PR_HOME_ADDRESS_STREET), street);
		fromProp(shape.writes(PR_HOME_ADDRESS_CITY), city);
		fromProp(shape.writes(PR_HOME_ADDRESS_STATE_OR_PROVINCE), state);
		fromProp(shape.writes(PR_HOME_ADDRESS_COUNTRY), country);
		fromProp(shape.writes(PR_HOME_ADDRESS_POSTAL_CODE), postal);
		if (street || city || state || country || postal) {
			std::string addr = mkAddress(street, city, state, postal, country);
			shape.write(TAGGED_PROPVAL{tag, EWSContext::cpystr(addr)});
			street.reset(), city.reset(), state.reset(), country.reset(), postal.reset();
		}
	}
	if ((tag = shape.tag(NtOtherAddress)) && !shape.writes(tag)) {
		fromProp(shape.writes(PR_OTHER_ADDRESS_STREET), street);
		fromProp(shape.writes(PR_OTHER_ADDRESS_CITY), city);
		fromProp(shape.writes(PR_OTHER_ADDRESS_STATE_OR_PROVINCE), state);
		fromProp(shape.writes(PR_OTHER_ADDRESS_COUNTRY), country);
		fromProp(shape.writes(PR_OTHER_ADDRESS_POSTAL_CODE), postal);
		if (street || city || state || country || postal) {
			std::string addr = mkAddress(street, city, state, postal, country);
			shape.write(TAGGED_PROPVAL{tag, EWSContext::cpystr(addr)});
		}
	}

	if ((tag = shape.tag(NtFileAs)) && !shape.writes(tag)) {
		const TAGGED_PROPVAL* displayName = shape.writes(PR_DISPLAY_NAME);
		if (displayName)
			shape.write(TAGGED_PROPVAL{tag, displayName->pvalue});
	}
}

/**
 * @brief      Build combined address from (optional) parts
 *
 * @param      street      Street part of the address
 * @param      city        City part of the address
 * @param      state       State part of the address
 * @param      postalCode  Postal code part of the address
 * @param      country     Country part of the address
 *
 * @return     Combined address string
 */
std::string tContact::mkAddress(const std::optional<std::string>& street, const std::optional<std::string>& city,
                                const std::optional<std::string>& state, const std::optional<std::string>& postal,
                                const std::optional<std::string>& country)
{
	auto get = [](const std::optional<std::string> &src) { return src ? src->c_str() : ""; };
	auto con = [](bool src, const char *c) { return src ? c : ""; };
	bool lines[] = {bool(street), city || state || postal, bool(country)};
	return fmt::format(addressTemplate, get(street), con(lines[0] || lines[1], "\n"),
	                    get(city), con(city && state, " "), get(state), con((city || state) && postal, " "), get(postal),
	                    con((lines[0] || lines[1]) && lines[2], "\n"), get(country));
}

void tContact::update(const sShape& shape)
{
	fromProp(shape.get(PR_ASSISTANT), AssistantName);
	fromProp(shape.get(PR_BIRTHDAY), Birthday);
	fromProp(shape.get(PR_BUSINESS_HOME_PAGE), BusinessHomePage);
	fromProp(shape.get(PR_COMPANY_NAME), CompanyName);
	fromProp(shape.get(PR_DEPARTMENT_NAME), Department);
	fromProp(shape.get(PR_TITLE), JobTitle);
	fromProp(shape.get(PR_OFFICE_LOCATION), OfficeLocation);
	fromProp(shape.get(PR_SPOUSE_NAME), SpouseName);
	fromProp(shape.get(PR_WEDDING_ANNIVERSARY), WeddingAnniversary);
	fromProp(shape.get(NtFileAs), FileAs);
	const char* val;
	if ((val = shape.get<char>(PR_BUSINESS_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::BusinessPhone));
	if ((val = shape.get<char>(PR_HOME_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::HomePhone));
	if ((val = shape.get<char>(PR_PRIMARY_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::PrimaryPhone));
	if ((val = shape.get<char>(PR_BUSINESS2_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::BusinessPhone2));
	if ((val = shape.get<char>(PR_MOBILE_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::MobilePhone));
	if ((val = shape.get<char>(PR_PAGER_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::Pager));
	if ((val = shape.get<char>(PR_BUSINESS_FAX_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::BusinessFax));
	if ((val = shape.get<char>(PR_ASSISTANT_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::AssistantPhone));
	if ((val = shape.get<char>(PR_HOME2_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::HomePhone2));
	if ((val = shape.get<char>(PR_COMPANY_MAIN_PHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::CompanyMainPhone));
	if ((val = shape.get<char>(PR_HOME_FAX_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::HomeFax));
	if ((val = shape.get<char>(PR_OTHER_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::OtherTelephone));
	if ((val = shape.get<char>(PR_CALLBACK_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::Callback));
	if ((val = shape.get<char>(PR_RADIO_TELEPHONE_NUMBER)))
		defaulted(PhoneNumbers).emplace_back(tPhoneNumberDictionaryEntry(val, Enum::RadioPhone));

	std::optional<tPhysicalAddressDictionaryEntry> bAddr, hAddr, oAddr; // "Business", "Home", and "Other" address
	if ((val = shape.get<char>(NtBusinessAddressCity)))
		defaulted(bAddr, Enum::Business).City = val;
	if ((val = shape.get<char>(NtBusinessAddressCountry)))
		defaulted(bAddr, Enum::Business).CountryOrRegion = val;
	if ((val = shape.get<char>(NtBusinessAddressPostalCode)))
		defaulted(bAddr, Enum::Business).PostalCode = val;
	if ((val = shape.get<char>(NtBusinessAddressState)))
		defaulted(bAddr, Enum::Business).State = val;
	if ((val = shape.get<char>(NtBusinessAddressStreet)))
		defaulted(bAddr, Enum::Business).Street = val;
	if ((val = shape.get<char>(PR_HOME_ADDRESS_CITY)))
		defaulted(hAddr, Enum::Home).City = val;
	if ((val = shape.get<char>(PR_HOME_ADDRESS_COUNTRY)))
		defaulted(hAddr, Enum::Home).CountryOrRegion = val;
	if ((val = shape.get<char>(PR_HOME_ADDRESS_POSTAL_CODE)))
		defaulted(hAddr, Enum::Home).PostalCode = val;
	if ((val = shape.get<char>(PR_HOME_ADDRESS_STATE_OR_PROVINCE)))
		defaulted(hAddr, Enum::Home).State = val;
	if ((val = shape.get<char>(PR_HOME_ADDRESS_STREET)))
		defaulted(hAddr, Enum::Home).Street = val;
	if ((val = shape.get<char>(PR_OTHER_ADDRESS_CITY)))
		defaulted(oAddr, Enum::Other).City = val;
	if ((val = shape.get<char>(PR_OTHER_ADDRESS_COUNTRY)))
		defaulted(oAddr, Enum::Other).CountryOrRegion = val;
	if ((val = shape.get<char>(PR_OTHER_ADDRESS_POSTAL_CODE)))
		defaulted(oAddr, Enum::Other).PostalCode = val;
	if ((val = shape.get<char>(PR_OTHER_ADDRESS_STATE_OR_PROVINCE)))
		defaulted(oAddr, Enum::Other).State = val;
	if ((val = shape.get<char>(PR_OTHER_ADDRESS_STREET)))
		defaulted(oAddr, Enum::Other).Street = val;
	if (bAddr || hAddr || oAddr) {
		PhysicalAddresses.emplace().reserve(bAddr.has_value()+hAddr.has_value()+oAddr.has_value());
		if (bAddr)
			PhysicalAddresses->emplace_back(std::move(*bAddr));
		if (hAddr)
			PhysicalAddresses->emplace_back(std::move(*hAddr));
		if (oAddr)
			PhysicalAddresses->emplace_back(std::move(*oAddr));
	}

	const TAGGED_PROPVAL* prop;
	if ((prop = shape.get(PR_DISPLAY_NAME_PREFIX)))
		fromProp(prop, defaulted(CompleteName).Title);
	if ((prop = shape.get(PR_GIVEN_NAME))) {
		fromProp(prop, GivenName);
		fromProp(prop, defaulted(CompleteName).FirstName);
	}
	if ((prop = shape.get(PR_MIDDLE_NAME))) {
		fromProp(prop, MiddleName);
		fromProp(prop, defaulted(CompleteName).MiddleName);
	}
	if ((prop = shape.get(PR_SURNAME))) {
		fromProp(prop, Surname);
		fromProp(prop, defaulted(CompleteName).LastName);
	}
	if ((prop = shape.get(PR_GENERATION))) {
		fromProp(prop, Generation);
		fromProp(prop, defaulted(CompleteName).Suffix);
	}
	if ((prop = shape.get(PR_INITIALS))) {
		fromProp(prop, Initials);
		fromProp(prop, defaulted(CompleteName).Initials);
	}
	if ((prop = shape.get(PR_DISPLAY_NAME))) {
		fromProp(prop, DisplayName);
		fromProp(prop, defaulted(CompleteName).FullName);
	}
	if ((prop = shape.get(PR_NICKNAME))) {
		fromProp(prop, Nickname);
		fromProp(prop, defaulted(CompleteName).Nickname);
	}
	if ((prop = shape.get(PR_CHILDRENS_NAMES))) {
		const STRING_ARRAY* names = static_cast<const STRING_ARRAY*>(prop->pvalue);
		Children.emplace(names->begin(), names->end());
	}

	if ((prop = shape.get(NtEmailAddress1)))
		defaulted(EmailAddresses).emplace_back(static_cast<const char*>(prop->pvalue), Enum::EmailAddress1);
	if ((prop = shape.get(NtEmailAddress2)))
		defaulted(EmailAddresses).emplace_back(static_cast<const char*>(prop->pvalue), Enum::EmailAddress2);
	if ((prop = shape.get(NtEmailAddress3)))
		defaulted(EmailAddresses).emplace_back(static_cast<const char*>(prop->pvalue), Enum::EmailAddress3);
	if ((prop = shape.get(NtPostalAddressIndex)))
		PostalAddressIndex.emplace(*static_cast<uint32_t*>(prop->pvalue));
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Generate name restriction
 *
 * @param      name    Name to filter by
 * @param      op      Name comparator
 *
 * @return     Restriction filtering by name
 */
RESTRICTION* tContactsView::namefilter(const std::string& name, relop op)
{
	RESTRICTION* res = EWSContext::construct<RESTRICTION>();
	res->rt = mapi_rtype::property;
	res->prop = EWSContext::alloc<RESTRICTION_PROPERTY>();
	res->prop->relop = op;
	res->prop->propval.proptag = res->prop->proptag = PR_DISPLAY_NAME;
	res->prop->propval.pvalue = EWSContext::alloc(name.size()+1);
	strcpy(static_cast<char*>(res->prop->propval.pvalue), name.c_str());
	return res;
}

/**
 * @brief      Generate restriction to filter by names
 *
 * New restriction is stack allocated and must not be freed manually.
 *
 * @return     Pointer to restriction or nullptr if no condition is set
 */
RESTRICTION* tContactsView::restriction(const sGetNameId&) const
{
	auto initialRes = InitialName ? namefilter(*InitialName, relop::ge) : nullptr;
	auto finalRes = FinalName ? namefilter(*FinalName, relop::le) : nullptr;
	return tRestriction::all(initialRes, finalRes);
}

///////////////////////////////////////////////////////////////////////////////

tDistinguishedFolderId::tDistinguishedFolderId(const std::string_view& name) :
    Id(name)
{}

///////////////////////////////////////////////////////////////////////////////

tEffectiveRights::tEffectiveRights(uint32_t perm) :
    CreateAssociated(perm & frightsCreate),
    CreateContents(perm & frightsCreate),
    CreateHierarchy(perm & frightsCreateSubfolder),
    Delete(perm & frightsDeleteAny),
    Modify(perm & frightsEditAny),
    Read(perm & frightsReadAny)
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
	&PSETID_Meeting,
	&PSETID_Appointment,
	&PSETID_Common,
	&PS_PUBLIC_STRINGS,
	&PSETID_Address,
	&PS_INTERNET_HEADERS,
	&PSETID_CalendarAssistant,
	&PSETID_UnifiedMessaging,
	&PSETID_Task,
	&PSETID_Sharing
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
	if ((data = tps.get<const char>(PR_DISPLAY_NAME)))
		Name = data;
	if ((data = tps.get<const char>(PR_EMAIL_ADDRESS)))
		EmailAddress = data;
	if ((data = tps.get<const char>(PR_ADDRTYPE)))
		RoutingType = data;
}

/**
 * @brief      Generate recipient properties
 *
 * @param      rcpt    Propval array to place recipient properties in
 * @param      type    Type of the recipient (MAPI_TO, MAPI_CC, or MAPI_BCC)
 */
void tEmailAddressType::mkRecipient(TPROPVAL_ARRAY* rcpt, uint32_t type) const
{
	if (rcpt == nullptr)
		throw EWSError::NotEnoughMemory(E3289);
	if (!EmailAddress)
		throw EWSError::InvalidRecipients(E3290);
	auto displayname = Name ? Name->c_str() : EmailAddress->c_str();
	ec_error_t err;
	if ((err = rcpt->set(PR_DISPLAY_NAME, displayname)) == ecServerOOM ||
	    (err = rcpt->set(PR_TRANSMITABLE_DISPLAY_NAME, displayname)) == ecServerOOM ||
	    (err = rcpt->set(PR_ADDRTYPE, RoutingType ? RoutingType->c_str() : "SMTP")) == ecServerOOM ||
	    (err = rcpt->set(PR_EMAIL_ADDRESS, EmailAddress->c_str())) == ecServerOOM ||
	    (err = rcpt->set(PR_RECIPIENT_TYPE, &type)) == ecServerOOM)
		throw EWSError::NotEnoughMemory(E3291);
}

tAttendee::tAttendee(const TPROPVAL_ARRAY& tps)
{
	const char* data;
	if ((data = tps.get<const char>(PR_DISPLAY_NAME)))
		Mailbox.Name = data;
	if ((data = tps.get<const char>(PR_EMAIL_ADDRESS)))
		Mailbox.EmailAddress = data;
	if ((data = tps.get<const char>(PR_ADDRTYPE)))
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

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Combine restrictions into an AND restriction
 *
 * If at least one restriction is a nullptr, the other is returned unchanged,
 * otherwise the restrictions are *moved* into the new parent restriction.
 *
 * New restriction is stack allocated and must not be freed manually.
 *
 * @param      r1    First restriction
 * @param      r2    Second restriction
 *
 * @return Pointer to combined restriction or nullptr if both inputs are nullptr
 */
RESTRICTION* tRestriction::all(RESTRICTION* r1, RESTRICTION* r2)
{
	if (!r1 || !r2)
		return r1 ? r1 : r2;
	RESTRICTION* res = EWSContext::construct<RESTRICTION>();
	res->rt = mapi_rtype::r_and;
	res->andor = EWSContext::construct<RESTRICTION_AND_OR>();
	res->andor->count = 2;
	res->andor->pres = EWSContext::alloc<RESTRICTION>(2);
	res->andor->pres[0] = std::move(*r1);
	res->andor->pres[1] = std::move(*r2);
	return res;
}


/**
 * @brief      Build restriction from XML data
 *
 * Automatically tries to resolve named properties to the correct tag.
 *
 * New restriction is stack allocated and must not be freed manually.
 *
 * @param      getId   Function to resolve property name
 *
 * @return     RESTRICTION* or nullptr if empty
 */
RESTRICTION* tRestriction::build(const sGetNameId& getId) const
{
	if (!source)
		return nullptr;
	RESTRICTION* restriction = EWSContext::alloc<RESTRICTION>();
	deserialize(*restriction, source, getId);
	return restriction;
}

void tRestriction::deserialize(RESTRICTION& dst, const tinyxml2::XMLElement* src, const sGetNameId& getId)
{
	const char* name = src->Name();
	if (!strcmp(name, "And") || !strcmp(name, "Or")) {
		build_andor(dst, src, getId);
	} else if (!strcmp(name, "Contains")) {
		build_contains(dst, src, getId);
	} else if (!strcmp(name, "Excludes")) {
		build_excludes(dst, src, getId);
	} else if (!strcmp(name, "Exists")) {
		build_exists(dst, src, getId);
	} else if (!strcmp(name, "Not")) {
		build_not(dst, src, getId);
	} else try {
		build_compare(dst, src, relop(Enum::RestrictionRelop(name).index()), getId);
	} catch (const EnumError &) {
		/* The name of the node could not be mapped to a relop */
		throw EWSError::InvalidRestriction(E3220(name));
	}
}

void tRestriction::build_andor(RESTRICTION& dst, const tinyxml2::XMLElement* src, const sGetNameId& getId)
{
	dst.rt = strcmp(src->Name(), "And") ? mapi_rtype::r_or : mapi_rtype::r_and;
	dst.andor = EWSContext::alloc<RESTRICTION_AND_OR>();
	dst.andor->count = 0;
	for (const tinyxml2::XMLElement *child = src->FirstChildElement();
	     child != nullptr; child = child->NextSiblingElement())
		++dst.andor->count;
	RESTRICTION* res = dst.andor->pres = EWSContext::alloc<RESTRICTION>(dst.andor->count);
	for (const tinyxml2::XMLElement *child = src->FirstChildElement();
	     child != nullptr; child = child->NextSiblingElement())
		deserialize(*res++, child, getId);
}

void tRestriction::build_compare(RESTRICTION& dst, const tinyxml2::XMLElement* src, relop op, const sGetNameId& getId)
{
	uint32_t tag = getTag(src, getId);
	const tinyxml2::XMLElement* cmptarget = src->FirstChildElement("FieldURIOrConstant");
	if (!cmptarget)
		throw EWSError::InvalidRestriction(E3221);
	void* constantData = loadConstant(cmptarget, PROP_TYPE(tag));
	dst.rt = constantData ? mapi_rtype::property : mapi_rtype::propcmp;
	if (constantData) {
		/* Constant found and loaded -> compare to static data */
		dst.prop = EWSContext::construct<RESTRICTION_PROPERTY>();
		dst.prop->relop = op;
		dst.prop->proptag = tag;
		dst.prop->propval = TAGGED_PROPVAL{tag, constantData};
	} else {
		dst.pcmp = EWSContext::construct<RESTRICTION_PROPCOMPARE>();
		dst.pcmp->relop = op;
		dst.pcmp->proptag1 = tag;
		dst.pcmp->proptag2 = getTag(cmptarget, getId);
		if (!dst.pcmp->comparable())
			throw EWSError::InvalidRestriction(E3223(dst.pcmp->proptag1, dst.pcmp->proptag2));
	}
}

void tRestriction::build_contains(RESTRICTION& dst, const tinyxml2::XMLElement* src, const sGetNameId& getId)
{
	dst.rt = mapi_rtype::content;
	dst.cont = EWSContext::construct<RESTRICTION_CONTENT>();
	if (!(dst.cont->propval.proptag = dst.cont->proptag = getTag(src, getId)))
		throw EWSError::InvalidRestriction(E3224);
	if (!dst.cont->comparable())
			throw EWSError::InvalidRestriction(E3225);
	if (!(dst.cont->propval.pvalue = loadConstant(src, PROP_TYPE(dst.cont->proptag))))
		throw EWSError::InvalidRestriction(E3226);
	const char* mode = src->Attribute("ContainmentMode");
	if (!mode || !strcmp(mode, "FullString"))
		dst.cont->fuzzy_level = FL_FULLSTRING;
	else if (!strcmp(mode, "Prefixed"))
		dst.cont->fuzzy_level = FL_PREFIX;
	else if (!strcmp(mode, "Substring"))
		dst.cont->fuzzy_level = FL_SUBSTRING;
	else if (!strcmp(mode, "PrefixOnWords"))
		dst.cont->fuzzy_level = FL_PREFIX_ON_ANY_WORD;
	else if (!strcmp(mode, "ExactPhrase"))
		dst.cont->fuzzy_level = FL_PHRASE_MATCH;
	else
		throw EWSError::InvalidRestriction(E3227(mode));
	const char* comp = src->Attribute("ContainmentComparison");
	if (!comp || !strcmp(comp, "Exact"))
		;
	else if (!strcmp(comp, "IgnoreCase"))
		dst.cont->fuzzy_level |= FL_IGNORECASE;
	else if (!strcmp(comp, "IgnoreNonSpacingCharacters"))
		dst.cont->fuzzy_level |= FL_IGNORENONSPACE;
	else if (!strcmp(comp, "Loose"))
		dst.cont->fuzzy_level |= FL_LOOSE;
	else if (!strcmp(comp, "LooseAndIgnoreCase"))
		dst.cont->fuzzy_level |= FL_LOOSE | FL_IGNORECASE;
	else if (!strcmp(comp, "LooseAndIgnoreNonSpace"))
		dst.cont->fuzzy_level |= FL_LOOSE | FL_IGNORENONSPACE;
	else if (!strcmp(comp, "IgnoreCaseAndNoneSpacingCharacters"))
		dst.cont->fuzzy_level |= FL_LOOSE | FL_IGNORECASE | FL_IGNORENONSPACE;
	else
		throw EWSError::InvalidRestriction(E3228(comp));
}

void tRestriction::build_excludes(RESTRICTION& dst, const tinyxml2::XMLElement* src, const sGetNameId& getId)
{
	dst.rt = mapi_rtype::bitmask;
	dst.bm = EWSContext::construct<RESTRICTION_BITMASK>();
	dst.bm->bitmask_relop = bm_relop::nez;
	if (!(dst.bm->proptag = getTag(src, getId)))
		throw EWSError::InvalidRestriction(E3229);
	if (!dst.bm->comparable())
		throw EWSError::InvalidRestriction(E3230(tExtendedFieldURI::typeName(PROP_TYPE(dst.bm->proptag)), dst.bm->proptag));
	const tinyxml2::XMLElement* bitmask = src->FirstChildElement("BitMask");
	if (!bitmask)
		throw EWSError::InvalidRestriction(E3231);
	dst.bm->mask = bitmask->UnsignedAttribute("Value");
}

void tRestriction::build_exists(RESTRICTION& dst, const tinyxml2::XMLElement* src, const sGetNameId& getId)
{
	dst.rt = mapi_rtype::exist;
	dst.exist = EWSContext::construct<RESTRICTION_EXIST>();
	if (!(dst.exist->proptag = getTag(src, getId)))
		throw EWSError::InvalidRestriction(E3232);
}

void tRestriction::build_not(RESTRICTION& dst, const tinyxml2::XMLElement* src, const sGetNameId& getId)
{
	const tinyxml2::XMLElement* child = src->FirstChildElement();
	if (!child)
		throw EWSError::InvalidRestriction(E3233);
	dst.rt = mapi_rtype::r_not;
	dst.xnot = EWSContext::construct<RESTRICTION_NOT>();
	deserialize(dst.xnot->res, child, getId);
}

void* tRestriction::loadConstant(const tinyxml2::XMLElement* parent, uint16_t type)
{
	const tinyxml2::XMLElement* constantNode = parent->FirstChildElement("Constant");
	if (!constantNode)
		return nullptr;
	const char* value = constantNode->Attribute("Value");
	if (!value)
		throw EWSError::InvalidRestriction(E3234);
	size_t allocSize = typeWidth(type);
	auto dest = allocSize ? EWSContext::alloc(allocSize) : nullptr;
	switch(type) {
	case PT_SHORT:{
		int temp;
		XMLError res = constantNode->QueryIntAttribute("Value", &temp);
		if (res != XML_SUCCESS || temp < SHRT_MIN || temp > USHRT_MAX)
			throw EWSError::InvalidRestriction(E3235(value));
		*static_cast<int16_t *>(dest) = temp;
		break;
	}
	case PT_ERROR:
	case PT_LONG:
		if (constantNode->QueryIntAttribute("Value", static_cast<int32_t *>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidRestriction(E3236(value));
		break;
	case PT_FLOAT:
		if (constantNode->QueryFloatAttribute("Value", static_cast<float*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidRestriction(E3237(value));
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		if (constantNode->QueryDoubleAttribute("Value", static_cast<double*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidRestriction(E3238(value));
		break;
	case PT_BOOLEAN:
		if (constantNode->QueryBoolAttribute("Value", static_cast<bool*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidRestriction(E3239(value));
		break;
	case PT_CURRENCY:
	case PT_I8:
		if (constantNode->QueryInt64Attribute("Value", static_cast<int64_t *>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidRestriction(E3240(value));
		break;
	case PT_SYSTIME:
		*static_cast<uint64_t*>(dest) = sTimePoint(constantNode->Attribute("Value")).toNT(); break;
	case PT_STRING8:
	case PT_UNICODE: {
		size_t len = strlen(value);
		dest = EWSContext::alloc(len + 1);
		memcpy(static_cast<char *>(dest), value, len + 1);
		break;
	}
	default:
		throw EWSError::InvalidRestriction(E3241(tExtendedFieldURI::typeName(type)));
	}
	return dest;
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
	if (propname.kind == MNID_ID)
		PropertyId = propname.lid;
	else if (propname.kind == MNID_STRING)
		PropertyName = propname.pname;

	auto it = std::find_if(std::begin(propsetIds), std::end(propsetIds),
	                       [&](const auto &propsetId) { return *propsetId == propname.guid; });
	if (it != std::end(propsetIds))
		DistinguishedPropertySetId = Enum::DistinguishedPropertySetType(static_cast<uint8_t>(std::distance(std::begin(propsetIds), it)));
}

/**
 * @brief      Get Tag ID
 *
 * @return     Tag ID or 0 if named property
 */
uint32_t tExtendedFieldURI::tag() const
{
	return PropertyTag ? PROP_TAG(type(), *PropertyTag) : 0;
}

/**
 * @brief      Get Tag ID
 *
 * Automatically tries to resolve named properties to the correct tag.
 *
 * @param      getId   Function to resolve property name
 *
 * @return     Tag ID
 */
uint32_t tExtendedFieldURI::tag(const sGetNameId& getId) const
{
	return PROP_TAG(type(), PropertyTag ? *PropertyTag : getId(name()));
}

/**
 * @brief      Get property name
 *
 * @return     Property name or KIND_NONE name if regular tag.
 */
PROPERTY_NAME tExtendedFieldURI::name() const
{
	static constexpr PROPERTY_NAME NONAME{KIND_NONE, {}, 0, nullptr};
	if (!PropertySetId && !DistinguishedPropertySetId)
		return NONAME;
	PROPERTY_NAME name{};
	name.guid = PropertySetId ? *PropertySetId : *propsetIds[DistinguishedPropertySetId->index()];
	if (PropertyName) {
		name.kind = MNID_STRING;
		name.pname = deconst(PropertyName->c_str());
	} else if (PropertyId) {
		name.kind = MNID_ID;
		name.lid = *PropertyId;
	} else {
		return NONAME;
	}
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
	if (PropertyTag)
		shape.add(tag(), add ? sShape::FL_EXT : sShape::FL_RM);
	else if ((PropertySetId || DistinguishedPropertySetId) && (PropertyName || PropertyId))
		shape.add(name(), type(), add ? sShape::FL_EXT : sShape::FL_RM);
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
	if (type == typeMap.end() || strcmp(type->first, PropertyType.c_str()))
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
	switch (type) {
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
	ExtendedFieldURI(pn.kind == KIND_NONE ?
	                 tExtendedFieldURI(tp.proptag) :
	                 tExtendedFieldURI(PROP_TYPE(tp.proptag), pn)),
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
	for (const XMLElement *child = xml->FirstChildElement("Value");
	     child != nullptr; child = child->NextSiblingElement("Value"))
		++container->count;
	container->*values = EWSContext::alloc<T>(container->count);
	const XMLElement* child = xml->FirstChildElement("Value");
	for (T *value = container->*values; value < container->*values + container->count; ++value) {
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
	if (!dest)
		propval.pvalue = dest = allocSize ? EWSContext::alloc(allocSize) : nullptr;
	const char* content = xml->GetText();
	switch(type) {
	case PT_SHORT:{
		int temp;
		XMLError res = xml->QueryIntText(&temp);
		if (res != XML_SUCCESS || temp < SHRT_MIN || temp > USHRT_MAX)
			/* be flexible, allow both signed and unsigned range */
			throw EWSError::InvalidExtendedPropertyValue(E3101(content ? content : "(nil)"));
		*static_cast<int16_t *>(dest) = temp;
		break;
	}
	case PT_ERROR:
	case PT_LONG:
		if (xml->QueryIntText(static_cast<int32_t *>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3102(content ? content : "(nil)"));
		break;
	case PT_FLOAT:
		if (xml->QueryFloatText(static_cast<float*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3103(content ? content : "(nil)"));
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		if (xml->QueryDoubleText(static_cast<double*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3104(content ? content : "(nil)"));
		break;
	case PT_BOOLEAN:
		if (xml->QueryBoolText(static_cast<bool*>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3105(content ? content : "(nil)"));
		break;
	case PT_CURRENCY:
	case PT_I8:
		if (xml->QueryInt64Text(static_cast<int64_t *>(dest)) != XML_SUCCESS)
			throw EWSError::InvalidExtendedPropertyValue(E3106(content ? content : "(nil)"));
		break;
	case PT_SYSTIME:
		*static_cast<uint64_t*>(dest) = sTimePoint(xml->GetText()).toNT(); break;
	case PT_STRING8:
	case PT_UNICODE: {
		auto src = znul(xml->GetText());
		size_t len = strlen(src);
		if (!dest)
			propval.pvalue = dest = EWSContext::alloc(len + 1);
		else
			dest = *static_cast<char**>(dest) = EWSContext::alloc<char>(len + 1);
		memcpy(static_cast<char*>(dest), src, len + 1);
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
	for (T *val = content->*value; val < content->*value + content->count; ++val) {
		if constexpr (std::is_same_v<T, char*>)
			serialize(*val, type&~MV_FLAG, xml->InsertNewChildElement("t:Value"));
		else
			serialize(val, type&~MV_FLAG, xml->InsertNewChildElement("t:Value"));
	}
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
	switch (type) {
	case PT_BOOLEAN:
		return xml->SetText(bool(*(reinterpret_cast<const uint8_t*>(data))));
	case PT_SHORT:
		return xml->SetText(*reinterpret_cast<const int16_t *>(data));
	case PT_LONG:
	case PT_ERROR:
		return xml->SetText(*reinterpret_cast<const int32_t *>(data));
	case PT_I8:
	case PT_CURRENCY:
		return xml->SetText(*reinterpret_cast<const int64_t *>(data));
	case PT_SYSTIME:
		return sTimePoint::fromNT(*reinterpret_cast<const int64_t *>(data)).serialize(xml);
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

/**
 * @brief      Generate SORTORDER_SET from FieldOrder list
 *
 * Result is stack allocated and must not be manually freed.
 *
 * @param      sorts   List of field orders
 * @param      getId   @param      getId
 *
 * @return     Pointer to SORTORDER_SET structure or nullptr if input array is empty
 */
SORTORDER_SET* tFieldOrder::build(const std::vector<tFieldOrder>& sorts, const sGetNameId& getId)
{
	if (sorts.empty())
		return nullptr;
	if (sorts.size() > std::numeric_limits<decltype(SORTORDER_SET::count)>::max())
		throw InputError(E3247);
	SORTORDER_SET* sset = EWSContext::construct<SORTORDER_SET>();
	sset->count = sorts.size();
	sset->ccategories = sset->cexpanded = 0;
	sset->psort = EWSContext::alloc<SORT_ORDER>(sset->count);
	SORT_ORDER* current = sset->psort;
	for (const tFieldOrder& sort : sorts) {
		uint32_t tag = sort.fieldURI.tag(getId);
		current->type = PROP_TYPE(tag);
		current->propid = PROP_ID(tag);
		current->table_sort = sort.Order.index();
	}
	return sset;
}

///////////////////////////////////////////////////////////////////////////////

decltype(tFieldURI::tagMap) tFieldURI::tagMap = {
	{"calendar:DateTimeStamp", PR_CREATION_TIME},
	{"calendar:End", PR_END_DATE},
	{"calendar:IsResponseRequested", PR_RESPONSE_REQUESTED},
	{"calendar:Organizer", PR_SENDER_ADDRTYPE},
	{"calendar:Organizer", PR_SENDER_EMAIL_ADDRESS},
	{"calendar:Organizer", PR_SENDER_NAME},
	{"calendar:Start", PR_START_DATE},
	{"contacts:AssistantName", PR_ASSISTANT},
	{"contacts:Birthday", PR_BIRTHDAY},
	{"contacts:BusinessHomePage", PR_BUSINESS_HOME_PAGE},
	{"contacts:Children", PR_CHILDRENS_NAMES},
	{"contacts:CompanyName", PR_COMPANY_NAME},
	{"contacts:CompleteName", PR_DISPLAY_NAME_PREFIX},
	{"contacts:CompleteName", PR_DISPLAY_NAME},
	{"contacts:CompleteName", PR_GENERATION},
	{"contacts:CompleteName", PR_GIVEN_NAME},
	{"contacts:CompleteName", PR_INITIALS},
	{"contacts:CompleteName", PR_MIDDLE_NAME},
	{"contacts:CompleteName", PR_NICKNAME}, // TODO: YomiFirstName, YomiLastName;
	{"contacts:CompleteName", PR_SURNAME},
	{"contacts:Department", PR_DEPARTMENT_NAME},
	{"contacts:DisplayName", PR_DISPLAY_NAME},
	{"contacts:Generation", PR_GENERATION},
	{"contacts:GivenName", PR_GIVEN_NAME},
	{"contacts:Initials", PR_INITIALS},
	{"contacts:JobTitle", PR_TITLE},
	{"contacts:Manager", PR_MANAGER_NAME},
	{"contacts:MiddleName", PR_GIVEN_NAME},
	{"contacts:Nickname", PR_NICKNAME},
	{"contacts:OfficeLocation", PR_OFFICE_LOCATION},
	{"contacts:SpouseName", PR_SPOUSE_NAME},
	{"contacts:Surname", PR_SURNAME},
	{"contacts:WeddingAnniversary", PR_WEDDING_ANNIVERSARY},
	{"folder:ChildFolderCount", PR_FOLDER_CHILD_COUNT},
	{"folder:DisplayName", PR_DISPLAY_NAME},
	{"folder:FolderClass", PR_CONTAINER_CLASS},
	{"folder:FolderId", PidTagFolderId},
	{"folder:ParentFolderId", PR_PARENT_ENTRYID},
	{"folder:TotalCount", PR_CONTENT_COUNT},
	{"folder:UnreadCount", PR_CONTENT_UNREAD},
	{"item:ConversationId", PR_CONVERSATION_ID},
	{"item:DateTimeCreated", PR_CREATION_TIME},
	{"item:DateTimeReceived", PR_MESSAGE_DELIVERY_TIME},
	{"item:DateTimeSent", PR_CLIENT_SUBMIT_TIME},
	{"item:DisplayTo", PR_DISPLAY_TO},
	{"item:Flag", PR_FLAG_STATUS},
	{"item:HasAttachments", PR_HASATTACH},
	{"item:Importance", PR_IMPORTANCE},
	{"item:InReplyTo", PR_IN_REPLY_TO_ID},
	{"item:InternetMessageHeaders", PR_TRANSPORT_MESSAGE_HEADERS},
	{"item:IsAssociated", PR_ASSOCIATED},
	{"item:ItemClass", PR_MESSAGE_CLASS},
	{"item:LastModifiedName", PR_LAST_MODIFIER_NAME},
	{"item:LastModifiedTime", PR_LAST_MODIFICATION_TIME},
	{"item:ParentFolderId", PR_PARENT_ENTRYID},
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
	{"calendar:AllowNewTimeProposal", {NtAppointmentNotAllowPropose, PT_BOOLEAN}},
	{"calendar:AppointmentReplyTime", {NtAppointmentReplyTime, PT_SYSTIME}},
	{"calendar:AppointmentState", {NtAppointmentStateFlags, PT_LONG}},
	{"calendar:AppointmentSequenceNumber", {NtAppointmentSequence, PT_LONG}},
	{"calendar:End", {NtAppointmentEndWhole, PT_SYSTIME}},
	{"calendar:End", {NtCommonEnd, PT_SYSTIME}},
	{"calendar:IsAllDayEvent", {NtAppointmentSubType, PT_BOOLEAN}},
	{"calendar:IsCancelled", {NtAppointmentStateFlags, PT_LONG}},
	{"calendar:IsMeeting", {NtAppointmentStateFlags, PT_LONG}},
	{"calendar:IsRecurring", {NtRecurring, PT_BOOLEAN}},
	{"calendar:LegacyFreeBusyStatus", {NtBusyStatus, PT_LONG}},
	{"calendar:Location", {NtLocation, PT_UNICODE}},
	{"calendar:MeetingRequestWasSent", {NtFInvited, PT_BOOLEAN}},
	{"calendar:MyResponseType", {NtResponseStatus, PT_LONG}},
	{"calendar:Recurrence", {NtAppointmentRecur, PT_BINARY}},
	{"calendar:DeletedOccurrences", {NtAppointmentRecur, PT_BINARY}},
	{"calendar:Start", {NtAppointmentStartWhole, PT_SYSTIME}},
	{"calendar:Start", {NtCommonStart, PT_SYSTIME}},
	{"calendar:UID", {NtGlobalObjectId, PT_BINARY}},
	{"calendar:RecurrenceId", {NtExceptionReplaceTime, PT_SYSTIME}},
	{"contacts:DisplayName", {NtFileAs, PT_UNICODE}},
	{"contacts:FileAs", {NtFileAs, PT_UNICODE}},
	{"contacts:PostalAddressIndex", {NtPostalAddressIndex, PT_LONG}},
	{"item:Categories", {NtCategories, PT_MV_UNICODE}},
	{"item:Flag", {NtTaskDateCompleted, PT_SYSTIME}},
	{"item:Flag", {NtTaskDueDate, PT_SYSTIME}},
	{"item:Flag", {NtTaskStartDate, PT_SYSTIME}},
	{"item:ReminderDueBy", {NtReminderTime, PT_SYSTIME}},
	{"item:ReminderIsSet", {NtReminderSet, PT_BOOLEAN}},
	{"item:ReminderMinutesBeforeStart", {NtReminderDelta, PT_LONG}},
	{"task:ActualWork", {NtTaskActualEffort, PT_LONG}},
	// {"task:AssignedTime", {}},
	{"task:BillingInformation", {NtBilling, PT_UNICODE}},
	// {"task:ChangeCount", {}},
	{"task:Companies", {NtCompanies, PT_MV_UNICODE}},
	{"task:CompleteDate", {NtTaskDateCompleted, PT_SYSTIME}},
	// {"task:Contacts", {}},
	// {"task:DelegationState", {}},
	// {"task:Delegator", {}},
	{"task:DueDate", {NtTaskDueDate, PT_SYSTIME}},
	// {"task:IsAssignmentEditable", {}},
	{"task:IsComplete", {NtTaskComplete, PT_BOOLEAN}},
	{"task:IsRecurring", {NtTaskFRecurring, PT_BOOLEAN}},
	// {"task:IsTeamTask", {}},
	{"task:Mileage", {NtMileage, PT_UNICODE}},
	{"task:Owner", {NtTaskOwner, PT_UNICODE}},
	{"task:PercentComplete", {NtPercentComplete, PT_DOUBLE}},
	{"task:Recurrence", {NtTaskRecurrence, PT_BINARY}},
	{"task:StartDate", {NtTaskStartDate, PT_SYSTIME}},
	{"task:Status", {NtTaskStatus, PT_LONG}},
	// {"task:StatusDescription", {}},
	{"task:TotalWork", {NtTaskEstimatedEffort, PT_LONG}},
};

decltype(tFieldURI::specialMap) tFieldURI::specialMap = {{
	{"calendar:OptionalAttendees", sShape::OptionalAttendees},
	{"calendar:RequiredAttendees", sShape::RequiredAttendees},
	{"calendar:Resources", sShape::Resources},
	{"folder:EffectiveRights", sShape::Rights},
	{"folder:PermissionSet", sShape::Permissions},
	{"item:Attachments", sShape::Attachments},
	{"item:Body", sShape::Body},
	{"item:EffectiveRights", sShape::Rights},
	{"item:IsDraft", sShape::MessageFlags},
	{"item:IsFromMe", sShape::MessageFlags},
	{"item:IsResend", sShape::MessageFlags},
	{"item:IsSubmitted", sShape::MessageFlags},
	{"item:IsUnmodified", sShape::MessageFlags},
	{"item:MimeContent", sShape::MimeContent},
	{"message:BccRecipients", sShape::BccRecipients},
	{"message:CcRecipients", sShape::CcRecipients},
	{"message:ToRecipients", sShape::ToRecipients},
}};


void tFieldURI::tags(sShape& shape, bool add) const
{
	auto tags = tagMap.equal_range(FieldURI);
	for (auto it = tags.first; it != tags.second; ++it)
		shape.add(it->second, add ? sShape::FL_FIELD : sShape::FL_RM);
	bool found = tags.first != tags.second;

	auto names = nameMap.equal_range(FieldURI);
	for (auto it = names.first; it != names.second; ++it)
		shape.add(it->second.first, it->second.second,
		          add ? sShape::FL_FIELD : sShape::FL_RM);
	found |= names.first != names.second;

	static auto compval = [](const SMEntry& v1, const char* const v2){return strcmp(v1.first, v2) < 0;};
	auto specials = std::lower_bound(specialMap.begin(), specialMap.end(), FieldURI.c_str(), compval);
	if (specials != specialMap.end() && specials->first == FieldURI) {
		shape.special |= specials->second;
		found = true;
	}
	if (!found)
		mlog(LV_NOTICE, "ews: unknown field URI '%s' (ignored)", FieldURI.c_str());
}

/**
 * @brief      Return tag of the field
 *
 * If a field is mapped to multiple tags, only the first tag is returned.
 * Automatically tries to resolve named properties to the correct tag.
 *
 * @param      getId   Function to resolve property name
 *
 * @return    Tag or 0 if not found
 */
uint32_t tFieldURI::tag(const sGetNameId& getId) const
{
	auto tags = tagMap.equal_range(FieldURI);
	if (tags.first != tagMap.end())
		return tags.first->second;
	auto names = nameMap.equal_range(FieldURI);
	return names.first == nameMap.end() ? 0 :
	       PROP_TAG(names.first->second.second, getId(names.first->second.first));
}

///////////////////////////////////////////////////////////////////////////////

tFileAttachment::tFileAttachment(const sAttachmentId& aid, const TPROPVAL_ARRAY& props) : tAttachment(aid, props)
{
	const TAGGED_PROPVAL *tp = props.find(PR_ATTACH_DATA_BIN);
	if (tp) {
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
	for (uint32_t tag : tagsStructural)
		shape.add(tag);
	size_t baseShape = BaseShape.index();
	for (uint32_t tag : tagsIdOnly)
		shape.add(tag, sShape::FL_FIELD);
	if (baseShape >= 1)
		for (uint32_t tag : tagsDefault)
			shape.add(tag, sShape::FL_FIELD);
	if (baseShape == 2) {
		/* "tagsAll" is really an _extra_ list (over default), not "all" */
		for (uint32_t tag : tagsAll)
			shape.add(tag, sShape::FL_FIELD);

		/* XXX
		bool is_root = ... == PRIVATE_FID_ROOT;
		if (is_root)
			for (uint32_t tag : tagsAllRootOnly)
				shape.add(tag, sShape::FL_FIELD);
		*/
	}
	if (AdditionalProperties)
		for (const auto& additional : *AdditionalProperties)
			additional.tags(shape);
}

///////////////////////////////////////////////////////////////////////////////

tFolderType::tFolderType(const sShape& shape) : tBaseFolderType(shape)
{
	fromProp(shape.get(PR_CONTENT_UNREAD), UnreadCount);
}

///////////////////////////////////////////////////////////////////////////////

uint32_t tFractionalPageView::offset(uint32_t total) const
{
	return static_cast<size_t>(total) * Numerator / Denominator;
}

void tFractionalPageView::update(tFindResponsePagingAttributes& attr, uint32_t count, uint32_t total) const
{
	attr.NumeratorOffset = offset(total) + count;
	attr.AbsoluteDenominator = total;
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

decltype(tIndexedFieldURI::tagMap) tIndexedFieldURI::tagMap = {{
	{{"contacts:PhoneNumber", "AssistantPhone"}, PR_ASSISTANT_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "BusinessFax"}, PR_BUSINESS_FAX_NUMBER},
	{{"contacts:PhoneNumber", "BusinessPhone"}, PR_BUSINESS_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "BusinessPhone2"}, PR_BUSINESS2_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "Callback"}, PR_CALLBACK_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "Car"}, PR_CAR_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "CompanyMainPhone"}, PR_COMPANY_MAIN_PHONE_NUMBER},
	{{"contacts:PhoneNumber", "HomeFax"}, PR_HOME_FAX_NUMBER},
	{{"contacts:PhoneNumber", "HomePhone"}, PR_HOME_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "HomePhone2"}, PR_HOME2_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "MobilePhone"}, PR_MOBILE_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "OtherFax"}, PR_PRIMARY_FAX_NUMBER},
	{{"contacts:PhoneNumber", "OtherTelephone"}, PR_OTHER_TELEPHONE_NUMBER},
	{{"contacts:PhoneNumber", "Pager"}, PR_PAGER_TELEPHONE_NUMBER}, // same as PR_BEEPER_TELEPHONE_NUMBER
	{{"contacts:PhoneNumber", "RadioPhone"}, PR_RADIO_TELEPHONE_NUMBER},
	{{"contacts:PhysicalAddress:City", "Home"}, PR_HOME_ADDRESS_CITY},
	{{"contacts:PhysicalAddress:City", "Other"}, PR_OTHER_ADDRESS_CITY},
	{{"contacts:PhysicalAddress:CountryOrRegion", "Home"}, PR_HOME_ADDRESS_COUNTRY},
	{{"contacts:PhysicalAddress:CountryOrRegion", "Other"}, PR_OTHER_ADDRESS_COUNTRY},
	{{"contacts:PhysicalAddress:PostalCode", "Home"}, PR_HOME_ADDRESS_POSTAL_CODE},
	{{"contacts:PhysicalAddress:PostalCode", "Other"}, PR_OTHER_ADDRESS_POSTAL_CODE},
	{{"contacts:PhysicalAddress:State", "Home"}, PR_HOME_ADDRESS_STATE_OR_PROVINCE},
	{{"contacts:PhysicalAddress:State", "Other"}, PR_OTHER_ADDRESS_STATE_OR_PROVINCE},
	{{"contacts:PhysicalAddress:Street", "Home"}, PR_HOME_ADDRESS_STREET},
	{{"contacts:PhysicalAddress:Street", "Other"}, PR_OTHER_ADDRESS_STREET},
}};

/**
 * @brief      Mapping for indexed field URIs -> property name / type pairs
 *
 * Must be sorted alphabetically.
 *
 * Contains an entry for the respective composite address property for each
 * address part. Composite property *must* be specified after address part
 * property.
 */
decltype(tIndexedFieldURI::nameMap) tIndexedFieldURI::nameMap = {{
	{{"contacts:EmailAddress", "EmailAddress1"}, {NtEmailAddress1, PT_UNICODE}},
	{{"contacts:EmailAddress", "EmailAddress2"}, {NtEmailAddress2, PT_UNICODE}},
	{{"contacts:EmailAddress", "EmailAddress3"}, {NtEmailAddress3, PT_UNICODE}},
	{{"contacts:ImAddress", "ImAddress1"}, {NtImAddress1, PT_UNICODE}},
	{{"contacts:PhysicalAddress:City", "Business"}, {NtBusinessAddressCity, PT_UNICODE}},
	{{"contacts:PhysicalAddress:City", "Business"}, {NtBusinessAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:City", "Home"}, {NtHomeAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:City", "Other"}, {NtOtherAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:CountryOrRegion", "Business"}, {NtBusinessAddressCountry, PT_UNICODE}},
	{{"contacts:PhysicalAddress:CountryOrRegion", "Business"}, {NtBusinessAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:CountryOrRegion", "Home"}, {NtHomeAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:CountryOrRegion", "Other"}, {NtOtherAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:PostalCode", "Business"}, {NtBusinessAddressPostalCode, PT_UNICODE}},
	{{"contacts:PhysicalAddress:PostalCode", "Business"}, {NtBusinessAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:PostalCode", "Home"}, {NtHomeAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:PostalCode", "Other"}, {NtOtherAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:State", "Business"}, {NtBusinessAddressState, PT_UNICODE}},
	{{"contacts:PhysicalAddress:State", "Business"}, {NtBusinessAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:State", "Home"}, {NtHomeAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:State", "Other"}, {NtOtherAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:Street", "Business"}, {NtBusinessAddressStreet, PT_UNICODE}},
	{{"contacts:PhysicalAddress:Street", "Business"}, {NtBusinessAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:Street", "Home"}, {NtHomeAddress, PT_UNICODE}},
	{{"contacts:PhysicalAddress:Street", "Other"}, {NtOtherAddress, PT_UNICODE}},
}};

/**
 * @brief      Collect tags specified by indexed field URI
 *
 * Will add composite address fields.
 * As these fields are not mapped, this has no effect when reading.
 * When writing, this will cause the composite field tags to be resolved, but
 * not actively filled by the standard SetItemField mechanism. Instead, these
 * properties are explicitely synthesized by tContact::genFields.
 *
 * @param      shape   Shape to store tags in
 * @param      add     Whether tags are added or deleted
 */
void tIndexedFieldURI::tags(sShape& shape, bool add) const
{
	static auto compval = [](const auto& v1, const tIndexedFieldURI& v2)
	{return std::tie(v1.first.first, v1.first.second) < std::tie(v2.FieldURI, v2.FieldIndex);};

	auto tagIt = std::lower_bound(tagMap.begin(), tagMap.end(), *this, compval);
	if (tagIt != tagMap.end() && tagIt->first.first == FieldURI && tagIt->first.second == FieldIndex)
		shape.add(tagIt->second, add ? sShape::FL_FIELD : sShape::FL_RM);

	// Additional
	auto names = std::lower_bound(nameMap.begin(), nameMap.end(), *this, compval);
	while (names != nameMap.end() && names->first.first == FieldURI && names->first.second == FieldIndex) {
		shape.add(names->second.first, names->second.second,
		          add ? sShape::FL_FIELD : sShape::FL_RM);
		++names;
	}
}

/**
 * @brief      Get tag represented by indexed field URI
 *
 * If an indexed field URI corresponds to multiple tags, only the first match
 * is returned.
 *
 * @param      getId   Function to resolve named property
 *
 * @return
 */
uint32_t tIndexedFieldURI::tag(const sGetNameId& getId) const
{
	static auto compval = [](const auto& v1, const tIndexedFieldURI& v2)
	{return std::tie(v1.first.first, v1.first.second) < std::tie(v2.FieldURI, v2.FieldIndex);};

	auto tagIt = std::lower_bound(tagMap.begin(), tagMap.end(), *this, compval);
	if (tagIt != tagMap.end() && tagIt->first.first == FieldURI && tagIt->first.second == FieldIndex)
		return tagIt->second;

	auto names = std::lower_bound(nameMap.begin(), nameMap.end(), *this, compval);
	if (names != nameMap.end() && names->first.first == FieldURI && names->first.second == FieldIndex) {
		uint16_t tagid =  getId(names->second.first);
		return tagid ? PROP_TAG(names->second.second, tagid) : 0;
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////////

uint32_t tIndexedPageView::offset(uint32_t total) const
{
	return BasePoint == Enum::Beginning ? Offset :
	       total > Offset ? total - Offset : 0;
}

void tIndexedPageView::update(tFindResponsePagingAttributes& attr, uint32_t count, uint32_t) const
{
	attr.IndexedPagingOffset = Offset + count;
}

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
std::vector<tInternetMessageHeader> tInternetMessageHeader::parse(const char *content)
{
	std::vector<tInternetMessageHeader> result;
	vmime::parsingContext vpctx;
	vpctx.setInternationalizedEmailSupport(true); /* RFC 6532 */
	vmime::header hdr;
	hdr.parse(vpctx, content);
	for (const auto &hf : hdr.getFieldList()) {
		auto k = hf->getName();
		vmime::text txt;
		txt.parse(hf->getValue()->generate());
		result.emplace_back(k, txt.getConvertedText(vmime::charsets::UTF_8).c_str());
	}
	return result;
}

///////////////////////////////////////////////////////////////////////////////

tItem::tItem(const sShape& shape)
{
	tItem::update(shape);
}

void tItem::update(const sShape& shape)
{
	const uint32_t* v32;
	const TAGGED_PROPVAL* prop;
	fromProp(shape.get(PR_ASSOCIATED), IsAssociated);
	const TAGGED_PROPVAL *bodyText = shape.get(PR_BODY), *bodyHtml = shape.get(PR_HTML);
	if (bodyHtml) {
		const BINARY* content = reinterpret_cast<const BINARY*>(bodyHtml->pvalue);
		const cpid_t* cpid = shape.get<cpid_t>(PR_INTERNET_CPID, sShape::FL_ANY);
		const char* cset;
		if (cpid && *cpid != CP_UTF8 && (cset = cpid_to_cset(*cpid)))
			Body.emplace(iconvtext(content->pc, content->cb, cset, "UTF-8"), Enum::HTML);
		else
			Body.emplace(std::string_view(content->pc, content->cb), Enum::HTML);
	} else if (bodyText) {
		Body.emplace(reinterpret_cast<const char*>(bodyText->pvalue), Enum::Text);
	} else if (shape.requested(PR_BODY) || shape.requested(PR_HTML)) {
		Body.emplace("", Enum::Text);
	}

	if ((prop = shape.get(PR_CHANGE_KEY)))
		fromProp(prop, defaulted(ItemId).ChangeKey);
	fromProp(shape.get(PR_CLIENT_SUBMIT_TIME), DateTimeSent);
	if ((prop = shape.get(PR_CONVERSATION_ID))) {
		fromProp(prop, defaulted(ConversationId).Id);
		ConversationId->type = tItemId::ID_GENERIC;
	}
	if ((prop = shape.get(PR_CREATION_TIME)))
		fromProp(prop, DateTimeCreated);
	else
		fromProp(shape.get(PR_LOCAL_COMMIT_TIME), DateTimeCreated);
	fromProp(shape.get(PR_DISPLAY_BCC), DisplayBcc);
	fromProp(shape.get(PR_DISPLAY_CC), DisplayCc);
	fromProp(shape.get(PR_DISPLAY_TO),DisplayTo);
	if ((prop = shape.get(PR_ENTRYID)))
		fromProp(prop, defaulted(ItemId).Id);
	fromProp(shape.get(PR_HASATTACH), HasAttachments);
	if ((v32 = shape.get<uint32_t>(PR_IMPORTANCE)))
		Importance = *v32 == IMPORTANCE_LOW ? Enum::Low :
		             *v32 == IMPORTANCE_HIGH ? Enum::High : Enum::Normal;
	fromProp(shape.get(PR_IN_REPLY_TO_ID), InReplyTo);
	fromProp(shape.get(PR_LAST_MODIFIER_NAME), LastModifiedName);
	fromProp(shape.get(PR_LAST_MODIFICATION_TIME), LastModifiedTime);
	fromProp(shape.get(PR_MESSAGE_CLASS), ItemClass);
	fromProp(shape.get(PR_MESSAGE_DELIVERY_TIME), DateTimeReceived);
	if ((v32 = shape.get<uint32_t>(PR_MESSAGE_FLAGS))) {
		IsSubmitted = *v32 & MSGFLAG_SUBMITTED;
		IsDraft = *v32 & MSGFLAG_UNSENT;
		IsFromMe = *v32 & MSGFLAG_FROMME;
		IsResend = *v32 & MSGFLAG_RESEND;
		IsUnmodified = *v32 & MSGFLAG_UNMODIFIED;
	}
	fromProp(shape.get(PR_MESSAGE_SIZE), Size);
	if ((prop = shape.get(PR_PARENT_ENTRYID)))
		fromProp(prop, defaulted(ParentFolderId).Id);
	if ((v32 = shape.get<uint32_t>(PR_SENSITIVITY)))
		Sensitivity = *v32 == SENSITIVITY_PRIVATE ? Enum::Private :
		              *v32 == SENSITIVITY_COMPANY_CONFIDENTIAL ? Enum::Confidential :
		              *v32 == SENSITIVITY_PERSONAL ? Enum::Personal : Enum::Normal;
	fromProp(shape.get(PR_SUBJECT), Subject);
	if ((prop = shape.get(PR_TRANSPORT_MESSAGE_HEADERS)))
		InternetMessageHeaders.emplace(tInternetMessageHeader::parse(static_cast<const char*>(prop->pvalue)));
	if ((prop = shape.get(NtCategories)) && PROP_TYPE(prop->proptag) == PT_MV_UNICODE) {
		const STRING_ARRAY* categories = static_cast<const STRING_ARRAY*>(prop->pvalue);
		Categories.emplace(categories->count);
		char** src = categories->ppstr;
		for (std::string& dest : *Categories)
			dest = *src++;
	}
	if ((prop = shape.get(NtReminderTime)))
		ReminderDueBy.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
	fromProp(shape.get(NtReminderSet), ReminderIsSet);
	fromProp(shape.get(NtReminderDelta), ReminderMinutesBeforeStart);
	if ((v32 = shape.get<uint32_t>(PR_FLAG_STATUS))) {
		defaulted(Flag).FlagStatus = *v32 == followupComplete ? Enum::Complete : Enum::Flagged;
		if ((prop = shape.get(NtTaskDateCompleted)))
			defaulted(Flag).CompleteDate.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
		if ((prop = shape.get(NtTaskDueDate)))
			defaulted(Flag).DueDate.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
		if ((prop = shape.get(NtTaskStartDate)))
			defaulted(Flag).StartDate.emplace(rop_util_nttime_to_unix2(*static_cast<const uint64_t*>(prop->pvalue)));
	} else {
		defaulted(Flag).FlagStatus = Enum::NotFlagged;
	}

	shape.putExtended(ExtendedProperty);
};

sItem tItem::create(const sShape& shape)
{
	const char* itemClass = shape.get<char>(PR_MESSAGE_CLASS, sShape::FL_ANY);
	if (!itemClass)
		return tItem(shape);
	if (class_match_prefix(itemClass, "IPM.Note") == 0 ||
	    class_match_prefix(itemClass, "IPM.StickyNote") == 0 ||
	    class_match_prefix(itemClass, "REPORT.IPM") == 0)
		return tMessage(shape);
	else if (class_match_prefix(itemClass, "IPM.Appointment") == 0)
		return tCalendarItem(shape);
	else if (class_match_prefix(itemClass, "IPM.Contact") == 0)
		return tContact(shape);
	else if (class_match_prefix(itemClass, "IPM.Task") == 0)
		return tTask(shape);
	else if (class_match_prefix(itemClass, "IPM.Schedule.Meeting.Canceled") == 0)
		return tMeetingCancellationMessage(shape);
	else if (class_match_prefix(itemClass, "IPM.Schedule.Meeting.Request") == 0)
		return tMeetingRequestMessage(shape);
	else if (class_match_prefix(itemClass, "IPM.Schedule.Meeting.Resp") == 0)
		return tMeetingResponseMessage(shape);
	return tItem(shape);
}

///////////////////////////////////////////////////////////////////////////////

decltype(tItemResponseShape::namedTagsDefault) tItemResponseShape::namedTagsDefault = {{
	{&NtCommonStart, PT_SYSTIME},
	{&NtCommonEnd, PT_SYSTIME},
	{&NtEmailAddress1, PT_UNICODE},
	{&NtEmailAddress2, PT_UNICODE},
	{&NtEmailAddress3, PT_UNICODE},
}};

/**
 * @brief     Collect property tags and names for folder shape

 * @param     shape   Shape to store tags in
 */
void tItemResponseShape::tags(sShape& shape) const
{

	for (uint32_t tag : tagsStructural)
		shape.add(tag);
	for (uint32_t tag : tagsIdOnly)
		shape.add(tag, sShape::FL_FIELD);
	std::string_view type = BodyType ? *BodyType : Enum::Best;
	if ((IncludeMimeContent && *IncludeMimeContent) || (BodyType && type == Enum::Best))
		shape.special |= sShape::MimeContent;
	if (AdditionalProperties)
		for (const auto& additional : *AdditionalProperties)
			additional.tags(shape);
	if (shape.special & sShape::Body) {
		if (type == Enum::Best || type == Enum::Text)
			shape.add(PR_BODY, sShape::FL_FIELD);
		if (type == Enum::Best || type == Enum::HTML)
			shape.add(PR_HTML, sShape::FL_FIELD).add(PR_INTERNET_CPID);
		shape.special &= ~sShape::Body;
	}
	if (shape.special & sShape::MessageFlags) {
		shape.add(PR_MESSAGE_FLAGS, sShape::FL_FIELD);
		shape.special &= ~sShape::MessageFlags;
	}
	size_t baseShape = BaseShape.index();
	if (baseShape >= 1) {
		for (uint32_t tag : tagsDefault)
			shape.add(tag, sShape::FL_FIELD);
		for (const auto& named : namedTagsDefault)
			shape.add(*named.first, named.second, sShape::FL_FIELD);
	}
}

///////////////////////////////////////////////////////////////////////////////

tMessage::tMessage(const sShape& shape) : tItem(shape)
{
	tMessage::update(shape);
}

void tMessage::update(const sShape& shape)
{
	const TAGGED_PROPVAL* prop;
	fromProp(shape.get(PR_CONVERSATION_INDEX), ConversationIndex);
	fromProp(shape.get(PR_CONVERSATION_TOPIC), ConversationTopic);
	fromProp(shape.get(PR_INTERNET_MESSAGE_ID), InternetMessageId);
	fromProp(shape.get(PR_INTERNET_REFERENCES), References);
	fromProp(shape.get(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED), IsDeliveryReceiptRequested);
	if ((prop = shape.get(PR_RCVD_REPRESENTING_ADDRTYPE)))
		fromProp(prop, defaulted(ReceivedRepresenting).Mailbox.RoutingType);
	if ((prop = shape.get(PR_RCVD_REPRESENTING_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(ReceivedRepresenting).Mailbox.EmailAddress);
	if ((prop = shape.get(PR_RCVD_REPRESENTING_NAME)))
		fromProp(prop, defaulted(ReceivedRepresenting).Mailbox.Name);
	fromProp(shape.get(PR_READ), IsRead);
	fromProp(shape.get(PR_READ_RECEIPT_REQUESTED), IsReadReceiptRequested);
	if ((prop = shape.get(PR_RECEIVED_BY_ADDRTYPE)))
		fromProp(prop, defaulted(ReceivedBy).Mailbox.RoutingType);
	if ((prop = shape.get(PR_RECEIVED_BY_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(ReceivedBy).Mailbox.EmailAddress);
	if ((prop = shape.get(PR_RECEIVED_BY_NAME)))
		fromProp(prop, defaulted(ReceivedBy).Mailbox.Name);
	if ((prop = shape.get(PR_SENDER_ADDRTYPE)))
		fromProp(prop, defaulted(Sender).Mailbox.RoutingType);
	if ((prop = shape.get(PR_SENDER_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(Sender).Mailbox.EmailAddress);
	if ((prop = shape.get(PR_SENDER_NAME)))
		fromProp(prop, defaulted(Sender).Mailbox.Name);
	if ((prop = shape.get(PR_SENT_REPRESENTING_ADDRTYPE)))
		fromProp(prop, defaulted(From).Mailbox.RoutingType);
	if ((prop = shape.get(PR_SENT_REPRESENTING_EMAIL_ADDRESS)))
		fromProp(prop, defaulted(From).Mailbox.EmailAddress);
	if ((prop = shape.get(PR_SENT_REPRESENTING_NAME)))
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
{
	return std::visit([&](auto &&v) { return v.tags(shape, add); }, asVariant());
}

/**
 * @brief     Get first tag specified by the path
 *
 * In most cases a path maps to exactly one tag,
 * for the other cases only the first mapped tag is returned.
 * Automatically tries to resolve named properties to the correct tag.
 *
 * @param      getId   Function to resolve property name
 *
 * @return    Tag or 0 if not found
 */
uint32_t tPath::tag(const sGetNameId& getId) const
{
	return std::visit([&](auto &&v) { return v.tag(getId); }, asVariant());
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      List of pre-defined profiles
 *
 * Index maps directly to Enum::PermissionLevelType/Enum::CalendarPermissionLevelType,
 * except for Enum::Custom.
 */
decltype(tBasePermission::profileTable) tBasePermission::profileTable = {
	0,
	frightsOwner,
	rightsPublishingEditor,
	rightsEditor,
	rightsPublishingAuthor,
	rightsAuthor,
	rightsNoneditingAuthor,
	rightsReviewer,
	rightsContributor,
	frightsFreeBusySimple,
	frightsFreeBusyDetailed,
};

/**
 * @brief      Create permission from properties
 *
 * The properties `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and
 * `PR_SMTP_ADDRESS` are expected.
 *
 * @param      props   Single row from the permission table
 */
tBasePermission::tBasePermission(const TPROPVAL_ARRAY& props)
{
	auto memberId = props.get<const uint32_t>(PR_MEMBER_ID);
	if (memberId && *memberId == 0) {
		UserId.DistinguishedUser = Enum::Default;
	} else if (memberId && *memberId == U_ANON) {
		UserId.DistinguishedUser = Enum::Anonymous;
	} else {
		fromProp(props.find(PR_SMTP_ADDRESS), UserId.PrimarySmtpAddress);
		fromProp(props.find(PR_MEMBER_NAME), UserId.DisplayName);
	}
	static constexpr uint32_t none = 0;
	auto rights = props.get<const uint32_t>(PR_MEMBER_RIGHTS);
	if (!rights)
		rights = &none;
	CanCreateItems.emplace(*rights & frightsCreate);
	CanCreateSubFolders.emplace(*rights & frightsCreateSubfolder);
	IsFolderOwner.emplace(*rights & frightsOwner);
	IsFolderVisible.emplace(*rights & frightsVisible);
	IsFolderContact.emplace(*rights & frightsContact);
	EditItems.emplace(*rights & frightsEditAny ? Enum::All :
	                  *rights & frightsEditOwned ? Enum::Owned : Enum::None);
	DeleteItems.emplace(*rights & frightsDeleteAny ? Enum::All :
	                    *rights & frightsDeleteOwned ? Enum::Owned : Enum::None);
}


/**
 * @brief      Generate permission information
 *
 * @param      rights  Instance specific basic rights
 *
 * @return     PERMISSION_DATA struct representing the permission
 */
PERMISSION_DATA tBasePermission::write(uint32_t rights) const
{
	auto updateIf = [&](const std::optional<bool>& s, uint32_t f) {
	                	if (!s)
	                		return;
	                	if (*s)
	                		rights |= f;
	                	else
	                		rights &= ~f;
	                };
	updateIf(CanCreateItems, frightsCreate);
	updateIf(CanCreateSubFolders, frightsCreateSubfolder);
	updateIf(IsFolderOwner, frightsOwner);
	updateIf(IsFolderVisible, frightsVisible);
	updateIf(IsFolderContact, frightsContact);
	if (EditItems)
		rights |= *EditItems == Enum::All ? frightsEditAny :
		          *EditItems == Enum::Owned ? frightsEditOwned : 0;
	if (DeleteItems)
		rights |= *DeleteItems == Enum::All ? frightsDeleteAny :
		          *DeleteItems == Enum::Owned ? frightsDeleteOwned : 0;

	PERMISSION_DATA perm{UserId.DistinguishedUser ? ROW_MODIFY : ROW_ADD,
		                 TPROPVAL_ARRAY{0, EWSContext::alloc<TAGGED_PROPVAL>(3)}};
	uint16_t& count = perm.propvals.count;
	perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_MEMBER_RIGHTS, EWSContext::construct<uint32_t>(rights)};
	if (UserId.DistinguishedUser) {
		const uint32_t *memberId = *UserId.DistinguishedUser == Enum::Anonymous ? &U_ANON : &U_DEFAULT;
		perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_MEMBER_ID, const_cast<uint32_t*>(memberId)};
		return perm;
	}
	if (UserId.DisplayName)
		perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_MEMBER_NAME, EWSContext::cpystr(*UserId.DisplayName)};
	if (UserId.PrimarySmtpAddress)
		perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_SMTP_ADDRESS, EWSContext::cpystr(*UserId.PrimarySmtpAddress)};
	return perm;
}

/**
 * @brief      Create permission from properties
 *
 * The properties `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and
 * `PR_SMTP_ADDRESS` are expected.
 *
 * @param      props   Single row from the permission table
 */
tCalendarPermission::tCalendarPermission(const TPROPVAL_ARRAY& props) : tBasePermission(props)
{
	static constexpr uint32_t none = 0;
	auto rights = props.get<const uint32_t>(PR_MEMBER_RIGHTS);
	if (!rights)
		rights = &none;
	ReadItems.emplace(*rights & frightsReadAny ? Enum::FullDetails :
	                  *rights & frightsFreeBusyDetailed ? Enum::FreeBusyTimeAndSubjectAndLocation :
	                  *rights & frightsFreeBusySimple ? Enum::TimeOnly :Enum::None);
	auto it = std::find(profileTable.begin(), profileTable.end(), *rights);
	size_t index = std::distance(profileTable.begin(), it);
	if (index < calendarProfiles)
		CalendarPermissionLevel = static_cast<uint8_t>(index);
	else
		CalendarPermissionLevel = Enum::Custom;
}


/**
 * @brief      Generate permission information
 *
 * @return     PERMISSION_DATA struct representing the permission
 */
PERMISSION_DATA tCalendarPermission::write() const
{
	uint32_t rights = CalendarPermissionLevel == Enum::Custom ?
	                  0 : profileTable[CalendarPermissionLevel.index()];
	if (ReadItems)
		rights |= *ReadItems == Enum::FullDetails ? frightsReadAny : 0;
	return tBasePermission::write(rights);
}

/**
 * @brief      Create permission from properties
 *
 * The properties `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and
 * `PR_SMTP_ADDRESS` are expected.
 *
 * @param      props   Single row from the permission table
 */
tPermission::tPermission(const TPROPVAL_ARRAY& props) : tBasePermission(props)
{
	static constexpr uint32_t none = 0;
	auto rights = props.get<const uint32_t>(PR_MEMBER_RIGHTS);
	if (!rights)
		rights = &none;
	ReadItems.emplace(*rights & frightsReadAny ? Enum::FullDetails : Enum::None);
	auto it = std::find(profileTable.begin(), profileTable.end(), *rights);
	size_t index = std::distance(profileTable.begin(), it);
	if (index < profiles)
		PermissionLevel = static_cast<uint8_t>(index);
	else
		PermissionLevel = Enum::Custom;
}

/**
 * @brief      Generate permission information
 *
 * @return     PERMISSION_DATA struct representing the permission
 */
PERMISSION_DATA tPermission::write() const
{
	uint32_t rights = PermissionLevel == Enum::Custom ?
	                  0 : profileTable[PermissionLevel.index()];
	if (ReadItems)
		rights |= *ReadItems == Enum::FullDetails ? frightsReadAny : 0;
	return tBasePermission::write(rights);
}

/**
 * @brief      Create permission set from property table
 *
 * The properties `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and
 * `PR_SMTP_ADDRESS` are expected to be contained in the table.
 *
 * @param      propTable   Permission table
 */
tPermissionSet::tPermissionSet(const TARRAY_SET& propTable)
{
	Permissions.reserve(propTable.count);
	for (const TPROPVAL_ARRAY& props : propTable)
		Permissions.emplace_back(props);
}

/**
 * @brief      Generate list of permissions to write to exmdb
 *
 * @return     List of PERMISSION_DATA structures
 */
std::vector<PERMISSION_DATA> tPermissionSet::write() const
{
	std::vector<PERMISSION_DATA> res;
	res.reserve(Permissions.size());
	std::transform(Permissions.begin(), Permissions.end(), std::back_inserter(res),
	               [](const tPermission& perm){return perm.write();});
	return res;
}

/**
 * @brief      Create permission set from property table
 *
 * The properties `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and
 * `PR_SMTP_ADDRESS` are expected to be contained in the table.
 *
 * @param      propTable   Permission table
 */
tCalendarPermissionSet::tCalendarPermissionSet(const TARRAY_SET& propTable)
{
	CalendarPermissions.reserve(propTable.count);
	for (const TPROPVAL_ARRAY& props : propTable)
		CalendarPermissions.emplace_back(props);
}

/**
 * @brief      Generate list of permissions to write to exmdb
 *
 * @return     List of PERMISSION_DATA structures
 */
std::vector<PERMISSION_DATA> tCalendarPermissionSet::write() const
{
	std::vector<PERMISSION_DATA> res;
	res.reserve(CalendarPermissions.size());
	std::transform(CalendarPermissions.begin(), CalendarPermissions.end(), std::back_inserter(res),
	               [](const tCalendarPermission& perm){return perm.write();});
	return res;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Calculate time zone offset for time point
 *
 * @param      tp      Time point to calculate offset for
 *
 * @return     Offset in minutes
 */
std::chrono::minutes tSerializableTimeZone::offset(time_point tp) const
{
	if (!hasDst())
		return std::chrono::minutes(Bias);
	auto temp = clock::to_time_t(tp) - Bias * 60;
	tm datetime;
	if (gmtime_r(&temp, &datetime) == nullptr)
		datetime = {};

	auto &first  = StandardTime.Month < DaylightTime.Month ? StandardTime : DaylightTime;
	auto &second = StandardTime.Month < DaylightTime.Month ? DaylightTime : StandardTime;

	int firstDO    = first.DayOrder == 5 ? -1 : static_cast<int>(first.DayOrder);
	int secondDO   = second.DayOrder == 5 ? -1 : static_cast<int>(second.DayOrder);
	int firstMday  = ical_get_dayofmonth(datetime.tm_year + 1900,
	                 first.Month, firstDO, static_cast<int>(first.DayOfWeek.index()));
	int secondMday = ical_get_dayofmonth(datetime.tm_year + 1900,
	                 second.Month, secondDO, static_cast<int>(second.DayOfWeek.index()));

	int64_t dStamp = static_cast<int64_t>(datetime.tm_sec) + datetime.tm_min * 60 +
	                 datetime.tm_hour * 3600 + datetime.tm_mday * 86400 +
	                 (datetime.tm_mon + 1) * 2678400;
	int64_t fStamp = static_cast<int64_t>(first.Time.second) + first.Time.minute * 60 +
	                 first.Time.hour * 3600 + firstMday * 86400 +
	                 first.Month * 2678400;
	int64_t sStamp = static_cast<int64_t>(second.Time.second) + second.Time.minute * 60 +
	                 second.Time.hour * 3600 + secondMday * 86400 +
	                 second.Month * 2678400;

	int bias = dStamp < fStamp || dStamp >= sStamp ? second.Bias : first.Bias;
	return std::chrono::minutes(Bias + bias);
}

/**
 * @brief      Convert from UTC to timezone
 *
 * @param      tp     Time point to convert
 *
 * @return     Adjusted time point
 */
EWS::time_point tSerializableTimeZone::apply(EWS::time_point tp) const
{
	return tp + offset(tp);
}

/**
 * @brief      Convert from UTC to timezone
 *
 * @param      tp     Time point to convert
 *
 * @return     Adjusted time point
 */
EWS::time_point tSerializableTimeZone::remove(EWS::time_point tp) const
{
	return tp - offset(tp);
}

/**
 * @brief      Check whether timezones change throughout the year
 *
 * @return     true iff both specifications are valid
 */
bool tSerializableTimeZone::hasDst() const
{
	return StandardTime.valid() && DaylightTime.valid();
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief     Check if all contained values are in the correct range
 *
 * @return    true iff specification is valid
 */
bool tSerializableTimeZoneTime::valid() const
{
	return Time.hour < 24 && Time.minute < 60 && Time.second < 60 && DayOrder >= 1 && DayOrder <= 5 &&
	       Month >= 1 && Month <= 12;
}

///////////////////////////////////////////////////////////////////////////////

/**
 * @brief      Write property to shape
 *
 * @param      shape  Shape to write property to
 */
void tSetFolderField::put(sShape& shape) const
{
	const XMLElement* child = folder->FirstChildElement();
	if (!child)
		throw EWSError::InvalidExtendedPropertyValue(E3178);
	if (!strcmp(child->Name(), "ExtendedProperty")) {
		tExtendedProperty prop(child);
		if (prop.ExtendedFieldURI.tag())
			shape.write(prop.propval);
		else
			shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	} else {
		convProp(folder->Name(), child->Name(), child, shape);
	}
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
	if (!child)
		throw EWSError::InvalidExtendedPropertyValue(E3108);
	if (!strcmp(child->Name(), "ExtendedProperty")) {
		tExtendedProperty prop(child);
		if (prop.ExtendedFieldURI.tag())
			shape.write(prop.propval);
		else
			shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	} else if (std::holds_alternative<tIndexedFieldURI>(fieldURI.asVariant())) {
		const tIndexedFieldURI& uri = std::get<tIndexedFieldURI>(fieldURI.asVariant());
		auto getId = [&shape](const PROPERTY_NAME& name){return PROP_ID(shape.tag(name));};
		uint32_t tag = uri.tag(getId);
		if (!tag) {
			mlog(LV_WARN, "ews: failed to resolve indexed property %s/%s", uri.FieldURI.c_str(), uri.FieldIndex.c_str());
			return;
		} else if (PROP_TYPE(tag) != PT_UNICODE) {
			/* All currently known indexed fields are text */
			mlog(LV_WARN, "ews: unsupported indexed property type for %s/%s", uri.FieldURI.c_str(), uri.FieldIndex.c_str());
			return;
		}
		const tinyxml2::XMLElement* value = item;
		// The value is contained in the lower most text node. The XML path is ignored.
		for (const tinyxml2::XMLElement *temp= item->FirstChildElement();
		     temp != nullptr; temp = temp->FirstChildElement())
			value = temp;
		const char*	text = value->GetText(); // Life time of the XML node exceeds shape, no need to copy value
		shape.write(TAGGED_PROPVAL{tag, const_cast<char *>(znul(text))});
	} else {
		convProp(item->Name(), child->Name(), child, shape);
	}
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

tSyncFolderItemsDelete::tSyncFolderItemsDelete(const sBase64Binary& meid) : ItemId(meid, tItemId::ID_ITEM)
{}

///////////////////////////////////////////////////////////////////////////////

tTargetFolderIdType::tTargetFolderIdType(sFolderId&& id) :
    FolderId(std::move(id))
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
