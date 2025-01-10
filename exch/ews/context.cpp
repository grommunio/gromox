// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cctype>
#include <fmt/core.h>
#include <sstream>

#include <libHX/string.h>

#include <gromox/rop_util.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/scope.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>

#include "exceptions.hpp"
#include "ews.hpp"
#include "namedtags.hpp"
#include "structures.hpp"

DECLARE_HPM_API(gromox::EWS, extern);

namespace gromox::EWS
{

using namespace Exceptions;
using namespace Structures;

namespace
{

/**
 * @brief      Convert string to lower case
 *
 * @param      str     String to convert
 *
 * @return     Reference to the string
 */
inline std::string &tolower(std::string &str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);
	return str;
}

/**
 * @brief      Checks if two dates are on the same day
 *
 * @param      tm    First time point
 * @param      tm    Second time point
 *
 * @return     true if both time points are on the same day, false otherwise
 */
inline bool is_same_day(const tm& date1, const tm& date2)
{return date1.tm_year == date2.tm_year && date1.tm_yday == date2.tm_yday;}

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
 * @brief      Write property to shape (string specialization)
 *
 * @param      shape   Shape to write to
 * @param      value   value to write
 * @param      tag     Property tag to use
 */
void writeProp(sShape& shape, const std::optional<std::string>& value, uint32_t tag)
{if(value) shape.write(TAGGED_PROPVAL{tag, const_cast<char*>(value->c_str())});}

/**
 * @brief      Write property to shape (time point specialization)
 *
 * @param      shape   Shape to write to
 * @param      value   value to write
 * @param      tag     Property tag to use
 */
void writeProp(sShape& shape, const std::optional<sTimePoint>& value, uint32_t tag)
{if(value) shape.write(TAGGED_PROPVAL{tag, EWSContext::construct<uint64_t>(value->toNT())});}

/**
 * @brief      Write property to shape (string specialization)
 *
 * @param      shape   Shape to write to
 * @param      value   value to write
 * @param      name    Property name to write to
 * @param      type    Property type to use
 */
void writeProp(sShape& shape, const std::optional<std::string>& value, const PROPERTY_NAME& name, uint16_t type)
{if(value) shape.write(name, TAGGED_PROPVAL{type, const_cast<char*>(value->c_str())});}

/**
 * @brief      Convert string week day representation to a pattern type
 * specific bit mask
 *
 * @param daysOfWeek
 * @param weekrecur
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
void daysofweek_to_pts(const std::string& daysOfWeek, uint32_t& weekrecur)
{
	std::istringstream strstream(daysOfWeek);
	std::string dayOfWeek;

	while(strstream >> dayOfWeek) {
		tolower(dayOfWeek);
		if(dayOfWeek == "day") {
			weekrecur = 0x7F;
			break;
		}
		else if(dayOfWeek == "weekday") {
			weekrecur = 0x3E;
			break;
		}
		else if(dayOfWeek == "weekendday") {
			weekrecur = 0x41;
			break;
		}
		else if(dayOfWeek == "sunday")
			weekrecur |= 1 << FIRSTDOW_SUNDAY;
		else if(dayOfWeek == "monday")
			weekrecur |= 1 << FIRSTDOW_MONDAY;
		else if(dayOfWeek ==  "tuesday")
			weekrecur |= 1 << FIRSTDOW_TUESDAY;
		else if(dayOfWeek == "wednesday")
			weekrecur |= 1 << FIRSTDOW_WEDNESDAY;
		else if(dayOfWeek == "thursday")
			weekrecur |= 1 << FIRSTDOW_THURSDAY;
		else if(dayOfWeek == "friday")
			weekrecur |= 1 << FIRSTDOW_FRIDAY;
		else if(dayOfWeek == "saturday")
			weekrecur |= 1 << FIRSTDOW_SATURDAY;
		else
			throw EWSError::CalendarInvalidRecurrence(E3260);
	}
}

/**
 * @brief Calculate the first ever day, week, or month of a recurring series
 *
 * @param recur_pat
 * @param tmp_tm
 */
void calc_firstdatetime(RECURRENCE_PATTERN &recur_pat, tm* tmp_tm)
{
	switch(recur_pat.patterntype) {
	case rptMinute:
		recur_pat.firstdatetime = recur_pat.startdate % recur_pat.period;
		break;
	case rptWeek: {
		// determine the first day of the week in which the first event occurrs
		auto startdate = rop_util_rtime_to_unix(recur_pat.startdate);
		if(gmtime_r(&startdate, tmp_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3261);
		auto weekstart = rop_util_unix_to_rtime(
			 startdate - ((tmp_tm->tm_wday - recur_pat.firstdow + 7) % 7) * 86400);
		recur_pat.firstdatetime = weekstart % (10080 * recur_pat.period);
		break;
	}
	case rptMonth:
	case rptMonthNth: {
		recur_pat.firstdatetime = 0;
		int fdt = ((((12 % recur_pat.period) * ((tmp_tm->tm_year + 299) % recur_pat.period)) % recur_pat.period) + tmp_tm->tm_mon) % recur_pat.period;
			for (int i = 0; i < fdt; ++i)
				// minutes in month
				recur_pat.firstdatetime += ical_get_monthdays(1601 + (i / 12), (i % 12) + 1) * 1440;
		break;
	}
	}
}

/**
 * @brief Calculate the number of days per week that an occurrence occurs
 *
 * @param weekrecur
 * @return uint8_t
 */
uint8_t calc_daycount(uint32_t weekrecur)
{
	uint8_t daycount = 0;
	while(weekrecur) {
		daycount += weekrecur & 1;
		weekrecur >>= 1;
	}
	return daycount;
}

/**
 * @brief Calculate the ending date for the recurrence
 *
 * @param recur_pat
 * @param tmp_tm
 */
void calc_enddate(RECURRENCE_PATTERN &recur_pat, tm* tmp_tm)
{
	time_t enddate = rop_util_rtime_to_unix(recur_pat.startdate);
	// forwardcount is the number of occurrences we can skip and still
	// be inside the recurrence range (minus one to make sure there is
	// always at least one occurrence left)
	uint32_t forwardcount = 0;
	switch(recur_pat.recurfrequency) {
	case IDC_RCEV_PAT_ORB_DAILY:
		if (recur_pat.patterntype == rptMinute)
			// occurrencecount - 1 because the first day already counts
			enddate += recur_pat.period * 60 * (recur_pat.occurrencecount - 1);
		break;
	case IDC_RCEV_PAT_ORB_WEEKLY: {
		uint8_t daycount = calc_daycount(recur_pat.pts.weekrecur);
		if(daycount == 0)
			throw EWSError::CalendarInvalidRecurrence(E3282);
		forwardcount = (recur_pat.occurrencecount - 1) / daycount;
		// number of remaining occurrences after the week skip
		uint32_t restocc = recur_pat.occurrencecount - forwardcount * daycount - 1;
		forwardcount *= recur_pat.period;
		enddate += forwardcount * 604800; // seconds in a week
		if(gmtime_r(&enddate, tmp_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3262);
		for(int j = 1; restocc > 0; ++j) {
			if((tmp_tm->tm_wday + j) % 7 == (int) recur_pat.firstdow)
				enddate += (recur_pat.period - 1) * 604800;
			// If this is a matching day, one occurrence less to process
			if(recur_pat.pts.weekrecur & (1 << ((tmp_tm->tm_wday + j) % 7)))
				--restocc;
			// Next day
			enddate += 86400;
		}
		break;
	}
	case IDC_RCEV_PAT_ORB_MONTHLY:
	case IDC_RCEV_PAT_ORB_YEARLY:
		forwardcount = (recur_pat.occurrencecount - 1) * recur_pat.period;
		auto curyear = tmp_tm->tm_year + 1900;
		auto curmonth = tmp_tm->tm_mon;
		while(forwardcount > 0) {
			// month in seconds
			enddate += ical_get_monthdays(curyear, curmonth) * 86400;
			if(curmonth >= 12) {
				curmonth = 1;
				++curyear;
			}
			else {
				++curmonth;
			}
			--forwardcount;
		}
		if(gmtime_r(&enddate, tmp_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3263);
		tmp_tm->tm_year += 1900;
		++tmp_tm->tm_mon;

		switch(recur_pat.patterntype) {
		case rptMonth:
			// compensation between 28 and 31
			if (recur_pat.pts.dayofmonth >= 28 &&
					recur_pat.pts.dayofmonth <= 31 &&
					tmp_tm->tm_mday < (int)recur_pat.pts.dayofmonth) {
				if (tmp_tm->tm_mday < 28)
					enddate -= tmp_tm->tm_mday * 86400;
				else
					enddate += (ical_get_monthdays(tmp_tm->tm_year, tmp_tm->tm_mon) - tmp_tm->tm_mday) * 86400;
			}
			break;
		case rptMonthNth:
			if(recur_pat.pts.monthnth.recurnum == 5)
				// Set date on the last day of the last month
				enddate += (ical_get_monthdays(tmp_tm->tm_year, tmp_tm->tm_mon) - tmp_tm->tm_mday) * 86400;
			else
				// Set date on the first day of the last month
				enddate -= (tmp_tm->tm_mday - 1) * 86400;

			// calculate the day of the last occurrence
			for(int j = 0; j < 7; ++j) {
				if(gmtime_r(&enddate, tmp_tm) == nullptr)
					throw EWSError::CalendarInvalidRecurrence(E3264);
				if(recur_pat.pts.monthnth.recurnum == 5 &&
				  (1 << (tmp_tm->tm_wday - j) % 7) & recur_pat.pts.monthnth.weekrecur)
					enddate -= j * 86400;
				else if(recur_pat.pts.monthnth.recurnum != 5 &&
				       (1 << (tmp_tm->tm_wday + j) % 7) & recur_pat.pts.monthnth.weekrecur)
					enddate += (j + ((recur_pat.pts.monthnth.recurnum - 1) * 7)) * 86400;
			}
			break;
		}
		break;
	}
	recur_pat.enddate = rop_util_unix_to_rtime(enddate);
}

/**
 * @brief Return the active timezone definition rule for a given year
 *
 * @param tzdef
 * @param year
 * @return TZRULE*
 */
TZRULE* active_rule_for_year(const TIMEZONEDEFINITION* tzdef, const int year)
{
	for(auto i = tzdef->crules - 1; i >= 0; --i)
	{
		if(((tzdef->prules[i].flags & TZRULE_FLAG_EFFECTIVE_TZREG) &&
		     tzdef->prules[i].year <= year) ||
		    tzdef->prules[i].year == year)
			return &tzdef->prules[i];
	}
	return nullptr;
}

/**
 * @brief Calculate the start of daylight saving oder standard time
 *
 * @param year
 * @param ruledate
 * @return time_t
 */
time_t timegm_dststd_start(const int year, const SYSTEMTIME* ruledate)
{
	struct tm tempTm;
	tempTm.tm_year = year;
	tempTm.tm_mon = ruledate->month - 1;
	tempTm.tm_mday = ical_get_dayofmonth(year + 1900, ruledate->month, ruledate->day == 5 ? -1 : ruledate->day, ruledate->dayofweek);
	tempTm.tm_hour = ruledate->hour;
	tempTm.tm_min = ruledate->minute;
	tempTm.tm_sec = ruledate->second;
	tempTm.tm_isdst = 0;
	return timegm(&tempTm);
}

/**
 * @brief Calculate the offset from UTC from the timezone definition
 *
 * @param tzdef
 * @param startTime
 */
int64_t offset_from_tz(const TIMEZONEDEFINITION* tzdef, const time_t startTime)
{
	int64_t offset = 0;
	struct tm startDateUtc;
	gmtime_r(&startTime, &startDateUtc);
	int startDateYear = startDateUtc.tm_year + 1900;
	TZRULE *rule = active_rule_for_year(tzdef, startDateYear);
	if(rule == nullptr)
		throw EWSError::TimeZone(E3295(startDateYear));

	offset = rule->bias;
	if(rule->standarddate.month != 0 && rule->daylightdate.month != 0)
	{
		// convert all times to UTC for comparison
		time_t stdStartTime = timegm_dststd_start(startDateUtc.tm_year, &rule->standarddate) + offset * 60;
		time_t dstStartTime = timegm_dststd_start(startDateUtc.tm_year, &rule->daylightdate) + offset * 60;
		auto utcStartTime = startTime + offset * 60;

		if((dstStartTime <= stdStartTime && utcStartTime >= dstStartTime && utcStartTime < stdStartTime) || // northern hemisphere dst
			(dstStartTime > stdStartTime && (utcStartTime < stdStartTime || utcStartTime > dstStartTime))) // southern hemisphere dst
		{
			offset += rule->daylightbias;
		}
	}
	return offset;
}

/**
 * @brief Get GlobalObjectId(PidLidGlobalObjectId/PidLidCleanGlobalObjectId)
 *        from UID sent by the client
 *
 * @param uid
 * @param goid_bin
 */
void uid_to_goid(const char* uid, BINARY &goid_bin)
{
	GLOBALOBJECTID goid;
	auto uid_len = strlen(uid);
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	char tmp_buff[1024];
	if(strncasecmp(uid, EncodedGlobalId_hex, 32) == 0)
	{
		if(!decode_hex_binary(uid, tmp_buff, std::size(tmp_buff)))
			throw EWSError::CorruptData(E3296(uid));
		ext_pull.init(tmp_buff, uid_len / 2, EWSContext::alloc, 0);
		if(ext_pull.g_goid(&goid) != EXT_ERR_SUCCESS)
			throw EWSError::InternalServerError(E3297(uid));
		if(ext_pull.m_offset == uid_len / 2 &&
		    (goid.year < 1601 || goid.year > 4500 ||
		    goid.month > 12 || goid.month == 0 ||
		    goid.day > ical_get_monthdays(goid.year, goid.month)))
			goid.year = goid.month = goid.day = 0;
	}
	else
	{
		memset(&goid, 0, sizeof(GLOBALOBJECTID));
		goid.arrayid = EncodedGlobalId;
		goid.year = goid.month = goid.day = 0;
		goid.creationtime = 0;
		goid.data.cb = 12 + uid_len;
		goid.data.pv = EWSContext::alloc(goid.data.cb);
		if(goid.data.pv == nullptr)
			throw EWSError::NotEnoughMemory(E3298);
		static_assert(sizeof(ThirdPartyGlobalId) == 12);
		memcpy(goid.data.pb, ThirdPartyGlobalId, 12);
		memcpy(goid.data.pb + 12, uid, uid_len);
	}
	if(!ext_push.init(tmp_buff, 1024, 0) ||
		ext_push.p_goid(goid) != EXT_ERR_SUCCESS)
		throw EWSError::InternalServerError(E3299);
	goid_bin.cb = ext_push.m_offset;
	goid_bin.pb = ext_push.m_udata;
}

} // Anonymous namespace

namespace detail
{

void Cleaner::operator()(BINARY* x) {rop_util_free_binary(x);}
void Cleaner::operator()(MESSAGE_CONTENT *x) {message_content_free(x);}

} // gromox::EWS::detail


///////////////////////////////////////////////////////////////////////////////////////////////////

EWSContext::EWSContext(int id, HTTP_AUTH_INFO ai, const char *data, uint64_t length,
    EWSPlugin &p) :
	m_ID(id), m_orig(*get_request(id)), m_auth_info(ai),
	m_request(data, length), m_response(p.server_version()), m_plugin(p),
	m_created(tp_now())
{
	tinyxml2::XMLElement* imp = nullptr;
	if(m_request.header && (imp = m_request.header->FirstChildElement("ExchangeImpersonation")) &&
	   (imp = imp->FirstChildElement("ConnectingSID")) && (imp = imp->FirstChildElement()))
		impersonate(imp->Name(), imp->GetText());
}

EWSContext::~EWSContext()
{
	if(m_notify)
		for (const auto &sub : m_notify->nct_subs)
			unsubscribe(sub);
}

/**
 * @brief      Copy string to context allocated buffer
 *
 * @param      src   Source string
 *
 * @return     Pointer to copied C-string
 */
char* EWSContext::cpystr(const std::string_view& src)
{
	char* dst = alloc<char>(src.size()+1);
	strncpy(dst, src.data(), src.size());
	dst[src.size()] = 0;
	return dst;
}

/**
 * @brief      Create new folder
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder to create folder in
 * @param      folder    Folder object to create
 *
 * @return     Folder object containing FolderId
 */
sFolder EWSContext::create(const std::string& dir, const sFolderSpec& parent, const sFolder& folder) const
{
	sShape shape;
	uint64_t changeNumber;
	if(!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNumber))
		throw DispatchError(E3153);
	const tBaseFolderType& baseFolder = std::visit([](const auto& f) -> const tBaseFolderType&
	                                                 {return static_cast<const tBaseFolderType&>(f);}, folder);
	for(const tExtendedProperty& prop : baseFolder.ExtendedProperty)
		prop.ExtendedFieldURI.tag()? shape.write(prop.propval) : shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	shape.write(TAGGED_PROPVAL{PidTagParentFolderId, deconst(&parent.folderId)});
	const char* fclass = "IPF.Note";
	mapi_folder_type type = FOLDER_GENERIC;
	if(baseFolder.FolderClass)
		fclass = baseFolder.FolderClass->c_str();
	else
		switch(folder.index()) {
		case 1: //CalendarFolder
			fclass = "IPF.Appointment"; break;
		case 2: // ContactsFolder
			fclass = "IPF.Contact"; break;
		case 3: // SearchFolder
			type = FOLDER_SEARCH; break;
		case 4: // TasksFolder
			fclass = "IPF.Task"; break;
		}
	shape.write(TAGGED_PROPVAL{PR_FOLDER_TYPE, &type});
	shape.write(TAGGED_PROPVAL{PR_CONTAINER_CLASS, deconst(fclass)});
	if(baseFolder.DisplayName)
		shape.write(TAGGED_PROPVAL{PR_DISPLAY_NAME, deconst(baseFolder.DisplayName->c_str())});
	uint64_t now = rop_util_current_nttime();
	shape.write(TAGGED_PROPVAL{PR_CREATION_TIME, &now});
	shape.write({PR_LAST_MODIFICATION_TIME, &now});
	shape.write({PidTagChangeNumber, &changeNumber});

	bool isPublic = parent.location == parent.PUBLIC;
	uint32_t accountId = getAccountId(*parent.target, isPublic);
	XID xid((parent.location == parent.PRIVATE? rop_util_make_user_guid : rop_util_make_domain_guid)(accountId), changeNumber);

	BINARY ckey = serialize(xid);
	shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, &ckey});

	auto pcl = mkPCL(xid);
	shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, pcl.get()});

	sFolderSpec created = parent;
	getNamedTags(dir, shape, true);
	TPROPVAL_ARRAY props = shape.write();
	ec_error_t err = ecSuccess;
	if (!m_plugin.exmdb.create_folder(dir.c_str(), CP_ACP, &props,
	    &created.folderId, &err))
		throw EWSError::FolderSave(E3154);
	if (err == ecDuplicateName)
		throw EWSError::FolderExists(E3155);
	if (err != ecSuccess)
		throw EWSError::FolderSave(std::string(E3154) + ": " + mapi_strerror(err));
	if (created.folderId == 0)
		throw EWSError::FolderExists(E3155); // ??

	sShape retshape = sShape(tFolderResponseShape());
	return loadFolder(dir, created.folderId, retshape);
}

/**
 * @brief      Create new item
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder to create item in
 * @param      content   Item content to store
 *
 * @return     Item object containing ItemId
 */
sItem EWSContext::create(const std::string& dir, const sFolderSpec& parent, const MESSAGE_CONTENT& content) const
{
	ec_error_t error;
	auto messageId = content.proplist.get<const uint64_t>(PidTagMid);
	if(!messageId)
		throw DispatchError(E3112);
	if (!m_plugin.exmdb.write_message(dir.c_str(), CP_ACP, parent.folderId,
	    &content, &error) || error)
		throw EWSError::ItemSave(E3254);

	sShape retshape = sShape(tItemResponseShape());
	return loadItem(dir, parent.folderId, *messageId, retshape);
}

/**
 * @brief      Schedule notification stream for closing
 */
void EWSContext::disableEventStream()
{
	if(m_notify)
		m_notify->state = NotificationContext::S_CLOSING;
}

/**
 * @brief      Get effective username for exmdb operations
 *
 * Some exmdb calls do implicit access checks for public folders, in which case
 * a username has to be supplied. For private stores, nullptr has to be given
 * instead.
 *
 * @param       Folder to access
 *
 * @return      username if public folder, nullptr if
 */
const char* EWSContext::effectiveUser(const sFolderSpec& folder) const
{return folder.location == sFolderSpec::PUBLIC? m_auth_info.username : nullptr;}

/**
 * @brief      Initialize notification context
 *
 * @param      timeout   Stream timeout (minutes)
 */
void EWSContext::enableEventStream(int timeout)
{
	m_state = S_STREAM_NOTIFY;
	auto expire = tp_now() + std::chrono::minutes(timeout);
	m_notify = std::make_unique<NotificationContext>(expire);
}

/**
 * @brief     Get user or domain ID by name
 *
 * @param     name       Name to resolve
 * @param     isDomain   Whether target is a domain
 *
 * @return Account ID
 */
uint32_t EWSContext::getAccountId(const std::string& name, bool isDomain) const
{
	uint32_t accountId, unused1;
	display_type unused2;
	BOOL res;
	if(isDomain)
		res = mysql_adaptor_get_domain_ids(name.c_str(), &accountId, &unused1);
	else
		res = mysql_adaptor_get_user_ids(name.c_str(), &accountId, &unused1, &unused2);
	if(!res)
		throw EWSError::CannotFindUser(E3113(isDomain? "domain" : "user", name));
	return accountId;
}

/**
 * @brief      Get named property IDs
 *
 * @param      dir       Home directory of user or domain
 * @param      propNames List of property names to retrieve
 * @param      create Whether to create requested names if necessary
 *
 * @return     Array of property IDs
 */
uint16_t EWSContext::getNamedPropId(const std::string& dir, const PROPERTY_NAME& propName, bool create) const
{
	PROPNAME_ARRAY propNames{1, deconst(&propName)};
	PROPID_ARRAY namedIds{};
	if (!m_plugin.exmdb.get_named_propids(dir.c_str(), create ? TRUE : false,
	    &propNames, &namedIds) || namedIds.size() != 1)
		throw DispatchError(E3246);
	return namedIds[0];
}

/**
 * @brief      Get named property IDs
 *
 * @param      dir       Home directory of user or domain
 * @param      propNames List of property names to retrieve
 * @param      create Whether to create requested names if necessary
 *
 * @return     Array of property IDs
 */
PROPID_ARRAY EWSContext::getNamedPropIds(const std::string& dir, const PROPNAME_ARRAY& propNames, bool create) const
{
	PROPID_ARRAY namedIds{};
	if(!m_plugin.exmdb.get_named_propids(dir.c_str(), create? TRUE : false, &propNames, &namedIds))
		throw DispatchError(E3069);
	return namedIds;
}

/**
 * @brief      Load named tags into shape
 *
 * Immediatly returns if the shape is already associated with the store.
 *
 * @param      dir    Home directory of user or domain
 * @param      shape  Shape to load tags into
 * @param      create Whether to create requested names if necessary
 */
void EWSContext::getNamedTags(const std::string& dir, sShape& shape, bool create) const
{
	if(shape.store == dir)
		return;
	PROPNAME_ARRAY propNames = shape.namedProperties();
	if(propNames.count == 0)
		return;
	PROPID_ARRAY namedIds = getNamedPropIds(dir, propNames, create);
	if (namedIds.size() != propNames.size())
		return;
	shape.namedProperties(namedIds);
	shape.store = dir;
}

/**
 * @brief      Get property name from ID
 *
 * @param      dir     Home directory of user or domain
 * @param      id      Id of the property
 *
 * @return     Property name
 */
PROPERTY_NAME* EWSContext::getPropertyName(const std::string& dir, uint16_t id) const
{
	PROPNAME_ARRAY propnames{};
	if (!m_plugin.exmdb.get_named_propnames(dir.c_str(), {id}, &propnames) ||
	    propnames.size() != 1)
		throw DispatchError(E3070);
	return propnames.ppropname;
}

/**
 * @brief      Convert ESSDN to username
 *
 * @param      essdn   ESSDN to convert
 *
 * @throw      DispatchError   Conversion failed
 *
 * @return     Username
 *
 * @todo       This should probably verify the domain id as well (currently ignored)
 */
std::string EWSContext::essdn_to_username(const std::string& essdn) const
{
	auto id2u = [&](int id, std::string &user) -> ec_error_t {
		char buf[UADDR_SIZE];
		if (!mysql_adaptor_get_username_from_id(id, buf, std::size(buf)))
			throw DispatchError(E3002);
		user = buf;
		return ecSuccess;
	};
	std::string username;
	auto err = gromox::cvt_essdn_to_username(essdn.c_str(),
	           m_plugin.x500_org_name.c_str(), id2u, username);
	if (err == ecSuccess)
		return username;
	if (err == ecUnknownUser)
		throw DispatchError(E3002);
	throw DispatchError(E3003);
}

/**
 * @brief      Assert that experimental mode is enabled
 */
void EWSContext::experimental(const char* name) const
{
	if(!m_plugin.experimental)
		throw UnknownRequestError(E3021(name));
}

/**
 * @brief      Get user maildir from Mailbox speciication
 *
 * @param      Mailbox   Mailbox structure
 *
 * @throw      DispatchError   Could not retrieve maildir
 *
 * @return     Path to the user's maildir
 */
std::string EWSContext::get_maildir(const std::string& username) const
{
	sql_meta_result mres;
	if (mysql_adaptor_meta(username.c_str(), WANTPRIV_METAONLY, mres) != 0)
		throw EWSError::CannotFindUser(E3007);
	return std::move(mres.maildir);
}

/**
 * @brief      Get user maildir from Mailbox speciication
 *
 * @param      Mailbox   Mailbox structure
 *
 * @throw      DispatchError   Could not retrieve maildir
 *
 * @return     Path to the user's maildir
 */
std::string EWSContext::get_maildir(const tMailbox& Mailbox) const
{
	std::string RoutingType = Mailbox.RoutingType.value_or("smtp");
	std::string Address = Mailbox.Address;
	if(tolower(RoutingType) == "ex"){
		Address = essdn_to_username(Address);
		RoutingType = "smtp";
	}
	if(RoutingType == "smtp") {
		sql_meta_result mres;
		if (mysql_adaptor_meta(Address.c_str(), WANTPRIV_METAONLY, mres) != 0)
			throw EWSError::CannotFindUser(E3125);
		return std::move(mres.maildir);
	} else
		throw EWSError::InvalidRoutingType(E3006(RoutingType));
}

/**
 * @brief      Get user or domain maildir from folder spec
 *
 * @param      folder  Folder specification
 *
 * @return     Home directory of user or domain
 */
std::string EWSContext::getDir(const sFolderSpec& folder) const
{
	const char* target = folder.target? folder.target->c_str() : m_auth_info.username;
	const char* at = strchr(target, '@');
	bool isPublic = folder.location == sFolderSpec::AUTO? at == nullptr : folder.location == sFolderSpec::PUBLIC;
	if(isPublic && at)
		target = at+1;
	if (isPublic) {
		char targetDir[256];
		if (!mysql_adaptor_get_homedir(target, targetDir, std::size(targetDir)))
			throw EWSError::CannotFindUser(E3126);
		return targetDir;
	}
	sql_meta_result mres;
	if (mysql_adaptor_meta(target, WANTPRIV_METAONLY, mres) != 0)
		throw EWSError::CannotFindUser(E3126);
	return std::move(mres.maildir);
}

/**
 * @brief      Get cached events from all subscriptions
 *
 * Loads up to 50 cached events as specified in
 * https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/getevents-operation#remarks.
 *
 * @param subscription   Subscription ID
 *
 * @return List of events and indicator whether there are more events
 */
std::pair<std::list<sNotificationEvent>, bool> EWSContext::getEvents(const tSubscriptionId& subscriptionId) const
{
	auto mgr = m_plugin.get_submgr(subscriptionId.ID, subscriptionId.timeout);
	if (mgr == nullptr)
		throw EWSError::InvalidSubscription(E3202);
	if (mgr->username != m_auth_info.username)
		throw EWSError::AccessDenied(E3203);
	std::pair<std::list<sNotificationEvent>, bool> result{{}, mgr->events.size() > 50};
	auto &evt = mgr->events;
	if(result.second) {
		auto it = evt.begin();
		std::advance(it, 50);
		result.first.splice(result.first.end(), evt, evt.begin(), it);
	}
	else
		result.first.splice(result.first.end(), evt);
	return result;
}

/**
 * @brief     Get entry ID property of folder
 *
 * Also works on non-existant folders.
 *
 * @param     dir       Store directory
 * @param     folderId  Folder ID
 *
 * @return    Tagged property containing the entry ID
 */
TAGGED_PROPVAL EWSContext::getFolderEntryId(const std::string& dir, uint64_t folderId) const
{
	static constexpr uint32_t propids[] = {PR_ENTRYID};
	static constexpr PROPTAG_ARRAY proptags = {1, deconst(propids)};
	TPROPVAL_ARRAY props = getFolderProps(dir, folderId, proptags);
	if(props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
		throw EWSError::FolderPropertyRequestFailed(E3022);
	return *props.ppropval;
}

/**
 * @brief     Get properties of specified folder
 *
 * @param     dir       Store directory
 * @param     folderId  Folder ID
 * @param     props     Properties to get
 *
 * @return    Property values
 */
TPROPVAL_ARRAY EWSContext::getFolderProps(const std::string& dir, uint64_t folderId, const PROPTAG_ARRAY& props) const
{
	TPROPVAL_ARRAY result;
	if (!m_plugin.exmdb.get_folder_properties(dir.c_str(), CP_ACP, folderId, &props, &result))
		throw EWSError::FolderPropertyRequestFailed(E3023);
	return result;
}

/**
 * @brief     Get entry ID property of item
 *
 * Also works on non-existant items.
 *
 * @param     folder  Folder specification
 *
 * @return    Tagged property containing the entry ID
 */
TAGGED_PROPVAL EWSContext::getItemEntryId(const std::string& dir, uint64_t mid) const
{
	static constexpr uint32_t propids[] = {PR_ENTRYID};
	static constexpr PROPTAG_ARRAY proptags = {1, deconst(propids)};
	TPROPVAL_ARRAY props = getItemProps(dir, mid, proptags);
	if(props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
		throw EWSError::ItemPropertyRequestFailed(E3024);
	return *props.ppropval;
}

/**
 * @brief      Get folder property value
 *
 * @param      dir   Store directory
 * @param      fid   Folder ID
 * @param      tag   Tag ID
 *
 * @return     Pointer to property value or nullptr if not found
 */
const void* EWSContext::getFolderProp(const std::string& dir, uint64_t fid, uint32_t tag) const
{
	PROPTAG_ARRAY proptags{1, &tag};
	TPROPVAL_ARRAY props = getFolderProps(dir, fid, proptags);
	if(props.count != 1 || props.ppropval->proptag != tag)
		throw EWSError::FolderPropertyRequestFailed(E3169);
	return props.ppropval->pvalue;
}

/**
 * @brief      Get item property value
 *
 * @param      dir   Store directory
 * @param      mid   Message ID
 * @param      tag   Tag ID
 *
 * @return     Pointer to property value or nullptr if not found
 */
const void* EWSContext::getItemProp(const std::string& dir, uint64_t mid, uint32_t tag) const
{
	PROPTAG_ARRAY proptags{1, &tag};
	TPROPVAL_ARRAY props = getItemProps(dir, mid, proptags);
	if(props.count != 1 || props.ppropval->proptag != tag)
		throw EWSError::ItemPropertyRequestFailed(E3127);
	return props.ppropval->pvalue;
}

/**
 * @brief     Get properties of a message item
 *
 * @param     dir     User home dir
 * @param     mid     Message ID
 * @param     props   Properties to get
 *
 * @return    Property values
 */
TPROPVAL_ARRAY EWSContext::getItemProps(const std::string& dir,	uint64_t mid, const PROPTAG_ARRAY& props) const
{
	TPROPVAL_ARRAY result;
	if (!m_plugin.exmdb.get_message_properties(dir.c_str(), m_auth_info.username,
	    CP_ACP, mid, &props, &result))
		throw EWSError::ItemPropertyRequestFailed(E3025);
	return result;
}

/**
 * @brief      Get mailbox GUID from store property
 *
 * @param      dir   Store directory
 *
 * @return     GUID of the mailbox
 */
GUID EWSContext::getMailboxGuid(const std::string& dir) const
{
	static constexpr uint32_t recordKeyTag = PR_STORE_RECORD_KEY;
	static constexpr PROPTAG_ARRAY recordKeyTags = {1, deconst(&recordKeyTag)};
	TPROPVAL_ARRAY recordKeyProp;
	if(!m_plugin.exmdb.get_store_properties(dir.c_str(), CP_ACP, &recordKeyTags, &recordKeyProp) ||
	   recordKeyProp.count != 1 || recordKeyProp.ppropval->proptag != PR_STORE_RECORD_KEY)
		throw DispatchError(E3194);
	const BINARY* recordKeyData = static_cast<const BINARY*>(recordKeyProp.ppropval->pvalue);
	EXT_PULL guidPull;
	guidPull.init(recordKeyData->pv, recordKeyData->cb, alloc, 0);
	GUID mailboxGuid;
	ext_error(guidPull.g_guid(&mailboxGuid));
	return mailboxGuid;
}

/**
 * @brief      Collect mailbox metadata
 *
 * @param      dir       Store directory
 * @param      isDomain  Whether target is a domain
 *
 * @return     Mailbox metadata struct
 */
sMailboxInfo EWSContext::getMailboxInfo(const std::string& dir, bool isDomain) const
{
	sMailboxInfo mbinfo{getMailboxGuid(dir), 0, isDomain};
	auto getId = isDomain? mysql_adaptor_get_id_from_homedir : mysql_adaptor_get_id_from_maildir;
	if(!getId(dir.c_str(), &mbinfo.accountId))
		throw EWSError::CannotFindUser(E3192(isDomain? "domain" : "user", dir));
	return mbinfo;
}

/**
 * @brief      Setup impersonation for user
 *
 * @param      addrtype    Adress type
 * @param      addr        Smtp address of the user to impersonate
 */
void EWSContext::impersonate(const char* addrtype, const char* addr)
{
	if(!addrtype || !addr)
		return;
	if(strcmp(addrtype, "PrincipalName") && strcmp(addrtype, "PrimarySmtpAddres") && strcmp(addrtype, "SmtpAddress"))
		throw EWSError::ImpersonationFailed(E3242);
	impersonationMaildir = get_maildir(addr);
	if(!(permissions(impersonationMaildir, rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE)) & frightsGromoxStoreOwner))
		throw EWSError::ImpersonateUserDenied(E3243);
	impersonationUser = addr;
	m_auth_info.username = impersonationUser.c_str();
	m_auth_info.maildir = impersonationMaildir.c_str();
}

/**
 * @brief     Load attachment
 *
 * @param     dir      Store to load from
 * @param     aid      Attachment ID
 *
 * @return    Attachment structure
 */
sAttachment EWSContext::loadAttachment(const std::string& dir, const sAttachmentId& aid) const
{
	auto aInst = m_plugin.loadAttachmentInstance(dir, aid.folderId(), aid.messageId(), aid.attachment_num);
	static uint32_t tagIDs[] = {PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG, PR_ATTACH_DATA_BIN,
	                            PR_ATTACH_CONTENT_ID, PR_ATTACH_LONG_FILENAME, PR_ATTACHMENT_FLAGS};
	TPROPVAL_ARRAY props;
	PROPTAG_ARRAY tags{std::size(tagIDs), tagIDs};
	if(!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0, aInst->instanceId, &tags, &props))
		throw DispatchError(E3083);
	return tAttachment::create(aid, props);
}

/**
 * @brief      Load permission table
 *
 * @param      dir   Store to load from
 * @param      fid   Folder Id
 *
 * @return     Property table containing `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and `PR_SMTP_ADDRESS` tags
 */
TARRAY_SET EWSContext::loadPermissions(const std::string& dir, uint64_t fid) const
{
	uint32_t tableId, rowCount;
	const auto& exmdb = m_plugin.exmdb;
	if(!exmdb.load_permission_table(dir.c_str(), fid, 0, &tableId, &rowCount))
		throw EWSError::ItemCorrupt(E3283);
	auto unloadTable = make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
	static constexpr uint32_t tags[] = {PR_MEMBER_ID, PR_MEMBER_NAME, PR_MEMBER_RIGHTS, PR_SMTP_ADDRESS};
	static constexpr PROPTAG_ARRAY proptags = {std::size(tags), deconst(tags)};
	TARRAY_SET propTable;
	if(!exmdb.query_table(dir.c_str(), "", CP_UTF8, tableId, &proptags, 0, rowCount, &propTable))
		throw EWSError::ItemCorrupt(E3284);
	return propTable;
}

/**
 * @brief     Load special folder fields for calendar folders
 *
 * @param     dir     Store to load from
 * @param     fid     Folder ID
 * @param     folder  Folder object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fId, tBaseFolderType& folder, uint64_t special) const
{
	if(special & sShape::Rights)
		folder.EffectiveRights.emplace(permissions(dir, fId));
}

/**
 * @brief     Load generic special folder fields
 *
 * Currently supports
 * - loading of permissions
 *
 * @param     dir     Store to load from
 * @param     fid     Folder ID
 * @param     folder  Folder object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fId, tCalendarFolderType& folder, uint64_t special) const
{
	loadSpecial(dir, fId, static_cast<tBaseFolderType&>(folder), special);
	if(special & sShape::Permissions)
		folder.PermissionSet.emplace(loadPermissions(dir, fId));
}

/**
 * @brief     Load generic special folder fields for contacts folder
 *
 * Currently supports
 * - loading of permissions
 *
 * @param     dir     Store to load from
 * @param     fid     Folder ID
 * @param     folder  Folder object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fId, tContactsFolderType& folder, uint64_t special) const
{
	loadSpecial(dir, fId, static_cast<tBaseFolderType&>(folder), special);
	if(special & sShape::Permissions)
		folder.PermissionSet.emplace(loadPermissions(dir, fId));
}

/**
 * @brief     Load special folder fields for normal folders
 *
 * @param     dir     Store to load from
 * @param     fid     Folder ID
 * @param     folder  Folder object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fId, tFolderType& folder, uint64_t special) const
{
	loadSpecial(dir, fId, static_cast<tBaseFolderType&>(folder), special);
	if(special & sShape::Permissions)
		folder.PermissionSet.emplace(loadPermissions(dir, fId));
}

/**
 * @brief      Load folder properties
 *
 * @param      folder  Folder specification
 * @param      shape   Requested folder shape
 *
 * @return     Folder data
 */
sFolder EWSContext::loadFolder(const std::string& dir, uint64_t folderId, Structures::sShape& shape) const
{
	shape.clean();
	getNamedTags(dir, shape);
	shape.properties(getFolderProps(dir, folderId, shape.proptags()));
	sFolder folder = tBaseFolderType::create(shape);
	if(shape.special)
		std::visit([&](auto&& f) {loadSpecial(dir, folderId, f, shape.special);}, folder);
	return folder;
}

/**
 * @brief     Load generic special fields
 *
 * Currently supports
 * - loading of mime content
 * - loading of attachment metadata
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     item    Message object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fid, uint64_t mid, tItem& item, uint64_t special) const
{
	auto& exmdb = m_plugin.exmdb;
	if(special & sShape::MimeContent)
	{
		MESSAGE_CONTENT *content = nullptr;
		if (!exmdb.read_message(dir.c_str(), nullptr, CP_ACP, mid, &content) ||
		    content == nullptr)
			throw EWSError::ItemNotFound(E3071);
		MAIL mail;
		auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		                  {*ids = getNamedPropIds(dir, *names); return TRUE;};
		auto getPropName = [&](uint16_t id, PROPERTY_NAME** name)
		                   {*name = getPropertyName(dir, id); return TRUE;};
		auto log_id = dir + ":m" + std::to_string(mid);
		if (!oxcmail_export(content, log_id.c_str(), false,
		    oxcmail_body::plain_and_html, &mail, alloc, getPropIds, getPropName))
			throw EWSError::ItemCorrupt(E3072);
		auto mailLen = mail.get_length();
		if(mailLen < 0)
			throw EWSError::ItemCorrupt(E3073);
		STREAM tempStream;
		if(!mail.serialize(&tempStream))
			throw EWSError::ItemCorrupt(E3074);
		auto& mimeContent = item.MimeContent.emplace();
		mimeContent.reserve(mailLen);
		uint8_t* data;
		unsigned int size = STREAM_BLOCK_SIZE;
		while((data = static_cast<uint8_t*>(tempStream.get_read_buf(&size))) != nullptr) {
			mimeContent.insert(mimeContent.end(), data, data+size);
			size = STREAM_BLOCK_SIZE;
		}
	}
	if(special & sShape::Attachments)
	{
		static uint32_t tagIDs[] = {PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG, PR_ATTACH_CONTENT_ID,
			                        PR_ATTACH_LONG_FILENAME, PR_ATTACHMENT_FLAGS};
		auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
		uint16_t count;
		if(!exmdb.get_message_instance_attachments_num(dir.c_str(), mInst->instanceId, &count))
			throw DispatchError(E3079);
		sAttachmentId aid(this->getItemEntryId(dir, mid), 0);
		item.Attachments.emplace().reserve(count);
		for(uint16_t i = 0; i < count; ++i)
		{
			auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
			TPROPVAL_ARRAY props;
			PROPTAG_ARRAY tags{std::size(tagIDs), tagIDs};
			if(!exmdb.get_instance_properties(dir.c_str(), 0, aInst->instanceId, &tags, &props))
				throw DispatchError(E3080);
			aid.attachment_num = i;
			item.Attachments->emplace_back(tAttachment::create(aid, props));
		}
	}
	if(special & sShape::Rights)
		item.EffectiveRights.emplace(permissions(dir, fid));
}

/**
 * @brief     Load message attributes not contained in tags
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     message Message object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fid, uint64_t mid, tMessage& message, uint64_t special) const
{
	loadSpecial(dir, fid, mid, static_cast<tItem&>(message), special);
	if (!(special & sShape::Recipients))
		return;
	TARRAY_SET rcpts;
	if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
	{
		mlog(LV_ERR, "[ews] failed to load message recipients (%s:%llu)",
			dir.c_str(), static_cast<unsigned long long>(mid));
		return;
	}
	for (TPROPVAL_ARRAY **tps = rcpts.pparray; tps < &rcpts.pparray[rcpts.count]; ++tps)
	{
		uint32_t *recipientType = (*tps)->get<uint32_t>(PR_RECIPIENT_TYPE);
		if (!recipientType)
			continue;
		switch (*recipientType)
		{
		case MAPI_TO:
			if (special & sShape::ToRecipients)
				defaulted(message.ToRecipients).emplace_back(**tps);
			break;
		case MAPI_CC:
			if (special & sShape::CcRecipients)
				defaulted(message.CcRecipients).emplace_back(**tps);
			break;
		case MAPI_BCC:
			if (special & sShape::BccRecipients)
				defaulted(message.BccRecipients).emplace_back(**tps);
			break;
		}
	}
}

/**
 * @brief     Load message attributes not contained in tags
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     calItem Calendar object to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string& dir, uint64_t fid, uint64_t mid, tCalendarItem& calItem, uint64_t special) const
{
	loadSpecial(dir, fid, mid, static_cast<tItem&>(calItem), special);
	if (!(special & sShape::Attendees))
		return;
	TARRAY_SET rcpts;
	if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts))
	{
		mlog(LV_ERR, "[ews] failed to load calItem recipients (%s:%llu)",
			dir.c_str(), static_cast<unsigned long long>(mid));
		return;
	}
	for (TPROPVAL_ARRAY **tps = rcpts.pparray; tps < &rcpts.pparray[rcpts.count]; ++tps)
	{
		uint32_t *recipientType = (*tps)->get<uint32_t>(PR_RECIPIENT_TYPE);
		if (!recipientType)
			continue;
		switch (*recipientType)
		{
		case 1: //Required attendee
			if (special & sShape::RequiredAttendees)
				defaulted(calItem.RequiredAttendees).emplace_back(**tps);
			break;
		case 2: //Optional attendee
			if (special & sShape::OptionalAttendees)
				defaulted(calItem.OptionalAttendees).emplace_back(**tps);
			break;
		case 3: //Resource
			if (special & sShape::Resources)
				defaulted(calItem.Resources).emplace_back(**tps);
			break;
		}
	}
}

/**
 * @brief update properties of a tCalendarItem
 *
 * @param calItem     Calendar item
 * @param shape       Requested item shape
 * @param props       Properties to update
 */
void EWSContext::updateProps(tCalendarItem& calItem, sShape& shape, const TPROPVAL_ARRAY& props) const
{
	shape.clean();
	shape.properties(props);
	calItem.update(shape);
}

/**
 * @brief      Load item
 *
 * @param      dir    Store directory
 * @param      fid    Parent folder ID
 * @param      mid    Message ID
 * @param      shape  Requested item shape
 *
 * @return     The s item.
 */
sItem EWSContext::loadItem(const std::string&dir, uint64_t fid, uint64_t mid, sShape& shape) const
{
	shape.clean();
	getNamedTags(dir, shape);
	shape.properties(getItemProps(dir, mid, shape.proptags()));
	sItem item = tItem::create(shape);
	if(shape.special)
		std::visit([&](auto &&it) { loadSpecial(dir, fid, mid, it, shape.special); }, item);
	return item;
}

/**
 * @brief      Load occurrence
 *
 * @param      dir      Store directory
 * @param      fid      Parent folder ID
 * @param      mid      Message ID
 * @param      basedate Basedate of the occurrence
 * @param      shape    Requested item shape
 *
 * @return     The s item.
 */
sItem EWSContext::loadOccurrence(const std::string& dir, uint64_t fid, uint64_t mid, uint32_t basedate, sShape& shape) const
{
	auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
	uint16_t count;
	if(!m_plugin.exmdb.get_message_instance_attachments_num(dir.c_str(), mInst->instanceId, &count))
		throw DispatchError(E3210);

	shape.clean();
	getNamedTags(dir, shape);
	shape.properties(getItemProps(dir, mid, shape.proptags()));
	PROPNAME_ARRAY propnames;
	propnames.count = 1;
	PROPERTY_NAME propname_buff[1];
	propname_buff[0].kind = MNID_ID;
	propname_buff[0].guid = PSETID_Appointment;
	propname_buff[0].lid = PidLidExceptionReplaceTime;
	propnames.ppropname = propname_buff;
	PROPID_ARRAY namedids = getNamedPropIds(dir, propnames, true);
	auto ex_replace_time_tag = PROP_TAG(PT_SYSTIME, namedids[0]);
	TPROPVAL_ARRAY props;
	PROPTAG_ARRAY tags = shape.proptags();
	tags.emplace_back(ex_replace_time_tag);

	auto basedate_ts = clock::to_time_t(rop_util_rtime_to_unix2(basedate));
	struct tm basedate_local;
	localtime_r(&basedate_ts, &basedate_local);

	for(uint16_t i = 0; i < count; ++i)
	{
		auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
		auto eInst = m_plugin.loadEmbeddedInstance(dir, aInst->instanceId);
		if(!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0, eInst->instanceId, &tags, &props))
			throw DispatchError(E3211);

		auto exstarttime = props.get<const uint64_t>(ex_replace_time_tag);
		if(!exstarttime)
			continue;
		auto exstart = clock::to_time_t(rop_util_nttime_to_unix2(*exstarttime));
		struct tm exstart_local;
		localtime_r(&exstart, &exstart_local);
		if(is_same_day(basedate_local, exstart_local))
		{
			sItem item = tItem::create(shape);
			if(shape.special)
				std::visit([&](auto &&it) { loadSpecial(dir, fid, mid, it, shape.special); }, item);
			std::visit([&](auto &&it) { updateProps(it, shape, props); }, item);

			return item;
		}
	}
	throw EWSError::ItemCorrupt(E3209);
}

/**
 * @brief      Generate initial predecessor change list from xid
 *
 * @param      xid  Initial change key
 *
 * @return     Serialized predecessor change list buffer
 */
std::unique_ptr<BINARY, detail::Cleaner> EWSContext::mkPCL(const XID& xid, PCL pcl) const
{
	if(!pcl.append(xid))
		throw DispatchError(E3121);
	std::unique_ptr<BINARY, detail::Cleaner> pcltemp(pcl.serialize());
	if(!pcltemp)
		throw EWSError::NotEnoughMemory(E3122);
	return pcltemp;
}

/**
 * @brief      Move or copy a folder
 *
 * @param      dir         Store directory
 * @param      folderId    Id of the folder to move/copy
 * @param      newParent   Id of the target folder
 * @param      accountId   Account ID of the executing user
 * @param      copy        Whether to copy the folder (instead of moving)
 *
 * @return     ID of the new folder if copied
 */
uint64_t EWSContext::moveCopyFolder(const std::string& dir, const sFolderSpec& folder, uint64_t newParent, uint32_t accountId,
                                    bool copy) const
{
	static constexpr uint32_t tagIds[] = {PidTagParentFolderId, PR_DISPLAY_NAME};
	static constexpr PROPTAG_ARRAY tags = {std::size(tagIds), deconst(tagIds)};
	TPROPVAL_ARRAY props;
	if(!m_plugin.exmdb.get_folder_properties(dir.c_str(), CP_ACP, folder.folderId, &tags, &props))
		throw DispatchError(E3159);
	uint64_t* parentFid = props.get<uint64_t>(PidTagParentFolderId);
	auto folderName = props.get<const char>(PR_DISPLAY_NAME);
	if(!parentFid || !folderName)
		throw DispatchError(E3160);
	sFolderSpec parentFolder = folder;
	parentFolder.folderId = *parentFid;
	if(!(permissions(dir, folder.folderId) & frightsDeleteAny) ||
	   !(permissions(dir, parentFolder.folderId) & frightsDeleteAny))
			throw EWSError::AccessDenied(E3157);
	ec_error_t errcode = ecSuccess;
	if (!m_plugin.exmdb.movecopy_folder(dir.c_str(), CP_ACP, false,
	    m_auth_info.username, *parentFid, folder.folderId, newParent,
	    folderName, copy ? TRUE : false, &errcode))
		throw EWSError::MoveCopyFailed(E3161);
	if (errcode == ecDuplicateName)
		throw EWSError::FolderExists(E3162);
	if (errcode != ecSuccess)
		throw EWSError::MoveCopyFailed(std::string(E3163) + ": " + mapi_strerror(errcode));
	if(!copy) {
		updated(dir, folder);
		return folder.folderId;
	}
	uint64_t newFolderId;
	if(!m_plugin.exmdb.get_folder_by_name(dir.c_str(), newParent, folderName, &newFolderId))
		throw DispatchError(E3164);
	return newFolderId;
}

/**
 * @brief      Move or copy message object
 *
 * @param      dir         Store directory
 * @param      itemId      Message iD
 * @param      newParent   Destination folder
 * @param      accountId   Account ID of executing user
 * @param      copy        Whether to copy (instead of moving)
 *
 * @return     New message ID
 */
uint64_t EWSContext::moveCopyItem(const std::string& dir, const sMessageEntryId& meid, uint64_t newParent, bool copy) const
{
	auto& exmdb = m_plugin.exmdb;
	uint64_t newId;
	if(!exmdb.allocate_message_id(dir.c_str(), newParent, &newId))
		throw DispatchError(E3182);
	BOOL success;
	if (!m_plugin.exmdb.movecopy_message(dir.c_str(), CP_ACP,
	    meid.messageId(), newParent, newId, copy? false : TRUE,
	    &success) || !success)
		throw EWSError::MoveCopyFailed(E3183);
	return newId;
}

/**
 * @brief    Normalize mailbox specification
 *
 * If EmailAddress is empty, nothing happens.
 *
 * Ensures that `RoutingType` equals "smtp", performing essdn resolution if
 * necessary.
 *
 * @throw      DispatchError   Unsupported RoutingType
 *
 * @param Mailbox
 */
void EWSContext::normalize(tEmailAddressType& Mailbox) const
{
	if(!Mailbox.EmailAddress)
		return;
	if(!Mailbox.RoutingType)
		Mailbox.RoutingType = "smtp";
	if(tolower(*Mailbox.RoutingType) == "smtp")
		return;
	if(Mailbox.RoutingType != "ex")
		throw  EWSError::InvalidRoutingType(E3114(*Mailbox.RoutingType));
	Mailbox.EmailAddress = essdn_to_username(*Mailbox.EmailAddress);
	Mailbox.RoutingType = "smtp";
}

/**
 * @brief    Normalize mailbox specification
 *
 * Ensures that `RoutingType` equals "smtp", performing essdn resolution if
 * necessary.
 *
 * @throw      DispatchError   Unsupported RoutingType
 *
 * @param Mailbox
 */
void EWSContext::normalize(tMailbox& Mailbox) const
{
	if(!Mailbox.RoutingType)
		Mailbox.RoutingType = "smtp";
	if(tolower(*Mailbox.RoutingType) == "smtp")
		return;
	if(Mailbox.RoutingType != "ex")
		throw  EWSError::InvalidRoutingType(E3010(*Mailbox.RoutingType));
	Mailbox.Address = essdn_to_username(Mailbox.Address);
	Mailbox.RoutingType = "smtp";
}

/**
 * @brief     Get folder permissions for current user
 *
 * Always returns full access if the maildir matches the currently logged in user.
 *
 * @param     maildir     Target maildir
 * @param     folderId    Target folder ID
 *
 * @return    Permission flags
 */
uint32_t EWSContext::permissions(const std::string& maildir, uint64_t folderId) const
{
	if(maildir == m_auth_info.maildir)
		return 0xFFFFFFFF;
	uint32_t permissions = 0;
	m_plugin.exmdb.get_folder_perm(maildir.c_str(), folderId, m_auth_info.username, &permissions);
	return permissions;
}

/**
 * @brief     Get folder specification from distinguished folder ID
 *
 * Convenience proxy for sFolderSpec constructor to be used with varian::visit.
 *
 * @param     fId     Distinguished folder ID to resolve
 *
 * @return    Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const tDistinguishedFolderId& fId) const
{
	sFolderSpec folder = sFolderSpec(fId);
	if(!folder.target)
		folder.target = m_auth_info.username;
	return folder;
}

/**
 * @brief      Get folder specification from entry ID
 *
 * @param      fId    Folder Id
 *
 * @return     Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const tFolderId& fId) const
{
	assertIdType(fId.type, tFolderId::ID_FOLDER);
	sFolderEntryId eid(fId.Id.data(), fId.Id.size());
	sFolderSpec folderSpec;
	folderSpec.location = eid.isPrivate()? sFolderSpec::PRIVATE : sFolderSpec::PUBLIC;
	folderSpec.folderId = rop_util_make_eid_ex(1, rop_util_gc_to_value(eid.global_counter));
	if(eid.isPrivate())
	{
		char temp[UADDR_SIZE];
		if(!mysql_adaptor_get_username_from_id(eid.accountId(), temp, UADDR_SIZE))
			throw EWSError::CannotFindUser(E3026);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!mysql_adaptor_get_domain_info(eid.accountId(), domaininfo))
			throw EWSError::CannotFindUser(E3027);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief      Get folder specification form any folder specification
 *
 * @param      fId    Folder Id
 *
 * @return     Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const sFolderId& fId) const
{return std::visit([this](const auto& f){return resolveFolder(f);}, fId);}

/**
 * @brief      Get specification of folder containing the message
 *
 * @param      eid    Message entry ID
 *
 * @return     Folder specification
 */
sFolderSpec EWSContext::resolveFolder(const sMessageEntryId& eid) const
{
	sFolderSpec folderSpec;
	folderSpec.location = eid.isPrivate()? sFolderSpec::PRIVATE : sFolderSpec::PUBLIC;
	folderSpec.folderId = rop_util_make_eid_ex(1, eid.folderId());
	if(eid.isPrivate())
	{
		char temp[UADDR_SIZE];
		if(!mysql_adaptor_get_username_from_id(eid.accountId(), temp, UADDR_SIZE))
			throw EWSError::CannotFindUser(E3075);
		folderSpec.target = temp;
	}
	else
	{
		sql_domain domaininfo;
		if(!mysql_adaptor_get_domain_info(eid.accountId(), domaininfo))
			throw EWSError::CannotFindUser(E3076);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief     Send message
 *
 * @param     dir      Home directory the message is associtated with
 * @param     content  Message content
 */
void EWSContext::send(const std::string &dir, uint64_t log_msg_id,
    const MESSAGE_CONTENT &content) const
{
	if(!content.children.prcpts)
		throw EWSError::MissingRecipients(E3115);
	MAIL mail;
	auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
		                  {*ids = getNamedPropIds(dir, *names); return TRUE;};
	auto getPropName = [&](uint16_t id, PROPERTY_NAME** name)
					   {*name = getPropertyName(dir, id); return TRUE;};
	std::string log_id;
	if (log_msg_id != 0)
		log_id = dir + ":m" + std::to_string(log_msg_id);
	if (!oxcmail_export(&content, log_id.c_str(), false,
	    oxcmail_body::plain_and_html, &mail, alloc, getPropIds, getPropName))
		throw EWSError::ItemCorrupt(E3116);
	std::vector<std::string> rcpts;
	rcpts.reserve(content.children.prcpts->count);
	for (auto &rcpt : *content.children.prcpts) {
		tEmailAddressType addr(rcpt);
		if(!addr.EmailAddress)
			continue;
		normalize(addr);
		rcpts.emplace_back(*addr.EmailAddress);
	}
	auto err = cu_send_mail(mail, m_plugin.smtp_url.c_str(),
	           m_auth_info.username, rcpts);
	if(err != ecSuccess)
		throw DispatchError(E3117(err));
}

/**
 * @brief      Serialize XID to BINARY
 *
 * The internal buffer of the BINARY is stack allocated and must not be
 * manually freed.
 *
 * @param      xid   XID object to serialize
 *
 * @return     BINARY objet containing serialize data
 */
BINARY EWSContext::serialize(const XID& xid) const
{
	uint8_t* buff = alloc<uint8_t>(xid.size);
	EXT_PUSH ext_push;
	if(!ext_push.init(buff, xid.size, 0) || ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		throw DispatchError(E3120);
	return BINARY{ext_push.m_offset, {buff}};
}

/**
 * @brief      Add subscription to notification context
 *
 * @param      subscriptionId  Subscription to add
 *
 * @return     true if subscription was added, false on error (not found or no access)
 */
bool EWSContext::streamEvents(const tSubscriptionId& subscriptionId) const
{
	if(m_notify)
		m_notify->nct_subs.emplace_back(subscriptionId);
	return m_plugin.linkSubscription(subscriptionId, *this);
}

/**
 * @brief      Create MESSAGE_CONTENT from string
 *
 * @param     dir          Home directory of the associated store
 * @param     mimeContent  MimeContent data
 *
 * @return    Pointer to new MESSAGE_CONTENT structure
 */
EWSContext::MCONT_PTR EWSContext::toContent(const std::string& dir, std::string& mimeContent) const
{
	MAIL mail;
	if (!mail.load_from_str(mimeContent.data(), mimeContent.size()))
		throw EWSError::ItemCorrupt(E3123);
	auto getPropIds = [&](const PROPNAME_ARRAY* names, PROPID_ARRAY* ids)
	{*ids = getNamedPropIds(dir, *names, true); return TRUE;};
	MCONT_PTR cnt(oxcmail_import("utf-8", "UTC", &mail, EWSContext::alloc, getPropIds));
	if(!cnt)
		throw EWSError::ItemCorrupt(E3124);
	return cnt;
}

/**
 * @brief     Convert item to MESSAGE_CONTENT
 *
 * @param     dir      Home directory of the associated store
 * @param     parent   Parent folder to store the message in
 * @param     item     Item to convert
 * @param     persist  Whether the message is to be stored
 *
 * @return Pointer to MESSAGE_CONTENT structure
 */
EWSContext::MCONT_PTR EWSContext::toContent(const std::string& dir, const sFolderSpec& parent, sItem& item, bool persist) const
{
	const auto& exmdb = m_plugin.exmdb;
	uint64_t messageId, changeNumber;
	BINARY *ckey = nullptr, *pclbin = nullptr;

	if(persist) {
		if(!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &messageId))
			throw DispatchError(E3118);
		if(!exmdb.allocate_cn(dir.c_str(), &changeNumber))
			throw DispatchError(E3119);

		bool isPublic = parent.location == parent.PUBLIC;
		uint32_t accountId = getAccountId(*parent.target, isPublic);
		XID xid((parent.location == parent.PRIVATE? rop_util_make_user_guid : rop_util_make_domain_guid)(accountId), changeNumber);

		ckey = construct<BINARY>(serialize(xid));

		auto pcltemp = mkPCL(xid);
		uint8_t* pcldata = alloc<uint8_t>(pcltemp->cb);
		memcpy(pcldata, pcltemp->pv, pcltemp->cb);
		pclbin = construct<BINARY>(BINARY{pcltemp->cb, {pcldata}});
	}

	sShape shape;
	MCONT_PTR content(message_content_init());
	if(!content)
		throw EWSError::NotEnoughMemory(E3217);
	std::visit([&](auto& i){toContent(dir, i, shape, content);}, item);

	if(!shape.writes(PR_LAST_MODIFICATION_TIME))
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFICATION_TIME, EWSContext::construct<uint64_t>(rop_util_current_nttime())});
	if(persist) {
		static constexpr uint8_t trueVal = TRUE;
		if(!shape.writes(PR_READ))	// Unless specified otherwise, newly created items should be marked as read
			shape.write(TAGGED_PROPVAL{PR_READ, const_cast<uint8_t*>(&trueVal)});
		shape.write(TAGGED_PROPVAL{PidTagMid, construct<uint64_t>(messageId)});
		shape.write(TAGGED_PROPVAL{PidTagChangeNumber, construct<uint64_t>(changeNumber)});
		shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, ckey});
		shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, pclbin});
	}
	getNamedTags(dir, shape, true);

	for(const TAGGED_PROPVAL& prop : shape.write())
		if (content->proplist.set(prop) == -ENOMEM)
			throw EWSError::NotEnoughMemory(E3217);
	return content;
}

/**
 * @brief      Write calendar item properties to shape
 *
 * Must forward the call to tItem overload.
 *
 * Currently a stub.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Calendar item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tCalendarItem& item, sShape& shape, MCONT_PTR& content) const
{
	toContent(dir, static_cast<tItem&>(item), shape, content);
	// TODO: goid
	if(!item.ItemClass)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, deconst("IPM.Appointment")});
	int64_t startOffset = 0, endOffset = 0;
	time_t startTime = 0, endTime = 0;
	if(item.Start) {
		startTime = clock::to_time_t(item.Start.value().time);
		startOffset = std::chrono::duration_cast<std::chrono::minutes>(item.Start.value().offset).count();
	}
	if(item.End) {
		endTime = clock::to_time_t(item.End.value().time);
		endOffset = std::chrono::duration_cast<std::chrono::minutes>(item.Start.value().offset).count();
	}
	// TODO handle no start and/or end times

	if(item.IsAllDayEvent)
		shape.write(NtAppointmentSubType, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(item.IsAllDayEvent.value())});
	else
		shape.write(NtAppointmentSubType, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(0)});
	if(item.LegacyFreeBusyStatus)
		shape.write(NtBusyStatus, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(item.LegacyFreeBusyStatus->index())});
	else
		shape.write(NtBusyStatus, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(olBusy)});
	if(item.IsResponseRequested)
		shape.write(TAGGED_PROPVAL{PR_RESPONSE_REQUESTED, construct<uint32_t>(item.IsResponseRequested.value())});
	if(item.AllowNewTimeProposal)
		shape.write(NtAppointmentNotAllowPropose, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(!item.AllowNewTimeProposal.value())});
	if(item.Location)
		shape.write(NtLocation, TAGGED_PROPVAL{PT_UNICODE, deconst(item.Location.value().c_str())});

	uint8_t isrecurring = item.IsRecurring && item.IsRecurring.value() ? 1 : 0;

	if(item.Recurrence) {
		auto localStartTime = clock::to_time_t(item.Start.value().time);
		auto localEndTime = clock::to_time_t(item.End.value().time);
		auto duration = localEndTime - localStartTime;
		struct tm startdate_tm;
		if (localtime_r(&localStartTime, &startdate_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3265);
		APPOINTMENT_RECUR_PAT apr{};
		uint32_t deleted_dates[1024], modified_dates[1024];
		EXCEPTIONINFO exceptions[1024];
		EXTENDEDEXCEPTION ext_exceptions[1024];

		apr.readerversion2 = 0x3006;
		apr.writerversion2 = 0x3009;
		apr.exceptioncount = 0;
		apr.pexceptioninfo = exceptions;
		apr.pextendedexception = ext_exceptions;
		apr.starttimeoffset = 60 * startdate_tm.tm_hour + startdate_tm.tm_min;
		apr.endtimeoffset = apr.starttimeoffset + duration / 60;
		apr.recur_pat.readerversion = 0x3004;
		apr.recur_pat.writerversion = 0x3004;
		apr.recur_pat.calendartype = CAL_DEFAULT;
		apr.recur_pat.deletedinstancecount = 0;
		apr.recur_pat.pdeletedinstancedates = deleted_dates;
		apr.recur_pat.modifiedinstancecount = 0;
		apr.recur_pat.pmodifiedinstancedates = modified_dates;
		apr.recur_pat.slidingflag = 0;
		startdate_tm.tm_hour = 0;
		startdate_tm.tm_min = 0;
		startdate_tm.tm_sec = 0;
		time_t startdate = timegm(&startdate_tm);
		apr.recur_pat.startdate = rop_util_unix_to_rtime(startdate);
		uint8_t rectype = rectypeNone;
		auto& rp = item.Recurrence->RecurrencePattern;
		auto& rr = item.Recurrence->RecurrenceRange;

		if(std::holds_alternative<tDailyRecurrencePattern>(rp)) {
			auto interval = std::get<tDailyRecurrencePattern>(rp).Interval;
			if(interval < 1 || interval > 999)
				throw EWSError::CalendarInvalidRecurrence(E3266);
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_DAILY;
			apr.recur_pat.patterntype = rptMinute;
			apr.recur_pat.period = interval * 1440;
			rectype = rectypeDaily;
		}
		else if(std::holds_alternative<tWeeklyRecurrencePattern>(rp)) {
			auto interval = std::get<tWeeklyRecurrencePattern>(rp).Interval;
			if(interval < 1 || interval > 99)
				throw EWSError::CalendarInvalidRecurrence(E3267);
			auto firstdow = 1; // TODO get from user settings?
			if(std::get<tWeeklyRecurrencePattern>(rp).FirstDayOfWeek)
				firstdow = std::get<tWeeklyRecurrencePattern>(rp).FirstDayOfWeek->index();
			if(firstdow > 6)
				throw EWSError::CalendarInvalidRecurrence(E3268);

			const auto& daysOfWeek = std::get<tWeeklyRecurrencePattern>(rp).DaysOfWeek;
			apr.recur_pat.pts.weekrecur = 0;
			daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.weekrecur);
			if(apr.recur_pat.pts.weekrecur == 0)
				throw EWSError::CalendarInvalidRecurrence(E3269);

			// every weekday has daily frequency and weekly pattern type
			apr.recur_pat.recurfrequency = apr.recur_pat.pts.weekrecur != 0x3E ?
				IDC_RCEV_PAT_ORB_WEEKLY : IDC_RCEV_PAT_ORB_DAILY;
			apr.recur_pat.patterntype = rptWeek;
			apr.recur_pat.period = interval;
			apr.recur_pat.firstdow = firstdow;
			rectype = rectypeWeekly;
		}
		else if(std::holds_alternative<tRelativeMonthlyRecurrencePattern>(rp)) {
			auto interval = std::get<tRelativeMonthlyRecurrencePattern>(rp).Interval;
			if(interval < 1 || interval > 99)
				throw EWSError::CalendarInvalidRecurrence(E3270);

			const auto& daysOfWeek = std::get<tRelativeMonthlyRecurrencePattern>(rp).DaysOfWeek;
			apr.recur_pat.pts.monthnth.weekrecur = 0;
			daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.monthnth.weekrecur);
			if(apr.recur_pat.pts.monthnth.weekrecur == 0)
				throw EWSError::CalendarInvalidRecurrence(E3271);
			auto dayOfWeekIndex = std::get<tRelativeMonthlyRecurrencePattern>(rp).DayOfWeekIndex.index();
			if(dayOfWeekIndex > 4)
				throw EWSError::CalendarInvalidRecurrence(E3272);

			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
			apr.recur_pat.patterntype = rptMonthNth;
			apr.recur_pat.period = interval;
			apr.recur_pat.pts.monthnth.recurnum = static_cast<uint8_t>(dayOfWeekIndex) + 1;
			rectype = rectypeMonthly;
		}
		else if(std::holds_alternative<tAbsoluteMonthlyRecurrencePattern>(rp)) {
			auto interval = std::get<tAbsoluteMonthlyRecurrencePattern>(rp).Interval;
			if(interval < 1 || interval > 99)
				throw EWSError::CalendarInvalidRecurrence(E3273);
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
			apr.recur_pat.patterntype = rptMonth;
			apr.recur_pat.period = interval;
			apr.recur_pat.pts.dayofmonth = std::get<tAbsoluteMonthlyRecurrencePattern>(rp).DayOfMonth;
			if(apr.recur_pat.pts.dayofmonth < 1 || apr.recur_pat.pts.dayofmonth > 31)
				throw EWSError::CalendarInvalidRecurrence(E3274);
			rectype = rectypeMonthly;
		}
		else if(std::holds_alternative<tRelativeYearlyRecurrencePattern>(rp)) {
			const auto& daysOfWeek = std::get<tRelativeYearlyRecurrencePattern>(rp).DaysOfWeek;
			apr.recur_pat.pts.monthnth.weekrecur = 0;
			daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.monthnth.weekrecur);
			if(apr.recur_pat.pts.monthnth.weekrecur == 0)
				throw EWSError::CalendarInvalidRecurrence(E3275);
			auto dayOfWeekIndex = std::get<tRelativeYearlyRecurrencePattern>(rp).DayOfWeekIndex.index();
			auto month = std::get<tRelativeYearlyRecurrencePattern>(rp).Month.index();
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
			apr.recur_pat.patterntype = rptMonthNth;
			apr.recur_pat.period = 12;
			apr.recur_pat.pts.monthnth.recurnum = static_cast<uint8_t>(dayOfWeekIndex) + 1;
			rectype = rectypeYearly;
			startdate_tm.tm_mon = month;
		}
		else if(std::holds_alternative<tAbsoluteYearlyRecurrencePattern>(rp)) {
			auto month = std::get<tAbsoluteYearlyRecurrencePattern>(rp).Month.index();
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
			apr.recur_pat.patterntype = rptMonth;
			apr.recur_pat.period = 12;
			apr.recur_pat.pts.dayofmonth = std::get<tAbsoluteYearlyRecurrencePattern>(rp).DayOfMonth;
			if(apr.recur_pat.pts.dayofmonth < 1 || apr.recur_pat.pts.dayofmonth > 31)
				throw EWSError::CalendarInvalidRecurrence(E3279);
			rectype = rectypeYearly;
			startdate_tm.tm_mon = month;
		}
		else
			throw EWSError::CalendarInvalidRecurrence(E3280);

		calc_firstdatetime(apr.recur_pat, &startdate_tm);
		if(std::holds_alternative<tNoEndRecurrenceRange>(rr)) {
			apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_NOEND;
			apr.recur_pat.occurrencecount = 0xA; // value for a recurring series with no end date
			apr.recur_pat.enddate = ENDDATE_MISSING;
		}
		else if(std::holds_alternative<tEndDateRecurrenceRange>(rr)) {
			apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_END;
			apr.recur_pat.occurrencecount = 0xA; // TODO count occurrences, but this field doesn't really matter
			auto ed = std::get<tEndDateRecurrenceRange>(rr).EndDate;
			auto enddate = clock::to_time_t(ed);
			apr.recur_pat.enddate = rop_util_unix_to_rtime(enddate);
		}
		else if(std::holds_alternative<tNumberedRecurrenceRange>(rr)) {
			apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_AFTERNOCCUR;
			apr.recur_pat.occurrencecount = std::get<tNumberedRecurrenceRange>(rr).NumberOfOccurrences;
			calc_enddate(apr.recur_pat, &startdate_tm);
		}
		else
			throw EWSError::CalendarInvalidRecurrence(E3281);

		BINARY tmp_bin;
		EXT_PUSH ext_push;

		if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
		     ext_push.p_apptrecpat(apr) != EXT_ERR_SUCCESS)
			throw EWS::DispatchError(E3120);
		tmp_bin.cb = ext_push.m_offset;
		tmp_bin.pb = ext_push.m_udata;

		// copy the data from ext_push, so it is not lost when ext_push goes out of scope
		uint8_t* recurdata = alloc<uint8_t>(tmp_bin.cb);
		memcpy(recurdata, tmp_bin.pv, tmp_bin.cb);

		isrecurring = 1;
		shape.write(NtRecurrenceType, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(rectype)});
		shape.write(NtAppointmentRecur, TAGGED_PROPVAL{PT_BINARY, construct<BINARY>(BINARY{tmp_bin.cb, {recurdata}})});
		// TODO: midnight in local time persist in UTC
		auto clipstart = EWSContext::construct<uint64_t>(rop_util_unix_to_nttime(startdate));
		shape.write(NtClipStart, TAGGED_PROPVAL{PT_SYSTIME, clipstart});
		// TODO: midnight in local time persist in UTC
		auto clipend = EWSContext::construct<uint64_t>(rop_util_rtime_to_nttime(apr.recur_pat.enddate));
		shape.write(NtClipEnd, TAGGED_PROPVAL{PT_SYSTIME, clipend});
	}
	shape.write(NtRecurring, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(isrecurring)});

	uint32_t tag;
	if((tag = shape.tag(NtCalendarTimeZone)))
	{
		const TAGGED_PROPVAL* caltz = shape.writes(NtCalendarTimeZone);
		if(caltz)
		{
			auto buf = ianatz_to_tzdef(static_cast<char*>(caltz->pvalue));
			if(buf != nullptr)
			{
				size_t len = buf->size();
				if(len > std::numeric_limits<uint32_t>::max())
					throw InputError(E3293);
				BINARY* temp_bin = construct<BINARY>(BINARY{uint32_t(buf->size()),
					{reinterpret_cast<uint8_t*>(const_cast<char*>(buf->data()))}});
				shape.write(NtAppointmentTimeZoneDefinitionStartDisplay,
					TAGGED_PROPVAL{PT_BINARY, temp_bin});
				shape.write(NtAppointmentTimeZoneDefinitionEndDisplay,
					TAGGED_PROPVAL{PT_BINARY, temp_bin});

				// If the offsets of start or end times are not set, probably
				// the client didn't send the offset information in date tags.
				// Try to get the offset from the timezone definition.
				if(startOffset == 0 || endOffset == 0)
				{
					EXT_PULL ext_pull;
					TIMEZONEDEFINITION tzdef;
					ext_pull.init(buf->data(), buf->size(), alloc, EXT_FLAG_UTF16);
					if(ext_pull.g_tzdef(&tzdef) != EXT_ERR_SUCCESS)
						throw EWS::DispatchError(E3294);
					startOffset = endOffset = offset_from_tz(&tzdef, startTime);
				}
				item.Start.value().offset = std::chrono::minutes(startOffset);
				item.End.value().offset = std::chrono::minutes(endOffset);
			}
		}
	}
	// The named prop tags are not available in the shape at this point, so set
	// values of them at the end.
	auto start = EWSContext::construct<uint64_t>(rop_util_unix_to_nttime(startTime + startOffset * 60));
	shape.write(NtCommonStart, TAGGED_PROPVAL{PT_SYSTIME, start});
	shape.write(NtAppointmentStartWhole, TAGGED_PROPVAL{PT_SYSTIME, start});
	shape.write(TAGGED_PROPVAL{PR_START_DATE, start});
	shape.write(NtReminderTime, TAGGED_PROPVAL{PT_SYSTIME, start});
	auto end = EWSContext::construct<uint64_t>(rop_util_unix_to_nttime(endTime + endOffset * 60));
	shape.write(NtCommonEnd, TAGGED_PROPVAL{PT_SYSTIME, end});
	shape.write(NtAppointmentEndWhole, TAGGED_PROPVAL{PT_SYSTIME, end});
	shape.write(TAGGED_PROPVAL{PR_END_DATE, end});

	shape.write(NtReminderSet, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(
		item.ReminderIsSet && item.ReminderIsSet.value() ? 1 : 0)});
	uint32_t reminderdelta = 0;
	if(item.ReminderMinutesBeforeStart)
		reminderdelta = item.ReminderMinutesBeforeStart.value();
	shape.write(NtReminderDelta, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(reminderdelta)});
	shape.write(NtReminderSignalTime, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(
		rop_util_unix_to_nttime(startTime + (startOffset - reminderdelta) * 60))});

	if(item.UID)
	{
		BINARY goid_bin;
		auto uid = item.UID.value().c_str();
		uid_to_goid(uid, goid_bin);
		BINARY* goid = construct<BINARY>(BINARY{goid_bin.cb, {goid_bin.pb}});
		shape.write(NtGlobalObjectId, TAGGED_PROPVAL{PT_BINARY, goid});
		shape.write(NtCleanGlobalObjectId, TAGGED_PROPVAL{PT_BINARY, goid});
	}
}

/**
 * @brief      Write contact item properties to shape
 *
 * Must forward call to tItem overload.
 *
 * Currently a stub.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Contact item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content
 */
void EWSContext::toContent(const std::string& dir, tContact& item, sShape& shape, MCONT_PTR& content) const
{
	toContent(dir, static_cast<tItem&>(item), shape, content);
	shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, const_cast<char*>("IPM.Contact")});
	if(item.CompleteName) {
		writeProp(shape, item.CompleteName->Title, PR_TITLE);
		writeProp(shape, item.CompleteName->FirstName, PR_GIVEN_NAME);
		writeProp(shape, item.CompleteName->MiddleName, PR_MIDDLE_NAME);
		writeProp(shape, item.CompleteName->LastName, PR_SURNAME);
		writeProp(shape, item.CompleteName->Suffix, PR_GENERATION);
		writeProp(shape, item.CompleteName->Initials, PR_INITIALS);
		writeProp(shape, item.CompleteName->FullName, PR_DISPLAY_NAME);
		writeProp(shape, item.CompleteName->Nickname, PR_NICKNAME);
	}

	writeProp(shape, item.DisplayName, PR_DISPLAY_NAME);
	writeProp(shape, item.GivenName, PR_GIVEN_NAME);
	writeProp(shape, item.Initials, PR_INITIALS);
	writeProp(shape, item.MiddleName, PR_MIDDLE_NAME);
	writeProp(shape, item.Nickname, PR_NICKNAME);
	writeProp(shape, item.CompanyName, PR_COMPANY_NAME);
	writeProp(shape, item.AssistantName, PR_ASSISTANT);
	writeProp(shape, item.Birthday, PR_BIRTHDAY);
	writeProp(shape, item.BusinessHomePage, PR_BUSINESS_HOME_PAGE);
	writeProp(shape, item.Department, PR_DEPARTMENT_NAME);
	writeProp(shape, item.Generation, PR_GENERATION);
	writeProp(shape, item.JobTitle, PR_TITLE);
	writeProp(shape, item.CompanyName, PR_COMPANY_NAME);
	writeProp(shape, item.OfficeLocation, PR_OFFICE_LOCATION);
	writeProp(shape, item.SpouseName, PR_SPOUSE_NAME);
	writeProp(shape, item.Surname, PR_SURNAME);
	writeProp(shape, item.WeddingAnniversary, PR_WEDDING_ANNIVERSARY);

	if(!item.FileAs && item.DisplayName)
		shape.write(NtFileAs, TAGGED_PROPVAL{PT_UNICODE, cpystr(*item.DisplayName)});
	if(item.PostalAddressIndex)
		shape.write(NtPostalAddressIndex, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(item.PostalAddressIndex->index())});
	if(item.EmailAddresses)
		for(const tEmailAddressDictionaryEntry& entry : *item.EmailAddresses) {
			const PROPERTY_NAME& name = entry.Key == Enum::EmailAddress1? NtEmailAddress1 :
			                            entry.Key == Enum::EmailAddress2? NtEmailAddress2 : NtEmailAddress3;
			shape.write(name, TAGGED_PROPVAL{PT_UNICODE, const_cast<char*>(entry.Entry.c_str())});
		}
	if(item.PhysicalAddresses)
		for(const tPhysicalAddressDictionaryEntry& entry : *item.PhysicalAddresses) {
			std::string address = item.mkAddress(entry.Street, entry.City, entry.State, entry.PostalCode,
			                                     entry.CountryOrRegion);
			if(entry.Key == Enum::Business) {
				writeProp(shape, entry.City, NtBusinessAddressCity, PT_UNICODE);
				writeProp(shape, entry.CountryOrRegion, NtBusinessAddressCountry, PT_UNICODE);
				writeProp(shape, entry.PostalCode, NtBusinessAddressPostalCode, PT_UNICODE);
				writeProp(shape, entry.State, NtBusinessAddressState, PT_UNICODE);
				writeProp(shape, entry.Street, NtBusinessAddressStreet, PT_UNICODE);
				shape.write(NtBusinessAddress, TAGGED_PROPVAL{PT_UNICODE, cpystr(address)});
			} else if(entry.Key == Enum::Home) {
				writeProp(shape, entry.City, PR_HOME_ADDRESS_CITY);
				writeProp(shape, entry.CountryOrRegion, PR_HOME_ADDRESS_COUNTRY);
				writeProp(shape, entry.PostalCode, PR_HOME_ADDRESS_POSTAL_CODE);
				writeProp(shape, entry.State, PR_HOME_ADDRESS_STATE_OR_PROVINCE);
				writeProp(shape, entry.Street, PR_HOME_ADDRESS_STREET);
				shape.write(NtHomeAddress, TAGGED_PROPVAL{PT_UNICODE, cpystr(address)});
			} else if(entry.Key == Enum::Other) {
				writeProp(shape, entry.City, PR_OTHER_ADDRESS_CITY);
				writeProp(shape, entry.CountryOrRegion, PR_OTHER_ADDRESS_COUNTRY);
				writeProp(shape, entry.PostalCode, PR_OTHER_ADDRESS_POSTAL_CODE);
				writeProp(shape, entry.State, PR_OTHER_ADDRESS_STATE_OR_PROVINCE);
				writeProp(shape, entry.Street, PR_OTHER_ADDRESS_STREET);
				shape.write(NtOtherAddress, TAGGED_PROPVAL{PT_UNICODE, cpystr(address)});
			}
		}
	if(item.PhoneNumbers)
		for(const tPhoneNumberDictionaryEntry& entry : *item.PhoneNumbers) {
			uint32_t tag;
			switch(entry.Key) {
			case 0: tag = PR_ASSISTANT_TELEPHONE_NUMBER; break;
			case 1: tag = PR_BUSINESS_FAX_NUMBER; break;
			case 2: tag = PR_BUSINESS_TELEPHONE_NUMBER; break;
			case 3: tag = PR_BUSINESS2_TELEPHONE_NUMBER; break;
			case 4: tag = PR_CALLBACK_TELEPHONE_NUMBER; break;
			case 6: tag = PR_COMPANY_MAIN_PHONE_NUMBER; break;
			case 7: tag = PR_HOME_FAX_NUMBER; break;
			case 8: tag = PR_HOME_TELEPHONE_NUMBER; break;
			case 9: tag = PR_HOME2_TELEPHONE_NUMBER; break;
			case 11: tag = PR_MOBILE_TELEPHONE_NUMBER; break;
			case 13: tag = PR_OTHER_TELEPHONE_NUMBER; break;
			case 14: tag = PR_PAGER_TELEPHONE_NUMBER; break;
			case 15: tag = PR_PRIMARY_TELEPHONE_NUMBER; break;
			case 16: tag = PR_RADIO_TELEPHONE_NUMBER; break;
			default: continue;
			}
			shape.write(TAGGED_PROPVAL{tag, const_cast<char*>(entry.Entry.c_str())});
		}
	if(item.Children) {
		if(item.Children->size() > std::numeric_limits<uint32_t>::max())
			throw InputError(E3258);
		STRING_ARRAY* sa = construct<STRING_ARRAY>(STRING_ARRAY{static_cast<uint32_t>(item.Children->size()),
		                                                        alloc<char*>(item.Children->size())});
		auto it = sa->begin();
		for(const std::string& child : *item.Children)
			*it++ = const_cast<char*>(child.c_str());
	}
}

/**
 * @brief      Write item properties to shape
 *
 * Provides base for all derived classes and should be called before further
 * processing.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tItem& item, sShape& shape, MCONT_PTR& content) const
{
	if(item.MimeContent)
		content = toContent(dir, *item.MimeContent);
	if(item.Body)
	{
		auto body = const_cast<char*>(item.Body.value().c_str());
		if(item.Body.value().BodyType == Enum::Text)
			shape.write(TAGGED_PROPVAL{PR_BODY, body});
		else if(item.Body.value().BodyType == Enum::HTML)
		{
			size_t bodylen = strlen(body);
			if(bodylen > std::numeric_limits<uint32_t>::max())
				throw InputError(E3256);
			BINARY* html = construct<BINARY>(BINARY{uint32_t(strlen(body)),
			                                       {reinterpret_cast<uint8_t*>(body)}});
			shape.write(TAGGED_PROPVAL{PR_HTML, html});
		}
	}
	if(item.ItemClass)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, deconst(item.ItemClass->c_str())});
	if(item.Sensitivity)
		shape.write(TAGGED_PROPVAL{PR_SENSITIVITY, construct<uint32_t>(item.Sensitivity->index())});
	if(item.Categories && item.Categories->size() && item.Categories->size() <= std::numeric_limits<uint32_t>::max()) {
		uint32_t count = item.Categories->size();
		STRING_ARRAY* categories = construct<STRING_ARRAY>(STRING_ARRAY{count, alloc<char*>(count)});
		char** dest = categories->ppstr;
		for(const std::string& category : *item.Categories) {
			*dest = alloc<char>(category.size()+1);
			HX_strlcpy(*dest++, category.c_str(), category.size()+1);
		}
		shape.write(NtCategories, TAGGED_PROPVAL{PT_MV_UNICODE, categories});
	}
	if(item.Importance)
		shape.write(TAGGED_PROPVAL{PR_IMPORTANCE, construct<uint32_t>(item.Importance->index())});
	if(item.Subject)
		shape.write(TAGGED_PROPVAL{PR_SUBJECT, deconst(item.Subject->c_str())});

	auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
	shape.write(TAGGED_PROPVAL{PR_CREATION_TIME, now});
	shape.write(TAGGED_PROPVAL{PR_LOCAL_COMMIT_TIME, now});

	for(const tExtendedProperty& prop : item.ExtendedProperty)
		prop.ExtendedFieldURI.tag()? shape.write(prop.propval) : shape.write(prop.ExtendedFieldURI.name(), prop.propval);
}

/**
 * @brief      Write message properties to shape
 *
 * Must forward call to tItem overload.
 *
 * @param      dir       Home directory of the target store
 * @param      item      Message to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content
 *
 * @todo Map remaining fields
 */
void EWSContext::toContent(const std::string& dir, tMessage& item, sShape& shape, MCONT_PTR& content) const
{
	toContent(dir, static_cast<tItem&>(item), shape, content);
	size_t recipients = (item.ToRecipients? item.ToRecipients->size() : 0)
	                    + (item.CcRecipients? item.CcRecipients->size() : 0)
	                    + (item.BccRecipients? item.BccRecipients->size() : 0);
	if(recipients) {
		if(!content->children.prcpts && !(content->children.prcpts = tarray_set_init()))
			throw EWSError::NotEnoughMemory(E3288);
		TARRAY_SET* rcpts = content->children.prcpts;
		if(item.ToRecipients)
			for(const auto& rcpt : *item.ToRecipients)
				rcpt.mkRecipient(rcpts->emplace(), MAPI_TO);
		if(item.CcRecipients)
			for(const auto& rcpt : *item.CcRecipients)
				rcpt.mkRecipient(rcpts->emplace(), MAPI_CC);
		if(item.BccRecipients)
			for(const auto& rcpt : *item.BccRecipients)
				rcpt.mkRecipient(rcpts->emplace(), MAPI_BCC);
	}
	if(item.From) {
		if(item.From->Mailbox.RoutingType)
			shape.write(TAGGED_PROPVAL{PR_SENT_REPRESENTING_ADDRTYPE, item.From->Mailbox.RoutingType->data()});
		if(item.From->Mailbox.EmailAddress)
			shape.write(TAGGED_PROPVAL{PR_SENT_REPRESENTING_EMAIL_ADDRESS, item.From->Mailbox.EmailAddress->data()});
		if(item.From->Mailbox.Name)
			shape.write(TAGGED_PROPVAL{PR_SENT_REPRESENTING_NAME, item.From->Mailbox.Name->data()});
	}
}

/**
 * @brief      Mark folder as updated
 *
 * @param      dir       Home directory of user or domain
 * @param      folder    Folder to update
 */
void EWSContext::updated(const std::string& dir, const sFolderSpec& folder) const
{
	if(!folder.target)
		throw DispatchError(E3172);
	const BINARY* pclData = getFolderProp<BINARY>(dir, folder.folderId, PR_PREDECESSOR_CHANGE_LIST);
	PCL pclOld;
	if(pclData && !pclOld.deserialize(pclData))
		throw DispatchError(E3170);
	uint64_t changeNum;
	if(!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
		throw DispatchError(E3171);
	bool isPublic = folder.location == folder.PUBLIC;
	uint32_t accountId = getAccountId(*folder.target, isPublic);
	XID changeKey{(isPublic? rop_util_make_domain_guid : rop_util_make_user_guid)(accountId), changeNum};
	BINARY ckeyBin = serialize(changeKey);
	auto ppcl = mkPCL(changeKey, std::move(pclOld));
	uint64_t now = rop_util_current_nttime();
	TAGGED_PROPVAL props[] = {{PidTagChangeNumber, &changeNum},
		                      {PR_CHANGE_KEY, &ckeyBin,},
		                      {PR_PREDECESSOR_CHANGE_LIST, ppcl.get()},
		                      {PR_LAST_MODIFICATION_TIME, &now}};
	TPROPVAL_ARRAY proplist{std::size(props), props};
	PROBLEM_ARRAY problems;
	if(!m_plugin.exmdb.set_folder_properties(dir.c_str(), CP_ACP, folder.folderId, &proplist, &problems) || problems.count)
		throw EWSError::FolderSave(E3173);
}

/**
 * @brief      Create subscriptions
 *
 * @param      folderIds  Folders to subscribe to
 * @param      eventMask  Events to subscribe to
 * @param      all        Whether to subscribe to all folders
 * @param      timeout    Timeout (minutes) of the subscription
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const std::vector<sFolderId>& folderIds, uint16_t eventMask, bool all, uint32_t timeout) const
{
	tSubscriptionId subscriptionId(timeout);
	auto mgr = m_plugin.make_submgr(subscriptionId, m_auth_info.username);
	if(folderIds.empty()) {
		mgr->mailboxInfo = getMailboxInfo(m_auth_info.maildir, false);
		detail::ExmdbSubscriptionKey key =
			m_plugin.subscribe(m_auth_info.maildir, eventMask, true, rop_util_make_eid_ex(1, PRIVATE_FID_IPMSUBTREE),
		                       subscriptionId.ID);
		mgr->inner_subs.emplace_back(key);
		return subscriptionId;
	}
	mgr->inner_subs.reserve(folderIds.size());
	std::string target;
	std::string maildir;
	for(const sFolderId& f : folderIds) {
		sFolderSpec folderspec = std::visit([&](const auto& fid){return resolveFolder(fid);}, f);
		if(!folderspec.target)
			folderspec.target = m_auth_info.username;
		if(target.empty()) {
			target = *folderspec.target;
			maildir = get_maildir(*folderspec.target);
			mgr->mailboxInfo = getMailboxInfo(maildir, folderspec.location == folderspec.PUBLIC);
		} else if(target != *folderspec.target)
			throw EWSError::InvalidSubscriptionRequest(E3200);
		if(!(permissions(maildir, folderspec.folderId) & frightsReadAny))
			continue; // TODO: proper error handling
		mgr->inner_subs.emplace_back(m_plugin.subscribe(maildir,
			eventMask, all, folderspec.folderId, subscriptionId.ID));
	}
	return subscriptionId;
}

/**
 * @brief      Create new pull subscription
 *
 * @param      req    Pull subscription request
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const tPullSubscriptionRequest& req) const
{
	bool all = req.SubscribeToAllFolders && *req.SubscribeToAllFolders;
	if(all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3198);
	return subscribe(req.FolderIds? *req.FolderIds : std::vector<sFolderId>(), req.eventMask(), all, req.Timeout);
}

/**
 * @brief      Create new streaming subscription
 *
 * @param      req    Streaming subscription request
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const tStreamingSubscriptionRequest& req) const
{
	bool all = req.SubscribeToAllFolders && *req.SubscribeToAllFolders;
	if(all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3198);
	return subscribe(req.FolderIds? *req.FolderIds : std::vector<sFolderId>(), req.eventMask(), all, 5);
}

/**
 * @brief     End subscriptions
 *
 * @param subscriptionId   Subscription to remove
 */
bool EWSContext::unsubscribe(const Structures::tSubscriptionId& subscriptionId) const
{return m_plugin.unsubscribe(subscriptionId.ID, m_auth_info.username);}

/**
 * @brief      Add update tags to the shape
 *
 * @param      dir       Home directory of user or domain
 * @param      username  Account name of the user updating the message
 * @param      mid       Message ID
 */
void EWSContext::updated(const std::string& dir, const sMessageEntryId& mid, sShape& shape) const
{
	uint64_t changeNum;
	if(!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
		throw DispatchError(E3084);
	uint64_t localCommitTime = rop_util_current_nttime();
	shape.write(TAGGED_PROPVAL{PR_LOCAL_COMMIT_TIME, construct<uint64_t>(localCommitTime)});
	shape.write(TAGGED_PROPVAL{PR_LAST_MODIFICATION_TIME, construct<uint64_t>(localCommitTime)});

	char displayName[1024];
	if(!mysql_adaptor_get_user_displayname(m_auth_info.username, displayName, std::size(displayName)) || !*displayName)
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFIER_NAME, strcpy(alloc<char>(strlen(displayName)+1), displayName)});
	else
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFIER_NAME, const_cast<char*>(m_auth_info.username)});

	static constexpr size_t ABEIDBUFFSIZE = 1280;
	uint8_t* abEidBuff = alloc<uint8_t>(ABEIDBUFFSIZE);
	EXT_PUSH wAbEid;
	std::string essdn;
	auto err = cvt_username_to_essdn(m_auth_info.username,
	           m_plugin.x500_org_name.c_str(), mysql_adaptor_get_user_ids,
	           mysql_adaptor_get_domain_ids, essdn);
	if (err != ecSuccess)
		throw DispatchError(E3085);
	HX_strupper(essdn.data());
	EMSAB_ENTRYID abEid{0, DT_MAILUSER, essdn.data()};
	if(!wAbEid.init(abEidBuff, ABEIDBUFFSIZE, EXT_FLAG_UTF16) || wAbEid.p_abk_eid(abEid) != EXT_ERR_SUCCESS)
		throw DispatchError(E3085);
	BINARY* abEidContainer = construct<BINARY>(BINARY{wAbEid.m_offset, {abEidBuff}});
	shape.write(TAGGED_PROPVAL{PR_LAST_MODIFIER_ENTRYID, abEidContainer});

	XID changeKey{(mid.isPrivate()? rop_util_make_user_guid : rop_util_make_domain_guid)(mid.accountId()), changeNum};
	BINARY* changeKeyContainer = construct<BINARY>(serialize(changeKey));
	shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, changeKeyContainer});

	const BINARY* currentPclContainer = getItemProp<BINARY>(dir, mid.messageId(), PR_PREDECESSOR_CHANGE_LIST);
	PCL pcl;
	if (currentPclContainer != nullptr && !pcl.deserialize(currentPclContainer))
		throw DispatchError(E3087);
	auto serializedPcl = mkPCL(changeKey, std::move(pcl));
	BINARY* newPclContainer = construct<BINARY>(BINARY{serializedPcl->cb, {alloc<uint8_t>(serializedPcl->cb)}});
	memcpy(newPclContainer->pv, serializedPcl->pv, serializedPcl->cb);
	shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, newPclContainer});

	shape.write(TAGGED_PROPVAL{PidTagChangeNumber, construct<uint64_t>(changeNum)});
}

/**
 * @brief      Write permissions
 *
 * @param      dir     Store to write to
 * @param      fid     Folder Id to set permissions on
 * @param      perms   Permission data to write
 */
void EWSContext::writePermissions(const std::string& dir, uint64_t fid, const std::vector<PERMISSION_DATA>& perms) const
{
		size_t memberCount = perms.size();
		if(memberCount > std::numeric_limits<uint16_t>::max())
			throw InputError(E3285);
		const auto& exmdb = m_plugin.exmdb;
		if(!exmdb.empty_folder_permission(dir.c_str(), fid))
			throw EWSError::FolderSave(E3286);
		if(!exmdb.update_folder_permission(dir.c_str(), fid, false, uint16_t(memberCount), perms.data()))
			throw EWSError::FolderSave(E3287);
}

/**
 * @brief      Validate consistency of message entry id
 *
 * @param      meid          Message entry id to validate
 * @param      throwOnError  Whether to throw an appropriate EWSError instead of returning
 *
 * @return     true if entry id is consistent, false otherwise (and throwOnError is false)
 */
void EWSContext::validate(const std::string& dir, const sMessageEntryId& meid) const
{
	const uint64_t* parentFid = nullptr;
	try {
		parentFid = getItemProp<uint64_t>(dir, meid.messageId(), PidTagParentFolderId);
	} catch (const DispatchError&) {
	}
	if(!parentFid)
		throw EWSError::ItemNotFound(E3187);
	if(rop_util_get_gc_value(*parentFid) != meid.folderId())
		throw EWSError::InvalidId(E3188);
}

/**
 * @brief     Check whether id is of the correct type
 *
 * @param     have       Observed ID type
 * @param     wanted     Expected ID type
 *
 * @throw     EWSError   Exception with details
 */
void EWSContext::assertIdType(tBaseItemId::IdType have, tBaseItemId::IdType wanted)
{
	using IdType = tBaseItemId::IdType;
	if(have == wanted)
		return;
	if(wanted == IdType::ID_FOLDER && have == IdType::ID_ITEM)
		throw EWSError::CannotUseItemIdForFolderId(E3213);
	else if(wanted == IdType::ID_ITEM && have == IdType::ID_FOLDER)
		throw EWSError::CannotUseFolderIdForItemId(E3214);
	else if(wanted == IdType::ID_ATTACHMENT)
		throw EWSError::InvalidIdNotAnItemAttachmentId(E3215);
	throw EWSError::InvalidId(E3216);
}

/**
 * @brief     Convert EXT_PUSH/EXT_PULL return code to exception
 *
 * @param     code           ext_buffer return code
 * @param     msg            Error message
 * @param     responseCode   EWSError response code for generic errors
 *
 * @todo      Add more exceptions for better differentiation
 */
void EWSContext::ext_error(pack_result code, const char* msg, const char* responseCode)
{
	switch(code)
	{
	case EXT_ERR_SUCCESS: return;
	case EXT_ERR_ALLOC: throw Exceptions::EWSError::NotEnoughMemory(msg? msg : E3128);
	case EXT_ERR_BUFSIZE:
	default:
		if(responseCode && msg)
			throw Exceptions::EWSError(responseCode, msg);
		else
			throw DispatchError(code == EXT_ERR_BUFSIZE ? E3145 :
			      Exceptions::E3028(static_cast<int>(code)));
	}
}

}
