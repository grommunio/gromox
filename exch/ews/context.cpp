// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <sstream>
#include <fmt/format.h>
#include <libHX/endian.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <vmime/message.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/freebusy.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "exceptions.hpp"
#include "ews.hpp"
#include "exceptions.hpp"
#include "namedtags.hpp"
#include "structures.hpp"
#include "../bounce_exch.cpp"

DECLARE_HPM_API(gromox::EWS, extern);

namespace gromox::EWS {

using namespace Exceptions;
using namespace Structures;

namespace {

struct DelegFolderPerm {
	uint64_t fid;
	std::optional<Enum::DelegateFolderPermissionLevelType> tDelegatePermissions::*field;


};

constexpr DelegFolderPerm delegFolderMap[] = {
	{PRIVATE_FID_CALENDAR, &tDelegatePermissions::CalendarFolderPermissionLevel},
	{PRIVATE_FID_TASKS,    &tDelegatePermissions::TasksFolderPermissionLevel},
	{PRIVATE_FID_INBOX,    &tDelegatePermissions::InboxFolderPermissionLevel},
	{PRIVATE_FID_CONTACTS, &tDelegatePermissions::ContactsFolderPermissionLevel},
	{PRIVATE_FID_NOTES,    &tDelegatePermissions::NotesFolderPermissionLevel},
	{PRIVATE_FID_JOURNAL,  &tDelegatePermissions::JournalFolderPermissionLevel},
};

/**
 * @brief      Convert string to lower case
 *
 * @param      str     String to convert
 *
 * @return     Reference to the string
 */
inline std::string &tolower_inplace(std::string &str)
{
	std::transform(str.begin(), str.end(), str.begin(), HX_tolower);
	return str;
}

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
 * @brief      Write property to shape (string specialization)
 *
 * @param      shape   Shape to write to
 * @param      value   value to write
 * @param      tag     Property tag to use
 */
static void writeProp(sShape &shape, const std::optional<std::string> &value, proptag_t tag)
{
	if (value)
		shape.write(TAGGED_PROPVAL{tag, const_cast<char *>(value->c_str())});
}

/**
 * @brief      Write property to shape (time point specialization)
 *
 * @param      shape   Shape to write to
 * @param      value   value to write
 * @param      tag     Property tag to use
 */
static void writeProp(sShape &shape, const std::optional<sTimePoint> &value, proptag_t tag)
{
	if (value)
		shape.write(TAGGED_PROPVAL{tag, EWSContext::construct<uint64_t>(value->toNT())});
}

/**
 * @brief      Write property to shape (string specialization)
 *
 * @param      shape   Shape to write to
 * @param      value   value to write
 * @param      name    Property name to write to
 * @param      type    Property type to use
 */
void writeProp(sShape &shape, const std::optional<std::string> &value,
    const PROPERTY_NAME &name, proptype_t type)
{
	if (value)
		shape.write(name, TAGGED_PROPVAL{type, const_cast<char *>(value->c_str())});
}

void writeBoolProp(sShape &shape, const std::optional<bool> &value, proptag_t tag)
{
	if (value)
		shape.write(TAGGED_PROPVAL{tag, EWSContext::construct<uint8_t>(*value ? 1 : 0)});
}

uint64_t toNT(const time_point& tp)
{
	using namespace std::chrono;
	auto secs = duration_cast<seconds>(tp.time_since_epoch());
	return rop_util_unix_to_nttime(secs.count());
}

/**
 * @brief      Convert string week day representation to a pattern type
 * specific bit mask
 *
 * @param daysOfWeek
 * @param weekrecur
 *
 * PatternTypeSpecific Week/MonthNth (MS-OXOCAL v22.1 §2.2.1.44.1.4)
 * X  (1 bit): This bit is not used. MUST be zero and MUST be ignored.
 * Sa (1 bit): (0x00000040) The event occurs on Saturday.
 * F  (1 bit): (0x00000020) The event occurs on Friday.
 * Th (1 bit): (0x00000010) The event occurs on Thursday.
 * W  (1 bit): (0x00000008) The event occurs on Wednesday.
 * Tu (1 bit): (0x00000004) The event occurs on Tuesday.
 * M  (1 bit): (0x00000002) The event occurs on Monday.
 * Su (1 bit): (0x00000001) The event occurs on Sunday.
 * unused (3 bytes): These bits are not used. MUST be zero and MUST be ignored.
 * Nth Day of month: (bits M, Tu, W, Th, F, Sa, Su are set) - only rptMonthNth
 * Nth Weekday of month: (bits M, Tu, W, Th, F are set) - only rptMonthNth
 * Nth Weekend of month: (bits Sa, Su are set) - only rptMonthNth
 */
void daysofweek_to_pts(const std::string& daysOfWeek, uint32_t& weekrecur)
{
	std::istringstream strstream(daysOfWeek);
	std::string dayOfWeek;

	while (strstream >> dayOfWeek) {
		tolower_inplace(dayOfWeek);
		if (dayOfWeek == "day") {
			weekrecur |= week_recur_bit::day;
		} else if (dayOfWeek == "weekday") {
			weekrecur |= week_recur_bit::weekday;
		} else if (dayOfWeek == "weekendday") {
			weekrecur |= week_recur_bit::weekend;
		} else if (dayOfWeek == "sunday") {
			weekrecur |= week_recur_bit::sun;
		} else if (dayOfWeek == "monday") {
			weekrecur |= week_recur_bit::mon;
		} else if (dayOfWeek == "tuesday") {
			weekrecur |= week_recur_bit::tue;
		} else if (dayOfWeek == "wednesday") {
			weekrecur |= week_recur_bit::wed;
		} else if (dayOfWeek == "thursday") {
			weekrecur |= week_recur_bit::thu;
		} else if (dayOfWeek == "friday") {
			weekrecur |= week_recur_bit::fri;
		} else if (dayOfWeek == "saturday") {
			weekrecur |= week_recur_bit::sat;
		} else {
			throw EWSError::CalendarInvalidRecurrence(E3260);
		}
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
		// determine the first day of the week in which the first event occurs
		auto startdate = rop_util_rtime_to_unix(recur_pat.startdate);
		if (gmtime_r(&startdate, tmp_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3261);
		auto weekstart = rop_util_unix_to_rtime(
			 startdate - ((tmp_tm->tm_wday - recur_pat.firstdow + 7) % 7) * 86400);
		recur_pat.firstdatetime = weekstart % (10080 * recur_pat.period);
		break;
	}
	case rptMonth:
	case rptMonthEnd:
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
	while (weekrecur) {
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
	/* every weekday is a daily frequency with a weekly pattern */
	switch (recur_pat.patterntype == rptWeek ? IDC_RCEV_PAT_ORB_WEEKLY :
	        recur_pat.recurfrequency) {
	case IDC_RCEV_PAT_ORB_DAILY:
		if (recur_pat.patterntype == rptMinute)
			// occurrencecount - 1 because the first day already counts
			enddate += recur_pat.period * 60 * (recur_pat.occurrencecount - 1);
		break;
	case IDC_RCEV_PAT_ORB_WEEKLY: {
		uint8_t daycount = calc_daycount(recur_pat.pts.weekrecur);
		if (daycount == 0)
			throw EWSError::CalendarInvalidRecurrence(E3282);
		forwardcount = (recur_pat.occurrencecount - 1) / daycount;
		// number of remaining occurrences after the week skip
		uint32_t restocc = recur_pat.occurrencecount - forwardcount * daycount - 1;
		forwardcount *= recur_pat.period;
		enddate += forwardcount * 604800; // seconds in a week
		if (gmtime_r(&enddate, tmp_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3262);
		for (int j = 1; restocc > 0; ++j) {
			if ((tmp_tm->tm_wday + j) % 7 == static_cast<int>(recur_pat.firstdow))
				enddate += (recur_pat.period - 1) * 604800;
			// If this is a matching day, one occurrence less to process
			if (recur_pat.pts.weekrecur & (1 << ((tmp_tm->tm_wday + j) % 7)))
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
		while (forwardcount > 0) {
			// month in seconds
			enddate += ical_get_monthdays(curyear, curmonth) * 86400;
			if (curmonth >= 12) {
				curmonth = 1;
				++curyear;
			} else {
				++curmonth;
			}
			--forwardcount;
		}
		if (gmtime_r(&enddate, tmp_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3263);
		tmp_tm->tm_year += 1900;
		++tmp_tm->tm_mon;

		switch(recur_pat.patterntype) {
		case rptMonth:
			// compensation between 28 and 31
			if (recur_pat.pts.dayofmonth >= 28 &&
			    recur_pat.pts.dayofmonth <= 31 &&
			    tmp_tm->tm_mday < static_cast<int>(recur_pat.pts.dayofmonth)) {
				if (tmp_tm->tm_mday < 28)
					enddate -= tmp_tm->tm_mday * 86400;
				else
					enddate += (ical_get_monthdays(tmp_tm->tm_year, tmp_tm->tm_mon) - tmp_tm->tm_mday) * 86400;
			}
			break;
		case rptMonthNth:
			if (recur_pat.pts.monthnth.recurnum == 5)
				// Set date on the last day of the last month
				enddate += (ical_get_monthdays(tmp_tm->tm_year, tmp_tm->tm_mon) - tmp_tm->tm_mday) * 86400;
			else
				// Set date on the first day of the last month
				enddate -= (tmp_tm->tm_mday - 1) * 86400;

			// calculate the day of the last occurrence
			for (int j = 0; j < 7; ++j) {
				if (gmtime_r(&enddate, tmp_tm) == nullptr)
					throw EWSError::CalendarInvalidRecurrence(E3264);
				if (recur_pat.pts.monthnth.recurnum == 5 &&
				  (1 << (tmp_tm->tm_wday - j) % 7) & recur_pat.pts.monthnth.weekrecur)
					enddate -= j * 86400;
				else if (recur_pat.pts.monthnth.recurnum != 5 &&
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
	if (strncasecmp(uid, EncodedGlobalId_hex, 32) == 0) {
		if (!decode_hex_binary(uid, tmp_buff, std::size(tmp_buff)))
			throw EWSError::CorruptData(E3296(uid));
		ext_pull.init(tmp_buff, uid_len / 2, EWSContext::alloc, 0);
		if (ext_pull.g_goid(&goid) != pack_result::ok)
			throw EWSError::InternalServerError(E3297(uid));
		if (ext_pull.m_offset == uid_len / 2 &&
		    (goid.year < 1601 || goid.year > 4500 ||
		    goid.month > 12 || goid.month == 0 ||
		    goid.day > ical_get_monthdays(goid.year, goid.month)))
			goid.year = goid.month = goid.day = 0;
	} else {
		goid = {};
		goid.arrayid = EncodedGlobalId;
		goid.year = goid.month = goid.day = 0;
		goid.creationtime = 0;
		goid.data.cb = 12 + uid_len;
		goid.data.pv = EWSContext::alloc(goid.data.cb);
		if (goid.data.pv == nullptr)
			throw EWSError::NotEnoughMemory(E3298);
		static_assert(sizeof(ThirdPartyGlobalId) == 12);
		memcpy(goid.data.pb, ThirdPartyGlobalId, 12);
		memcpy(goid.data.pb + 12, uid, uid_len);
	}
	if (!ext_push.init(tmp_buff, 1024, 0) ||
	    ext_push.p_goid(goid) != pack_result::ok)
		throw EWSError::InternalServerError(E3299);
	goid_bin.cb = ext_push.m_offset;
	goid_bin.pv = EWSContext::alloc(goid_bin.cb);
	if (goid_bin.pv == nullptr)
		throw EWSError::NotEnoughMemory(E3321);
	memcpy(goid_bin.pv, ext_push.m_udata, goid_bin.cb);
}

/**
 * @brief      Mark an item's ItemId as an occurrence ID
 *
 * Appends the basedate to the entry ID and sets the type to ID_OCCURRENCE
 * so clients can use this ItemId to address the specific occurrence.
 */
void markOccurrenceId(sItem &item, uint32_t basedate)
{
	auto setter = [bd = cpu_to_le32(basedate)](auto &it) {
		if (!it.ItemId)
			return;
		it.ItemId->Id.append(reinterpret_cast<const char *>(&bd),
		                     sizeof(bd));
		it.ItemId->type = tBaseItemId::ID_OCCURRENCE;
	};
	std::visit(setter, item);
}

}

/**
 * Find EXCEPTIONINFO for this basedate from the recurrence blob.
 * It has the correct startdatetime/enddatetime for the exception,
 * unlike the embedded message which may have the master's dates.
 */
static const EXCEPTIONINFO *
find_exc(const APPOINTMENT_RECUR_PAT &apr, uint32_t basedate)
{
	uint32_t bd = basedate / 1440;
	for (const auto &ei : apr.pexceptioninfo)
		if (ei.originalstartdate / 1440 == bd)
			return &ei;
	return nullptr;
}

/**
 * @brief      Test whether a date is truly deleted (not a modified exception)
 *
 * Compared by day, as imported blobs carry a time of day. The modified
 * list holds the new day of a moved exception, so only the exceptions
 * tell whether the original day was modified.
 *
 * @param      apr    Appointment recurrence pattern
 * @param      date   Date in rtime format
 *
 * @return     true if the date is deleted and not modified
 */
bool isTrulyDeleted(const APPOINTMENT_RECUR_PAT &apr, uint32_t date)
{
	auto &rp = apr.recur_pat;
	auto same_day = [&](uint32_t d) { return d / 1440 == date / 1440; };
	return std::any_of(rp.pdeletedinstancedates.cbegin(), rp.pdeletedinstancedates.cend(), same_day) &&
	       find_exc(apr, date) == nullptr;
}

/**
 * @brief      Day of month of a MonthNth slot
 *
 * Picks the @order'th (1–4, or 5 for the last) of those days in the month
 * whose weekday is in @mask (bit 0 = Sunday), like RRULE BYDAY with BYSETPOS.
 */
static int nth_matching_mday(int year, int month, unsigned int order,
    uint32_t mask)
{
	int mdays = ical_get_monthdays(year, month);
	int dow1 = ical_get_dayofweek(year, month, 1);
	auto match = [&](int d) { return mask & (1U << (dow1 + d - 1) % 7); };
	if (order == 5) {
		for (int d = mdays; d >= 1; --d)
			if (match(d))
				return d;
		return 0;
	}
	for (int d = 1, n = 0; d <= mdays; ++d)
		if (match(d) && ++n == static_cast<int>(order))
			return d;
	return 0;
}

/**
 * @brief      Enumerate the visible occurrence dates of a recurrence pattern
 *
 * Walks the pattern in chronological order and invokes @cb for every
 * occurrence that is not truly deleted (or for every one, with @all).
 * Modified exceptions are still visible and are reported at their *original*
 * slot, so a caller that wants the rescheduled time has to consult the
 * EXCEPTIONINFO itself.
 *
 * Enumeration stops when @cb returns true or the pattern is exhausted.
 * OccurrenceCount bounds only an end-after-N pattern. The others are bounded
 * by EndDate, which is ENDDATE_MISSING for a never-ending pattern, so the
 * callback should return true once it has seen enough.
 *
 * @param      apr    Appointment recurrence pattern
 * @param      cb     Callback, returns true to stop enumeration
 * @param      all    Include deleted occurrences
 */
static void walkOccurrenceDates(const APPOINTMENT_RECUR_PAT &apr,
    const std::function<bool(uint32_t)> &cb, bool all = false)
{
	auto &rp = apr.recur_pat;
	auto bycount = rp.endtype == IDC_RCEV_PAT_ERB_AFTERNOCCUR;
	uint32_t count = bycount ? rp.occurrencecount : UINT32_MAX;
	uint32_t last = bycount ? UINT32_MAX :
	                rp.endtype == IDC_RCEV_PAT_ERB_END ? rp.enddate : ENDDATE_MISSING;
	auto visit = [&](uint32_t date) -> bool {
		if (date > last)
			return true;
		if (!all && isTrulyDeleted(apr, date))
			return false;
		return cb(date);
	};

	switch (rp.patterntype) {
	case rptMinute:
		/* Daily: period is in minutes (day count * 1440) */
		for (uint32_t i = 0; i < count; ++i)
			if (visit(rp.startdate + i * rp.period))
				return;
		break;
	case rptWeek: {
		auto start_unix = rop_util_rtime_to_unix(rp.startdate);
		struct tm tm;
		if ((rp.pts.weekrecur & 0x7f) == 0 || gmtime_r(&start_unix, &tm) == nullptr)
			break;
		int start_wday = tm.tm_wday;
		int days_back = (start_wday - static_cast<int>(rp.firstdow) + 7) % 7;
		uint32_t week_start = rp.startdate - days_back * 1440;
		uint32_t raw = 0;
		for (uint32_t week = week_start; raw < count; week += rp.period * 7 * 1440) {
			for (int d = 0; d < 7 && raw < count; ++d) {
				int wday = (rp.firstdow + d) % 7;
				uint32_t date = week + d * 1440;
				if (date < rp.startdate)
					continue;
				if (!(rp.pts.weekrecur & (1 << wday)))
					continue;
				++raw;
				if (visit(date))
					return;
			}
		}
		break;
	}
	case rptMonth:
	case rptMonthEnd:
	case rptMonthNth:
	case rptHjMonth:
	case rptHjMonthEnd:
	case rptHjMonthNth: {
		/* Hijri patterns are expanded as Gregorian, as freebusy does */
		bool nth = rp.patterntype == rptMonthNth ||
		           rp.patterntype == rptHjMonthNth;
		const auto &mn = rp.pts.monthnth;
		auto start_unix = rop_util_rtime_to_unix(rp.startdate);
		struct tm tm;
		if (rp.period == 0 || rp.period > 99 * 12 ||
		    gmtime_r(&start_unix, &tm) == nullptr ||
		    (nth && (mn.recurnum < 1 || mn.recurnum > 5 ||
		    (mn.weekrecur & 0x7f) == 0)))
			break;
		int year = tm.tm_year + 1900, month = tm.tm_mon + 1;
		if (rp.period % 12 == 0) {
			/* yearly: the month is in FirstDateTime (MS-OXOCAL) */
			ical_time it;
			ical_get_itime_from_yearday(1601,
				rp.firstdatetime / 1440 + 1, &it);
			if (it.month >= 1 && it.month <= 12)
				month = it.month;
		}
		for (uint32_t raw = 0; raw < count; month += rp.period) {
			while (month > 12) {
				month -= 12;
				++year;
			}
			struct tm occ = {};
			occ.tm_year = year - 1900;
			occ.tm_mon  = month - 1;
			if (nth)
				occ.tm_mday = nth_matching_mday(year, month,
				              mn.recurnum, mn.weekrecur);
			else
				occ.tm_mday = std::min<int>(rp.pts.dayofmonth,
				              ical_get_monthdays(year, month));
			auto date = rop_util_unix_to_rtime(timegm(&occ));
			if (date < rp.startdate)
				continue;
			++raw;
			if (visit(date))
				return;
		}
		break;
	}
	}
}

/**
 * @brief      Compute the Nth occurrence date
 *
 * Deleted occurrences are skipped unless @all. Modified exceptions are
 * always counted.
 *
 * @param      apr    Appointment recurrence pattern
 * @param      index  1-based occurrence index
 * @param      all    Count deleted occurrences too, like EWS InstanceIndex
 *
 * @return     Occurrence date in rtime format (minutes since 1601-01-01)
 */
uint32_t nthOccurrenceDate(const APPOINTMENT_RECUR_PAT &apr, uint32_t index,
    bool all)
{
	if (index < 1)
		throw InputError(E3307);

	uint32_t count = 0, found = 0;
	walkOccurrenceDates(apr, [&](uint32_t date) {
		if (++count < index)
			return false;
		found = date;
		return true;
	}, all);
	if (found == 0)
		throw InputError(E3334);
	return found;
}

/**
 * @brief      Last non-deleted occurrence date of a bounded series
 *
 * @return     Occurrence date in rtime format, or 0 if there is none
 */
uint32_t lastOccurrenceDate(const APPOINTMENT_RECUR_PAT &apr)
{
	uint32_t last = 0;
	walkOccurrenceDates(apr, [&](uint32_t date) {
		last = std::max(last, date);
		return false;
	});
	return last;
}

/**
 * @brief      Collect occurrence basedates overlapping a time window
 *
 * Mirrors the expansion GetUserAvailability performs, so that a CalendarView
 * and a Detailed free/busy query over the same window agree on which
 * occurrences exist.
 *
 * A modified exception is enumerated at its original slot but tested with its
 * rescheduled start/end, so occurrences moved into or out of the window are
 * handled correctly. Because an exception may be moved to an arbitrary time,
 * enumeration only stops once the slots are past both the window and the last
 * exception's original slot.
 *
 * @param      apr        Appointment recurrence pattern
 * @param      tz         Recurrence time zone (may be nullptr)
 * @param      tz_offset  Offset between the blob's local-as-UTC rtimes and UTC,
 *                        used without tz
 * @param      start      Window start (UTC)
 * @param      end        Window end (UTC)
 *
 * @return     Basedates in rtime format, chronologically ordered
 */
static std::vector<uint32_t>
occurrenceDatesInRange(const APPOINTMENT_RECUR_PAT &apr, const TZDEF *tz,
    std::chrono::seconds tz_offset, time_t start, time_t end)
{
	std::vector<uint32_t> out;
	auto toUtc = [&](uint32_t rtime) -> time_t {
		int64_t off;
		if (tz != nullptr && tz_to_offset(*tz, rop_util_rtime_to_unix(rtime), off))
			return rop_util_rtime_to_unix(rtime) + off * 60;
		return rop_util_rtime_to_unix(rtime) + tz_offset.count();
	};
	/*
	 * Guard against a corrupted occurrencecount turning the walk into a
	 * near-infinite loop. A window wide enough to hold more occurrences
	 * than this is not something a client can usefully consume anyway.
	 */
	static constexpr size_t walk_cap = 65536;
	size_t visited = 0;
	uint32_t last_exc = 0;
	for (const auto &ei : apr.pexceptioninfo)
		last_exc = std::max(last_exc, ei.originalstartdate / 1440 *
		           1440 + apr.starttimeoffset);

	walkOccurrenceDates(apr, [&](uint32_t date) {
		if (++visited > walk_cap)
			return true;
		if (date + apr.starttimeoffset > last_exc &&
		    toUtc(date + apr.starttimeoffset) > end)
			return true;
		auto exc = find_exc(apr, date);
		time_t occ_start, occ_end;
		if (exc != nullptr) {
			occ_start = toUtc(exc->startdatetime);
			occ_end   = toUtc(exc->enddatetime);
		} else {
			occ_start = toUtc(date + apr.starttimeoffset);
			occ_end   = toUtc(date + apr.endtimeoffset);
		}
		/* Overlap, matching the semantics of tCalendarView::datefilter */
		if (occ_end >= start && occ_start <= end)
			out.push_back(date);
		return false;
	});
	return out;
}

namespace {

/**
 * @brief      Map MAPI rights to delegate permission level
 */
Enum::DelegateFolderPermissionLevelType rights_to_deleg_level(uint32_t rights)
{
	rights &= ~(frightsContact | frightsFreeBusySimple | frightsFreeBusyDetailed);
	if (rights == 0)
		return Enum::None;
	if (rights == rightsEditor)
		return Enum::Editor;
	if (rights == rightsReviewer)
		return Enum::Reviewer;
	if (rights == rightsAuthor)
		return Enum::Author;
	return Enum::Custom;
}

/**
 * @brief      Map delegate permission level to MAPI rights
 *
 * DelegateFolderPermissionLevelType indices:
 * 0=None, 1=Editor, 2=Reviewer, 3=Author, 4=Custom
 */
uint32_t deleg_level_to_rights(Enum::DelegateFolderPermissionLevelType level)
{
	switch (level.index()) {
	case 0: return 0;
	case 1: return rightsEditor;
	case 2: return rightsReviewer;
	case 3: return rightsAuthor;
	default: return 0;
	}
}

static inline time_t unix_day(time_t t)
{
	return t >= 0 ? t / 86400 : (t - 86399) / 86400;
}

/**
 * @brief      Convert a client-supplied recurrence to the item's time zone
 *
 * The pattern and range are given relative to the request's time zone
 * (or the zone of the range start date, if it has one). A start date
 * without a zone on the local day of the item start is taken as local,
 * since responses give the range in the item's time zone.
 *
 * @param      rec    Recurrence as received
 * @param      frame  Time zone of the request
 * @param      start  Item start (UTC)
 * @param      tz     Item time zone
 */
void shift_recurrence(tRecurrenceType &rec, const sRecurrenceFrame &frame,
    const TZDEF &tz, time_t start)
{
	int64_t b;
	if (!tz_to_offset(tz, start, b))
		return;
	auto day = unix_day(start - b * 60);
	auto first = clock::to_time_t(std::visit([](const auto &r) STATIC_IN_CXX23 {
	             return r.StartDate; }, rec.RecurrenceRange));
	if (!rec.startDateZone() && unix_day(first) == day)
		return;
	auto east = rec.startDateZone().value_or(frame.offset(start));
	int days = day - unix_day(start + east * 60);
	/*
	 * The series start is its first instance, MS-OXOCAL v22.1 §2.2.1.5.
	 * A weekly rule that names the local weekday of the start, and would
	 * lose it when moved, was given in the item's time zone already.
	 */
	auto wday = [](time_t d) { return static_cast<int>((d % 7 + 11) % 7); };
	if (rec.weeklyOn(wday(day)) && !rec.weeklyOn(wday(day - days)))
		return;
	rec.shift(days);
}

bool has_element(const tinyxml2::XMLElement *xml, const char *name)
{
	for (; xml != nullptr; xml = xml->NextSiblingElement())
		if (strcmp(xml->Name(), name) == 0 ||
		    has_element(xml->FirstChildElement(), name))
			return true;
	return false;
}

/**
 * @brief      Determine the time zone of a request's recurrence data
 *
 * Requests with MeetingTimeZone (Exchange 2007 style) carry the zone with
 * the item and are not converted. Without a TimeZoneContext header,
 * recurrences are in UTC. A TimeZoneContext that cannot be resolved
 * (including one lacking the mandatory TimeZoneDefinition) leaves the
 * recurrence unconverted rather than guessing UTC.
 *
 * @return     Frame, or nothing for no conversion
 */
std::optional<sRecurrenceFrame> make_recurrence_frame(const SOAP::Envelope &req)
{
	if (has_element(req.body, "MeetingTimeZone"))
		return std::nullopt;
	sRecurrenceFrame frame;
	auto def = req.header != nullptr ? req.header->FirstChildElement("TimeZoneContext") : nullptr;
	if (def == nullptr)
		return frame;
	def = def->FirstChildElement("TimeZoneDefinition");
	if (def == nullptr)
		return std::nullopt;
	auto tzdef = lookup_tz_get_tzdef(def->Attribute("Id"));
	if (tzdef) {
		frame.tz = std::move(*tzdef);
		return frame;
	}
	auto period = def->FirstChildElement("Periods");
	period = period != nullptr ? period->FirstChildElement("Period") : nullptr;
	auto bias = period != nullptr ? period->Attribute("Bias") : nullptr;
	if (bias == nullptr)
		return std::nullopt;
	bool negative = *bias == '-';
	if (*bias == '-' || *bias == '+')
		++bias;
	char *end = nullptr;
	auto sec = HX_strtoull8601p_sec(bias, &end);
	if (end == nullptr || end == bias)
		return std::nullopt;
	frame.bias = negative ? sec / 60 : -static_cast<int32_t>(sec / 60);
	return frame;
}

} // Anonymous namespace

///////////////////////////////////////////////////////////////////////////////////////////////////

EWSContext::EWSContext(detail::ContextKey id, const HTTP_AUTH_INFO &ai,
    const char *data, uint64_t length, EWSPlugin &p) :
	m_ctx_id(id), m_orig(*get_request(id)), m_auth_info(ai),
	m_request(data, length), m_response(p.server_version()), m_plugin(p),
	m_created(tp_now()), m_recurrence_frame(make_recurrence_frame(m_request))
{
	tinyxml2::XMLElement *imp = nullptr;
	if (m_request.header && (imp = m_request.header->FirstChildElement("ExchangeImpersonation")) &&
	   (imp = imp->FirstChildElement("ConnectingSID")) && (imp = imp->FirstChildElement()))
		impersonate(imp->Name(), imp->GetText());
}

/**
 * @brief      Get the language for text the server writes
 *
 * Like the mailbox session of Exchange, this is the MailboxCulture header
 * of the request if there is one, else the language of the user.
 *
 * @return     Locale string, possibly empty
 */
const char *EWSContext::culture() const
{
	auto hdr = m_request.header != nullptr ?
	           m_request.header->FirstChildElement("MailboxCulture") : nullptr;
	auto text = hdr != nullptr ? hdr->GetText() : nullptr;
	return !znoval(text) ? text : znul(m_auth_info.lang);
}

EWSContext::~EWSContext()
{
	if (m_notify)
		for (const auto &sub : m_notify->nct_subs)
			m_plugin.detachSubscription(sub, m_ctx_id);
}

/**
 * @brief      Copy string to context allocated buffer
 *
 * @param      src   Source string
 *
 * @return     Pointer to copied C-string
 */
char *EWSContext::cpystr(const std::string_view src)
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
	if (!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNumber))
		throw DispatchError(E3153);
	const auto &baseFolder =
		std::visit([](const auto &f) STATIC_IN_CXX23 -> const tBaseFolderType & {
			return static_cast<const tBaseFolderType &>(f);
		}, folder);
	for (const tExtendedProperty &prop : baseFolder.ExtendedProperty)
		if (prop.ExtendedFieldURI.tag())
			shape.write(prop.propval);
		else
			shape.write(prop.ExtendedFieldURI.name(), prop.propval);
	shape.write(TAGGED_PROPVAL{PidTagParentFolderId, deconst(&parent.folderId)});
	const char* fclass = "IPF.Note";
	mapi_folder_type type = FOLDER_GENERIC;
	if (baseFolder.FolderClass)
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
	if (baseFolder.DisplayName)
		shape.write(TAGGED_PROPVAL{PR_DISPLAY_NAME, deconst(baseFolder.DisplayName->c_str())});
	uint64_t now = rop_util_current_nttime();
	shape.write(TAGGED_PROPVAL{PR_CREATION_TIME, &now});
	shape.write({PR_LAST_MODIFICATION_TIME, &now});
	shape.write({PidTagChangeNumber, &changeNumber});

	bool isPublic = parent.location == parent.PUBLIC;
	uint32_t accountId = getAccountId(*parent.target, isPublic);
	XID xid{parent.location == parent.PRIVATE ?
		rop_util_make_user_guid(accountId) :
		rop_util_make_domain_guid(accountId), changeNumber};

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
		throw EWSError::FolderSave(E3322(err));
	if (created.folderId == 0)
		throw EWSError::FolderExists(E3323); // ??

	sShape retshape = sShape(tFolderResponseShape());
	return loadFolder(dir, created.folderId, retshape);
}

/**
 * @brief      Create new item
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder to create item in
 * @param      content   Item content to store
 * @param      withAttachments  Whether to return the attachment IDs as well
 *
 * @return     Item object containing ItemId
 */
sItem EWSContext::create(const std::string& dir, const sFolderSpec& parent,
    const MESSAGE_CONTENT &content, bool withAttachments) const
{
	ec_error_t error;
	auto messageId = content.proplist.get<const uint64_t>(PidTagMid);
	if (!messageId)
		throw DispatchError(E3112);
	if (!content.proplist.has(PidTagChangeNumber))
		throw EWSError::ItemSave(E3254);
	uint64_t outmid = 0, outcn = 0;
	if (!m_plugin.exmdb.write_message(dir.c_str(), CP_ACP, parent.folderId,
	    &content, {}, &outmid, &outcn, &error) || error != ecSuccess)
		throw EWSError::ItemSave(E3324);

	sShape retshape = sShape(tItemResponseShape());
	if (withAttachments)
		retshape.special |= sShape::Attachments;
	return loadItem(dir, parent.folderId, *messageId, retshape);
}

/**
 * @brief      Fill in the ItemIds of conflicting or adjacent meetings
 *
 * @param      folder    Folder of the item the meetings relate to
 * @param      dir       Store directory
 * @param      meetings  Meetings with their free/busy UIDs
 */
void EWSContext::conflictItemIds(const sFolderSpec &folder, const std::string &dir,
    std::vector<tConflictingMeeting> &meetings) const
{
	sFolderSpec calendar = folder;
	calendar.folderId = eid_t(1, PRIVATE_FID_CALENDAR);
	auto tag = PROP_TAG(PT_BINARY, getNamedPropId(dir, NtCleanGlobalObjectId, true));
	for (auto &m : meetings) try {
		if (m.uid.empty())
			continue;
		BINARY goid{};
		uid_to_goid(m.uid.c_str(), goid);
		TAGGED_PROPVAL pv{tag, &goid};
		MESSAGE_CONTENT content{};
		content.proplist.count = 1;
		content.proplist.ppropval = &pv;
		auto mid = findExistingByGoid(calendar, dir, content);
		if (mid)
			m.ItemId.emplace(sBase64Binary(getItemEntryId(dir, *mid)), tItemId::ID_ITEM);
	} catch (const EWSError &) {
	}
}

/**
 * @brief Find calendar item using goid and clean goid
 *
 * @param calendarFolder The calendar folder
 * @param calendarDir    Store directory
 * @param content        Item content
 *
 * @return PidTagMid value of item matching goid or clean goid
 */
std::optional<uint64_t> EWSContext::findExistingByGoid(const sFolderSpec& calendarFolder, const std::string& calendarDir,
	const MESSAGE_CONTENT& content) const
{
	std::array<RESTRICTION_PROPERTY, 2> propertyRestrictions{};
	std::array<RESTRICTION, 2> childRestrictions{};
	size_t restrictionCount = 0;

	auto addRestriction = [&](const BINARY *value, propid_t propId) {
		if (value == nullptr || value->cb == 0 || value->pb == nullptr || propId == 0 ||
		    restrictionCount >= propertyRestrictions.size())
			return;
		auto tag = PROP_TAG(PT_BINARY, propId);
		auto &propRestriction = propertyRestrictions[restrictionCount];
		propRestriction.relop = RELOP_EQ;
		propRestriction.proptag = tag;
		propRestriction.propval.proptag = tag;
		propRestriction.propval.pvalue = deconst(value);

		childRestrictions[restrictionCount].rt = RES_PROPERTY;
		childRestrictions[restrictionCount].prop = &propRestriction;
		++restrictionCount;
	};

	auto pidGlobalId      = getNamedPropId(calendarDir, NtGlobalObjectId, true);
	auto pidCleanGlobalId = getNamedPropId(calendarDir, NtCleanGlobalObjectId, true);
	const BINARY* goid = content.proplist.get<const BINARY>(PROP_TAG(PT_BINARY, pidGlobalId));
	const BINARY* cleanGoid = content.proplist.get<const BINARY>(PROP_TAG(PT_BINARY, pidCleanGlobalId));
	addRestriction(goid, pidGlobalId);
	addRestriction(cleanGoid, pidCleanGlobalId);

	if (restrictionCount == 0)
		return std::nullopt;

	RESTRICTION restriction{};
	RESTRICTION_AND_OR orGroup{};
	if (restrictionCount == 1) {
		restriction.rt = RES_PROPERTY;
		restriction.prop = &propertyRestrictions[0];
	} else {
		orGroup.count = static_cast<uint32_t>(restrictionCount);
		orGroup.pres = childRestrictions.data();
		restriction.rt = RES_OR;
		restriction.andor = &orGroup;
	}

	uint32_t tableId = 0, rowCount = 0;
	const char *calUser = effectiveUser(calendarFolder);
	if (!m_plugin.exmdb.load_content_table(calendarDir.c_str(), CP_ACP,
	    calendarFolder.folderId, calUser, TABLE_FLAG_NONOTIFICATIONS,
	    &restriction, nullptr, &tableId, &rowCount))
		throw EWSError::ItemPropertyRequestFailed(E3245);
	auto unloadTable = HX::make_scope_exit([&, tableId]{
		m_plugin.exmdb.unload_table(calendarDir.c_str(), tableId);
	});
	if (rowCount == 0)
		return std::nullopt;

	static constexpr proptag_t midTagValue = PidTagMid;
	TARRAY_SET rows{};
	if (!m_plugin.exmdb.query_table(calendarDir.c_str(), calUser, CP_ACP,
	    tableId, {&midTagValue, 1}, 0, 1, &rows))
		throw EWSError::ItemCorrupt(E3284);
	if (rows.count == 0 || rows.pparray[0] == nullptr)
		return std::nullopt;
	auto mid = rows.pparray[0]->get<const uint64_t>(PidTagMid);
	if (!mid)
		return std::nullopt;
	return std::optional<uint64_t>(*mid);
}

/**
 * @brief      Get the attachment numbers of a message instance
 *
 * They have gaps once an attachment was deleted from a cached instance.
 *
 * @return     false if the instance could not be read
 */
static bool attachment_nums(const EWSPlugin &plugin, const std::string &dir,
    uint32_t inst, std::vector<uint32_t> &nums)
{
	static constexpr proptag_t tags[] = {PR_ATTACH_NUM};
	TARRAY_SET rows{};
	if (!plugin.exmdb.query_message_instance_attachment_table(dir.c_str(),
	    inst, proptag_cspan{tags}, 0, INT32_MAX, &rows))
		return false;
	nums.clear();
	nums.reserve(rows.count);
	for (uint32_t i = 0; i < rows.count; ++i) {
		auto num = rows.pparray[i]->get<const uint32_t>(PR_ATTACH_NUM);
		if (num != nullptr)
			nums.push_back(*num);
	}
	return true;
}

/**
 * @brief Check whether a GlobalObjectId names one occurrence of a series
 *
 * The date fields are zero on a series master and carry the instance date on
 * a single occurrence.
 */
static bool goid_is_instance(const BINARY *goid_bin)
{
	if (goid_bin == nullptr || goid_bin->cb == 0)
		return false;
	GLOBALOBJECTID goid{};
	EXT_PULL ep;
	ep.init(goid_bin->pb, goid_bin->cb, EWSContext::alloc, 0);
	if (ep.g_goid(&goid) != pack_result::ok)
		return false;
	return goid.year != 0 || goid.month != 0 || goid.day != 0;
}

/**
 * @brief      Instance date of a GlobalObjectId
 *
 * @return     Local midnight of the occurrence as rtime, 0 for a series
 */
static uint32_t goid_basedate(const BINARY *goid_bin)
{
	if (goid_bin == nullptr || goid_bin->cb == 0)
		return 0;
	GLOBALOBJECTID goid{};
	EXT_PULL ep;
	ep.init(goid_bin->pb, goid_bin->cb, EWSContext::alloc, 0);
	if (ep.g_goid(&goid) != pack_result::ok || goid.year < 1601 ||
	    goid.year > 4500 || goid.month < 1 || goid.month > 12 ||
	    goid.day < 1 || goid.day > ical_get_monthdays(goid.year, goid.month))
		return 0;
	struct tm tm{};
	tm.tm_year = goid.year - 1900;
	tm.tm_mon  = goid.month - 1;
	tm.tm_mday = goid.day;
	return rop_util_unix_to_rtime(timegm(&tm));
}

/**
 * @brief      Principal that a delegate copy of a meeting message is for
 *
 * A delegate rule puts a copy of the message into the delegate's mailbox
 * and names the principal in PR_RCVD_REPRESENTING_*.
 *
 * @param      props  Properties of the message
 * @param      owner  Owner of the mailbox holding the message
 *
 * @return     The principal's username, or nothing if the message is no
 *             delegate copy for someone other than @owner
 */
std::optional<std::string> EWSContext::delegatePrincipal(const TPROPVAL_ARRAY &props,
    const std::string &owner) const try
{
	auto dlg = props.get<const uint8_t>(PR_DELEGATED_BY_RULE);
	if (dlg == nullptr || *dlg == 0)
		return std::nullopt;
	auto type  = props.get<const char>(PR_RCVD_REPRESENTING_ADDRTYPE);
	auto email = props.get<const char>(PR_RCVD_REPRESENTING_EMAIL_ADDRESS);
	if (email == nullptr || *email == '\0')
		return std::nullopt;
	std::string who = type != nullptr && strcasecmp(type, "EX") == 0 ?
	                  essdn_to_username(email) : email;
	if (strcasecmp(who.c_str(), owner.c_str()) == 0 ||
	    get_maildir(who) == get_maildir(owner))
		return std::nullopt;
	return who;
} catch (const DispatchError &) {
	/* Principal unknown here, so the copy is answered as before */
	return std::nullopt;
}

/**
 * @brief      Check that the caller may answer for @principal in its calendar
 *
 * @throw      EWSError::AccessDenied
 */
void EWSContext::checkPrincipalCalendar(const std::string &principal) const
{
	sFolderSpec cal;
	cal.location = sFolderSpec::PRIVATE;
	cal.target   = principal;
	cal.folderId = eid_t(1, PRIVATE_FID_CALENDAR);
	auto rights = permissions(getDir(cal), cal.folderId);
	if (!(rights & frightsOwner) &&
	    (rights & (frightsCreate | frightsEditAny)) != (frightsCreate | frightsEditAny))
		throw EWSError::AccessDenied(E3590);
}

/**
 * @brief      Translate the named properties of a message to another store
 *
 * Properties whose name is unknown in @src are dropped.
 *
 * @param      src  Store the IDs in @mc belong to
 * @param      dst  Store to translate them to
 * @param      mc   Message, with recipients and attachments
 */
void EWSContext::remapNamedProps(const std::string &src, const std::string &dst,
    MESSAGE_CONTENT &mc) const
{
	if (src == dst)
		return;
	std::vector<TPROPVAL_ARRAY *> lists;
	auto walk = [&](auto &&self, MESSAGE_CONTENT &m) -> void {
		lists.push_back(&m.proplist);
		if (m.children.prcpts != nullptr)
			for (auto &row : *m.children.prcpts)
				lists.push_back(&row);
		if (m.children.pattachments != nullptr)
			for (auto &at : *m.children.pattachments) {
				lists.push_back(&at.proplist);
				if (at.pembedded != nullptr)
					self(self, *at.pembedded);
			}
	};
	walk(walk, mc);
	PROPID_ARRAY ids;
	for (auto pl : lists)
		for (unsigned int i = 0; i < pl->count; ++i)
			if (is_nameprop_id(PROP_ID(pl->ppropval[i].proptag)))
				ids.push_back(PROP_ID(pl->ppropval[i].proptag));
	std::sort(ids.begin(), ids.end());
	ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
	if (ids.empty())
		return;
	PROPNAME_ARRAY names{};
	if (!m_plugin.exmdb.get_named_propnames(src.c_str(), ids, &names) ||
	    names.count != ids.size())
		throw EWSError::ItemSave(E3591);
	auto nids = getNamedPropIds(dst, names, true);
	if (nids.size() != ids.size())
		throw EWSError::ItemSave(E3591);
	for (auto pl : lists) {
		std::vector<proptag_t> drop;
		for (unsigned int i = 0; i < pl->count; ++i) {
			auto &tag = pl->ppropval[i].proptag;
			if (!is_nameprop_id(PROP_ID(tag)))
				continue;
			auto k = std::lower_bound(ids.begin(), ids.end(), PROP_ID(tag)) - ids.begin();
			if (nids[k] == 0)
				drop.push_back(tag);
			else
				tag = PROP_TAG(PROP_TYPE(tag), nids[k]);
		}
		for (auto t : drop)
			pl->erase(t);
	}
}

/**
 * @brief      Sequence number of one occurrence in the series
 *
 * The higher one of the series and of the exception for @p basedate,
 * 0 if the series cannot be read.
 *
 * @param      dir       Store
 * @param      mid       Series
 * @param      basedate  Occurrence date
 * @param      seqTag    Tag of PidLidAppointmentSequence in @p dir
 */
uint32_t EWSContext::occurrenceSequence(const std::string &dir, uint64_t mid,
    uint32_t basedate, proptag_t seqTag) const
{
	MESSAGE_CONTENT *ct = nullptr;
	if (!m_plugin.exmdb.read_message(dir.c_str(), nullptr, CP_ACP, mid, &ct) ||
	    ct == nullptr)
		return 0;
	auto mseq = ct->proplist.get<const uint32_t>(seqTag);
	uint32_t seq = mseq != nullptr ? *mseq : 0;
	if (ct->children.pattachments == nullptr)
		return seq;
	auto rtag = PROP_TAG(PT_SYSTIME, getNamedPropId(dir, NtExceptionReplaceTime, true));
	auto series = loadSeriesTimes(dir, mid);
	for (const auto &at : *ct->children.pattachments) {
		if (at.pembedded == nullptr)
			continue;
		auto t = at.pembedded->proplist.get<const uint64_t>(rtag);
		if (t == nullptr || !series.replaces(basedate, *t))
			continue;
		auto eseq = at.pembedded->proplist.get<const uint32_t>(seqTag);
		if (eseq != nullptr && *eseq > seq)
			seq = *eseq;
		break;
	}
	return seq;
}

/**
 * @brief      Answer a request for one occurrence in the series
 *
 * The series is the Calendar object whose PidLidGlobalObjectId is the
 * PidLidCleanGlobalObjectId of the request, MS-OXOCAL v22.1 §3.1.5.1.
 * Its occurrence becomes an exception with the times, subject, location
 * and response of the request, or its exception is updated.
 *
 * @param      cal       Calendar folder
 * @param      calDir    Store of the calendar
 * @param      req       Request properties, named IDs of @p calDir
 * @param      basedate  Occurrence date
 * @param      response  Response type
 *
 * @return     Message ID of the series, none if there is no series
 */
std::optional<uint64_t> EWSContext::acceptOccurrence(const sFolderSpec &cal,
    const std::string &calDir, const TPROPVAL_ARRAY &req, uint32_t basedate,
    uint32_t response) const
{
	auto cgoid = req.get<BINARY>(PROP_TAG(PT_BINARY,
	             getNamedPropId(calDir, NtCleanGlobalObjectId, true)));
	if (cgoid == nullptr || cgoid->cb == 0)
		return std::nullopt;
	TAGGED_PROPVAL key = {PROP_TAG(PT_BINARY,
		getNamedPropId(calDir, NtGlobalObjectId, true)), deconst(cgoid)};
	MESSAGE_CONTENT match{};
	match.proplist = {1, &key};
	auto series = findExistingByGoid(cal, calDir, match);
	if (!series)
		return std::nullopt;
	if (!(permissions(calDir, cal.folderId) & (frightsOwner | frightsEditAny)))
		throw EWSError::AccessDenied(E3601);

	auto tag = [&](const PROPERTY_NAME &name, proptype_t type) {
		return PROP_TAG(type, getNamedPropId(calDir, name, true));
	};
	/* An out-of-date request leaves the occurrence alone, §3.1.5.2 */
	auto seqTag = tag(NtAppointmentSequence, PT_LONG);
	auto rseq = req.get<const uint32_t>(seqTag);
	if (rseq != nullptr && occurrenceSequence(calDir, *series,
	    basedate, seqTag) > *rseq)
		return series;
	std::vector<TAGGED_PROPVAL> vals;
	auto copy = [&](proptag_t from, proptag_t to) {
		auto v = req.getval(from);
		if (v != nullptr)
			vals.push_back({to, deconst(v)});
	};
	auto start = tag(NtAppointmentStartWhole, PT_SYSTIME);
	auto end   = tag(NtAppointmentEndWhole, PT_SYSTIME);
	copy(req.has(start) ? start : PR_START_DATE, PR_START_DATE);
	copy(req.has(end) ? end : PR_END_DATE, PR_END_DATE);
	copy(PR_SUBJECT, PR_SUBJECT);
	auto loc = tag(NtLocation, PT_UNICODE);
	copy(loc, loc);
	auto reply = tag(NtAppointmentReplyName, PT_UNICODE);
	copy(reply, reply);
	uint32_t busy = response == respAccepted ? olBusy :
	                response == respTentative ? olTentative : olFree;
	vals.push_back({tag(NtBusyStatus, PT_LONG), construct<uint32_t>(busy)});
	vals.push_back({tag(NtResponseStatus, PT_LONG), construct<uint32_t>(response)});
	vals.push_back({tag(NtAppointmentReplyTime, PT_SYSTIME),
		construct<uint64_t>(rop_util_current_nttime())});
	vals.push_back({tag(NtAppointmentStateFlags, PT_LONG),
		construct<uint32_t>(asfMeeting | asfReceived)});
	const TPROPVAL_ARRAY occ{static_cast<uint16_t>(vals.size()), vals.data()};
	updateOccurrence(calDir, cal.folderId, *series, basedate, occ, {});
	return series;
}

/**
 * @brief Create a calendar item after accepting a meeting request
 *
 * A request for one occurrence updates that occurrence in the series of
 * the attendee, see MS-OXOCAL v22.1 §3.1.4.8.1 and §3.1.5.1.
 *
 * @param refId          Item id
 * @param response       Response type
 * @param owner          Calendar to use if not that of the request's
 *                       mailbox, e.g. the principal's for a delegate copy
 * @param basedate       Set to the occurrence date for a request for one
 *                       occurrence of a series, else to 0
 *
 * @return Message ID of the calendar item or of the series
 */
std::optional<uint64_t> EWSContext::createCalendarItemFromMeetingRequest(const tItemId &refId,
    uint32_t response, const std::string *owner, uint32_t *basedate) const
{
	if (basedate != nullptr)
		*basedate = 0;
	// Duplicate the original request and persist it as a calendar appointment.
	assertIdType(refId.type, tItemId::ID_ITEM);
	sMessageEntryId requestId(refId.Id.data(), refId.Id.size());
	sFolderSpec requestFolder = resolveFolder(requestId);
	std::string dir = getDir(requestFolder);
	validate(dir, requestId);
	const char *username = effectiveUser(requestFolder);

	MESSAGE_CONTENT *content = nullptr;
	if (!m_plugin.exmdb.read_message(dir.c_str(), username, CP_ACP, requestId.messageId(), &content) ||
	    content == nullptr)
		throw EWSError::ItemNotFound(E3143);

	auto pidGoid = getNamedPropId(dir, NtGlobalObjectId);
	auto instDate = goid_basedate(content->proplist.get<const BINARY>(PROP_TAG(PT_BINARY, pidGoid)));

	message_content_ptr calendarItem(content->dup());
	if (!calendarItem)
		throw EWSError::ItemSave(E3325);

	auto &props = calendarItem->proplist;
	/*
	 * Strip message IDs (so write_message creates/updates rather than
	 * colliding) and inbox-specific envelope properties that have no
	 * place on a calendar item. Keep in sync with mr_insert_to_cal().
	 */
	static constexpr proptag_t rmProps[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST,
		PR_RECEIVED_BY_ENTRYID, PR_RECEIVED_BY_NAME,
		PR_RECEIVED_BY_ADDRTYPE, PR_RECEIVED_BY_EMAIL_ADDRESS,
		PR_RECEIVED_BY_SEARCH_KEY, PR_RCVD_REPRESENTING_ENTRYID,
		PR_RCVD_REPRESENTING_NAME, PR_RCVD_REPRESENTING_ADDRTYPE,
		PR_RCVD_REPRESENTING_EMAIL_ADDRESS,
		PR_RCVD_REPRESENTING_SEARCH_KEY, PR_MESSAGE_TO_ME,
		PR_TRANSPORT_MESSAGE_HEADERS, PR_CONTENT_FILTER_SCL,
	};
	for (auto tag : rmProps)
		props.erase(tag);

	requestFolder.folderId = eid_t(1, PRIVATE_FID_CALENDAR);
	requestFolder.location = sFolderSpec::PRIVATE;
	if (owner != nullptr)
		requestFolder.target = *owner;
	else if (!requestFolder.target)
		requestFolder.target = m_auth_info.username;
	std::string calendarDir = getDir(requestFolder);

	auto calRights = permissions(calendarDir, requestFolder.folderId);
	if (!(calRights & (frightsOwner | frightsCreate)))
		throw EWSError::AccessDenied(E3130);
	remapNamedProps(dir, calendarDir, *calendarItem);

	if (props.set(PR_MESSAGE_CLASS, "IPM.Appointment") != ecSuccess)
		throw EWSError::ItemSave(E3326);

	/*
	 * Copy PidLidTimeZoneDescription to CalendarTimeZone so EWS can expose
	 * StartTimeZone/EndTimeZone on the calendar item. oxcical sets the
	 * former; EWS reads the latter.
	 */
	auto pidTzDesc = getNamedPropId(calendarDir, NtTimeZoneDescription);
	auto pidCalTz  = getNamedPropId(calendarDir, NtCalendarTimeZone, true);
	if (pidTzDesc != 0 && pidCalTz != 0) {
		auto tz = props.get<const char>(PROP_TAG(PT_UNICODE, pidTzDesc));
		if (tz != nullptr)
			props.set(PROP_TAG(PT_UNICODE, pidCalTz), tz);
	}

	/* Set response/state/busy properties on the calendar item itself. */
	auto pidResp  = getNamedPropId(calendarDir, NtResponseStatus, true);
	auto pidState = getNamedPropId(calendarDir, NtAppointmentStateFlags, true);
	auto pidBusy  = getNamedPropId(calendarDir, NtBusyStatus, true);
	uint32_t stateFlags = asfMeeting | asfReceived;
	uint32_t busyValue  = response == respAccepted ? olBusy :
	                      response == respTentative ? olTentative : olFree;
	if (props.set(PROP_TAG(PT_LONG, pidResp), construct<uint32_t>(response)) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, pidState), construct<uint32_t>(stateFlags)) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, pidBusy), construct<uint32_t>(busyValue)) != ecSuccess)
		throw EWSError::ItemSave(E3327);

	/*
	 * MS-OXOCAL v22.1 §2.2.1.32/33: PidLidCommonStart and PidLidCommonEnd
	 * equal the whole start and end. Outlook deletes both from the request
	 * when it clears its flag, and EWS reads Start and End from them.
	 */
	const std::pair<const PROPERTY_NAME &, const PROPERTY_NAME &> times[] = {
		{NtAppointmentStartWhole, NtCommonStart},
		{NtAppointmentEndWhole, NtCommonEnd},
	};
	for (const auto &[whole, common] : times) {
		auto src = getNamedPropId(calendarDir, whole);
		auto v = src != 0 ? props.get<const uint64_t>(PROP_TAG(PT_SYSTIME, src)) : nullptr;
		if (v == nullptr)
			continue;
		auto dst = PROP_TAG(PT_SYSTIME, getNamedPropId(calendarDir, common, true));
		if (props.set(dst, construct<uint64_t>(*v)) != ecSuccess)
			throw EWSError::ItemSave(E3327);
	}

	/* eM Client drops calendar items without IsAllDayEvent */
	auto pidSubType = getNamedPropId(calendarDir, NtAppointmentSubType, true);
	if (!props.has(PROP_TAG(PT_BOOLEAN, pidSubType)) &&
	    props.set(PROP_TAG(PT_BOOLEAN, pidSubType), construct<uint8_t>(0)) != ecSuccess)
		throw EWSError::ItemSave(E3475);

	/* OXOCAL v22.1 §2.2.4.5: a delegate answering names itself */
	if (strcasecmp(requestFolder.target->c_str(), m_auth_info.username) != 0) {
		std::string dlgName;
		auto pidReplyName = getNamedPropId(calendarDir, NtAppointmentReplyName, true);
		if (mysql_adaptor_get_user_displayname(m_auth_info.username, dlgName) &&
		    props.set(PROP_TAG(PT_UNICODE, pidReplyName), dlgName.c_str()) != ecSuccess)
			throw EWSError::ItemSave(E3327);
	}

	if (instDate != 0) {
		auto series = acceptOccurrence(requestFolder, calendarDir,
		              props, instDate, response);
		if (series) {
			if (basedate != nullptr)
				*basedate = instDate;
			return series;
		}
		/* Invited to this occurrence only, see §3.1.5.1 */
	}

	std::optional<uint64_t> existingMid = findExistingByGoid(requestFolder, calendarDir, *calendarItem);
	if (existingMid && !(calRights & (frightsOwner | frightsEditAny)))
		throw EWSError::AccessDenied(E3601);
	if (existingMid && props.set(PidTagMid, construct<uint64_t>(*existingMid)) != ecSuccess)
		throw EWSError::ItemSave(E3328);

	ec_error_t err = ecSuccess;
	uint64_t newMid = 0, newCn = 0;
	if (!m_plugin.exmdb.write_message(calendarDir.c_str(), CP_ACP, requestFolder.folderId,
	        calendarItem.get(), {}, &newMid, &newCn, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3329);
	return existingMid ? *existingMid : newMid;
}

/**
 * @brief Find the Meeting object of a meeting request
 *
 * @param refId  Meeting request
 * @param owner  Calendar to search if not that of the request's mailbox,
 *               e.g. the principal's for a delegate copy
 *
 * @return Message ID in that calendar, none for a single occurrence or
 *         when there is no Meeting object
 */
std::optional<uint64_t> EWSContext::findMeetingObject(const tItemId &refId,
    const std::string *owner) const
{
	assertIdType(refId.type, tItemId::ID_ITEM);
	sMessageEntryId requestId(refId.Id.data(), refId.Id.size());
	sFolderSpec folder = resolveFolder(requestId);
	std::string dir = getDir(folder);
	auto goidTag  = PROP_TAG(PT_BINARY, getNamedPropId(dir, NtGlobalObjectId, true));
	auto cgoidTag = PROP_TAG(PT_BINARY, getNamedPropId(dir, NtCleanGlobalObjectId, true));
	const proptag_t tags[] = {goidTag, cgoidTag};
	TPROPVAL_ARRAY goids = getItemProps(dir, requestId.messageId(), tags);
	/* An occurrence matches the series master through the clean goid */
	if (goid_is_instance(goids.get<const BINARY>(goidTag)))
		return std::nullopt;
	folder.folderId = eid_t(1, PRIVATE_FID_CALENDAR);
	if (owner == nullptr) {
		MESSAGE_CONTENT content{};
		content.proplist = goids;
		return findExistingByGoid(folder, dir, content);
	}
	/* The named property IDs differ between the two stores */
	folder.location = sFolderSpec::PRIVATE;
	folder.target   = *owner;
	std::string calDir = getDir(folder);
	auto calTag = [&](const PROPERTY_NAME &name) {
		return PROP_TAG(PT_BINARY, getNamedPropId(calDir, name, true));
	};
	TAGGED_PROPVAL vals[2];
	uint16_t count = 0;
	if (auto v = goids.get<BINARY>(goidTag); v != nullptr)
		vals[count++] = {calTag(NtGlobalObjectId), v};
	if (auto v = goids.get<BINARY>(cgoidTag); v != nullptr)
		vals[count++] = {calTag(NtCleanGlobalObjectId), v};
	MESSAGE_CONTENT content{};
	content.proplist = {count, vals};
	return findExistingByGoid(folder, calDir, content);
}

/**
 * @brief      Schedule notification stream for closing
 */
void EWSContext::disableEventStream()
{
	if (m_notify)
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
{
	return folder.location == sFolderSpec::PUBLIC ? m_auth_info.username : nullptr;
}

/**
 * @brief      Initialize notification context
 *
 * @param      timeout   Stream timeout (minutes)
 */
void EWSContext::enableEventStream(int timeout)
{
	m_state = S_STREAM_NOTIFY;
	auto expire = tp_now() + std::chrono::minutes(timeout);
	if (m_notify)
		mlog(LV_DEBUG, "EWSContext::m_notify already populated, programming error");
	m_notify = std::make_unique<NotificationContext>(expire);
}

/**
 * @brief      Export message content to string
 *
 * @param      dir       Parent store
 * @param      content   Content to export
 * @param      log_id    Log ID
 *
 * @return     Serialized content
 */
std::string EWSContext::exportContent(const std::string& dir, const MESSAGE_CONTENT& content, const std::string& log_id) const
{
	auto mail = vmime::make_shared<vmime::message>();
	oxcmail_converter cvt;
	cvt.log_id = log_id.c_str();
	cvt.alloc = alloc;
	cvt.get_propids = [&](const PROPNAME_ARRAY *names, PROPID_ARRAY *ids) {
	                  	*ids = getNamedPropIds(dir, *names);
	                  	return TRUE;
	                  };
	cvt.get_propname = [&](propid_t id, PROPERTY_NAME **name) {
	                   	*name = getPropertyName(dir, id);
	                   	return TRUE;
	                   };
	if (cvt.mapi_to_inet(content, mail) != ecSuccess)
		throw EWSError::ItemCorrupt(E3072);
	return vmail_to_string(*mail);
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
	uint32_t accountId;
	BOOL res;
	if (isDomain)
		res = mysql_adaptor_get_domain_ids(name.c_str(), &accountId, nullptr);
	else
		res = mysql_adaptor_get_user_ids(name.c_str(), &accountId, nullptr, nullptr);
	if (!res)
		throw EWSError::CannotFindUser(E3113(isDomain ? "domain" : "user", name));
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
propid_t EWSContext::getNamedPropId(const std::string &dir,
    const PROPERTY_NAME &propName, bool create) const
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
	if (!m_plugin.exmdb.get_named_propids(dir.c_str(), create ? TRUE : false, &propNames, &namedIds))
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
	if (shape.store == dir)
		return;
	PROPNAME_ARRAY propNames = shape.namedProperties();
	if (propNames.count == 0)
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
PROPERTY_NAME *EWSContext::getPropertyName(const std::string &dir, propid_t id) const
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
	std::string username;
	auto err = gromox::cvt_essdn_to_username(essdn.c_str(),
	           m_plugin.x500_org_name.c_str(), mysql_adaptor_userid_to_name, username);
	if (err == ecSuccess)
		return username;
	if (err == ecUnknownUser)
		throw DispatchError(E3002);
	throw DispatchError(E3003);
}

/**
 * @brief      Get the user owning a store
 *
 * @param      dir   Home directory of the store
 *
 * @return     Owner of a private store, the caller otherwise
 */
std::string EWSContext::storeOwner(const std::string &dir) const
{
	if (dir == m_auth_info.maildir)
		return m_auth_info.username;
	unsigned int user_id = 0;
	std::string owner;
	if (!mysql_adaptor_get_id_from_maildir(dir.c_str(), &user_id) ||
	    mysql_adaptor_userid_to_name(user_id, owner) != ecSuccess)
		return m_auth_info.username;
	return owner;
}

/**
 * @brief      Check whether the caller acts as the owner of a store
 *
 * Store owners, which is what Full Access amounts to, send as the
 * mailbox, like emsmdb and zcore do when submitting from that store.
 *
 * @param      dir   Home directory of the store
 */
bool EWSContext::actsAsOwner(const std::string &dir) const
{
	if (dir == m_auth_info.maildir)
		return true;
	uint32_t perm = 0;
	return m_plugin.exmdb.get_mbox_perm(dir.c_str(),
	       m_auth_info.username, &perm) && (perm & frightsGromoxStoreOwner);
}

/**
 * @brief      Check whether the caller is on the Send-As list of a store
 *
 * @param      dir   Home directory of the store
 */
bool EWSContext::onSendAsList(const std::string &dir) const
{
	std::vector<std::string> list;
	if (!m_plugin.exmdb.read_delegates(dir.c_str(), 1, &list))
		return false;
	for (const auto &d : list)
		if (strcasecmp(d.c_str(), m_auth_info.username) == 0 ||
		    mysql_adaptor_check_mlist_include(d.c_str(), m_auth_info.username))
			return true;
	return false;
}

/**
 * @brief      Sender properties of meeting mail sent from a store
 *
 * The store owner organizes, the caller may be a delegate. A caller
 * acting as the owner or holding Send-As rights sends as the owner.
 * Values are allocated with alloc() and stay valid for the request.
 *
 * @param      dir   Home directory of the store
 */
std::vector<TAGGED_PROPVAL> EWSContext::meetingIdentity(const std::string &dir) const
{
	auto copyStr = [](const std::string &str) {
		return strcpy(alloc<char>(str.size() + 1), str.c_str());
	};
	auto mkAbEid = [&](const char *user) {
		std::string essdn;
		if (cvt_username_to_essdn(user, m_plugin.x500_org_name.c_str(),
		    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids, essdn) != ecSuccess)
			throw DispatchError(E3379);
		EMSAB_ENTRYID abEid{0, DT_MAILUSER, essdn.data()};
		EXT_PUSH ext_push;
		static constexpr size_t ABEIDBUFFSIZE = 1280;
		auto abEidBuff = alloc<char>(ABEIDBUFFSIZE);
		if (!ext_push.init(abEidBuff, ABEIDBUFFSIZE, EXT_FLAG_UTF16) ||
		    ext_push.p_abk_eid(abEid) != pack_result::ok)
			throw DispatchError(E3380);
		return construct<BINARY>(BINARY{ext_push.m_offset, {abEidBuff}});
	};
	auto organizer = copyStr(storeOwner(dir));
	auto username = actsAsOwner(dir) || onSendAsList(dir) ? organizer :
	                deconst(m_auth_info.username);
	std::string dispName;
	if (!mysql_adaptor_get_user_displayname(username, dispName))
		throw DispatchError(E3378);
	auto displayName = copyStr(dispName);
	auto orgName = displayName;
	auto senderEid = mkAbEid(username), orgEid = senderEid;
	if (strcasecmp(organizer, username) != 0) {
		if (!mysql_adaptor_get_user_displayname(organizer, dispName))
			throw DispatchError(E3378);
		orgName = copyStr(dispName);
		orgEid = mkAbEid(organizer);
	}
	auto addrType = deconst("SMTP");
	return {
		{PR_SENT_REPRESENTING_NAME, orgName},
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, organizer},
		{PR_SENT_REPRESENTING_ADDRTYPE, addrType},
		{PR_SENT_REPRESENTING_EMAIL_ADDRESS, organizer},
		{PR_SENT_REPRESENTING_ENTRYID, orgEid},
		{PR_SENDER_NAME, displayName},
		{PR_SENDER_SMTP_ADDRESS, username},
		{PR_SENDER_ADDRTYPE, addrType},
		{PR_SENDER_EMAIL_ADDRESS, username},
		{PR_SENDER_ENTRYID, senderEid},
	};
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
	tolower_inplace(RoutingType);
	if (RoutingType == "ex") {
		Address = essdn_to_username(Address);
		RoutingType = "smtp";
	}
	if (RoutingType == "smtp") {
		sql_meta_result mres;
		if (mysql_adaptor_meta(Address.c_str(), WANTPRIV_METAONLY, mres) != 0)
			throw EWSError::CannotFindUser(E3125);
		return std::move(mres.maildir);
	}
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
	const char *target = folder.target ? folder.target->c_str() : m_auth_info.username;
	const char *at = strchr(target, '@');
	bool isPublic = folder.location == sFolderSpec::AUTO ? at == nullptr :
	                folder.location == sFolderSpec::PUBLIC;
	if (isPublic && at)
		target = at + 1;
	if (isPublic) {
		char targetDir[256];
		if (!mysql_adaptor_get_homedir(target, targetDir, std::size(targetDir)))
			throw EWSError::CannotFindUser(E3126);
		return targetDir;
	}
	sql_meta_result mres;
	if (mysql_adaptor_meta(target, WANTPRIV_METAONLY, mres) != 0)
		throw EWSError::CannotFindUser(E3331);
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
	auto mgr = m_plugin.get_submgr(subscriptionId.tsub_rawkey, subscriptionId.timeout);
	if (mgr == nullptr)
		throw EWSError::InvalidSubscription(E3202);
	std::lock_guard evguard(mgr->lock);
	if (mgr->username != m_auth_info.username)
		throw EWSError::AccessDenied(E3203);
	if (mgr->overflow)
		/*
		 * Backlog was previously dropped in EWSPlugin::event() because
		 * the client could not keep up. Fault the subscription to make
		 * the caller (streaming notify() / pull GetEvents) report it
		 * in ErrorSubscriptionIds.
		 */
		throw EWSError::InvalidSubscription(E3454);
	std::pair<std::list<sNotificationEvent>, bool> result{{}, mgr->events.size() > 50};
	auto &evt = mgr->events;
	if (result.second) {
		auto it = evt.begin();
		std::advance(it, 50);
		result.first.splice(result.first.end(), evt, evt.begin(), it);
	} else {
		result.first.splice(result.first.end(), evt);
	}
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
	static constexpr proptag_t propids[] = {PR_ENTRYID};
	static constexpr PROPTAG_ARRAY proptags = {1, deconst(propids)};
	TPROPVAL_ARRAY props = getFolderProps(dir, folderId, proptags);
	if (props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
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
TPROPVAL_ARRAY EWSContext::getFolderProps(const std::string &dir,
    uint64_t folderId, proptag_cspan tags) const
{
	TPROPVAL_ARRAY result;
	if (!m_plugin.exmdb.get_folder_properties(dir.c_str(), CP_ACP,
	    folderId, tags, &result))
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
	static constexpr proptag_t propids[] = {PR_ENTRYID};
	static constexpr PROPTAG_ARRAY proptags = {1, deconst(propids)};
	TPROPVAL_ARRAY props = getItemProps(dir, mid, proptags);
	if (props.count != 1 || props.ppropval->proptag != PR_ENTRYID)
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
const void *EWSContext::getFolderProp(const std::string &dir, uint64_t fid,
    proptag_t tag) const
{
	PROPTAG_ARRAY proptags{1, &tag};
	TPROPVAL_ARRAY props = getFolderProps(dir, fid, proptags);
	if (props.count != 1 || props.ppropval->proptag != tag)
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
const void *EWSContext::getItemProp(const std::string &dir, uint64_t mid,
    proptag_t tag) const
{
	PROPTAG_ARRAY proptags{1, &tag};
	TPROPVAL_ARRAY props = getItemProps(dir, mid, proptags);
	if (props.count != 1 || props.ppropval->proptag != tag)
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
TPROPVAL_ARRAY EWSContext::getItemProps(const std::string &dir, uint64_t mid,
    proptag_cspan props) const
{
	TPROPVAL_ARRAY result;
	if (!m_plugin.exmdb.get_message_properties(dir.c_str(), m_auth_info.username,
	    CP_ACP, mid, props, &result))
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
	static constexpr proptag_t recordKeyTag = PR_STORE_RECORD_KEY;
	TPROPVAL_ARRAY recordKeyProp;
	if (!m_plugin.exmdb.get_store_properties(dir.c_str(), CP_ACP,
	    {&recordKeyTag, 1}, &recordKeyProp) ||
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
	auto getId = isDomain ? mysql_adaptor_get_id_from_homedir : mysql_adaptor_get_id_from_maildir;
	if (!getId(dir.c_str(), &mbinfo.accountId))
		throw EWSError::CannotFindUser(E3192(isDomain ? "domain" : "user", dir));
	return mbinfo;
}

/**
 * @brief      Setup impersonation for user
 *
 * @param      addrtype    Address type
 * @param      addr        Smtp address of the user to impersonate
 */
void EWSContext::impersonate(const char* addrtype, const char* addr)
{
	if (!addrtype || !addr || *addr == '\0')
		return;
	if (strcasecmp(addrtype, "sid") == 0)
		/*
		 * SID-based impersonation is part of MS-OXWSCDATA but not yet
		 * implemented. To add support, we need to use ldap to resolve
		 * SID (objectSid attribute) to username
		 *
		 * For now, SID impersonation returns "unsupported ConnectingSID".
		 */
		throw EWSError::ImpersonationFailed(E3276);
	if (strcasecmp(addrtype, "PrincipalName") != 0 &&
	    strcasecmp(addrtype, "PrimarySmtpAddress") != 0 &&
	    strcasecmp(addrtype, "SmtpAddress") != 0)
		throw EWSError::ImpersonationFailed(E3242);

	sql_meta_result mres;
	if (mysql_adaptor_meta(addr, WANTPRIV_METAONLY, mres) != 0)
		throw EWSError::CannotFindUser(E3330);
	if (!(permissions(mres.maildir, eid_t{1, PRIVATE_FID_IPMSUBTREE}) & frightsGromoxStoreOwner))
		throw EWSError::ImpersonateUserDenied(E3243);
	impersonationUser    = std::move(mres.username);
	impersonationMaildir = std::move(mres.maildir);
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
	static constexpr proptag_t tagIDs[] = {
		PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG,
		PR_ATTACH_DATA_BIN, PR_ATTACH_CONTENT_ID,
		PR_ATTACH_LONG_FILENAME, PR_ATTACH_FLAGS,
	};
	TPROPVAL_ARRAY props;
	if (!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0,
	    aInst->instanceId, proptag_cspan{tagIDs}, &props))
		throw DispatchError(E3083);
	sShape shape(props);

	auto method = props.get<const uint32_t>(PR_ATTACH_METHOD);
	if (method != nullptr && *method == ATTACH_EMBEDDED_MSG) {
		auto eInst = m_plugin.loadEmbeddedInstance(dir, aInst);
		MESSAGE_CONTENT content{};
		if (!m_plugin.exmdb.read_message_instance(dir.c_str(),
		    eInst->instanceId, &content))
			throw DispatchError(E3208);
		auto log_id = dir + ":a" + std::to_string(aid.attachment_num);
		shape.mimeContent.emplace(exportContent(dir, content, log_id));
	}
	return tAttachment::create(aid, std::move(shape));
}

/**
 * @brief      Load permission table
 *
 * @param      dir   Store to load from
 * @param      fid   Folder Id
 *
 * @return     Property table containing `PR_MEMBER_ID`, `PR_MEMBER_NAME`, `PR_MEMBER_RIGHTS` and `PR_SMTP_ADDRESS` tags
 */
TARRAY_SET EWSContext::loadPermissions(const std::string& dir, uint64_t fid, bool freebusy) const
{
	uint32_t tableId, rowCount;
	const auto& exmdb = m_plugin.exmdb;
	uint32_t flags = freebusy ? PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY : 0;
	if (!exmdb.load_permission_table(dir.c_str(), fid, flags, &tableId, &rowCount))
		throw EWSError::ItemCorrupt(E3283);
	auto unloadTable = HX::make_scope_exit([&, tableId]{exmdb.unload_table(dir.c_str(), tableId);});
	static constexpr proptag_t tags[] = {PR_MEMBER_ID, PR_MEMBER_NAME, PR_MEMBER_RIGHTS, PR_SMTP_ADDRESS};
	TARRAY_SET propTable;
	if (!exmdb.query_table(dir.c_str(), "", CP_UTF8, tableId,
	    proptag_cspan{tags}, 0, rowCount, &propTable))
		throw EWSError::ItemCorrupt(E3332);
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
	if (special & sShape::Rights)
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
	if (special & sShape::Permissions)
		folder.PermissionSet.emplace(loadPermissions(dir, fId, true));
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
	if (special & sShape::Permissions)
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
	if (special & sShape::Permissions)
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
	if (shape.special)
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
	if (special & sShape::MimeContent) {
		MESSAGE_CONTENT *content = nullptr;
		if (!exmdb.read_message(dir.c_str(), nullptr, CP_ACP, mid, &content) ||
		    content == nullptr)
			throw EWSError::ItemNotFound(E3071);
		auto log_id = dir + ":m" + std::to_string(mid);
		try {
			item.MimeContent.emplace(exportContent(dir, *content, log_id));
		} catch (const std::exception &e) {
			mlog(LV_WARN, "[ews] %s: MIME export failed: %s", log_id.c_str(), e.what());
		}
	}
	if (special & sShape::Attachments) {
		static constexpr proptag_t tagIDs[] = {
			PR_ATTACH_METHOD, PR_DISPLAY_NAME, PR_ATTACH_MIME_TAG,
			PR_ATTACH_CONTENT_ID, PR_ATTACH_LONG_FILENAME,
			PR_ATTACH_FLAGS, PR_ATTACH_SIZE,
			PR_ATTACHMENT_HIDDEN,
		};
		auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
		std::vector<uint32_t> nums;
		if (!attachment_nums(m_plugin, dir, mInst->instanceId, nums))
			throw DispatchError(E3079);
		sAttachmentId aid(this->getItemEntryId(dir, mid), 0);
		item.Attachments.emplace().reserve(nums.size());
		for (auto i : nums) {
			auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
			TPROPVAL_ARRAY props;
			if (!exmdb.get_instance_properties(dir.c_str(), 0,
			    aInst->instanceId, proptag_cspan{tagIDs}, &props))
				throw DispatchError(E3080);
			auto hidden = props.get<const uint8_t>(PR_ATTACHMENT_HIDDEN);
			if (hidden && *hidden)
				continue;
			sShape shape(props);
			auto method = props.get<const uint32_t>(PR_ATTACH_METHOD);
			if (method != nullptr && *method == ATTACH_EMBEDDED_MSG) {
				auto eInst = m_plugin.loadEmbeddedInstance(dir, aInst);
				MESSAGE_CONTENT eInstContent{};
				if (!exmdb.read_message_instance(dir.c_str(), eInst->instanceId, &eInstContent))
					throw DispatchError(E3333);
				auto log_id = dir + ":a" + std::to_string(i);
				try {
					shape.mimeContent.emplace(exportContent(dir, eInstContent, log_id));
				} catch (const std::exception &e) {
					mlog(LV_WARN, "[ews] %s: MIME export failed, skipping attachment", log_id.c_str());
					continue;
				}
			}
			aid.attachment_num = i;
			item.Attachments->emplace_back(tAttachment::create(aid, std::move(shape)));
		}
		if (item.Attachments->empty())
			item.Attachments.reset();
	}
	if (special & sShape::Rights) {
		auto rights = permissions(dir, fid);
		/* Withheld private items can be neither read nor changed */
		if (special & sShape::Redacted)
			rights &= ~(frightsReadAny | frightsEditAny | frightsEditOwned |
			          frightsDeleteAny | frightsDeleteOwned);
		item.EffectiveRights.emplace(rights);
	}
}

/* Reply-To addresses of a message */
static std::vector<tEmailAddressType> reply_to_list(const BINARY &entries)
{
	std::vector<tEmailAddressType> list;
	if (entries.pb == nullptr || entries.cb == 0)
		return list;
	EXT_PULL pull;
	BINARY_ARRAY addressArray{};
	auto cleanup = HX::make_scope_exit([&]() {
		for (uint32_t i = 0; i < addressArray.count; ++i)
			std::free(addressArray.pbin[i].pb);
		std::free(addressArray.pbin);
	});
	pull.init(entries.pb, entries.cb, zalloc, EXT_FLAG_WCOUNT);
	if (pull.g_flatentry_a(&addressArray) != pack_result::ok)
		return list;
	list.reserve(addressArray.count);
	for (uint32_t i = 0; i < addressArray.count; ++i) {
		EXT_PULL entryPull;
		entryPull.init(addressArray.pbin[i].pb, addressArray.pbin[i].cb, zalloc, EXT_FLAG_UTF16);
		ONEOFF_ENTRYID entry{};
		if (entryPull.g_oneoff_eid(&entry) != pack_result::ok)
			continue;
		if (entry.pmail_address.empty())
			continue;
		auto &recipient = list.emplace_back();
		recipient.EmailAddress = std::move(entry.pmail_address);
		if (!entry.pdisplay_name.empty())
			recipient.Name = std::move(entry.pdisplay_name);
		if (!entry.paddress_type.empty())
			recipient.RoutingType = std::move(entry.paddress_type);
		else
			recipient.RoutingType = "SMTP";
	}
	return list;
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

	if (special & (sShape::ToRecipients | sShape::CcRecipients | sShape::BccRecipients)) {
		TARRAY_SET rcpts;
		if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts)) {
			mlog(LV_ERR, "[ews] failed to load message recipients (%s:%llu)",
				dir.c_str(), static_cast<unsigned long long>(mid));
		} else {
			for (const auto &rcpt : rcpts) {
				auto recipientType = rcpt.get<const uint32_t>(PR_RECIPIENT_TYPE);
				if (!recipientType)
					continue;
				switch (*recipientType) {
				case MAPI_TO:
					if (special & sShape::ToRecipients)
						defaulted(message.ToRecipients).emplace_back(rcpt);
					break;
				case MAPI_CC:
					if (special & sShape::CcRecipients)
						defaulted(message.CcRecipients).emplace_back(rcpt);
					break;
				case MAPI_BCC:
					if (special & sShape::BccRecipients)
						defaulted(message.BccRecipients).emplace_back(rcpt);
					break;
				}
			}
		}
	}

	if (!(special & sShape::ReplyToRecipients))
		return;

	void *propval = nullptr;
	if (!m_plugin.exmdb.get_message_property(dir.c_str(), nullptr, CP_ACP, mid,
	    PR_REPLY_RECIPIENT_ENTRIES, &propval) || propval == nullptr)
		return;
	auto list = reply_to_list(*static_cast<const BINARY *>(propval));
	if (list.empty())
		return;
	auto &replyList = defaulted(message.ReplyTo);
	replyList.insert(replyList.end(), std::make_move_iterator(list.begin()),
		std::make_move_iterator(list.end()));
}

/**
 * @brief     Load meeting request attributes not contained in tags
 *
 * Populates attendee lists from the recipient table in addition
 * to loading standard message attributes.
 *
 * @param     dir     Store to load from
 * @param     fid     Parent folder ID
 * @param     mid     Message to load
 * @param     meetReq Meeting request to store data in
 * @param     special Bit mask of attributes to load
 */
void EWSContext::loadSpecial(const std::string &dir, uint64_t fid,
    uint64_t mid, tMeetingMessage &meetMsg, uint64_t special) const
{
	loadSpecial(dir, fid, mid, static_cast<tMessage &>(meetMsg), special);
	if (!meetMsg.UID || meetMsg.AssociatedCalendarItemId)
		return;
	/*
	 * Populate AssociatedCalendarItemId by searching the
	 * calendar for an item matching the CleanGlobalObjectId.
	 */
	auto goid = getItemProp<BINARY>(dir, mid,
	    PROP_TAG(PT_BINARY, getNamedPropId(dir,
	    NtCleanGlobalObjectId)));
	if (goid == nullptr || goid->cb == 0)
		return;
	sFolderSpec calFolder;
	calFolder.folderId = eid_t(1,
	    PRIVATE_FID_CALENDAR);
	calFolder.location = sFolderSpec::PRIVATE;
	calFolder.target = m_auth_info.username;
	std::string calDir = getDir(calFolder);
	auto pidCgoid  = getNamedPropId(calDir, NtCleanGlobalObjectId);
	auto cgoid_tag = PROP_TAG(PT_BINARY, pidCgoid);
	const RESTRICTION_PROPERTY rprop = {RELOP_EQ, cgoid_tag, {cgoid_tag, deconst(goid)}};
	const RESTRICTION rst = {RES_PROPERTY, {deconst(&rprop)}};
	uint32_t table_id = 0, row_count = 0;
	if (!m_plugin.exmdb.load_content_table(calDir.c_str(),
	    CP_ACP, calFolder.folderId, nullptr,
	    TABLE_FLAG_NONOTIFICATIONS, &rst, nullptr,
	    &table_id, &row_count) || row_count == 0)
		return;
	auto cl_tbl = HX::make_scope_exit([&]() {
		m_plugin.exmdb.unload_table(calDir.c_str(), table_id);
	});
	static constexpr proptag_t eid_tag = PR_ENTRYID;
	TARRAY_SET rows{};
	if (!m_plugin.exmdb.query_table(calDir.c_str(), nullptr,
	    CP_ACP, table_id, {&eid_tag, 1}, 0, 1, &rows) ||
	    rows.count == 0 || rows.pparray[0] == nullptr)
		return;
	auto eid = rows.pparray[0]->get<const BINARY>(PR_ENTRYID);
	if (eid == nullptr || eid->cb == 0)
		return;
	meetMsg.AssociatedCalendarItemId.emplace();
	meetMsg.AssociatedCalendarItemId->Id.assign(*eid);
}

void EWSContext::loadSpecial(const std::string &dir, uint64_t fid, uint64_t mid,
    tMeetingRequestMessage &meetReq, uint64_t special) const
{
	loadSpecial(dir, fid, mid,
	            static_cast<tMeetingMessage &>(meetReq), special);
	if (!(special & sShape::Attendees))
		return;
	TARRAY_SET rcpts;
	if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts)) {
		mlog(LV_ERR, "[ews] failed to load meeting request "
		     "attendees (%s:%llu)", dir.c_str(),
		     static_cast<unsigned long long>(mid));
		return;
	}
	for (const auto &rcpt : rcpts) {
		auto recipientType = rcpt.get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (!recipientType)
			continue;
		auto flags = rcpt.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (flags != nullptr && (*flags & recipOrganizer))
			continue;
		switch (*recipientType) {
		case MAPI_TO:
			if (special & sShape::RequiredAttendees)
				defaulted(meetReq.RequiredAttendees).emplace_back(rcpt);
			break;
		case MAPI_CC:
			if (special & sShape::OptionalAttendees)
				defaulted(meetReq.OptionalAttendees).emplace_back(rcpt);
			break;
		case MAPI_BCC:
			if (special & sShape::Resources)
				defaulted(meetReq.Resources).emplace_back(rcpt);
			break;
		}
	}
}

/**
 * @brief     Load calendar item attributes not contained in tags
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
	/* IsMeeting is only there when the shape asked for it */
	bool meeting = calItem.IsMeeting && *calItem.IsMeeting;
	if (!calItem.IsMeeting) {
		auto flags = getItemProp<uint32_t>(dir, mid, PROP_TAG(PT_LONG,
		             getNamedPropId(dir, NtAppointmentStateFlags)));
		meeting = flags != nullptr && *flags & asfMeeting;
	}
	if (!meeting)
		return;
	TARRAY_SET rcpts;
	if (!m_plugin.exmdb.get_message_rcpts(dir.c_str(), mid, &rcpts)) {
		mlog(LV_ERR, "[ews] failed to load calItem recipients (%s:%llu)",
			dir.c_str(), static_cast<unsigned long long>(mid));
		return;
	}
	for (const auto &rcpt : rcpts) {
		auto recipientType = rcpt.get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (!recipientType)
			continue;
		auto flags = rcpt.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (flags != nullptr && (*flags & recipOrganizer))
			continue;
		switch (*recipientType) {
		case MAPI_TO:
			if (special & sShape::RequiredAttendees)
				defaulted(calItem.RequiredAttendees).emplace_back(rcpt);
			break;
		case MAPI_CC:
			if (special & sShape::OptionalAttendees)
				defaulted(calItem.OptionalAttendees).emplace_back(rcpt);
			break;
		case MAPI_BCC:
			if (special & sShape::Resources)
				defaulted(calItem.Resources).emplace_back(rcpt);
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
	shape.clean(true);
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
	shape.x500Org = m_plugin.x500_org_name.c_str();
	getNamedTags(dir, shape);
	shape.properties(getItemProps(dir, mid, shape.proptags()));
	sItem item = tItem::create(shape);
	if (auto special = shape.specials())
		std::visit([&](auto &&it) { loadSpecial(dir, fid, mid, it, special); }, item);
	return item;
}

/**
 * @brief      Convert a local-as-UTC rtime of the series to UTC
 */
clock::time_point EWSContext::sOccurrenceSeries::toUtc(uint32_t rtime) const
{
	int64_t off;
	if (tzdef && tz_to_offset(*tzdef, rop_util_rtime_to_unix(rtime), off))
		return rop_util_rtime_to_unix2(rtime) + std::chrono::minutes(off);
	return rop_util_rtime_to_unix2(rtime) + tzOffset;
}

/**
 * @brief      Convert a UTC NTTIME to a local-as-UTC rtime of the series
 *
 * The offset is taken at the converted instant, so a series that
 * crosses a DST change keeps the wall clock time of each occurrence.
 */
uint32_t EWSContext::sOccurrenceSeries::toLocal(uint64_t nttime) const
{
	auto utc = rop_util_nttime_to_unix(nttime);
	int64_t off;
	if (tzdef && tz_to_offset(*tzdef, utc, off) &&
	    tz_to_offset(*tzdef, utc - off * 60, off))
		return rop_util_unix_to_rtime(utc - off * 60);
	return rop_util_unix_to_rtime(utc - tzOffset.count());
}

/**
 * @brief      Parse the recurrence and time zone of a series master
 *
 * @param      recur  PidLidAppointmentRecur
 * @param      start  PR_START_DATE (UTC)
 * @param      tzbin  PidLidAppointmentTimeZoneDefinitionRecur
 */
void EWSContext::sOccurrenceSeries::parse(const BINARY *recur,
    const uint64_t *start, const BINARY *tzbin)
{
	/*
	 * Recurrence blob rtimes are "local-as-UTC" – derive the offset
	 * from the master's PR_START_DATE (real UTC) vs the recurrence
	 * pattern's first occurrence rtime.
	 */
	if (recur != nullptr && recur->cb > 0) {
		EXT_PULL rp;
		rp.init(recur->pb, recur->cb, nullptr, 0);
		aprValid = rp.g_apptrecpat(&apr) == pack_result::ok;
	}
	if (!aprValid)
		return;
	startOff = apr.starttimeoffset;
	endOff   = apr.endtimeoffset;
	if (start != nullptr) {
		auto su  = rop_util_nttime_to_unix(*start);
		auto sl  = rop_util_rtime_to_unix(apr.recur_pat.startdate + apr.starttimeoffset);
		tzOffset = std::chrono::seconds(su - sl);
	}
	if (tzbin != nullptr)
		tzdef = EXT_PULL::bin_to_tzdef(*tzbin);
}

/**
 * @brief      Original and actual start/end of an occurrence (UTC)
 */
EWSContext::sOccurrenceSeries::times
EWSContext::sOccurrenceSeries::occurrenceTimes(uint32_t basedate) const
{
	times t;
	t.orig_start = toUtc(basedate + startOff);
	/* An embedded message has the master's dates */
	auto exc = aprValid ? find_exc(apr, basedate) : nullptr;
	if (exc != nullptr) {
		t.start = toUtc(exc->startdatetime);
		t.end   = toUtc(exc->enddatetime);
	} else {
		t.start = t.orig_start;
		t.end   = toUtc(basedate + endOff);
	}
	return t;
}

/**
 * @brief      Whether an exception replaces the occurrence at @basedate
 *
 * @param      basedate  Basedate of the occurrence
 * @param      exrt      PidLidExceptionReplaceTime of the exception (UTC)
 */
bool EWSContext::sOccurrenceSeries::replaces(uint32_t basedate,
    uint64_t exrt) const
{
	return replaces(basedate, toUtc(basedate + startOff), exrt);
}

/**
 * @param      orig  Original start of the occurrence (UTC)
 */
bool EWSContext::sOccurrenceSeries::replaces(uint32_t basedate,
    clock::time_point orig, uint64_t exrt) const
{
	/* Compare days in the series zone, not in the server's */
	auto diff = std::chrono::duration_cast<std::chrono::minutes>(
	            rop_util_nttime_to_unix2(exrt) - orig).count();
	int64_t local = int64_t{basedate} + startOff + diff;
	return local >= 0 && local / 1440 == basedate / 1440;
}

/**
 * @brief      Load the recurrence and time zone of a series master
 *
 * Enough for occurrence times, unlike loadOccurrenceSeries().
 */
EWSContext::sOccurrenceSeries
EWSContext::loadSeriesTimes(const std::string &dir, uint64_t mid) const
{
	auto recur_tag = PROP_TAG(PT_BINARY, getNamedPropId(dir,
	                 NtAppointmentRecur, true));
	auto tzr_tag   = PROP_TAG(PT_BINARY, getNamedPropId(dir,
	                 NtAppointmentTimeZoneDefinitionRecur, true));
	const proptag_t tags[] = {PR_START_DATE, recur_tag, tzr_tag};
	auto props = getItemProps(dir, mid, tags);
	sOccurrenceSeries s;
	s.mid = mid;
	s.parse(props.get<const BINARY>(recur_tag),
		props.get<const uint64_t>(PR_START_DATE),
		props.get<const BINARY>(tzr_tag));
	return s;
}

/**
 * @brief      Load the master properties of a recurring series
 *
 * Leaves the master's properties in @shape and parses the recurrence
 * pattern and time zone from them. The occurrences need
 * loadOccurrenceInstances() in addition.
 *
 * @param      dir    Store directory
 * @param      fid    Parent folder ID
 * @param      mid    Message ID of the recurring master
 * @param      shape  Requested item shape
 */
EWSContext::sOccurrenceSeries
EWSContext::loadOccurrenceSeries(const std::string &dir, uint64_t fid,
    uint64_t mid, sShape &shape) const
{
	sOccurrenceSeries s;
	s.fid = fid;
	s.mid = mid;
	shape.clean();
	shape.x500Org = m_plugin.x500_org_name.c_str();
	getNamedTags(dir, shape);
	shape.properties(getItemProps(dir, mid, shape.proptags()));

	auto start = shape.get<const uint64_t>(PR_START_DATE);
	if (start == nullptr)
		start = shape.get<uint64_t>(NtCommonStart);
	s.parse(shape.get<const BINARY>(NtAppointmentRecur), start,
		shape.get<BINARY>(NtAppointmentTimeZoneDefinitionRecur, sShape::FL_ANY));
	return s;
}

/**
 * @brief      Load what all occurrences of a series share
 *
 * Builds the master item the occurrences are copied from and locates the
 * exception attachments. Expects the master's properties in @shape, as left
 * by loadOccurrenceSeries().
 *
 * @param      dir    Store directory
 * @param      s      Series
 * @param      shape  Requested item shape
 */
void EWSContext::loadOccurrenceInstances(const std::string &dir,
    sOccurrenceSeries &s, sShape &shape) const
{
	auto mInst = m_plugin.loadMessageInstance(dir, s.fid, s.mid);
	std::vector<uint32_t> nums;
	if (!attachment_nums(m_plugin, dir, mInst->instanceId, nums))
		throw DispatchError(E3210);

	PROPNAME_ARRAY propnames;
	propnames.count = 1;
	PROPERTY_NAME propname_buff[1];
	propname_buff[0].kind = MNID_ID;
	propname_buff[0].guid = PSETID_Appointment;
	propname_buff[0].lid  = PidLidExceptionReplaceTime;
	propnames.ppropname   = propname_buff;
	PROPID_ARRAY namedids = getNamedPropIds(dir, propnames, true);
	auto ex_replace_time_tag = PROP_TAG(PT_SYSTIME, namedids[0]);
	s.excTags = shape.proptags_vec();
	s.excTags.emplace_back(ex_replace_time_tag);

	/* Exceptions carry no MimeContent, see materializeOccurrence() */
	s.base.emplace(tItem::create(shape));
	if (auto special = shape.specials() & ~sShape::MimeContent)
		std::visit([&](auto &&it) {
			loadSpecial(dir, s.fid, s.mid, it, special);
		}, *s.base);

	const proptag_t ex_tags[] = {ex_replace_time_tag};
	for (auto i : nums) {
		auto aInst = m_plugin.loadAttachmentInstance(dir, s.fid, s.mid, i);
		std::shared_ptr<EWSPlugin::ExmdbInstance> eInst;
		try {
			eInst = m_plugin.loadEmbeddedInstance(dir, aInst);
		} catch (const DispatchError &) {
			continue; /* skip non-embedded attachments */
		}
		TPROPVAL_ARRAY props;
		if (!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0,
		    eInst->instanceId, proptag_cspan{ex_tags}, &props))
			throw DispatchError(E3211);
		auto exstarttime = props.get<const uint64_t>(ex_replace_time_tag);
		if (!exstarttime)
			continue;
		s.exceptions.emplace_back(sOccurrenceSeries::exc_slot{
			*exstarttime, std::move(eInst)});
	}
}

/**
 * @brief      Build one occurrence of a series
 *
 * @param      dir      Store directory
 * @param      s        Series, from loadOccurrenceSeries() and
 *                      loadOccurrenceInstances()
 * @param      basedate Basedate of the occurrence
 * @param      shape    Requested item shape
 *
 * @return     The occurrence, with its occurrence ItemId
 */
sItem EWSContext::materializeOccurrence(const std::string &dir,
    sOccurrenceSeries &s, uint32_t basedate, sShape &shape) const
{
	/* Judge every occurrence by its series first */
	shape.applySeriesAccess();
	auto matching_exc = s.aprValid ? find_exc(s.apr, basedate) : nullptr;
	auto stamp = [&](sItem &item, Enum::CalendarItemTypeType type) {
		if (auto cal = std::get_if<tCalendarItem>(&item)) {
			auto t = s.occurrenceTimes(basedate);
			cal->Start.emplace(t.start);
			cal->End.emplace(t.end);
			cal->CalendarItemType.emplace(type);
			cal->RecurrenceId.emplace(s.toUtc(basedate + s.startOff));
			cal->OriginalStart = cal->RecurrenceId;
			cal->Recurrence.reset();
			cal->ModifiedOccurrences.reset();
			cal->DeletedOccurrences.reset();
		}
		markOccurrenceId(item, basedate);
	};

	auto orig = s.toUtc(basedate + s.startOff);
	auto slot = std::find_if(s.exceptions.begin(), s.exceptions.end(),
	            [&](const sOccurrenceSeries::exc_slot &e) {
	            	return s.replaces(basedate, orig, e.replace_time);
	            });
	if (slot != s.exceptions.end()) {
		TPROPVAL_ARRAY props;
		if (!m_plugin.exmdb.get_instance_properties(dir.c_str(), 0,
		    slot->inst->instanceId, s.excTags, &props))
			throw DispatchError(E3211);
		sItem item = *s.base;
		std::visit([&](auto &&it) { updateProps(it, shape, props); }, item);
		stamp(item, Enum::Exception);
		return item;
	}
	if (matching_exc != nullptr) {
		/* Modified in the blob only: apply its overrides */
		sItem item = *s.base;
		auto cal = std::get_if<tCalendarItem>(&item);
		const auto &xe = s.apr.pextendedexception[matching_exc -
		                 s.apr.pexceptioninfo.data()];
		auto ovr = matching_exc->overrideflags;
		if (cal != nullptr && ovr & ARO_SUBJECT &&
		    shape.requested(PR_SUBJECT))
			cal->Subject.emplace(xe.subject);
		if (cal != nullptr && ovr & ARO_LOCATION &&
		    shape.requested(shape.tag(NtLocation)))
			cal->Location.emplace(xe.location);
		stamp(item, Enum::Exception);
		return item;
	}

	/* Unmodified occurrence: construct from master properties */
	if (shape.specials() & sShape::MimeContent && !s.occBase) {
		s.occBase.emplace(*s.base);
		std::visit([&](auto &&it) {
			loadSpecial(dir, s.fid, s.mid, it, sShape::MimeContent);
		}, *s.occBase);
	}
	sItem item = s.occBase ? *s.occBase : *s.base;
	stamp(item, Enum::Occurrence);
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
	auto s = loadOccurrenceSeries(dir, fid, mid, shape);
	loadOccurrenceInstances(dir, s, shape);
	return materializeOccurrence(dir, s, basedate, shape);
}

/**
 * @brief      Expand a recurring master into its occurrences within a window
 *
 * Produces one item per visible occurrence overlapping [start, end], each
 * carrying its own occurrence ItemId (resolvable via GetItem) and the
 * occurrence's own Start/End. Deleted occurrences are omitted and modified
 * ones are returned as Exception rather than Occurrence. Both are decided by
 * materializeOccurrence().
 *
 * @param      dir    Store directory
 * @param      fid    Folder ID
 * @param      mid    Message ID of the recurring master
 * @param      start  Window start (UTC)
 * @param      end    Window end (UTC)
 * @param      shape  Shape to load the occurrences with
 *
 * @return     Expanded occurrences, chronologically ordered
 */
std::vector<sItem> EWSContext::expandOccurrences(const std::string &dir,
    uint64_t fid, uint64_t mid, time_t start, time_t end, sShape &shape) const
{
	auto s = loadOccurrenceSeries(dir, fid, mid, shape);
	if (!s.aprValid) {
		auto bin = shape.get<const BINARY>(NtAppointmentRecur);
		throw EWSError::ItemCorrupt(bin == nullptr || bin->cb == 0 ? E3305 : E3306);
	}
	auto dates = occurrenceDatesInRange(s.apr, s.tzdef ? &*s.tzdef : nullptr,
	             s.tzOffset, start, end);
	if (dates.empty())
		return {};
	loadOccurrenceInstances(dir, s, shape);
	std::vector<sItem> items;
	items.reserve(dates.size());
	for (auto date : dates)
		items.emplace_back(materializeOccurrence(dir, s, date, shape));
	return items;
}

/**
 * @brief      Resolve an OccurrenceItemId InstanceIndex to a basedate
 *
 * @param      dir    Store directory
 * @param      mid    Message ID of the recurring master
 * @param      index  1-based occurrence index (InstanceIndex from EWS)
 *
 * @return     Basedate in rtime format
 */
uint32_t EWSContext::resolveOccurrenceIndex(const std::string &dir,
    uint64_t mid, uint32_t index) const try
{
	auto [recur_tag, apr] = loadRecurPat(dir, mid);
	auto date = nthOccurrenceDate(apr, index, true);
	if (isTrulyDeleted(apr, date))
		throw EWSError::CalendarOccurrenceIsDeletedFromRecurrence(E3483);
	return date;
} catch (const InputError &e) {
	throw EWSError::CalendarOccurrenceIndexIsOutOfRecurrenceRange(e.what());
}

/**
 * @brief      Refuse the occurrence id of a deleted occurrence
 *
 * @param      dir       Store directory
 * @param      mid       Message ID of the recurring master
 * @param      basedate  Basedate from the occurrence id
 */
void EWSContext::checkOccurrence(const std::string &dir, uint64_t mid,
    uint32_t basedate) const
{
	if (isTrulyDeleted(loadRecurPat(dir, mid).second, basedate))
		throw EWSError::CalendarOccurrenceIsDeletedFromRecurrence(E3488);
}

/**
 * @brief      Delete a single occurrence from a recurring appointment
 *
 * Adds the occurrence date to the deleted instances list in the
 * recurrence blob and drops the exception of a modified occurrence.
 *
 * @param      dir       Store directory
 * @param      fid       Folder ID
 * @param      mid       Message ID of the recurring master
 * @param      basedate  Occurrence date in rtime format
 */
void EWSContext::deleteOccurrence(const std::string &dir, uint64_t fid,
    uint64_t mid, uint32_t basedate) const
{
	auto [recur_tag, apr] = loadRecurPat(dir, mid);
	auto ret = apr.remove_instance(basedate);
	if (ret == 0)
		return; /* already deleted */
	if (ret == 1)
		deleteExceptionAttachment(dir, fid, mid, basedate);
	if (!saveRecurBlob(dir, mid, recur_tag, apr))
		throw DispatchError(E3308);
}

/**
 * @brief      Remove the exception attachment of an occurrence
 *
 * Otherwise oxcical would still export the occurrence as an override.
 */
void EWSContext::deleteExceptionAttachment(const std::string &dir,
    uint64_t fid, uint64_t mid, uint32_t basedate) const
{
	auto &exmdb = m_plugin.exmdb;
	m_plugin.unloadMessageInstance(dir, mid);
	auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
	uint16_t count = 0;
	if (!exmdb.get_message_instance_attachments_num(dir.c_str(),
	    mInst->instanceId, &count))
		throw DispatchError(E3485);
	const proptag_t tags[] = {PROP_TAG(PT_SYSTIME,
		getNamedPropId(dir, NtExceptionReplaceTime, true))};
	auto series = loadSeriesTimes(dir, mid);
	for (uint16_t i = 0; i < count; ++i) {
		auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
		std::shared_ptr<EWSPlugin::ExmdbInstance> eInst;
		try {
			eInst = m_plugin.loadEmbeddedInstance(dir, aInst);
		} catch (const DispatchError &) {
			continue; /* skip non-embedded attachments */
		}
		TPROPVAL_ARRAY props{};
		if (!exmdb.get_instance_properties(dir.c_str(), 0,
		    eInst->instanceId, proptag_cspan{tags}, &props))
			throw DispatchError(E3486);
		auto extime = props.get<const uint64_t>(tags[0]);
		if (extime == nullptr || !series.replaces(basedate, *extime))
			continue;
		ec_error_t err = ecSuccess;
		if (!exmdb.delete_message_instance_attachment(dir.c_str(),
		    mInst->instanceId, i) ||
		    !exmdb.flush_instance(dir.c_str(), mInst->instanceId, &err) ||
		    err != ecSuccess)
			throw EWSError::ItemSave(E3487);
		/* The attachment numbers have a gap now */
		m_plugin.unloadMessageInstance(dir, mid);
		return;
	}
}

/**
 * Compute timezone offset (in rtime minutes) from the master appointment's
 * real UTC start vs the recurrence blob's local-as-UTC startdate.
 */
int32_t EWSContext::recurTzOffset(const std::string &dir, uint64_t mid,
    const APPOINTMENT_RECUR_PAT &apr) const
{
	proptag_t tags[] = {PR_START_DATE};
	TPROPVAL_ARRAY sd_res = getItemProps(dir, mid, tags);
	if (sd_res.count != 1 || sd_res.ppropval->proptag != PR_START_DATE)
		return 0;
	auto su = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(sd_res.ppropval->pvalue));
	auto sl = rop_util_rtime_to_unix(apr.recur_pat.startdate + apr.starttimeoffset);
	int64_t diff = (su - sl) / 60;
	if (diff < std::numeric_limits<int32_t>::min() || diff > std::numeric_limits<int32_t>::max())
		return 0;  // probable data corruption, pretend it does not exist
	return int32_t(diff);
}

/**
 * Apply property changes to an EXCEPTIONINFO/EXTENDEDEXCEPTION pair
 * in the recurrence blob.
 */
template<typename F> static void applyExceptionOverrides(EXCEPTIONINFO &ei,
    EXTENDEDEXCEPTION &ee, const TPROPVAL_ARRAY &props, propid_t location_id,
    propid_t busystatus_id, propid_t subtype_id, propid_t reminderdelta_id,
    propid_t reminderset_id, F &&to_local)
{
	for (unsigned int j = 0; j < props.count; ++j) {
		auto tag = props.ppropval[j].proptag;
		if (tag == PR_SUBJECT || tag == PR_SUBJECT_A ||
		    tag == PR_NORMALIZED_SUBJECT ||
		    tag == PR_NORMALIZED_SUBJECT_A) {
			ei.overrideflags |= ARO_SUBJECT;
			ei.subject = static_cast<char *>(props.ppropval[j].pvalue);
			ee.subject = ei.subject;
		} else if (PROP_ID(tag) == location_id) {
			ei.overrideflags |= ARO_LOCATION;
			ei.location = static_cast<char *>(props.ppropval[j].pvalue);
			ee.location = ei.location;
		} else if (PROP_ID(tag) == busystatus_id) {
			ei.overrideflags |= ARO_BUSYSTATUS;
			ei.busystatus = *static_cast<uint32_t *>(props.ppropval[j].pvalue);
		} else if (PROP_ID(tag) == subtype_id) {
			ei.overrideflags |= ARO_SUBTYPE;
			ei.subtype = *static_cast<uint32_t *>(props.ppropval[j].pvalue);
		} else if (PROP_ID(tag) == reminderdelta_id) {
			ei.overrideflags |= ARO_REMINDERDELTA;
			ei.reminderdelta = *static_cast<uint32_t *>(props.ppropval[j].pvalue);
		} else if (PROP_ID(tag) == reminderset_id) {
			ei.overrideflags |= ARO_REMINDER;
			ei.reminderset = *static_cast<uint32_t *>(props.ppropval[j].pvalue);
		} else if (tag == PR_START_DATE) {
			auto nt = *static_cast<const uint64_t *>(props.ppropval[j].pvalue);
			ei.startdatetime = to_local(nt);
			ee.startdatetime = ei.startdatetime;
		} else if (tag == PR_END_DATE) {
			auto nt = *static_cast<const uint64_t *>(props.ppropval[j].pvalue);
			ei.enddatetime = to_local(nt);
			ee.enddatetime = ei.enddatetime;
		} else if (tag == PR_BODY || tag == PR_BODY_W || tag == PR_HTML) {
			ei.overrideflags |= ARO_EXCEPTIONAL_BODY;
		}
	}
	ei.overrideflags |= ARO_ATTACHMENT;
	ei.attachment = 1;
}

/**
 * Move the ModifiedInstanceDates entry of an exception whose start changed
 * from @old_start to @new_start. Blobs written by older versions keyed the
 * entry by the original day @basedate.
 */
static void moveModifiedDate(RECURRENCE_PATTERN &rp, uint32_t old_start,
    uint32_t basedate, uint32_t new_start)
{
	auto &mods = rp.pmodifiedinstancedates;
	auto day = [](uint32_t d) { return d / 1440; };
	auto it = std::find_if(mods.begin(), mods.end(),
	          [&](uint32_t m) { return day(m) == day(old_start); });
	if (it == mods.end())
		it = std::find_if(mods.begin(), mods.end(),
		     [&](uint32_t m) { return day(m) == day(basedate); });
	if (it == mods.end())
		return;
	*it = day(new_start) * 1440;
	rp.sort_mods();
}

/**
 * Serialize an APPOINTMENT_RECUR_PAT and save it as a property.
 * Returns false on serialization failure.
 */
bool EWSContext::saveRecurBlob(const std::string &dir, uint64_t mid,
    proptag_t recur_tag, const APPOINTMENT_RECUR_PAT &apr) const
{
	EXT_PUSH ext_push;
	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_apptrecpat(apr) != pack_result::ok)
		return false;
	BINARY new_bin;
	new_bin.cb = ext_push.m_offset;
	new_bin.pb = ext_push.m_udata;
	std::vector<TAGGED_PROPVAL> rprop = {{recur_tag, &new_bin}};

	/*
	 * The series changed with its occurrence, so give it a new change
	 * number and key. Otherwise SyncFolderItems and ICS never report
	 * the change and other clients keep the old occurrences.
	 */
	uint64_t cn = 0;
	if (!m_plugin.exmdb.allocate_cn(dir.c_str(), &cn))
		return false;
	uint64_t now = rop_util_current_nttime();
	rprop.push_back({PidTagChangeNumber, &cn});
	rprop.push_back({PR_LAST_MODIFICATION_TIME, &now});
	const proptag_t ctags[] = {PR_CHANGE_KEY, PR_PREDECESSOR_CHANGE_LIST};
	auto cur = getItemProps(dir, mid, ctags);
	auto oldkey = cur.get<const BINARY>(PR_CHANGE_KEY);
	XID xid;
	EXT_PULL ep;
	BINARY ckey{};
	binary_ptr pcl_buf;
	if (oldkey != nullptr) {
		ep.init(oldkey->pb, oldkey->cb, nullptr, 0);
		if (ep.g_xid(oldkey->cb, &xid) == pack_result::ok) {
			xid = XID{xid.guid, cn};
			ckey = serialize(xid);
			PCL pcl;
			auto oldpcl = cur.get<const BINARY>(PR_PREDECESSOR_CHANGE_LIST);
			if (oldpcl != nullptr && !pcl.deserialize(oldpcl))
				pcl = PCL{};
			pcl_buf = mkPCL(xid, std::move(pcl));
			rprop.push_back({PR_CHANGE_KEY, &ckey});
			rprop.push_back({PR_PREDECESSOR_CHANGE_LIST, pcl_buf.get()});
		}
	}
	const TPROPVAL_ARRAY rpropvals = {static_cast<uint16_t>(rprop.size()), rprop.data()};
	PROBLEM_ARRAY rproblems;
	return m_plugin.exmdb.set_message_properties(dir.c_str(),
	       nullptr, CP_ACP, mid, &rpropvals, &rproblems) &&
	       rproblems.count == 0;
}

/**
 * Resolve PidLidAppointmentRecur, load the binary, and parse it.
 * Returns the resolved proptag and the parsed recurrence pattern.
 */
std::pair<proptag_t, APPOINTMENT_RECUR_PAT>
EWSContext::loadRecurPat(const std::string &dir, uint64_t mid) const
{
	const PROPERTY_NAME pn[] = {{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur}};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna);
	proptag_t tag = PROP_TAG(PT_BINARY, ids[0]);
	auto props = getItemProps(dir, mid, proptag_cspan{&tag, 1});
	auto bin = props.get<const BINARY>(tag);
	if (bin == nullptr)
		throw EWSError::CalendarCannotUseIdForRecurringMasterId(E3477);
	EXT_PULL ext_pull;
	ext_pull.init(bin->pb, bin->cb, nullptr, 0);
	APPOINTMENT_RECUR_PAT apr{};
	if (ext_pull.g_apptrecpat(&apr) != pack_result::ok)
		throw EWSError::ItemCorrupt(E3306);
	return {tag, std::move(apr)};
}

void EWSContext::updateOccurrence(const std::string &dir, uint64_t fid,
    uint64_t mid, uint32_t basedate, const TPROPVAL_ARRAY &props,
    const proptag_cspan &rm_tags) const
{
	auto &exmdb = m_plugin.exmdb;

	/* Resolve named property IDs */
	const PROPERTY_NAME pn_buf[] = {
		{MNID_ID, PSETID_Appointment, PidLidExceptionReplaceTime},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur},
		{MNID_ID, PSETID_Appointment, PidLidLocation},
		{MNID_ID, PSETID_Appointment, PidLidBusyStatus},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSubType},
		{MNID_ID, PSETID_Common, PidLidReminderDelta},
		{MNID_ID, PSETID_Common, PidLidReminderSet},
		{MNID_ID, PSETID_Common, PidLidCommonStart},
		{MNID_ID, PSETID_Common, PidLidCommonEnd},
		{MNID_ID, PSETID_Appointment, PidLidRecurring},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentStartWhole},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentEndWhole},
	};
	const PROPNAME_ARRAY propnames = {std::size(pn_buf), deconst(pn_buf)};
	auto namedids         = getNamedPropIds(dir, propnames, true);
	auto ex_replace_tag   = PROP_TAG(PT_SYSTIME, namedids[0]);
	auto recur_tag        = PROP_TAG(PT_BINARY, namedids[1]);
	auto location_id      = namedids[2];
	auto busystatus_id    = namedids[3];
	auto subtype_id       = namedids[4];
	auto reminderdelta_id = namedids[5];
	auto reminderset_id   = namedids[6];
	auto common_start_tag = PROP_TAG(PT_SYSTIME, namedids[7]);
	auto common_end_tag   = PROP_TAG(PT_SYSTIME, namedids[8]);
	auto recurring_tag    = PROP_TAG(PT_BOOLEAN, namedids[9]);
	auto appt_start_tag   = PROP_TAG(PT_SYSTIME, namedids[10]);
	auto appt_end_tag     = PROP_TAG(PT_SYSTIME, namedids[11]);

	/* A cached instance may predate saveRecurBlob; flushing it reverts it */
	m_plugin.unloadMessageInstance(dir, mid);
	auto mInst = m_plugin.loadMessageInstance(dir, fid, mid);
	uint16_t att_count = 0;
	if (!exmdb.get_message_instance_attachments_num(dir.c_str(),
	    mInst->instanceId, &att_count))
		throw DispatchError(E3335);

	/* Search for an existing exception matching this basedate */
	auto series = loadSeriesTimes(dir, mid);

	for (uint16_t i = 0; i < att_count; ++i) {
		auto aInst = m_plugin.loadAttachmentInstance(dir, fid, mid, i);
		std::shared_ptr<EWSPlugin::ExmdbInstance> eInst;
		try {
			eInst = m_plugin.loadEmbeddedInstance(dir, aInst);
		} catch (const DispatchError &) {
			continue; /* skip non-embedded attachments */
		}
		TPROPVAL_ARRAY eprops{};
		proptag_t etags[] = {ex_replace_tag};
		if (!exmdb.get_instance_properties(dir.c_str(), 0,
		    eInst->instanceId, proptag_cspan{etags}, &eprops))
			continue;
		auto extime = eprops.get<const uint64_t>(ex_replace_tag);
		if (!extime || !series.replaces(basedate, *extime))
			continue;

		/* Found existing exception – update its embedded message */
		PROBLEM_ARRAY problems;
		if (rm_tags.size() > 0 &&
		    !exmdb.remove_instance_properties(dir.c_str(),
		    eInst->instanceId, rm_tags, &problems))
			throw EWSError::ItemSave(E3309);
		if (!exmdb.set_instance_properties(dir.c_str(),
		    eInst->instanceId, &props, &problems))
			throw EWSError::ItemSave(E3336);

		/* Scan props once for body changes and start/end times */
		bool body_upd = false;
		bool has_html = false, has_text = false;
		uint64_t upd_start_nt = 0, upd_end_nt = 0;
		bool has_start = false, has_end = false;
		for (unsigned int j = 0; j < props.count; ++j) {
			auto t = props.ppropval[j].proptag;
			if (t == PR_HTML) {
				body_upd = true;
				has_html = true;
			} else if (t == PR_BODY || t == PR_BODY_W) {
				body_upd = true;
				has_text = true;
			} else if (t == PR_START_DATE) {
				upd_start_nt = *static_cast<const uint64_t *>(props.ppropval[j].pvalue);
				has_start = true;
			} else if (t == PR_END_DATE) {
				upd_end_nt = *static_cast<const uint64_t *>(props.ppropval[j].pvalue);
				has_end = true;
			}
		}
		if (body_upd) {
			std::vector<proptag_t> body_rm = {PR_RTF_COMPRESSED};
			if (has_html && !has_text) {
				body_rm.emplace_back(PR_BODY);
				body_rm.emplace_back(PR_BODY_W);
			} else if (has_text && !has_html) {
				body_rm.emplace_back(PR_HTML);
			}
			PROBLEM_ARRAY rtf_problems;
			if (!exmdb.remove_instance_properties(dir.c_str(),
			    eInst->instanceId, proptag_cspan{body_rm}, &rtf_problems))
				throw EWSError::ItemSave(E3337);
			uint8_t rtf_nosync = 0;
			const TAGGED_PROPVAL rtf_prop[] = {{PR_RTF_IN_SYNC, &rtf_nosync}};
			const TPROPVAL_ARRAY rtf_arr = {std::size(rtf_prop), deconst(rtf_prop)};
			if (!exmdb.set_instance_properties(dir.c_str(),
			    eInst->instanceId, &rtf_arr, &rtf_problems))
				throw EWSError::ItemSave(E3338);
		}

		/*
		 * Set PidLidRecurring=false and PR_MESSAGE_CLASS to the
		 * exception class on the embedded message.
		 */
		uint8_t recurring_false = 0;
		const TAGGED_PROPVAL rf_props[] = {
			{recurring_tag, &recurring_false},
			{PR_MESSAGE_CLASS, deconst(IPM_Appointment_Exception)},
		};
		const TPROPVAL_ARRAY rf_arr = {std::size(rf_props), deconst(rf_props)};
		if (!exmdb.set_instance_properties(dir.c_str(),
		    eInst->instanceId, &rf_arr, &problems))
			throw EWSError::ItemSave(E3339);

		/*
		 * Ensure the attachment is properly marked as hidden exception
		 * with all required properties (oxcical layout).
		 */
		uint32_t afl = afException;
		uint8_t ahid = true;
		uint32_t att_linkid = 0;
		uint32_t att_fl = 0;
		uint32_t indet_rendering_pos = UINT32_MAX;
		std::vector<TAGGED_PROPVAL> afix_vec = {
			{PR_ATTACHMENT_FLAGS, &afl},
			{PR_ATTACHMENT_HIDDEN, &ahid},
			{PR_ATTACHMENT_LINKID, &att_linkid},
			{PR_ATTACH_FLAGS, &att_fl},
			{PR_RENDERING_POSITION, &indet_rendering_pos},
		};

		if (has_start)
			afix_vec.push_back({PR_EXCEPTION_STARTTIME, &upd_start_nt});
		if (has_end)
			afix_vec.push_back({PR_EXCEPTION_ENDTIME, &upd_end_nt});
		const TPROPVAL_ARRAY afix_arr = {static_cast<uint16_t>(afix_vec.size()), afix_vec.data()};
		if (!exmdb.set_instance_properties(dir.c_str(),
		    aInst->instanceId, &afix_arr, &problems))
			throw EWSError::ItemSave(E3340);
		ec_error_t err = ecSuccess;
		if (!exmdb.flush_instance(dir.c_str(),
		    eInst->instanceId, &err) || err != ecSuccess)
			throw EWSError::ItemSave(E3341);
		if (!exmdb.flush_instance(dir.c_str(),
		    aInst->instanceId, &err) || err != ecSuccess)
			throw EWSError::ItemSave(E3342);
		if (!exmdb.flush_instance(dir.c_str(),
		    mInst->instanceId, &err) || err != ecSuccess)
			throw EWSError::ItemSave(E3343);

		/* Also update the EXCEPTIONINFO in the recurrence blob */
		auto recur_bin = getItemProp<const BINARY>(dir, mid, recur_tag);
		if (recur_bin) {
			EXT_PULL ext_pull;
			ext_pull.init(recur_bin->pb, recur_bin->cb, nullptr, 0);
			APPOINTMENT_RECUR_PAT apr{};
			if (ext_pull.g_apptrecpat(&apr) == pack_result::ok) {
				auto to_local = [&](uint64_t nt) { return series.toLocal(nt); };
				for (size_t k = 0; k < apr.pexceptioninfo.size(); ++k) {
					auto &ei = apr.pexceptioninfo[k];
					if (ei.originalstartdate / 1440 != basedate / 1440)
						continue;
					auto old_start = ei.startdatetime;
					applyExceptionOverrides(ei,
						apr.pextendedexception[k],
						props, location_id,
						busystatus_id, subtype_id,
						reminderdelta_id,
						reminderset_id, to_local);
					moveModifiedDate(apr.recur_pat, old_start,
						basedate, ei.startdatetime);
					break;
				}
				saveRecurBlob(dir, mid, recur_tag, apr);
			}
		}
		return;
	}

	/* No existing exception — create a new one */

	/*
	 * Read recurrence blob first — needed for timezone offset and
	 * occurrence time computation before building the embedded msg.
	 */
	auto recur_bin = getItemProp<const BINARY>(dir, mid, recur_tag);
	if (!recur_bin)
		throw EWSError::ItemCorrupt(E3344);
	EXT_PULL ext_pull;
	ext_pull.init(recur_bin->pb, recur_bin->cb, nullptr, 0);
	APPOINTMENT_RECUR_PAT apr{};
	if (ext_pull.g_apptrecpat(&apr) != pack_result::ok)
		throw EWSError::ItemCorrupt(E3345);

	auto to_local = [&](uint64_t nt) { return series.toLocal(nt); };

	/* Compute occurrence start/end as local-as-UTC rtimes */
	auto start_rtime = basedate + apr.starttimeoffset;
	auto end_rtime   = basedate + apr.endtimeoffset;

	/*
	 * Check if the update has explicit start/end times and override
	 * rtimes. Pick up the subject for the attachment's PR_DISPLAY_NAME,
	 * too.
	 */
	uint64_t start_nttime = 0, end_nttime = 0;
	bool has_explicit_start = false, has_explicit_end = false;
	const char *disp_name = nullptr;
	bool body_changed = false;
	const BINARY *upd_html = nullptr;
	const char *upd_text = nullptr;
	for (unsigned int j = 0; j < props.count; ++j) {
		auto tag = props.ppropval[j].proptag;
		if (tag == PR_START_DATE) {
			start_nttime = *static_cast<const uint64_t *>(props.ppropval[j].pvalue);
			start_rtime  = to_local(start_nttime);
			has_explicit_start = true;
		} else if (tag == PR_END_DATE) {
			end_nttime = *static_cast<const uint64_t *>(props.ppropval[j].pvalue);
			end_rtime  = to_local(end_nttime);
			has_explicit_end = true;
		} else if (!disp_name && (tag == PR_SUBJECT ||
		    tag == PR_NORMALIZED_SUBJECT)) {
			disp_name = static_cast<const char *>(props.ppropval[j].pvalue);
		} else if (tag == PR_HTML) {
			body_changed = true;
			upd_html = static_cast<const BINARY *>(props.ppropval[j].pvalue);
		} else if (tag == PR_BODY || tag == PR_BODY_W) {
			body_changed = true;
			upd_text = static_cast<const char *>(props.ppropval[j].pvalue);
		}
	}

	/* If no explicit times, compute real UTC NTTIMEs from rtimes */
	if (!has_explicit_start)
		start_nttime = rop_util_unix_to_nttime(series.toUtc(start_rtime));
	if (!has_explicit_end)
		end_nttime = rop_util_unix_to_nttime(series.toUtc(end_rtime));

	/* Read master's properties as defaults for the embedded message */
	auto master_props = getItemProps(dir, mid, proptag_cspan{});

	/* Create new attachment instance */
	uint32_t aInstId = 0, aNum = 0;
	if (!exmdb.create_attachment_instance(dir.c_str(),
	    mInst->instanceId, &aInstId, &aNum))
		throw EWSError::ItemSave(E3346);

	/* Set attachment properties — match oxcical exception layout */
	uint32_t method = ATTACH_EMBEDDED_MSG;
	uint32_t att_flags_val = afException;
	uint8_t att_hidden = true;
	uint32_t att_linkid = 0;
	uint32_t att_fl = 0;
	BINARY att_enc{};
	uint32_t indet_rendering_pos = UINT32_MAX;
	auto att_start_nt = construct<uint64_t>(start_nttime);
	auto att_end_nt   = construct<uint64_t>(end_nttime);
	std::vector<TAGGED_PROPVAL> att_pvec = {
		{PR_ATTACH_METHOD, &method},
		{PR_ATTACHMENT_FLAGS, &att_flags_val},
		{PR_ATTACHMENT_HIDDEN, &att_hidden},
		{PR_ATTACHMENT_LINKID, &att_linkid},
		{PR_ATTACH_FLAGS, &att_fl},
		{PR_ATTACH_ENCODING, &att_enc},
		{PR_RENDERING_POSITION, &indet_rendering_pos},
		{PR_EXCEPTION_STARTTIME, att_start_nt},
		{PR_EXCEPTION_ENDTIME, att_end_nt},
	};

	/* Build embedded message content */
	MESSAGE_CONTENT content{};

	/*
	 * Copy relevant properties from the master message.
	 * Pick up the master subject as disp_name fallback, too.
	 */
	std::vector<TAGGED_PROPVAL> emb_props;
	for (unsigned int j = 0; j < master_props.count; ++j) {
		auto tag = master_props.ppropval[j].proptag;
		/* Skip properties that should not be on exceptions */
		if (tag == PR_ENTRYID || tag == PR_CHANGE_KEY ||
		    tag == PR_SOURCE_KEY || tag == PR_PREDECESSOR_CHANGE_LIST ||
		    tag == PidTagMid || tag == PidTagChangeNumber ||
		    PROP_TAG(0, PROP_ID(tag)) == PROP_TAG(0, PROP_ID(recur_tag)))
			continue;
		if (!disp_name && tag == PR_SUBJECT)
			disp_name = static_cast<const char *>(
				master_props.ppropval[j].pvalue);
		emb_props.push_back(master_props.ppropval[j]);
	}

	if (disp_name)
		att_pvec.push_back({PR_DISPLAY_NAME, deconst(disp_name)});
	TPROPVAL_ARRAY att_list = {static_cast<uint16_t>(att_pvec.size()),
	                           att_pvec.data()};

	/* Apply the update properties (overrides) */
	for (unsigned int j = 0; j < props.count; ++j) {
		auto tag = props.ppropval[j].proptag;
		/* Remove any existing prop with same tag */
		std::erase_if(emb_props, [tag](const TAGGED_PROPVAL &p) { return p.proptag == tag; });
		emb_props.push_back(props.ppropval[j]);
	}

	/*
	 * If the body was updated, synchronize all body formats on the
	 * embedded message. write_attachment_instance does *not* run
	 * sync_message_body_formats, so we must do it here. Remove *all* stale
	 * body formats from the master copy, then regenerate the missing ones
	 * from the update's format.
	 *
	 * Remove master properties that will be replaced on the exception:
	 * recurring flag, message class, all date tags, and (if body changed)
	 * all body format tags.
	 */
	auto occ_start_nt = construct<uint64_t>(start_nttime);
	auto occ_end_nt   = construct<uint64_t>(end_nttime);
	std::erase_if(emb_props, [&](const TAGGED_PROPVAL &p) {
			auto t = p.proptag;
			if (t == recurring_tag ||
			    t == PR_MESSAGE_CLASS ||
			    t == PR_START_DATE || t == PR_END_DATE ||
			    t == common_start_tag ||
			    t == common_end_tag ||
			    t == appt_start_tag ||
			    t == appt_end_tag)
				return true;
			if (body_changed &&
			    (t == PR_BODY || t == PR_BODY_W ||
			     t == PR_HTML || t == PR_RTF_COMPRESSED ||
			     t == PR_RTF_IN_SYNC))
				return true;
			return false;
		});

	/* Re-add body formats from the update */
	if (body_changed) {
		if (upd_html != nullptr)
			emb_props.push_back({PR_HTML, deconst(upd_html)});
		if (upd_text != nullptr)
			emb_props.push_back({PR_BODY, deconst(upd_text)});
		if (upd_html != nullptr && upd_text == nullptr) {
			std::string plain;
			if (html_to_plain(*upd_html, CP_UTF8, plain) >= 0)
				emb_props.push_back({PR_BODY, cpystr(plain)});
		} else if (upd_text != nullptr && upd_html == nullptr) {
			std::string html;
			if (plain_to_html(upd_text, html) == ecSuccess) {
				auto bin = construct<BINARY>(BINARY{static_cast<uint32_t>(html.size()), {cpystr(html)}});
				emb_props.push_back({PR_HTML, bin});
			}
		}
		emb_props.push_back({PR_RTF_IN_SYNC, construct<uint8_t>(0)});
	}

	/* Set exception-specific properties */
	emb_props.push_back({recurring_tag, construct<uint8_t>(0)});
	emb_props.push_back({PR_MESSAGE_CLASS, deconst(IPM_Appointment_Exception)});
	emb_props.push_back({PR_START_DATE, occ_start_nt});
	emb_props.push_back({PR_END_DATE, occ_end_nt});
	emb_props.push_back({common_start_tag, occ_start_nt});
	emb_props.push_back({common_end_tag, occ_end_nt});
	emb_props.push_back({appt_start_tag, occ_start_nt});
	emb_props.push_back({appt_end_tag, occ_end_nt});

	/*
	 * Set PidLidExceptionReplaceTime to the original start time. This must
	 * be the original date+time (not just date) so Outlook can match the
	 * embedded message to the exception.
	 */
	auto orig_time = construct<uint64_t>(rop_util_unix_to_nttime(
	                 series.occurrenceTimes(basedate).orig_start));
	emb_props.push_back({ex_replace_tag, orig_time});

	content.proplist.count = emb_props.size();
	content.proplist.ppropval = emb_props.data();

	/* Write attachment with embedded message */
	ATTACHMENT_CONTENT ac{};
	ac.proplist = att_list;
	ac.pembedded = &content;
	PROBLEM_ARRAY write_problems;
	if (!exmdb.write_attachment_instance(dir.c_str(),
	    aInstId, &ac, false, &write_problems))
		throw EWSError::ItemSave(E3347);

	ec_error_t err = ecSuccess;
	if (!exmdb.flush_instance(dir.c_str(), aInstId, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3348);
	if (!exmdb.flush_instance(dir.c_str(), mInst->instanceId, &err) ||
	    err != ecSuccess)
		throw EWSError::ItemSave(E3349);

	/* Update the recurrence blob: add to modified+deleted lists */
	auto &rp = apr.recur_pat;

	/* Add to deleted instances (required for modified occurrences too) */
	if (!rp.contains_del(basedate)) {
		rp.pdeletedinstancedates.emplace_back(basedate);
		rp.sort_dels();
	}

	/* Build new EXCEPTIONINFO + EXTENDEDEXCEPTION entries */
	auto &ei = apr.pexceptioninfo.emplace_back();
	ei.startdatetime = start_rtime;
	ei.enddatetime = end_rtime;
	/* MS-OXOCAL v22.1 §2.2.1.44.2: the original start, not its day */
	ei.originalstartdate = basedate / 1440 * 1440 + apr.starttimeoffset;
	ei.overrideflags = 0;

	auto &ee = apr.pextendedexception.emplace_back();
	ee.changehighlight.size = sizeof(uint32_t);
	ee.startdatetime = start_rtime;
	ee.enddatetime = end_rtime;
	ee.originalstartdate = ei.originalstartdate;

	applyExceptionOverrides(ei, ee, props, location_id,
		busystatus_id, subtype_id, reminderdelta_id,
		reminderset_id, to_local);

	/* MS-OXOCAL v22.1 §3.1.4.6.2: the new start day of the exception */
	rp.pmodifiedinstancedates.emplace_back(ei.startdatetime / 1440 * 1440);
	rp.sort_mods();

	apr.sort_exceptions();
	if (!saveRecurBlob(dir, mid, recur_tag, apr))
		throw DispatchError(E3350);
}

/**
 * @brief      Update attendee recipients on existing calendar item
 *
 * Used by UpdateItem when the client sets RequiredAttendees,
 * OptionalAttendees, or Resources. Replaces the attendee kinds present
 * in the update via the message instance API, keeps the organizer row
 * and the other kinds, and sets organizer properties.
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder specification
 * @param      mid       Message ID of the calendar item
 * @param      shape     Shape containing attendee XML pointers
 * @param      oldRcpts  Recipients of the item before the update
 * @param      keepResponses  Whether attendees that stay keep their
 *                       response
 */
void EWSContext::updateAttendees(const std::string &dir,
    const sFolderSpec &parent, uint64_t mid, const sShape &shape,
    const TARRAY_SET &oldRcpts, bool keepResponses) const
{
	auto &exmdb = plugin().exmdb;
	auto inst = m_plugin.loadMessageInstance(dir, parent.folderId, mid);
	if (!exmdb.empty_message_instance_rcpts(dir.c_str(), inst->instanceId))
		throw EWSError::ItemSave(E3092);

	auto rcpts = tarray_set_init();
	if (rcpts == nullptr)
		throw EWSError::NotEnoughMemory(E3455);
	auto cl_rcpts = HX::make_scope_exit([&]() { tarray_set_free(rcpts); });
	std::vector<std::string> oldAddrs;
	for (const auto &row : oldRcpts)
		oldAddrs.emplace_back(rcptAddress(row));
	uint32_t row_id = 0;
	auto parseAttendees = [&](const tinyxml2::XMLElement *xml, uint32_t type) {
		for (auto entry = xml->FirstChildElement("Attendee");
		     entry != nullptr;
		     entry = entry->NextSiblingElement("Attendee")) {
			tAttendee att(entry);
			if (att.empty_address())
				continue;
			auto rcpt = rcpts->emplace();
			att.Mailbox.mkRecipient(rcpt, type);
			/* update_message_instance_rcpts wants PR_ROWID */
			static constexpr uint32_t sendable = recipSendable;
			if (rcpt->set(PR_ROWID, &row_id) != ecSuccess ||
			    rcpt->set(PR_RECIPIENT_FLAGS, &sendable) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3456);
			++row_id;
			/* MS-OXOCAL v22.1 §3.1.4.7.3.2 */
			if (!keepResponses)
				continue;
			auto addr = rcptAddress(*rcpt);
			auto it = addr.empty() ? oldAddrs.cend() :
			          std::find_if(oldAddrs.cbegin(), oldAddrs.cend(),
			          [&](const std::string &o) { return strcasecmp(o.c_str(), addr.c_str()) == 0; });
			if (it == oldAddrs.cend())
				continue;
			auto &old = oldRcpts.pparray[it - oldAddrs.cbegin()];
			for (auto tag : {PR_RECIPIENT_TRACKSTATUS, PR_RECIPIENT_TRACKSTATUS_TIME}) {
				auto v = old->getval(tag);
				if (v != nullptr && rcpt->set(tag, v) != ecSuccess)
					throw EWSError::NotEnoughMemory(E3456);
			}
		}
	};
	for (const auto &row : oldRcpts) {
		auto type = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
		auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		bool keep = flags != nullptr && *flags & recipOrganizer;
		if (!keep && type != nullptr) {
			auto t = *type & 0xf;
			keep = (t == MAPI_TO && !shape.requiredAttendees) ||
			       (t == MAPI_CC && !shape.optionalAttendees) ||
			       (t == MAPI_BCC && !shape.resourceAttendees);
		}
		if (!keep)
			continue;
		tpropval_array_ptr dup(row.dup());
		if (dup == nullptr ||
		    dup->set(PR_ROWID, &row_id) != ecSuccess ||
		    rcpts->append_move(std::move(dup)) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3456);
		++row_id;
	}
	if (shape.requiredAttendees)
		parseAttendees(shape.requiredAttendees, MAPI_TO);
	if (shape.optionalAttendees)
		parseAttendees(shape.optionalAttendees, MAPI_CC);
	if (shape.resourceAttendees)
		parseAttendees(shape.resourceAttendees, MAPI_BCC);

	if (rcpts->count > 0) {
		if (!exmdb.update_message_instance_rcpts(dir.c_str(),
		    inst->instanceId, rcpts))
			throw EWSError::ItemSave(E3351);
		/* Set organizer properties when attendees are present */
		auto oprops = meetingIdentity(dir);
		/* MS-OXOCAL v22.1 §2.2.1.9/10/11 */
		auto meetType   = construct<uint32_t>(mtgRequest);
		auto apptState  = construct<uint32_t>(asfMeeting);
		auto respStatus = construct<uint32_t>(respOrganized);
		const TPROPVAL_ARRAY oproplist = {static_cast<uint16_t>(oprops.size()), oprops.data()};
		PROBLEM_ARRAY problems;
		if (!exmdb.set_instance_properties(dir.c_str(),
		    inst->instanceId, &oproplist, &problems))
			throw EWSError::ItemSave(E3353);
		const PROPERTY_NAME pnames[] = {
			NtMeetingType,
			NtAppointmentStateFlags,
			NtResponseStatus,
		};
		const PROPNAME_ARRAY pnarr = {std::size(pnames), deconst(pnames)};
		auto ids = getNamedPropIds(dir, pnarr);
		if (ids.size() == 3 && ids[0] && ids[1] && ids[2]) {
			const TAGGED_PROPVAL nprops[] = {
				{PROP_TAG(PT_LONG, ids[0]), meetType},
				{PROP_TAG(PT_LONG, ids[1]), apptState},
				{PROP_TAG(PT_LONG, ids[2]), respStatus},
			};
			const TPROPVAL_ARRAY nproplist = {std::size(nprops), deconst(nprops)};
			if (!exmdb.set_instance_properties(dir.c_str(),
			    inst->instanceId, &nproplist, &problems))
				throw EWSError::ItemSave(E3354);
		}
	}

	ec_error_t err;
	if (!exmdb.flush_instance(dir.c_str(),
	    inst->instanceId, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3355);
}

/**
 * @brief      Update mail recipients on existing message
 *
 * Used by UpdateItem when the client sets ToRecipients, CcRecipients,
 * or BccRecipients. Only recipient types present in the update are
 * replaced, rows of other types are kept.
 *
 * @param      dir     Store directory
 * @param      parent  Parent folder specification
 * @param      mid     Message ID of the mail item
 * @param      shape   Shape containing recipient XML pointers
 */
void EWSContext::updateMessageRecipients(const std::string &dir,
    const sFolderSpec &parent, uint64_t mid, const sShape &shape) const
{
	auto &exmdb = plugin().exmdb;
	auto inst = m_plugin.loadMessageInstance(dir, parent.folderId, mid);
	uint16_t old_count = 0;
	if (!exmdb.get_message_instance_rcpts_num(dir.c_str(),
	    inst->instanceId, &old_count))
		throw EWSError::ItemSave(E3457);
	TARRAY_SET old_rcpts{};
	if (old_count > 0 && !exmdb.get_message_instance_rcpts(dir.c_str(),
	    inst->instanceId, 0, old_count, &old_rcpts))
		throw EWSError::ItemSave(E3458);

	auto rcpts = tarray_set_init();
	if (rcpts == nullptr)
		throw EWSError::NotEnoughMemory(E3460);
	auto cl_rcpts = HX::make_scope_exit([&]() { tarray_set_free(rcpts); });
	uint32_t nextRow = 0;
	for (const auto &old : old_rcpts) {
		auto rowId = old.get<const uint32_t>(PR_ROWID);
		if (rowId == nullptr)
			continue;
		if (*rowId >= nextRow)
			nextRow = *rowId + 1;
		auto rtype = old.get<const uint32_t>(PR_RECIPIENT_TYPE);
		bool replace = rtype != nullptr &&
		               ((*rtype == MAPI_TO && shape.toRecipients != nullptr) ||
		                (*rtype == MAPI_CC && shape.ccRecipients != nullptr) ||
		                (*rtype == MAPI_BCC && shape.bccRecipients != nullptr));
		if (!replace)
			continue;
		/* A row containing only PR_ROWID removes that recipient */
		auto rcpt = rcpts->emplace();
		if (rcpt == nullptr)
			throw EWSError::NotEnoughMemory(E3459);
		if (rcpt->set(PR_ROWID, rowId) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3461);
	}
	auto parseRcpts = [&](const tinyxml2::XMLElement *xml, uint32_t type) {
		if (xml == nullptr)
			return;
		for (auto entry = xml->FirstChildElement("Mailbox");
		     entry != nullptr;
		     entry = entry->NextSiblingElement("Mailbox")) {
			tEmailAddressType addr(entry);
			auto rcpt = rcpts->emplace();
			addr.mkRecipient(rcpt, type);
			/* update_message_instance_rcpts wants PR_ROWID */
			if (rcpt->set(PR_ROWID, &nextRow) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3461);
			++nextRow;
		}
	};
	parseRcpts(shape.toRecipients, MAPI_TO);
	parseRcpts(shape.ccRecipients, MAPI_CC);
	parseRcpts(shape.bccRecipients, MAPI_BCC);

	if (rcpts->count == 0)
		return;
	if (!exmdb.update_message_instance_rcpts(dir.c_str(),
	    inst->instanceId, rcpts))
		throw EWSError::ItemSave(E3462);
	ec_error_t err;
	if (!exmdb.flush_instance(dir.c_str(),
	    inst->instanceId, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3463);
}

static std::optional<int64_t>
lookup_tz_get_offset(const std::string &name, time_t local_start) = delete;

static std::optional<int64_t>
lookup_tz_get_offset(const char *name, time_t local_start)
{
	auto def = lookup_tz_get_tzdef(name);
	if (!def)
		return std::nullopt;
	int64_t off = 0;
	if (tz_to_offset(*def, local_start, off))
		return off;
	return std::nullopt;
}

/*
 * MS-OXOCAL v22.1 §2.2.1.14/§2.2.1.15: the clip bounds of a series are
 * midnight in the local zone on the first/last day, stored as UTC.
 */
static uint64_t clip_time(const std::optional<TZDEF> &tz, uint32_t rtime)
{
	time_t t = rop_util_rtime_to_unix(rtime);
	int64_t off = 0;
	if (rtime != ENDDATE_MISSING && tz && tz_to_offset(*tz, t, off))
		t += off * 60;
	return rop_util_unix_to_nttime(t);
}

/**
 * @brief      Convert EWS Recurrence XML to MAPI properties and write to shape
 *
 * Used by UpdateItem when the client modifies the recurrence of an existing
 * calendar item.  The start/end times needed for blob construction are taken
 * from the shape if they were also updated, otherwise read from the message.
 *
 * @param      dir   Store directory
 * @param      mid   Message ID of the calendar item
 * @param      xml   XML element containing the Recurrence child elements
 * @param      shape Shape to write properties to
 */
void EWSContext::applyRecurrence(const std::string &dir, uint64_t mid,
    const tinyxml2::XMLElement *xml, sShape &shape) const
{
	tRecurrenceType recurrence(xml);

	/* Resolve named property IDs for start/end and all-day flag */
	const PROPERTY_NAME pn_buf[] = {
		{MNID_ID, PSETID_Common, PidLidCommonStart},
		{MNID_ID, PSETID_Common, PidLidCommonEnd},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSubType},
	};
	const PROPNAME_ARRAY propnames = {std::size(pn_buf), deconst(pn_buf)};
	auto namedids    = getNamedPropIds(dir, propnames, false);
	auto start_tag   = PROP_TAG(PT_SYSTIME, namedids[0]);
	auto end_tag     = PROP_TAG(PT_SYSTIME, namedids[1]);
	auto subtype_tag = PROP_TAG(PT_BOOLEAN, namedids[2]);

	/* Get start/end: prefer values from the shape (co-updated), fall back to message */
	time_t localStartTime = 0, localEndTime = 0;
	auto sp = shape.writes(start_tag);
	auto ep = shape.writes(end_tag);
	if (sp) {
		localStartTime = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(sp->pvalue));
	} else {
		auto v = getItemProp<const uint64_t>(dir, mid, start_tag);
		if (v)
			localStartTime = rop_util_nttime_to_unix(*v);
	}
	if (ep) {
		localEndTime = rop_util_nttime_to_unix(*static_cast<const uint64_t *>(ep->pvalue));
	} else {
		auto v = getItemProp<const uint64_t>(dir, mid, end_tag);
		if (v)
			localEndTime = rop_util_nttime_to_unix(*v);
	}
	if (localStartTime == 0 || localEndTime == 0)
		throw EWSError::CalendarInvalidRecurrence(E3265);

	std::optional<TZDEF> item_tz;
	if (auto caltz = shape.writes(NtCalendarTimeZone))
		item_tz = lookup_tz_get_tzdef(static_cast<const char *>(caltz->pvalue));
	if (!item_tz && shape.tag(NtAppointmentTimeZoneDefinitionRecur) != 0) {
		/* An item stored with an unknown zone name has no definition */
		const proptag_t tztag = shape.tag(NtAppointmentTimeZoneDefinitionRecur);
		auto props = getItemProps(dir, mid, {&tztag, 1});
		item_tz = binary_to_tzdef(props.get<const BINARY>(tztag));
	}
	if (item_tz && m_recurrence_frame)
		shift_recurrence(recurrence, *m_recurrence_frame, *item_tz, localStartTime);

	/* Check if this is an all-day event */
	bool isAllDay = false;
	auto st = shape.writes(subtype_tag);
	if (st) {
		isAllDay = *static_cast<const uint8_t *>(st->pvalue) != 0;
	} else {
		auto v = getItemProp<const uint8_t>(dir, mid, subtype_tag);
		if (v)
			isAllDay = *v != 0;
	}

	/*
	 * For all-day events the duration must be a whole number of days.
	 * Round up to the next day boundary if not. Days are counted in
	 * local time, where a DST change day is not 86400s long.
	 */
	auto duration = localEndTime - localStartTime;
	if (isAllDay) {
		int64_t sb = 0, eb = 0;
		if (item_tz && (!tz_to_offset(*item_tz, localStartTime, sb) ||
		    !tz_to_offset(*item_tz, localEndTime, eb)))
			sb = eb = 0;
		duration = localEndTime - eb * 60 - (localStartTime - sb * 60);
		if (duration % 86400 != 0) {
			duration = (duration + 86399) / 86400 * 86400;
			auto le = localStartTime - sb * 60 + duration;
			if (item_tz && !tz_to_offset(*item_tz, le, eb))
				eb = sb;
			localEndTime = le + eb * 60;
			auto corrected_end = construct<uint64_t>(rop_util_unix_to_nttime(localEndTime));
			shape.write(TAGGED_PROPVAL{end_tag, corrected_end});
		}
	}
	/*
	 * Use RecurrenceRange StartDate for the recurrence start date. For
	 * all-day events, the Start time is midnight local in UTC (e.g. 23:00Z
	 * for CET), but StartDate is the correct date.
	 */
	auto &rr = recurrence.RecurrenceRange;
	auto rangeStart = clock::to_time_t(std::visit([](const auto &r) STATIC_IN_CXX23 { return r.StartDate; }, rr));
	struct tm startdate_tm{};
	if (gmtime_r(&rangeStart, &startdate_tm) == nullptr)
		throw EWSError::CalendarInvalidRecurrence(E3356);

	APPOINTMENT_RECUR_PAT apr{};

	if (isAllDay) {
		apr.starttimeoffset = 0;
		apr.endtimeoffset = duration / 60;
	} else {
		/* localStartTime is real UTC from NTTIME.  Convert to
		 * the appointment's local timezone for the blob. */
		time_t appt_local = localStartTime;
		int64_t b;
		if (item_tz && tz_to_offset(*item_tz, localStartTime, b))
			appt_local = localStartTime - static_cast<time_t>(b) * 60;
		struct tm start_tm{};
		gmtime_r(&appt_local, &start_tm);
		apr.starttimeoffset = 60 * start_tm.tm_hour + start_tm.tm_min;
		apr.endtimeoffset = apr.starttimeoffset + duration / 60;
	}
	startdate_tm.tm_hour = 0;
	startdate_tm.tm_min = 0;
	startdate_tm.tm_sec = 0;
	time_t startdate = timegm(&startdate_tm);
	apr.recur_pat.startdate = rop_util_unix_to_rtime(startdate);
	uint8_t rectype = rectypeNone;
	auto &rp = recurrence.RecurrencePattern;

	if (std::holds_alternative<tDailyRecurrencePattern>(rp)) {
		auto interval = std::get<tDailyRecurrencePattern>(rp).Interval;
		if (interval < 1 || interval > 999)
			throw EWSError::CalendarInvalidRecurrence(E3266);
		apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_DAILY;
		apr.recur_pat.patterntype = rptMinute;
		apr.recur_pat.period = interval * 1440;
		rectype = rectypeDaily;
	} else if (std::holds_alternative<tWeeklyRecurrencePattern>(rp)) {
		auto interval = std::get<tWeeklyRecurrencePattern>(rp).Interval;
		if (interval < 1 || interval > 99)
			throw EWSError::CalendarInvalidRecurrence(E3267);
		auto firstdow = 1;
		if (std::get<tWeeklyRecurrencePattern>(rp).FirstDayOfWeek)
			firstdow = std::get<tWeeklyRecurrencePattern>(rp).FirstDayOfWeek->index();
		if (firstdow > 6)
			throw EWSError::CalendarInvalidRecurrence(E3268);
		const auto &daysOfWeek = std::get<tWeeklyRecurrencePattern>(rp).DaysOfWeek;
		apr.recur_pat.pts.weekrecur = 0;
		daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.weekrecur);
		if (apr.recur_pat.pts.weekrecur == 0)
			throw EWSError::CalendarInvalidRecurrence(E3269);
		apr.recur_pat.recurfrequency = apr.recur_pat.pts.weekrecur != 0x3E ?
			IDC_RCEV_PAT_ORB_WEEKLY : IDC_RCEV_PAT_ORB_DAILY;
		apr.recur_pat.patterntype = rptWeek;
		apr.recur_pat.period = interval;
		apr.recur_pat.firstdow = firstdow;
		rectype = rectypeWeekly;
	} else if (std::holds_alternative<tRelativeMonthlyRecurrencePattern>(rp)) {
		auto interval = std::get<tRelativeMonthlyRecurrencePattern>(rp).Interval;
		if (interval < 1 || interval > 99)
			throw EWSError::CalendarInvalidRecurrence(E3270);
		const auto &daysOfWeek = std::get<tRelativeMonthlyRecurrencePattern>(rp).DaysOfWeek;
		apr.recur_pat.pts.monthnth.weekrecur = 0;
		daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.monthnth.weekrecur);
		if (apr.recur_pat.pts.monthnth.weekrecur == 0)
			throw EWSError::CalendarInvalidRecurrence(E3271);
		auto dayOfWeekIndex = std::get<tRelativeMonthlyRecurrencePattern>(rp).DayOfWeekIndex.index();
		if (dayOfWeekIndex > 4)
			throw EWSError::CalendarInvalidRecurrence(E3272);
		apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
		apr.recur_pat.patterntype = rptMonthNth;
		apr.recur_pat.period = interval;
		apr.recur_pat.pts.monthnth.recurnum = static_cast<uint8_t>(dayOfWeekIndex) + 1;
		rectype = rectypeMonthly;
	} else if (std::holds_alternative<tAbsoluteMonthlyRecurrencePattern>(rp)) {
		auto interval = std::get<tAbsoluteMonthlyRecurrencePattern>(rp).Interval;
		if (interval < 1 || interval > 99)
			throw EWSError::CalendarInvalidRecurrence(E3273);
		apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
		apr.recur_pat.patterntype = rptMonth;
		apr.recur_pat.period = interval;
		apr.recur_pat.pts.dayofmonth = std::get<tAbsoluteMonthlyRecurrencePattern>(rp).DayOfMonth;
		if (apr.recur_pat.pts.dayofmonth < 1 || apr.recur_pat.pts.dayofmonth > 31)
			throw EWSError::CalendarInvalidRecurrence(E3274);
		rectype = rectypeMonthly;
	} else if (std::holds_alternative<tRelativeYearlyRecurrencePattern>(rp)) {
		const auto &daysOfWeek = std::get<tRelativeYearlyRecurrencePattern>(rp).DaysOfWeek;
		apr.recur_pat.pts.monthnth.weekrecur = 0;
		daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.monthnth.weekrecur);
		if (apr.recur_pat.pts.monthnth.weekrecur == 0)
			throw EWSError::CalendarInvalidRecurrence(E3275);
		auto dayOfWeekIndex = std::get<tRelativeYearlyRecurrencePattern>(rp).DayOfWeekIndex.index();
		auto month = std::get<tRelativeYearlyRecurrencePattern>(rp).Month.index();
		apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
		apr.recur_pat.patterntype = rptMonthNth;
		apr.recur_pat.period = 12;
		apr.recur_pat.pts.monthnth.recurnum = static_cast<uint8_t>(dayOfWeekIndex) + 1;
		rectype = rectypeYearly;
		startdate_tm.tm_mon = month;
	} else if (std::holds_alternative<tAbsoluteYearlyRecurrencePattern>(rp)) {
		auto month = std::get<tAbsoluteYearlyRecurrencePattern>(rp).Month.index();
		apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
		apr.recur_pat.patterntype = rptMonth;
		apr.recur_pat.period = 12;
		apr.recur_pat.pts.dayofmonth = std::get<tAbsoluteYearlyRecurrencePattern>(rp).DayOfMonth;
		if (apr.recur_pat.pts.dayofmonth < 1 || apr.recur_pat.pts.dayofmonth > 31)
			throw EWSError::CalendarInvalidRecurrence(E3279);
		rectype = rectypeYearly;
		startdate_tm.tm_mon = month;
	} else {
		throw EWSError::CalendarInvalidRecurrence(E3280);
	}

	calc_firstdatetime(apr.recur_pat, &startdate_tm);
	if (std::holds_alternative<tNoEndRecurrenceRange>(rr)) {
		apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_NOEND;
		apr.recur_pat.occurrencecount = 0xA;
		apr.recur_pat.enddate = ENDDATE_MISSING;
	} else if (std::holds_alternative<tEndDateRecurrenceRange>(rr)) {
		apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_END;
		apr.recur_pat.occurrencecount = 0xA;
		auto ed = std::get<tEndDateRecurrenceRange>(rr).EndDate;
		auto enddate = clock::to_time_t(ed);
		apr.recur_pat.enddate = rop_util_unix_to_rtime(enddate);
	} else if (std::holds_alternative<tNumberedRecurrenceRange>(rr)) {
		apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_AFTERNOCCUR;
		apr.recur_pat.occurrencecount = std::get<tNumberedRecurrenceRange>(rr).NumberOfOccurrences;
		calc_enddate(apr.recur_pat, &startdate_tm);
	} else {
		throw EWSError::CalendarInvalidRecurrence(E3281);
	}

	BINARY tmp_bin;
	EXT_PUSH ext_push;
	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_apptrecpat(apr) != pack_result::ok)
		throw DispatchError(E3120);
	tmp_bin.cb = ext_push.m_offset;
	tmp_bin.pb = ext_push.m_udata;

	auto recurdata = alloc<char>(tmp_bin.cb);
	memcpy(recurdata, tmp_bin.pc, tmp_bin.cb);

	shape.write(NtRecurrenceType, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(rectype)});
	shape.write(NtAppointmentRecur, TAGGED_PROPVAL{PT_BINARY, construct<BINARY>(BINARY{tmp_bin.cb, {recurdata}})});
	shape.write(NtRecurring, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(1)});
	auto clipstart = construct<uint64_t>(clip_time(item_tz, apr.recur_pat.startdate));
	shape.write(NtClipStart, TAGGED_PROPVAL{PT_SYSTIME, clipstart});
	auto clipend = construct<uint64_t>(clip_time(item_tz, apr.recur_pat.enddate));
	shape.write(NtClipEnd, TAGGED_PROPVAL{PT_SYSTIME, clipend});
}

/**
 * @brief      Anchor a recurrence pattern on a new start date
 *
 * The pattern is kept if the date is one of its days. Otherwise a single
 * weekday, day of month or nth weekday is moved to the date, and a set
 * of weekdays is rotated by the same number of days as the start.
 *
 * @param      rp    Pattern to change
 * @param      date  Midnight of the new start date, local time as UTC
 * @param      days  Number of days the start was moved by
 *
 * @return     false if the pattern cannot be moved
 */
static bool move_pattern(RECURRENCE_PATTERN &rp, time_t date, int days)
{
	switch (rp.calendartype) {
	case CAL_DEFAULT:
	case CAL_GREGORIAN:
	case CAL_GREGORIAN_US:
	case CAL_GREGORIAN_ME_FRENCH:
	case CAL_GREGORIAN_ARABIC:
	case CAL_GREGORIAN_XLIT_ENGLISH:
	case CAL_GREGORIAN_XLIT_FRENCH:
		break;
	default:
		return false;
	}
	struct tm tm;
	if (rp.slidingflag != 0 || rp.period == 0 ||
	    gmtime_r(&date, &tm) == nullptr)
		return false;
	int year = tm.tm_year + 1900, month = tm.tm_mon + 1, mday = tm.tm_mday;
	int mdays = ical_get_monthdays(year, month);
	uint32_t wbit = 1U << tm.tm_wday;
	switch (rp.patterntype) {
	case rptMinute:
		break;
	case rptWeek: {
		auto &w = rp.pts.weekrecur;
		w &= 0x7f;
		if (w & wbit)
			break;
		if (std::popcount(w) == 1) {
			w = wbit;
		} else {
			int r = (days % 7 + 7) % 7;
			w = ((w << r) | (w >> (7 - r))) & 0x7f;
		}
		if (!(w & wbit))
			return false;
		if (rp.recurfrequency == IDC_RCEV_PAT_ORB_DAILY ||
		    rp.recurfrequency == IDC_RCEV_PAT_ORB_WEEKLY)
			rp.recurfrequency = w == 0x3E ? IDC_RCEV_PAT_ORB_DAILY :
			                    IDC_RCEV_PAT_ORB_WEEKLY;
		break;
	}
	case rptMonth:
		if (std::min<int>(rp.pts.dayofmonth, mdays) != mday)
			rp.pts.dayofmonth = mday;
		break;
	case rptMonthEnd:
		if (mday != mdays) {
			rp.patterntype = rptMonth;
			rp.pts.dayofmonth = mday;
		}
		break;
	case rptMonthNth: {
		auto &mn = rp.pts.monthnth;
		if (mn.recurnum >= 1 && mn.recurnum <= 5 &&
		    nth_matching_mday(year, month, mn.recurnum, mn.weekrecur) == mday)
			break;
		if (std::popcount(mn.weekrecur & 0x7f) != 1)
			return false;
		unsigned int nth = (mday - 1) / 7 + 1;
		if (nth == 5 || (mn.recurnum == 5 && mday + 7 > mdays))
			nth = 5;
		mn.weekrecur = wbit;
		mn.recurnum = nth;
		break;
	}
	default:
		return false;
	}
	rp.startdate = rop_util_unix_to_rtime(date);
	if (rp.endtype == IDC_RCEV_PAT_ERB_END) {
		rp.enddate += days * 1440;
		if (rp.enddate < rp.startdate)
			return false;
	}
	calc_firstdatetime(rp, &tm);
	return true;
}

/**
 * @brief      Keep a series in line with its start and end
 *
 * macOS Calendar moves a series by sending a new Start and End without
 * the Recurrence. Series with exceptions are left alone.
 *
 * @param      dir    Store directory
 * @param      mid    Message ID of the series
 * @param      shape  Shape of the update
 */
void EWSContext::moveRecurrence(const std::string &dir, uint64_t mid,
    sShape &shape) const
{
	auto sp = shape.writes(NtCommonStart);
	auto ep = shape.writes(NtCommonEnd);
	if (sp == nullptr && ep == nullptr)
		return;
	const PROPERTY_NAME pn[] = {
		{MNID_ID, PSETID_Appointment, PidLidAppointmentRecur},
		{MNID_ID, PSETID_Appointment, PidLidRecurring},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentTimeZoneDefinitionRecur},
		{MNID_ID, PSETID_Appointment, PidLidAppointmentSubType},
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna);
	/* the Recurrence is being deleted */
	for (auto t : shape.remove_vec())
		if (PROP_ID(t) == ids[0] || PROP_ID(t) == ids[1])
			return;
	const proptag_t tags[] = {PROP_TAG(PT_BINARY, ids[0]),
		PROP_TAG(PT_BOOLEAN, ids[1]), PROP_TAG(PT_BINARY, ids[2]),
		PROP_TAG(PT_BOOLEAN, ids[3]), PR_START_DATE, PR_END_DATE};
	auto props = getItemProps(dir, mid, tags);
	auto bin = props.get<const BINARY>(tags[0]);
	auto recurring = props.get<const uint8_t>(tags[1]);
	auto ostart = props.get<const uint64_t>(PR_START_DATE);
	auto oend = props.get<const uint64_t>(PR_END_DATE);
	if (bin == nullptr || (recurring != nullptr && *recurring == 0) ||
	    ostart == nullptr || oend == nullptr)
		return;
	EXT_PULL ext_pull;
	ext_pull.init(bin->pb, bin->cb, nullptr, EXT_FLAG_UTF16);
	APPOINTMENT_RECUR_PAT apr{};
	if (ext_pull.g_apptrecpat(&apr) != pack_result::ok ||
	    !apr.recur_pat.pdeletedinstancedates.empty() ||
	    !apr.recur_pat.pmodifiedinstancedates.empty() ||
	    !apr.pexceptioninfo.empty())
		return;
	std::optional<TZDEF> tz;
	if (auto t = shape.writes(NtAppointmentTimeZoneDefinitionRecur))
		tz = binary_to_tzdef(static_cast<const BINARY *>(t->pvalue));
	if (!tz)
		tz = binary_to_tzdef(props.get<const BINARY>(tags[2]));
	/* a series moved without its pattern has a bogus offset */
	int64_t fallback = recurTzOffset(dir, mid, apr);
	if (fallback < -840 || fallback > 840)
		fallback = 0;
	auto local = [&](time_t t) {
		int64_t b;
		if (!tz || !tz_to_offset(*tz, t, b))
			b = fallback;
		return t - b * 60;
	};
	auto allday = shape.writes(tags[3]);
	auto alldayv = allday != nullptr ? static_cast<const uint8_t *>(allday->pvalue) :
	               props.get<const uint8_t>(tags[3]);
	bool isAllDay = alldayv != nullptr && *alldayv != 0;
	auto nt = [](const TAGGED_PROPVAL *p, const uint64_t *o) {
		return rop_util_nttime_to_unix(p != nullptr ?
		       *static_cast<const uint64_t *>(p->pvalue) : *o);
	};
	time_t os = local(rop_util_nttime_to_unix(*ostart));
	time_t ns = local(nt(sp, ostart)), ne = local(nt(ep, oend));
	if (isAllDay) {
		/* tolerate an offset that is off by the DST bias */
		os = unix_day(os + 43200) * 86400;
		ns = unix_day(ns + 43200) * 86400;
		ne = unix_day(ne + 43200) * 86400;
	}
	if (ne < ns)
		return;
	int days = unix_day(ns) - unix_day(os);
	uint32_t st = (ns - unix_day(ns) * 86400) / 60;
	uint32_t et = st + (ne - ns) / 60;
	if (days == 0 && st == apr.starttimeoffset && et == apr.endtimeoffset)
		return;
	if (days != 0 &&
	    !move_pattern(apr.recur_pat, unix_day(ns) * 86400, days))
		return;
	if (days != 0 && apr.recur_pat.endtype == IDC_RCEV_PAT_ERB_AFTERNOCCUR) try {
		apr.recur_pat.enddate = nthOccurrenceDate(apr,
		                        apr.recur_pat.occurrencecount, true);
	} catch (const InputError &) {
		return;
	}
	apr.starttimeoffset = st;
	apr.endtimeoffset = et;
	EXT_PUSH ext_push;
	if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ext_push.p_apptrecpat(apr) != pack_result::ok)
		throw DispatchError(E3120);
	auto recurdata = alloc<char>(ext_push.m_offset);
	memcpy(recurdata, ext_push.m_udata, ext_push.m_offset);
	shape.write(NtAppointmentRecur, TAGGED_PROPVAL{PT_BINARY,
		construct<BINARY>(BINARY{ext_push.m_offset, {recurdata}})});
	const auto &rp = apr.recur_pat;
	shape.write(NtClipStart, TAGGED_PROPVAL{PT_SYSTIME,
		construct<uint64_t>(clip_time(tz, rp.startdate))});
	auto clipend = rp.endtype == IDC_RCEV_PAT_ERB_NOEND ||
	               rp.endtype == IDC_RCEV_PAT_ERB_NOEND1 ?
	               ENDDATE_MISSING : rp.enddate;
	shape.write(NtClipEnd, TAGGED_PROPVAL{PT_SYSTIME,
		construct<uint64_t>(clip_time(tz, clipend))});
}

/**
 * @brief      Generate initial predecessor change list from xid
 *
 * @param      xid  Initial change key
 *
 * @return     Serialized predecessor change list buffer
 */
binary_ptr EWSContext::mkPCL(const XID& xid, PCL pcl) const
{
	if (!pcl.append(xid))
		throw DispatchError(E3121);
	binary_ptr pcltemp(pcl.serialize());
	if (!pcltemp)
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
	static constexpr proptag_t tagIds[] = {PidTagParentFolderId, PR_DISPLAY_NAME};
	TPROPVAL_ARRAY props;
	if (!m_plugin.exmdb.get_folder_properties(dir.c_str(), CP_ACP,
	    folder.folderId, proptag_cspan{tagIds}, &props))
		throw DispatchError(E3159);
	uint64_t* parentFid = props.get<uint64_t>(PidTagParentFolderId);
	auto folderName = props.get<const char>(PR_DISPLAY_NAME);
	if (!parentFid || !folderName)
		throw DispatchError(E3160);
	sFolderSpec parentFolder = folder;
	parentFolder.folderId = *parentFid;
	if (!(permissions(dir, folder.folderId) & frightsDeleteAny) ||
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
	if (!copy)
		/* movecopy_folder bumps the moved folder's change number itself. */
		return folder.folderId;
	uint64_t newFolderId;
	if (!m_plugin.exmdb.get_folder_by_name(dir.c_str(), newParent, folderName, &newFolderId))
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
	if (!exmdb.allocate_message_id(dir.c_str(), newParent, &newId))
		throw DispatchError(E3182);
	BOOL success;
	if (!m_plugin.exmdb.movecopy_message(dir.c_str(), CP_ACP,
	    meid.messageId(), newParent, newId, copy ? false : TRUE,
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
	if (!Mailbox.EmailAddress)
		return;
	if (!Mailbox.RoutingType)
		Mailbox.RoutingType = "smtp";
	tolower_inplace(*Mailbox.RoutingType);
	if (Mailbox.RoutingType == "smtp")
		return;
	if (Mailbox.RoutingType != "ex")
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
	if (!Mailbox.RoutingType)
		Mailbox.RoutingType = "smtp";
	tolower_inplace(*Mailbox.RoutingType);
	if (Mailbox.RoutingType == "smtp")
		return;
	if (Mailbox.RoutingType != "ex")
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
	if (maildir == m_auth_info.maildir)
		return 0xFFFFFFFF;
	uint32_t permissions = 0;
	if (m_plugin.exmdb.get_mbox_perm(maildir.c_str(),
	    m_auth_info.username, &permissions) &&
	    (permissions & frightsGromoxStoreOwner))
		return 0xFFFFFFFF;
	if (!m_plugin.exmdb.get_folder_perm(maildir.c_str(), folderId,
	    m_auth_info.username, &permissions))
		return 0;
	return permissions;
}

/**
 * @brief      Returns whether the user sees the private items of a folder
 *
 * Only users with access to the whole store and delegates allowed to see
 * private items see them in full, others only get their times and busy
 * status.
 *
 * @param      dir     Store of the folder
 * @param      folder  Folder of the items
 * @param      rights  Rights of the user on the folder
 */
bool EWSContext::seesPrivateItems(const std::string &dir,
    const sFolderSpec &folder, uint32_t rights) const
{
	if (folder.location != sFolderSpec::PRIVATE ||
	    rights & frightsGromoxStoreOwner)
		return true;
	auto it = m_seesPrivateItems.find(dir);
	if (it == m_seesPrivateItems.end())
		it = m_seesPrivateItems.emplace(dir, sees_private_items(dir.c_str(),
		     m_plugin.x500_org_name.c_str(), m_auth_info.username)).first;
	return it->second;
}

/**
 * @brief      Refuse access to a private item the user does not see
 *
 * @param      dir     Store of the item
 * @param      folder  Folder of the item
 * @param      rights  Rights of the user on the folder
 * @param      mid     Message ID of the item
 */
void EWSContext::assertCanReadPrivate(const std::string &dir,
    const sFolderSpec &folder, uint32_t rights, uint64_t mid) const
{
	if (seesPrivateItems(dir, folder, rights))
		return;
	static constexpr proptag_t tags[] = {PR_SENSITIVITY};
	auto sens = getItemProps(dir, mid, tags).get<const uint32_t>(PR_SENSITIVITY);
	if (sens != nullptr && *sens == SENSITIVITY_PRIVATE)
		throw EWSError::AccessDenied(E3501);
}

/**
 * @brief      Limit a shape to what the reader may see in a folder
 *
 * @param      dir     Store of the folder
 * @param      folder  Folder to read from
 * @param      rights  Rights of the reader on the folder
 * @param      shape   Shape to restrict
 */
void EWSContext::restrictShape(const std::string &dir, const sFolderSpec &folder,
    uint32_t rights, sShape &shape) const
{
	shape.restrict(rights, rights & frightsGromoxStoreOwner ? PROPID_ARRAY{} :
		getNamedPropIds(dir, sShape::fbNames),
		seesPrivateItems(dir, folder, rights));
}

/**
 * @brief      Verify the caller may claim a given identity as sender
 *
 * @param      identity   SMTP address the message claims to be sent from
 *
 * @throw      EWSError::SendAsDenied   Caller lacks Send-As rights on
 *              the claimed identity
 */
void EWSContext::validate_sendas_perms(const std::string &identity) const
{
	if (identity.empty() ||
	    strcasecmp(identity.c_str(), m_auth_info.username) == 0)
		return; /* claiming to be yourself never needs a grant */
	std::string maildir;
	try {
		maildir = get_maildir(identity);
	} catch (...) {
		/* Unresolvable (external/nonexistent) address is never a valid Send-As target */
		throw EWSError::SendAsDenied(E3474);
	}
	if (maildir == m_auth_info.maildir)
		return; /* alias of the caller's own mailbox */
	uint32_t permission = 0;
	if (!m_plugin.exmdb.get_mbox_perm(maildir.c_str(),
	    m_auth_info.username, &permission))
		throw EWSError::AccessDenied(E3474);
	if (permission & (frightsGromoxSendAs | frightsGromoxStoreOwner))
		return;
	/* get_mbox_perm only knows the Send-On-Behalf list */
	if (!onSendAsList(maildir))
		throw EWSError::SendAsDenied(E3474);
}

/**
 * @brief      Verify the caller may send a message with its sender identity
 *
 * @param      content   Message about to be submitted
 */
void EWSContext::validate_sendas_perms(const MESSAGE_CONTENT &content) const
{
	auto &pl = content.proplist;
	auto addr = pl.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (addr == nullptr) {
		auto type = pl.get<const char>(PR_SENT_REPRESENTING_ADDRTYPE);
		auto email = pl.get<const char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
		if (email == nullptr)
			return;
		if (type != nullptr && strcasecmp(type, "EX") == 0) {
			validate_sendas_perms(essdn_to_username(email));
			return;
		}
		addr = email;
	}
	validate_sendas_perms(addr);
}

/**
 * @brief      Sender identity of mail the caller is about to submit
 *
 * Without From, the caller sends in its own name. The caller is also
 * the Sender, unless it holds Send-As rights on From, or owns the store
 * of From and submits from that store.
 *
 * @param      dir     Home directory of the store submitting the mail
 * @param      props   Message properties
 * @param      drop    Receives stale tags of a replaced identity
 *
 * @return     Properties to set
 */
std::vector<TAGGED_PROPVAL> EWSContext::submitIdentity(const std::string &dir,
    const TPROPVAL_ARRAY &props, std::vector<proptag_t> &drop) const
{
	auto user = m_auth_info.username;
	auto smtpOf = [&](proptag_t smtpTag, proptag_t typeTag,
	              proptag_t addrTag) -> std::string {
		auto smtp = props.get<const char>(smtpTag);
		if (smtp != nullptr && *smtp != '\0')
			return smtp;
		auto addr = props.get<const char>(addrTag);
		if (addr == nullptr || *addr == '\0')
			return {};
		auto type = props.get<const char>(typeTag);
		if (type == nullptr || strcasecmp(type, "SMTP") == 0)
			return addr;
		if (strcasecmp(type, "EX") == 0) try {
			return essdn_to_username(addr);
		} catch (const DispatchError &) {
		}
		return {};
	};
	auto sendAs = [&](const std::string &repr) {
		std::string maildir;
		try {
			maildir = get_maildir(repr);
		} catch (const EWSError &) {
			return false;
		}
		if (maildir == m_auth_info.maildir)
			return true;
		/* Store owners act as the mailbox only in its own store */
		uint32_t perm = 0;
		if (maildir == dir &&
		    m_plugin.exmdb.get_mbox_perm(maildir.c_str(), user, &perm) &&
		    (perm & frightsGromoxStoreOwner))
			return true;
		std::vector<std::string> list;
		if (!m_plugin.exmdb.read_delegates(maildir.c_str(), 1, &list))
			return false;
		for (const auto &d : list)
			if (strcasecmp(d.c_str(), user) == 0 ||
			    mysql_adaptor_check_mlist_include(d.c_str(), user))
				return true;
		return false;
	};
	auto copyStr = [](const std::string &str) {
		return strcpy(alloc<char>(str.size() + 1), str.c_str());
	};
	auto dispName = [&](const std::string &who) -> char * {
		std::string name;
		if (!mysql_adaptor_get_user_displayname(who.c_str(), name) ||
		    name.empty())
			return nullptr;
		return copyStr(name);
	};
	std::vector<TAGGED_PROPVAL> out;
	auto stamp = [&](const std::string &who, proptag_t nameTag,
	             proptag_t typeTag, proptag_t addrTag, proptag_t smtpTag,
	             proptag_t eidTag, proptag_t skeyTag) {
		auto addr = copyStr(who);
		auto name = dispName(who);
		out.push_back({nameTag, name != nullptr ? name : addr});
		out.push_back({typeTag, deconst("SMTP")});
		out.push_back({addrTag, addr});
		out.push_back({smtpTag, addr});
		drop.push_back(eidTag);
		drop.push_back(skeyTag);
	};
	auto repr = smtpOf(PR_SENT_REPRESENTING_SMTP_ADDRESS,
	            PR_SENT_REPRESENTING_ADDRTYPE,
	            PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (repr.empty() && !props.has(PR_SENT_REPRESENTING_ENTRYID)) {
		repr = user;
		stamp(repr, PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ADDRTYPE,
		      PR_SENT_REPRESENTING_EMAIL_ADDRESS,
		      PR_SENT_REPRESENTING_SMTP_ADDRESS,
		      PR_SENT_REPRESENTING_ENTRYID, PR_SENT_REPRESENTING_SEARCH_KEY);
	} else if (!repr.empty() && !props.has(PR_SENT_REPRESENTING_NAME)) {
		auto name = dispName(repr);
		if (name != nullptr)
			out.push_back({PR_SENT_REPRESENTING_NAME, name});
	}
	std::string sender = user;
	if (!repr.empty() && strcasecmp(repr.c_str(), user) != 0 && sendAs(repr))
		sender = repr;
	auto cur = smtpOf(PR_SENDER_SMTP_ADDRESS, PR_SENDER_ADDRTYPE,
	           PR_SENDER_EMAIL_ADDRESS);
	if (strcasecmp(cur.c_str(), sender.c_str()) != 0)
		stamp(sender, PR_SENDER_NAME, PR_SENDER_ADDRTYPE,
		      PR_SENDER_EMAIL_ADDRESS, PR_SENDER_SMTP_ADDRESS,
		      PR_SENDER_ENTRYID, PR_SENDER_SEARCH_KEY);
	return out;
}

/**
 * @brief      Complete the sender identity of mail about to be submitted
 *
 * @param      dir       Home directory of the store submitting the mail
 * @param      content   Message to submit
 */
void EWSContext::stampSubmitIdentity(const std::string &dir,
    MESSAGE_CONTENT &content) const
{
	std::vector<proptag_t> drop;
	for (const auto &prop : submitIdentity(dir, content.proplist, drop))
		if (content.proplist.set(prop) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3530);
	for (auto tag : drop)
		content.proplist.erase(tag);
}

/**
 * @brief      Read delegate permissions from folder ACLs
 */
tDelegatePermissions EWSContext::readDelegatePermissions(const std::string &dir, const std::string &username) const
{
	tDelegatePermissions dp;
	for (const auto &m : delegFolderMap) {
		uint32_t rights = 0;
		if (!m_plugin.exmdb.get_folder_perm(dir.c_str(),
		    eid_t(1, m.fid), username.c_str(), &rights))
			continue; /* ignore error */
		dp.*(m.field) = rights_to_deleg_level(rights);
	}
	return dp;
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
	if (!folder.target)
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
	folderSpec.folderId = eid.folderId();
	if (eid.isPrivate()) {
		std::string ubuf;
		if (mysql_adaptor_userid_to_name(eid.accountId(), ubuf) != ecSuccess)
			throw EWSError::CannotFindUser(E3026);
		folderSpec.target = std::move(ubuf);
	} else {
		sql_domain domaininfo;
		if (!mysql_adaptor_get_domain_info(eid.accountId(), domaininfo))
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
{
	return std::visit([this](const auto &f) { return resolveFolder(f); }, fId);
}

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
	folderSpec.folderId = eid.folderId();
	if (eid.isPrivate()) {
		std::string ubuf;
		if (mysql_adaptor_userid_to_name(eid.accountId(), ubuf) != ecSuccess)
			throw EWSError::CannotFindUser(E3075);
		folderSpec.target = std::move(ubuf);
	} else {
		sql_domain domaininfo;
		if (!mysql_adaptor_get_domain_info(eid.accountId(), domaininfo))
			throw EWSError::CannotFindUser(E3076);
		folderSpec.target = domaininfo.name;
	}
	return folderSpec;
}

/**
 * @brief      Find a contact photo by email address in the given store's
 *             default Contacts folder
 *
 * @param      dir    Home directory of the mailbox whose Contacts folder to search
 * @param      email  Email address to match against Email1/2/3
 *
 * @return     Pointer to the photo's binary data, or nullptr if no matching
 *             contact (or no photo on it) was found
 *
 * @note       Only searches the default Contacts folder, not any user-created
 *             subfolders under it.
 */
const BINARY *EWSContext::findContactPhoto(const std::string &dir,
    const std::string &email) const
{
	std::array<PROPERTY_NAME, 3> names = {NtEmailAddress1, NtEmailAddress2, NtEmailAddress3};
	PROPNAME_ARRAY propNames = {static_cast<uint16_t>(names.size()), names.data()};
	PROPID_ARRAY propIds = getNamedPropIds(dir, propNames);
	if (propIds.size() != names.size())
		return nullptr;

	std::array<RESTRICTION_PROPERTY, 3> propertyRestrictions{};
	std::array<RESTRICTION, 3> childRestrictions{};
	TAGGED_PROPVAL matchValue{0, deconst(email.c_str())};
	for (size_t i = 0; i < names.size(); ++i) {
		auto tag = PROP_TAG(PT_UNICODE, propIds[i]);
		propertyRestrictions[i].relop = RELOP_EQ;
		propertyRestrictions[i].proptag = tag;
		propertyRestrictions[i].propval.proptag = tag;
		propertyRestrictions[i].propval.pvalue = matchValue.pvalue;
		childRestrictions[i].rt = RES_PROPERTY;
		childRestrictions[i].prop = &propertyRestrictions[i];
	}
	RESTRICTION_AND_OR orGroup = {static_cast<uint32_t>(childRestrictions.size()), childRestrictions.data()};
	RESTRICTION restriction = {RES_OR, {&orGroup}};

	uint32_t tableId = 0, rowCount = 0;
	eid_t contactsFid(1, PRIVATE_FID_CONTACTS);
	if (!m_plugin.exmdb.load_content_table(dir.c_str(), CP_ACP, contactsFid,
	    nullptr, TABLE_FLAG_NONOTIFICATIONS, &restriction, nullptr, &tableId, &rowCount) ||
	    rowCount == 0)
		return nullptr;
	auto cl_tbl = HX::make_scope_exit([&]() {
		m_plugin.exmdb.unload_table(dir.c_str(), tableId);
	});

	static constexpr proptag_t midTag = PidTagMid;
	TARRAY_SET rows{};
	if (!m_plugin.exmdb.query_table(dir.c_str(), nullptr, CP_ACP, tableId,
	    {&midTag, 1}, 0, 1, &rows) || rows.count == 0 || rows.pparray[0] == nullptr)
		return nullptr;
	auto mid = rows.pparray[0]->get<const eid_t>(PidTagMid);
	if (mid == nullptr)
		return nullptr;

	MESSAGE_CONTENT *content = nullptr;
	if (!m_plugin.exmdb.read_message(dir.c_str(), nullptr, CP_ACP, *mid, &content) ||
	    content == nullptr || content->children.pattachments == nullptr)
		return nullptr;
	for (const auto &att : *content->children.pattachments) {
		auto isPhoto = att.proplist.get<const uint8_t>(PR_ATTACHMENT_CONTACTPHOTO);
		if (isPhoto != nullptr && *isPhoto)
			return att.proplist.get<const BINARY>(PR_ATTACH_DATA_BIN);
	}
	return nullptr;
}

/**
 * @brief      Check whether a message has a recipient with an address
 *
 * Clients leave attendee rows without any address behind. A meeting
 * message whose recipients are all like that has nobody to go to, and
 * submitting it would produce an <invalid@invalid> envelope recipient.
 * Where such rows sit next to real attendees, send() leaves them out of
 * the envelope.
 */
bool EWSContext::has_rcpt_address(const MESSAGE_CONTENT &content)
{
	if (content.children.prcpts == nullptr)
		return false;
	for (const auto &rcpt : *content.children.prcpts) {
		auto a = rcpt.get<const char>(PR_SMTP_ADDRESS);
		if (a != nullptr && *a != '\0')
			return true;
		a = rcpt.get<const char>(PR_EMAIL_ADDRESS);
		if (a != nullptr && *a != '\0')
			return true;
	}
	return false;
}

/**
 * @brief     Send message
 *
 * The submit identity is completed on the outgoing copy only, callers
 * that keep a copy stamp it themselves.
 *
 * @param     dir      Home directory the message is associtated with
 * @param     msg      Message content
 */
void EWSContext::send(const std::string &dir, uint64_t log_msg_id,
    const MESSAGE_CONTENT &msg) const
{
	if (msg.children.prcpts == nullptr ||
	    msg.children.prcpts->count == 0)
		throw EWSError::MissingRecipients(E3115);
	std::vector<proptag_t> drop;
	auto ident = submitIdentity(dir, msg.proplist, drop);
	for (const auto &prop : ident)
		drop.push_back(prop.proptag);
	std::vector<TAGGED_PROPVAL> props;
	props.reserve(msg.proplist.count + ident.size());
	for (const auto &prop : msg.proplist)
		if (std::find(drop.begin(), drop.end(), prop.proptag) == drop.end())
			props.push_back(prop);
	props.insert(props.end(), ident.begin(), ident.end());
	auto content = msg;
	content.proplist = {static_cast<uint16_t>(props.size()), props.data()};
	std::string log_id;
	auto mail = vmime::make_shared<vmime::message>();
	oxcmail_converter cvt;
	cvt.get_propids = [&](const PROPNAME_ARRAY *names, PROPID_ARRAY *ids) {
	                  	*ids = getNamedPropIds(dir, *names);
	                  	return TRUE;
	                  };
	cvt.get_propname = [&](propid_t id, PROPERTY_NAME **name) {
	                   	*name = getPropertyName(dir, id);
	                   	return TRUE;
	                   };
	if (log_msg_id != 0)
		log_id = dir + ":m" + std::to_string(log_msg_id);
	cvt.log_id = log_id.c_str();
	cvt.alloc = alloc;
	if (cvt.mapi_to_inet(content, mail) != ecSuccess)
		throw EWSError::ItemCorrupt(E3116);

	std::vector<std::string> rcpts;
	rcpts.reserve(content.children.prcpts->count);
	bool organizer = false;
	for (auto &rcpt : *content.children.prcpts) {
		/* The organizer row of a meeting is not an addressee */
		auto flags = rcpt.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (flags != nullptr && *flags & recipOrganizer) {
			organizer = true;
			continue;
		}
		if (flags != nullptr && !(*flags & recipSendable))
			continue;
		tEmailAddressType addr(rcpt);
		if (!addr.EmailAddress)
			continue;
		normalize(addr);
		if (!addr.EmailAddress->empty())
			rcpts.emplace_back(*addr.EmailAddress);
	}
	if (rcpts.empty() && organizer)
		return;
	auto err = cu_send_vmail(mail, m_plugin.smtp_url.c_str(),
	           m_auth_info.username, rcpts);
	if (err != ecSuccess)
		throw DispatchError(E3117(err));

	auto get_smtp_address = [&](proptag_t smtp_tag, proptag_t addrtype_tag,
	                            proptag_t email_tag) -> const char * {
		auto addr = content.proplist.get<const char>(smtp_tag);
		if (addr != nullptr)
			return addr;

		auto type = content.proplist.get<const char>(addrtype_tag);
		if (type == nullptr || strcasecmp(type, "SMTP") == 0)
			return content.proplist.get<const char>(email_tag);

		return nullptr;
	};

	auto actor = get_auth_info(m_ctx_id).username;
	auto subject = content.proplist.get<const char>(PR_SUBJECT);

	auto representing = get_smtp_address(
		PR_SENT_REPRESENTING_SMTP_ADDRESS,
		PR_SENT_REPRESENTING_ADDRTYPE,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS);

	auto sender = get_smtp_address(
		PR_SENDER_SMTP_ADDRESS,
		PR_SENDER_ADDRTYPE,
		PR_SENDER_EMAIL_ADDRESS);

	std::string representation;
	if (actor != nullptr && representing != nullptr &&
	    strcasecmp(actor, representing) != 0) {
		if (sender != nullptr && strcasecmp(actor, sender) == 0)
			representation = " on behalf of "s + representing;
		else
			representation = " as "s + representing;
	}

	mlog(LV_INFO,
		"ews-audit: %s sent message \"%s\"%s in mailbox %s",
		znul(actor), txt2cstr(subject).c_str(),
		txt2cstr(representation.c_str()).c_str(),
		znul(m_auth_info.username));
}

/**
 * @brief      Turn a copy of a series master into a message for one occurrence
 *
 * oxcical exports it as a single VEVENT with a RECURRENCE-ID.
 *
 * @param      dir       Store directory
 * @param      basedate  Basedate of the occurrence
 * @param      msg       Copy of the master, modified in place
 */
void EWSContext::toInstance(const std::string &dir, uint32_t basedate,
    MESSAGE_CONTENT &msg) const
{
	const PROPERTY_NAME names[] = {
		NtAppointmentRecur, NtAppointmentTimeZoneDefinitionRecur,
		NtAppointmentTimeZoneDefinitionStartDisplay,
		NtAppointmentTimeZoneDefinitionEndDisplay,
		NtAppointmentStartWhole, NtAppointmentEndWhole, NtCommonStart,
		NtCommonEnd, NtExceptionReplaceTime, NtIsException,
		NtGlobalObjectId, NtRecurring, NtRecurrencePattern,
		NtRecurrenceType, NtLocation,
	};
	enum {
		l_recur, l_tzrecur, l_tzstart, l_tzend, l_startwhole,
		l_endwhole, l_commonstart, l_commonend, l_replacetime,
		l_isexception, l_goid, l_recurring, l_pattern, l_rectype,
		l_location,
	};
	static_assert(l_location + 1 == std::size(names));
	const PROPNAME_ARRAY pna = {std::size(names), deconst(names)};
	auto ids = getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(names))
		throw DispatchError(E3491);
	auto &props = msg.proplist;
	auto recur_tag = PROP_TAG(PT_BINARY, ids[l_recur]);
	auto tzr_tag   = PROP_TAG(PT_BINARY, ids[l_tzrecur]);
	auto tzs_tag   = PROP_TAG(PT_BINARY, ids[l_tzstart]);
	auto tze_tag   = PROP_TAG(PT_BINARY, ids[l_tzend]);
	auto goid_tag  = PROP_TAG(PT_BINARY, ids[l_goid]);

	sOccurrenceSeries s;
	s.parse(props.get<const BINARY>(recur_tag),
		props.get<const uint64_t>(PR_START_DATE),
		props.get<const BINARY>(tzr_tag));
	if (!s.aprValid)
		throw EWSError::CalendarCannotUseIdForRecurringMasterId(E3489);
	auto t = s.occurrenceTimes(basedate);
	uint64_t start = rop_util_unix_to_nttime(t.start);
	uint64_t end   = rop_util_unix_to_nttime(t.end);
	uint64_t orig  = rop_util_unix_to_nttime(t.orig_start);
	uint8_t yes = 1, no = 0;
	const TAGGED_PROPVAL tv[] = {
		{PR_START_DATE, &start},
		{PR_END_DATE, &end},
		{PROP_TAG(PT_SYSTIME, ids[l_startwhole]), &start},
		{PROP_TAG(PT_SYSTIME, ids[l_endwhole]), &end},
		{PROP_TAG(PT_SYSTIME, ids[l_commonstart]), &start},
		{PROP_TAG(PT_SYSTIME, ids[l_commonend]), &end},
		{PROP_TAG(PT_SYSTIME, ids[l_replacetime]), &orig},
		{PROP_TAG(PT_BOOLEAN, ids[l_isexception]), &yes},
		{PROP_TAG(PT_BOOLEAN, ids[l_recurring]), &no},
	};
	for (const auto &p : tv)
		if (props.set(p.proptag, p.pvalue) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3491);

	/* MS-OXOCAL v26 §2.2.1.27: the instance date, a local day */
	auto goid_bin = props.get<const BINARY>(goid_tag);
	if (goid_bin != nullptr) {
		GLOBALOBJECTID goid{};
		EXT_PULL ep;
		ep.init(goid_bin->pb, goid_bin->cb, alloc, 0);
		auto ts = rop_util_rtime_to_unix(basedate);
		struct tm tm{};
		EXT_PUSH epu;
		if (ep.g_goid(&goid) == pack_result::ok &&
		    gmtime_r(&ts, &tm) != nullptr) {
			goid.year  = tm.tm_year + 1900;
			goid.month = tm.tm_mon + 1;
			goid.day   = tm.tm_mday;
			if (!epu.init(nullptr, 0, 0) ||
			    epu.p_goid(goid) != pack_result::ok)
				throw EWSError::NotEnoughMemory(E3491);
			BINARY bin;
			bin.cb = epu.m_offset;
			bin.pv = epu.m_udata;
			if (props.set(goid_tag, &bin) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3491);
		}
	}

	/* Without the recurrence, oxcical takes the zone from these */
	auto tzr = props.get<const BINARY>(tzr_tag);
	if (tzr != nullptr && (!props.has(tzs_tag) || !props.has(tze_tag)) &&
	    ((!props.has(tzs_tag) && props.set(tzs_tag, tzr) != ecSuccess) ||
	    (!props.has(tze_tag) && props.set(tze_tag, tzr) != ecSuccess)))
		throw EWSError::NotEnoughMemory(E3491);

	auto exc = find_exc(s.apr, basedate);
	if (exc != nullptr) {
		const auto &xe = s.apr.pextendedexception[exc -
		                 s.apr.pexceptioninfo.data()];
		if (exc->overrideflags & ARO_SUBJECT) {
			/* oxcmail prefers these over PR_SUBJECT */
			props.erase(PR_SUBJECT_PREFIX);
			props.erase(PR_NORMALIZED_SUBJECT);
			if (props.set(PR_SUBJECT, xe.subject.c_str()) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3491);
		}
		if (exc->overrideflags & ARO_LOCATION &&
		    props.set(PROP_TAG(PT_UNICODE, ids[l_location]),
		    xe.location.c_str()) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3491);
	}

	/* The exception message carries the body of the occurrence */
	auto xrt_tag = PROP_TAG(PT_SYSTIME, ids[l_replacetime]);
	const MESSAGE_CONTENT *emb = nullptr;
	if (exc != nullptr && msg.children.pattachments != nullptr)
		for (const auto &at : *msg.children.pattachments) {
			if (at.pembedded == nullptr)
				continue;
			auto xrt = at.pembedded->proplist.get<const uint64_t>(xrt_tag);
			if (xrt != nullptr && s.replaces(basedate, *xrt)) {
				emb = at.pembedded;
				break;
			}
		}
	static constexpr proptag_t body_tags[] =
		{PR_BODY, PR_HTML, PR_RTF_COMPRESSED, PR_RTF_IN_SYNC};
	if (emb != nullptr && (emb->proplist.has(PR_BODY) ||
	    emb->proplist.has(PR_HTML) || emb->proplist.has(PR_RTF_COMPRESSED))) {
		for (auto tag : body_tags)
			props.erase(tag);
		for (auto tag : body_tags) {
			auto v = emb->proplist.getval(tag);
			if (v != nullptr && props.set(tag, v) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3535);
		}
	}
	props.erase(recur_tag);
	props.erase(tzr_tag);
	props.erase(PROP_TAG(PT_UNICODE, ids[l_pattern]));
	props.erase(PROP_TAG(PT_LONG, ids[l_rectype]));
	/* oxcical would export each exception as an extra VEVENT */
	msg.set_attachments_internal(nullptr);
}

/**
 * @brief      Prefix the subject of a meeting cancellation
 *
 * MS-OXOCAL v22.1 §2.2.8.2 gives cancellations a localized subject prefix.
 * Use the one Exchange and Outlook use in that language.
 *
 * @param      props  Properties of the cancellation
 * @param      lang   Language of the prefix
 * @param      norm   Storage for the normalized subject
 * @param      full   Storage for the full subject
 *
 * @return     Tagged values to set, pointing into norm and full
 */
static std::array<TAGGED_PROPVAL, 3> cancel_subject(const TPROPVAL_ARRAY &props,
    const char *lang, std::string &norm, std::string &full)
{
	auto subj = props.get<const char>(PR_NORMALIZED_SUBJECT);
	if (subj == nullptr)
		subj = props.get<const char>(PR_SUBJECT);
	auto pfx = meeting_subject_prefix(lang, "canceled");
	norm = znul(subj);
	full = pfx + norm;
	return {{
		{PR_SUBJECT_PREFIX, deconst(pfx)},
		{PR_NORMALIZED_SUBJECT, norm.data()},
		{PR_SUBJECT, full.data()},
	}};
}

/**
 * @brief      Send a meeting message for one occurrence of a series
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder of the meeting
 * @param      mid       Message ID of the series master
 * @param      master    Content of the series master
 * @param      basedate  Basedate of the occurrence
 * @param      cls       Message class to send
 * @param      saveCopy  Whether to keep a copy in Sent Items
 */
void EWSContext::sendInstance(const std::string &dir,
    const sFolderSpec &parent, uint64_t mid, const MESSAGE_CONTENT &master,
    uint32_t basedate, const char *cls, bool saveCopy) const
{
	auto &exmdb = m_plugin.exmdb;
	message_content_ptr inst(master.dup());
	if (!inst)
		throw EWSError::NotEnoughMemory(E3492);
	toInstance(dir, basedate, *inst);
	const PROPERTY_NAME pn[] = {NtAppointmentSequence, NtOwnerCriticalChange};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(pn) ||
	    std::find(ids.cbegin(), ids.cend(), 0) != ids.cend())
		throw EWSError::ItemSave(E3541);
	auto now = rop_util_current_nttime();
	/* MS-OXOCAL v22.1 §3.1.5.4: the Meeting object keeps the new number */
	uint32_t newseq = nextSequence(dir, parent, mid, true, now);
	m_plugin.unloadMessageInstance(dir, mid);
	auto &props = inst->proplist;
	if (props.set(PR_MESSAGE_CLASS, cls) != ecSuccess ||
	    props.set(PR_CLIENT_SUBMIT_TIME, &now) != ecSuccess ||
	    props.set(PR_MESSAGE_DELIVERY_TIME, &now) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, ids[0]), &newseq) != ecSuccess ||
	    props.set(PROP_TAG(PT_SYSTIME, ids[1]), &now) != ecSuccess)
		throw EWSError::NotEnoughMemory(E3492);
	if (strcmp(cls, "IPM.Schedule.Meeting.Request") == 0 &&
	    props.set(PR_RESPONSE_REQUESTED, &byte_value_one) != ecSuccess)
		throw EWSError::NotEnoughMemory(E3536);
	if (strcmp(cls, "IPM.Schedule.Meeting.Canceled") == 0) {
		std::string norm, full;
		for (const auto &p : cancel_subject(props, culture(), norm, full))
			if (props.set(p) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3492);
	}
	/* The owner organizes and the caller sends */
	for (const auto &prop : meetingIdentity(dir))
		if (props.set(prop) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3492);
	props.erase(PR_SENDER_SEARCH_KEY);
	props.erase(PR_SENT_REPRESENTING_SEARCH_KEY);
	send(dir, mid, *inst);
	if (!saveCopy)
		return;
	static constexpr proptag_t rmProps[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST, PR_ENTRYID, PR_SOURCE_KEY,
	};
	for (auto tag : rmProps)
		props.erase(tag);
	auto sentitems = resolveFolder(
	                 tDistinguishedFolderId(Enum::sentitems));
	uint64_t newMid = 0, newCn = 0;
	ec_error_t err = ecSuccess;
	if (!exmdb.write_message(dir.c_str(), CP_ACP, sentitems.folderId,
	    inst.get(), {}, &newMid, &newCn, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3490);
}

/**
 * @brief      Stamp properties on the exceptions of a series message
 *
 * oxcical exports each exception as its own VEVENT and takes ORGANIZER,
 * ATTENDEE, DTSTAMP and SEQUENCE from the exception message, which
 * UpdateItem creates without them.
 *
 * @param      msg     Duplicated series message
 * @param      props   Properties to set
 *
 * @return     false if memory ran out
 */
static bool stamp_exceptions(MESSAGE_CONTENT &msg,
    const std::vector<TAGGED_PROPVAL> &props)
{
	if (msg.children.pattachments == nullptr)
		return true;
	for (auto &at : *msg.children.pattachments) {
		if (at.pembedded == nullptr)
			continue;
		auto cls = at.pembedded->proplist.get<const char>(PR_MESSAGE_CLASS);
		if (cls == nullptr ||
		    class_match_prefix(cls, IPM_Appointment_Exception) != 0)
			continue;
		for (const auto &p : props)
			if (at.pembedded->proplist.set(p) != ecSuccess)
				return false;
		auto rcpts = at.pembedded->children.prcpts;
		if (msg.children.prcpts == nullptr ||
		    (rcpts != nullptr && rcpts->count > 0))
			continue;
		rcpts = msg.children.prcpts->dup();
		if (rcpts == nullptr)
			return false;
		at.pembedded->set_rcpts_internal(rcpts);
	}
	return true;
}

/**
 * @brief      Send meeting cancellation to attendees
 *
 * Reads the calendar item, stamps it as a cancellation, and
 * either saves a copy in Sent Items or sends directly.
 */
void EWSContext::sendMeetingCancellation(const std::string &dir, const sMessageEntryId &meid,
    const sFolderSpec &parent, bool saveCopy,
    std::optional<uint32_t> basedate) const
{
	auto &exmdb = m_plugin.exmdb;
	const char *username = effectiveUser(parent);
	MESSAGE_CONTENT *cancelcontent = nullptr;
	if (!exmdb.read_message(dir.c_str(), username, CP_ACP, meid.messageId(),
	    &cancelcontent) || cancelcontent == nullptr)
		throw EWSError::ItemNotFound(E3389);
	auto cls = cancelcontent->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (cls == nullptr ||
	    class_match_prefix(cls, "IPM.Appointment") != 0 ||
	    !has_rcpt_address(*cancelcontent))
		return;
	/* The cancellation carries the content of the meeting */
	if (!(permissions(dir, parent.folderId) & frightsReadAny))
		throw EWSError::AccessDenied(E3604);
	/* Callers delete the item afterwards, so check before that */
	validate_sendas_perms(storeOwner(dir));
	if (basedate) {
		sendInstance(dir, parent, meid.messageId(), *cancelcontent,
			*basedate, "IPM.Schedule.Meeting.Canceled", saveCopy);
		return;
	}
	/* The caller sends, the stored PR_SENDER may name someone else */
	auto ident = meetingIdentity(dir);
	const std::vector<proptag_t> staleKeys
		{PR_SENDER_SEARCH_KEY, PR_SENT_REPRESENTING_SEARCH_KEY};
	const PROPERTY_NAME pn[] = {NtAppointmentSequence, NtOwnerCriticalChange};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(pn) ||
	    std::find(ids.cbegin(), ids.cend(), 0) != ids.cend())
		throw EWSError::ItemSave(E3541);
	auto seq_tag = PROP_TAG(PT_LONG, ids[0]);
	auto crit_tag = PROP_TAG(PT_SYSTIME, ids[1]);
	auto now = rop_util_current_nttime();
	uint32_t newseq = nextSequence(dir, parent, meid.messageId(), true, now);
	/* RFC 5546 §3.2.5: every VEVENT of the CANCEL needs these */
	auto excProps = ident;
	excProps.push_back({seq_tag, &newseq});
	excProps.push_back({crit_tag, &now});
	if (saveCopy) {
		sFolderSpec sentitems = resolveFolder(tDistinguishedFolderId(Enum::sentitems));
		uint64_t newMid = 0;
		if (!exmdb.allocate_message_id(dir.c_str(), sentitems.folderId, &newMid))
			throw EWSError::InternalServerError(E3132);
		BOOL result = false;
		if (!exmdb.movecopy_message(dir.c_str(), CP_ACP, meid.messageId(),
		    sentitems.folderId, newMid, false, &result) || !result)
			throw EWSError::InternalServerError(E3301);
		const char *sentuser = effectiveUser(sentitems);
		std::vector<TAGGED_PROPVAL> sprops = {
			{PR_MESSAGE_CLASS, deconst("IPM.Schedule.Meeting.Canceled")},
			{PR_CLIENT_SUBMIT_TIME, &now},
			{PR_MESSAGE_DELIVERY_TIME, &now},
			{seq_tag, &newseq},
			{crit_tag, &now},
		};
		sprops.insert(sprops.end(), ident.begin(), ident.end());
		std::string norm, full;
		auto subj = cancel_subject(cancelcontent->proplist, culture(), norm, full);
		sprops.insert(sprops.end(), subj.begin(), subj.end());
		const TPROPVAL_ARRAY sproplist{static_cast<uint16_t>(sprops.size()), sprops.data()};
		PROBLEM_ARRAY sproblems;
		if (!exmdb.set_message_properties(dir.c_str(), sentuser, CP_ACP,
		    newMid, &sproplist, &sproblems) ||
		    !exmdb.remove_message_properties(dir.c_str(), CP_ACP,
		    newMid, staleKeys))
			throw EWSError::ItemSave(E3092);
		MESSAGE_CONTENT *sentcontent = nullptr;
		if (!exmdb.read_message(dir.c_str(), sentuser, CP_ACP, newMid,
		    &sentcontent) || sentcontent == nullptr)
			throw EWSError::ItemNotFound(E3390);
		message_content_ptr outcontent(sentcontent->dup());
		if (!outcontent ||
		    !stamp_exceptions(*outcontent, excProps))
			throw EWSError::NotEnoughMemory(E3407);
		send(dir, meid.messageId(), *outcontent);
	} else {
		message_content_ptr dupcontent(cancelcontent->dup());
		if (!dupcontent)
			throw EWSError::NotEnoughMemory(E3407);
		auto &props = dupcontent->proplist;
		if (props.set(PR_MESSAGE_CLASS,
		    "IPM.Schedule.Meeting.Canceled") != ecSuccess ||
		    props.set(PR_CLIENT_SUBMIT_TIME, &now) != ecSuccess ||
		    props.set(PR_MESSAGE_DELIVERY_TIME, &now) != ecSuccess ||
		    props.set(seq_tag, &newseq) != ecSuccess ||
		    props.set(crit_tag, &now) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3407);
		for (const auto &prop : ident)
			if (props.set(prop) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3407);
		std::string norm, full;
		for (const auto &p : cancel_subject(props, culture(), norm, full))
			if (props.set(p) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3407);
		for (auto tag : staleKeys)
			props.erase(tag);
		if (!stamp_exceptions(*dupcontent, excProps))
			throw EWSError::NotEnoughMemory(E3407);
		send(dir, meid.messageId(), *dupcontent);
	}
}
/* Subject prefix of a meeting response, MS-OXOCAL v22.1 §2.2.7.2 */
static const char *resp_subject_prefix(const char *cls, const char *lang)
{
	if (cls == nullptr)
		return nullptr;
	if (strcasecmp(cls, "IPM.Schedule.Meeting.Resp.Pos") == 0)
		return meeting_subject_prefix(lang, "accepted");
	if (strcasecmp(cls, "IPM.Schedule.Meeting.Resp.Tent") == 0)
		return meeting_subject_prefix(lang, "tentative");
	if (strcasecmp(cls, "IPM.Schedule.Meeting.Resp.Neg") == 0)
		return meeting_subject_prefix(lang, "declined");
	return nullptr;
}

/**
 * @brief      Get the SMTP address of a recipient row
 *
 * @param      row     Recipient row
 *
 * @return     Address, or an empty string if it cannot be resolved
 */
std::string EWSContext::rcptAddress(const TPROPVAL_ARRAY &row) const
{
	tEmailAddressType addr(row);
	try {
		normalize(addr);
	} catch (const DispatchError &) {
		return {};
	}
	return addr.EmailAddress.value_or("");
}

/**
 * @brief      Send a cancellation to attendees dropped from a meeting
 *
 * MS-OXOCAL v22.1 §3.1.4.9.1.1: only the removed attendees get the
 * Meeting Cancellation object.
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder of the meeting
 * @param      mid       Message ID of the meeting
 * @param      oldRcpts  Recipients of the meeting before the update
 * @param      saveCopy  Whether to keep a copy in Sent Items
 */
void EWSContext::cancelRemovedAttendees(const std::string &dir,
    const sFolderSpec &parent, uint64_t mid, const TARRAY_SET &oldRcpts,
    bool saveCopy) const
{
	auto &exmdb = m_plugin.exmdb;
	MESSAGE_CONTENT *cur = nullptr;
	if (!exmdb.read_message(dir.c_str(), effectiveUser(parent), CP_ACP,
	    mid, &cur) || cur == nullptr)
		throw EWSError::ItemNotFound(E3389);
	auto cls = cur->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (cls == nullptr || class_match_prefix(cls, "IPM.Appointment") != 0)
		return;
	std::vector<std::string> kept;
	if (cur->children.prcpts != nullptr)
		for (const auto &row : *cur->children.prcpts)
			kept.emplace_back(rcptAddress(row));
	auto is_kept = [&](const std::string &a) {
		return std::any_of(kept.cbegin(), kept.cend(),
		       [&](const std::string &k) {
		       	return strcasecmp(k.c_str(), a.c_str()) == 0;
		       });
	};
	message_content_ptr cancel(cur->dup());
	if (!cancel)
		throw EWSError::NotEnoughMemory(E3407);
	auto rcpts = tarray_set_init();
	if (rcpts == nullptr)
		throw EWSError::NotEnoughMemory(E3406);
	cancel->set_rcpts_internal(rcpts);
	for (const auto &row : oldRcpts) {
		auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
		if (flags != nullptr && *flags & recipOrganizer)
			continue;
		auto addr = rcptAddress(row);
		if (addr.empty()) {
			mlog(LV_WARN, "[ews] %s:m%llu: removed attendee has "
			     "no usable address, no cancellation sent",
			     dir.c_str(), static_cast<unsigned long long>(mid));
			continue;
		}
		if (is_kept(addr))
			continue;
		tpropval_array_ptr dup(row.dup());
		if (dup == nullptr ||
		    rcpts->append_move(std::move(dup)) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3406);
	}
	if (rcpts->count == 0)
		return;

	/* MS-OXOCAL v22.1 §2.2.8, §3.1.4.9.1 */
	const PROPERTY_NAME pn[] = {
		NtAppointmentSequence, NtAppointmentStateFlags,
		NtResponseStatus, NtBusyStatus, NtIntendedBusyStatus,
		NtOwnerCriticalChange,
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(pn) ||
	    std::find(ids.cbegin(), ids.cend(), 0) != ids.cend())
		throw EWSError::ItemSave(E3495);
	auto &props = cancel->proplist;
	auto seq_tag = PROP_TAG(PT_LONG, ids[0]);
	auto state_tag = PROP_TAG(PT_LONG, ids[1]);
	auto now = rop_util_current_nttime();
	uint32_t newseq = nextSequence(dir, parent, mid, false, now);
	auto st = props.get<const uint32_t>(state_tag);
	uint32_t state = (st != nullptr ? *st : asfMeeting) |
	                 asfReceived | asfCanceled;
	uint32_t resp = respNotResponded, busy = olFree;
	std::string norm, full;
	auto subjProps = cancel_subject(props, culture(), norm, full);
	if (props.set(PR_MESSAGE_CLASS,
	    "IPM.Schedule.Meeting.Canceled") != ecSuccess ||
	    props.set(PR_CLIENT_SUBMIT_TIME, &now) != ecSuccess ||
	    props.set(PR_MESSAGE_DELIVERY_TIME, &now) != ecSuccess ||
	    props.set(seq_tag, &newseq) != ecSuccess ||
	    props.set(PROP_TAG(PT_SYSTIME, ids[5]), &now) != ecSuccess ||
	    props.set(state_tag, &state) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, ids[2]), &resp) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, ids[3]), &busy) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, ids[4]), &busy) != ecSuccess ||
	    props.set(subjProps[0]) != ecSuccess ||
	    props.set(subjProps[1]) != ecSuccess ||
	    props.set(subjProps[2]) != ecSuccess)
		throw EWSError::NotEnoughMemory(E3406);
	/* The owner organizes and the caller sends */
	auto ident = meetingIdentity(dir);
	for (const auto &prop : ident)
		if (props.set(prop) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3406);
	props.erase(PR_SENDER_SEARCH_KEY);
	props.erase(PR_SENT_REPRESENTING_SEARCH_KEY);
	/* RFC 5546 §3.2.5: every VEVENT of the CANCEL needs these */
	ident.push_back({seq_tag, &newseq});
	ident.push_back({PROP_TAG(PT_SYSTIME, ids[5]), &now});
	if (!stamp_exceptions(*cancel, ident))
		throw EWSError::NotEnoughMemory(E3406);
	send(dir, mid, *cancel);
	if (!saveCopy)
		return;
	static constexpr proptag_t rmProps[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST, PR_ENTRYID, PR_SOURCE_KEY,
	};
	for (auto tag : rmProps)
		props.erase(tag);
	auto sentitems = resolveFolder(tDistinguishedFolderId(Enum::sentitems));
	uint64_t newMid = 0, newCn = 0;
	ec_error_t err = ecSuccess;
	if (!exmdb.write_message(dir.c_str(), CP_ACP, sentitems.folderId,
	    cancel.get(), {}, &newMid, &newCn, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3490);
}

/**
 * @brief      Pick the sequence number of an outgoing meeting message
 *
 * MS-OXOCAL v22.1 §3.1.5.4: every update or cancellation increments it.
 * The Meeting object records the new number as its last sequence, and
 * as its sequence with the sequence time only when all attendees are
 * told.
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder of the meeting
 * @param      mid       Message ID of the meeting
 * @param      toAll     Whether the message goes to all attendees
 * @param      critical  PidLidOwnerCriticalChange of the message
 *
 * @return     Sequence number for the outgoing message
 */
uint32_t EWSContext::nextSequence(const std::string &dir,
    const sFolderSpec &parent, uint64_t mid, bool toAll,
    uint64_t critical) const
{
	const PROPERTY_NAME pn[] = {
		NtAppointmentSequence, NtAppointmentLastSequence,
		NtAppointmentSequenceTime, NtOwnerCriticalChange,
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(pn) ||
	    std::find(ids.cbegin(), ids.cend(), 0) != ids.cend())
		throw EWSError::ItemSave(E3541);
	const proptag_t tags[] = {
		PROP_TAG(PT_LONG, ids[0]), PROP_TAG(PT_LONG, ids[1]),
		PROP_TAG(PT_SYSTIME, ids[2]), PROP_TAG(PT_SYSTIME, ids[3]),
	};
	auto props = getItemProps(dir, mid, tags);
	auto seq = props.get<const uint32_t>(tags[0]);
	auto last = props.get<const uint32_t>(tags[1]);
	auto seqtime = props.get<const uint64_t>(tags[2]);
	auto owncrit = props.get<const uint64_t>(tags[3]);
	uint32_t val = std::max(seq != nullptr ? *seq : 0,
	               last != nullptr ? *last : 0) + 1;
	std::vector<TAGGED_PROPVAL> vals{{tags[1], &val}};
	if (toAll) {
		vals.push_back({tags[0], &val});
		vals.push_back({tags[2], &critical});
		vals.push_back({tags[3], &critical});
	} else if (seqtime == nullptr && owncrit != nullptr) {
		vals.push_back({tags[2], deconst(owncrit)});
	}
	const TPROPVAL_ARRAY list = {static_cast<uint16_t>(vals.size()),
	                            vals.data()};
	PROBLEM_ARRAY problems;
	if (!m_plugin.exmdb.set_message_properties(dir.c_str(),
	    effectiveUser(parent), CP_ACP, mid, &list, &problems))
		throw EWSError::ItemSave(E3542);
	return val;
}

/**
 * @brief      Record the attendees an update is not sent to
 *
 * MS-OXOCAL v22.1 §2.2.1.25, §3.1.4.7.3.4. An empty list removes
 * the property, so a copied calendar item does not pass on a stale one.
 *
 * @param      props  Properties of the meeting update
 * @param      tag    Tag of PidLidAppointmentUnsendableRecipients
 * @param      rows   Recipient rows of the unsendable attendees
 */
void EWSContext::setUnsendable(TPROPVAL_ARRAY &props, proptag_t tag,
    const std::vector<TPROPVAL_ARRAY *> &rows)
{
	props.erase(tag);
	if (rows.empty())
		return;
	static constexpr proptag_t keep[] = {
		PR_DISPLAY_NAME, PR_ADDRTYPE, PR_EMAIL_ADDRESS,
		PR_SMTP_ADDRESS, PR_ENTRYID, PR_DISPLAY_TYPE,
		PR_RECIPIENT_TYPE, PR_RECIPIENT_FLAGS,
		PR_RECIPIENT_TRACKSTATUS, PR_RECIPIENT_TRACKSTATUS_TIME,
	};
	std::vector<std::vector<TAGGED_PROPVAL>> vals(rows.size());
	std::vector<TPROPVAL_ARRAY> sub(rows.size());
	std::vector<TPROPVAL_ARRAY *> ptrs(rows.size());
	for (size_t i = 0; i < rows.size(); ++i) {
		for (auto t : keep) {
			auto v = rows[i]->getval(t);
			if (v != nullptr)
				vals[i].emplace_back(TAGGED_PROPVAL{t, deconst(v)});
		}
		sub[i] = {static_cast<uint16_t>(vals[i].size()), vals[i].data()};
		ptrs[i] = &sub[i];
	}
	const TARRAY_SET set = {static_cast<uint32_t>(ptrs.size()), ptrs.data()};
	/* Only a SHOULD, so the update goes out without it */
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_UTF16) ||
	    ep.p_rcpt_stream(set) != pack_result::ok)
		return;
	BINARY bin;
	bin.cb = ep.m_offset;
	bin.pv = ep.m_udata;
	if (props.set(tag, &bin) != ecSuccess)
		throw EWSError::NotEnoughMemory(E3408);
}

/**
 * @brief      Record that the meeting requests went out
 *
 * Sets PidLidFInvited, which EWS reports as MeetingRequestWasSent. Outlook
 * shows a meeting without it as not sent yet. The mail is out already, so
 * a failure is only logged.
 */
static void mark_invited(const EWSContext &ctx, const std::string &dir,
    const sFolderSpec &parent, uint64_t mid)
{
	auto propid = ctx.getNamedPropId(dir, NtFInvited, true);
	if (propid == 0)
		return;
	const TAGGED_PROPVAL val = {PROP_TAG(PT_BOOLEAN, propid), deconst(&byte_value_one)};
	const TPROPVAL_ARRAY list = {1, deconst(&val)};
	PROBLEM_ARRAY problems;
	if (!ctx.plugin().exmdb.set_message_properties(dir.c_str(),
	    ctx.effectiveUser(parent), CP_ACP, mid, &list, &problems))
		mlog(LV_ERR, "[ews] %s:m%llu: cannot set PidLidFInvited",
			dir.c_str(), static_cast<unsigned long long>(rop_util_get_gc_value(mid)));
}

/**
 * @brief      Send the update of a meeting changed by UpdateItem
 *
 * MS-OXWSMTGS v14.0 §2.2.5.3: the SendToChanged modes only address
 * the attendees that were added or removed. Removed attendees are
 * handled by cancelRemovedAttendees.
 *
 * @param      dir       Store directory
 * @param      parent    Parent folder of the meeting
 * @param      mid       Message ID of the meeting
 * @param      oldRcpts  Recipients before the update to send only to
 *                       the added attendees, nullptr to send to all
 * @param      saveCopy  Whether to keep a copy in Sent Items
 * @param      highlight PidLidChangeHighlight of the update
 * @param      full      Whether it is a full update
 */
void EWSContext::sendMeetingUpdate(const std::string &dir,
    const sFolderSpec &parent, uint64_t mid, const TARRAY_SET *oldRcpts,
    bool saveCopy, uint32_t highlight, bool full) const
{
	auto &exmdb = m_plugin.exmdb;
	MESSAGE_CONTENT *cur = nullptr;
	if (!exmdb.read_message(dir.c_str(), effectiveUser(parent), CP_ACP,
	    mid, &cur) || cur == nullptr)
		throw EWSError::ItemNotFound(E3404);
	auto cls = cur->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (cls == nullptr || class_match_prefix(cls, "IPM.Appointment") != 0 ||
	    cur->children.prcpts == nullptr || cur->children.prcpts->count == 0)
		return;
	/*
	 * read_message returns pointers backed by ndr_stack regions, which
	 * set() must not free. Thus, dup() first.
	 */
	message_content_ptr req(cur->dup());
	if (!req)
		throw EWSError::NotEnoughMemory(E3408);
	auto rcpts = req->children.prcpts;
	std::vector<TPROPVAL_ARRAY *> unsendable;
	if (oldRcpts != nullptr) {
		/*
		 * MS-OXOCAL v22.1 §3.1.4.7.3.4: the other attendees stay
		 * listed in the request but are marked unsendable.
		 */
		std::vector<std::string> old;
		for (const auto &row : *oldRcpts)
			old.emplace_back(rcptAddress(row));
		for (auto &row : *rcpts) {
			auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
			uint32_t f = flags != nullptr ? *flags : 0;
			if (f & recipOrganizer)
				continue;
			auto a = rcptAddress(row);
			if (!a.empty() && std::none_of(old.cbegin(), old.cend(),
			    [&](const std::string &o) {
			    	return strcasecmp(o.c_str(), a.c_str()) == 0;
			    }))
				continue;
			if (flags == nullptr || f & recipSendable)
				f |= recipOriginal;
			f &= ~recipSendable;
			if (row.set(PR_RECIPIENT_FLAGS, &f) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3408);
			unsendable.push_back(&row);
		}
	}
	if (std::none_of(rcpts->begin(), rcpts->end(),
	    [](const TPROPVAL_ARRAY &row) {
	    	auto flags = row.get<const uint32_t>(PR_RECIPIENT_FLAGS);
	    	return flags == nullptr || (*flags & recipSendable &&
	    	       !(*flags & recipOrganizer));
	    }))
		return;
	const PROPERTY_NAME pn[] = {
		NtAppointmentSequence, NtOwnerCriticalChange,
		NtAppointmentUnsendableRecipients, NtFInvited,
		NtChangeHighlight, NtMeetingType,
	};
	const PROPNAME_ARRAY pna = {std::size(pn), deconst(pn)};
	auto ids = getNamedPropIds(dir, pna, true);
	if (ids.size() != std::size(pn) ||
	    std::find(ids.cbegin(), ids.cend(), 0) != ids.cend())
		throw EWSError::ItemSave(E3541);
	auto &props = req->proplist;
	/*
	 * MS-OXOCAL v22.1 §2.2.6.2, §2.2.6.5. The first invitation to go
	 * out stays the initial request.
	 */
	auto invited = props.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, ids[3]));
	uint32_t mtgType = full ? mtgFull : mtgInfo;
	if (invited != nullptr && *invited != 0 &&
	    (props.set(PROP_TAG(PT_LONG, ids[4]), &highlight) != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, ids[5]), &mtgType) != ecSuccess))
		throw EWSError::NotEnoughMemory(E3408);
	auto now = rop_util_current_nttime();
	uint32_t seq = nextSequence(dir, parent, mid, oldRcpts == nullptr, now);
	setUnsendable(props, PROP_TAG(PT_BINARY, ids[2]), unsendable);
	if (props.set(PR_MESSAGE_CLASS,
	    "IPM.Schedule.Meeting.Request") != ecSuccess ||
	    props.set(PROP_TAG(PT_LONG, ids[0]), &seq) != ecSuccess ||
	    props.set(PROP_TAG(PT_SYSTIME, ids[1]), &now) != ecSuccess ||
	    props.set(PR_RESPONSE_REQUESTED, &byte_value_one) != ecSuccess ||
	    props.set(PR_CLIENT_SUBMIT_TIME, &now) != ecSuccess ||
	    props.set(PR_MESSAGE_DELIVERY_TIME, &now) != ecSuccess)
		throw EWSError::NotEnoughMemory(E3408);
	/* The owner organizes and the caller sends */
	auto ident = meetingIdentity(dir);
	for (const auto &prop : ident)
		if (props.set(prop) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3408);
	props.erase(PR_SENDER_SEARCH_KEY);
	props.erase(PR_SENT_REPRESENTING_SEARCH_KEY);
	/* RFC 5546 §3.2.2: every VEVENT of the REQUEST needs these */
	ident.push_back({PROP_TAG(PT_LONG, ids[0]), &seq});
	ident.push_back({PROP_TAG(PT_SYSTIME, ids[1]), &now});
	if (!stamp_exceptions(*req, ident))
		throw EWSError::NotEnoughMemory(E3408);
	send(dir, mid, *req);
	mark_invited(*this, dir, parent, mid);
	if (!saveCopy)
		return;
	static constexpr proptag_t rmProps[] = {
		PidTagMid, PidTagChangeNumber, PR_CHANGE_KEY,
		PR_PREDECESSOR_CHANGE_LIST, PR_ENTRYID, PR_SOURCE_KEY,
	};
	for (auto tag : rmProps)
		props.erase(tag);
	auto sentitems = resolveFolder(tDistinguishedFolderId(Enum::sentitems));
	uint64_t newMid = 0, newCn = 0;
	ec_error_t err = ecSuccess;
	if (!exmdb.write_message(dir.c_str(), CP_ACP, sentitems.folderId,
	    req.get(), {}, &newMid, &newCn, &err) || err != ecSuccess)
		throw EWSError::ItemSave(E3540);
}

/**
 * @brief      Send a meeting update for one occurrence to the attendees
 *
 * MS-OXOCAL v22.1 §3.1.4.7.3: the update is a meeting request for
 * the instance, which oxcical exports with RECURRENCE-ID.
 */
void EWSContext::sendOccurrenceUpdate(const std::string &dir,
    const sMessageEntryId &meid, const sFolderSpec &parent, bool saveCopy,
    uint32_t basedate) const
{
	MESSAGE_CONTENT *content = nullptr;
	if (!m_plugin.exmdb.read_message(dir.c_str(), effectiveUser(parent),
	    CP_ACP, meid.messageId(), &content) || content == nullptr)
		throw EWSError::ItemNotFound(E3537);
	auto cls = content->proplist.get<const char>(PR_MESSAGE_CLASS);
	if (cls == nullptr ||
	    class_match_prefix(cls, "IPM.Appointment") != 0 ||
	    content->children.prcpts == nullptr ||
	    content->children.prcpts->count == 0)
		return;
	sendInstance(dir, parent, meid.messageId(), *content, basedate,
		"IPM.Schedule.Meeting.Request", saveCopy);
}

/**
 * @brief      Send a meeting response to the organizer
 *
 * Gives the response the prefixed subject of the request and the
 * organizer as recipient. To send, duplicates the original meeting request,
 * stamps the responder's identity on PR_SENDER_*, preserves
 * PR_SENT_REPRESENTING_* as the organizer, and sends.
 *
 * @param      responseRef  Meeting request or meeting responded to
 * @param      respItem     Response to complete
 * @param      doSend       Whether to send the response
 *
 * @return     false if no response was sent
 */
bool EWSContext::sendMeetingResponse(const tItemId &responseRef,
    MESSAGE_CONTENT &respItem, bool doSend) const
{
	std::optional<uint32_t> basedate;
	if (responseRef.type == tItemId::ID_OCCURRENCE)
		basedate = sOccurrenceId(responseRef.Id.data(),
		           responseRef.Id.size()).basedate;
	else
		assertIdType(responseRef.type, tItemId::ID_ITEM);
	sMessageEntryId refMid(responseRef.Id.data(), responseRef.Id.size());
	sFolderSpec refFolder = resolveFolder(refMid);
	std::string refDir = getDir(refFolder);
	const char *refUser = effectiveUser(refFolder);
	MESSAGE_CONTENT *reqContent = nullptr;
	if (!plugin().exmdb.read_message(refDir.c_str(), refUser, CP_ACP,
	    refMid.messageId(), &reqContent) || reqContent == nullptr)
		throw EWSError::ItemNotFound(E3143);
	auto wantResp = reqContent->proplist.get<const uint8_t>(PR_RESPONSE_REQUESTED);
	auto orgSmtp = reqContent->proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (!orgSmtp)
		orgSmtp = reqContent->proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	tEmailAddressType org;
	if (orgSmtp != nullptr) {
		org.EmailAddress = orgSmtp;
		auto orgName = reqContent->proplist.get<const char>(PR_SENT_REPRESENTING_NAME);
		if (orgName)
			org.Name = orgName;
		org.RoutingType = "SMTP";
	}

	/* Subject and recipient for the saved copy or the draft */
	auto respClass = respItem.proplist.get<const char>(PR_MESSAGE_CLASS);
	auto topic = reqContent->proplist.get<const char>(PR_NORMALIZED_SUBJECT);
	if (topic == nullptr)
		topic = reqContent->proplist.get<const char>(PR_SUBJECT);
	if (topic != nullptr && !respItem.proplist.has(PR_SUBJECT)) {
		auto pfx = resp_subject_prefix(respClass, culture());
		if (pfx == nullptr)
			pfx = "";
		if (respItem.proplist.set(PR_SUBJECT_PREFIX, pfx) != ecSuccess ||
		    respItem.proplist.set(PR_NORMALIZED_SUBJECT, topic) != ecSuccess ||
		    respItem.proplist.set(PR_SUBJECT, cpystr(std::string(pfx) + topic)) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3288);
	}
	if (orgSmtp != nullptr && (respItem.children.prcpts == nullptr ||
	    respItem.children.prcpts->count == 0)) {
		auto rcpts = tarray_set_init();
		if (rcpts == nullptr)
			throw EWSError::NotEnoughMemory(E3288);
		respItem.set_rcpts_internal(rcpts);
		org.mkRecipient(rcpts->emplace(), MAPI_TO);
	}
	if (!doSend || (wantResp != nullptr && *wantResp == 0) || orgSmtp == nullptr)
		return false;

	message_content_ptr content(reqContent->dup());
	if (!content)
		throw EWSError::NotEnoughMemory(E3288);
	if (basedate)
		toInstance(refDir, *basedate, *content);
	if (respClass)
		content->proplist.set(PR_MESSAGE_CLASS, respClass);
	for (auto tag : {PR_SUBJECT, PR_SUBJECT_PREFIX, PR_NORMALIZED_SUBJECT}) {
		auto str = respItem.proplist.get<const char>(tag);
		if (str == nullptr)
			content->proplist.erase(tag);
		else if (content->proplist.set(tag, str) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3288);
	}
	auto now = EWSContext::construct<uint64_t>(rop_util_current_nttime());
	content->proplist.set(PR_CLIENT_SUBMIT_TIME, now);
	content->proplist.set(PR_MESSAGE_DELIVERY_TIME, now);
	/*
	 * The attendee is the owner of the request, the caller may be a
	 * delegate. A delegate answering its copy responds on behalf of the
	 * principal.
	 */
	std::optional<std::string> principal;
	if (refFolder.location == sFolderSpec::PRIVATE)
		principal = delegatePrincipal(reqContent->proplist, *refFolder.target);
	std::string attendee = principal ? *principal :
	                       refFolder.location == sFolderSpec::PRIVATE ?
	                       *refFolder.target : m_auth_info.username;
	if (principal)
		validate_sendas_perms(attendee);
	auto respUser = !principal && (actsAsOwner(refDir) || onSendAsList(refDir)) ?
	                cpystr(attendee) :
	                deconst(m_auth_info.username);
	std::string respName, attName;
	mysql_adaptor_get_user_displayname(respUser, respName);
	mysql_adaptor_get_user_displayname(attendee.c_str(), attName);
	content->proplist.set(PR_SENDER_SMTP_ADDRESS, respUser);
	content->proplist.set(PR_SENDER_EMAIL_ADDRESS, respUser);
	content->proplist.set(PR_SENDER_ADDRTYPE, deconst("SMTP"));
	/* oxcical takes the ATTENDEE of a REPLY from PR_SENT_REPRESENTING_* */
	content->proplist.set(PR_SENT_REPRESENTING_SMTP_ADDRESS, attendee.c_str());
	content->proplist.set(PR_SENT_REPRESENTING_EMAIL_ADDRESS, attendee.c_str());
	content->proplist.set(PR_SENT_REPRESENTING_ADDRTYPE, deconst("SMTP"));
	content->proplist.erase(PR_SENT_REPRESENTING_ENTRYID);
	content->proplist.erase(PR_SENT_REPRESENTING_SEARCH_KEY);
	if (!respName.empty())
		content->proplist.set(PR_SENDER_NAME, respName.c_str());
	if (!attName.empty())
		content->proplist.set(PR_SENT_REPRESENTING_NAME, attName.c_str());
	else
		content->proplist.erase(PR_SENT_REPRESENTING_NAME);
	if (content->children.prcpts)
		tarray_set_free(content->children.prcpts);
	content->children.prcpts = tarray_set_init();
	if (!content->children.prcpts)
		throw EWSError::NotEnoughMemory(E3406);
	org.mkRecipient(content->children.prcpts->emplace(), MAPI_TO);
	/* The copy in Sent Items names the same sender as the mail */
	for (auto tag : {PR_SENDER_NAME, PR_SENDER_ADDRTYPE,
	     PR_SENDER_EMAIL_ADDRESS, PR_SENDER_SMTP_ADDRESS,
	     PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ADDRTYPE,
	     PR_SENT_REPRESENTING_EMAIL_ADDRESS,
	     PR_SENT_REPRESENTING_SMTP_ADDRESS}) {
		auto str = content->proplist.get<const char>(tag);
		if (str == nullptr)
			respItem.proplist.erase(tag);
		else if (respItem.proplist.set(tag, str) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3288);
	}
	for (auto tag : {PR_SENDER_ENTRYID, PR_SENDER_SEARCH_KEY,
	     PR_SENT_REPRESENTING_ENTRYID, PR_SENT_REPRESENTING_SEARCH_KEY})
		respItem.proplist.erase(tag);
	send(refDir, 0, *content);
	return true;
}

/**
 * @brief      Send read receipt if requested by the sender
 *
 * Tests whether the message has PR_READ_RECEIPT_REQUESTED set and, if so,
 * generates and sends a read receipt (MDN) to the original sender. After
 * sending, the receipt request flags are cleared to prevent duplicate
 * notifications.
 *
 * @param      dir     Store directory
 * @param      mid     Message ID
 */
void EWSContext::notifyReadReceipt(const std::string &dir,
    uint64_t mid) const try
{
	void *pval = nullptr;
	if (!m_plugin.exmdb.get_message_property(dir.c_str(), nullptr,
	    CP_ACP, mid, PR_READ_RECEIPT_REQUESTED, &pval))
		return;
	if (!pvb_enabled(pval))
		return;
	MESSAGE_CONTENT *pbrief = nullptr;
	if (!m_plugin.exmdb.get_message_brief(dir.c_str(), CP_ACP,
	    mid, &pbrief) || pbrief == nullptr)
		return;
	auto str = pbrief->proplist.get<const char>(
	           PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str == nullptr)
		return;
	std::vector<std::string> rcpt_list = {str};
	vmime::shared_ptr<vmime::message> imail;
	if (!exch_bouncer_make(mysql_adaptor_get_user_displayname,
	    mysql_adaptor_meta, m_auth_info.username, pbrief,
	    "BOUNCE_NOTIFY_READ", imail))
		return;
	auto ret = cu_send_vmail(std::move(imail), m_plugin.smtp_url.c_str(),
	           m_auth_info.username, rcpt_list);
	if (ret != ecSuccess)
		mlog(LV_ERR, "[ews] read receipt send: %s", mapi_strerror(ret));
	const TAGGED_PROPVAL propval_buff[] = {
		{PR_READ_RECEIPT_REQUESTED, deconst(&byte_value_zero)},
		{PR_NON_RECEIPT_NOTIFICATION_REQUESTED, deconst(&byte_value_zero)},
	};
	const TPROPVAL_ARRAY propvals = {std::size(propval_buff), deconst(propval_buff)};
	PROBLEM_ARRAY problems;
	m_plugin.exmdb.set_message_properties(dir.c_str(), nullptr,
		CP_ACP, mid, &propvals, &problems);
} catch (const std::exception &e) {
	mlog(LV_ERR, "[ews] read receipt: %s", e.what());
}

/**
 * @brief      Clear the receipt request of a message
 *
 * Makes notifyReadReceipt() a no-op for the message from now on.
 *
 * @param      refId   Item to suppress the read receipt for
 */
void EWSContext::suppressReadReceipt(const tItemId &refId) const
{
	assertIdType(refId.type, tItemId::ID_ITEM);
	sMessageEntryId mid(refId.Id.data(), refId.Id.size());
	sFolderSpec parent = resolveFolder(mid);
	std::string dir = getDir(parent);
	validate(dir, mid);
	auto rights = permissions(dir, parent.folderId);
	if (!(rights & frightsEditAny))
		throw EWSError::AccessDenied(E3527);
	assertCanReadPrivate(dir, parent, rights, mid.messageId());
	const TAGGED_PROPVAL propval_buff[] = {
		{PR_READ_RECEIPT_REQUESTED, deconst(&byte_value_zero)},
		{PR_NON_RECEIPT_NOTIFICATION_REQUESTED, deconst(&byte_value_zero)},
	};
	const TPROPVAL_ARRAY propvals = {std::size(propval_buff), deconst(propval_buff)};
	PROBLEM_ARRAY problems;
	if (!m_plugin.exmdb.set_message_properties(dir.c_str(),
	    effectiveUser(parent), CP_ACP, mid.messageId(), &propvals, &problems))
		throw EWSError::ItemSave(E3409);
}

/**
 * @brief      Whether the item is the organizer's copy of the meeting
 */
bool EWSContext::isOrganizer(const std::string &dir, uint64_t mid) const
{
	void *state = nullptr;
	auto tag = PROP_TAG(PT_LONG, getNamedPropId(dir, NtAppointmentStateFlags, true));
	if (!m_plugin.exmdb.get_message_property(dir.c_str(), nullptr, CP_ACP,
	    mid, tag, &state))
		throw EWSError::ItemNotFound(E3389);
	return state == nullptr ||
	       !(*static_cast<const uint32_t *>(state) & asfReceived);
}

/**
 * @brief      Cancel a meeting and remove it from the organizer's calendar
 *
 * @param      refId     Calendar item or occurrence to cancel
 * @param      saveCopy  Whether to keep a copy in Sent Items
 */
void EWSContext::cancelCalendarItem(const tItemId &refId, bool saveCopy) const
{
	if (refId.type != tItemId::ID_OCCURRENCE)
		assertIdType(refId.type, tItemId::ID_ITEM);
	sMessageEntryId meid(refId.Id.data(), refId.Id.size());
	sFolderSpec parent = resolveFolder(meid);
	std::string dir = getDir(parent);
	validate(dir, meid);
	auto rights = permissions(dir, parent.folderId);
	if (!(rights & frightsDeleteAny))
		throw EWSError::AccessDenied(E3131);
	assertCanReadPrivate(dir, parent, rights, meid.messageId());

	if (!isOrganizer(dir, meid.messageId()))
		throw EWSError::CalendarIsNotOrganizer(E3470);

	if (refId.type == tItemId::ID_OCCURRENCE) {
		auto basedate = sOccurrenceId(refId.Id.data(),
		                refId.Id.size()).basedate;
		checkOccurrence(dir, meid.messageId(), basedate);
		sendMeetingCancellation(dir, meid, parent, saveCopy, basedate);
		deleteOccurrence(dir, parent.folderId, meid.messageId(), basedate);
		return;
	}
	sendMeetingCancellation(dir, meid, parent, saveCopy);

	sFolderSpec deleted = resolveFolder(tDistinguishedFolderId(Enum::deleteditems));
	uint64_t new_mid = 0;
	if (!m_plugin.exmdb.allocate_message_id(dir.c_str(), deleted.folderId, &new_mid))
		throw EWSError::MoveCopyFailed(E3425);
	BOOL result = false;
	if (!m_plugin.exmdb.movecopy_message(dir.c_str(), CP_ACP, meid.messageId(),
	    deleted.folderId, new_mid, TRUE, &result) || !result)
		throw EWSError::CannotDeleteObject(E3471);
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
	auto buff = alloc<char>(xid.size);
	EXT_PUSH ext_push;
	if (!ext_push.init(buff, xid.size, 0) ||
	   ext_push.p_xid(xid) != pack_result::ok)
		throw DispatchError(E3357);
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
	if (!m_notify)
		return false;
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
message_content_ptr EWSContext::toContent(const std::string &dir,
    std::string &mimeContent) const
{
	MAIL mail;
	if (!mail.refonly_parse(mimeContent.data(), mimeContent.size()))
		throw EWSError::ItemCorrupt(E3123);
	oxcmail_converter cvt;
	cvt.alloc = EWSContext::alloc;
	cvt.get_propids = [&](const PROPNAME_ARRAY *names, PROPID_ARRAY *ids) {
	                  	*ids = getNamedPropIds(dir, *names, true);
	                  	return TRUE;
	                  };
	auto cnt = cvt.inet_to_mapi(mail);
	if (!cnt)
		throw EWSError::ItemCorrupt(E3124);
	return cnt;
}

/**
 * @brief      Add a file attachment to a new message
 *
 * @param      content  Message to add to
 * @param      file     Attachment to add
 */
void EWSContext::addAttachment(MESSAGE_CONTENT &content,
    const tFileAttachment &file)
{
	if (content.children.pattachments == nullptr) {
		auto list = attachment_list_init();
		if (list == nullptr)
			throw EWSError::NotEnoughMemory(E3570);
		content.set_attachments_internal(list);
	}
	auto ac = attachment_content_init();
	if (ac == nullptr)
		throw EWSError::NotEnoughMemory(E3570);
	if (!content.children.pattachments->append_internal(ac)) {
		attachment_content_free(ac);
		throw EWSError::ItemSave(E3571);
	}
	static constexpr uint32_t rendpos = UINT32_MAX;
	auto now = construct<mapitime_t>(rop_util_current_nttime());
	auto props = file.props();
	props.push_back({PR_RENDERING_POSITION, deconst(&rendpos)});
	props.push_back({PR_CREATION_TIME, now});
	props.push_back({PR_LAST_MODIFICATION_TIME, now});
	for (const auto &prop : props)
		if (ac->proplist.set(prop) != ecSuccess)
			throw EWSError::NotEnoughMemory(E3570);
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
message_content_ptr EWSContext::toContent(const std::string &dir,
    const sFolderSpec &parent, sCreateItem &item, bool persist) const
{
	const auto& exmdb = m_plugin.exmdb;
	uint64_t messageId, changeNumber;
	BINARY *ckey = nullptr, *pclbin = nullptr;

	if (persist) {
		if (!exmdb.allocate_message_id(dir.c_str(), parent.folderId, &messageId))
			throw DispatchError(E3118);
		if (!exmdb.allocate_cn(dir.c_str(), &changeNumber))
			throw DispatchError(E3119);

		bool isPublic = parent.location == parent.PUBLIC;
		uint32_t accountId = getAccountId(*parent.target, isPublic);
		XID xid{parent.location == parent.PRIVATE ?
			rop_util_make_user_guid(accountId) :
			rop_util_make_domain_guid(accountId), changeNumber};

		ckey = construct<BINARY>(serialize(xid));

		auto pcltemp = mkPCL(xid);
		auto pcldata = alloc<char>(pcltemp->cb);
		memcpy(pcldata, pcltemp->pc, pcltemp->cb);
		pclbin = construct<BINARY>(BINARY{pcltemp->cb, {pcldata}});
	}

	sShape shape;
	message_content_ptr content(message_content_init());
	if (!content)
		throw EWSError::NotEnoughMemory(E3217);
	std::visit([&](auto& i){toContent(dir, i, shape, content);}, item);

	if (!shape.writes(PR_LAST_MODIFICATION_TIME))
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFICATION_TIME, EWSContext::construct<uint64_t>(rop_util_current_nttime())});
	if (persist) {
		if (!shape.writes(PR_READ))
			/* Unless specified otherwise, newly created items should be marked as read */
			shape.write(TAGGED_PROPVAL{PR_READ, deconst(&byte_value_one)});
		shape.write(TAGGED_PROPVAL{PidTagMid, construct<uint64_t>(messageId)});
		shape.write(TAGGED_PROPVAL{PidTagChangeNumber, construct<uint64_t>(changeNumber)});
		shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, ckey});
		shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, pclbin});
	}
	getNamedTags(dir, shape, true);

	for (const TAGGED_PROPVAL &prop : shape.write()) {
		auto err = content->proplist.set(prop);
		if (err == ecServerOOM)
			throw EWSError::NotEnoughMemory(E3358);
	}
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
void EWSContext::toContent(const std::string &dir, tCalendarItem &item,
    sShape &shape, message_content_ptr &content) const
{
	toContent(dir, static_cast<tItem&>(item), shape, content);
	if (!item.ItemClass)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, deconst("IPM.Appointment")});
	int64_t startOffset = 0, endOffset = 0;
	time_t startTime = 0, endTime = 0;
	bool calcStartOffset = false, calcEndOffset = false;
	if (item.Start) {
		startTime = clock::to_time_t(item.Start.value().time);
		startOffset = std::chrono::duration_cast<std::chrono::minutes>(item.Start.value().offset).count();
		calcStartOffset = item.Start.value().needCalcOffset();
	}
	if (item.End) {
		endTime = clock::to_time_t(item.End.value().time);
		endOffset = std::chrono::duration_cast<std::chrono::minutes>(item.End.value().offset).count();
		calcEndOffset = item.End.value().needCalcOffset();
	}
	if (!item.Start || !item.End) {
		const char* missing = item.Start ? "End" : "Start";
		throw EWSError::ItemCorrupt(E3046(missing, "CalendarItem"));
	}

	if (!shape.writes(NtCalendarTimeZone)) {
		const auto &tz = item.timezoneId();
		if(!tz.empty())
			shape.write(NtCalendarTimeZone, TAGGED_PROPVAL{PT_UNICODE, cpystr(tz)});
	}

	if (item.IsAllDayEvent)
		shape.write(NtAppointmentSubType, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(item.IsAllDayEvent.value())});
	else
		shape.write(NtAppointmentSubType, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(0)});
	if (item.LegacyFreeBusyStatus)
		shape.write(NtBusyStatus, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(item.LegacyFreeBusyStatus->index())});
	else
		shape.write(NtBusyStatus, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(olBusy)});
	if (item.IsResponseRequested)
		shape.write(TAGGED_PROPVAL{PR_RESPONSE_REQUESTED, construct<uint32_t>(item.IsResponseRequested.value())});
	if (item.AllowNewTimeProposal)
		shape.write(NtAppointmentNotAllowPropose, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(!item.AllowNewTimeProposal.value())});
	if (item.Location)
		shape.write(NtLocation, TAGGED_PROPVAL{PT_UNICODE, deconst(item.Location.value().c_str())});

	uint8_t isrecurring = item.IsRecurring && item.IsRecurring.value() ? 1 : 0;

	if (item.Recurrence) {
		auto localStartTime = clock::to_time_t(item.Start.value().time);
		auto localEndTime = clock::to_time_t(item.End.value().time);
		bool isAllDay = item.IsAllDayEvent && item.IsAllDayEvent.value();
		/*
		 * For all-day events the duration must be a whole number of
		 * days. Round up to the next day boundary if not. (XXX: what
		 * about timezone change days that do not have a length of
		 * 86400s?)
		 */
		if (isAllDay && (localEndTime - localStartTime) % 86400 != 0) {
			auto days = (localEndTime - localStartTime + 86399) / 86400;
			localEndTime = localStartTime + days * 86400;
			endTime = localEndTime;
		}
		auto duration = localEndTime - localStartTime;
		struct tm startdate_tm;
		/*
		 * Use the RecurrenceRange's StartDate for the recurrence
		 * start. For all-day events, the Start field is midnight local
		 * time expressed in UTC (e.g. 23:00Z for CET), but the
		 * StartDate in the RecurrenceRange is the correct date-only
		 * value.
		 */
		if (auto tz = lookup_tz_get_tzdef(item.timezoneId().c_str());
		    tz && m_recurrence_frame) {
			time_t start = localStartTime;
			int64_t b;
			if (!calcStartOffset)
				start += static_cast<time_t>(startOffset) * 60;
			else if (tz_to_offset(*tz, start, b))
				start += b * 60;
			shift_recurrence(*item.Recurrence, *m_recurrence_frame, *tz, start);
		}
		auto &rr = item.Recurrence->RecurrenceRange;
		auto rangeStart = clock::to_time_t(std::visit(
		                  [](const auto &r) STATIC_IN_CXX23 { return r.StartDate; }, rr));
		if (gmtime_r(&rangeStart, &startdate_tm) == nullptr)
			throw EWSError::CalendarInvalidRecurrence(E3359);
		APPOINTMENT_RECUR_PAT apr{};

		if (isAllDay) {
			apr.starttimeoffset = 0;
			apr.endtimeoffset = duration / 60;
		} else {
			/*
			 * The blob stores times in the appointment's local
			 * timezone. Compute the local appointment time:
			 *
			 * - calcStartOffset=true: client sent time without TZ
			 *   suffix, so .time already *is* in local time.
			 * - calcStartOffset=false: client sent explicit TZ,
			 *   compute real UTC (time+offset), then convert to
			 *   local via calendar timezone bias.
			 */
			time_t appt_local;
			if (calcStartOffset) {
				appt_local = localStartTime;
			} else {
				int64_t tz_off = 0;
				/*
				 * Read timezone name directly from the item
				 * rather than shape – the shape's named
				 * property cache has not been resolved yet.
				 */
				const auto &tz = item.timezoneId();
				if (!tz.empty()) {
					auto offset = lookup_tz_get_offset(tz.c_str(), localStartTime);
					if (offset)
						tz_off = *offset;
				}
				auto real_utc = localStartTime + static_cast<time_t>(startOffset) * 60;
				appt_local    = real_utc - static_cast<time_t>(tz_off) * 60;
			}
			struct tm start_tm;
			gmtime_r(&appt_local, &start_tm);
			apr.starttimeoffset = 60 * start_tm.tm_hour + start_tm.tm_min;
			apr.endtimeoffset   = apr.starttimeoffset + duration / 60;
		}
		startdate_tm.tm_hour = 0;
		startdate_tm.tm_min = 0;
		startdate_tm.tm_sec = 0;
		time_t startdate = timegm(&startdate_tm);
		apr.recur_pat.startdate = rop_util_unix_to_rtime(startdate);
		uint8_t rectype = rectypeNone;
		auto& rp = item.Recurrence->RecurrencePattern;

		if (std::holds_alternative<tDailyRecurrencePattern>(rp)) {
			auto interval = std::get<tDailyRecurrencePattern>(rp).Interval;
			if (interval < 1 || interval > 999)
				throw EWSError::CalendarInvalidRecurrence(E3360);
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_DAILY;
			apr.recur_pat.patterntype = rptMinute;
			apr.recur_pat.period = interval * 1440;
			rectype = rectypeDaily;
		} else if (std::holds_alternative<tWeeklyRecurrencePattern>(rp)) {
			auto interval = std::get<tWeeklyRecurrencePattern>(rp).Interval;
			if (interval < 1 || interval > 99)
				throw EWSError::CalendarInvalidRecurrence(E3361);
			auto firstdow = 1; // TODO get from user settings?
			if (std::get<tWeeklyRecurrencePattern>(rp).FirstDayOfWeek)
				firstdow = std::get<tWeeklyRecurrencePattern>(rp).FirstDayOfWeek->index();
			if (firstdow > 6)
				throw EWSError::CalendarInvalidRecurrence(E3362);

			const auto& daysOfWeek = std::get<tWeeklyRecurrencePattern>(rp).DaysOfWeek;
			apr.recur_pat.pts.weekrecur = 0;
			daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.weekrecur);
			if (apr.recur_pat.pts.weekrecur == 0)
				throw EWSError::CalendarInvalidRecurrence(E3363);

			// every weekday has daily frequency and weekly pattern type
			apr.recur_pat.recurfrequency = apr.recur_pat.pts.weekrecur != 0x3E ?
				IDC_RCEV_PAT_ORB_WEEKLY : IDC_RCEV_PAT_ORB_DAILY;
			apr.recur_pat.patterntype = rptWeek;
			apr.recur_pat.period = interval;
			apr.recur_pat.firstdow = firstdow;
			rectype = rectypeWeekly;
		} else if (std::holds_alternative<tRelativeMonthlyRecurrencePattern>(rp)) {
			auto interval = std::get<tRelativeMonthlyRecurrencePattern>(rp).Interval;
			if (interval < 1 || interval > 99)
				throw EWSError::CalendarInvalidRecurrence(E3364);

			const auto& daysOfWeek = std::get<tRelativeMonthlyRecurrencePattern>(rp).DaysOfWeek;
			apr.recur_pat.pts.monthnth.weekrecur = 0;
			daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.monthnth.weekrecur);
			if (apr.recur_pat.pts.monthnth.weekrecur == 0)
				throw EWSError::CalendarInvalidRecurrence(E3365);
			auto dayOfWeekIndex = std::get<tRelativeMonthlyRecurrencePattern>(rp).DayOfWeekIndex.index();
			if (dayOfWeekIndex > 4)
				throw EWSError::CalendarInvalidRecurrence(E3366);

			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
			apr.recur_pat.patterntype = rptMonthNth;
			apr.recur_pat.period = interval;
			apr.recur_pat.pts.monthnth.recurnum = static_cast<uint8_t>(dayOfWeekIndex) + 1;
			rectype = rectypeMonthly;
		} else if (std::holds_alternative<tAbsoluteMonthlyRecurrencePattern>(rp)) {
			auto interval = std::get<tAbsoluteMonthlyRecurrencePattern>(rp).Interval;
			if (interval < 1 || interval > 99)
				throw EWSError::CalendarInvalidRecurrence(E3367);
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_MONTHLY;
			apr.recur_pat.patterntype = rptMonth;
			apr.recur_pat.period = interval;
			apr.recur_pat.pts.dayofmonth = std::get<tAbsoluteMonthlyRecurrencePattern>(rp).DayOfMonth;
			if (apr.recur_pat.pts.dayofmonth < 1 || apr.recur_pat.pts.dayofmonth > 31)
				throw EWSError::CalendarInvalidRecurrence(E3368);
			rectype = rectypeMonthly;
		} else if (std::holds_alternative<tRelativeYearlyRecurrencePattern>(rp)) {
			const auto& daysOfWeek = std::get<tRelativeYearlyRecurrencePattern>(rp).DaysOfWeek;
			apr.recur_pat.pts.monthnth.weekrecur = 0;
			daysofweek_to_pts(daysOfWeek, apr.recur_pat.pts.monthnth.weekrecur);
			if (apr.recur_pat.pts.monthnth.weekrecur == 0)
				throw EWSError::CalendarInvalidRecurrence(E3369);
			auto dayOfWeekIndex = std::get<tRelativeYearlyRecurrencePattern>(rp).DayOfWeekIndex.index();
			auto month = std::get<tRelativeYearlyRecurrencePattern>(rp).Month.index();
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
			apr.recur_pat.patterntype = rptMonthNth;
			apr.recur_pat.period = 12;
			apr.recur_pat.pts.monthnth.recurnum = static_cast<uint8_t>(dayOfWeekIndex) + 1;
			rectype = rectypeYearly;
			startdate_tm.tm_mon = month;
		} else if (std::holds_alternative<tAbsoluteYearlyRecurrencePattern>(rp)) {
			auto month = std::get<tAbsoluteYearlyRecurrencePattern>(rp).Month.index();
			apr.recur_pat.recurfrequency = IDC_RCEV_PAT_ORB_YEARLY;
			apr.recur_pat.patterntype = rptMonth;
			apr.recur_pat.period = 12;
			apr.recur_pat.pts.dayofmonth = std::get<tAbsoluteYearlyRecurrencePattern>(rp).DayOfMonth;
			if (apr.recur_pat.pts.dayofmonth < 1 || apr.recur_pat.pts.dayofmonth > 31)
				throw EWSError::CalendarInvalidRecurrence(E3370);
			rectype = rectypeYearly;
			startdate_tm.tm_mon = month;
		} else {
			throw EWSError::CalendarInvalidRecurrence(E3371);
		}

		calc_firstdatetime(apr.recur_pat, &startdate_tm);
		if (std::holds_alternative<tNoEndRecurrenceRange>(rr)) {
			apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_NOEND;
			apr.recur_pat.occurrencecount = 0xA; // value for a recurring series with no end date
			apr.recur_pat.enddate = ENDDATE_MISSING;
		} else if (std::holds_alternative<tEndDateRecurrenceRange>(rr)) {
			apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_END;
			apr.recur_pat.occurrencecount = 0xA; // TODO count occurrences, but this field doesn't really matter
			auto ed = std::get<tEndDateRecurrenceRange>(rr).EndDate;
			auto enddate = clock::to_time_t(ed);
			apr.recur_pat.enddate = rop_util_unix_to_rtime(enddate);
		} else if (std::holds_alternative<tNumberedRecurrenceRange>(rr)) {
			apr.recur_pat.endtype = IDC_RCEV_PAT_ERB_AFTERNOCCUR;
			apr.recur_pat.occurrencecount = std::get<tNumberedRecurrenceRange>(rr).NumberOfOccurrences;
			calc_enddate(apr.recur_pat, &startdate_tm);
		} else {
			throw EWSError::CalendarInvalidRecurrence(E3372);
		}

		BINARY tmp_bin;
		EXT_PUSH ext_push;

		if (!ext_push.init(nullptr, 0, EXT_FLAG_UTF16) ||
		    ext_push.p_apptrecpat(apr) != pack_result::ok)
			throw EWS::DispatchError(E3373);
		tmp_bin.cb = ext_push.m_offset;
		tmp_bin.pb = ext_push.m_udata;

		// copy the data from ext_push, so it is not lost when ext_push goes out of scope
		auto recurdata = alloc<char>(tmp_bin.cb);
		memcpy(recurdata, tmp_bin.pc, tmp_bin.cb);

		isrecurring = 1;
		shape.write(NtRecurrenceType, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(rectype)});
		shape.write(NtAppointmentRecur, TAGGED_PROPVAL{PT_BINARY, construct<BINARY>(BINARY{tmp_bin.cb, {recurdata}})});
		auto item_tz = lookup_tz_get_tzdef(item.timezoneId().c_str());
		auto clipstart = EWSContext::construct<uint64_t>(clip_time(item_tz, apr.recur_pat.startdate));
		shape.write(NtClipStart, TAGGED_PROPVAL{PT_SYSTIME, clipstart});
		auto clipend = EWSContext::construct<uint64_t>(clip_time(item_tz, apr.recur_pat.enddate));
		shape.write(NtClipEnd, TAGGED_PROPVAL{PT_SYSTIME, clipend});
	}
	shape.write(NtRecurring, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint32_t>(isrecurring)});

	/*
	 * Read timezone name directly from item rather than shape – the
	 * shape's named property cache has not been resolved yet at this
	 * point, so shape.writes(NtCalendarTimeZone) would return nullptr even
	 * though the value was written above.
	 */
	const auto &tz = item.timezoneId();
	if (!tz.empty()) {
		auto buf = lookup_tz_get_sv(tz.c_str());
		if (buf == nullptr)
			mlog(LV_DEBUG, "[ews] %s:m?: unknown timezone \"%s\"",
				dir.c_str(), tz.c_str());
		if (buf != nullptr) {
			size_t len = buf->size();
			if (len > UINT32_MAX)
				throw InputError(E3293);
			auto temp_bin = construct<BINARY>(BINARY{static_cast<uint32_t>(len), {deconst(buf->data())}});
			shape.write(NtAppointmentTimeZoneDefinitionStartDisplay,
				TAGGED_PROPVAL{PT_BINARY, temp_bin});
			shape.write(NtAppointmentTimeZoneDefinitionEndDisplay,
				TAGGED_PROPVAL{PT_BINARY, temp_bin});
			shape.write(NtAppointmentTimeZoneDefinitionRecur,
				TAGGED_PROPVAL{PT_BINARY, temp_bin});

			auto tzdef = EXT_PULL::bin_to_tzdef(*buf);
			if (!tzdef)
				throw EWS::DispatchError(E3294);

			/*
			 * Write PidLidTimeZoneStruct – the freebusy and
			 * recurrence expansion code uses this to determine the
			 * timezone of times in the recurrence blob.
			 */
			if (tzdef->rules.size() > 0) {
				TZSTRUCT tzs{};
				auto &rule = tzdef->rules.back();
				tzs.bias = rule.bias;
				tzs.daylightbias = rule.daylightbias;
				tzs.standarddate = rule.standarddate;
				tzs.daylightdate = rule.daylightdate;
				tzs.standardyear = tzs.standarddate.year;
				tzs.daylightyear = tzs.daylightdate.year;
				auto tzdata = alloc<char>(48);
				EXT_PUSH ep;
				if (ep.init(tzdata, 48, 0) &&
				    ep.p_tzstruct(tzs) == pack_result::ok)
					shape.write(NtTimeZoneStruct,
						TAGGED_PROPVAL{PT_BINARY,
						construct<BINARY>(BINARY{ep.m_offset, {tzdata}})});
			}

			if ((startOffset == 0 && calcStartOffset) &&
			    !tz_to_offset(*tzdef, startTime, startOffset))
				throw EWSError::TimeZone(E3300);
			if ((endOffset == 0 && calcEndOffset) &&
			    !tz_to_offset(*tzdef, endTime, endOffset))
				throw EWSError::TimeZone(E3374);
			item.Start.value().offset = std::chrono::minutes(startOffset);
			item.End.value().offset = std::chrono::minutes(endOffset);
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
	if (item.ReminderMinutesBeforeStart)
		reminderdelta = item.ReminderMinutesBeforeStart.value();
	shape.write(NtReminderDelta, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(reminderdelta)});
	shape.write(NtReminderSignalTime, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(
		rop_util_unix_to_nttime(startTime + (startOffset - reminderdelta) * 60))});

	shape.write(NtPrivate, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint8_t>(
		item.Sensitivity && item.Sensitivity->index() >= 2 ? 1 : 0)});

	if (item.UID) {
		BINARY goid_bin;
		auto uid = item.UID.value().c_str();
		uid_to_goid(uid, goid_bin);
		auto goid = construct<BINARY>(BINARY{goid_bin.cb, {goid_bin.pc}});
		shape.write(NtGlobalObjectId, TAGGED_PROPVAL{PT_BINARY, goid});
		shape.write(NtCleanGlobalObjectId, TAGGED_PROPVAL{PT_BINARY, goid});
	} else if (!shape.writes(NtGlobalObjectId)) {
		GLOBALOBJECTID goid{};
		goid.arrayid = EncodedGlobalId;
		goid.creationtime = rop_util_unix_to_nttime(time(nullptr));
		goid.data.cb = 16;
		goid.data.pb = alloc<uint8_t>(16);
		EXT_PUSH ep;
		char buf[256];
		if (!ep.init(goid.data.pb, 16, 0) ||
		    ep.p_guid(GUID::random_new()) != pack_result::ok ||
		    !ep.init(buf, sizeof(buf), 0) ||
		    ep.p_goid(goid) != pack_result::ok)
			throw EWSError::InternalServerError(E3375);
		auto gdata = alloc<char>(ep.m_offset);
		memcpy(gdata, ep.m_cdata, ep.m_offset);
		auto gb = construct<BINARY>(BINARY{ep.m_offset, {gdata}});
		shape.write(NtGlobalObjectId, TAGGED_PROPVAL{PT_BINARY, gb});
		shape.write(NtCleanGlobalObjectId, TAGGED_PROPVAL{PT_BINARY, gb});
	}

	size_t recipients = 0;
	for (const auto &list : {&item.RequiredAttendees, &item.OptionalAttendees, &item.Resources})
		if (*list)
			recipients += std::count_if((*list)->begin(), (*list)->end(),
			              [](const tAttendee &a) { return !a.empty_address(); });
	if (recipients) {
		if (!content->children.prcpts && !(content->children.prcpts = tarray_set_init()))
			throw EWSError::NotEnoughMemory(E3377);
		TARRAY_SET* rcpts = content->children.prcpts;
		auto add_attendee = [](TPROPVAL_ARRAY *rcpt, const tAttendee &att, uint32_t type) STATIC_IN_CXX23 {
			att.Mailbox.mkRecipient(rcpt, type);
			static constexpr uint32_t sendable = recipSendable;
			if (rcpt->set(PR_RECIPIENT_FLAGS, &sendable) != ecSuccess)
				throw EWSError::NotEnoughMemory(E3377);
		};
		if (item.RequiredAttendees)
			for (const auto &att : *item.RequiredAttendees)
				if (!att.empty_address())
					add_attendee(rcpts->emplace(), att, MAPI_TO);
		if (item.OptionalAttendees)
			for (const auto &att : *item.OptionalAttendees)
				if (!att.empty_address())
					add_attendee(rcpts->emplace(), att, MAPI_CC);
		if (item.Resources)
			for (const auto &att : *item.Resources)
				if (!att.empty_address())
					add_attendee(rcpts->emplace(), att, MAPI_BCC);
		for (const auto &prop : meetingIdentity(dir))
			shape.write(prop);
		/* MS-OXOCAL v22.1 §2.2.1.9/10/11 */
		auto meetType = construct<uint32_t>(mtgRequest);
		auto apptState = construct<uint32_t>(asfMeeting);
		auto respStatus = construct<uint32_t>(respOrganized);
		shape.write(NtMeetingType, TAGGED_PROPVAL{PT_LONG, meetType});
		shape.write(NtAppointmentStateFlags, TAGGED_PROPVAL{PT_LONG, apptState});
		shape.write(NtResponseStatus, TAGGED_PROPVAL{PT_LONG, respStatus});
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
void EWSContext::toContent(const std::string &dir, tContact &item,
    sShape &shape, message_content_ptr &content) const
{
	toContent(dir, static_cast<tItem&>(item), shape, content);
	shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, const_cast<char*>("IPM.Contact")});
	if (item.CompleteName) {
		writeProp(shape, item.CompleteName->Title, PR_TITLE);
		writeProp(shape, item.CompleteName->FirstName, PR_GIVEN_NAME);
		writeProp(shape, item.CompleteName->MiddleName, PR_MIDDLE_NAME);
		writeProp(shape, item.CompleteName->LastName, PR_SURNAME);
		writeProp(shape, item.CompleteName->Suffix, PR_GENERATION);
		writeProp(shape, item.CompleteName->Initials, PR_INITIALS);
		writeProp(shape, item.CompleteName->FullName, PR_DISPLAY_NAME);
		writeProp(shape, item.CompleteName->Nickname, PR_NICKNAME);
		writeProp(shape, item.CompleteName->YomiFirstName,
		          NtYomiFirstName, PT_UNICODE);
		writeProp(shape, item.CompleteName->YomiLastName,
		          NtYomiLastName, PT_UNICODE);
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
	writeProp(shape, item.Manager, PR_MANAGER_NAME);
	writeProp(shape, item.OfficeLocation, PR_OFFICE_LOCATION);
	writeProp(shape, item.Profession, PR_PROFESSION);
	writeProp(shape, item.SpouseName, PR_SPOUSE_NAME);
	writeProp(shape, item.Surname, PR_SURNAME);
	writeProp(shape, item.WeddingAnniversary, PR_WEDDING_ANNIVERSARY);
	writeProp(shape, item.YomiCompanyName, NtYomiCompanyName, PT_UNICODE);

	if (!shape.writes(PR_DISPLAY_NAME)) {
		std::string dn;
		if (item.GivenName)
			dn = *item.GivenName;
		if (item.Surname) {
			if (!dn.empty())
				dn += ' ';
			dn += *item.Surname;
		}
		if (!dn.empty())
			shape.write(TAGGED_PROPVAL{PR_DISPLAY_NAME, cpystr(dn)});
	}
	if (item.FileAs)
		shape.write(NtFileAs, TAGGED_PROPVAL{PT_UNICODE, cpystr(*item.FileAs)});
	else if (!shape.writes(NtFileAs) && item.DisplayName)
		shape.write(NtFileAs, TAGGED_PROPVAL{PT_UNICODE, cpystr(*item.DisplayName)});
	if (auto id = item.FileAsMapping ? tContact::fileUnderId(*item.FileAsMapping) : std::nullopt)
		shape.write(NtFileUnderId, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(*id)});
	if (item.PostalAddressIndex)
		shape.write(NtPostalAddressIndex, TAGGED_PROPVAL{PT_LONG, construct<uint32_t>(item.PostalAddressIndex->index())});
	if (item.EmailAddresses)
		for (const tEmailAddressDictionaryEntry &entry : *item.EmailAddresses) {
			const PROPERTY_NAME &addrName = entry.Key == Enum::EmailAddress1 ? NtEmailAddress1 :
			                                entry.Key == Enum::EmailAddress2 ? NtEmailAddress2 :
			                                NtEmailAddress3;
			const PROPERTY_NAME &dispName = entry.Key == Enum::EmailAddress1 ? NtEmailDisplayName1 :
			                                entry.Key == Enum::EmailAddress2 ? NtEmailDisplayName2 :
			                                NtEmailDisplayName3;
			const PROPERTY_NAME &typeName = entry.Key == Enum::EmailAddress1 ? NtEmailAddressType1 :
			                                entry.Key == Enum::EmailAddress2 ? NtEmailAddressType2 :
			                                NtEmailAddressType3;
			shape.write(addrName, TAGGED_PROPVAL{PT_UNICODE, const_cast<char*>(entry.Entry.c_str())});
			const char *addrType = entry.RoutingType ? entry.RoutingType->c_str() : "SMTP";
			shape.write(typeName, TAGGED_PROPVAL{PT_UNICODE, const_cast<char*>(addrType)});
			const char *displayName = entry.Name ? entry.Name->c_str() : entry.Entry.c_str();
			shape.write(dispName, TAGGED_PROPVAL{PT_UNICODE, const_cast<char*>(displayName)});
		}
	if (item.ImAddresses)
		for (const tImAddressDictionaryEntry &entry : *item.ImAddresses)
			if (entry.Key == Enum::ImAddress1)
				shape.write(NtImAddress1, TAGGED_PROPVAL{PT_UNICODE, const_cast<char *>(entry.Entry.c_str())});
	if (item.PhysicalAddresses)
		for (const tPhysicalAddressDictionaryEntry &entry : *item.PhysicalAddresses) {
			std::string address = item.mkAddress(entry.Street, entry.City, entry.State, entry.PostalCode,
			                                     entry.CountryOrRegion);
			if (entry.Key == Enum::Business) {
				writeProp(shape, entry.City, NtBusinessAddressCity, PT_UNICODE);
				writeProp(shape, entry.CountryOrRegion, NtBusinessAddressCountry, PT_UNICODE);
				writeProp(shape, entry.PostalCode, NtBusinessAddressPostalCode, PT_UNICODE);
				writeProp(shape, entry.State, NtBusinessAddressState, PT_UNICODE);
				writeProp(shape, entry.Street, NtBusinessAddressStreet, PT_UNICODE);
				shape.write(NtBusinessAddress, TAGGED_PROPVAL{PT_UNICODE, cpystr(address)});
			} else if (entry.Key == Enum::Home) {
				writeProp(shape, entry.City, PR_HOME_ADDRESS_CITY);
				writeProp(shape, entry.CountryOrRegion, PR_HOME_ADDRESS_COUNTRY);
				writeProp(shape, entry.PostalCode, PR_HOME_ADDRESS_POSTAL_CODE);
				writeProp(shape, entry.State, PR_HOME_ADDRESS_STATE_OR_PROVINCE);
				writeProp(shape, entry.Street, PR_HOME_ADDRESS_STREET);
				shape.write(NtHomeAddress, TAGGED_PROPVAL{PT_UNICODE, cpystr(address)});
			} else if (entry.Key == Enum::Other) {
				writeProp(shape, entry.City, PR_OTHER_ADDRESS_CITY);
				writeProp(shape, entry.CountryOrRegion, PR_OTHER_ADDRESS_COUNTRY);
				writeProp(shape, entry.PostalCode, PR_OTHER_ADDRESS_POSTAL_CODE);
				writeProp(shape, entry.State, PR_OTHER_ADDRESS_STATE_OR_PROVINCE);
				writeProp(shape, entry.Street, PR_OTHER_ADDRESS_STREET);
				shape.write(NtOtherAddress, TAGGED_PROPVAL{PT_UNICODE, cpystr(address)});
			}
		}
	if (item.PhoneNumbers)
		for (const tPhoneNumberDictionaryEntry &entry : *item.PhoneNumbers) {
			proptag_t tag;
			switch(entry.Key) {
			case 0: tag = PR_ASSISTANT_TELEPHONE_NUMBER; break;
			case 1: tag = PR_BUSINESS_FAX_NUMBER; break;
			case 2: tag = PR_BUSINESS_TELEPHONE_NUMBER; break;
			case 3: tag = PR_BUSINESS2_TELEPHONE_NUMBER; break;
			case 4: tag = PR_CALLBACK_TELEPHONE_NUMBER; break;
			case 5: tag = PR_CAR_TELEPHONE_NUMBER; break;
			case 6: tag = PR_COMPANY_MAIN_PHONE_NUMBER; break;
			case 7: tag = PR_HOME_FAX_NUMBER; break;
			case 8: tag = PR_HOME_TELEPHONE_NUMBER; break;
			case 9: tag = PR_HOME2_TELEPHONE_NUMBER; break;
			case 10: tag = PR_ISDN_NUMBER; break;
			case 11: tag = PR_MOBILE_TELEPHONE_NUMBER; break;
			case 12: tag = PR_PRIMARY_FAX_NUMBER; break;
			case 13: tag = PR_OTHER_TELEPHONE_NUMBER; break;
			case 14: tag = PR_PAGER_TELEPHONE_NUMBER; break;
			case 15: tag = PR_PRIMARY_TELEPHONE_NUMBER; break;
			case 16: tag = PR_RADIO_TELEPHONE_NUMBER; break;
			case 17: tag = PR_TELEX_NUMBER; break;
			case 18: tag = PR_TTYTDD_PHONE_NUMBER; break;
			default: continue;
			}
			shape.write(TAGGED_PROPVAL{tag, const_cast<char*>(entry.Entry.c_str())});
		}
	if (item.Children) {
		if (item.Children->size() > UINT32_MAX)
			throw InputError(E3258);
		STRING_ARRAY* sa = construct<STRING_ARRAY>(STRING_ARRAY{static_cast<uint32_t>(item.Children->size()),
		                                                        alloc<char*>(item.Children->size())});
		auto it = sa->begin();
		for (const std::string &child : *item.Children)
			*it++ = const_cast<char*>(child.c_str());
		shape.write(TAGGED_PROPVAL{PR_CHILDRENS_NAMES, sa});
	}
}

/**
 * @brief      Write task properties to shape
 *
 * @param      dir       Home directory of the target store
 * @param      item      Task item to create
 * @param      shape     Shape to store properties in
 * @param      content   Message content
 */
void EWSContext::toContent(const std::string &dir, tTask &item, sShape &shape,
    message_content_ptr &content) const
{
	toContent(dir, static_cast<tItem &>(item), shape, content);
	if (!item.ItemClass)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, deconst("IPM.Task")});
	if (item.ActualWork)
		shape.write(NtTaskActualEffort, TAGGED_PROPVAL{PT_LONG,
		            construct<int32_t>(*item.ActualWork)});
	writeProp(shape, item.BillingInformation, NtBilling, PT_UNICODE);
	if (item.Companies && !item.Companies->empty() &&
	    item.Companies->size() <= UINT32_MAX) {
		uint32_t count = item.Companies->size();
		auto sa = construct<STRING_ARRAY>(STRING_ARRAY{count,
		          alloc<char *>(count)});
		char **dest = sa->ppstr;
		for (const std::string &c : *item.Companies)
			*dest++ = deconst(c.c_str());
		shape.write(NtCompanies, TAGGED_PROPVAL{PT_MV_UNICODE, sa});
	}
	if (item.CompleteDate)
		shape.write(NtTaskDateCompleted, TAGGED_PROPVAL{PT_SYSTIME,
		            construct<uint64_t>(toNT(*item.CompleteDate))});
	if (item.DueDate)
		shape.write(NtTaskDueDate, TAGGED_PROPVAL{PT_SYSTIME,
		            construct<uint64_t>(toNT(*item.DueDate))});
	if (item.StartDate)
		shape.write(NtTaskStartDate, TAGGED_PROPVAL{PT_SYSTIME,
		            construct<uint64_t>(toNT(*item.StartDate))});
	if (item.IsComplete)
		shape.write(NtTaskComplete, TAGGED_PROPVAL{PT_BOOLEAN,
		            construct<uint8_t>(*item.IsComplete ? 1 : 0)});
	writeProp(shape, item.Mileage, NtMileage, PT_UNICODE);
	writeProp(shape, item.Owner, NtTaskOwner, PT_UNICODE);
	if (item.PercentComplete)
		shape.write(NtPercentComplete, TAGGED_PROPVAL{PT_DOUBLE,
		            construct<double>(*item.PercentComplete / 100.0)});
	if (item.Status) {
		uint32_t st = tsvNotStarted;
		if (*item.Status == Enum::InProgress)
			st = tsvInProgress;
		else if (*item.Status == Enum::Completed)
			st = tsvComplete;
		else if (*item.Status == Enum::WaitingOnOthers)
			st = tsvWaiting;
		else if (*item.Status == Enum::Deferred)
			st = tsvDeferred;
		shape.write(NtTaskStatus, TAGGED_PROPVAL{PT_LONG,
		            construct<uint32_t>(st)});
	}
	if (item.TotalWork)
		shape.write(NtTaskEstimatedEffort, TAGGED_PROPVAL{PT_LONG,
		            construct<int32_t>(*item.TotalWork)});
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
 */
void EWSContext::toContent(const std::string &dir, tItem &item, sShape &shape,
    message_content_ptr &content) const
{
	if (item.MimeContent)
		content = toContent(dir, *item.MimeContent);
	if (item.Attachments)
		for (const auto &att : *item.Attachments) {
			auto file = std::get_if<tFileAttachment>(&att);
			if (file == nullptr)
				throw EWSError::ItemSave(E3572);
			addAttachment(*content, *file);
		}
	if (item.Body) {
		auto body = item.Body.value().c_str();
		if (item.Body.value().BodyType == Enum::Text) {
			shape.write(TAGGED_PROPVAL{PR_BODY, deconst(body)});
		} else if (item.Body.value().BodyType == Enum::HTML) {
			size_t bodylen = strlen(body);
			if (bodylen > UINT32_MAX)
				throw InputError(E3256);
			auto html = construct<BINARY>(BINARY{static_cast<uint32_t>(bodylen), {deconst(body)}});
			shape.write(TAGGED_PROPVAL{PR_HTML, html});
		}
		shape.write(TAGGED_PROPVAL{PR_INTERNET_CPID, construct<uint32_t>(CP_UTF8)});
	}
	if (item.ItemClass)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, deconst(item.ItemClass->c_str())});
	if (item.Sensitivity)
		shape.write(TAGGED_PROPVAL{PR_SENSITIVITY, construct<uint32_t>(item.Sensitivity->index())});
	if (item.Categories && item.Categories->size() &&
	    item.Categories->size() <= UINT32_MAX) {
		uint32_t count = item.Categories->size();
		STRING_ARRAY* categories = construct<STRING_ARRAY>(STRING_ARRAY{count, alloc<char*>(count)});
		char** dest = categories->ppstr;
		for (const std::string &category : *item.Categories) {
			*dest = alloc<char>(category.size() + 1);
			HX_strlcpy(*dest++, category.c_str(), category.size() + 1);
		}
		shape.write(NtCategories, TAGGED_PROPVAL{PT_MV_UNICODE, categories});
	}
	if (item.Importance)
		shape.write(TAGGED_PROPVAL{PR_IMPORTANCE, construct<uint32_t>(item.Importance->index())});
	if (item.Subject)
		shape.write(TAGGED_PROPVAL{PR_SUBJECT, deconst(item.Subject->c_str())});
	if (item.InReplyTo)
		shape.write(TAGGED_PROPVAL{PR_IN_REPLY_TO_ID, deconst(item.InReplyTo->c_str())});
	writeBoolProp(shape, item.IsAssociated, PR_ASSOCIATED);

	std::optional<uint32_t> messageFlags;
	auto applyFlag = [&](const std::optional<bool>& flag, uint32_t mask) {
		if (!flag)
			return;
		if (!messageFlags)
			messageFlags.emplace(0);
		if (*flag)
			*messageFlags |= mask;
	};
	applyFlag(item.IsSubmitted, MSGFLAG_SUBMITTED);
	applyFlag(item.IsDraft, MSGFLAG_UNSENT);
	applyFlag(item.IsFromMe, MSGFLAG_FROMME);
	applyFlag(item.IsResend, MSGFLAG_RESEND);
	applyFlag(item.IsUnmodified, MSGFLAG_UNMODIFIED);
	if (messageFlags)
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_FLAGS, construct<uint32_t>(*messageFlags)});

	if (item.ReminderDueBy) {
		auto reminderNt = toNT(*item.ReminderDueBy);
		shape.write(NtReminderTime, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(reminderNt)});
		shape.write(NtReminderSignalTime, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(reminderNt)});
	}
	if (item.ReminderIsSet)
		shape.write(NtReminderSet, TAGGED_PROPVAL{PT_BOOLEAN, construct<uint8_t>(*item.ReminderIsSet ? 1 : 0)});
	if (item.ReminderMinutesBeforeStart)
		shape.write(NtReminderDelta, TAGGED_PROPVAL{PT_LONG, construct<int32_t>(*item.ReminderMinutesBeforeStart)});
	if (item.Flag) {
		uint32_t status = 0;
		bool setStatus = false;
		if (item.Flag->FlagStatus == Enum::Flagged) {
			status = followupFlagged;
			setStatus = true;
		} else if (item.Flag->FlagStatus == Enum::Complete) {
			status = followupComplete;
			setStatus = true;
		}
		if (setStatus)
			shape.write(TAGGED_PROPVAL{PR_FLAG_STATUS, construct<uint32_t>(status)});
		if (item.Flag->StartDate)
			shape.write(NtTaskStartDate, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(toNT(*item.Flag->StartDate))});
		if (item.Flag->DueDate)
			shape.write(NtTaskDueDate, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(toNT(*item.Flag->DueDate))});
		if (item.Flag->CompleteDate)
			shape.write(NtTaskDateCompleted, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(toNT(*item.Flag->CompleteDate))});
	}

	auto now = EWSContext::construct<mapitime_t>(rop_util_current_nttime());
	shape.write(TAGGED_PROPVAL{PR_CREATION_TIME, now});
	shape.write(TAGGED_PROPVAL{PR_LOCAL_COMMIT_TIME, now});

	for (const tExtendedProperty &prop : item.ExtendedProperty)
		if (prop.ExtendedFieldURI.tag())
			shape.write(prop.propval);
		else
			shape.write(prop.ExtendedFieldURI.name(), prop.propval);
}

void EWSContext::rcpt_add_unique(TARRAY_SET *rcpts, tEmailAddressType rcpt, uint32_t type) const
{
	if (rcpt.EmailAddress)
		/* Normalize EX->SMTP for comparison */
		normalize(rcpt);
	const char *needle = rcpt.EmailAddress ? rcpt.EmailAddress->c_str() : nullptr;
	if (needle != nullptr) {
		for (const auto &row : *rcpts) {
			auto rtype = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
			if (rtype == nullptr || *rtype != type)
				continue;
			/* Prefer PR_SMTP_ADDRESS for comparison; fall back to SMTP PR_EMAIL_ADDRESS */
			auto smtp = row.get<const char>(PR_SMTP_ADDRESS);
			if (smtp == nullptr) {
				auto at = row.get<const char>(PR_ADDRTYPE);
				auto em = row.get<const char>(PR_EMAIL_ADDRESS);
				if (at != nullptr && em != nullptr && strcasecmp(at, "SMTP") == 0)
					smtp = em;
			}
			if (smtp != nullptr && strcasecmp(smtp, needle) == 0)
				return;
		}
	}
	/* Not found: add recipient and record SMTP address if available */
	auto row = rcpts->emplace();
	rcpt.mkRecipient(row, type);
	if (needle != nullptr) {
		auto err = row->set(PR_SMTP_ADDRESS, needle);
		if (err == ecServerOOM || err == ecMAPIOOM)
			throw EWSError::NotEnoughMemory(E3291);
	}
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
 */
void EWSContext::toContent(const std::string &dir, tMessage &item,
    sShape &shape, message_content_ptr &content) const
{
	auto &to = item.ToRecipients, &cc = item.CcRecipients, &bcc = item.BccRecipients;
	toContent(dir, static_cast<tItem&>(item), shape, content);
	if (!item.ItemClass && !content->proplist.has(PR_MESSAGE_CLASS))
		shape.write(TAGGED_PROPVAL{PR_MESSAGE_CLASS, deconst("IPM.Note")});
	size_t recipients = (to ? to->size() : 0) +
	                    (cc ? cc->size() : 0) +
	                    (bcc ? bcc->size() : 0);
	auto rcpts = content->children.prcpts;
	if (recipients > 0 && rcpts == nullptr) {
		rcpts = content->children.prcpts = tarray_set_init();
		if (rcpts == nullptr)
			throw EWSError::NotEnoughMemory(E3381);
	}
	if (rcpts != nullptr) {
		if (to)
			for (const auto &rcpt : *to)
				rcpt_add_unique(rcpts, rcpt, MAPI_TO);
		if (cc)
			for (const auto &rcpt : *cc)
				rcpt_add_unique(rcpts, rcpt, MAPI_CC);
		if (bcc)
			for (const auto &rcpt : *bcc)
				rcpt_add_unique(rcpts, rcpt, MAPI_BCC);
	}
	/* An address without RoutingType is an SMTP address */
	auto writeAddr = [&](const tEmailAddressType &mb, proptag_t typeTag,
	                 proptag_t addrTag, proptag_t nameTag, proptag_t smtpTag) {
		writeProp(shape, mb.Name, nameTag);
		if (!mb.EmailAddress) {
			writeProp(shape, mb.RoutingType, typeTag);
			return;
		}
		auto addr = deconst(mb.EmailAddress->c_str());
		auto type = mb.RoutingType ? mb.RoutingType->c_str() : "SMTP";
		shape.write(TAGGED_PROPVAL{typeTag, deconst(type)});
		shape.write(TAGGED_PROPVAL{addrTag, addr});
		if (strcasecmp(type, "SMTP") == 0)
			shape.write(TAGGED_PROPVAL{smtpTag, addr});
	};
	if (item.From)
		writeAddr(item.From->Mailbox, PR_SENT_REPRESENTING_ADDRTYPE,
			PR_SENT_REPRESENTING_EMAIL_ADDRESS,
			PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (item.Sender)
		writeAddr(item.Sender->Mailbox, PR_SENDER_ADDRTYPE,
			PR_SENDER_EMAIL_ADDRESS, PR_SENDER_NAME,
			PR_SENDER_SMTP_ADDRESS);
	if (item.References)
		shape.write(TAGGED_PROPVAL{PR_INTERNET_REFERENCES, deconst(item.References->c_str())});
	if (item.ConversationIndex) {
		auto bin = construct<BINARY>(BINARY{
		           static_cast<uint32_t>(item.ConversationIndex->size()),
		           {item.ConversationIndex->data()}});
		shape.write(TAGGED_PROPVAL{PR_CONVERSATION_INDEX, bin});
	}
	if (item.ConversationTopic)
		shape.write(TAGGED_PROPVAL{PR_CONVERSATION_TOPIC, deconst(item.ConversationTopic->c_str())});
	if (item.IsResponseRequested)
		writeBoolProp(shape, item.IsResponseRequested, PR_RESPONSE_REQUESTED);
	if (item.IsDeliveryReceiptRequested)
		writeBoolProp(shape, item.IsDeliveryReceiptRequested, PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
	if (item.IsReadReceiptRequested)
		writeBoolProp(shape, item.IsReadReceiptRequested, PR_READ_RECEIPT_REQUESTED);
	auto ensureMessageFlags = [&]() -> uint32_t* {
		const TAGGED_PROPVAL* prop = shape.writes(PR_MESSAGE_FLAGS);
		if (!prop) {
			auto flags = construct<uint32_t>(0);
			shape.write(TAGGED_PROPVAL{PR_MESSAGE_FLAGS, flags});
			prop = shape.writes(PR_MESSAGE_FLAGS);
		}
		return static_cast<uint32_t*>(prop->pvalue);
	};
	if (item.IsRead) {
		writeBoolProp(shape, item.IsRead, PR_READ);
		uint32_t* flags = ensureMessageFlags();
		if (*item.IsRead)
			*flags |= MSGFLAG_READ;
		else
			*flags &= ~MSGFLAG_READ;
	}
}

void EWSContext::toContent(const std::string &dir, tAcceptItem &item,
    sShape &shape, message_content_ptr &content) const
{
	if (!item.ItemClass)
		item.ItemClass.emplace("IPM.Schedule.Meeting.Resp.Pos");
	toContent(dir, static_cast<tMessage &>(item), shape, content);
}

void EWSContext::toContent(const std::string &dir, tTentativelyAcceptItem &item,
    sShape &shape, message_content_ptr &content) const
{
	if (!item.ItemClass)
		item.ItemClass.emplace("IPM.Schedule.Meeting.Resp.Tent");
	toContent(dir, static_cast<tMessage &>(item), shape, content);
}

void EWSContext::toContent(const std::string &dir, tDeclineItem &item,
    sShape &shape, message_content_ptr &content) const
{
	if (!item.ItemClass)
		item.ItemClass.emplace("IPM.Schedule.Meeting.Resp.Neg");
	toContent(dir, static_cast<tMessage &>(item), shape, content);
}

/*
 * ReplyToItem/ReplyAllToItem/ForwardItem carry their message in Message, as
 * the comment on tReplyToItem explains. Whatever the message leaves out is
 * taken from the item referred to.
 */
void EWSContext::toContent(const std::string &dir, tReplyToItem &item,
    sShape &shape, message_content_ptr &content) const
{
	toContent(dir, item.Message, shape, content);
	smartResponse(item.ReferenceItemId, smart_type::reply,
		item.NewBodyContent, !item.Nested, shape, content);
}

void EWSContext::toContent(const std::string &dir, tReplyAllToItem &item,
    sShape &shape, message_content_ptr &content) const
{
	toContent(dir, item.Message, shape, content);
	smartResponse(item.ReferenceItemId, smart_type::reply_all,
		item.NewBodyContent, !item.Nested, shape, content);
}

void EWSContext::toContent(const std::string &dir, tForwardItem &item,
    sShape &shape, message_content_ptr &content) const
{
	toContent(dir, item.Message, shape, content);
	smartResponse(item.ReferenceItemId, smart_type::forward,
		item.NewBodyContent, !item.Nested, shape, content);
}

/* Author of a message, as the representing or the actual sender */
static std::optional<tEmailAddressType> msg_author(const TPROPVAL_ARRAY &props)
{
	static constexpr proptag_t tags[][4] = {
		{PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENT_REPRESENTING_EMAIL_ADDRESS,
		 PR_SENT_REPRESENTING_ADDRTYPE, PR_SENT_REPRESENTING_NAME},
		{PR_SENDER_SMTP_ADDRESS, PR_SENDER_EMAIL_ADDRESS,
		 PR_SENDER_ADDRTYPE, PR_SENDER_NAME},
	};
	for (const auto &t : tags) {
		tEmailAddressType addr;
		auto str = props.get<const char>(t[0]);
		if (str != nullptr) {
			addr.EmailAddress = str;
			addr.RoutingType = "SMTP";
		} else if ((str = props.get<const char>(t[1])) != nullptr) {
			addr.EmailAddress = str;
			auto type = props.get<const char>(t[2]);
			if (type != nullptr)
				addr.RoutingType = type;
		} else {
			continue;
		}
		auto name = props.get<const char>(t[3]);
		if (name != nullptr)
			addr.Name = name;
		return addr;
	}
	return std::nullopt;
}

/* Display names of the recipients of one type */
static std::string rcpt_names(const TARRAY_SET *rcpts, uint32_t type)
{
	std::string out;
	if (rcpts == nullptr)
		return out;
	for (const auto &row : *rcpts) {
		auto rtype = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (rtype == nullptr || *rtype != type)
			continue;
		auto name = row.get<const char>(PR_DISPLAY_NAME);
		if (name == nullptr)
			name = row.get<const char>(PR_SMTP_ADDRESS);
		if (name == nullptr)
			name = row.get<const char>(PR_EMAIL_ADDRESS);
		if (name == nullptr)
			continue;
		if (!out.empty())
			out += "; ";
		out += name;
	}
	return out;
}

/*
 * NewBodyContent followed by a header and the body of the referenced
 * message, the way Exchange quotes it.
 */
static std::string smart_body(const tBody &nb, const MESSAGE_CONTENT &ref)
{
	const auto &props = ref.proplist;
	bool html = nb.BodyType == Enum::HTML;
	std::vector<std::pair<const char *, std::string>> hdr;
	auto author = msg_author(props);
	if (author && author->EmailAddress) {
		std::string from = author->Name ? *author->Name + " <" +
		                   *author->EmailAddress + ">" : *author->EmailAddress;
		hdr.emplace_back("From", std::move(from));
	}
	auto when = props.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	if (when == nullptr)
		when = props.get<const uint64_t>(PR_MESSAGE_DELIVERY_TIME);
	if (when != nullptr) {
		auto t = rop_util_nttime_to_unix(*when);
		struct tm tm{};
		char buf[64];
		if (localtime_r(&t, &tm) != nullptr &&
		    strftime(buf, std::size(buf), "%a, %d %b %Y %H:%M", &tm) > 0)
			hdr.emplace_back("Sent", buf);
	}
	auto to = rcpt_names(ref.children.prcpts, MAPI_TO);
	if (!to.empty())
		hdr.emplace_back("To", std::move(to));
	auto cc = rcpt_names(ref.children.prcpts, MAPI_CC);
	if (!cc.empty())
		hdr.emplace_back("Cc", std::move(cc));
	auto subj = props.get<const char>(PR_SUBJECT);
	hdr.emplace_back("Subject", subj != nullptr ? subj : "");

	auto cpid = props.get<const uint32_t>(PR_INTERNET_CPID);
	auto text = props.get<const char>(PR_BODY);
	auto hbin = props.get<const BINARY>(PR_HTML);
	std::string orig;
	const char *cset;
	if (html && hbin != nullptr && hbin->pc != nullptr)
		orig = cpid != nullptr && *cpid != CP_UTF8 &&
		       (cset = cpid_to_cset(static_cast<cpid_t>(*cpid))) != nullptr ?
		       iconvtext({hbin->pc, hbin->cb}, cset, "UTF-8") :
		       std::string(hbin->pc, hbin->cb);
	else if (html && text != nullptr)
		plain_to_html(text, orig);
	else if (text != nullptr)
		orig = text;
	else if (hbin != nullptr && hbin->pc != nullptr &&
	    html_to_plain({hbin->pc, hbin->cb}, cpid != nullptr ?
	    static_cast<cpid_t>(*cpid) : CP_UTF8, orig) < 0)
		orig.clear();

	std::string out = nb;
	if (!html) {
		out += "\r\n\r\n________________________________\r\n";
		for (const auto &[k, v] : hdr)
			out += std::string(k) + ": " + v + "\r\n";
		return out + "\r\n" + orig;
	}
	out += "<hr><div>";
	for (const auto &[k, v] : hdr) {
		std::unique_ptr<char[], stdlib_delete> q(HX_strquote(v.c_str(), HXQUOTE_HTML, nullptr));
		if (q == nullptr)
			throw std::bad_alloc();
		out += std::string("<b>") + k + ":</b> " + q.get() + "<br>";
	}
	return out + "</div><br>" + orig;
}

/**
 * @brief      Complete a reply or forward from the item it refers to
 *
 * Exchange addresses a reply to the Reply-To or the sender of the
 * referenced item, and a reply to all additionally to its To and Cc
 * recipients, leaving out the mailbox owner. Recipients given in the
 * request are added to those. NewBodyContent is put above the quoted
 * referenced message, and a forward carries its attachments.
 *
 * @param      refId    Item replied to or forwarded
 * @param      type     Kind of response
 * @param      newBody  NewBodyContent of the request
 * @param      merge    Whether to add recipients to those given
 * @param      shape    Shape of the response
 * @param      content  Content of the response
 */
void EWSContext::smartResponse(const tItemId &refId, smart_type type,
    const std::optional<tBody> &newBody, bool merge, sShape &shape,
    message_content_ptr &content) const
{
	assertIdType(refId.type, tItemId::ID_ITEM);
	sMessageEntryId mid(refId.Id.data(), refId.Id.size());
	sFolderSpec folder = resolveFolder(mid);
	std::string dir = getDir(folder);
	validate(dir, mid);
	if (!(permissions(dir, folder.folderId) & (frightsOwner | frightsReadAny)))
		throw EWSError::AccessDenied(E3515);
	auto owner = effectiveUser(folder);
	MESSAGE_CONTENT *ref = nullptr;
	if (!m_plugin.exmdb.read_message(dir.c_str(), owner, CP_ACP,
	    mid.messageId(), &ref) || ref == nullptr)
		throw EWSError::ItemNotFound(E3516);
	const auto &props = ref->proplist;

	auto topic = props.get<const char>(PR_NORMALIZED_SUBJECT);
	if (topic == nullptr)
		topic = props.get<const char>(PR_SUBJECT);
	if (topic == nullptr)
		topic = "";
	if (!shape.writes(PR_SUBJECT))
		shape.write(TAGGED_PROPVAL{PR_SUBJECT, cpystr(std::string(
			type == smart_type::forward ? "FW: " : "RE: ") + topic)});
	if (!shape.writes(PR_CONVERSATION_TOPIC)) {
		auto ct = props.get<const char>(PR_CONVERSATION_TOPIC);
		shape.write(TAGGED_PROPVAL{PR_CONVERSATION_TOPIC,
			cpystr(ct != nullptr ? ct : topic)});
	}
	if (newBody && !shape.writes(PR_BODY) && !shape.writes(PR_HTML)) {
		auto body = smart_body(*newBody, *ref);
		if (newBody->BodyType == Enum::HTML) {
			if (body.size() > UINT32_MAX)
				throw InputError(E3256);
			shape.write(TAGGED_PROPVAL{PR_HTML, construct<BINARY>(BINARY{
				static_cast<uint32_t>(body.size()), {cpystr(body)}})});
		} else {
			shape.write(TAGGED_PROPVAL{PR_BODY, cpystr(body)});
		}
		shape.write(TAGGED_PROPVAL{PR_INTERNET_CPID, construct<uint32_t>(CP_UTF8)});
	}
	if (type == smart_type::forward) {
		auto atts = ref->children.pattachments;
		if (atts == nullptr || atts->count == 0 ||
		    (content->children.pattachments != nullptr &&
		    content->children.pattachments->count > 0))
			return;
		auto dup = atts->dup();
		if (dup == nullptr)
			throw EWSError::NotEnoughMemory(E3518);
		content->set_attachments_internal(dup);
		return;
	}

	auto msgid = props.get<const char>(PR_INTERNET_MESSAGE_ID);
	if (msgid != nullptr && *msgid != '\0') {
		if (!shape.writes(PR_IN_REPLY_TO_ID))
			shape.write(TAGGED_PROPVAL{PR_IN_REPLY_TO_ID, cpystr(msgid)});
		auto refs = props.get<const char>(PR_INTERNET_REFERENCES);
		if (!shape.writes(PR_INTERNET_REFERENCES))
			shape.write(TAGGED_PROPVAL{PR_INTERNET_REFERENCES,
				cpystr(refs != nullptr && *refs != '\0' ?
				std::string(refs) + " " + msgid : std::string(msgid))});
	}

	auto rcpts = content->children.prcpts;
	if (!merge && rcpts != nullptr && rcpts->count > 0)
		return;
	if (rcpts == nullptr) {
		rcpts = content->children.prcpts = tarray_set_init();
		if (rcpts == nullptr)
			throw EWSError::NotEnoughMemory(E3517);
	}
	auto add = [&](tEmailAddressType &&addr, uint32_t rtype) {
		if (!addr.EmailAddress)
			return;
		try {
			normalize(addr);
		} catch (const EWSError &) {
			return;
		}
		if (type == smart_type::reply_all &&
		    ((owner != nullptr && strcasecmp(addr.EmailAddress->c_str(), owner) == 0) ||
		    strcasecmp(addr.EmailAddress->c_str(), m_auth_info.username) == 0))
			return;
		rcpt_add_unique(rcpts, std::move(addr), rtype);
	};
	auto replyTo = props.get<const BINARY>(PR_REPLY_RECIPIENT_ENTRIES);
	auto targets = replyTo != nullptr ? reply_to_list(*replyTo) :
	               std::vector<tEmailAddressType>();
	if (targets.empty()) {
		auto author = msg_author(props);
		if (author)
			targets.emplace_back(std::move(*author));
	}
	for (auto &addr : targets)
		add(std::move(addr), MAPI_TO);
	if (type != smart_type::reply_all || ref->children.prcpts == nullptr)
		return;
	for (const auto &row : *ref->children.prcpts) {
		auto rtype = row.get<const uint32_t>(PR_RECIPIENT_TYPE);
		if (rtype != nullptr && (*rtype == MAPI_TO || *rtype == MAPI_CC))
			add(tEmailAddressType(row), *rtype);
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
	if (!folder.target)
		throw DispatchError(E3172);
	const BINARY* pclData = getFolderProp<BINARY>(dir, folder.folderId, PR_PREDECESSOR_CHANGE_LIST);
	PCL pclOld;
	if (pclData && !pclOld.deserialize(pclData))
		throw DispatchError(E3170);
	uint64_t changeNum;
	if (!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
		throw DispatchError(E3171);
	bool isPublic = folder.location == folder.PUBLIC;
	uint32_t accountId = getAccountId(*folder.target, isPublic);
	XID changeKey{isPublic ?
		rop_util_make_domain_guid(accountId) :
		rop_util_make_user_guid(accountId), changeNum};
	BINARY ckeyBin = serialize(changeKey);
	auto ppcl = mkPCL(changeKey, std::move(pclOld));
	uint64_t now = rop_util_current_nttime();
	TAGGED_PROPVAL props[] = {{PidTagChangeNumber, &changeNum},
		                      {PR_CHANGE_KEY, &ckeyBin,},
		                      {PR_PREDECESSOR_CHANGE_LIST, ppcl.get()},
		                      {PR_LAST_MODIFICATION_TIME, &now}};
	TPROPVAL_ARRAY proplist{std::size(props), props};
	PROBLEM_ARRAY problems;
	if (!m_plugin.exmdb.set_folder_properties(dir.c_str(), CP_ACP,
	    folder.folderId, &proplist, &problems) || problems.count)
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
tSubscriptionId EWSContext::subscribe(const std::vector<sFolderId> &folderIds,
    uint16_t eventMask, bool all, time_duration timeout) const
{
	tSubscriptionId subscriptionId(timeout);
	auto mgr = m_plugin.make_submgr(subscriptionId, m_auth_info.username);
	if (folderIds.empty()) {
		mgr->mailboxInfo = getMailboxInfo(m_auth_info.maildir, false);
		mgr->inner_subs.emplace_back(m_plugin.subscribe(m_auth_info.maildir,
			eventMask, true, eid_t(1, PRIVATE_FID_IPMSUBTREE),
			subscriptionId.tsub_rawkey));
		return subscriptionId;
	}
	std::string target;
	std::string maildir;
	for (const sFolderId &f : folderIds) {
		sFolderSpec folderspec = std::visit([&](const auto& fid){return resolveFolder(fid);}, f);
		if (!folderspec.target)
			folderspec.target = m_auth_info.username;
		if (target.empty()) {
			target = *folderspec.target;
			maildir = get_maildir(*folderspec.target);
			mgr->mailboxInfo = getMailboxInfo(maildir, folderspec.location == folderspec.PUBLIC);
		} else if (target != *folderspec.target) {
			throw EWSError::InvalidSubscriptionRequest(E3200);
		}
		if (!(permissions(maildir, folderspec.folderId) & frightsReadAny))
			continue; // TODO: proper error handling
		mgr->folders.emplace(rop_util_get_gc_value(folderspec.folderId));
	}
	/* Filtered in EWSPlugin::event */
	if (!mgr->folders.empty())
		mgr->inner_subs.emplace_back(m_plugin.subscribe(maildir,
			eventMask, true, 0, subscriptionId.tsub_rawkey));
	return subscriptionId;
}

/**
 * @brief      Create new pull subscription
 *
 * @param      req    Pull subscription request
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const tPullSubscriptionRequest &req) const
{
	bool all = req.SubscribeToAllFolders && *req.SubscribeToAllFolders;
	if (all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3198);
	return subscribe(req.FolderIds ? *req.FolderIds : std::vector<sFolderId>(),
	       req.eventMask(), all, std::chrono::minutes(req.Timeout));
}

/**
 * @brief      Create new push subscription
 *
 * @param      req    Push subscription request
 *
 * @return     Subscription ID
 */
tSubscriptionId EWSContext::subscribe(const tPushSubscriptionRequest& req) const
{
	bool all = req.SubscribeToAllFolders && *req.SubscribeToAllFolders;
	if (all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3382);
	return subscribe(req.FolderIds ? *req.FolderIds : std::vector<sFolderId>(),
	       req.eventMask(), all, std::chrono::minutes(req.StatusFrequency));
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
	if (all && req.FolderIds)
		throw EWSError::InvalidSubscriptionRequest(E3383);
	return subscribe(req.FolderIds ? *req.FolderIds : std::vector<sFolderId>(),
	       req.eventMask(), all, m_plugin.streaming_subscription_timeout);
}

/**
 * @brief     End subscriptions
 *
 * @param subscriptionId   Subscription to remove
 */
bool EWSContext::unsubscribe(const Structures::tSubscriptionId& subscriptionId) const
{
	return m_plugin.unsubscribe(subscriptionId.tsub_rawkey, m_auth_info.username);
}

/**
 * @brief      Get pending value from shape, falling back to the stored one
 *
 * @param      shape  Shape with the pending writes
 * @param      props  Stored properties
 * @param      name   Property name
 * @param      tag    Property tag
 *
 * @return     Pointer to the value or nullptr if neither is present
 */
template<typename T> static const T *currentValue(const sShape &shape,
    const TPROPVAL_ARRAY &props, const PROPERTY_NAME &name, proptag_t tag)
{
	auto p = shape.writes(name);
	return static_cast<const T *>(p != nullptr ? p->pvalue : props.getval(tag));
}

/**
 * @brief      Recompute the reminder signal time after an item change
 *
 * For appointments the reminder is due at the start time, otherwise at
 * PidLidReminderTime (MS-OXORMDR v16 §2.2.1.4).
 *
 * @param      dir    Store directory
 * @param      mid    Message ID
 * @param      shape  Shape with the pending writes
 */
void EWSContext::updateReminder(const std::string &dir, uint64_t mid, sShape &shape) const
{
	auto tagSet = shape.tag(NtReminderSet), tagDelta = shape.tag(NtReminderDelta);
	auto tagTime = shape.tag(NtReminderTime), tagStart = shape.tag(NtCommonStart);
	auto tagSignal = shape.tag(NtReminderSignalTime);
	if (tagSet == 0 || tagDelta == 0 || tagTime == 0 || tagSignal == 0)
		return;
	if (!shape.writes(NtReminderSet) && !shape.writes(NtReminderDelta) &&
	    !shape.writes(NtReminderTime) && !shape.writes(NtCommonStart))
		return;
	if (tagStart == 0) {
		/* Not part of the shape, since setDatetimeFields would write it */
		PROPERTY_NAME name = NtCommonStart;
		auto ids = getNamedPropIds(dir, PROPNAME_ARRAY{1, &name});
		if (ids.size() != 1 || ids[0] == 0)
			return;
		tagStart = PROP_TAG(PT_SYSTIME, ids[0]);
	}
	auto tagRecur = shape.tag(NtRecurring);
	const proptag_t tags[] = {PR_MESSAGE_CLASS, tagDelta, tagTime, tagStart, tagSignal, tagRecur};
	auto props = getItemProps(dir, mid, {tags, tagRecur != 0 ? std::size(tags) : std::size(tags) - 1});

	auto recur = currentValue<uint8_t>(shape, props, NtRecurring, tagRecur);
	if (tagRecur != 0 && recur != nullptr && *recur) {
		/*
		 * A series signals at the next instance, or at 4501-01-01
		 * once no instance is left, see MS-OXORMDR v16 §3.1.4.6.2.
		 * Keep it on that instance when only the delta changes.
		 */
		static constexpr uint64_t noMoreSignals = 0x0CB34557A3DD4000;
		auto newDelta = shape.writes(NtReminderDelta);
		auto oldDelta = props.get<const int32_t>(tagDelta);
		auto signal = props.get<const uint64_t>(tagSignal);
		if (newDelta == nullptr || oldDelta == nullptr ||
		    signal == nullptr || *signal >= noMoreSignals ||
		    shape.writes(NtCommonStart) ||
		    shape.writes(NtReminderSignalTime))
			return;
		auto diff = static_cast<int64_t>(*oldDelta) -
		            *static_cast<const int32_t *>(newDelta->pvalue);
		shape.write(NtReminderSignalTime, TAGGED_PROPVAL{PT_SYSTIME,
			construct<uint64_t>(*signal + diff * 600000000)});
		return;
	}
	auto cls = props.get<const char>(PR_MESSAGE_CLASS);
	bool appt = class_match_prefix(cls, "IPM.Appointment") == 0 ||
	            class_match_prefix(cls, "IPM.Schedule.Meeting") == 0;
	auto delta = currentValue<int32_t>(shape, props, NtReminderDelta, tagDelta);
	auto due = appt ?
	           currentValue<uint64_t>(shape, props, NtCommonStart, tagStart) :
	           currentValue<uint64_t>(shape, props, NtReminderTime, tagTime);
	if (due == nullptr)
		return;
	if (appt && shape.writes(NtCommonStart))
		shape.write(NtReminderTime, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(*due)});
	uint64_t signal = *due;
	if (appt && delta != nullptr)
		signal -= static_cast<int64_t>(*delta) * 600000000;
	shape.write(NtReminderSignalTime, TAGGED_PROPVAL{PT_SYSTIME, construct<uint64_t>(signal)});
}

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
	if (!m_plugin.exmdb.allocate_cn(dir.c_str(), &changeNum))
		throw DispatchError(E3084);
	uint64_t localCommitTime = rop_util_current_nttime();
	shape.write(TAGGED_PROPVAL{PR_LOCAL_COMMIT_TIME, construct<mapitime_t>(localCommitTime)});
	shape.write(TAGGED_PROPVAL{PR_LAST_MODIFICATION_TIME, construct<mapitime_t>(localCommitTime)});

	std::string displayName;
	if (mysql_adaptor_get_user_displayname(m_auth_info.username,
	    displayName) && !displayName.empty())
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFIER_NAME, strcpy(alloc<char>(displayName.size() + 1), displayName.c_str())});
	else
		shape.write(TAGGED_PROPVAL{PR_LAST_MODIFIER_NAME, const_cast<char*>(m_auth_info.username)});

	static constexpr size_t ABEIDBUFFSIZE = 1280;
	auto abEidBuff = alloc<char>(ABEIDBUFFSIZE);
	EXT_PUSH wAbEid;
	std::string essdn;
	auto err = cvt_username_to_essdn(m_auth_info.username,
	           m_plugin.x500_org_name.c_str(), mysql_adaptor_get_user_ids,
	           mysql_adaptor_get_domain_ids, essdn);
	if (err != ecSuccess)
		throw DispatchError(E3384);
	HX_strupper(essdn.data());
	EMSAB_ENTRYID abEid{0, DT_MAILUSER, essdn.data()};
	if (!wAbEid.init(abEidBuff, ABEIDBUFFSIZE, EXT_FLAG_UTF16) ||
	    wAbEid.p_abk_eid(abEid) != pack_result::ok)
		throw DispatchError(E3385);
	BINARY* abEidContainer = construct<BINARY>(BINARY{wAbEid.m_offset, {abEidBuff}});
	shape.write(TAGGED_PROPVAL{PR_LAST_MODIFIER_ENTRYID, abEidContainer});

	XID changeKey{mid.isPrivate() ?
		rop_util_make_user_guid(mid.accountId()) :
		rop_util_make_domain_guid(mid.accountId()), changeNum};
	BINARY* changeKeyContainer = construct<BINARY>(serialize(changeKey));
	shape.write(TAGGED_PROPVAL{PR_CHANGE_KEY, changeKeyContainer});

	auto currentPclContainer = getItemProp<const BINARY>(dir,
	                           mid.messageId(), PR_PREDECESSOR_CHANGE_LIST);
	PCL pcl;
	if (currentPclContainer != nullptr && !pcl.deserialize(currentPclContainer))
		throw DispatchError(E3087);
	auto serializedPcl = mkPCL(changeKey, std::move(pcl));
	auto newPclContainer = construct<BINARY>(BINARY{serializedPcl->cb, {alloc<char>(serializedPcl->cb)}});
	memcpy(newPclContainer->pc, serializedPcl->pc, newPclContainer->cb);
	shape.write(TAGGED_PROPVAL{PR_PREDECESSOR_CHANGE_LIST, newPclContainer});

	shape.write(TAGGED_PROPVAL{PidTagChangeNumber, construct<uint64_t>(changeNum)});
}


/**
 * @brief      Write delegate permissions to folder ACLs
 */
bool EWSContext::writeDelegatePermissions(const std::string &dir, const std::string &username,
    const tDelegatePermissions &dp) const
{
	std::string dispname;
	mysql_adaptor_get_user_displayname(username.c_str(), dispname);

	bool changed = false;
	for (const auto &m : delegFolderMap) {
		const auto &level = dp.*(m.field);
		if (!level)
			continue;
		uint32_t rights = deleg_level_to_rights(*level);
		PERMISSION_DATA perm = {ROW_ADD, TPROPVAL_ARRAY{0, EWSContext::alloc<TAGGED_PROPVAL>(4)}};
		uint16_t &count = perm.propvals.count;
		perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_MEMBER_RIGHTS, EWSContext::construct<uint32_t>(rights)};
		perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_SMTP_ADDRESS, EWSContext::cpystr(username)};
		if (!dispname.empty())
			perm.propvals.ppropval[count++] = TAGGED_PROPVAL{PR_MEMBER_NAME, EWSContext::cpystr(dispname)};
		uint64_t fid = eid_t(1, m.fid);
		if (m_plugin.exmdb.update_folder_permission(dir.c_str(),
		    fid, 0, 1, &perm))
			changed = true;
	}
	return changed;
}


namespace {

/**
 * Delegates of the LocalFreebusy message, as parallel arrays
 */
struct DelegateList {
	std::vector<BINARY> eids;
	std::vector<char *> names;
	std::vector<uint32_t> flags;
};

/**
 * @brief      Returns the delegates stored in the LocalFreebusy message
 *
 * @param      props  Properties of the LocalFreebusy message
 */
DelegateList readDelegateList(const TPROPVAL_ARRAY &props)
{
	DelegateList list;
	auto e = props.get<const BINARY_ARRAY>(PR_SCHDINFO_DELEGATE_ENTRYIDS);
	auto n = props.get<const STRING_ARRAY>(PR_SCHDINFO_DELEGATE_NAMES);
	auto f = props.get<const LONG_ARRAY>(PR_DELEGATE_FLAGS);
	if (e != nullptr)
		list.eids.assign(e->pbin, e->pbin + e->count);
	for (size_t i = 0; i < list.eids.size(); ++i) {
		list.names.emplace_back(n != nullptr && i < n->count ? n->ppstr[i] : deconst(""));
		list.flags.emplace_back(f != nullptr && i < f->count ? f->pl[i] : DF_HIDEPRIVATE);
	}
	return list;
}

/**
 * @brief      Add, update or remove a delegate
 *
 * @param      list         Delegates to change
 * @param      username     Delegate
 * @param      org          X500 organization name of the store
 * @param      viewPrivate  New ShowPrivate flag, none keeps the current one
 * @param      remove       Remove the delegate instead
 *
 * @return     Returns whether the list was changed
 */
bool editDelegateList(DelegateList &list, const std::string &username,
    const char *org, std::optional<bool> viewPrivate, bool remove)
{
	size_t idx = 0;
	while (idx < list.eids.size() &&
	       !delegate_eid_is(list.eids[idx], org, username.c_str()))
		++idx;
	if (remove) {
		if (idx == list.eids.size())
			return false;
		list.eids.erase(list.eids.begin() + idx);
		list.names.erase(list.names.begin() + idx);
		list.flags.erase(list.flags.begin() + idx);
		return true;
	}
	if (idx < list.eids.size()) {
		if (!viewPrivate)
			return false;
		list.flags[idx] = *viewPrivate;
		return true;
	}
	std::string eid, dispname;
	if (cvt_username_to_abkeid(username.c_str(), org, DT_MAILUSER,
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    eid) != ecSuccess)
		throw EWSError::InternalServerError(E3522);
	if (!mysql_adaptor_get_user_displayname(username.c_str(), dispname) ||
	    dispname.empty())
		dispname = username;
	auto buf = EWSContext::alloc<char>(eid.size());
	memcpy(buf, eid.data(), eid.size());
	list.eids.emplace_back(BINARY{static_cast<uint32_t>(eid.size()), {buf}});
	list.names.emplace_back(EWSContext::cpystr(dispname));
	list.flags.emplace_back(viewPrivate.value_or(false));
	return true;
}

}

/**
 * @brief      Returns the LocalFreebusy message holding the delegates
 *
 * @param      dir     Store of the delegator
 * @param      refMid  Message named in PidTagFreeBusyEntryIds[1]
 *
 * @return     Returns @refMid if it exists, else the first one found
 */
std::optional<uint64_t> EWSContext::findDelegateMessage(const std::string &dir,
    std::optional<uint64_t> refMid) const
{
	const auto &exmdb = m_plugin.exmdb;
	uint32_t tableId = 0, rowCount = 0;
	if (!exmdb.load_content_table(dir.c_str(), CP_ACP,
	    eid_t(1, PRIVATE_FID_LOCAL_FREEBUSY), nullptr,
	    TABLE_FLAG_NONOTIFICATIONS, nullptr, nullptr, &tableId, &rowCount))
		throw EWSError::InternalServerError(E3520);
	auto unloadTable = HX::make_scope_exit([&]() { exmdb.unload_table(dir.c_str(), tableId); });
	static constexpr std::array<proptag_t, 2> rowTags = {PidTagMid, PR_MESSAGE_CLASS};
	TARRAY_SET rows{};
	if (!exmdb.query_table(dir.c_str(), nullptr, CP_ACP, tableId, rowTags,
	    0, rowCount, &rows))
		throw EWSError::InternalServerError(E3521);
	std::optional<uint64_t> mid;
	for (const auto &row : rows) {
		auto m = row.get<const uint64_t>(PidTagMid);
		auto cls = row.get<const char>(PR_MESSAGE_CLASS);
		if (m == nullptr || cls == nullptr ||
		    class_match_prefix(cls, "IPM.Microsoft.ScheduleData.FreeBusy") != 0)
			continue;
		if (*m == refMid)
			return *m;
		if (!mid)
			mid = *m;
	}
	return mid;
}

/**
 * @brief      Name a LocalFreebusy message in PidTagFreeBusyEntryIds[1]
 *
 * The property is set on the root folder and the inbox, as MS-OXODLGT
 * v16.0 §3.1.4.2 asks.
 *
 * @param      dir     Store of the delegator
 * @param      fbEids  Current PidTagFreeBusyEntryIds of the inbox
 * @param      mid     LocalFreebusy message
 */
void EWSContext::stampDelegateMessage(const std::string &dir,
    const BINARY_ARRAY *fbEids, uint64_t mid) const
{
	std::vector<BINARY> fb;
	if (fbEids != nullptr)
		fb.assign(fbEids->pbin, fbEids->pbin + fbEids->count);
	if (fb.size() < 4)
		fb.resize(4);
	fb[1] = *static_cast<const BINARY *>(getItemEntryId(dir, mid).pvalue);
	if (fb[3].cb == 0)
		fb[3] = *static_cast<const BINARY *>(getFolderEntryId(dir,
		        eid_t(1, PRIVATE_FID_LOCAL_FREEBUSY)).pvalue);
	BINARY_ARRAY fbArr{static_cast<uint32_t>(fb.size()), fb.data()};
	TAGGED_PROPVAL fbProp{PR_FREEBUSY_ENTRYIDS, &fbArr};
	TPROPVAL_ARRAY fbProps{1, &fbProp};
	for (eid_t f : {eid_t(1, PRIVATE_FID_ROOT), eid_t(1, PRIVATE_FID_INBOX)}) {
		PROBLEM_ARRAY problems;
		updated(dir, sFolderSpec(m_auth_info.username, f));
		if (!m_plugin.exmdb.set_folder_properties(dir.c_str(), CP_ACP, f,
		    &fbProps, &problems) || problems.count > 0)
			throw EWSError::InternalServerError(E3524);
	}
}

/**
 * @brief      Update a delegate in the LocalFreebusy message
 *
 * Outlook and grommunio-web keep the delegates there, with ShowPrivate in
 * PidTagDelegateFlags, see sees_private_items().
 *
 * @param      dir          Store of the delegator
 * @param      username     Delegate
 * @param      viewPrivate  New ShowPrivate flag, none keeps the current one
 * @param      remove       Remove the delegate instead
 */
void EWSContext::writeDelegateFlags(const std::string &dir,
    const std::string &username, std::optional<bool> viewPrivate,
    bool remove) const
{
	const auto &exmdb = m_plugin.exmdb;
	/* Clients open the message named in PidTagFreeBusyEntryIds[1] */
	static constexpr proptag_t fbTag[] = {PR_FREEBUSY_ENTRYIDS};
	auto inboxProps = getFolderProps(dir, eid_t(1, PRIVATE_FID_INBOX), fbTag);
	auto fbEids = inboxProps.get<const BINARY_ARRAY>(PR_FREEBUSY_ENTRYIDS);
	std::optional<uint64_t> refMid;
	if (fbEids != nullptr && fbEids->count > 1 && fbEids->pbin[1].cb > 0) try {
		refMid = sMessageEntryId(fbEids->pbin[1].pv, fbEids->pbin[1].cb).messageId();
	} catch (const EWSError &) {
	}
	auto mid = findDelegateMessage(dir, refMid);
	if (!mid && remove)
		return;
	static constexpr std::array<proptag_t, 3> tags = {PR_SCHDINFO_DELEGATE_ENTRYIDS,
		PR_SCHDINFO_DELEGATE_NAMES, PR_DELEGATE_FLAGS};
	DelegateList list;
	if (mid)
		list = readDelegateList(getItemProps(dir, *mid, tags));
	if (!editDelegateList(list, username, m_plugin.x500_org_name.c_str(),
	    viewPrivate, remove))
		return;

	BINARY_ARRAY eidArr{static_cast<uint32_t>(list.eids.size()), list.eids.data()};
	STRING_ARRAY nameArr{static_cast<uint32_t>(list.names.size()), list.names.data()};
	LONG_ARRAY flagArr{static_cast<uint32_t>(list.flags.size()), list.flags.data()};
	if (!mid) {
		/* No delegate rule, so the delegator gets the meeting requests */
		static constexpr uint8_t wantsCopy = 1, wantsInfo = 0;
		const TAGGED_PROPVAL newProps[] = {
			{PR_MESSAGE_CLASS, deconst("IPM.Microsoft.ScheduleData.FreeBusy")},
			{PR_SUBJECT, deconst("LocalFreebusy")},
			{PR_SCHDINFO_BOSS_WANTS_COPY, deconst(&wantsCopy)},
			{PR_SCHDINFO_BOSS_WANTS_INFO, deconst(&wantsInfo)},
			{PR_SCHDINFO_DELEGATE_ENTRYIDS, &eidArr},
			{PR_SCHDINFO_DELEGATE_NAMES, &nameArr},
			{PR_DELEGATE_FLAGS, &flagArr},
		};
		MESSAGE_CONTENT content{};
		content.proplist = {std::size(newProps), deconst(newProps)};
		uint64_t newMid = 0, newCn = 0;
		ec_error_t err = ecSuccess;
		if (!exmdb.write_message(dir.c_str(), CP_ACP,
		    eid_t(1, PRIVATE_FID_LOCAL_FREEBUSY), &content, {},
		    &newMid, &newCn, &err) || err != ecSuccess)
			throw EWSError::InternalServerError(E3523);
		stampDelegateMessage(dir, fbEids, newMid);
		return;
	}
	if (*mid != refMid)
		stampDelegateMessage(dir, fbEids, *mid);
	if (list.eids.empty() &&
	    !exmdb.remove_message_properties(dir.c_str(), CP_ACP, *mid, tags))
		throw EWSError::InternalServerError(E3524);
	sShape shape;
	if (!list.eids.empty()) {
		shape.write(TAGGED_PROPVAL{PR_SCHDINFO_DELEGATE_ENTRYIDS, &eidArr});
		shape.write(TAGGED_PROPVAL{PR_SCHDINFO_DELEGATE_NAMES, &nameArr});
		shape.write(TAGGED_PROPVAL{PR_DELEGATE_FLAGS, &flagArr});
	}
	updated(dir, sMessageEntryId(getItemEntryId(dir, *mid)), shape);
	auto msgProps = shape.write();
	PROBLEM_ARRAY problems;
	if (!exmdb.set_message_properties(dir.c_str(), nullptr, CP_ACP, *mid,
	    &msgProps, &problems))
		throw EWSError::InternalServerError(E3524);
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
		if (memberCount > UINT16_MAX)
			throw InputError(E3285);
		const auto& exmdb = m_plugin.exmdb;
		if (!exmdb.empty_folder_permission(dir.c_str(), fid))
			throw EWSError::FolderSave(E3286);
		if (!exmdb.update_folder_permission(dir.c_str(), fid, false,
		    static_cast<uint16_t>(memberCount), perms.data()))
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
	if (!parentFid)
		throw EWSError::ItemNotFound(E3187);
	if (*parentFid != meid.folderId())
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
	if (have == wanted)
		return;
	if (wanted == IdType::ID_FOLDER && have == IdType::ID_ITEM)
		throw EWSError::CannotUseItemIdForFolderId(E3213);
	else if (wanted == IdType::ID_ITEM && have == IdType::ID_FOLDER)
		throw EWSError::CannotUseFolderIdForItemId(E3214);
	else if (wanted == IdType::ID_ATTACHMENT)
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
	switch (code) {
	case pack_result::ok: return;
	case pack_result::alloc: throw Exceptions::EWSError::NotEnoughMemory(msg ? msg : E3128);
	case pack_result::bufsize:
	default:
		if (responseCode && msg)
			throw Exceptions::EWSError(responseCode, msg);
		throw DispatchError(code == pack_result::bufsize ? E3145 :
		      Exceptions::E3028(static_cast<int>(code)));
	}
}

}
