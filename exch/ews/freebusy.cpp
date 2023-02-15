// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <string>
#include <fmt/core.h>
#include <fmt/format.h>
#include <libHX/string.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>

#include "ews.hpp"
#include "structures.hpp"

static constexpr unsigned int asfMeeting = 1, asfReceived = 2, asfCanceled = 4;

using namespace gromox;

template<> struct fmt::formatter<ICAL_TIME> {
	auto parse(format_parse_context &ctx) { return ctx.begin(); }
	format_context::iterator format(const ICAL_TIME &t, format_context &ctx) const
	{
		return fmt::format_to(ctx.out(), "{:04}{:02}{:02}T{:02}{:02}{:02}",
		       t.year, t.month, t.day, t.hour, t.minute, t.second);
	}
};

namespace {

struct event {
	time_t start_time = 0, end_time = 0;
	EXCEPTIONINFO *ei = nullptr;
	EXTENDEDEXCEPTION *xe = nullptr;
};

struct fbtags {
	fbtags(gromox::EWS::EWSPlugin::_exmdb &, const char *);

	uint32_t apptstartwhole = 0, apptendwhole = 0, busystatus = 0;
	uint32_t recurring = 0, apptrecur = 0, apptsubtype = 0;
	uint32_t private_flag = 0, apptstateflags = 0, clipend = 0;
	uint32_t location = 0, reminderset = 0, globalobjectid = 0;
	uint32_t timezonestruct = 0;
};

}

fbtags::fbtags(gromox::EWS::EWSPlugin::_exmdb &client, const char *dir)
{
	using namespace gromox::EWS::Exceptions;
	static const PROPERTY_NAME propname_buff[] = {
		{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStartWhole},
		{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentEndWhole},
		{MNID_ID, PSETID_APPOINTMENT, PidLidBusyStatus},
		{MNID_ID, PSETID_APPOINTMENT, PidLidRecurring},
		{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentRecur},
		{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentSubType},
		{MNID_ID, PSETID_COMMON,      PidLidPrivate},
		{MNID_ID, PSETID_APPOINTMENT, PidLidAppointmentStateFlags},
		{MNID_ID, PSETID_APPOINTMENT, PidLidClipEnd},
		{MNID_ID, PSETID_APPOINTMENT, PidLidLocation},
		{MNID_ID, PSETID_COMMON,      PidLidReminderSet},
		{MNID_ID, PSETID_MEETING,     PidLidGlobalObjectId},
		{MNID_ID, PSETID_APPOINTMENT, PidLidTimeZoneStruct},
	};
	const PROPNAME_ARRAY propnames = {std::size(propname_buff), deconst(propname_buff)};
	PROPID_ARRAY ids;
	if (!client.get_named_propids(dir, false, &propnames, &ids))
		throw DispatchError(E3015);
	if (ids.count != propnames.count)
		throw DispatchError(E3016);

	apptstartwhole = PROP_TAG(PT_SYSTIME, ids.ppropid[0]);
	apptendwhole   = PROP_TAG(PT_SYSTIME, ids.ppropid[1]);
	busystatus     = PROP_TAG(PT_LONG,    ids.ppropid[2]);
	recurring      = PROP_TAG(PT_BOOLEAN, ids.ppropid[3]);
	apptrecur      = PROP_TAG(PT_BINARY,  ids.ppropid[4]);
	apptsubtype    = PROP_TAG(PT_BOOLEAN, ids.ppropid[5]);
	private_flag   = PROP_TAG(PT_BOOLEAN, ids.ppropid[6]);
	apptstateflags = PROP_TAG(PT_LONG,    ids.ppropid[7]);
	clipend        = PROP_TAG(PT_SYSTIME, ids.ppropid[8]);
	location       = PROP_TAG(PT_UNICODE, ids.ppropid[9]);
	reminderset    = PROP_TAG(PT_BOOLEAN, ids.ppropid[10]);
	globalobjectid = PROP_TAG(PT_BINARY,  ids.ppropid[11]);
	timezonestruct = PROP_TAG(PT_BINARY,  ids.ppropid[12]);
}

static bool fill_tzcom(ical_component &tzcom, const SYSTEMTIME &sys, int year,
    int from_bias, int to_bias, bool dstmonth)
{
	std::string str;
	if (!dstmonth) {
		str = "16010101T000000";
	} else if (sys.year == 0) {
		int day = ical_get_dayofmonth(year, sys.month, sys.day,	sys.dayofweek);
		str = fmt::format("{}", ICAL_TIME{year, sys.month, day,
		      sys.hour, sys.minute, sys.second});
	} else if (sys.year == 1) {
		str = fmt::format("{}", ICAL_TIME{year, sys.month, sys.day,
		      sys.hour, sys.minute, sys.second});
	} else {
		return false;
	}

	int utc_offset = -from_bias;
	tzcom.append_line("TZOFFSETFROM", fmt::format("{:+03}{:02}",
		utc_offset / 60, abs(utc_offset) % 60));
	utc_offset = -to_bias;
	tzcom.append_line("TZOFFSETTO", fmt::format("{:+03}{:02}",
		utc_offset / 60, abs(utc_offset) % 60));
	tzcom.append_line("DTSTART", std::move(str));

	if (!dstmonth)
		return true;
	if (sys.year == 0) {
		auto &line = tzcom.append_line("RRULE");
		line.append_value("FREQ", "YEARLY");
		int order = sys.day == 5 ? -1 : sys.day;
		auto dow = weekday_to_str(sys.dayofweek);
		if (dow == nullptr)
			return false;
		line.append_value("BYDAY", fmt::format("{}{}", order, dow));
		line.append_value("BYMONTH", fmt::format("{}", sys.month));
	} else if (sys.year == 1) {
		auto &line = tzcom.append_line("RRULE");
		line.append_value("FREQ", "YEARLY");
		line.append_value("BYMONTHDAY", fmt::format("{}", sys.day));
		line.append_value("BYMONTH", fmt::format("{}", sys.month));
	}
	return true;
}

static std::optional<ical_component> tz_to_vtimezone(int year,
    const char *tzid, const TIMEZONESTRUCT &tz)
{
	std::optional<ical_component> com("VTIMEZONE");
	com->append_line("TZID", tzid);

	auto &stdtime = com->append_comp("STANDARD");
	int std_bias  = tz.bias + tz.standardbias;
	int dst_bias  = tz.bias + tz.daylightbias;
	if (!fill_tzcom(stdtime, tz.standarddate, year, dst_bias, std_bias,
	    tz.daylightdate.month))
		return std::nullopt;
	if (tz.daylightdate.month == 0)
		return com;
	auto &dsttime = com->append_comp("DAYLIGHT");
	if (!fill_tzcom(dsttime, tz.daylightdate, year, std_bias, dst_bias,
	    tz.standarddate.month))
		return std::nullopt;
	return com;
}

static bool recurrencepattern_to_rrule(const ical_component *tzcom,
    time_t start_whole, const APPOINTMENT_RECUR_PAT &apr, ICAL_RRULE *irrule)
{
	auto &rpat = apr.recur_pat;
	ICAL_TIME itime;
	ical_line line("RRULE");

	switch (rpat.patterntype) {
	case PATTERNTYPE_DAY:
		line.append_value("FREQ", "DAILY");
		line.append_value("INTERVAL", fmt::format("{}", rpat.period / 1440));
		break;
	case PATTERNTYPE_WEEK: {
		line.append_value("FREQ", "WEEKLY");
		line.append_value("INTERVAL", fmt::format("{}", rpat.period));
		auto &val = line.append_value("BYDAY");
		for (unsigned int wd = 0; wd < 7; ++wd)
			if (rpat.pts.weekrecur & (1 << wd))
				val.append_subval(weekday_to_str(wd));
		break;
	}
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_HJMONTH: {
		auto monthly  = rpat.period % 12 != 0;
		auto interval = rpat.period;
		line.append_value("FREQ", monthly ? "MONTHLY" : "YEARLY");
		if (monthly)
			interval /= 12;
		line.append_value("INTERVAL", fmt::format("{}", interval));
		line.append_value("BYMONTHDAY", fmt::format("{}",
			rpat.pts.dayofmonth == 31 ? -1 : rpat.pts.dayofmonth));//test what happens if making recurrence with day30/31 (rather than lastday)
		if (monthly)
			break;
		ical_get_itime_from_yearday(1601, rpat.firstdatetime / 1440 + 1, &itime);
		line.append_value("BYMONTH", fmt::format("{}", itime.month));
		break;
	}
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH: {
		auto monthly  = rpat.period % 12 != 0;
		auto interval = rpat.period;
		line.append_value("FREQ", monthly ? "MONTHLY" : "YEARLY");
		if (monthly)
			interval /= 12;
		line.append_value("INTERVAL", fmt::format("{}", interval));
		auto &pts = rpat.pts;
		auto &val = line.append_value("BYDAY");
		for (unsigned int wd = 0; wd < 7; ++wd)
			if (pts.monthnth.weekrecur & (1 << wd))
				val.append_subval(weekday_to_str(wd));
		line.append_value("BYSETPOS", fmt::format("{}",
			pts.monthnth.recurnum == 5 ? -1 : pts.monthnth.recurnum));
		if (monthly)
			break;
		line.append_value("BYMONTH", fmt::format("{}", rpat.firstdatetime));
		break;
	}
	default:
		return false;
	}
	if (rpat.endtype == ENDTYPE_AFTER_N_OCCURRENCES) {
		line.append_value("COUNT", fmt::format("{}", rpat.occurrencecount));
	} else if (rpat.endtype == ENDTYPE_AFTER_DATE) {
		auto ut = rop_util_rtime_to_unix(rpat.enddate + apr.starttimeoffset);
		ical_utc_to_datetime(tzcom, ut, &itime);
		line.append_value("UNTIL", fmt::format("{}Z", itime));
	}
	if (rpat.patterntype == PATTERNTYPE_WEEK) {
		auto wd = weekday_to_str(rpat.firstdow);
		if (wd == nullptr)
			return false;
		line.append_value("WKST", wd);
	}
	return ical_parse_rrule(tzcom, start_whole, &line.value_list, irrule);
}

static bool find_recur_times(const ical_component *tzcom,
    time_t start_whole, const APPOINTMENT_RECUR_PAT &apr,
    time_t start_time, time_t end_time, std::vector<event> &evlist)
{
	ICAL_RRULE irrule;

	if (!recurrencepattern_to_rrule(tzcom, start_whole, apr, &irrule))
		return false;
	do {
		auto itime = irrule.instance_itime;
		time_t ut{}, utnz{};
		if (!ical_itime_to_utc(tzcom, itime, &ut) || ut < start_time ||
		    !ical_itime_to_utc(nullptr, itime, &utnz))
			continue;
		auto &ei = apr.pexceptioninfo;
		auto time_test = [&](const EXCEPTIONINFO &e) {
			return rop_util_rtime_to_unix(e.originalstartdate) == utnz;
		};
		if (std::any_of(&ei[0], &ei[apr.exceptioncount], time_test))
			continue;
		evlist.push_back(event{ut, ut + (apr.endtimeoffset - apr.starttimeoffset) * 60});
		if (ut >= end_time)
			break;
	} while (irrule.iterate());
	for (unsigned int i = 0; i < apr.exceptioncount; ++i) {
		auto ut = rop_util_rtime_to_unix(apr.pexceptioninfo[i].startdatetime);
		ICAL_TIME itime;
		if (!ical_utc_to_datetime(nullptr, ut, &itime) ||
		    !ical_itime_to_utc(tzcom, itime, &ut) ||
		    ut < start_time || ut > end_time)
			continue;
		event event = {ut};
		ut = rop_util_rtime_to_unix(apr.pexceptioninfo[i].enddatetime);
		if (!ical_utc_to_datetime(nullptr, ut, &itime) ||
		    !ical_itime_to_utc(tzcom, itime, &ut))
			continue;
		event.end_time = ut;
		event.ei = &apr.pexceptioninfo[i];
		event.xe = &apr.pextendedexception[i];
		evlist.push_back(std::move(event));
	}
	return true;
}

static int goid_to_icaluid2(BINARY *gobj, std::string &uid_buf)
{
	EXT_PUSH epush;
	char guidbuf[16], ngidbuf[56];
	GLOBALOBJECTID ngid;

	if (gobj == nullptr) {
		if (!epush.init(guidbuf, std::size(guidbuf), 0) ||
		    epush.p_guid(GUID::random_new()) != EXT_ERR_SUCCESS)
			return -EIO;
		ngid.arrayid = EncodedGlobalId;
		ngid.creationtime = rop_util_unix_to_nttime(time(nullptr));
		ngid.data.cb = 16;
		ngid.data.pc = guidbuf;
		uid_buf.resize(std::size(ngidbuf) * 2 + 1);
		if (!epush.init(ngidbuf, std::size(ngidbuf), 0) ||
		    epush.p_goid(ngid) != EXT_ERR_SUCCESS ||
		    !encode_hex_binary(ngidbuf, epush.m_offset,
		    uid_buf.data(), uid_buf.size()))
			return -EIO;
		return 2;
	}

	EXT_PULL epull;
	auto cl_0 = make_scope_exit([&]() { free(ngid.data.pc); });
	epull.init(gobj->pb, gobj->cb, malloc, 0);
	if (epull.g_goid(&ngid) != EXT_ERR_SUCCESS)
		return -EIO;
	static_assert(sizeof(ThirdPartyGlobalId) == 12);
	if (ngid.data.cb >= 12 && memcmp(ngid.data.pc, ThirdPartyGlobalId, 12) == 0) {
		auto m = ngid.data.cb - 12;
		if (m > 255)
			m = 255;//check if this is the typical boundary(OXFB)
		uid_buf.assign(&ngid.data.pc[12], m);
		return 1;
	}

	uid_buf.resize(56*2+1);
	ngid.year = ngid.month = ngid.day = 0;
	if (!epush.init(ngidbuf, std::size(ngidbuf), 0) ||
	    epush.p_goid(ngid) != EXT_ERR_SUCCESS ||
	    !encode_hex_binary(ngidbuf, epush.m_offset, uid_buf.data(), uid_buf.size()))
		return -EIO;
	return 2;
}

static bool goid_to_icaluid(BINARY *gobj, std::string &uid_buf)
{
	auto ret = goid_to_icaluid2(gobj, uid_buf);
	if (ret < 0)
		return false;
	if (ret == 2)
		HX_strupper(uid_buf.data());
	return true;
}

namespace gromox::EWS::Structures
{

using namespace gromox::EWS::Exceptions;

tCalendarEvent::tCalendarEvent(time_t start_time, time_t end_time,
    uint32_t busy_type, const std::string &uid, const char *subject,
    const char *location, bool is_meeting, bool is_recurring, bool is_exception,
    bool is_reminder, bool is_private, bool detailed) :
	StartTime(time_point::clock::from_time_t(start_time)),
	EndTime(time_point::clock::from_time_t(end_time))
{
	switch (busy_type) {
	case olFree: BusyType = "Free"; break;
	case olTentative: BusyType = "Tentative"; break;
	case olBusy: BusyType = "Busy"; break;
	case olOutOfOffice: BusyType = "OOF"; break;
	case olWorkingElsewhere: BusyType = "WorkingElsewhere"; break;
	default: BusyType = "NoData"; break;
	}
	if (!detailed)
		return;
	auto &details = CalenderEventDetails.emplace();
	details.ID = uid;
	if (subject != nullptr)
		details.Subject = subject;
	if (location != nullptr)
		details.Location = location;
	details.IsMeeting     = is_meeting;
	details.IsRecurring   = is_recurring;
	details.IsException   = is_exception;
	details.IsReminderSet = is_reminder;
	details.IsPrivate     = is_private;
}

tFreeBusyView::tFreeBusyView(const char *username, const char *dir,
    time_t start_time, time_t end_time, const EWSContext &ctx)
{
	auto &exmdb_client = ctx.plugin.exmdb;
	fbtags ptag(exmdb_client, dir);
	uint32_t permission = 0;

	if (username != nullptr) {
		if (!exmdb_client.get_folder_perm(dir,
		    rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR), username, &permission))
			throw DispatchError(E3017);
		if (!(permission & (frightsFreeBusySimple | frightsFreeBusyDetailed | frightsReadAny)))
			throw AccessDenied(E3018);
	} else {
		permission = frightsFreeBusyDetailed | frightsReadAny;
	}

	bool detailed     = permission & (frightsFreeBusyDetailed | frightsReadAny);
	FreeBusyViewType  = detailed ? "Detailed" : "FreeBusy";
	auto start_nttime = rop_util_unix_to_nttime(start_time);
	auto end_nttime   = rop_util_unix_to_nttime(end_time);
	static constexpr uint8_t fixed_true = 1;

	/* C1: apptstartwhole >= start && apptstartwhole <= end */
	RESTRICTION_PROPERTY rst_1 = {RELOP_GE, ptag.apptstartwhole, {ptag.apptstartwhole, &start_nttime}};
	RESTRICTION_PROPERTY rst_2 = {RELOP_LE, ptag.apptstartwhole, {ptag.apptstartwhole, &end_nttime}};
	RESTRICTION rst_3[2]       = {{RES_PROPERTY, {&rst_1}}, {RES_PROPERTY, {&rst_2}}};
	RESTRICTION_AND_OR rst_4   = {std::size(rst_3), rst_3};

	/* C2: apptendwhole >= start && apptendwhole <= end */
	RESTRICTION_PROPERTY rst_5 = {RELOP_GE, ptag.apptendwhole, {ptag.apptendwhole, &start_nttime}};
	RESTRICTION_PROPERTY rst_6 = {RELOP_LE, ptag.apptendwhole, {ptag.apptendwhole, &end_nttime}};
	RESTRICTION rst_7[2]       = {{RES_PROPERTY, {&rst_5}}, {RES_PROPERTY, {&rst_6}}};
	RESTRICTION_AND_OR rst_8   = {std::size(rst_7), rst_7};

	/* C3: apptstartwhole < start && apptendwhole > end */
	RESTRICTION_PROPERTY rst_9  = {RELOP_LT, ptag.apptstartwhole, {ptag.apptstartwhole, &start_nttime}};
	RESTRICTION_PROPERTY rst_10 = {RELOP_GT, ptag.apptendwhole, {ptag.apptendwhole, &end_nttime}};
	RESTRICTION rst_11[2]       = {{RES_PROPERTY, {&rst_9}}, {RES_PROPERTY, {&rst_10}}};
	RESTRICTION_AND_OR rst_12   = {std::size(rst_11), rst_11};

	/* C4: have(clipend) && recurring && clipend >= start */
	RESTRICTION_EXIST rst_13    = {ptag.clipend};
	RESTRICTION_PROPERTY rst_14 = {RELOP_EQ, ptag.recurring, {ptag.recurring, deconst(&fixed_true)}};
	RESTRICTION_PROPERTY rst_15 = {RELOP_GE, ptag.clipend, {ptag.clipend, &start_nttime}};
	RESTRICTION rst_16[3]       = {{RES_EXIST, {&rst_13}}, {RES_PROPERTY, {&rst_14}}, {RES_PROPERTY, {&rst_15}}};
	RESTRICTION_AND_OR rst_17   = {std::size(rst_16), rst_16};

	/* C5: !have(clipend) && recurring && apptstartwhole <= end */
	RESTRICTION_EXIST rst_18    = {ptag.clipend};
	RESTRICTION rst_19          = {RES_EXIST, {&rst_18}};
	RESTRICTION_PROPERTY rst_20 = {RELOP_EQ, ptag.recurring, {ptag.recurring, deconst(&fixed_true)}};
	RESTRICTION_PROPERTY rst_21 = {RELOP_LE, ptag.apptstartwhole, {ptag.apptstartwhole, &end_nttime}};
	RESTRICTION rst_22[3]       = {{RES_NOT, {&rst_19}}, {RES_PROPERTY, {&rst_20}}, {RES_PROPERTY, {&rst_21}}};
	RESTRICTION_AND_OR rst_23   = {std::size(rst_22), rst_22};

	/* OR over C1-C5 */
	RESTRICTION rst_24[5]       = {{RES_AND, {&rst_4}}, {RES_AND, {&rst_8}}, {RES_AND, {&rst_12}}, {RES_AND, {&rst_17}}, {RES_AND, {&rst_23}}};
	RESTRICTION_AND_OR rst_25   = {std::size(rst_24), rst_24};
	RESTRICTION rst_26          = {RES_OR, {&rst_25}};

	uint32_t table_id = 0, row_count = 0;
	if (!exmdb_client.load_content_table(dir, 0, rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR),
	    nullptr, TABLE_FLAG_NONOTIFICATIONS, &rst_26, nullptr, &table_id, &row_count))
		throw DispatchError(E3019);
	auto cl_0 = make_scope_exit([&]() {
		exmdb_client.unload_table(dir, table_id);
	});
	uint32_t proptag_buff[] = {
		ptag.apptstartwhole, ptag.apptendwhole, ptag.busystatus,
		ptag.recurring, ptag.apptrecur, ptag.apptsubtype, ptag.private_flag,
		ptag.apptstateflags, ptag.location, ptag.reminderset,
		ptag.globalobjectid, ptag.timezonestruct, PR_SUBJECT,
	};
	const PROPTAG_ARRAY proptags = {std::size(proptag_buff), deconst(proptag_buff)};
	TARRAY_SET rows;
	if (!exmdb_client.query_table(dir, nullptr, 0, table_id, &proptags, 0,
	    row_count, &rows))
		throw DispatchError(E3020);
	auto &cal_events = CalendarEventArray.emplace();
	cal_events.reserve(rows.count);

	for (size_t i = 0; i < rows.count; ++i) {
		std::string uid_buf;
		if (!goid_to_icaluid(rows.pparray[i]->get<BINARY>(ptag.globalobjectid), uid_buf))
			continue;
		auto ts = rows.pparray[i]->get<const uint64_t>(ptag.apptstartwhole);
		if (ts == nullptr)
			continue;
		auto start_whole = rop_util_nttime_to_unix(*ts);
		ts = rows.pparray[i]->get<uint64_t>(ptag.apptendwhole);
		if (ts == nullptr)
			continue;
		auto end_whole   = rop_util_nttime_to_unix(*ts);
		auto subject     = rows.pparray[i]->get<const char>(PR_SUBJECT);
		auto location    = rows.pparray[i]->get<const char>(ptag.location);
		auto flag        = rows.pparray[i]->get<const uint8_t>(ptag.reminderset);
		bool is_reminder = flag != nullptr && *flag != 0;
		flag = rows.pparray[i]->get<uint8_t>(ptag.private_flag);
		bool is_private  = flag != nullptr && *flag != 0;
		auto num = rows.pparray[i]->get<const uint32_t>(ptag.busystatus);
		uint32_t busy_type = num == nullptr || *num > olWorkingElsewhere ? 0 : *num;
		num = rows.pparray[i]->get<uint32_t>(ptag.apptstateflags);
		bool is_meeting = num != nullptr && *num & asfMeeting;
		flag = rows.pparray[i]->get<uint8_t>(ptag.recurring);
		if (flag == nullptr || *flag == 0) {
			cal_events.emplace_back(start_whole, end_whole,
				busy_type, uid_buf.c_str(), subject, location,
				is_meeting, false, false, is_reminder,
				is_private, detailed);
			continue;
		}
		EXT_PULL epull;
		std::optional<ical_component> tzcom;
		auto bin = rows.pparray[i]->get<const BINARY>(ptag.timezonestruct);
		if (bin != nullptr) {
			TIMEZONESTRUCT tz;
			epull.init(bin->pb, bin->cb, malloc, EXT_FLAG_UTF16);
			if (epull.g_tzstruct(&tz) != EXT_ERR_SUCCESS)
				continue;
			tzcom = tz_to_vtimezone(1600, "timezone", tz);
			if (!tzcom.has_value())
				continue;
		}
		bin = rows.pparray[i]->get<BINARY>(ptag.apptrecur);
		if(bin == nullptr)
			continue;
		APPOINTMENT_RECUR_PAT apprecurr;
		epull.init(bin->pb, bin->cb, malloc, EXT_FLAG_UTF16);
		if (epull.g_apptrecpat(&apprecurr) != EXT_ERR_SUCCESS)
			continue;
		std::vector<event> event_list;
		if (!find_recur_times(tzcom.has_value() ? &*tzcom : nullptr,
		    start_whole, apprecurr, start_time, end_time, event_list))
			continue;

		for (const auto &event : event_list) {
			if (event.ei == nullptr || event.xe == nullptr) {
				cal_events.emplace_back(event.start_time,
					event.end_time, busy_type, uid_buf.c_str(),
					subject, location, is_meeting, TRUE,
					false, is_reminder, is_private, detailed);
				continue;
			}
			bool ov_meeting  = (event.ei->overrideflags & ARO_MEETINGTYPE) ? event.ei->meetingtype & 1 : is_meeting;
			bool ov_reminder = (event.ei->overrideflags & ARO_REMINDER)    ? event.ei->reminderset == 0 : is_reminder;
			uint32_t ov_busy = (event.ei->overrideflags & ARO_BUSYSTATUS)  ? event.ei->busystatus : busy_type;
			auto ov_subj     = (event.ei->overrideflags & ARO_SUBJECT)     ? event.xe->subject : subject;
			auto ov_location = (event.ei->overrideflags & ARO_LOCATION)    ? event.xe->location : location;
			cal_events.emplace_back(event.start_time, event.end_time,
				ov_busy, uid_buf, ov_subj, ov_location,
				ov_meeting, TRUE, TRUE, ov_reminder, is_private,
				detailed);
		}
	}
	cl_0.release();
	if (!exmdb_client.unload_table(dir, table_id))
		throw DispatchError(E3019);
}

} //namespace EWS::Structures
