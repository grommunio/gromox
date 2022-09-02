// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// A fugly copy of oxcical.cpp
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/cookie_parser.hpp>
#include <gromox/endian.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/list_file.hpp>
#include <gromox/mapidefs.h>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/socket.h>
#include <gromox/util.hpp>
#define TRY(expr) do { int klfdv = (expr); if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

enum { /* for PidLidAppointmentStateFlags */
	asfMeeting = 0x1U,
	asfReceived = 0x2U,
	asfCanceled = 0x4U,
};

namespace {

struct event_node {
	time_t start_time = 0, end_time = 0;
	EXCEPTIONINFO *pexception = nullptr;
	EXTENDEDEXCEPTION *pex_exception = nullptr;
};

}

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

static time_t g_end_time;
static time_t g_start_time;
static const char *g_username;
static std::optional<ical_component> g_tz_component;
static constexpr char fmt_datetimelcl[] = "%04d%02d%02dT%02d%02d%02d",
	fmt_datetimeutc[] = "%04d%02d%02dT%02d%02d%02dZ";

static int sprintf_dtutc(char *b, size_t z, const ICAL_TIME &t)
{
	return snprintf(b, z, fmt_datetimeutc, t.year, t.month, t.day, t.hour,
	       t.minute, t.second);
}

static std::optional<ical_component> tzstruct_to_vtimezone(int year,
    const char *tzid, TIMEZONESTRUCT *ptzstruct) try
{
	int day;
	int order;
	char tmp_buff[1024];
	
	auto pcomponent = std::make_optional<ical_component>("VTIMEZONE");
	auto piline = &pcomponent->append_line("TZID", tzid);
	/* STANDARD component */
	auto pcomponent1 = &pcomponent->append_comp("STANDARD");
	if (0 == ptzstruct->daylightdate.month) {
		strcpy(tmp_buff, "16010101T000000");
	} else if (ptzstruct->standarddate.year == 0) {
		day = ical_get_dayofmonth(year,
			ptzstruct->standarddate.month,
			ptzstruct->standarddate.day,
			ptzstruct->standarddate.dayofweek);
		snprintf(tmp_buff, arsizeof(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->standarddate.month,
			day, (int)ptzstruct->standarddate.hour,
			(int)ptzstruct->standarddate.minute,
			(int)ptzstruct->standarddate.second);
	} else if (1 == ptzstruct->standarddate.year) {
		snprintf(tmp_buff, arsizeof(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->standarddate.month,
			(int)ptzstruct->standarddate.day,
			(int)ptzstruct->standarddate.hour,
			(int)ptzstruct->standarddate.minute,
			(int)ptzstruct->standarddate.second);
	} else {
		return {};
	}
	pcomponent1->append_line("DTSTART", tmp_buff);
	if (0 != ptzstruct->daylightdate.month) {
		if (0 == ptzstruct->standarddate.year) {
			auto piline = &pcomponent1->append_line("RRULE");
			piline->append_value("FREQ", "YEARLY");
			order = ptzstruct->standarddate.day;
			if (order == 5)
				order = -1;
			auto dow = weekday_to_str(ptzstruct->standarddate.dayofweek);
			if (dow == nullptr)
				return {};
			snprintf(tmp_buff, std::size(tmp_buff), "%d%s", order, dow);
			piline->append_value("BYDAY", tmp_buff);
			snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->standarddate.month);
			piline->append_value("BYMONTH", tmp_buff);
		} else if (1 == ptzstruct->standarddate.year) {
			piline = &pcomponent->append_line("RRULE");
			piline->append_value("FREQ", "YEARLY");
			snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->standarddate.day);
			piline->append_value("BYMONTHDAY", tmp_buff);
			snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->standarddate.month);
			piline->append_value("BYMONTH", tmp_buff);
		}
	}
	int utc_offset = -(ptzstruct->bias + ptzstruct->daylightbias);
	tmp_buff[0] = utc_offset >= 0 ? '+' : '-';
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	pcomponent1->append_line("TZOFFSETFROM", tmp_buff);
	utc_offset = -(ptzstruct->bias + ptzstruct->standardbias);
	tmp_buff[0] = utc_offset >= 0 ? '+' : '-';
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	pcomponent1->append_line("TZOFFSETTO", tmp_buff);
	if (ptzstruct->daylightdate.month == 0)
		return pcomponent;
	/* DAYLIGHT component */
	pcomponent1 = &pcomponent->append_comp("DAYLIGHT");
	if (0 == ptzstruct->daylightdate.year) {
		day = ical_get_dayofmonth(year,
			ptzstruct->daylightdate.month,
			ptzstruct->daylightdate.day,
			ptzstruct->daylightdate.dayofweek);
		snprintf(tmp_buff, arsizeof(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->daylightdate.month,
			day, (int)ptzstruct->daylightdate.hour,
			(int)ptzstruct->daylightdate.minute,
			(int)ptzstruct->daylightdate.second);
	} else if (1 == ptzstruct->daylightdate.year) {
		snprintf(tmp_buff, arsizeof(tmp_buff), fmt_datetimelcl,
			year, (int)ptzstruct->daylightdate.month,
			(int)ptzstruct->daylightdate.day,
			(int)ptzstruct->daylightdate.hour,
			(int)ptzstruct->daylightdate.minute,
			(int)ptzstruct->daylightdate.second);
	} else {
		return {};
	}
	pcomponent1->append_line("DTSTART", tmp_buff);
	if (0 == ptzstruct->daylightdate.year) {
		auto piline = &pcomponent1->append_line("RRULE");
		piline->append_value("FREQ", "YEARLY");
		order = ptzstruct->daylightdate.day;
		if (order == 5)
			order = -1;
		auto dow = weekday_to_str(ptzstruct->daylightdate.dayofweek);
		if (dow == nullptr)
			return {};
		snprintf(tmp_buff, std::size(tmp_buff), "%d%s", order, dow);
		piline->append_value("BYDAY", tmp_buff);
		snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->daylightdate.month);
		piline->append_value("BYMONTH", tmp_buff);
	} else if (1 == ptzstruct->daylightdate.year) {
		auto piline = &pcomponent1->append_line("RRULE");
		piline->append_value("FREQ", "YEARLY");
		snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->daylightdate.day);
		piline->append_value("BYMONTHDAY", tmp_buff);
		snprintf(tmp_buff, arsizeof(tmp_buff), "%d", (int)ptzstruct->daylightdate.month);
		piline->append_value("BYMONTH", tmp_buff);
	}
	utc_offset = -(ptzstruct->bias + ptzstruct->standardbias);
	tmp_buff[0] = utc_offset >= 0 ? '+' : '-';
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	pcomponent1->append_line("TZOFFSETFROM", tmp_buff);
	utc_offset = -(ptzstruct->bias + ptzstruct->daylightbias);
	tmp_buff[0] = utc_offset >= 0 ? '+' : '-';
	utc_offset = abs(utc_offset);
	sprintf(tmp_buff + 1, "%02d%02d", utc_offset/60, utc_offset%60);
	pcomponent1->append_line("TZOFFSETTO", tmp_buff);
	return pcomponent;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2092: ENOMEM\n");
	return {};
}

static BOOL recurrencepattern_to_rrule(const ical_component &tzcom,
    time_t whole_start_time, const APPOINTMENT_RECUR_PAT *apr,
    ICAL_RRULE *pirrule) try
{
	ICAL_TIME itime;
	char tmp_buff[1024];
	
	ical_line iline("RRULE");
	auto piline = &iline;
	switch (apr->recur_pat.patterntype) {
	case PATTERNTYPE_DAY:
		piline->append_value("FREQ", "DAILY");
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period/1440);
		piline->append_value("INTERVAL", tmp_buff);
		break;
	case PATTERNTYPE_WEEK: {
		piline->append_value("FREQ", "WEEKLY");
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period);
		piline->append_value("INTERVAL", tmp_buff);
		auto &pivalue = piline->append_value("BYDAY");
		for (unsigned int wd = 0; wd < 7; ++wd)
			if (apr->recur_pat.pts.weekrecur & (1 << wd))
				pivalue.append_subval(weekday_to_str(wd));
		break;
	}
	case PATTERNTYPE_MONTH:
	case PATTERNTYPE_HJMONTH: {
		auto monthly = apr->recur_pat.period % 12 != 0;
		piline->append_value("FREQ", monthly ? "MONTHLY" : "YEARLY");
		if (monthly) {
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period);
			piline->append_value("INTERVAL", tmp_buff);
			if (apr->recur_pat.pts.dayofmonth == 31)
				strcpy(tmp_buff, "-1");
			else
				snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.pts.dayofmonth);
			piline->append_value("BYMONTHDAY", tmp_buff);
		} else {
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period/12);
			piline->append_value("INTERVAL", tmp_buff);
			if (apr->recur_pat.pts.dayofmonth == 31)
				strcpy(tmp_buff, "-1");
			else
				snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.pts.dayofmonth);
			piline->append_value("BYMONTHDAY", tmp_buff);
			ical_get_itime_from_yearday(1601, apr->recur_pat.firstdatetime / 1440 + 1, &itime);
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", itime.month);
			piline->append_value("BYMONTH", tmp_buff);
		}
		break;
	}
	case PATTERNTYPE_MONTHNTH:
	case PATTERNTYPE_HJMONTHNTH: {
		auto monthly = apr->recur_pat.period % 12 != 0;
		piline->append_value("FREQ", monthly ? "MONTHLY" : "YEARLY");
		if (monthly) {
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period);
			piline->append_value("INTERVAL", tmp_buff);
			auto &pivalue = piline->append_value("BYDAY");
			for (unsigned int wd = 0; wd < 7; ++wd)
				if (apr->recur_pat.pts.monthnth.weekrecur & (1 << wd))
					pivalue.append_subval(weekday_to_str(wd));
			if (apr->recur_pat.pts.monthnth.recurnum == 5)
				strcpy(tmp_buff, "-1");
			else
				snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.pts.monthnth.recurnum);
			piline->append_value("BYSETPOS", tmp_buff);
		} else {
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.period / 12);
			piline->append_value("INTERVAL", tmp_buff);
			auto &pivalue = piline->append_value("BYDAY");
			for (unsigned int wd = 0; wd < 7; ++wd)
				if (apr->recur_pat.pts.monthnth.weekrecur & (1 << wd))
					pivalue.append_subval(weekday_to_str(wd));
			if (apr->recur_pat.pts.monthnth.recurnum == 5)
				strcpy(tmp_buff, "-1");
			else
				snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.pts.monthnth.recurnum);
			piline->append_value("BYSETPOS", tmp_buff);
			snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.firstdatetime);
			piline->append_value("BYMONTH", tmp_buff);
		}
		break;
	}
	default:
		return FALSE;
	}
	if (apr->recur_pat.endtype == ENDTYPE_AFTER_N_OCCURRENCES) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "%u", apr->recur_pat.occurrencecount);
		piline->append_value("COUNT", tmp_buff);
	} else if (apr->recur_pat.endtype == ENDTYPE_AFTER_DATE) {
		ical_utc_to_datetime(&tzcom, rop_util_rtime_to_unix(apr->recur_pat.enddate + apr->starttimeoffset), &itime);
		sprintf_dtutc(tmp_buff, std::size(tmp_buff), itime);
		piline->append_value("UNTIL", tmp_buff);
	}
	if (apr->recur_pat.patterntype == PATTERNTYPE_WEEK) {
		auto wd = weekday_to_str(apr->recur_pat.firstdow);
		if (wd == nullptr)
			return FALSE;
		piline->append_value("WKST", wd);
	}
	return ical_parse_rrule(&tzcom, whole_start_time,
		&piline->value_list, pirrule) ? TRUE : false;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-2093: ENOMEM\n");
	return false;
}

static BOOL find_recurrence_times(ical_component &tzcom,
    time_t whole_start_time, const APPOINTMENT_RECUR_PAT *apr,
	time_t start_time, time_t end_time, std::list<event_node> &plist)
{
	int i;
	time_t tmp_time;
	time_t tmp_time1;
	ICAL_RRULE irrule;

	if (!recurrencepattern_to_rrule(tzcom, whole_start_time,
	    apr, &irrule))
		return FALSE;	
	plist.clear();
	do {
		auto itime = irrule.instance_itime;
		ical_itime_to_utc(&tzcom, itime, &tmp_time);
		if (tmp_time < start_time)
			continue;
		ical_itime_to_utc(NULL, itime, &tmp_time1);
		for (i = 0; i < apr->exceptioncount; ++i) {
			if (tmp_time1 == rop_util_rtime_to_unix(apr->pexceptioninfo[i].originalstartdate))
				break;
		}
		if (i < apr->exceptioncount)
			continue;
		plist.emplace_back();
		auto pevnode = &plist.back();
		pevnode->start_time = tmp_time;
		pevnode->end_time = tmp_time + (apr->endtimeoffset - apr->starttimeoffset) * 60;
		pevnode->pexception = NULL;
		pevnode->pex_exception = NULL;
		if (tmp_time >= end_time)
			break;
	} while (irrule.iterate());
	for (i = 0; i < apr->exceptioncount; ++i) {
		tmp_time = rop_util_rtime_to_unix(apr->pexceptioninfo[i].startdatetime);
		ICAL_TIME itime;
		ical_utc_to_datetime(NULL, tmp_time, &itime);
		ical_itime_to_utc(&tzcom, itime, &tmp_time);
		if (tmp_time < start_time || tmp_time > end_time)
			continue;
		plist.emplace_back();
		auto pevnode = &plist.back();
		pevnode->start_time = tmp_time;
		tmp_time = rop_util_rtime_to_unix(apr->pexceptioninfo[i].enddatetime);
		ical_utc_to_datetime(NULL, tmp_time, &itime);
		ical_itime_to_utc(&tzcom, itime, &tmp_time);
		pevnode->end_time = tmp_time;
		pevnode->pexception = apr->pexceptioninfo + i;
		pevnode->pex_exception = apr->pextendedexception + i;
	}
	return TRUE;
}

static BOOL make_ical_uid(BINARY *pglobal_obj, char *uid_buff)
{
	GUID guid;
	time_t cur_time;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	char tmp_buff[256];
	char tmp_buff1[256];
	GLOBALOBJECTID globalobjectid;
	
	if (NULL != pglobal_obj) {
		ext_pull.init(pglobal_obj->pb, pglobal_obj->cb, malloc, 0);
		if (ext_pull.g_goid(&globalobjectid, 1) != EXT_ERR_SUCCESS)
			return FALSE;
		if (globalobjectid.data.cb >= sizeof(ThirdPartyGlobalId) &&
		    memcmp(globalobjectid.data.pb, ThirdPartyGlobalId, sizeof(ThirdPartyGlobalId)) == 0) {
			if (globalobjectid.data.cb - 12 > sizeof(tmp_buff) - 1) {
				memcpy(tmp_buff, globalobjectid.data.pb + 12,
									sizeof(tmp_buff) - 1);
				tmp_buff[sizeof(tmp_buff) - 1] = '\0';
			} else {
				memcpy(tmp_buff, globalobjectid.data.pb + 12,
								globalobjectid.data.cb - 12);
				tmp_buff[globalobjectid.data.cb - 12] = '\0';
			}
			strcpy(uid_buff, tmp_buff);
		} else {
			globalobjectid.year = 0;
			globalobjectid.month = 0;
			globalobjectid.day = 0;
			if (!ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
			    ext_push.p_goid(globalobjectid) != EXT_ERR_SUCCESS)
				return false;
			if (!encode_hex_binary(tmp_buff, ext_push.m_offset,
			    tmp_buff1, sizeof(tmp_buff1)))
				return FALSE;
			HX_strupper(tmp_buff1);
			strcpy(uid_buff, tmp_buff1);
		}
	} else {
		time(&cur_time);
		memset(&globalobjectid, 0, sizeof(GLOBALOBJECTID));
		globalobjectid.arrayid = EncodedGlobalId;
		globalobjectid.creationtime = rop_util_unix_to_nttime(cur_time);
		globalobjectid.data.cb = 16;
		globalobjectid.data.pv = tmp_buff1;
		guid = GUID::random_new();
		if (!ext_push.init(tmp_buff1, 16, 0) ||
		    ext_push.p_guid(guid) != EXT_ERR_SUCCESS ||
		    !ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
		    ext_push.p_goid(globalobjectid) != EXT_ERR_SUCCESS)
			return false;
		if (!encode_hex_binary(tmp_buff, ext_push.m_offset, tmp_buff1,
		    sizeof(tmp_buff1)))
			return FALSE;
		HX_strupper(tmp_buff1);
		strcpy(uid_buff, tmp_buff1);
	}
	return TRUE;
}

static void output_event(time_t start_time, time_t end_time,
	uint32_t busy_type, const char *uid, const char *subject,
	const char *location, BOOL b_meeting, BOOL b_recurring,
	BOOL b_exception, BOOL b_reminder, BOOL b_private)
{
	size_t tmp_len;
	ICAL_TIME itime;
	char tmp_buff[4096];
	
	if (!g_tz_component.has_value()) {
		printf("{\"StartTime\":%lld, ", static_cast<long long>(start_time));
		printf("\"EndTime\":%lld, ", static_cast<long long>(end_time));
	} else {
		ical_utc_to_datetime(&*g_tz_component, start_time, &itime);
		printf("{\"StartTime\":\"%d-%02d-%02dT%02d:%02d:%02d\", ",
					itime.year, itime.month, itime.day, itime.hour,
					itime.minute, itime.second);
		ical_utc_to_datetime(&*g_tz_component, end_time, &itime);
		printf("\"EndTime\":\"%d-%02d-%02dT%02d:%02d:%02d\", ",
				itime.year, itime.month, itime.day, itime.hour,
				itime.minute, itime.second);
	}
	switch (busy_type) {
	case 0x00000000:
		strcpy(tmp_buff, "Free");
		break;
	case 0x00000001:
		strcpy(tmp_buff, "Tentative");
		break;
	case 0x00000002:
		strcpy(tmp_buff, "Busy");
		break;
	case 0x00000003:
		strcpy(tmp_buff, "OOF");
		break;
	case 0x00000004:
		strcpy(tmp_buff, "WorkingElsewhere");
		break;
	default:
		strcpy(tmp_buff, "NoData");
		break;
	}
	printf("\"BusyType\":\"%s\", ", tmp_buff);
	printf("\"ID\":\"%s\", ", uid);
	if (subject != nullptr) {
		encode64(subject, strlen(subject),
		         tmp_buff, sizeof(tmp_buff), &tmp_len);
		printf("\"Subject\":\"%s\", ", tmp_buff);
	}
	if (location != nullptr) {
		encode64(location, strlen(location),
		         tmp_buff, sizeof(tmp_buff), &tmp_len);
		printf("\"Location\":\"%s\", ", tmp_buff);
	}
	printf(b_meeting ? "\"IsMeeting\":true, " : "\"IsMeeting\":false, ");
	printf(b_recurring ? "\"IsRecurring\":true, " : "\"IsRecurring\":false, ");
	printf(b_exception ? "\"IsException\":true, " : "\"IsException\":false, ");
	printf(b_reminder ? "\"IsReminderSet\":true, " : "\"IsReminderSet\":false, ");
	printf(b_private ? "\"IsPrivate\":true}" : "\"IsPrivate\":false}");
}

static BOOL get_freebusy(const char *dir)
{
	uint32_t table_id;
	uint32_t row_count;
	TARRAY_SET tmp_set;
	uint32_t permission;
	PROPID_ARRAY propids;
	PROPTAG_ARRAY proptags;
	RESTRICTION restriction;
	PROPERTY_NAME tmp_propnames[13];
	PROPNAME_ARRAY propnames;
	uint32_t tmp_proptags[13];
	
	auto start_nttime = rop_util_unix_to_nttime(g_start_time);
	auto end_nttime = rop_util_unix_to_nttime(g_end_time);
	propnames.count = 13;
	propnames.ppropname = tmp_propnames;
	for (size_t i = 0; i < arsizeof(tmp_propnames); ++i)
		tmp_propnames[i].kind = MNID_ID;
	for (size_t i = 0; i < 5; ++i)
		tmp_propnames[i].guid = PSETID_APPOINTMENT;
	tmp_propnames[0].lid = PidLidAppointmentStartWhole;
	tmp_propnames[1].lid = PidLidAppointmentEndWhole;
	tmp_propnames[2].lid = PidLidBusyStatus;
	tmp_propnames[3].lid = PidLidRecurring;
	tmp_propnames[4].lid = PidLidAppointmentRecur;
	tmp_propnames[5].lid = PidLidAppointmentSubType;

	tmp_propnames[6].guid = PSETID_COMMON;
	tmp_propnames[6].lid = PidLidPrivate;
	tmp_propnames[7].guid = PSETID_APPOINTMENT;
	tmp_propnames[7].lid = PidLidAppointmentStateFlags;
	tmp_propnames[8].guid = PSETID_APPOINTMENT;
	tmp_propnames[8].lid = PidLidClipEnd;
	tmp_propnames[9].guid = PSETID_APPOINTMENT;
	tmp_propnames[9].lid = PidLidLocation;
	tmp_propnames[10].guid = PSETID_COMMON;
	tmp_propnames[10].lid = PidLidReminderSet;
	tmp_propnames[11].guid = PSETID_MEETING;
	tmp_propnames[11].lid = PidLidGlobalObjectId;
	tmp_propnames[12].guid = PSETID_APPOINTMENT;
	tmp_propnames[12].lid = PidLidTimeZoneStruct;
	
	if (!exmdb_client::get_named_propids(dir, FALSE, &propnames, &propids))
		return FALSE;
	if (propids.count != propnames.count)
		return FALSE;
	uint32_t pidlidappointmentstartwhole = PROP_TAG(PT_SYSTIME, propids.ppropid[0]);
	uint32_t pidlidappointmentendwhole = PROP_TAG(PT_SYSTIME, propids.ppropid[1]);
	uint32_t pidlidbusystatus = PROP_TAG(PT_LONG, propids.ppropid[2]);
	uint32_t pidlidrecurring = PROP_TAG(PT_BOOLEAN, propids.ppropid[3]);
	uint32_t pidlidappointmentrecur = PROP_TAG(PT_BINARY, propids.ppropid[4]);
	uint32_t pidlidappointmentsubtype = PROP_TAG(PT_BOOLEAN, propids.ppropid[5]);
	uint32_t pidlidprivate = PROP_TAG(PT_BOOLEAN, propids.ppropid[6]);
	uint32_t pidlidappointmentstateflags = PROP_TAG(PT_LONG, propids.ppropid[7]);
	uint32_t pidlidclipend = PROP_TAG(PT_SYSTIME, propids.ppropid[8]);
	uint32_t pidlidlocation = PROP_TAG(PT_UNICODE, propids.ppropid[9]);
	uint32_t pidlidreminderset = PROP_TAG(PT_BOOLEAN, propids.ppropid[10]);
	uint32_t pidlidglobalobjectid = PROP_TAG(PT_BINARY, propids.ppropid[11]);
	uint32_t pidlidtimezonestruct = PROP_TAG(PT_BINARY, propids.ppropid[12]);
	
	if (NULL != g_username) {
		if (!exmdb_client::check_folder_permission(dir,
		    rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR),
		    g_username, &permission))
			return FALSE;
		if (!(permission & (frightsFreeBusySimple |
		    frightsFreeBusyDetailed | frightsReadAny))) {
			printf("{\"dir\":\"%s\", \"permission\":\"none\"}\n", dir);
			return TRUE;
		}
	} else {
		permission = frightsFreeBusyDetailed | frightsReadAny;
	}
	uint8_t tmp_true = 1;
	restriction.rt = RES_OR;
	restriction.pres = me_alloc<RESTRICTION_AND_OR>();
	auto andor = restriction.andor;
	andor->count = 4;
	auto prestriction = me_alloc<RESTRICTION>(4);
	andor->pres = prestriction;
	/*OR (pidlidappointmentstartwhole >= start
		&& pidlidappointmentstartwhole <= end) */
	prestriction[0].rt = RES_AND;
	prestriction[0].pres = me_alloc<RESTRICTION_AND_OR>();
	andor = prestriction[0].andor;
	auto prestriction1 = me_alloc<RESTRICTION>(2);
	andor->count = 2;
	andor->pres = prestriction1;
	prestriction1[0].rt = RES_PROPERTY;
	prestriction1[0].pres = me_alloc<RESTRICTION_PROPERTY>();
	auto rprop = prestriction1[0].prop;
	rprop->relop = RELOP_GE;
	rprop->proptag = pidlidappointmentstartwhole;
	rprop->propval.proptag = pidlidappointmentstartwhole;
	rprop->propval.pvalue = &start_nttime;
	prestriction1[1].rt = RES_PROPERTY;
	prestriction1[1].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction1[1].prop;
	rprop->relop = RELOP_LE;
	rprop->proptag = pidlidappointmentstartwhole;
	rprop->propval.proptag = pidlidappointmentstartwhole;
	rprop->propval.pvalue = &end_nttime;
	/* OR (pidlidappointmentendwhole >= start
		&& pidlidappointmentendwhole <= end) */
	prestriction[1].rt = RES_AND;
	prestriction[1].pres = me_alloc<RESTRICTION_AND_OR>();
	andor = prestriction[1].andor;
	prestriction1 = me_alloc<RESTRICTION>(2);
	andor->count = 2;
	andor->pres = prestriction1;
	prestriction1[0].rt = RES_PROPERTY;
	prestriction1[0].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction1[0].prop;
	rprop->relop = RELOP_GE;
	rprop->proptag = pidlidappointmentendwhole;
	rprop->propval.proptag = pidlidappointmentendwhole;
	rprop->propval.pvalue = &start_nttime;
	prestriction1[1].rt = RES_PROPERTY;
	prestriction1[1].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction1[1].prop;
	rprop->relop = RELOP_LE;
	rprop->proptag = pidlidappointmentendwhole;
	rprop->propval.proptag = pidlidappointmentendwhole;
	rprop->propval.pvalue = &end_nttime;
	/* OR (pidlidappointmentstartwhole < start
		&& pidlidappointmentendwhole > end) */
	prestriction[2].rt = RES_AND;
	prestriction[2].pres = me_alloc<RESTRICTION_AND_OR>();
	andor = prestriction[2].andor;
	prestriction1 = me_alloc<RESTRICTION>(2);
	andor->count = 2;
	andor->pres = prestriction1;
	prestriction1[0].rt = RES_PROPERTY;
	prestriction1[0].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction1[0].prop;
	rprop->relop = RELOP_LT;
	rprop->proptag = pidlidappointmentstartwhole;
	rprop->propval.proptag = pidlidappointmentstartwhole;
	rprop->propval.pvalue = &start_nttime;
	prestriction1[1].rt = RES_PROPERTY;
	prestriction1[1].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction1[1].prop;
	rprop->relop = RELOP_GT;
	rprop->proptag = pidlidappointmentendwhole;
	rprop->propval.proptag = pidlidappointmentendwhole;
	rprop->propval.pvalue = &end_nttime;
	/* OR */
	prestriction[3].rt = RES_OR;
	prestriction[3].pres = me_alloc<RESTRICTION_AND_OR>();
	andor = prestriction[3].andor;
	prestriction1 = me_alloc<RESTRICTION>(2);
	andor->count = 2;
	andor->pres = prestriction1;
	/* OR (EXIST(pidlidclipend) &&
		pidlidrecurring == true &&
		pidlidclipend >= start) */
	prestriction1[0].rt = RES_AND;
	prestriction1[0].pres = me_alloc<RESTRICTION_AND_OR>();
	andor = prestriction1[0].andor;
	andor->count = 3;
	auto prestriction2 = me_alloc<RESTRICTION>(3);
	andor->pres = prestriction2;
	prestriction2[0].rt = RES_EXIST;
	prestriction2[0].pres = me_alloc<RESTRICTION_EXIST>();
	auto rex = prestriction2[0].exist;
	rex->proptag = pidlidclipend;
	prestriction2[1].rt = RES_PROPERTY;
	prestriction2[1].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction2[1].prop;
	rprop->relop = RELOP_EQ;
	rprop->proptag = pidlidrecurring;
	rprop->propval.proptag = pidlidrecurring;
	rprop->propval.pvalue = &tmp_true;
	prestriction2[2].rt = RES_PROPERTY;
	prestriction2[2].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction2[2].prop;
	rprop->relop = RELOP_GE;
	rprop->proptag = pidlidclipend;
	rprop->propval.proptag = pidlidclipend;
	rprop->propval.pvalue = &start_nttime;
	/* OR (!EXIST(pidlidclipend) &&
		pidlidrecurring == true &&
		pidlidappointmentstartwhole <= end) */
	prestriction1[1].rt = RES_AND;
	prestriction1[1].pres = me_alloc<RESTRICTION_AND_OR>();
	andor = prestriction1[1].andor;
	andor->count = 3;
	prestriction2 = me_alloc<RESTRICTION>(3);
	andor->pres = prestriction2;
	prestriction2[0].rt = RES_NOT;
	auto prestriction3 = me_alloc<RESTRICTION>();
	prestriction2[0].pres = prestriction3;
	prestriction3->rt = RES_EXIST;
	prestriction3->pres = me_alloc<RESTRICTION_EXIST>();
	rex = prestriction3->exist;
	rex->proptag = pidlidclipend;
	prestriction2[1].rt = RES_PROPERTY;
	prestriction2[1].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction2[1].prop;
	rprop->relop = RELOP_EQ;
	rprop->proptag = pidlidrecurring;
	rprop->propval.proptag = pidlidrecurring;
	rprop->propval.pvalue = &tmp_true;
	prestriction2[2].rt = RES_PROPERTY;
	prestriction2[2].pres = me_alloc<RESTRICTION_PROPERTY>();
	rprop = prestriction2[2].prop;
	rprop->relop = RELOP_LE;
	rprop->proptag = pidlidappointmentstartwhole;
	rprop->propval.proptag = pidlidappointmentstartwhole;
	rprop->propval.pvalue = &end_nttime;
	/* end of OR */
	
	if (!exmdb_client::load_content_table(dir, 0,
	    rop_util_make_eid_ex(1, PRIVATE_FID_CALENDAR),
	    nullptr, TABLE_FLAG_NONOTIFICATIONS, &restriction, nullptr,
	    &table_id, &row_count))
		return FALSE;
	proptags.count = 13;
	proptags.pproptag = tmp_proptags;
	tmp_proptags[0] = pidlidappointmentstartwhole;
	tmp_proptags[1] = pidlidappointmentendwhole;
	tmp_proptags[2] = pidlidbusystatus;
	tmp_proptags[3] = pidlidrecurring;
	tmp_proptags[4] = pidlidappointmentrecur;
	tmp_proptags[5] = pidlidappointmentsubtype;
	tmp_proptags[6] = pidlidprivate;
	tmp_proptags[7] = pidlidappointmentstateflags;
	tmp_proptags[8] = pidlidlocation;
	tmp_proptags[9] = pidlidreminderset;
	tmp_proptags[10] = pidlidglobalobjectid;
	tmp_proptags[11] = pidlidtimezonestruct;
	tmp_proptags[12] = PR_SUBJECT;
	if (!exmdb_client::query_table(dir, nullptr, 0, table_id, &proptags,
	    0, row_count, &tmp_set))
		return FALSE;	
	printf("{\"dir\":\"%s\", \"permission\":", dir);
	printf((permission & (frightsFreeBusyDetailed | frightsReadAny)) ?
	       "\"detailed\", " : "\"simple\", ");
	printf("\"events\":[");

	BOOL b_first = FALSE;
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto ts = tmp_set.pparray[i]->get<const uint64_t>(pidlidappointmentstartwhole);
		if (ts == nullptr)
			continue;
		auto whole_start_time = rop_util_nttime_to_unix(*ts);
		ts = tmp_set.pparray[i]->get<uint64_t>(pidlidappointmentendwhole);
		if (ts == nullptr)
			continue;
		auto whole_end_time = rop_util_nttime_to_unix(*ts);
		char uid_buff[256];
		if (!make_ical_uid(tmp_set.pparray[i]->get<BINARY>(pidlidglobalobjectid), uid_buff))
			continue;
		auto psubject = tmp_set.pparray[i]->get<const char>(PR_SUBJECT);
		auto plocation = tmp_set.pparray[i]->get<const char>(pidlidlocation);
		auto pflag = tmp_set.pparray[i]->get<const uint8_t>(pidlidreminderset);
		BOOL b_reminder = pflag != nullptr && *pflag != 0 ? TRUE : false;
		pflag = tmp_set.pparray[i]->get<uint8_t>(pidlidprivate);
		BOOL b_private = pflag != nullptr && *pflag != 0 ? TRUE : false;
		auto num = tmp_set.pparray[i]->get<const uint32_t>(pidlidbusystatus);
		uint32_t busy_type = 0;
		if (num != nullptr) {
			busy_type = *num;
			if (busy_type > olWorkingElsewhere)
				busy_type = 0;
		}
		num = tmp_set.pparray[i]->get<uint32_t>(pidlidappointmentstateflags);
		BOOL b_meeting = (num != nullptr && *num & asfMeeting) ? TRUE : false;
		pflag = tmp_set.pparray[i]->get<uint8_t>(pidlidrecurring);
		if (pflag == nullptr || *pflag == 0) {
			if (b_first)
				printf(",");
			b_first = TRUE;
			output_event(whole_start_time, whole_end_time,
				busy_type, uid_buff, psubject, plocation,
				b_meeting, FALSE, FALSE, b_reminder, b_private);
			continue;
		}
		EXT_PULL ext_pull;
		std::optional<ical_component> ptz_component;
		auto bin = tmp_set.pparray[i]->get<const BINARY>(pidlidtimezonestruct);
		if (bin != nullptr) {
			TIMEZONESTRUCT tzstruct;
			ext_pull.init(bin->pb, bin->cb, malloc, EXT_FLAG_UTF16);
			if (ext_pull.g_tzstruct(&tzstruct) != EXT_ERR_SUCCESS)
				continue;
			ptz_component = tzstruct_to_vtimezone(
					1600, "timezone", &tzstruct);
			if (!ptz_component.has_value())
				continue;
		}
		bin = tmp_set.pparray[i]->get<BINARY>(pidlidappointmentrecur);
		if (bin == nullptr)
			continue;
		APPOINTMENT_RECUR_PAT apprecurr;
		ext_pull.init(bin->pb, bin->cb, malloc, EXT_FLAG_UTF16);
		if (ext_pull.g_apptrecpat(&apprecurr) != EXT_ERR_SUCCESS)
			continue;
		std::list<event_node> event_list;
		if (!find_recurrence_times(*ptz_component, whole_start_time,
		    &apprecurr, g_start_time, g_end_time, event_list))
			continue;
		while (event_list.size() > 0) {
			std::list<event_node> holder;
			holder.splice(holder.end(), event_list, event_list.begin());
			auto pevnode = &holder.front();
			if (pevnode->pexception == nullptr || pevnode->pex_exception == nullptr) {
				if (b_first)
					printf(",");
				b_first = TRUE;
				output_event(pevnode->start_time, pevnode->end_time,
					busy_type, uid_buff, psubject, plocation,
					b_meeting, TRUE, FALSE, b_reminder, b_private);
				continue;
			}
			BOOL b_meeting1, b_reminder1;
			if (pevnode->pexception->overrideflags & ARO_MEETINGTYPE)
				b_meeting1 = (pevnode->pexception->meetingtype & 1) ? TRUE : false;
			else
				b_meeting1 = b_meeting;
			if (pevnode->pexception->overrideflags & ARO_REMINDER)
				b_reminder1 = pevnode->pexception->reminderset == 0 ? false : TRUE;
			else
				b_reminder1 = b_reminder;
			uint32_t busy_type1 = (pevnode->pexception->overrideflags & ARO_BUSYSTATUS) ?
			                      pevnode->pexception->busystatus : busy_type;
			auto psubject1  = (pevnode->pexception->overrideflags & ARO_SUBJECT) ?
			                  pevnode->pex_exception->subject : psubject;
			auto plocation1 = (pevnode->pexception->overrideflags & ARO_LOCATION) ?
			                  pevnode->pex_exception->location : plocation;
			if (b_first)
				printf(",");
			b_first = TRUE;
			output_event(pevnode->start_time, pevnode->end_time,
				busy_type1, uid_buff, psubject1, plocation1,
				b_meeting1, TRUE, TRUE, b_reminder1, b_private);
		}
	}
	printf("]}\n");
	if (!exmdb_client::unload_table(dir, table_id))
		return FALSE;
	return TRUE;
}

int main(int argc, const char **argv)
{
	char *line;
	size_t len;
	char *ptoken;
	char *ptoken1;
	const char *pdir;
	const char *pdirs;
	const char *pbias;
	char tmp_buff[128];
	ICAL_TIME itime_end;
	const char *pstdbias;
	const char *pstdtime;
	const char *pdtlbias;
	const char *pdtltime;
	const char *pendtime;
	const char *pstdyear;
	const char *pdtlyear;
	ICAL_TIME itime_start;
	const char *pstdmonth;
	const char *pdtlmonth;
	const char *pstarttime;
	TIMEZONESTRUCT tzstruct{};
	const char *pstddayorder;
	const char *pdtldayorder;
	const char *pstddayofweek;
	const char *pdtldayofweek;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	exmdb_client_init(1, 0);
	auto cl_0 = make_scope_exit(exmdb_client_stop);
	auto ret = exmdb_client_run(PKGSYSCONFDIR, EXMDB_CLIENT_SKIP_PUBLIC);
	if (ret != 0)
		return EXIT_FAILURE;
	
	line = NULL;
	if (-1 == getline(&line, &len, stdin)) {
		fprintf(stderr, "fail to read parameters from stdin\n");
		exit(2);
	}
	auto pparser = cookie_parser_init(line);
	g_username = cookie_parser_get(pparser, "username");
	pstarttime = cookie_parser_get(pparser, "starttime");
	if (NULL == pstarttime) {
		fprintf(stderr, "fail to get \"starttime\" from stdin\n");
		exit(4);
	}
	pendtime = cookie_parser_get(pparser, "endtime");
	if (NULL == pendtime) {
		fprintf(stderr, "fail to get \"endtime\" from stdin\n");
		exit(5);
	}
	if (NULL == strchr(pstarttime, 'T') && NULL == strchr(pendtime, 'T')) {
		g_start_time = strtol(pstarttime, nullptr, 0);
		g_end_time = strtol(pendtime, nullptr, 0);
		g_tz_component.reset();
		goto GET_FREEBUSY_DATA;
	}
	if (6 != sscanf(pstarttime, "%d-%d-%dT%d:%d:%d",
		&itime_start.year, &itime_start.month, &itime_start.day,
		&itime_start.hour, &itime_start.minute, &itime_start.second)) {
		fprintf(stderr, "fail to parse \"starttime\" from stdin\n");
		exit(4);	
	}
	if (6 != sscanf(pendtime, "%d-%d-%dT%d:%d:%d",
		&itime_end.year, &itime_end.month, &itime_end.day,
		&itime_end.hour, &itime_end.minute, &itime_end.second)) {
		fprintf(stderr, "fail to parse \"endtime\" from stdin\n");
		exit(5);	
	}
	itime_start.leap_second = 0;
	itime_end.leap_second = 0;
	pbias = cookie_parser_get(pparser, "bias");
	if (NULL == pbias) {
		fprintf(stderr, "fail to get \"bias\" from stdin\n");
		exit(6);
	}
	pstdbias = cookie_parser_get(pparser, "stdbias");
	if (NULL == pstdbias) {
		fprintf(stderr, "fail to get \"stdbias\" from stdin\n");
		exit(7);
	}
	pstdtime = cookie_parser_get(pparser, "stdtime");
	if (NULL == pstdtime) {
		fprintf(stderr, "fail to get \"stdtime\" from stdin\n");
		exit(8);
	}
	pstddayorder = cookie_parser_get(pparser, "stddayorder");
	if (NULL == pstddayorder) {
		fprintf(stderr, "fail to get \"stddayorder\" from stdin\n");
		exit(9);
	}
	pstdmonth = cookie_parser_get(pparser, "stdmonth");
	if (NULL == pstdmonth) {
		fprintf(stderr, "fail to get \"stdmonth\" from stdin\n");
		exit(10);
	}
	pstdyear = cookie_parser_get(pparser, "stdyear");
	pstddayofweek = cookie_parser_get(pparser, "stddayofweek");
	if (NULL == pstddayofweek) {
		fprintf(stderr, "fail to get \"stddayofweek\" from stdin\n");
		exit(11);
	}
	pdtlbias = cookie_parser_get(pparser, "dtlbias");
	if (NULL == pdtlbias) {
		fprintf(stderr, "fail to get \"dtlbias\" from stdin\n");
		exit(12);
	}
	pdtltime = cookie_parser_get(pparser, "dtltime");
	if (NULL == pdtltime) {
		fprintf(stderr, "fail to get \"dtltime\" from stdin\n");
		exit(13);
	}
	pdtldayorder = cookie_parser_get(pparser, "dtldayorder");
	if (NULL == pdtldayorder) {
		fprintf(stderr, "fail to get \"dtldayorder\" from stdin\n");
		exit(14);
	}
	pdtlmonth = cookie_parser_get(pparser, "dtlmonth");
	if (NULL == pdtlmonth) {
		fprintf(stderr, "fail to get \"dtlmonth\" from stdin\n");
		exit(10);
	}
	pdtlyear = cookie_parser_get(pparser, "dtlyear");
	pdtldayofweek = cookie_parser_get(pparser, "dtldayofweek");
	if (NULL == pdtldayofweek) {
		fprintf(stderr, "fail to get \"dtldayofweek\" from stdin\n");
		exit(11);
	}
	tzstruct.bias = strtol(pbias, nullptr, 0);
	tzstruct.standardbias = strtol(pstdbias, nullptr, 0);
	tzstruct.daylightbias = strtol(pdtlbias, nullptr, 0);
	tzstruct.standarddate.year = pstdyear == nullptr ? 0 : strtol(pstdyear, nullptr, 0);
	tzstruct.standardyear = tzstruct.standarddate.year;
	tzstruct.standarddate.month = strtol(pstdmonth, nullptr, 0);
	if (strcasecmp(pstddayofweek, "Sunday") == 0)
		tzstruct.standarddate.dayofweek = 0;
	else if (strcasecmp(pstddayofweek, "Monday") == 0)
		tzstruct.standarddate.dayofweek = 1;
	else if (strcasecmp(pstddayofweek, "Tuesday") == 0)
		tzstruct.standarddate.dayofweek = 2;
	else if (strcasecmp(pstddayofweek, "Wednesday") == 0)
		tzstruct.standarddate.dayofweek = 3;
	else if (strcasecmp(pstddayofweek, "Thursday") == 0)
		tzstruct.standarddate.dayofweek = 4;
	else if (strcasecmp(pstddayofweek, "Friday") == 0)
		tzstruct.standarddate.dayofweek = 5;
	else if (strcasecmp(pstddayofweek, "Saturday") == 0)
		tzstruct.standarddate.dayofweek = 6;
	tzstruct.standarddate.day = strtol(pstddayorder, nullptr, 0);
	gx_strlcpy(tmp_buff, pstdtime, arsizeof(tmp_buff));
	ptoken = strchr(tmp_buff, ':');
	if (NULL == ptoken) {
		fprintf(stderr, "\"stdtime\" format error\n");
		exit(12);
	}
	*ptoken = '\0';
	ptoken ++;
	ptoken1 = strchr(ptoken, ':');
	if (NULL == ptoken1) {
		fprintf(stderr, "\"stdtime\" format error\n");
		exit(12);
	}
	*ptoken1 = '\0';
	ptoken1 ++;
	tzstruct.standarddate.hour = strtol(tmp_buff, nullptr, 0);
	tzstruct.standarddate.minute = strtol(ptoken, nullptr, 0);
	tzstruct.standarddate.second = strtol(ptoken1, nullptr, 0);
	tzstruct.daylightdate.year = pdtlyear == nullptr ? 0 : strtol(pdtlyear, nullptr, 0);
	tzstruct.daylightyear = tzstruct.daylightdate.year;
	tzstruct.daylightdate.month = strtol(pdtlmonth, nullptr, 0);
	if (strcasecmp(pdtldayofweek, "Sunday") == 0)
		tzstruct.daylightdate.dayofweek = 0;
	else if (strcasecmp(pdtldayofweek, "Monday") == 0)
		tzstruct.daylightdate.dayofweek = 1;
	else if (strcasecmp(pdtldayofweek, "Tuesday") == 0)
		tzstruct.daylightdate.dayofweek = 2;
	else if (strcasecmp(pdtldayofweek, "Wednesday") == 0)
		tzstruct.daylightdate.dayofweek = 3;
	else if (strcasecmp(pdtldayofweek, "Thursday") == 0)
		tzstruct.daylightdate.dayofweek = 4;
	else if (strcasecmp(pdtldayofweek, "Friday") == 0)
		tzstruct.daylightdate.dayofweek = 5;
	else if (strcasecmp(pdtldayofweek, "Saturday") == 0)
		tzstruct.daylightdate.dayofweek = 6;
	tzstruct.daylightdate.day = strtol(pdtldayorder, nullptr, 0);
	gx_strlcpy(tmp_buff, pdtltime, arsizeof(tmp_buff));
	ptoken = strchr(tmp_buff, ':');
	if (NULL == ptoken) {
		fprintf(stderr, "\"dtltime\" format error\n");
		exit(13);
	}
	*ptoken = '\0';
	ptoken ++;
	ptoken1 = strchr(ptoken, ':');
	if (NULL == ptoken1) {
		fprintf(stderr, "\"dtltime\" format error\n");
		exit(13);
	}
	*ptoken1 = '\0';
	ptoken1 ++;
	tzstruct.daylightdate.hour = strtol(tmp_buff, nullptr, 0);
	tzstruct.daylightdate.minute = strtol(ptoken, nullptr, 0);
	tzstruct.daylightdate.second = strtol(ptoken1, nullptr, 0);
	g_tz_component = tzstruct_to_vtimezone(
				1600, "timezone", &tzstruct);
	if (!g_tz_component.has_value()) {
		fprintf(stderr, "fail to produce vtimezone component\n");
		exit(14);
	}
	ical_itime_to_utc(&*g_tz_component, itime_start, &g_start_time);
	ical_itime_to_utc(&*g_tz_component, itime_end, &g_end_time);
 GET_FREEBUSY_DATA:
	pdirs = cookie_parser_get(pparser, "dirs");
	if (NULL == pdirs) {
		fprintf(stderr, "fail to get \"dirs\" from stdin\n");
		exit(15);
	}
	int dir_num = strtol(pdirs, nullptr, 0);
	for (decltype(dir_num) i = 0; i < dir_num; ++i) {
		snprintf(tmp_buff, arsizeof(tmp_buff), "dir%d", i);
		pdir = cookie_parser_get(pparser, tmp_buff);
		if (pdir != nullptr)
			get_freebusy(pdir);
	}
	exit(0);
}

